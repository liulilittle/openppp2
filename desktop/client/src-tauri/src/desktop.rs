use crate::config::{
    apply_network_overrides, build_node_config_with_base, default_config_string, prepare_policy_v2,
};
use crate::connection::ConnectionSnapshot;
use crate::policy::{PolicyReport, Staging, Workspace};
use crate::launch_options::{append_launch_args, merge_launch_options};
use crate::lifecycle::{
    close_action, should_disconnect_on_exit, tray_primary_action, CloseAction, TrayPrimaryAction,
};
use crate::manual_nodes::{
    delete_manual_node, find_node, merge_nodes, node_source, upsert_manual_node, ManualNodeInput,
    NodeSource,
};
use crate::pinger::{probe_nodes, targets_for_nodes};
use crate::preferences::{
    load_preferences, save_preferences, update_setting, Preferences, SubscriptionSource,
};
use crate::process::{CommandSpec, ProcessEvent, ProcessManager};
use crate::subscription::{
    refresh_with, RefreshResult, SubscriptionDocument, MAX_SUBSCRIPTION_BYTES,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};
use url::Url;

pub struct DesktopState {
    data_dir: PathBuf,
    preferences: Mutex<Preferences>,
    subscription: Mutex<Option<StoredSubscription>>,
    process: Mutex<ProcessManager>,
    last_node_id: Mutex<Option<String>>,
    network: Mutex<Value>,
    tray_items: Mutex<Option<TrayItems>>,
    exit_requested: AtomicBool,
    proxy: Mutex<ProxySession>,
    /// (kernel path, modified time, supports `ppp policy`) from the last probe.
    policy_kernel: Mutex<Option<(PathBuf, Option<std::time::SystemTime>, bool)>>,
    _instance: crate::windows::InstanceGuard,
}

#[derive(Default)]
struct ProxySession {
    address: String,
    auto: bool,
    applied: bool,
}

#[derive(Clone)]
struct TrayItems {
    status: MenuItem<Wry>,
    primary: MenuItem<Wry>,
}

struct StoredSubscription {
    document: SubscriptionDocument,
    fetched_at_ms: u64,
    cached: bool,
}

impl From<RefreshResult> for StoredSubscription {
    fn from(result: RefreshResult) -> Self {
        Self {
            document: result.document,
            fetched_at_ms: result.fetched_at_ms,
            cached: result.cached,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapPayload {
    subscription: Option<SubscriptionPayload>,
    config: String,
    launch_options: BTreeMap<String, Value>,
    settings: Value,
    connection: ConnectionSnapshot,
    network: Value,
    current_node_id: Option<String>,
    network_overrides: Value,
    administrator: bool,
    proxy_recovery_pending: bool,
    policy_dir: String,
    policy_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionPayload {
    url: String,
    name: String,
    updated_at: Option<String>,
    last_synced_at: u64,
    cached: bool,
    cache_age_minutes: u64,
    nodes: Vec<NodePayload>,
    sources: Vec<SubscriptionSource>,
    /// True when any subscription URL uses plain http.
    insecure_transport: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodePayload {
    id: String,
    name: String,
    subtitle: String,
    address: String,
    latency_ms: Option<u32>,
    favorite: bool,
    source: NodeSource,
    config: Option<Value>,
    options: Option<Value>,
    source_id: String,
    source_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyPayload {
    enabled: bool,
    policy_dir: String,
    policy: Option<Value>,
    rules: String,
    kernel_supported: Option<bool>,
    kernel_error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyDraftPayload {
    policy: Option<Value>,
    rules: String,
    result: PolicyReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectPayload {
    pid: u32,
    network: Value,
    session_id: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryPayload {
    network_recovery_pending: bool,
    proxy_recovery_pending: bool,
    message: String,
}

const NETWORK_RECOVERY_MARKER: &str = "network-recovery.pending";

fn network_recovery_marker(data_dir: &Path) -> PathBuf {
    data_dir.join(NETWORK_RECOVERY_MARKER)
}

fn persist_network_recovery_marker(data_dir: &Path) -> Result<(), String> {
    let marker = network_recovery_marker(data_dir);
    if marker.exists() {
        return Ok(());
    }
    let temporary = data_dir.join(format!("{NETWORK_RECOVERY_MARKER}.tmp"));
    let mut file = fs::File::create(&temporary).map_err(|error| error.to_string())?;
    use std::io::Write;
    file.write_all(b"version=1\nreason=forced-stop\n")
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, &marker).map_err(|error| error.to_string())
}

fn clear_network_recovery_marker(data_dir: &Path) -> Result<(), String> {
    let marker = network_recovery_marker(data_dir);
    match fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Runs Core's journal-only recovery entry point. The command receives the
/// same directory derived from the Core executable path, so it can open the
/// journal without loading a VPN configuration or creating a TAP session.
fn recover_pending_network(
    process: &mut ProcessManager,
    executable: &Path,
    data_dir: &Path,
) -> Result<(), String> {
    recover_pending_network_with(process, executable, data_dir, |process, spec| {
        process
            .run_recovery_worker(spec, Duration::from_secs(5))
            .map_err(|error| error.to_string())
    })
}

fn recover_pending_network_with(
    process: &mut ProcessManager,
    executable: &Path,
    data_dir: &Path,
    run_worker: impl FnOnce(&mut ProcessManager, CommandSpec) -> Result<bool, String>,
) -> Result<(), String> {
    let marker = network_recovery_marker(data_dir);
    let directory = executable
        .parent()
        .ok_or_else(|| "Core executable has no recovery directory".to_string())?
        .join("network-recovery");
    let journal = directory.join("network-recovery.journal");
    let network_required = process.snapshot().recovery_pending || marker.exists() || journal.exists();
    let mut core_recovered = !network_required;
    let mut errors = Vec::new();

    if network_required {
        let spec = CommandSpec::new(
            executable.to_path_buf(),
            [
                "--network-recovery".to_string(),
                format!("--network-recovery-dir={}", directory.display()),
            ],
        );
        match run_worker(process, spec) {
            Ok(true) => {
                // Core returns success only after validating the journal and
                // recovering every entry. It keeps the empty journal header;
                // file existence alone must not reinstate the recovery gate.
                core_recovered = true;
                // The marker is a second durable gate. Keep the visible pending
                // state when it cannot be removed, even if the worker succeeded.
                if let Err(error) = clear_network_recovery_marker(data_dir) {
                    errors.push(error);
                }
            }
            Ok(false) => errors.push("Core network recovery is still pending".into()),
            Err(error) => errors.push(error.to_string()),
        }
    }

    // Proxy recovery is an independent resource. A failed proxy restore must
    // not prevent us from attempting (or reporting) Core network recovery.
    let proxy_path = data_dir.join("proxy-recovery.json");
    if let Err(error) = crate::windows::restore_proxy(&proxy_path, false) {
        errors.push(error);
    }

    let network_pending = marker.exists() || !core_recovered;
    let proxy_pending = proxy_path.exists();
    if !network_pending && !proxy_pending {
        process.mark_recovery_complete();
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    if network_pending || proxy_pending {
        return Err("Network recovery is still pending".into());
    }
    Ok(())
}

impl DesktopState {
    fn new(app: &AppHandle) -> Result<Self, String> {
        let mut data_dir = app
            .path()
            .app_data_dir()
            .map_err(|error| error.to_string())?;
        #[cfg(debug_assertions)]
        if let Some(directory) = std::env::var_os("OPENPPP2_CLIENT_DATA_DIR") {
            data_dir = PathBuf::from(directory);
        }
        fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
        let ready = std::env::args()
            .find_map(|arg| arg.strip_prefix("--elevated-ready=").map(PathBuf::from));
        if let Some(path) = ready.as_ref() {
            if path.parent() != Some(data_dir.as_path())
                || !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("elevated-"))
            {
                return Err("Invalid elevation handoff path".into());
            }
        }
        let name = format!("Local\\OpenPPP2Client-{}", data_dir.to_string_lossy());
        let name = name.replace(['/', ':'], "_").replace('\\', "_");
        let name = format!("Local\\{name}");
        let instance = crate::windows::instance(&name, ready.is_some())?;
        let mut preferences = load_preferences(&data_dir.join("preferences.json"))
            .map_err(|error| error.to_string())?;
        for source in preferences
            .subscriptions
            .iter_mut()
            .filter(|s| valid_source_id(&s.id))
        {
            if let Ok(result) = refresh_with(
                &source.url,
                &data_dir.join(format!("subscription-{}.json", source.id)),
                |_| Err("startup".into()),
            ) {
                source.last_synced_at = result.fetched_at_ms;
                source.cached = true;
            }
        }
        let subscription = load_sources(&data_dir, &preferences);
        let proxy_recovery_path = data_dir.join("proxy-recovery.json");
        // Startup proxy cleanup is best effort, but its failure is a durable
        // recovery gate just like the Core network marker.
        let proxy_recovery_pending = crate::windows::restore_proxy(&proxy_recovery_path, false)
            .is_err()
            || proxy_recovery_path.exists();
        let recovery_marker = network_recovery_marker(&data_dir);
        let recovery_marker_for_events = recovery_marker.clone();
        let runtime_config_for_events = data_dir.join("runtime").join("appsettings.json");
        let emitter = app.clone();
        let process = ProcessManager::new(move |event| {
            let exited = matches!(&event.event, ProcessEvent::Exited(_));
            if exited {
                // The runtime config holds node keys; remove it once the
                // kernel is gone. Policy v2 keeps it: status/update derive
                // the policy store identity from this path.
                let runtime_config = runtime_config_for_events.clone();
                let keep = fs::read(&runtime_config)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|config| crate::config::uses_policy_v2(&config));
                if !keep {
                    let _ = fs::remove_file(&runtime_config);
                }
                let needs_recovery = match &event.event {
                    ProcessEvent::Exited(exit) => {
                        exit.recovery_pending
                            || (!exit.success
                                && matches!(exit.reason, crate::process::ExitReason::Natural))
                    }
                    _ => false,
                };
                // A process exit is not proof that Core's network journal is
                // empty.  Keep the durable gate until the independent worker
                // has opened the journal and verified every resource.  This
                // also covers a natural exit after a partial apply.
                let marker_result = if needs_recovery {
                    persist_network_recovery_marker(
                        recovery_marker_for_events
                            .parent()
                            .unwrap_or_else(|| Path::new(".")),
                    )
                } else {
                    Ok(())
                };
                if let Err(error) = marker_result {
                    let _ = emitter.emit("client://tray-error", error);
                }
            }
            let state = emitter.try_state::<DesktopState>();
            if let Some(state) = state.as_ref() {
                update_tray_phase(state, &event.connection.status);
                let mut proxy_restore_error = None;
                let mut proxy_apply_error = None;
                if let Ok(mut proxy) = state.proxy.lock() {
                    if exited
                        || event.connection.status == "reconnecting"
                        || event.connection.status == "error"
                    {
                        if proxy.applied {
                            if let Err(error) = crate::windows::restore_proxy(
                                &state.data_dir.join("proxy-recovery.json"),
                                false,
                            ) {
                                proxy_restore_error = Some(error);
                            }
                            proxy.applied = false;
                        }
                    } else if event.connection.status == "connected" && proxy.auto && !proxy.applied
                    {
                        if let Ok(address) = proxy.address.parse::<std::net::SocketAddr>() {
                            if std::net::TcpStream::connect_timeout(
                                &address,
                                Duration::from_millis(200),
                            )
                            .is_ok()
                            {
                                match crate::windows::apply_proxy(
                                    &state.data_dir.join("proxy-recovery.json"),
                                    &proxy.address,
                                ) {
                                    Ok(()) => proxy.applied = true,
                                    Err(error) => {
                                        proxy.auto = false;
                                        proxy_apply_error = Some(error);
                                    }
                                }
                            }
                        }
                    }
                }
                // Release the proxy lock before taking the process lock. The
                // connect path takes these locks in the opposite order.
                if let Some(error) = proxy_restore_error {
                    if let Ok(mut manager) = state.process.lock() {
                        manager.mark_recovery_pending();
                    }
                    let _ = emitter.emit("client://tray-error", error);
                }
                if let Some(error) = proxy_apply_error {
                    if state.data_dir.join("proxy-recovery.json").exists() {
                        if let Ok(mut manager) = state.process.lock() {
                            manager.mark_recovery_pending();
                        }
                    }
                    let _ = emitter.emit("client://tray-error", error);
                }
            }
            let _ = emitter.emit("client://process", event);
            if exited {
                if let Some(state) = state.as_ref() {
                    update_tray(state, false, None);
                }
            }
        });
        let mut process = process;
        // The journal is authoritative if the GUI was terminated between a
        // Core write and marker persistence.  An empty journal is harmless:
        // the worker verifies it and clears the marker gate.
        let journal_exists = resolve_ppp_path(&preferences.ppp_path)
            .ok()
            .and_then(|executable| {
                executable
                    .parent()
                    .map(|parent| parent.join("network-recovery/network-recovery.journal"))
            })
            .is_some_and(|journal| journal.exists());
        if recovery_marker.exists() || journal_exists || proxy_recovery_pending {
            process.mark_recovery_pending();
            // Startup recovery is best effort: an unavailable executable or a
            // still-conflicted resource must leave the gate pending while the
            // UI remains usable for an explicit retry.
            if let Ok(executable) = resolve_ppp_path(&preferences.ppp_path) {
                let _ = recover_pending_network(&mut process, &executable, &data_dir);
            }
        }
        Ok(Self {
            data_dir,
            preferences: Mutex::new(preferences),
            subscription: Mutex::new(subscription),
            process: Mutex::new(process),
            last_node_id: Mutex::new(None),
            network: Mutex::new(json!({})),
            tray_items: Mutex::new(None),
            exit_requested: AtomicBool::new(false),
            proxy: Mutex::new(ProxySession::default()),
            policy_kernel: Mutex::new(None),
            _instance: instance,
        })
    }

    /// Base directory for relative policy v2 rule, rule-set and fake-IP paths.
    fn policy_dir(&self) -> PathBuf {
        self.data_dir.join("policy")
    }

    fn save_preferences(&self, preferences: &Preferences) -> Result<(), String> {
        save_preferences(&self.data_dir.join("preferences.json"), preferences)
            .map_err(|error| error.to_string())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn valid_source_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn load_sources(directory: &Path, preferences: &Preferences) -> Option<StoredSubscription> {
    let mut nodes = Vec::new();
    let mut fetched_at_ms = 0;
    for source in preferences
        .subscriptions
        .iter()
        .filter(|s| s.enabled && valid_source_id(&s.id))
    {
        if let Ok(result) = refresh_with(
            &source.url,
            &directory.join(format!("subscription-{}.json", source.id)),
            |_| Err("startup".into()),
        ) {
            fetched_at_ms = fetched_at_ms.max(result.fetched_at_ms);
            nodes.extend(result.document.nodes.into_iter().map(|mut node| {
                node.id = format!("sub:{}:{}", source.id, node.id);
                node
            }));
        }
    }
    if nodes.is_empty() {
        return None;
    }
    Some(StoredSubscription {
        document: SubscriptionDocument {
            document_type: "openppp2-subscription".into(),
            version: 1,
            name: Some("Subscriptions".into()),
            profile_prefix: None,
            updated_at: None,
            nodes,
        },
        fetched_at_ms,
        cached: preferences
            .subscriptions
            .iter()
            .any(|s| s.enabled && s.cached),
    })
}

#[tauri::command]
fn client_save_subscription(
    mut source: SubscriptionSource,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let parsed = Url::parse(source.url.trim()).map_err(|_| "Invalid subscription URL")?;
    if !["https", "http"].contains(&parsed.scheme()) || parsed.host_str().is_none() {
        return Err("Use an HTTP/HTTPS subscription URL".into());
    }
    if source.id.is_empty() {
        source.id = format!("s{}", now_ms());
    }
    if !valid_source_id(&source.id) || source.name.trim().is_empty() {
        return Err("Invalid subscription ID or name".into());
    }
    source.url = source.url.trim().into();
    if state
        .process
        .lock()
        .map_err(|_| "Process lock")?
        .is_running()
        && state
            .last_node_id
            .lock()
            .map_err(|_| "Node lock")?
            .as_ref()
            .is_some_and(|id| id.starts_with(&format!("sub:{}:", source.id)))
    {
        return Err("Disconnect before editing the active subscription".into());
    }
    let mut preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
    let mut candidate = preferences.clone();
    if let Some(index) = candidate
        .subscriptions
        .iter()
        .position(|s| s.id == source.id)
    {
        let previous = &candidate.subscriptions[index];
        if previous.url == source.url {
            source.last_synced_at = previous.last_synced_at;
            source.cached = previous.cached;
            source.error = previous.error.clone();
        } else {
            source.last_synced_at = 0;
            source.cached = false;
            source.error.clear();
        }
        candidate.subscriptions[index] = source;
    } else {
        source.last_synced_at = 0;
        source.cached = false;
        source.error.clear();
        candidate.subscriptions.push(source);
    }
    state.save_preferences(&candidate)?;
    let stored = load_sources(&state.data_dir, &candidate);
    let payload = subscription_payload(stored.as_ref(), &candidate);
    *state.subscription.lock().map_err(|_| "Subscription lock")? = stored;
    *preferences = candidate;
    Ok(payload)
}

#[tauri::command]
fn client_delete_subscription(
    source_id: String,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    if !valid_source_id(&source_id) {
        return Err("Invalid source ID".into());
    }
    let prefix = format!("sub:{source_id}:");
    if state
        .process
        .lock()
        .map_err(|_| "Process lock")?
        .is_running()
        && state
            .last_node_id
            .lock()
            .map_err(|_| "Node lock")?
            .as_ref()
            .is_some_and(|id| id.starts_with(&prefix))
    {
        return Err("Disconnect before deleting the active subscription".into());
    }
    let mut preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
    let mut candidate = preferences.clone();
    candidate.subscriptions.retain(|s| s.id != source_id);
    candidate.favorites.retain(|id| !id.starts_with(&prefix));
    state.save_preferences(&candidate)?;
    let stored = load_sources(&state.data_dir, &candidate);
    let payload = subscription_payload(stored.as_ref(), &candidate);
    *state.subscription.lock().map_err(|_| "Subscription lock")? = stored;
    *preferences = candidate;
    Ok(payload)
}

#[tauri::command]
fn client_update_network(
    overrides: Value,
    state: State<'_, DesktopState>,
) -> Result<Value, String> {
    crate::network::validate(&overrides)?;
    let mut preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
    let mut candidate = preferences.clone();
    candidate.network_overrides = overrides.clone();
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(overrides)
}

#[tauri::command]
fn client_restore_proxy(force: bool, state: State<'_, DesktopState>) -> Result<(), String> {
    state.proxy.lock().map_err(|_| "Proxy lock")?.auto = false;
    if let Err(error) = crate::windows::restore_proxy(
        &state.data_dir.join("proxy-recovery.json"),
        force,
    ) {
        if let Ok(mut manager) = state.process.lock() {
            manager.mark_recovery_pending();
        }
        return Err(error);
    }
    state.proxy.lock().map_err(|_| "Proxy lock")?.applied = false;
    Ok(())
}

/// Retry the recovery paths owned by the desktop process. Core-owned network
/// state remains pending until a recovery worker verifies it was restored.
#[tauri::command]
fn client_retry_recovery(state: State<'_, DesktopState>) -> Result<RecoveryPayload, String> {
    let mut process = state.process.lock().map_err(|_| "Process lock")?;
    if process.is_running() {
        return Err("Disconnect before recovering network state".into());
    }
    let mut recovery_error = None;
    let proxy_path = state.data_dir.join("proxy-recovery.json");
    if process.snapshot().recovery_pending || proxy_path.exists() {
        // Retry the desktop-owned proxy record even when the configured Core
        // executable is unavailable. Proxy recovery must not depend on Core.
        if let Err(error) = crate::windows::restore_proxy(&proxy_path, false) {
            recovery_error = Some(error);
        }
        let preferences = state
            .preferences
            .lock()
            .map_err(|_| "Preferences lock")?
            .clone();
        let journal_exists = resolve_ppp_path(&preferences.ppp_path)
            .ok()
            .and_then(|executable| {
                executable
                    .parent()
                    .map(|parent| parent.join("network-recovery/network-recovery.journal"))
            })
            .is_some_and(|journal| journal.exists());
        if network_recovery_marker(&state.data_dir).exists() || journal_exists {
            match resolve_ppp_path(&preferences.ppp_path) {
                Ok(executable) => {
                    if let Err(error) = recover_pending_network(
                        &mut process,
                        &executable,
                        &state.data_dir,
                    ) {
                        recovery_error = Some(error);
                    }
                }
                Err(error) => recovery_error = Some(error),
            }
        }
        if !network_recovery_marker(&state.data_dir).exists()
            && !journal_exists
            && !proxy_path.exists()
        {
            process.mark_recovery_complete();
        }
    }
    let network_recovery_pending = process.snapshot().recovery_pending;
    let proxy_recovery_pending = if proxy_path.exists() {
        crate::windows::restore_proxy(&proxy_path, false).is_err() || proxy_path.exists()
    } else {
        false
    };
    Ok(RecoveryPayload {
        network_recovery_pending,
        proxy_recovery_pending,
        message: if let Some(error) = recovery_error {
            error
        } else if network_recovery_pending {
            "Core network recovery is still pending".into()
        } else if proxy_recovery_pending {
            "System proxy recovery is still pending".into()
        } else {
            String::new()
        },
    })
}

#[tauri::command]
async fn client_pick_executable() -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(crate::windows::pick_executable)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn client_elevate(app: AppHandle, state: State<'_, DesktopState>) -> Result<(), String> {
    if state
        .process
        .lock()
        .map_err(|_| "Process lock")?
        .is_running()
    {
        return Err("Disconnect before restarting".into());
    }
    let ready = state.data_dir.join(format!("elevated-{}.ready", now_ms()));
    crate::windows::elevate(&ready)?;
    tauri::async_runtime::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if ready.exists() {
                let _ = fs::remove_file(&ready);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err("Elevated application did not become ready".to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    prepare_exit(&app);
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn client_kernel_info(state: State<'_, DesktopState>) -> Result<Value, String> {
    let configured = state
        .preferences
        .lock()
        .map_err(|_| "Preferences lock")?
        .ppp_path
        .clone();
    let path = resolve_ppp_path(&configured)?;
    tauri::async_runtime::spawn_blocking(move || crate::kernel::inspect(&path))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn client_preview(
    node_id: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<Value, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "Preferences lock")?
        .clone();
    let stored = state.subscription.lock().map_err(|_| "Subscription lock")?;
    let nodes = stored
        .as_ref()
        .map(|s| s.document.nodes.as_slice())
        .unwrap_or_default();
    let mut config = if let Some(node) = node_id
        .as_ref()
        .and_then(|id| find_node(&preferences.manual_nodes, nodes, id))
    {
        build_node_config_with_base(node, Some(&preferences.raw_config))
            .map_err(|e| e.to_string())?
    } else {
        serde_json::from_str(if preferences.raw_config.is_empty() {
            default_config_string()
        } else {
            &preferences.raw_config
        })
        .map_err(|e| e.to_string())?
    };
    apply_local_policy(&mut config, &preferences, &state)?;
    if preferences.network_overrides.is_object() {
        apply_network_overrides(&mut config, &preferences.network_overrides)
            .map_err(|e| e.to_string())?;
    }
    prepare_policy_v2(&mut config, &state.policy_dir());
    let node_options = node_id
        .as_ref()
        .and_then(|id| find_node(&preferences.manual_nodes, nodes, id))
        .and_then(|n| n.options.as_ref());
    let options = merge_launch_options(&preferences.launch_options, node_options)
        .map_err(|e| e.to_string())?;
    let mut args = vec![format!("--mode={}", preferences.settings.connection_mode)];
    append_launch_args(&options, &mut args).map_err(|e| e.to_string())?;
    Ok(json!({ "config": crate::kernel::redact(config), "args": args }))
}

#[tauri::command]
fn client_open_data(state: State<'_, DesktopState>) -> Result<(), String> {
    std::process::Command::new("explorer.exe")
        .arg(&state.data_dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn client_bootstrap(state: State<'_, DesktopState>) -> Result<BootstrapPayload, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let subscription = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .map(|stored| subscription_payload(Some(stored), &preferences));
    Ok(BootstrapPayload {
        subscription: subscription.or_else(|| Some(subscription_payload(None, &preferences))),
        config: if preferences.raw_config.is_empty() {
            default_config_string().into()
        } else {
            preferences.raw_config.clone()
        },
        launch_options: preferences.launch_options.clone(),
        settings: json!({
            "autostart": preferences.settings.autostart,
            "closeToTray": preferences.settings.close_to_tray,
            "disconnectOnExit": preferences.settings.disconnect_on_exit,
            "language": preferences.settings.language,
            "appearance": preferences.settings.appearance,
            "connectionMode": preferences.settings.connection_mode,
            "pppPath": preferences.ppp_path,
            "autoSystemProxy": preferences.settings.auto_system_proxy,
        }),
        connection: state.process.lock().map_err(|_| "Process lock")?.snapshot(),
        network: state.network.lock().map_err(|_| "Network lock")?.clone(),
        current_node_id: state.last_node_id.lock().map_err(|_| "Node lock")?.clone(),
        network_overrides: if preferences.network_overrides.is_object() {
            preferences.network_overrides.clone()
        } else {
            json!({})
        },
        administrator: crate::windows::administrator(),
        proxy_recovery_pending: state.data_dir.join("proxy-recovery.json").exists(),
        policy_dir: state.policy_dir().to_string_lossy().into_owned(),
        policy_enabled: preferences.policy_enabled,
    })
}

#[tauri::command]
async fn subscription_refresh(
    url: String,
    source_id: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let parsed = Url::parse(&url).map_err(|_| "订阅地址无效".to_string())?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("订阅地址只支持 HTTP/HTTPS".into());
    }
    let source = {
        let mut preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
        let id = source_id.unwrap_or_else(|| format!("s{}", now_ms()));
        if !valid_source_id(&id) {
            return Err("Invalid source ID".into());
        }
        let source = preferences
            .subscriptions
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .unwrap_or(SubscriptionSource {
                id,
                name: parsed.host_str().unwrap_or("Subscription").into(),
                url: url.clone(),
                enabled: true,
                last_synced_at: 0,
                cached: false,
                error: String::new(),
            });
        if !preferences.subscriptions.iter().any(|s| s.id == source.id) {
            preferences.subscriptions.push(source.clone());
            state.save_preferences(&preferences)?;
        }
        source
    };
    let cache_path = state
        .data_dir
        .join(format!("subscription-{}.json", source.id));
    let fetch_url = url.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let origin_host = Url::parse(&fetch_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            let host = attempt.url().host_str().map(str::to_ascii_lowercase);
            if host != origin_host {
                return attempt.error("cross-host subscription redirect blocked");
            }
            if let Some(url::Host::Ipv4(ip)) = attempt.url().host() {
                if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
                    return attempt.error("redirect to local address blocked");
                }
            }
            if let Some(url::Host::Ipv6(ip)) = attempt.url().host() {
                if ip.is_loopback() || ip.is_unspecified() {
                    return attempt.error("redirect to local address blocked");
                }
            }
            attempt.follow()
        });
        let client = reqwest::blocking::Client::builder()
            .redirect(redirect_policy)
            .timeout(Duration::from_secs(15))
            .user_agent("OpenPPP2/Desktop")
            .build()
            .map_err(|error| error.to_string())?;
        refresh_with(&fetch_url, &cache_path, |target| {
            let mut response = client
                .get(target)
                .header("Accept", "application/json")
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .map_err(|error| error.to_string())?;
            let mut body = Vec::new();
            response
                .by_ref()
                .take((MAX_SUBSCRIPTION_BYTES + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|error| error.to_string())?;
            Ok(body)
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let item = preferences
        .subscriptions
        .iter_mut()
        .find(|s| s.id == source.id)
        .ok_or("Subscription removed during refresh")?;
    if item.url != url {
        return Err("Subscription URL changed during refresh".into());
    }
    match result {
        Ok(result) => {
            item.last_synced_at = result.fetched_at_ms;
            item.cached = result.cached;
            item.error = if result.cached {
                "Refresh failed; using cache".into()
            } else {
                String::new()
            };
        }
        Err(error) => {
            item.error = error;
            item.cached = true;
        }
    }
    state.save_preferences(&preferences)?;
    let stored = load_sources(&state.data_dir, &preferences);
    let payload = subscription_payload(stored.as_ref(), &preferences);
    *state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())? = stored;
    Ok(payload)
}

#[tauri::command]
async fn client_probe_latency(
    node_ids: Option<Vec<String>>,
    state: State<'_, DesktopState>,
    app: AppHandle,
) -> Result<BTreeMap<String, Option<u32>>, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let subscription_nodes = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .map(|stored| stored.document.nodes.clone())
        .unwrap_or_default();
    let nodes = merge_nodes(&preferences.manual_nodes, &subscription_nodes);
    let targets = targets_for_nodes(&nodes, node_ids.as_deref());
    let latencies = tauri::async_runtime::spawn_blocking(move || {
        probe_nodes(targets, 4, Duration::from_secs(3)).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())??;
    let _ = app.emit("client://latency", &latencies);
    Ok(latencies)
}

#[tauri::command]
fn client_connect(
    node_id: String,
    state: State<'_, DesktopState>,
) -> Result<ConnectPayload, String> {
    connect_node(&node_id, &state)
}

fn connect_node(node_id: &str, state: &DesktopState) -> Result<ConnectPayload, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let subscription_nodes = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .map(|stored| stored.document.nodes.clone())
        .unwrap_or_default();
    let node = find_node(&preferences.manual_nodes, &subscription_nodes, node_id)
        .cloned()
        .ok_or_else(|| "找不到所选节点".to_string())?;
    let mut config = build_node_config_with_base(&node, Some(&preferences.raw_config))
        .map_err(|error| error.to_string())?;
    apply_local_policy(&mut config, &preferences, state)?;
    if preferences.network_overrides.is_object() {
        apply_network_overrides(&mut config, &preferences.network_overrides)
            .map_err(|e| e.to_string())?;
    }
    if crate::config::uses_policy_v2(&config) {
        let policy_dir = state.policy_dir();
        fs::create_dir_all(&policy_dir).map_err(|error| error.to_string())?;
        prepare_policy_v2(&mut config, &policy_dir);
        check_policy_before_connect(&config, &preferences.settings.connection_mode, state)?;
    }
    if preferences.settings.connection_mode == "client" && !crate::windows::administrator() {
        return Err("Virtual adapter requires administrator privileges; restart as administrator in Settings".into());
    }
    let mut process = state.process.lock().map_err(|_| "Process lock")?;
    if process.is_running() {
        return Err("Disconnect before connecting another node".into());
    }
    // Validate/replay the journal before applying the connection gate. Core
    // retains an empty journal after clean teardown; its presence alone does
    // not imply unresolved resources and must not block every reconnect.
    let executable = resolve_ppp_path(&preferences.ppp_path)?;
    recover_pending_network(&mut process, &executable, &state.data_dir)?;
    let proxy_recovery_path = state.data_dir.join("proxy-recovery.json");
    if process.snapshot().recovery_pending
        || network_recovery_marker(&state.data_dir).exists()
        || proxy_recovery_path.exists()
    {
        return Err("Network recovery is still pending; recover it before connecting".into());
    }
    let runtime_dir = state.data_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).map_err(|error| error.to_string())?;
    let config_path = runtime_dir.join("appsettings.json");
    write_atomic(
        &config_path,
        &serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?,
    )?;
    let stats_path = runtime_dir.join(format!("stats-{}.ndjson", now_ms()));
    let mode = if preferences.settings.connection_mode == "proxy" {
        "proxy"
    } else {
        "client"
    };
    let mut spec = CommandSpec::new(
        executable,
        [
            format!("--mode={mode}"),
            format!("--config={}", config_path.display()),
            format!("--stats-json={}", stats_path.display()),
        ],
    );
    let launch_options = merge_launch_options(&preferences.launch_options, node.options.as_ref())
        .map_err(|error| error.to_string())?;
    append_launch_args(&launch_options, &mut spec.args).map_err(|error| error.to_string())?;
    let network = network_payload(&launch_options, &config);
    let address = network["httpProxy"].as_str().unwrap_or_default().to_owned();
    // A subnet-only client (proxyInternet off) refuses Internet targets, so publishing it as
    // the system proxy would break ordinary browsing.
    let proxy_internet = launch_options
        .get("proxyInternet")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let auto_system_proxy = mode == "proxy" && preferences.settings.auto_system_proxy && proxy_internet;
    if auto_system_proxy {
        let endpoint: std::net::SocketAddr = address
            .parse()
            .map_err(|_| "Configure a loopback HTTP proxy port before connecting")?;
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err("System proxy requires a loopback HTTP listener".into());
        }
        let listener = std::net::TcpListener::bind(endpoint)
            .map_err(|e| format!("HTTP proxy port unavailable: {e}"))?;
        drop(listener);
    }
    *state.proxy.lock().map_err(|_| "Proxy lock")? = ProxySession {
        address,
        auto: auto_system_proxy,
        applied: false,
    };
    spec.stats_path = Some(stats_path);
    let pid = process.start(spec).map_err(|error| error.to_string())?;
    *state.network.lock().map_err(|_| "Network lock")? = network.clone();
    *state
        .last_node_id
        .lock()
        .map_err(|_| "最近节点状态锁已损坏".to_string())? = Some(node.id.clone());
    update_tray_phase(state, "starting");
    Ok(ConnectPayload {
        pid,
        network,
        session_id: process.snapshot().session_id,
    })
}

/// Stops the kernel without holding `state.process`: the stop emits tray
/// updates that wait for the main thread, which may itself be waiting on
/// that lock.
fn stop_process(state: &DesktopState) -> Result<ProcessManager, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let mut process = state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .clone();
    process.stop().map_err(|error| error.to_string())?;
    if process.snapshot().recovery_pending {
        let executable = resolve_ppp_path(&preferences.ppp_path)?;
        recover_pending_network(&mut process, &executable, &state.data_dir)?;
    }
    Ok(process)
}

// Graceful stop can wait for the kernel's rollback; keep it off the main thread.
#[tauri::command(async)]
fn client_disconnect(state: State<'_, DesktopState>) -> Result<ConnectionSnapshot, String> {
    let process = stop_process(&state)?;
    if let Err(error) = crate::windows::restore_proxy(
        &state.data_dir.join("proxy-recovery.json"),
        false,
    ) {
        if let Ok(mut manager) = state.process.lock() {
            manager.mark_recovery_pending();
        }
        return Err(error);
    }
    Ok(process.snapshot())
}

#[tauri::command]
fn client_update_config(config: String, state: State<'_, DesktopState>) -> Result<(), String> {
    let value: Value = serde_json::from_str(&config).map_err(|error| error.to_string())?;
    if !value.is_object() {
        return Err("配置根节点必须是 JSON object".into());
    }
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    candidate.raw_config =
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(())
}

fn validated_client_config(
    config: &str,
    options: Value,
) -> Result<(String, BTreeMap<String, Value>), String> {
    let config_value: Value = serde_json::from_str(config).map_err(|error| error.to_string())?;
    if !config_value.is_object() {
        return Err("配置根节点必须是 JSON object".into());
    }
    let object = options
        .as_object()
        .ok_or_else(|| "启动参数必须是 JSON object".to_string())?;
    let launch_options: BTreeMap<String, Value> = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    append_launch_args(&launch_options, &mut Vec::new()).map_err(|error| error.to_string())?;
    let raw_config =
        serde_json::to_string_pretty(&config_value).map_err(|error| error.to_string())?;
    Ok((raw_config, launch_options))
}

#[tauri::command]
fn client_update_client_config(
    config: String,
    options: Value,
    state: State<'_, DesktopState>,
) -> Result<BTreeMap<String, Value>, String> {
    let (raw_config, launch_options) = validated_client_config(&config, options)?;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    candidate.raw_config = raw_config;
    candidate.launch_options = launch_options.clone();
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(launch_options)
}

#[tauri::command]
fn client_upsert_manual_node(
    node: ManualNodeInput,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    upsert_manual_node(&mut candidate.manual_nodes, node).map_err(|error| error.to_string())?;
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    let snapshot = preferences.clone();
    drop(preferences);
    current_subscription_payload(&state, &snapshot)
}

#[tauri::command]
fn client_delete_manual_node(
    node_id: String,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let running = state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .is_running();
    let is_current = state
        .last_node_id
        .lock()
        .map_err(|_| "最近节点状态锁已损坏".to_string())?
        .as_deref()
        == Some(&node_id);
    if running && is_current {
        return Err("正在使用的节点不能删除，请先断开连接".into());
    }

    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    delete_manual_node(&mut candidate.manual_nodes, &node_id).map_err(|error| error.to_string())?;
    candidate.favorites.remove(&node_id);
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    let snapshot = preferences.clone();
    drop(preferences);
    if is_current {
        *state
            .last_node_id
            .lock()
            .map_err(|_| "最近节点状态锁已损坏".to_string())? = None;
    }
    current_subscription_payload(&state, &snapshot)
}

#[tauri::command]
fn client_update_launch_options(
    options: Value,
    state: State<'_, DesktopState>,
) -> Result<BTreeMap<String, Value>, String> {
    let object = options
        .as_object()
        .ok_or_else(|| "启动参数必须是 JSON object".to_string())?;
    let launch_options: BTreeMap<String, Value> = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    append_launch_args(&launch_options, &mut Vec::new()).map_err(|error| error.to_string())?;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    candidate.launch_options = launch_options.clone();
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(launch_options)
}

#[tauri::command]
fn client_update_setting(
    key: String,
    value: Value,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    update_setting(&mut candidate, &key, value).map_err(|error| error.to_string())?;
    if key == "autostart" {
        crate::windows::autostart(candidate.settings.autostart)?;
    }
    if key == "connectionMode"
        && state
            .process
            .lock()
            .map_err(|_| "Process lock")?
            .is_running()
    {
        return Err("Disconnect before changing connection mode".into());
    }
    if key == "autoSystemProxy"
        && state
            .process
            .lock()
            .map_err(|_| "Process lock")?
            .is_running()
    {
        return Err("Disconnect before changing system proxy policy".into());
    }
    if let Err(error) = state.save_preferences(&candidate) {
        if key == "autostart" {
            let _ = crate::windows::autostart(preferences.settings.autostart);
        }
        return Err(error);
    }
    *preferences = candidate;
    Ok(())
}

#[tauri::command]
fn client_toggle_favorite(node_id: String, state: State<'_, DesktopState>) -> Result<(), String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    let mut candidate = preferences.clone();
    if !candidate.favorites.remove(&node_id) {
        candidate.favorites.insert(node_id);
    }
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(())
}

fn current_subscription_payload(
    state: &DesktopState,
    preferences: &Preferences,
) -> Result<SubscriptionPayload, String> {
    let subscription = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?;
    Ok(subscription_payload(subscription.as_ref(), preferences))
}

fn subscription_payload(
    stored: Option<&StoredSubscription>,
    preferences: &Preferences,
) -> SubscriptionPayload {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let subscription_nodes = stored
        .map(|stored| stored.document.nodes.as_slice())
        .unwrap_or_default();
    let nodes = merge_nodes(&preferences.manual_nodes, subscription_nodes);
    let fetched_at_ms = stored.map(|stored| stored.fetched_at_ms).unwrap_or(0);
    let insecure_transport = preferences.subscription_url.starts_with("http://")
        || preferences
            .subscriptions
            .iter()
            .any(|s| s.enabled && s.url.trim_start().starts_with("http://"));
    SubscriptionPayload {
        insecure_transport,
        url: preferences.subscription_url.clone(),
        name: stored
            .and_then(|stored| stored.document.name.clone())
            .clone()
            .unwrap_or_else(|| "本地节点".into()),
        updated_at: stored.and_then(|stored| stored.document.updated_at.clone()),
        last_synced_at: fetched_at_ms,
        cached: stored.is_some_and(|stored| stored.cached),
        cache_age_minutes: if fetched_at_ms == 0 {
            0
        } else {
            now.saturating_sub(fetched_at_ms) / 60_000
        },
        nodes: nodes
            .iter()
            .map(|node| NodePayload {
                id: node.id.clone(),
                name: node.name.clone(),
                subtitle: node.subtitle.clone(),
                address: display_address(node.server.as_deref().unwrap_or_default()),
                latency_ms: None,
                favorite: preferences.favorites.contains(&node.id),
                source: node_source(&preferences.manual_nodes, &node.id),
                config: node.config.clone().or_else(|| {
                    build_node_config_with_base(node, Some(&preferences.raw_config)).ok()
                }),
                options: node.options.clone(),
                source_id: node
                    .id
                    .strip_prefix("sub:")
                    .and_then(|id| id.split(':').next())
                    .unwrap_or("manual")
                    .into(),
                source_name: preferences
                    .subscriptions
                    .iter()
                    .find(|s| node.id.starts_with(&format!("sub:{}:", s.id)))
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| "Local".into()),
            })
            .collect(),
        sources: preferences.subscriptions.clone(),
    }
}

fn display_address(server: &str) -> String {
    let body = server.strip_prefix("ppp://").unwrap_or(server);
    let body = body
        .strip_prefix("ws/")
        .or_else(|| body.strip_prefix("wss/"))
        .unwrap_or(body);
    body.split('/').next().unwrap_or(body).to_owned()
}

fn network_payload(options: &BTreeMap<String, Value>, config: &Value) -> Value {
    let client = config.get("client");
    let proxy = |name: &str| {
        client
            .and_then(|value| value.get(name))
            .and_then(Value::as_object)
            .map(|value| {
                format!(
                    "{}:{}",
                    value
                        .get("bind")
                        .and_then(Value::as_str)
                        .unwrap_or("127.0.0.1"),
                    value.get("port").and_then(Value::as_u64).unwrap_or(0)
                )
            })
            .filter(|value| !value.ends_with(":0"))
            .unwrap_or_default()
    };
    json!({
        "tunIp": options.get("tunIp").and_then(Value::as_str).unwrap_or(""),
        "gateway": options.get("gateway").and_then(Value::as_str).unwrap_or(""),
        "httpProxy": proxy("http-proxy"), "socksProxy": proxy("socks-proxy"),
    })
}

/// Uses the GUI-managed policy v2 for this connection when the user enabled it.
fn apply_local_policy(
    config: &mut Value,
    preferences: &Preferences,
    state: &DesktopState,
) -> Result<(), String> {
    if !preferences.policy_enabled {
        return Ok(());
    }
    let policy = Workspace::new(state.policy_dir())
        .load()?
        .policy
        .ok_or("Local policy v2 is enabled but not created yet; create it on the Policy page or turn it off")?;
    let client = config
        .get_mut("client")
        .and_then(Value::as_object_mut)
        .ok_or("Node configuration has no client object")?;
    client.insert("policy".into(), policy);
    Ok(())
}

/// Resolves the kernel and requires `ppp policy` support. An older kernel
/// would ignore `client.policy` and, worse, start a client for `ppp policy`.
fn policy_kernel(state: &DesktopState) -> Result<PathBuf, String> {
    let configured = state
        .preferences
        .lock()
        .map_err(|_| "Preferences lock")?
        .ppp_path
        .clone();
    let path = resolve_ppp_path(&configured)?;
    let modified = fs::metadata(&path).and_then(|m| m.modified()).ok();
    let cached = state
        .policy_kernel
        .lock()
        .map_err(|_| "Kernel lock")?
        .clone()
        .filter(|(cached, time, _)| *cached == path && *time == modified);
    let supported = match cached {
        Some((_, _, supported)) => supported,
        None => {
            let info = crate::kernel::inspect(&path)?;
            let supported = info["policySupported"].as_bool().ok_or_else(|| {
                format!("Unable to determine kernel policy v2 support: version={}; probe={}",
                    info["version"].as_str().unwrap_or("Unknown"),
                    info["probeError"].as_str().unwrap_or("no recognizable version"))
            })?;
            *state.policy_kernel.lock().map_err(|_| "Kernel lock")? =
                Some((path.clone(), modified, supported));
            supported
        }
    };
    if supported {
        Ok(path)
    } else {
        Err("The selected ppp kernel does not support policy v2 (requires 2.1.7 or later)".into())
    }
}

fn policy_staging(state: &DesktopState) -> Result<Staging, String> {
    Staging::new(&state.data_dir.join("policy-staging"))
}

fn policy_runtime(state: &DesktopState) -> Result<&'static str, String> {
    let preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
    Ok(crate::policy::runtime_for_mode(&preferences.settings.connection_mode))
}

fn check_policy_before_connect(
    config: &Value,
    connection_mode: &str,
    state: &DesktopState,
) -> Result<(), String> {
    let kernel = policy_kernel(state)?;
    let staging = policy_staging(state)?;
    let path = staging.path("config.json");
    let policy_only = json!({ "client": { "policy": config["client"]["policy"] } });
    fs::write(&path, serde_json::to_vec(&policy_only).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let result = crate::policy::run(
        &kernel,
        &[
            "check".into(),
            "--config".into(),
            path.to_string_lossy().into_owned(),
            "--runtime".into(),
            crate::policy::runtime_for_mode(connection_mode).into(),
        ],
        crate::policy::OFFLINE_TIMEOUT,
    )?;
    if result.ok() {
        Ok(())
    } else {
        Err(format!("Policy check failed:\n{}", result.summary()))
    }
}

/// Validates a draft with `ppp policy check` without touching the workspace.
fn check_draft(state: &DesktopState, policy: &Value, rules: &str) -> Result<PolicyReport, String> {
    let kernel = policy_kernel(state)?;
    let staging = policy_staging(state)?;
    let config = staging.write_draft(policy, rules, &state.policy_dir())?;
    crate::policy::run(
        &kernel,
        &[
            "check".into(),
            "--config".into(),
            config.to_string_lossy().into_owned(),
            "--runtime".into(),
            policy_runtime(state)?.into(),
        ],
        crate::policy::OFFLINE_TIMEOUT,
    )
}

#[tauri::command(async)]
fn policy_load(state: State<'_, DesktopState>) -> Result<PolicyPayload, String> {
    let enabled = state.preferences.lock().map_err(|_| "Preferences lock")?.policy_enabled;
    let content = Workspace::new(state.policy_dir()).load()?;
    let (kernel_supported, kernel_error) = match policy_kernel(&state) {
        Ok(_) => (Some(true), String::new()),
        Err(error) => (
            state
                .policy_kernel
                .lock()
                .ok()
                .and_then(|cached| cached.as_ref().map(|(_, _, supported)| *supported)),
            error,
        ),
    };
    Ok(PolicyPayload {
        enabled,
        policy_dir: state.policy_dir().to_string_lossy().into_owned(),
        policy: content.policy,
        rules: content.rules,
        kernel_supported,
        kernel_error,
    })
}

#[tauri::command(async)]
fn policy_set_enabled(enabled: bool, state: State<'_, DesktopState>) -> Result<bool, String> {
    if enabled && Workspace::new(state.policy_dir()).load()?.policy.is_none() {
        return Err("Create and save a policy before enabling it".into());
    }
    let mut preferences = state.preferences.lock().map_err(|_| "Preferences lock")?;
    let mut candidate = preferences.clone();
    candidate.policy_enabled = enabled;
    state.save_preferences(&candidate)?;
    *preferences = candidate;
    Ok(enabled)
}

/// Saves only a draft that passes `ppp policy check`; otherwise returns the
/// report so the editor can show the diagnostics.
#[tauri::command(async)]
fn policy_save(
    policy: Value,
    rules: String,
    state: State<'_, DesktopState>,
) -> Result<PolicyDraftPayload, String> {
    let result = check_draft(&state, &policy, &rules)?;
    if result.ok() {
        Workspace::new(state.policy_dir()).save(&policy, &rules)?;
    }
    Ok(PolicyDraftPayload { policy: Some(policy), rules, result })
}

#[tauri::command(async)]
fn policy_check(
    policy: Value,
    rules: String,
    state: State<'_, DesktopState>,
) -> Result<PolicyReport, String> {
    check_draft(&state, &policy, &rules)
}

#[tauri::command(async)]
fn policy_explain(
    policy: Value,
    rules: String,
    target: String,
    network: String,
    port: Option<u16>,
    state: State<'_, DesktopState>,
) -> Result<PolicyReport, String> {
    let kernel = policy_kernel(&state)?;
    let staging = policy_staging(&state)?;
    let config = staging.write_draft(&policy, &rules, &state.policy_dir())?;
    let args = crate::policy::explain_args(&config, policy_runtime(&state)?, &target, &network, port)?;
    crate::policy::run(&kernel, &args, crate::policy::OFFLINE_TIMEOUT)
}

/// Generates a template draft; nothing is saved until the user saves it.
#[tauri::command(async)]
fn policy_init(
    template: String,
    geoip: Option<String>,
    geosite: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<PolicyDraftPayload, String> {
    if !crate::policy::TEMPLATES.contains(&template.as_str()) {
        return Err("Unknown policy template".into());
    }
    let kernel = policy_kernel(&state)?;
    let staging = policy_staging(&state)?;
    let mut args = vec![
        "init".into(),
        "--out".into(),
        staging.path("out").to_string_lossy().into_owned(),
        "--template".into(),
        template.clone(),
        "--runtime".into(),
        policy_runtime(&state)?.into(),
    ];
    for (flag, value) in [("--geoip", geoip), ("--geosite", geosite)] {
        if let Some(value) = value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()) {
            args.extend([flag.to_owned(), value]);
        }
    }
    let result = crate::policy::run(&kernel, &args, crate::policy::OFFLINE_TIMEOUT)?;
    if !result.ok() {
        return Ok(PolicyDraftPayload { policy: None, rules: String::new(), result });
    }
    let content = staging.read_output("out")?;
    Ok(PolicyDraftPayload { policy: content.policy, rules: content.rules, result })
}

/// Drafts a v2 policy from the current v1 settings (base config plus network
/// overrides). Exit code 5 means the draft differs and needs review.
#[tauri::command(async)]
fn policy_migrate(state: State<'_, DesktopState>) -> Result<PolicyDraftPayload, String> {
    let kernel = policy_kernel(&state)?;
    let preferences = state.preferences.lock().map_err(|_| "Preferences lock")?.clone();
    let mut legacy: Value = serde_json::from_str(if preferences.raw_config.trim().is_empty() {
        default_config_string()
    } else {
        &preferences.raw_config
    })
    .map_err(|e| e.to_string())?;
    if preferences.network_overrides.is_object() {
        apply_network_overrides(&mut legacy, &preferences.network_overrides).map_err(|e| e.to_string())?;
    }
    if crate::config::uses_policy_v2(&legacy) {
        return Err("The base configuration already uses policy v2".into());
    }
    let staging = policy_staging(&state)?;
    let source = staging.path("legacy.json");
    fs::write(&source, serde_json::to_vec_pretty(&legacy).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let result = crate::policy::run(
        &kernel,
        &[
            "migrate".into(),
            "--config".into(),
            source.to_string_lossy().into_owned(),
            "--out".into(),
            staging.path("out").to_string_lossy().into_owned(),
            "--runtime".into(),
            crate::policy::runtime_for_mode(&preferences.settings.connection_mode).into(),
        ],
        crate::policy::OFFLINE_TIMEOUT,
    )?;
    if !matches!(result.exit_code, 0 | 5) {
        return Ok(PolicyDraftPayload { policy: None, rules: String::new(), result });
    }
    let content = staging.read_output("out")?;
    Ok(PolicyDraftPayload { policy: content.policy, rules: content.rules, result })
}

/// Status and update use the runtime config path: the kernel derives the
/// policy identity and the `.ppp-policy` store from it.
fn runtime_policy_config(state: &DesktopState) -> Result<(PathBuf, Value), String> {
    let path = state.data_dir.join("runtime").join("appsettings.json");
    let config: Value = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(crate::config::uses_policy_v2)
        .ok_or("No policy status yet: connect once with policy v2 enabled")?;
    Ok((path, config))
}

#[tauri::command(async)]
fn policy_status(state: State<'_, DesktopState>) -> Result<PolicyReport, String> {
    let kernel = policy_kernel(&state)?;
    let (path, _) = runtime_policy_config(&state)?;
    crate::policy::run(
        &kernel,
        &["status".into(), "--config".into(), path.to_string_lossy().into_owned()],
        crate::policy::OFFLINE_TIMEOUT,
    )
}

/// Downloads remote rule sets through the running session's SOCKS listener.
/// The result is prepared for the next start; the running session keeps its
/// active policy unless `updates.enabled` publishes into it.
#[tauri::command(async)]
fn policy_update(state: State<'_, DesktopState>) -> Result<PolicyReport, String> {
    let kernel = policy_kernel(&state)?;
    let (path, config) = runtime_policy_config(&state)?;
    if config.pointer("/client/policy/updates/via").and_then(Value::as_str) != Some("proxy") {
        return Err("Manual update runs through the tunnel; set updates.via to proxy".into());
    }
    if !state.process.lock().map_err(|_| "Process lock")?.is_running() {
        return Err("Connect first: manual update uses the session's SOCKS listener".into());
    }
    let endpoint = state.network.lock().map_err(|_| "Network lock")?["socksProxy"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    if endpoint.parse::<std::net::SocketAddr>().map_or(true, |address| !address.ip().is_loopback()) {
        return Err("Manual update needs a loopback SOCKS listener".into());
    }
    crate::policy::run(
        &kernel,
        &[
            "update".into(),
            "--config".into(),
            path.to_string_lossy().into_owned(),
            "--proxy-endpoint".into(),
            endpoint,
        ],
        crate::policy::UPDATE_TIMEOUT,
    )
}

/// Clears Fake-IP mappings. Only while disconnected, and only inside the app
/// data directory; clients must also drop cached DNS answers from the pool.
#[tauri::command(async)]
fn policy_reset_fake_ip(state: State<'_, DesktopState>) -> Result<String, String> {
    if state.process.lock().map_err(|_| "Process lock")?.is_running() {
        return Err("Disconnect before resetting Fake-IP storage".into());
    }
    let runtime_dir = state.data_dir.join("runtime");
    let config = runtime_policy_config(&state).map(|(_, config)| config).unwrap_or(Value::Null);
    let storage = crate::policy::fake_ip_storage(&config, &runtime_dir);
    let data_dir = fs::canonicalize(&state.data_dir).map_err(|e| e.to_string())?;
    match fs::canonicalize(&storage) {
        Err(_) => return Ok("Fake-IP storage is already empty".into()),
        Ok(resolved) if !resolved.starts_with(&data_dir) || resolved == data_dir => {
            return Err(format!("Refusing to delete Fake-IP storage outside app data: {}", storage.display()))
        }
        Ok(resolved) if resolved.is_dir() => fs::remove_dir_all(&resolved).map_err(|e| e.to_string())?,
        Ok(resolved) => fs::remove_file(&resolved).map_err(|e| e.to_string())?,
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(0x0800_0000)
            .status();
    }
    Ok("Fake-IP storage cleared".into())
}

/// Elevated runs must not execute a binary chosen through the user-writable
/// preferences file unless it sits beside the app or under Program Files.
fn elevated_ppp_path_allowed(path: &Path) -> bool {
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        roots.push(dir);
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(value) = std::env::var_os(var) {
            roots.push(PathBuf::from(value));
        }
    }
    roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| path.starts_with(root))
}

fn resolve_ppp_path(configured: &str) -> Result<PathBuf, String> {
    let elevated = crate::windows::administrator();
    let path = if configured.trim().is_empty() {
        let name = if cfg!(windows) { "ppp.exe" } else { "ppp" };
        std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .unwrap_or(Path::new("."))
            .join(name)
    } else {
        PathBuf::from(configured)
    };
    if !path.is_file() {
        return Err(format!("找不到 ppp 可执行文件: {}", path.display()));
    }
    if elevated && !configured.trim().is_empty() && !elevated_ppp_path_allowed(&path) {
        return Err(format!(
            "管理员模式下只允许使用应用目录或 Program Files 下的 ppp: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::storage::write(path, bytes)
}

fn update_tray(state: &DesktopState, running: bool, node_name: Option<&str>) {
    // Native menu calls can wait on the main thread; never retain the mutex here.
    let Some(items) = state.tray_items.lock().ok().and_then(|items| items.clone()) else {
        return;
    };
    let status = if running {
        match node_name {
            Some(name) => format!("状态：已连接 - {name}"),
            None => "状态：已连接".to_string(),
        }
    } else {
        "状态：未连接".to_string()
    };
    let _ = items.status.set_text(status);
    let _ = items
        .primary
        .set_text(if running { "断开连接" } else { "连接" });
}

fn update_tray_phase(state: &DesktopState, phase: &str) {
    update_tray(state, !["disconnected", "error"].contains(&phase), None);
    let items = state.tray_items.lock().ok().and_then(|items| items.clone());
    if let Some(items) = items {
        let _ = items.status.set_text(format!("OpenPPP2: {phase}"));
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn handle_tray_primary(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<DesktopState>();
    let running = state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .is_running();
    let last_node_id = state
        .last_node_id
        .lock()
        .map_err(|_| "最近节点状态锁已损坏".to_string())?
        .clone();
    match tray_primary_action(running, last_node_id.as_deref()) {
        TrayPrimaryAction::Connect(node_id) => {
            connect_node(&node_id, &state)?;
        }
        TrayPrimaryAction::Disconnect => {
            let app = app.clone();
            std::thread::spawn(move || {
                let state = app.state::<DesktopState>();
                match stop_process(&state) {
                    Ok(_) => update_tray(&state, false, None),
                    Err(error) => {
                        let _ = app.emit("client://tray-error", error);
                    }
                }
            });
        }
        TrayPrimaryAction::ShowWindow => show_main_window(app),
    }
    Ok(())
}

fn prepare_exit(app: &AppHandle) {
    let state = app.state::<DesktopState>();
    if state.exit_requested.swap(true, Ordering::SeqCst) {
        return;
    }
    if should_disconnect_on_exit(true) {
        if let Err(error) = stop_process(&state) {
            let _ = app.emit("client://tray-error", error);
        }
        if let Err(error) =
            crate::windows::restore_proxy(&state.data_dir.join("proxy-recovery.json"), false)
        {
            if let Ok(mut manager) = state.process.lock() {
                manager.mark_recovery_pending();
            }
            let _ = app.emit("client://tray-error", error);
        }
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "状态：未连接", false, None::<&str>)?;
    let primary = MenuItem::with_id(app, "primary", "连接", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "打开 OpenPPP2", true, None::<&str>)?;
    let exit = MenuItem::with_id(app, "exit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &primary, &show, &exit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("OpenPPP2 Client")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "primary" => {
                if let Err(error) = handle_tray_primary(app) {
                    let _ = app.emit("client://tray-error", error);
                    show_main_window(app);
                }
            }
            "show" => show_main_window(app),
            "exit" => {
                prepare_exit(app);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;

    if let Ok(mut items) = app.state::<DesktopState>().tray_items.lock() {
        *items = Some(TrayItems { status, primary });
    }
    Ok(())
}

pub fn run() {
    if !cfg!(windows) {
        eprintln!("OpenPPP2 Client 只支持 Windows，并需要外部 ppp.exe。");
        return;
    }
    let app = tauri::Builder::default()
        .setup(|app| {
            let state = match DesktopState::new(&app.handle()) {
                Ok(state) => state,
                Err(error) if error == crate::windows::ALREADY_RUNNING => {
                    // A second launch shows the running client instead of exiting silently.
                    crate::windows::activate_existing(
                        "OpenPPP2 Client",
                        "OpenPPP2 已在运行，请从任务栏托盘图标打开。\nOpenPPP2 is already running; open it from the tray icon.",
                    );
                    std::process::exit(0);
                }
                Err(error) => return Err(error.into()),
            };
            app.manage(state);
            setup_tray(app)?;
            if let Some(path) = std::env::args()
                .find_map(|arg| arg.strip_prefix("--elevated-ready=").map(PathBuf::from))
            {
                fs::write(path, b"ready")?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<DesktopState>();
                let close_to_tray = state
                    .preferences
                    .lock()
                    .map(|preferences| preferences.settings.close_to_tray)
                    .unwrap_or(true);
                match close_action(close_to_tray, state.exit_requested.load(Ordering::SeqCst)) {
                    CloseAction::HideToTray => {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                    CloseAction::Exit => {
                        api.prevent_close();
                        prepare_exit(window.app_handle());
                        window.app_handle().exit(0);
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            policy_load,
            policy_set_enabled,
            policy_save,
            policy_check,
            policy_explain,
            policy_init,
            policy_migrate,
            policy_status,
            policy_update,
            policy_reset_fake_ip,
            client_bootstrap,
            subscription_refresh,
            client_probe_latency,
            client_connect,
            client_disconnect,
            client_update_config,
            client_update_client_config,
            client_upsert_manual_node,
            client_delete_manual_node,
            client_update_launch_options,
            client_update_setting,
            client_toggle_favorite,
            client_save_subscription,
            client_delete_subscription,
            client_update_network,
            client_restore_proxy,
            client_retry_recovery,
            client_pick_executable,
            client_elevate,
            client_kernel_info,
            client_preview,
            client_open_data,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build OpenPPP2 Client");
    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            prepare_exit(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{load_sources, subscription_payload, validated_client_config, StoredSubscription};
    use crate::manual_nodes::upsert_manual_node;
    use crate::manual_nodes::{ManualNodeInput, NodeSource};
    use crate::preferences::Preferences;
    use crate::subscription::{parse_subscription, RefreshResult};
    use serde_json::json;

    #[test]
    fn verified_empty_journal_clears_recovery_without_deleting_the_journal() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("data");
        let core_dir = directory.path().join("core");
        let journal_dir = core_dir.join("network-recovery");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&journal_dir).unwrap();
        let journal = journal_dir.join("network-recovery.journal");
        let header = b"NWRJ|1|test-owner|empty-checksum\n";
        std::fs::write(&journal, header).unwrap();
        super::persist_network_recovery_marker(&data_dir).unwrap();
        let executable = core_dir.join("ppp.exe");
        let mut process = crate::process::ProcessManager::new(|_| {});
        process.mark_recovery_pending();

        super::recover_pending_network_with(
            &mut process, &executable, &data_dir, |_, spec| {
                assert_eq!(spec.program, executable);
                assert_eq!(spec.args, vec![
                    "--network-recovery".to_string(),
                    format!("--network-recovery-dir={}", journal_dir.display()),
                ]);
                Ok(true)
            },
        ).unwrap();

        assert_eq!(std::fs::read(&journal).unwrap(), header);
        assert!(!super::network_recovery_marker(&data_dir).exists());
        assert!(!process.snapshot().recovery_pending);
        assert_eq!(process.snapshot().status, "disconnected");

        // Next startup sees the retained header and validates it again.
        process.mark_recovery_pending();
        super::recover_pending_network_with(
            &mut process, &executable, &data_dir, |_, _| Ok(true),
        ).unwrap();
        assert!(!process.snapshot().recovery_pending);
        assert!(journal.exists());
    }

    #[test]
    fn failed_or_unavailable_recovery_worker_keeps_the_durable_gate() {
        for result in [Ok(false), Err("worker unavailable".to_string())] {
            let directory = tempfile::tempdir().unwrap();
            super::persist_network_recovery_marker(directory.path()).unwrap();
            let marker = super::network_recovery_marker(directory.path());
            let original = std::fs::read(&marker).unwrap();
            let mut process = crate::process::ProcessManager::new(|_| {});
            process.mark_recovery_pending();
            assert!(super::recover_pending_network_with(
                &mut process, &directory.path().join("ppp.exe"), directory.path(),
                |_, _| result,
            ).is_err());
            assert!(process.snapshot().recovery_pending);
            assert_eq!(std::fs::read(&marker).unwrap(), original);
        }
    }

    #[test]
    fn successful_worker_cannot_clear_an_unremovable_marker() {
        let directory = tempfile::tempdir().unwrap();
        let marker = super::network_recovery_marker(directory.path());
        std::fs::create_dir(&marker).unwrap();
        let mut process = crate::process::ProcessManager::new(|_| {});
        process.mark_recovery_pending();
        assert!(super::recover_pending_network_with(
            &mut process, &directory.path().join("ppp.exe"), directory.path(),
            |_, _| Ok(true),
        ).is_err());
        assert!(marker.is_dir());
        assert!(process.snapshot().recovery_pending);
    }

    #[test]
    fn successful_core_recovery_does_not_hide_a_proxy_recovery_failure() {
        let directory = tempfile::tempdir().unwrap();
        super::persist_network_recovery_marker(directory.path()).unwrap();
        let proxy = directory.path().join("proxy-recovery.json");
        std::fs::write(&proxy, b"invalid backup").unwrap();
        let mut process = crate::process::ProcessManager::new(|_| {});
        process.mark_recovery_pending();
        assert!(super::recover_pending_network_with(
            &mut process, &directory.path().join("ppp.exe"), directory.path(),
            |_, _| Ok(true),
        ).is_err());
        assert!(!super::network_recovery_marker(directory.path()).exists());
        assert!(proxy.exists());
        assert!(process.snapshot().recovery_pending);
    }

    #[test]
    fn stored_subscription_keeps_cache_metadata() {
        let document = parse_subscription(br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"n","name":"N","server":"ppp://127.0.0.1:1/","key":{"protocol-key":"p"}}]}"#).unwrap();
        let stored = StoredSubscription::from(RefreshResult {
            document,
            cached: true,
            fetched_at_ms: 42,
        });
        assert!(stored.cached);
        assert_eq!(stored.fetched_at_ms, 42);
    }

    #[test]
    fn combined_payload_marks_manual_nodes_and_exposes_edit_data() {
        let mut preferences = Preferences::default();
        upsert_manual_node(
            &mut preferences.manual_nodes,
            ManualNodeInput {
                id: None,
                name: "Local".into(),
                subtitle: "Desktop".into(),
                config: json!({
                    "key": { "protocol-key": "p" },
                    "client": { "server": "ppp://127.0.0.1:20000/" }
                }),
                options: json!({ "mux": 2 }),
            },
        )
        .unwrap();
        let payload = subscription_payload(None, &preferences);
        assert_eq!(payload.nodes.len(), 1);
        assert_eq!(payload.nodes[0].source, NodeSource::Manual);
        assert!(payload.nodes[0]
            .config
            .as_ref()
            .is_some_and(|value| value.is_object()));
        assert_eq!(payload.nodes[0].options.as_ref().unwrap()["mux"], 2);
    }

    #[test]
    fn combined_client_config_validates_both_inputs_before_save() {
        let (config, options) = validated_client_config(
            r#"{"concurrent":2}"#,
            json!({ "mux": 4, "muxMode": "flow", "vnet": true }),
        )
        .unwrap();
        assert!(config.contains("\"concurrent\": 2"));
        assert_eq!(options["mux"], 4);

        assert!(validated_client_config("[]", json!({})).is_err());
        assert!(validated_client_config(
            r#"{"concurrent":2}"#,
            json!({ "muxMode": "unsupported" }),
        )
        .is_err());
    }

    #[test]
    fn separate_subscriptions_keep_duplicate_ids_and_isolate_caches() {
        use crate::preferences::SubscriptionSource;
        use crate::subscription::refresh_with;
        let directory = tempfile::tempdir().unwrap();
        let mut preferences = Preferences::default();
        for id in ["one", "two"] {
            let url = format!("https://{id}.test/sub");
            let source = SubscriptionSource {
                id: id.into(),
                name: id.into(),
                url: url.clone(),
                enabled: true,
                last_synced_at: 0,
                cached: false,
                error: String::new(),
            };
            refresh_with(&url,&directory.path().join(format!("subscription-{id}.json")),|_| Ok(br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"same","config":{}}]}"#.to_vec())).unwrap();
            preferences.subscriptions.push(source);
        }
        let stored = load_sources(directory.path(), &preferences).unwrap();
        assert_eq!(stored.document.nodes[0].id, "sub:one:same");
        assert_eq!(stored.document.nodes[1].id, "sub:two:same");
        preferences.subscriptions[0].url = "https://changed.test/sub".into();
        let stored = load_sources(directory.path(), &preferences).unwrap();
        assert_eq!(stored.document.nodes.len(), 1);
        assert_eq!(stored.document.nodes[0].id, "sub:two:same");
    }
}
