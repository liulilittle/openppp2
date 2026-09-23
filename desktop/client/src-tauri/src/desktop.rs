use crate::config::{build_node_config_with_base, default_config_string};
use crate::launch_options::{append_launch_args, merge_launch_options};
use crate::lifecycle::{
    close_action, should_disconnect_on_exit, tray_primary_action, CloseAction, TrayPrimaryAction,
};
use crate::manual_nodes::{
    delete_manual_node, find_node, merge_nodes, node_source, upsert_manual_node, ManualNodeInput,
    NodeSource,
};
use crate::pinger::{probe_nodes, targets_for_nodes};
use crate::preferences::{load_preferences, save_preferences, update_setting, Preferences};
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
    tray_items: Mutex<Option<TrayItems>>,
    exit_requested: AtomicBool,
}

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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectPayload {
    pid: u32,
    network: Value,
}

impl DesktopState {
    fn new(app: &AppHandle) -> Result<Self, String> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|error| error.to_string())?;
        fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
        let preferences = load_preferences(&data_dir.join("preferences.json"))
            .map_err(|error| error.to_string())?;
        let cached = if preferences.subscription_url.is_empty() {
            None
        } else {
            refresh_with(
                &preferences.subscription_url,
                &data_dir.join("subscription-cache.json"),
                |_| Err("startup".into()),
            )
            .ok()
        };
        let subscription = cached.map(StoredSubscription::from);
        let emitter = app.clone();
        let process = ProcessManager::new(move |event| {
            let exited = matches!(&event, ProcessEvent::Exited(_));
            let _ = emitter.emit("client://process", event);
            if exited {
                let state = emitter.state::<DesktopState>();
                update_tray(&state, false, None);
            }
        });
        Ok(Self {
            data_dir,
            preferences: Mutex::new(preferences),
            subscription: Mutex::new(subscription),
            process: Mutex::new(process),
            last_node_id: Mutex::new(None),
            tray_items: Mutex::new(None),
            exit_requested: AtomicBool::new(false),
        })
    }

    fn save_preferences(&self, preferences: &Preferences) -> Result<(), String> {
        save_preferences(&self.data_dir.join("preferences.json"), preferences)
            .map_err(|error| error.to_string())
    }
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
            "pppPath": preferences.ppp_path,
        }),
    })
}

#[tauri::command]
async fn subscription_refresh(
    url: String,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let parsed = Url::parse(&url).map_err(|_| "订阅地址无效".to_string())?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("订阅地址只支持 HTTP/HTTPS".into());
    }
    let cache_path = state.data_dir.join("subscription-cache.json");
    let fetch_url = url.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
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
    .map_err(|error| error.to_string())??;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    preferences.subscription_url = url;
    state.save_preferences(&preferences)?;
    let stored = StoredSubscription::from(result);
    let payload = subscription_payload(Some(&stored), &preferences);
    *state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())? = Some(stored);
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
    let config = build_node_config_with_base(&node, Some(&preferences.raw_config))
        .map_err(|error| error.to_string())?;
    let runtime_dir = state.data_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).map_err(|error| error.to_string())?;
    let config_path = runtime_dir.join("appsettings.json");
    write_atomic(
        &config_path,
        &serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?,
    )?;
    let stats_path = runtime_dir.join("stats.ndjson");
    let executable = resolve_ppp_path(&preferences.ppp_path)?;
    let mut spec = CommandSpec::new(
        executable,
        [
            "--mode=client".to_string(),
            format!("--config={}", config_path.display()),
            format!("--stats-json={}", stats_path.display()),
        ],
    );
    let launch_options = merge_launch_options(&preferences.launch_options, node.options.as_ref())
        .map_err(|error| error.to_string())?;
    append_launch_args(&launch_options, &mut spec.args).map_err(|error| error.to_string())?;
    spec.stats_path = Some(stats_path);
    let pid = state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .start(spec)
        .map_err(|error| error.to_string())?;
    *state
        .last_node_id
        .lock()
        .map_err(|_| "最近节点状态锁已损坏".to_string())? = Some(node.id.clone());
    update_tray(state, true, Some(&node.name));
    Ok(ConnectPayload {
        pid,
        network: network_payload(&launch_options, &config),
    })
}

#[tauri::command]
fn client_disconnect(state: State<'_, DesktopState>) -> Result<(), String> {
    state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .stop()
        .map_err(|error| error.to_string())
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
    preferences.raw_config =
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;
    state.save_preferences(&preferences)
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
    preferences.raw_config = raw_config;
    preferences.launch_options = launch_options.clone();
    state.save_preferences(&preferences)?;
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
    upsert_manual_node(&mut preferences.manual_nodes, node).map_err(|error| error.to_string())?;
    state.save_preferences(&preferences)?;
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
    delete_manual_node(&mut preferences.manual_nodes, &node_id)
        .map_err(|error| error.to_string())?;
    preferences.favorites.remove(&node_id);
    state.save_preferences(&preferences)?;
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
    preferences.launch_options = launch_options.clone();
    state.save_preferences(&preferences)?;
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
    update_setting(&mut preferences, &key, value).map_err(|error| error.to_string())?;
    state.save_preferences(&preferences)
}

#[tauri::command]
fn client_toggle_favorite(node_id: String, state: State<'_, DesktopState>) -> Result<(), String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    if !preferences.favorites.remove(&node_id) {
        preferences.favorites.insert(node_id);
    }
    state.save_preferences(&preferences)
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
    SubscriptionPayload {
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
                config: node.config.clone(),
                options: node.options.clone(),
            })
            .collect(),
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

fn resolve_ppp_path(configured: &str) -> Result<PathBuf, String> {
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
    Ok(path)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

fn update_tray(state: &DesktopState, running: bool, node_name: Option<&str>) {
    let Ok(items) = state.tray_items.lock() else {
        return;
    };
    let Some(items) = items.as_ref() else {
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
            state
                .process
                .lock()
                .map_err(|_| "进程状态锁已损坏".to_string())?
                .stop()
                .map_err(|error| error.to_string())?;
            update_tray(&state, false, None);
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
    let disconnect = state
        .preferences
        .lock()
        .map(|preferences| preferences.settings.disconnect_on_exit)
        .unwrap_or(true);
    if should_disconnect_on_exit(disconnect) {
        let result = state
            .process
            .lock()
            .map_err(|_| "进程状态锁已损坏".to_string())
            .and_then(|mut process| process.stop().map_err(|error| error.to_string()));
        if let Err(error) = result {
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
    let app = tauri::Builder::default()
        .setup(|app| {
            app.manage(DesktopState::new(&app.handle())?);
            setup_tray(app)?;
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
    use super::{subscription_payload, validated_client_config, StoredSubscription};
    use crate::manual_nodes::upsert_manual_node;
    use crate::manual_nodes::{ManualNodeInput, NodeSource};
    use crate::preferences::Preferences;
    use crate::subscription::{parse_subscription, RefreshResult};
    use serde_json::json;

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
}
