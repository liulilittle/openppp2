//! Desktop side of policy v2: the GUI-managed policy workspace and the
//! offline `ppp policy` commands (check, explain, init, migrate, status,
//! update) that the kernel exposes with `--json` reports.

use crate::config::prepare_policy_v2;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const POLICY_FILE: &str = "policy.json";
pub const RULES_FILE: &str = "routing.rules";
pub const TEMPLATES: [&str; 3] = ["direct-all", "proxy-all", "split-cn"];
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
pub const OFFLINE_TIMEOUT: Duration = Duration::from_secs(20);
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReport {
    pub exit_code: i32,
    pub report: Value,
}

impl PolicyReport {
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }

    /// One line per error diagnostic, for refusing a connection.
    pub fn summary(&self) -> String {
        let lines = self.report["diagnostics"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|item| item["severity"].as_str() != Some("warning"))
            .map(|item| {
                let mut line = format!(
                    "{}: {}",
                    item["code"].as_str().unwrap_or("E_POLICY"),
                    item["message"].as_str().unwrap_or_default()
                );
                if let Some(source) = item["source"].as_str().filter(|s| !s.is_empty()) {
                    line.push_str(&format!(" ({source}:{})", item["line"].as_u64().unwrap_or(0)));
                }
                line
            })
            .collect::<Vec<_>>();
        if lines.is_empty() {
            format!("policy {} exited with {}", self.report["command"].as_str().unwrap_or(""), self.exit_code)
        } else {
            lines.join("\n")
        }
    }
}

/// Runtime name `ppp policy` uses for capability checks.
pub fn runtime_for_mode(connection_mode: &str) -> &'static str {
    if connection_mode == "proxy" {
        "socks"
    } else {
        "tun"
    }
}

/// Runs `ppp policy <args> --json` and parses its schema 1 report. The kernel
/// writes the report on stdout for every exit code it documents (0, 2-5).
pub fn run(kernel: &Path, args: &[String], timeout: Duration) -> Result<PolicyReport, String> {
    let mut command = Command::new(kernel);
    command
        .arg("policy")
        .args(args)
        .arg("--json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().map_err(|e| format!("Cannot run ppp policy: {e}"))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let readers = [stdout_reader(stdout), stdout_reader(stderr)];
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("ppp policy timed out after {} s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let [stdout, stderr] = readers.map(|reader| reader.join().unwrap_or_default());
    let report: Value = serde_json::from_str(stdout.trim()).map_err(|_| {
        let detail = stderr.lines().chain(stdout.lines()).find(|l| !l.trim().is_empty());
        format!("ppp policy returned no JSON report{}", detail.map(|d| format!(": {d}")).unwrap_or_default())
    })?;
    Ok(PolicyReport {
        exit_code: status.code().unwrap_or(-1),
        report,
    })
}

fn stdout_reader<R: Read + Send + 'static>(stream: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stream.take(MAX_REPORT_BYTES).read_to_string(&mut text);
        text
    })
}

/// The GUI-managed policy: `policy.json` holds the `client.policy` object and
/// `routing.rules` the rule text. Relative paths inside resolve against this
/// directory (see `prepare_policy_v2`).
pub struct Workspace {
    dir: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceContent {
    pub policy: Option<Value>,
    pub rules: String,
}

impl Workspace {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load(&self) -> Result<WorkspaceContent, String> {
        let policy = match std::fs::read(self.dir.join(POLICY_FILE)) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).map_err(|e| format!("policy.json: {e}"))?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        let rules = match std::fs::read_to_string(self.dir.join(RULES_FILE)) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.to_string()),
        };
        Ok(WorkspaceContent { policy, rules })
    }

    pub fn save(&self, policy: &Value, rules: &str) -> Result<(), String> {
        validate_draft(policy)?;
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        crate::storage::write(&self.dir.join(RULES_FILE), rules.as_bytes())?;
        let mut policy = policy.clone();
        policy["rules"] = json!({ "path": RULES_FILE });
        crate::storage::write(
            &self.dir.join(POLICY_FILE),
            &serde_json::to_vec_pretty(&policy).map_err(|e| e.to_string())?,
        )
    }
}

pub fn validate_draft(policy: &Value) -> Result<(), String> {
    if !policy.is_object() {
        return Err("client.policy must be a JSON object".into());
    }
    if policy["version"].as_u64() != Some(2) {
        return Err("client.policy.version must be 2".into());
    }
    if serde_json::to_vec(policy).map_or(true, |bytes| bytes.len() > 2 * 1024 * 1024) {
        return Err("client.policy exceeds 2 MiB".into());
    }
    Ok(())
}

/// A throwaway directory under `root` for one policy command; removed on drop.
pub struct Staging {
    dir: PathBuf,
}

impl Staging {
    pub fn new(root: &Path) -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let dir = root.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(Self { dir })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Writes a policy-only config for check/explain. Rule-set and fake-IP
    /// paths stay anchored to the real workspace; the rules come from the draft.
    pub fn write_draft(&self, policy: &Value, rules: &str, workspace: &Path) -> Result<PathBuf, String> {
        validate_draft(policy)?;
        let mut config = json!({ "client": { "policy": policy } });
        prepare_policy_v2(&mut config, workspace);
        let rules_path = self.path(RULES_FILE);
        std::fs::write(&rules_path, rules).map_err(|e| e.to_string())?;
        config["client"]["policy"]["rules"] = json!({ "path": rules_path.to_string_lossy() });
        let config_path = self.path("config.json");
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(config_path)
    }

    /// Reads `policy.json` + `routing.rules` produced by `init` or `migrate`.
    pub fn read_output(&self, name: &str) -> Result<WorkspaceContent, String> {
        let output = self.path(name);
        let config: Value = serde_json::from_slice(
            &std::fs::read(output.join(POLICY_FILE)).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut policy = config["client"]["policy"].clone();
        if !policy.is_object() {
            return Err("ppp policy wrote no client.policy".into());
        }
        policy["rules"] = json!({ "path": RULES_FILE });
        let rules = std::fs::read_to_string(output.join(RULES_FILE)).map_err(|e| e.to_string())?;
        Ok(WorkspaceContent { policy: Some(policy), rules })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Arguments for `policy explain` from a GUI target.
pub fn explain_args(
    config: &Path,
    runtime: &str,
    target: &str,
    network: &str,
    port: Option<u16>,
) -> Result<Vec<String>, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("Enter a domain or IP address".into());
    }
    if !["tcp", "udp"].contains(&network) {
        return Err("network must be tcp or udp".into());
    }
    let mut args = vec![
        "explain".into(),
        "--config".into(),
        config.to_string_lossy().into_owned(),
        "--runtime".into(),
        runtime.into(),
    ];
    let kind = if target.parse::<std::net::IpAddr>().is_ok() { "--ip" } else { "--domain" };
    args.extend([kind.into(), target.into(), "--network".into(), network.into()]);
    if let Some(port) = port.filter(|port| *port > 0) {
        args.extend(["--port".into(), port.to_string()]);
    }
    Ok(args)
}

/// Fake-IP storage for a prepared runtime config: the configured path, or the
/// kernel default `./dns-fake-ip` beside the runtime config.
pub fn fake_ip_storage(config: &Value, runtime_dir: &Path) -> PathBuf {
    config
        .pointer("/client/policy/dns/fake-ip/storage")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(|path| runtime_dir.join(path))
        .unwrap_or_else(|| runtime_dir.join("dns-fake-ip"))
}
