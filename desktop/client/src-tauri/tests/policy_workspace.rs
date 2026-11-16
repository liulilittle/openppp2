use openppp2_client_desktop::policy::{self, Staging, Workspace};
use serde_json::{json, Value};
use std::path::Path;

fn draft() -> Value {
    json!({
        "version": 2,
        "rules": {"path": "elsewhere.rules"},
        "rule-sets": {"cn": {"format": "geoip-dat", "tag": "cn", "source": {"path": "geo/geoip.dat"}}}
    })
}

#[test]
fn workspace_round_trips_and_pins_the_rules_file() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = Workspace::new(dir.path().join("policy"));
    let empty = workspace.load().unwrap();
    assert!(empty.policy.is_none());
    assert_eq!(empty.rules, "");

    workspace.save(&draft(), "default proxy\n").unwrap();
    let loaded = workspace.load().unwrap();
    let policy = loaded.policy.unwrap();
    assert_eq!(policy["rules"]["path"], policy::RULES_FILE);
    assert_eq!(policy["rule-sets"]["cn"]["source"]["path"], "geo/geoip.dat");
    assert_eq!(loaded.rules, "default proxy\n");

    assert!(workspace.save(&json!({"version": 1}), "").is_err());
    assert!(workspace.save(&json!([]), "").is_err());
}

#[test]
fn staging_draft_anchors_rule_sets_to_the_workspace_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("policy");
    let staging_root = dir.path().join("staging");
    let staged_dir;
    {
        let staging = Staging::new(&staging_root).unwrap();
        let config_path = staging.write_draft(&draft(), "default direct\n", &workspace).unwrap();
        let config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let policy = &config["client"]["policy"];
        let rules = Path::new(policy["rules"]["path"].as_str().unwrap()).to_path_buf();
        assert_eq!(std::fs::read_to_string(&rules).unwrap(), "default direct\n");
        assert_eq!(
            Path::new(policy["rule-sets"]["cn"]["source"]["path"].as_str().unwrap()),
            workspace.join("geo/geoip.dat")
        );
        staged_dir = config_path.parent().unwrap().to_path_buf();
        assert!(staged_dir.is_dir());
    }
    assert!(!staged_dir.exists());
}

#[test]
fn explain_targets_choose_domain_or_ip() {
    let config = Path::new("/tmp/config.json");
    let domain = policy::explain_args(config, "tun", " service.example ", "tcp", Some(443)).unwrap();
    assert_eq!(&domain[5..], ["--domain", "service.example", "--network", "tcp", "--port", "443"]);
    let ip = policy::explain_args(config, "socks", "192.0.2.1", "udp", None).unwrap();
    assert_eq!(&ip[5..], ["--ip", "192.0.2.1", "--network", "udp"]);
    assert!(policy::explain_args(config, "tun", "", "tcp", None).is_err());
    assert!(policy::explain_args(config, "tun", "a.example", "icmp", None).is_err());
}

#[test]
fn fake_ip_storage_defaults_beside_the_runtime_config() {
    let runtime = Path::new("/data/runtime");
    assert_eq!(policy::fake_ip_storage(&Value::Null, runtime), runtime.join("dns-fake-ip"));
    let configured = json!({"client": {"policy": {"dns": {"fake-ip": {"storage": "/data/policy/fake"}}}}});
    assert_eq!(policy::fake_ip_storage(&configured, runtime), Path::new("/data/policy/fake"));
}

#[cfg(unix)]
#[test]
fn run_parses_reports_for_documented_exit_codes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("ppp");
    std::fs::write(
        &kernel,
        "#!/bin/sh\n[ \"$1\" = policy ] || exit 9\nprintf '{\"command\":\"%s\",\"args\":\"%s\",\"diagnostics\":[{\"code\":\"E_POLICY_RULES\",\"severity\":\"error\",\"message\":\"bad rule\",\"source\":\"routing.rules\",\"line\":3}]}' \"$2\" \"$*\"\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&kernel, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = policy::run(&kernel, &["check".into(), "--config".into(), "c.json".into()], policy::OFFLINE_TIMEOUT).unwrap();
    assert_eq!(result.exit_code, 2);
    assert!(!result.ok());
    assert_eq!(result.report["command"], "check");
    assert_eq!(result.report["args"], "policy check --config c.json --json");
    assert_eq!(result.summary(), "E_POLICY_RULES: bad rule (routing.rules:3)");

    std::fs::write(&kernel, "#!/bin/sh\necho 'not json' >&2\nexit 1\n").unwrap();
    let error = policy::run(&kernel, &["status".into()], policy::OFFLINE_TIMEOUT).unwrap_err();
    assert!(error.contains("not json"));
}

/// End-to-end against a real `ppp policy` (set OPENPPP2_POLICY_CLI to a
/// policy-capable kernel); skipped otherwise. Offline commands only.
#[test]
fn real_policy_cli_accepts_gui_drafts() {
    let Some(kernel) = std::env::var_os("OPENPPP2_POLICY_CLI") else { return };
    let kernel = std::path::PathBuf::from(kernel);
    let info = openppp2_client_desktop::kernel::inspect(&kernel).unwrap();
    assert_eq!(info["policySupported"].as_bool(), Some(true),
        "GUI capability probe rejected the policy kernel: version={}, probe_error={}",
        info["version"], info["probeError"]);
    let dir = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    {
        // Preserve the actual PE version resources but make the image
        // unlaunchable, exercising the real Win32 file-version fallback.
        let mut image = std::fs::read(&kernel).unwrap();
        let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
        assert_eq!(&image[pe..pe + 4], b"PE\0\0");
        image[pe + 4..pe + 6].copy_from_slice(&0xffffu16.to_le_bytes());
        let fixture = dir.path().join("unlaunchable-version-probe.exe");
        std::fs::write(&fixture, image).unwrap();
        let fallback = openppp2_client_desktop::kernel::inspect(&fixture).unwrap();
        assert_eq!(fallback["helpAvailable"], false);
        assert!(fallback["probeError"].as_str().is_some_and(|error| !error.is_empty()));
        assert_eq!(fallback["policySupported"], true);
    }
    let workspace = dir.path().join("policy");
    let staging = Staging::new(&dir.path().join("staging")).unwrap();
    let out = staging.path("out");
    let init = policy::run(
        &kernel,
        &["init".into(), "--out".into(), out.to_string_lossy().into_owned(), "--template".into(),
          "proxy-all".into(), "--runtime".into(), "tun".into()],
        policy::OFFLINE_TIMEOUT,
    )
    .unwrap();
    assert!(init.ok(), "{}", init.summary());
    let content = staging.read_output("out").unwrap();
    let draft = content.policy.unwrap();
    let rules = format!("{}[direct]\n=service.example\n", content.rules);

    let check_staging = Staging::new(&dir.path().join("staging")).unwrap();
    let config = check_staging.write_draft(&draft, &rules, &workspace).unwrap();
    let check = policy::run(
        &kernel,
        &["check".into(), "--config".into(), config.to_string_lossy().into_owned(), "--runtime".into(), "tun".into()],
        policy::OFFLINE_TIMEOUT,
    )
    .unwrap();
    assert!(check.ok(), "{}", check.summary());

    let args = policy::explain_args(&config, "tun", "service.example", "tcp", Some(443)).unwrap();
    let explain = policy::run(&kernel, &args, policy::OFFLINE_TIMEOUT).unwrap();
    assert!(explain.ok(), "{}", explain.summary());
    assert_eq!(explain.report["route"]["action"], "direct");
    assert_eq!(explain.report["route"]["line"], 5);

    let broken = check_staging.write_draft(&draft, "default proxy\n[nowhere]\n", &workspace).unwrap();
    let rejected = policy::run(
        &kernel,
        &["check".into(), "--config".into(), broken.to_string_lossy().into_owned(), "--runtime".into(), "tun".into()],
        policy::OFFLINE_TIMEOUT,
    )
    .unwrap();
    assert_eq!(rejected.exit_code, 2);
    assert!(!rejected.summary().is_empty());

    let legacy = dir.path().join("legacy.json");
    std::fs::write(&legacy, openppp2_client_desktop::config::default_config_string()).unwrap();
    let migrate_out = dir.path().join("migrated");
    let migrated = policy::run(
        &kernel,
        &["migrate".into(), "--config".into(), legacy.to_string_lossy().into_owned(), "--out".into(),
          migrate_out.to_string_lossy().into_owned(), "--runtime".into(), "tun".into()],
        policy::OFFLINE_TIMEOUT,
    )
    .unwrap();
    assert!(matches!(migrated.exit_code, 0 | 5), "{}", migrated.summary());
    assert!(migrated.report["migration"].is_object());
}
