use openppp2_client_desktop::{
    config::{apply_network_overrides, build_node_config_with_base},
    connection::ConnectionSnapshot,
    kernel, network,
    process::{ExitInfo, ExitReason, ProcessEvent},
    subscription::parse_subscription,
};
use serde_json::json;

#[test]
fn compact_config_missing_sections_does_not_panic_and_overrides_preserve_unknown_fields() {
    let document=parse_subscription(br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"a","server":"ppp://127.0.0.1:1234/","key":{"protocol-key":"secret"}}]}"#).unwrap();
    let mut config =
        build_node_config_with_base(&document.nodes[0], Some(r#"{"future":42}"#)).unwrap();
    assert_eq!(config["client"]["server"], "ppp://127.0.0.1:1234/");
    apply_network_overrides(&mut config, &json!({"client":{"http-proxy":{"port":9090}}})).unwrap();
    assert_eq!(config["future"], 42);
    assert_eq!(config["client"]["http-proxy"]["bind"], "127.0.0.1");
    assert!(build_node_config_with_base(&document.nodes[0], Some(r#"{"client":false}"#)).is_err());
    assert!(
        network::validate(&json!({"client":{"http-proxy":{"bind":"0.0.0.0","port":8080}}}))
            .is_err()
    );
    assert!(
        network::validate(&json!({"client":{"http-proxy":{"bind":"127.0.0.1","port":0}}})).is_err()
    );
    let redacted = kernel::redact(config);
    assert_eq!(redacted["key"]["protocol-key"], "[redacted]");
}

#[test]
fn intentional_disconnect_is_not_an_error() {
    let mut snapshot = ConnectionSnapshot {
        pid: Some(42),
        requested_stop: true,
        status: "stopping".into(),
        ..Default::default()
    };
    snapshot.apply(&ProcessEvent::Exited(ExitInfo {
        code: Some(1),
        success: false,
        reason: ExitReason::Graceful,
        timed_out: false,
        recovery_pending: false,
    }));
    assert_eq!(snapshot.status, "disconnected");
    assert!(snapshot.pid.is_none());
}

#[test]
fn forced_exit_keeps_recovery_pending_visible() {
    let mut snapshot = ConnectionSnapshot {
        pid: Some(42),
        requested_stop: true,
        status: "recovery_pending".into(),
        ..Default::default()
    };
    snapshot.apply(&ProcessEvent::Exited(ExitInfo {
        code: None,
        success: false,
        reason: ExitReason::ForcedKill,
        timed_out: true,
        recovery_pending: true,
    }));
    assert_eq!(snapshot.status, "recovery_pending");
    assert!(snapshot.recovery_pending);
    assert_eq!(snapshot.last_error, "network recovery is pending");
    assert!(snapshot.pid.is_none());
}

#[test]
fn duplicate_subscription_node_ids_are_rejected() {
    let body = json!({"type":"openppp2-subscription","version":1,"nodes":[{"id":"a","config":{}},{"id":"a","config":{}}]});
    assert!(parse_subscription(&serde_json::to_vec(&body).unwrap()).is_err());
}

#[test]
fn policy_support_is_derived_from_the_kernel_version_only() {
    assert_eq!(kernel::policy_supported("Version: 2.1.7.0"), Some(true));
    assert_eq!(kernel::policy_supported("openppp2 v2.2.0"), Some(true));
    assert_eq!(kernel::policy_supported("2.1.6.0"), Some(false));
    assert_eq!(kernel::policy_supported("1.9.9"), Some(false));
    assert_eq!(kernel::policy_supported("Unknown"), None);
}
