use openppp2_client_desktop::config::build_node_config;
use openppp2_client_desktop::subscription::{parse_subscription, refresh_with};
use serde_json::{json, Value};

fn compact_document() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "openppp2-subscription",
        "version": 1,
        "name": "My nodes",
        "profilePrefix": "Work",
        "updatedAt": "2026-07-19T12:00:00Z",
        "future": true,
        "nodes": [
            {
                "id": "tokyo-01",
                "name": "Tokyo",
                "subtitle": "jp-tokyo-eq",
                "server": "ppp://127.0.0.1:20000/",
                "key": { "protocol-key": "p", "transport-key": "t" },
                "client": { "guid": "client-guid" }
            },
            {
                "id": "disabled",
                "name": "Disabled",
                "enabled": false,
                "server": "ppp://127.0.0.1:20001/",
                "key": { "protocol-key": "p", "transport-key": "t" }
            }
        ]
    }))
    .unwrap()
}

#[test]
fn parses_v1_and_skips_disabled_nodes() {
    let document = parse_subscription(&compact_document()).unwrap();
    assert_eq!(document.name.as_deref(), Some("My nodes"));
    assert_eq!(document.updated_at.as_deref(), Some("2026-07-19T12:00:00Z"));
    assert_eq!(document.nodes.len(), 1);
    assert_eq!(document.nodes[0].id, "tokyo-01");
    assert_eq!(document.nodes[0].name, "Work Tokyo");
    assert_eq!(document.nodes[0].client_guid(), Some("client-guid"));
}

#[test]
fn rejects_wrong_contract_and_oversized_body() {
    let wrong_type = br#"{"type":"other","version":1,"nodes":[]}"#;
    assert!(parse_subscription(wrong_type)
        .unwrap_err()
        .to_string()
        .contains("type"));
    let wrong_version = br#"{"type":"openppp2-subscription","version":2,"nodes":[]}"#;
    assert!(parse_subscription(wrong_version)
        .unwrap_err()
        .to_string()
        .contains("version"));
    let too_large = vec![b' '; 2 * 1024 * 1024 + 1];
    assert!(parse_subscription(&too_large)
        .unwrap_err()
        .to_string()
        .contains("2 MiB"));
}

#[test]
fn rejects_invalid_or_empty_enabled_nodes() {
    let no_server =
        br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"a","name":"A","key":{}}]}"#;
    assert!(parse_subscription(no_server).is_err());
    let all_disabled = br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"a","name":"A","enabled":false}]}"#;
    assert!(parse_subscription(all_disabled).is_err());
}

#[test]
fn refresh_uses_only_valid_last_good_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("subscription.json");
    let first = refresh_with("https://sub.test/token", &cache, |_| Ok(compact_document())).unwrap();
    assert!(!first.cached);
    assert!(cache.is_file());

    let fallback =
        refresh_with("https://sub.test/token", &cache, |_| Err("offline".into())).unwrap();
    assert!(fallback.cached);
    assert_eq!(fallback.document.nodes[0].id, "tokyo-01");

    std::fs::write(&cache, b"broken").unwrap();
    assert!(refresh_with("https://sub.test/token", &cache, |_| Err("offline".into())).is_err());
}

#[test]
fn compact_node_merges_existing_client_defaults() {
    let document = parse_subscription(&compact_document()).unwrap();
    let config = build_node_config(&document.nodes[0]).unwrap();
    assert_eq!(config["client"]["server"], "ppp://127.0.0.1:20000/");
    assert_eq!(config["client"]["guid"], "client-guid");
    assert_eq!(config["client"]["http-proxy"]["port"], 8080);
    assert_eq!(config["key"]["protocol-key"], "p");
    assert_eq!(config["key"]["transport-key"], "t");
    assert_eq!(config["client"]["mappings"], Value::Array(vec![]));
}

#[test]
fn full_config_accepts_object_and_encoded_object() {
    for config in [
        json!({"client":{"server":"ppp://a:1/"}}),
        json!("{\"client\":{\"server\":\"ppp://b:2/\"}}"),
    ] {
        let body = serde_json::to_vec(&json!({
            "type":"openppp2-subscription", "version":1,
            "nodes":[{"id":"full", "name":"Full", "config":config}]
        }))
        .unwrap();
        let document = parse_subscription(&body).unwrap();
        assert!(build_node_config(&document.nodes[0]).unwrap()["client"]["server"].is_string());
    }
}
