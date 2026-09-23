use openppp2_client_desktop::manual_nodes::{
    delete_manual_node, find_node, merge_nodes, node_source, upsert_manual_node, ManualNodeInput,
    NodeSource,
};
use openppp2_client_desktop::subscription::SubscriptionNode;
use serde_json::json;

fn input(id: Option<&str>, name: &str, server: &str) -> ManualNodeInput {
    ManualNodeInput {
        id: id.map(str::to_owned),
        name: name.into(),
        subtitle: "local test".into(),
        config: json!({
            "key": { "protocol": "aes-128-cfb", "protocol-key": "secret" },
            "client": {
                "server": server,
                "guid": "desktop-guid",
                "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
                "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
            }
        }),
        options: json!({ "tunIp": "10.0.0.2" }),
    }
}

fn remote_node(id: &str) -> SubscriptionNode {
    SubscriptionNode {
        id: id.into(),
        name: "Remote".into(),
        subtitle: String::new(),
        server: Some("ppp://remote.test:20000/".into()),
        key: Some(json!({ "protocol-key": "remote" })),
        websocket: None,
        client: None,
        bandwidth: None,
        options: None,
        config: None,
    }
}

#[test]
fn manual_nodes_support_create_update_delete_and_merge() {
    let mut nodes = Vec::new();
    let created =
        upsert_manual_node(&mut nodes, input(None, "Office", "ppp://127.0.0.1:20000/")).unwrap();
    assert!(created.id.starts_with("manual:"));
    assert_eq!(created.server.as_deref(), Some("ppp://127.0.0.1:20000/"));
    assert_eq!(created.client_guid(), Some("desktop-guid"));
    assert_eq!(nodes.len(), 1);

    let updated = upsert_manual_node(
        &mut nodes,
        input(Some(&created.id), "Office 2", "ppp://127.0.0.1:21000/"),
    )
    .unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.name, "Office 2");
    assert_eq!(nodes.len(), 1);

    let merged = merge_nodes(&nodes, &[remote_node("remote-1")]);
    assert_eq!(
        merged
            .iter()
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>(),
        [created.id.as_str(), "remote-1"]
    );
    assert_eq!(
        find_node(&nodes, &[remote_node("remote-1")], &created.id)
            .unwrap()
            .name,
        "Office 2"
    );
    assert_eq!(node_source(&nodes, &created.id), NodeSource::Manual);
    assert_eq!(node_source(&nodes, "remote-1"), NodeSource::Subscription);
    assert_eq!(
        node_source(&nodes, "manual:remote-prefix"),
        NodeSource::Subscription
    );

    delete_manual_node(&mut nodes, &updated.id).unwrap();
    assert!(nodes.is_empty());
}

#[test]
fn manual_nodes_reject_invalid_or_unknown_profiles() {
    let mut nodes = Vec::new();
    assert!(upsert_manual_node(&mut nodes, input(None, "", "ppp://host:1/")).is_err());
    assert!(upsert_manual_node(&mut nodes, input(None, "Bad", "https://host:1/")).is_err());

    let mut missing_key = input(None, "Bad", "ppp://host:1/");
    missing_key.config["key"] = json!({});
    assert!(upsert_manual_node(&mut nodes, missing_key).is_err());

    let mut invalid_port = input(None, "Bad", "ppp://host:1/");
    invalid_port.config["client"]["http-proxy"]["port"] = json!(70000);
    assert!(upsert_manual_node(&mut nodes, invalid_port).is_err());

    assert!(upsert_manual_node(
        &mut nodes,
        input(Some("manual:missing"), "Missing", "ppp://host:1/"),
    )
    .is_err());
    assert!(delete_manual_node(&mut nodes, "manual:missing").is_err());
}
