use openppp2_client_desktop::{
    config::{apply_network_overrides, build_node_config, prepare_policy_v2, uses_policy_v2},
    network,
    subscription::parse_subscription,
};
use serde_json::{json, Value};
use std::path::Path;

fn node_config(client: Value) -> Value {
    let body = serde_json::to_vec(&json!({
        "type":"openppp2-subscription", "version":1,
        "nodes":[{
            "id":"n", "name":"N", "server":"ppp://127.0.0.1:20000/",
            "key":{"protocol-key":"p","transport-key":"t"}, "client":client
        }]
    }))
    .unwrap();
    build_node_config(&parse_subscription(&body).unwrap().nodes[0]).unwrap()
}

fn v1_overrides() -> Value {
    json!({
        "dns":{"servers":{"domestic":"doh.pub"}},
        "udp":{"dns":{"ttl":30}},
        "geo-rules":{"enabled":true},
        "client":{"routing":{"ip":{"bypass":["10.0.0.0/8"]}},"http-proxy":{"bind":"127.0.0.1","port":9090}},
        "p2p":{"mode":"direct-preferred"}
    })
}

#[test]
fn compact_v2_node_drops_v1_defaults_and_overrides() {
    let mut config = node_config(json!({"policy":{"version":2,"rules":{"path":"rules/main.rules"}}}));
    assert!(uses_policy_v2(&config));
    apply_network_overrides(&mut config, &v1_overrides()).unwrap();
    prepare_policy_v2(&mut config, Path::new("/data/policy"));

    for field in ["dns", "geo-rules", "routing", "bypass", "dns-rules"] {
        assert!(config.get(field).is_none(), "{field} must be removed");
    }
    assert!(config["udp"].get("dns").is_none());
    assert!(config["udp"].get("inactive").is_some());
    assert!(config["client"].get("routing").is_none());
    assert_eq!(config["client"]["http-proxy"]["port"], 9090);
    assert_eq!(config["p2p"]["mode"], "direct-preferred");
    assert_eq!(
        Path::new(config["client"]["policy"]["rules"]["path"].as_str().unwrap()),
        Path::new("/data/policy").join("rules/main.rules")
    );
}

#[test]
fn v2_relative_paths_are_anchored_and_absolute_paths_kept() {
    let absolute = std::env::temp_dir().join("geoip.dat");
    let mut config = node_config(json!({"policy":{
        "version":2,
        "dns":{"fake-ip":{"storage":"fake-ip"}},
        "rule-sets":{
            "cn":{"format":"geoip-dat","tag":"cn","source":{"path":"geo/geoip.dat"}},
            "abs":{"format":"geoip-dat","tag":"cn","source":{"path":absolute.to_string_lossy()}},
            "remote":{"format":"geosite-dat","tag":"cn","source":{"url":"https://example.invalid/geosite.dat"}}
        }
    }}));
    prepare_policy_v2(&mut config, Path::new("/data/policy"));
    let policy = &config["client"]["policy"];
    assert_eq!(
        Path::new(policy["rule-sets"]["cn"]["source"]["path"].as_str().unwrap()),
        Path::new("/data/policy").join("geo/geoip.dat")
    );
    assert_eq!(policy["rule-sets"]["abs"]["source"]["path"], json!(absolute.to_string_lossy()));
    assert_eq!(policy["rule-sets"]["remote"]["source"]["url"], "https://example.invalid/geosite.dat");
    assert_eq!(
        Path::new(policy["dns"]["fake-ip"]["storage"].as_str().unwrap()),
        Path::new("/data/policy").join("fake-ip")
    );
}

#[test]
fn v1_node_keeps_routing_and_dns_overrides() {
    let mut config = node_config(json!({"guid":"g"}));
    assert!(!uses_policy_v2(&config));
    apply_network_overrides(&mut config, &v1_overrides()).unwrap();
    prepare_policy_v2(&mut config, Path::new("/data/policy"));
    assert_eq!(config["dns"]["servers"]["domestic"], "doh.pub");
    assert_eq!(config["udp"]["dns"]["ttl"], 30);
    assert_eq!(config["client"]["routing"]["ip"]["bypass"][0], "10.0.0.0/8");
}

#[test]
fn network_overrides_accept_only_known_p2p_fields() {
    assert!(network::validate(&json!({"p2p":{"enabled":true,"mode":"direct-preferred"}})).is_ok());
    assert!(network::validate(&json!({"p2p":{"enabled":false,"mode":"relay"}})).is_ok());
    assert!(network::validate(&json!({"p2p":{"mode":"direct"}})).is_err());
    assert!(network::validate(&json!({"p2p":{"enabled":"yes"}})).is_err());
    assert!(network::validate(&json!({"p2p":{"stun":{"servers":[]}}})).is_err());
}
