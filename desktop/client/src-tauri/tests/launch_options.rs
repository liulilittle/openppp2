use openppp2_client_desktop::launch_options::{append_launch_args, merge_launch_options};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn map(value: Value) -> BTreeMap<String, Value> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[test]
fn node_options_override_global_values_and_map_to_cpp_arguments() {
    let global = map(json!({
        "tunIp": "10.0.0.2",
        "tunMask": "255.255.255.0",
        "gateway": "10.0.0.1",
        "dns1": "8.8.8.8",
        "dns2": "",
        "mux": 2,
        "muxMode": "compat",
        "vnet": true,
        "blockQuic": false,
        "staticMode": true,
        "route": "0.0.0.0",
        "perAppProxyEnabled": true
    }));
    let node = json!({
        "dns2": "1.1.1.1",
        "mux": 4,
        "muxMode": "flow",
        "blockQuic": true
    });
    let effective = merge_launch_options(&global, Some(&node)).unwrap();
    let mut args = Vec::new();
    append_launch_args(&effective, &mut args).unwrap();
    assert_eq!(
        args,
        [
            "--tun-ip=10.0.0.2",
            "--tun-mask=255.255.255.0",
            "--tun-gw=10.0.0.1",
            "--dns=8.8.8.8,1.1.1.1",
            "--tun-mux=4",
            "--mux-mode=flow",
            "--tun-vnet=yes",
            "--block-quic=yes",
            "--tun-static=yes",
        ]
    );
    assert!(args
        .iter()
        .all(|arg| !arg.contains("route") && !arg.contains("per-app")));
}

#[test]
fn invalid_supported_values_are_rejected_and_blank_values_are_skipped() {
    let mut args = Vec::new();
    append_launch_args(
        &map(json!({ "tunIp": "", "dns1": "", "dns2": "" })),
        &mut args,
    )
    .unwrap();
    assert!(args.is_empty());

    for invalid in [
        json!({ "mux": -1 }),
        json!({ "muxMode": "unknown" }),
        json!({ "vnet": "yes" }),
        json!({ "tunIp": 42 }),
    ] {
        assert!(append_launch_args(&map(invalid), &mut Vec::new()).is_err());
    }
    assert!(merge_launch_options(&BTreeMap::new(), Some(&json!([]))).is_err());
}
