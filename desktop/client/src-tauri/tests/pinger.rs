use openppp2_client_desktop::pinger::{
    parse_probe_endpoint, probe_endpoint, probe_nodes, targets_for_nodes, ProbeEndpoint,
};
use openppp2_client_desktop::subscription::parse_subscription;
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

#[test]
fn parses_all_supported_subscription_server_forms() {
    let cases = [
        ("ppp://example.com:20000/", "example.com", 20000),
        ("ppp://127.0.0.1:443/", "127.0.0.1", 443),
        ("ppp://ws/ws.example.com:80/", "ws.example.com", 80),
        ("ppp://wss/wss.example.com:443/path", "wss.example.com", 443),
        ("ppp://[::1]:20000/", "::1", 20000),
    ];
    for (server, host, port) in cases {
        let endpoint = parse_probe_endpoint(server).unwrap();
        assert_eq!(endpoint.host, host, "{server}");
        assert_eq!(endpoint.port, port, "{server}");
    }
}

#[test]
fn rejects_unprobeable_server_forms() {
    for server in [
        "https://example.com:443/",
        "ppp://example.com/",
        "ppp://:20000/",
        "ppp://ws/:443/",
        "",
    ] {
        assert!(parse_probe_endpoint(server).is_err(), "{server}");
    }
}

#[test]
fn probes_a_real_local_tcp_listener_and_reports_closed_ports_as_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = thread::spawn(move || listener.accept().unwrap());

    let success = probe_endpoint(
        &ProbeEndpoint {
            host: "127.0.0.1".into(),
            port,
        },
        Duration::from_secs(1),
    );
    assert!(success.is_some());
    drop(accept.join().unwrap());

    let unavailable = probe_endpoint(
        &ProbeEndpoint {
            host: "127.0.0.1".into(),
            port,
        },
        Duration::from_millis(100),
    );
    assert_eq!(unavailable, None);
}

#[test]
fn bounded_runner_returns_one_result_per_unique_node() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = thread::spawn(move || {
        for _ in 0..2 {
            let _ = listener.accept();
        }
    });
    let endpoint = ProbeEndpoint {
        host: "127.0.0.1".into(),
        port,
    };
    let results = probe_nodes(
        vec![("a".into(), endpoint.clone()), ("b".into(), endpoint)],
        4,
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.values().all(Option::is_some));
    accept.join().unwrap();

    let duplicate = probe_nodes(
        vec![
            (
                "a".into(),
                ProbeEndpoint {
                    host: "127.0.0.1".into(),
                    port,
                },
            ),
            (
                "a".into(),
                ProbeEndpoint {
                    host: "127.0.0.1".into(),
                    port,
                },
            ),
        ],
        4,
        Duration::from_millis(10),
    );
    assert!(duplicate.is_err());
}

#[test]
fn result_type_is_stable_for_tauri_serialization() {
    let empty = probe_nodes(Vec::new(), 4, Duration::from_millis(1)).unwrap();
    assert_eq!(empty, BTreeMap::<String, Option<u32>>::new());
}

#[test]
fn subscription_mapping_only_selects_known_node_ids() {
    let document = parse_subscription(br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"a","name":"A","server":"ppp://127.0.0.1:1001/","key":{"protocol-key":"p"}},{"id":"b","name":"B","server":"ppp://ws/127.0.0.1:1002/","key":{"protocol-key":"p"}}]}"#).unwrap();
    let all = targets_for_nodes(&document.nodes, None);
    assert_eq!(
        all.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        vec!["a", "b"]
    );

    let selected = vec!["b".to_string(), "unknown".to_string()];
    let one = targets_for_nodes(&document.nodes, Some(&selected));
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].0, "b");
    assert_eq!(one[0].1.port, 1002);
}
