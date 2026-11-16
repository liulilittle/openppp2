use openppp2_client_desktop::process::{CommandSpec, ExitReason, ProcessEvent, ProcessManager};
use openppp2_client_desktop::stats::StatsSampler;
use openppp2_client_desktop::telemetry::{classify_line, ConnectionSignal, Severity};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn telemetry_preserves_text_and_emits_only_evidence_based_signals() {
    let connected = classify_line("session established role=main");
    assert_eq!(connected.message, "session established role=main");
    assert_eq!(connected.signal, Some(ConnectionSignal::Connected));
    assert_eq!(connected.severity, Severity::Success);

    let failed = classify_line("handshake failed error=42");
    assert_eq!(failed.signal, Some(ConnectionSignal::Failed));
    assert_eq!(failed.severity, Severity::Error);

    let neutral = classify_line("tcp connecting 127.0.0.1:20000");
    assert_eq!(neutral.signal, None);
    assert_eq!(neutral.severity, Severity::Info);
    assert_eq!(classify_line("proxy-only connected").signal, None);
}

fn stats_line(monotonic_ms: u64, rx: u64, tx: u64) -> String {
    format!(
        r#"{{"type":"ppp-stats","version":1,"monotonic_ms":{monotonic_ms},"rx_bytes":{rx},"tx_bytes":{tx},"link":{{"quality_percent":99.2,"grade":"Good","error_count":1,"success_count":100}},"runtime":{{"phase":"connected","role":"client","requested_mux_mode":"flow","effective_mux_mode":"flow","mux_active_links":4,"effective_path":"direct","last_error":{{"code":0,"severity":"","retryable":false,"user_message_key":"","diagnostic_detail":""}}}}}}"#
    )
}

#[test]
fn stats_sampler_rejects_wrong_contract_and_computes_real_rates() {
    let mut sampler = StatsSampler::default();
    assert!(sampler.current().is_none());
    assert!(sampler
        .consume_line(r#"{"type":"other","version":1}"#)
        .is_err());
    assert!(sampler
        .consume_line(r#"{"type":"ppp-stats","version":2}"#)
        .is_err());

    let first = sampler
        .consume_line(&stats_line(1000, 1_000_000, 500_000))
        .unwrap();
    assert_eq!(first.rx_rate_mbps, 0.0);
    let second = sampler
        .consume_line(&stats_line(2000, 2_000_000, 750_000))
        .unwrap();
    assert_eq!(second.rx_rate_mbps, 8.0);
    assert_eq!(second.tx_rate_mbps, 2.0);
    assert_eq!(second.active_links, 4);
    assert_eq!(second.effective_path, "direct");
    assert_eq!(second.rx_bytes, 2_000_000);

    let reset = sampler.consume_line(&stats_line(3000, 10, 10)).unwrap();
    assert_eq!(reset.rx_rate_mbps, 0.0);
    assert_eq!(reset.tx_rate_mbps, 0.0);
}

#[test]
fn proxy_stats_use_session_traffic_and_distinguish_primary_from_mux_links() {
    let mut sampler = StatsSampler::default();
    let make_record = |time, rx, tx, phase| {
        let mut value: serde_json::Value = serde_json::from_str(&stats_line(time, 7, 7)).unwrap();
        value["runtime"]["traffic"] = serde_json::json!({"rx_bytes":rx,"tx_bytes":tx});
        value["runtime"]["phase"] = serde_json::json!(phase);
        value["runtime"]["mux_active_links"] = serde_json::json!(0);
        value.to_string()
    };
    let first = sampler.consume_line(&make_record(1000, 1_000_000, 500_000, "connected")).unwrap();
    assert_eq!(first.rx_bytes, 1_000_000);
    assert_eq!(first.active_links, 1);
    assert_eq!(first.mux_active_links, 0);
    let next = sampler.consume_line(&make_record(2000, 2_000_000, 750_000, "connected")).unwrap();
    assert_eq!(next.rx_rate_mbps, 8.0);
    assert_eq!(next.tx_rate_mbps, 2.0);
    let reset = sampler.consume_line(&make_record(3000, 0, 0, "reconnecting")).unwrap();
    assert_eq!(reset.rx_rate_mbps, 0.0);
    assert_eq!(reset.rx_bytes, 0);
    assert_eq!(reset.active_links, 0);
}

#[test]
fn process_manager_enforces_single_child_and_reports_stderr_and_exit_code() {
    let (tx, rx) = mpsc::channel();
    let mut manager = ProcessManager::new(move |event| {
        let _ = tx.send(event);
    });
    manager.start(fixture_command()).unwrap();
    assert!(manager
        .start(fixture_command())
        .unwrap_err()
        .to_string()
        .contains("运行中"));

    let mut saw_stderr = false;
    let mut exit_code = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !saw_stderr || exit_code.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("fixture did not finish: stderr={saw_stderr}, exit={exit_code:?}")
            }
            Err(error) => panic!("process event channel failed: {error}"),
            Ok(event) => match event.event {
                ProcessEvent::Telemetry(event) => {
                    saw_stderr |= event.message.contains("fixture stderr")
                }
                ProcessEvent::Exited(exit) => {
                    exit_code = exit.code;
                    assert_eq!(exit.reason, ExitReason::Natural);
                    assert!(!exit.recovery_pending);
                }
                ProcessEvent::Stats(_) => {}
                ProcessEvent::State(_) => {}
            },
        }
    }
    assert!(saw_stderr);
    assert_eq!(exit_code, Some(7));
    assert!(!manager.is_running());
}

fn fixture_command() -> CommandSpec {
    // Use a native child rather than paying for PowerShell startup/module
    // loading on busy Windows runners. Keep the child alive long enough to
    // exercise rejection of a second start, and retain a real exit code.
    CommandSpec::new(
        std::env::current_exe().unwrap(),
        [
            "--exact",
            "native_child_fixture",
            "--ignored",
            "--nocapture",
        ],
    )
}

#[test]
#[ignore = "subprocess fixture; invoked by the process manager tests"]
fn native_child_fixture() {
    eprintln!("fixture stderr");
    std::thread::sleep(Duration::from_millis(300));
    std::process::exit(7);
}

#[test]
fn stop_then_restart_keeps_the_new_session_authoritative() {
    let mut manager = ProcessManager::new(|_| {});
    manager.start(fixture_command()).unwrap();
    let first = manager.snapshot().session_id;
    manager.stop().unwrap();
    assert!(!manager.is_running());
    // Windows may need the independent recovery worker when CTRL+C cannot be
    // delivered to a detached console. Simulate its verified completion before
    // starting the next session.
    if manager.snapshot().recovery_pending {
        manager.mark_recovery_complete();
    }
    assert_eq!(manager.snapshot().status, "disconnected");
    manager.start(fixture_command()).unwrap();
    let second = manager.snapshot().session_id;
    assert!(second > first);
    for _ in 0..30 {
        let snapshot = manager.snapshot();
        if snapshot.session_id == second && snapshot.pid.is_none() { break; }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(manager.snapshot().session_id, second);
    assert_eq!(manager.snapshot().pid, None);
    assert_eq!(manager.snapshot().status, "error");
}

#[cfg(unix)]
#[test]
fn stop_waits_for_the_kernel_to_finish_its_shutdown_rollback() {
    let (tx, rx) = mpsc::channel();
    let mut manager = ProcessManager::new(move |event| { let _ = tx.send(event); });
    // Rollback that outlasts the old 750 ms deadline must still complete.
    manager
        .start(CommandSpec::new(
            "sh",
            ["-c", "trap 'sleep 1; echo rollback done >&2; exit 0' TERM; echo ready >&2; while :; do sleep 0.05; done"],
        ))
        .unwrap();
    for _ in 0..40 {
        let event = rx.recv_timeout(Duration::from_millis(500)).unwrap();
        if matches!(&event.event, ProcessEvent::Telemetry(t) if t.message.contains("ready")) { break; }
    }
    manager.stop().unwrap();
    let mut rollback = false;
    let mut exit_code = None;
    while let Ok(event) = rx.recv_timeout(Duration::from_millis(500)) {
        match event.event {
            ProcessEvent::Telemetry(t) => rollback |= t.message.contains("rollback done"),
            ProcessEvent::Exited(exit) => {
                exit_code = exit.code;
                assert_eq!(exit.reason, ExitReason::Graceful);
                assert!(!exit.timed_out);
                assert!(!exit.recovery_pending);
            }
            _ => {}
        }
    }
    assert!(rollback);
    assert_eq!(exit_code, Some(0));
}

#[test]
fn stats_sampler_reports_p2p_state_and_per_peer_paths() {
    let mut sampler = StatsSampler::default();
    let mut value: serde_json::Value = serde_json::from_str(&stats_line(1000, 1, 1)).unwrap();
    value["runtime"]["p2p_state"] = serde_json::json!("probing");
    // 10.0.0.7 in network byte order, as the kernel stores it.
    value["runtime"]["peers"] = serde_json::json!([
        {"virtual_ip": u32::from_le_bytes([10, 0, 0, 7]), "state": "direct", "effective_path": "direct"}
    ]);
    let view = sampler.consume_line(&value.to_string()).unwrap();
    assert_eq!(view.p2p_state, "probing");
    assert_eq!(view.peers.len(), 1);
    assert_eq!(view.peers[0].virtual_ip, "10.0.0.7");
    assert_eq!(view.peers[0].effective_path, "direct");
    assert_eq!(view.tcp_stack, "");

    value["tcp_stack"] = serde_json::json!({"requested": "lwip", "active": "lwip"});
    value["monotonic_ms"] = serde_json::json!(1500);
    assert_eq!(sampler.consume_line(&value.to_string()).unwrap().tcp_stack, "lwip");

    let legacy = sampler.consume_line(&stats_line(2000, 2, 2)).unwrap();
    assert_eq!(legacy.p2p_state, "");
    assert!(legacy.peers.is_empty());
}
