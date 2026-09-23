use openppp2_client_desktop::process::{CommandSpec, ProcessEvent, ProcessManager};
use openppp2_client_desktop::stats::StatsSampler;
use openppp2_client_desktop::telemetry::{classify_line, ConnectionSignal, Severity};
use std::sync::mpsc;
use std::time::Duration;

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
    for _ in 0..20 {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(error) => panic!("process event channel failed: {error}"),
            Ok(event) => match event {
                ProcessEvent::Telemetry(event) => {
                    saw_stderr |= event.message.contains("fixture stderr")
                }
                ProcessEvent::Exited(exit) => {
                    exit_code = exit.code;
                    break;
                }
                ProcessEvent::Stats(_) => {}
            },
        }
    }
    assert!(saw_stderr);
    assert_eq!(exit_code, Some(7));
    assert!(!manager.is_running());
}

#[cfg(windows)]
fn fixture_command() -> CommandSpec {
    CommandSpec::new(
        "powershell",
        [
            "-NoProfile",
            "-Command",
            "[Console]::Error.WriteLine('fixture stderr'); Start-Sleep -Milliseconds 300; exit 7",
        ],
    )
}

#[cfg(not(windows))]
fn fixture_command() -> CommandSpec {
    CommandSpec::new("sh", ["-c", "echo fixture stderr >&2; sleep 0.2; exit 7"])
}
