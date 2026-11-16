use crate::process::ProcessEvent;
use crate::stats::StatsView;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub session_id: u64,
    pub pid: Option<u32>,
    pub status: String,
    pub phase: String,
    pub last_error: String,
    pub stats: Option<StatsView>,
    pub requested_stop: bool,
    pub recovery_pending: bool,
    pub connected_at: Option<u64>,
}

impl Default for ConnectionSnapshot {
    fn default() -> Self {
        Self {
            session_id: 0,
            pid: None,
            status: "disconnected".into(),
            phase: "idle".into(),
            last_error: String::new(),
            stats: None,
            requested_stop: false,
            recovery_pending: false,
            connected_at: None,
        }
    }
}

impl ConnectionSnapshot {
    pub fn apply(&mut self, event: &ProcessEvent) {
        match event {
            ProcessEvent::Stats(stats) => {
                self.phase = stats.phase.clone();
                if !self.requested_stop {
                    self.status = match stats.phase.as_str() {
                        "connected" => "connected",
                        "reconnecting" => "reconnecting",
                        "failed" => "error",
                        "stopping" => "stopping",
                        "starting" => "starting",
                        "preparing_host" | "connecting" | "handshaking" | "applying_policy" => {
                            "connecting"
                        }
                        _ => &self.status,
                    }
                    .into();
                }
                if stats.last_error.code != 0 {
                    self.last_error = if stats.last_error.diagnostic_detail.is_empty() {
                        format!(
                            "{} ({})",
                            stats.last_error.user_message_key, stats.last_error.code
                        )
                    } else {
                        stats.last_error.diagnostic_detail.clone()
                    };
                } else if self.status == "connected" {
                    self.last_error.clear();
                }
                self.stats = Some(stats.clone());
            }
            ProcessEvent::Telemetry(event) if self.stats.is_none() && !self.requested_stop => {
                use crate::telemetry::ConnectionSignal;
                match event.signal {
                    Some(ConnectionSignal::Connected) => {
                        self.status = "connected".into();
                        self.last_error.clear();
                    }
                    Some(ConnectionSignal::Failed) => {
                        self.status = "error".into();
                        self.last_error = event.message.clone();
                    }
                    None => {}
                }
            }
            ProcessEvent::Exited(exit) => {
                self.recovery_pending = exit.recovery_pending;
                self.status = if exit.recovery_pending {
                    "recovery_pending"
                } else if self.requested_stop || exit.success {
                    "disconnected"
                } else {
                    "error"
                }
                .into();
                if self.status == "recovery_pending" {
                    self.last_error = "network recovery is pending".into();
                } else if self.status == "error" && self.last_error.is_empty() {
                    self.last_error = format!("ppp exited: {:?}", exit.code);
                }
                self.pid = None;
                self.phase = "idle".into();
                self.stats = None;
            }
            _ => {}
        }
        if self.status == "connected" && self.connected_at.is_none() {
            self.connected_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
        } else if self.status != "connected" {
            self.connected_at = None;
        }
    }
}
