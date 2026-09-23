use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Success,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionSignal {
    Connected,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryEvent {
    pub message: String,
    pub severity: Severity,
    pub signal: Option<ConnectionSignal>,
}

pub fn classify_line(line: &str) -> TelemetryEvent {
    let normalized = line.trim().to_ascii_lowercase();
    let connected = normalized.contains("session established")
        || normalized.contains("exchanger connected")
        || normalized.contains("client connected")
        || normalized.contains("proxy-only connected");
    let failed = normalized.contains("handshake failed")
        || normalized.contains("tcp connect failed")
        || normalized.contains("authentication failed")
        || normalized.contains("server rejected")
        || normalized.contains("connection failed");
    let (severity, signal) = if failed {
        (Severity::Error, Some(ConnectionSignal::Failed))
    } else if connected {
        (Severity::Success, Some(ConnectionSignal::Connected))
    } else {
        (Severity::Info, None)
    };
    TelemetryEvent {
        message: line.trim_end().to_owned(),
        severity,
        signal,
    }
}
