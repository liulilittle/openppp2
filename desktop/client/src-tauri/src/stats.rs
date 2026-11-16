use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatsError {
    #[error("stats JSON 无效: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("stats type 必须是 ppp-stats")]
    WrongType,
    #[error("仅支持 stats version=1")]
    WrongVersion,
}

#[derive(Clone, Debug, Deserialize)]
struct StatsRecord {
    #[serde(rename = "type")]
    record_type: String,
    version: u32,
    monotonic_ms: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    link: LinkRecord,
    runtime: RuntimeRecord,
    #[serde(default)]
    tcp_stack: Option<TcpStackRecord>,
}

#[derive(Clone, Debug, Deserialize)]
struct TcpStackRecord {
    #[serde(default)]
    active: String,
}

#[derive(Clone, Debug, Deserialize)]
struct LinkRecord {
    quality_percent: f64,
    grade: String,
    error_count: u64,
    success_count: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct RuntimeRecord {
    phase: String,
    role: String,
    #[serde(default)]
    traffic: Option<TrafficRecord>,
    #[serde(default)]
    requested_mux_mode: String,
    #[serde(default)]
    effective_mux_mode: String,
    #[serde(default)]
    mux_active_links: u16,
    #[serde(default)]
    effective_path: String,
    #[serde(default)]
    p2p_state: String,
    #[serde(default)]
    peers: Vec<PeerRecord>,
    #[serde(default)]
    last_error: RuntimeError,
}

#[derive(Clone, Debug, Deserialize)]
struct PeerRecord {
    #[serde(default)]
    virtual_ip: u32,
    #[serde(default)]
    state: String,
    #[serde(default)]
    effective_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    pub virtual_ip: String,
    pub state: String,
    pub effective_path: String,
}

impl From<&PeerRecord> for PeerView {
    fn from(peer: &PeerRecord) -> Self {
        // The kernel keeps the address in network byte order: first octet in the low byte.
        let ip = std::net::Ipv4Addr::from(peer.virtual_ip.to_le_bytes());
        Self {
            virtual_ip: ip.to_string(),
            state: peer.state.clone(),
            effective_path: peer.effective_path.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct TrafficRecord {
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeError {
    pub code: u32,
    pub severity: String,
    pub retryable: bool,
    #[serde(alias = "user_message_key")]
    pub user_message_key: String,
    #[serde(alias = "diagnostic_detail")]
    pub diagnostic_detail: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsView {
    pub sampled_at: u64,
    pub rx_rate_mbps: f64,
    pub tx_rate_mbps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub quality_percent: f64,
    pub quality_grade: String,
    pub error_count: u64,
    pub success_count: u64,
    pub phase: String,
    pub role: String,
    pub requested_mux_mode: String,
    pub effective_mux_mode: String,
    pub active_links: u16,
    pub mux_active_links: u16,
    pub effective_path: String,
    pub p2p_state: String,
    pub peers: Vec<PeerView>,
    pub tcp_stack: String,
    pub last_error: RuntimeError,
}

#[derive(Default)]
pub struct StatsSampler {
    previous: Option<StatsRecord>,
    current: Option<StatsView>,
}

impl StatsSampler {
    pub fn current(&self) -> Option<&StatsView> {
        self.current.as_ref()
    }

    pub fn consume_line(&mut self, line: &str) -> Result<StatsView, StatsError> {
        let mut record: StatsRecord = serde_json::from_str(line)?;
        if record.record_type != "ppp-stats" {
            return Err(StatsError::WrongType);
        }
        if record.version != 1 {
            return Err(StatsError::WrongVersion);
        }
        // Session traffic includes proxy traffic; legacy top-level counters may only cover TUN.
        if let Some(traffic) = &record.runtime.traffic {
            record.rx_bytes = traffic.rx_bytes;
            record.tx_bytes = traffic.tx_bytes;
        }
        let (rx_rate_mbps, tx_rate_mbps) = self
            .previous
            .as_ref()
            .and_then(|previous| {
                let elapsed = record.monotonic_ms.checked_sub(previous.monotonic_ms)?;
                let rx = record.rx_bytes.checked_sub(previous.rx_bytes)?;
                let tx = record.tx_bytes.checked_sub(previous.tx_bytes)?;
                (elapsed > 0).then(|| {
                    (
                        rx as f64 * 8.0 / elapsed as f64 / 1000.0,
                        tx as f64 * 8.0 / elapsed as f64 / 1000.0,
                    )
                })
            })
            .unwrap_or((0.0, 0.0));
        let view = StatsView {
            sampled_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            rx_rate_mbps,
            tx_rate_mbps,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            quality_percent: record.link.quality_percent,
            quality_grade: record.link.grade.clone(),
            error_count: record.link.error_count,
            success_count: record.link.success_count,
            phase: record.runtime.phase.clone(),
            role: record.runtime.role.clone(),
            requested_mux_mode: record.runtime.requested_mux_mode.clone(),
            effective_mux_mode: record.runtime.effective_mux_mode.clone(),
            active_links: if record.runtime.phase == "connected" { record.runtime.mux_active_links.max(1) } else { 0 },
            mux_active_links: record.runtime.mux_active_links,
            effective_path: record.runtime.effective_path.clone(),
            p2p_state: record.runtime.p2p_state.clone(),
            peers: record.runtime.peers.iter().map(PeerView::from).collect(),
            tcp_stack: record.tcp_stack.as_ref().map(|stack| stack.active.clone()).unwrap_or_default(),
            last_error: record.runtime.last_error.clone(),
        };
        self.previous = Some(record);
        self.current = Some(view.clone());
        Ok(view)
    }
}
