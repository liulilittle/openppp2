use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

use crate::subscription::SubscriptionNode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("节点地址必须使用 ppp://")]
    InvalidScheme,
    #[error("节点地址缺少主机或端口")]
    MissingEndpoint,
    #[error("节点地址无效: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("探测列表包含重复节点 ID: {0}")]
    DuplicateNode(String),
}

pub fn parse_probe_endpoint(server: &str) -> Result<ProbeEndpoint, ProbeError> {
    if !server.starts_with("ppp://") {
        return Err(ProbeError::InvalidScheme);
    }
    let body = server.strip_prefix("ppp://").unwrap_or_default();
    let body = body
        .strip_prefix("ws/")
        .or_else(|| body.strip_prefix("wss/"))
        .unwrap_or(body);
    let parsed = Url::parse(&format!("ppp://{body}"))?;
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(ProbeError::MissingEndpoint)?;
    let port = parsed.port().ok_or(ProbeError::MissingEndpoint)?;
    Ok(ProbeEndpoint {
        host: host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned(),
        port,
    })
}

pub fn probe_endpoint(endpoint: &ProbeEndpoint, timeout: Duration) -> Option<u32> {
    let started = Instant::now();
    let addresses = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .ok()?;
    for address in addresses {
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return None;
        };
        if remaining.is_zero() {
            return None;
        }
        if TcpStream::connect_timeout(&address, remaining).is_ok() {
            return Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32);
        }
    }
    None
}

pub fn probe_nodes(
    nodes: Vec<(String, ProbeEndpoint)>,
    max_workers: usize,
    timeout: Duration,
) -> Result<BTreeMap<String, Option<u32>>, ProbeError> {
    let mut ids = BTreeSet::new();
    for (id, _) in &nodes {
        if !ids.insert(id.clone()) {
            return Err(ProbeError::DuplicateNode(id.clone()));
        }
    }
    if nodes.is_empty() {
        return Ok(BTreeMap::new());
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(nodes)));
    let results = Arc::new(Mutex::new(BTreeMap::new()));
    let worker_count = max_workers.max(1).min(4).min(ids.len());
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        workers.push(thread::spawn(move || loop {
            let next = queue.lock().expect("probe queue lock poisoned").pop_front();
            let Some((id, endpoint)) = next else { break };
            let latency = probe_endpoint(&endpoint, timeout);
            results
                .lock()
                .expect("probe result lock poisoned")
                .insert(id, latency);
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(Arc::try_unwrap(results)
        .expect("probe results still shared")
        .into_inner()
        .expect("probe result lock poisoned"))
}

pub fn targets_for_nodes(
    nodes: &[SubscriptionNode],
    node_ids: Option<&[String]>,
) -> Vec<(String, ProbeEndpoint)> {
    let selected = node_ids.map(|ids| ids.iter().map(String::as_str).collect::<BTreeSet<_>>());
    nodes
        .iter()
        .filter(|node| {
            selected
                .as_ref()
                .is_none_or(|selected| selected.contains(node.id.as_str()))
        })
        .filter_map(|node| {
            let endpoint = parse_probe_endpoint(node.server.as_deref()?).ok()?;
            Some((node.id.clone(), endpoint))
        })
        .collect()
}
