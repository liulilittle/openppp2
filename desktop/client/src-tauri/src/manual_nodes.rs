use crate::subscription::SubscriptionNode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeSource {
    Manual,
    Subscription,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualNodeInput {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub subtitle: String,
    pub config: Value,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Error)]
pub enum ManualNodeError {
    #[error("节点名称不能为空")]
    EmptyName,
    #[error("节点配置必须是 JSON object")]
    InvalidConfig,
    #[error("节点配置缺少有效的 client.server")]
    InvalidServer,
    #[error("节点配置缺少 key")]
    InvalidKey,
    #[error("{0} 端口必须在 1 到 65535 之间")]
    InvalidPort(String),
    #[error("启动参数必须是 JSON object")]
    InvalidOptions,
    #[error("找不到手动节点: {0}")]
    NotFound(String),
}

pub fn upsert_manual_node(
    nodes: &mut Vec<SubscriptionNode>,
    input: ManualNodeInput,
) -> Result<SubscriptionNode, ManualNodeError> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ManualNodeError::EmptyName);
    }
    let root = input
        .config
        .as_object()
        .ok_or(ManualNodeError::InvalidConfig)?;
    let client = root
        .get("client")
        .and_then(Value::as_object)
        .ok_or(ManualNodeError::InvalidServer)?;
    let server = client
        .get("server")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ManualNodeError::InvalidServer)?;
    let parsed = Url::parse(server).map_err(|_| ManualNodeError::InvalidServer)?;
    if parsed.scheme() != "ppp" || parsed.host_str().is_none() {
        return Err(ManualNodeError::InvalidServer);
    }
    let key = root
        .get("key")
        .and_then(Value::as_object)
        .filter(|value| !value.is_empty())
        .ok_or(ManualNodeError::InvalidKey)?;
    for field in ["http-proxy", "socks-proxy"] {
        if let Some(proxy) = client.get(field).and_then(Value::as_object) {
            let valid = proxy
                .get("port")
                .and_then(Value::as_u64)
                .is_some_and(|port| (1..=65535).contains(&port));
            if !valid {
                return Err(ManualNodeError::InvalidPort(field.into()));
            }
        }
    }
    if !input.options.is_null() && !input.options.is_object() {
        return Err(ManualNodeError::InvalidOptions);
    }

    let (id, index) = match input.id.as_deref() {
        Some(id) => {
            let index = nodes
                .iter()
                .position(|node| node.id == id && id.starts_with("manual:"))
                .ok_or_else(|| ManualNodeError::NotFound(id.into()))?;
            (id.to_owned(), Some(index))
        }
        None => (next_manual_id(nodes), None),
    };
    let node = SubscriptionNode {
        id,
        name: name.into(),
        subtitle: input.subtitle.trim().into(),
        server: Some(server.into()),
        key: Some(Value::Object(key.clone())),
        websocket: root.get("websocket").cloned(),
        client: Some(Value::Object(client.clone())),
        bandwidth: client.get("bandwidth").cloned(),
        options: input.options.is_object().then_some(input.options),
        config: Some(input.config),
    };
    if let Some(index) = index {
        nodes[index] = node.clone();
    } else {
        nodes.push(node.clone());
    }
    Ok(node)
}

pub fn delete_manual_node(
    nodes: &mut Vec<SubscriptionNode>,
    id: &str,
) -> Result<(), ManualNodeError> {
    let index = nodes
        .iter()
        .position(|node| node.id == id && id.starts_with("manual:"))
        .ok_or_else(|| ManualNodeError::NotFound(id.into()))?;
    nodes.remove(index);
    Ok(())
}

pub fn merge_nodes(
    manual: &[SubscriptionNode],
    subscription: &[SubscriptionNode],
) -> Vec<SubscriptionNode> {
    let mut ids = BTreeSet::new();
    manual
        .iter()
        .chain(subscription)
        .filter(|node| ids.insert(node.id.clone()))
        .cloned()
        .collect()
}

pub fn find_node<'a>(
    manual: &'a [SubscriptionNode],
    subscription: &'a [SubscriptionNode],
    id: &str,
) -> Option<&'a SubscriptionNode> {
    manual.iter().chain(subscription).find(|node| node.id == id)
}

pub fn node_source(manual: &[SubscriptionNode], id: &str) -> NodeSource {
    if manual.iter().any(|node| node.id == id) {
        NodeSource::Manual
    } else {
        NodeSource::Subscription
    }
}

fn next_manual_id(nodes: &[SubscriptionNode]) -> String {
    let mut value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    loop {
        let id = format!("manual:{value}");
        if nodes.iter().all(|node| node.id != id) {
            return id;
        }
        value += 1;
    }
}
