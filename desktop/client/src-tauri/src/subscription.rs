use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

pub const MAX_SUBSCRIPTION_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SubscriptionError {
    #[error("订阅正文超过 2 MiB")]
    TooLarge,
    #[error("订阅 JSON 无效: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("订阅 type 必须是 openppp2-subscription")]
    WrongType,
    #[error("仅支持订阅 version=1")]
    WrongVersion,
    #[error("订阅中没有可用节点")]
    NoNodes,
    #[error("节点 {0} 无效: {1}")]
    InvalidNode(String, String),
    #[error("订阅刷新失败: {0}")]
    Refresh(String),
    #[error("订阅缓存读写失败: {0}")]
    Cache(#[from] std::io::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionDocument {
    #[serde(rename = "type")]
    pub document_type: String,
    pub version: u32,
    pub name: Option<String>,
    #[serde(rename = "profilePrefix")]
    pub profile_prefix: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub nodes: Vec<SubscriptionNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionNode {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub subtitle: String,
    pub server: Option<String>,
    pub key: Option<Value>,
    pub websocket: Option<Value>,
    pub client: Option<Value>,
    pub bandwidth: Option<Value>,
    pub options: Option<Value>,
    pub config: Option<Value>,
}

impl SubscriptionNode {
    pub fn client_guid(&self) -> Option<&str> {
        self.client.as_ref()?.get("guid")?.as_str()
    }
}

#[derive(Deserialize)]
struct RawDocument {
    #[serde(rename = "type")]
    document_type: String,
    version: u32,
    name: Option<String>,
    #[serde(rename = "profilePrefix")]
    profile_prefix: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawNode {
    id: String,
    name: Option<String>,
    #[serde(default)]
    subtitle: String,
    #[serde(default = "enabled_default")]
    enabled: bool,
    server: Option<String>,
    key: Option<Value>,
    websocket: Option<Value>,
    client: Option<Value>,
    bandwidth: Option<Value>,
    options: Option<Value>,
    config: Option<Value>,
}

fn enabled_default() -> bool {
    true
}

pub fn parse_subscription(bytes: &[u8]) -> Result<SubscriptionDocument, SubscriptionError> {
    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(SubscriptionError::TooLarge);
    }
    let raw: RawDocument = serde_json::from_slice(bytes)?;
    if raw.document_type != "openppp2-subscription" {
        return Err(SubscriptionError::WrongType);
    }
    if raw.version != 1 {
        return Err(SubscriptionError::WrongVersion);
    }

    let prefix = raw
        .profile_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut nodes = Vec::new();
    for node in raw.nodes.into_iter().filter(|node| node.enabled) {
        let id = node.id.trim().to_owned();
        if id.is_empty() {
            return Err(SubscriptionError::InvalidNode(
                "(empty)".into(),
                "id 不能为空".into(),
            ));
        }
        validate_node(&id, &node)?;
        let raw_name = node
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&id);
        let name = match prefix {
            Some(prefix) if !raw_name.starts_with(prefix) => format!("{prefix} {raw_name}"),
            _ => raw_name.to_owned(),
        };
        nodes.push(SubscriptionNode {
            id,
            name,
            subtitle: node.subtitle,
            server: node.server,
            key: node.key,
            websocket: node.websocket,
            client: node.client,
            bandwidth: node.bandwidth,
            options: node.options,
            config: node.config,
        });
    }
    if nodes.is_empty() {
        return Err(SubscriptionError::NoNodes);
    }
    Ok(SubscriptionDocument {
        document_type: raw.document_type,
        version: raw.version,
        name: raw.name,
        profile_prefix: raw.profile_prefix,
        updated_at: raw.updated_at,
        nodes,
    })
}

fn validate_node(id: &str, node: &RawNode) -> Result<(), SubscriptionError> {
    if let Some(config) = &node.config {
        let valid = match config {
            Value::Object(_) => true,
            Value::String(encoded) => serde_json::from_str::<Value>(encoded)
                .map(|value| value.is_object())
                .unwrap_or(false),
            _ => false,
        };
        return if valid {
            Ok(())
        } else {
            Err(SubscriptionError::InvalidNode(
                id.into(),
                "config 必须是 JSON object".into(),
            ))
        };
    }
    let server = node.server.as_deref().unwrap_or_default();
    let parsed = Url::parse(server).ok();
    if parsed
        .as_ref()
        .is_none_or(|url| url.scheme() != "ppp" || url.host_str().is_none())
    {
        return Err(SubscriptionError::InvalidNode(
            id.into(),
            "server 必须是有效的 ppp:// URI".into(),
        ));
    }
    if node
        .key
        .as_ref()
        .and_then(Value::as_object)
        .is_none_or(|key| key.is_empty())
    {
        return Err(SubscriptionError::InvalidNode(
            id.into(),
            "精简节点必须包含 key".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CacheEnvelope {
    url: String,
    fetched_at_ms: u64,
    document: Value,
}

pub struct RefreshResult {
    pub document: SubscriptionDocument,
    pub cached: bool,
    pub fetched_at_ms: u64,
}

pub fn refresh_with<F>(
    url: &str,
    cache_path: &Path,
    fetch: F,
) -> Result<RefreshResult, SubscriptionError>
where
    F: FnOnce(&str) -> Result<Vec<u8>, String>,
{
    match fetch(url).and_then(|bytes| {
        parse_subscription(&bytes)
            .map(|doc| (bytes, doc))
            .map_err(|e| e.to_string())
    }) {
        Ok((bytes, document)) => {
            let fetched_at_ms = now_ms();
            let envelope = CacheEnvelope {
                url: url.to_owned(),
                fetched_at_ms,
                document: serde_json::from_slice(&bytes)?,
            };
            write_atomic(cache_path, &serde_json::to_vec_pretty(&envelope)?)?;
            Ok(RefreshResult {
                document,
                cached: false,
                fetched_at_ms,
            })
        }
        Err(fetch_error) => {
            let bytes = fs::read(cache_path)
                .map_err(|_| SubscriptionError::Refresh(fetch_error.clone()))?;
            let envelope: CacheEnvelope = serde_json::from_slice(&bytes)
                .map_err(|_| SubscriptionError::Refresh(fetch_error.clone()))?;
            if envelope.url != url {
                return Err(SubscriptionError::Refresh(fetch_error));
            }
            let document_bytes = serde_json::to_vec(&envelope.document)?;
            let document = parse_subscription(&document_bytes)
                .map_err(|_| SubscriptionError::Refresh(fetch_error))?;
            Ok(RefreshResult {
                document,
                cached: true,
                fetched_at_ms: envelope.fetched_at_ms,
            })
        }
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
