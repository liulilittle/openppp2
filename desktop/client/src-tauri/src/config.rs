use crate::subscription::SubscriptionNode;
use serde_json::{Map, Value};
use thiserror::Error;

const DEFAULT_CONFIG: &str = include_str!("default-appsettings.json");

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("客户端默认配置无效: {0}")]
    Default(#[from] serde_json::Error),
    #[error("节点 config 必须是 JSON object")]
    InvalidFullConfig,
    #[error("精简节点缺少 server 或 key")]
    InvalidCompactConfig,
}

pub fn build_node_config(node: &SubscriptionNode) -> Result<Value, ConfigError> {
    build_node_config_with_base(node, None)
}

pub fn build_node_config_with_base(
    node: &SubscriptionNode,
    base: Option<&str>,
) -> Result<Value, ConfigError> {
    if let Some(config) = &node.config {
        return match config {
            Value::Object(_) => Ok(config.clone()),
            Value::String(encoded) => {
                let value: Value = serde_json::from_str(encoded)?;
                if value.is_object() {
                    Ok(value)
                } else {
                    Err(ConfigError::InvalidFullConfig)
                }
            }
            _ => Err(ConfigError::InvalidFullConfig),
        };
    }
    let Some(server) = &node.server else {
        return Err(ConfigError::InvalidCompactConfig);
    };
    let Some(key) = node.key.as_ref().and_then(Value::as_object) else {
        return Err(ConfigError::InvalidCompactConfig);
    };
    let mut root: Value = serde_json::from_str(
        base.filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_CONFIG),
    )?;
    if !root.is_object() {
        return Err(ConfigError::InvalidFullConfig);
    }
    merge_object(
        root.get_mut("key").and_then(Value::as_object_mut).unwrap(),
        key,
    );

    let client = root
        .get_mut("client")
        .and_then(Value::as_object_mut)
        .unwrap();
    if let Some(overrides) = node.client.as_ref().and_then(Value::as_object) {
        merge_object(client, overrides);
    }
    client.insert("server".into(), Value::String(server.clone()));
    client.insert("mappings".into(), Value::Array(Vec::new()));
    if let Some(bandwidth) = &node.bandwidth {
        client.insert("bandwidth".into(), bandwidth.clone());
    }
    if let Some(websocket) = node.websocket.as_ref().and_then(Value::as_object) {
        let target = root
            .get_mut("websocket")
            .and_then(Value::as_object_mut)
            .unwrap();
        merge_object(target, websocket);
    }
    Ok(root)
}

pub fn default_config_string() -> &'static str {
    DEFAULT_CONFIG
}

fn merge_object(target: &mut Map<String, Value>, source: &Map<String, Value>) {
    for (key, value) in source {
        target.insert(key.clone(), value.clone());
    }
}
