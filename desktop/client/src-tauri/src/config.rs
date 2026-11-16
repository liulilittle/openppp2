use crate::subscription::SubscriptionNode;
use serde_json::{Map, Value};
use std::path::Path;
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
    let defaults: Value = serde_json::from_str(DEFAULT_CONFIG)?;
    for field in ["key", "client", "websocket"] {
        if root.get(field).is_none() {
            root[field] = defaults[field].clone();
        } else if !root[field].is_object() {
            return Err(ConfigError::InvalidFullConfig);
        }
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
    if !client.get("mappings").is_some_and(Value::is_array) {
        client.insert("mappings".into(), Value::Array(Vec::new()));
    }
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

/// Top-level fields the kernel rejects next to `client.policy` (policy v2).
const LEGACY_POLICY_ROOT_FIELDS: [&str; 5] = ["routing", "geo-rules", "dns", "bypass", "dns-rules"];
/// `client.*` fields the kernel rejects next to `client.policy`.
const LEGACY_POLICY_CLIENT_FIELDS: [&str; 3] = ["routing", "bypass", "dns-rules"];

pub fn uses_policy_v2(config: &Value) -> bool {
    config
        .pointer("/client/policy")
        .is_some_and(|policy| !policy.is_null())
}

pub fn apply_network_overrides(config: &mut Value, overrides: &Value) -> Result<(), ConfigError> {
    if !overrides.is_object() || !config.is_object() {
        return Err(ConfigError::InvalidFullConfig);
    }
    fn merge(target: &mut Value, source: &Value) {
        if let Some(fields) = source.as_object() {
            if !target.is_object() { *target = Value::Object(Map::new()); }
            for (key, value) in fields { merge(&mut target[key], value); }
        } else { *target = source.clone(); }
    }
    if uses_policy_v2(config) {
        // Routing and DNS overrides are policy v1; a v2 node owns them in
        // client.policy, so only the remaining overrides apply.
        let mut overrides = overrides.clone();
        strip_legacy_policy(&mut overrides);
        merge(config, &overrides);
    } else {
        merge(config, overrides);
    }
    Ok(())
}

/// Removes policy v1 fields, which the kernel refuses to load together with
/// `client.policy`. The desktop defaults carry `dns` and `udp.dns`, so a
/// compact v2 node would otherwise never start.
pub fn strip_legacy_policy(config: &mut Value) {
    if let Some(root) = config.as_object_mut() {
        for field in LEGACY_POLICY_ROOT_FIELDS {
            root.remove(field);
        }
    }
    if let Some(udp) = config.get_mut("udp").and_then(Value::as_object_mut) {
        udp.remove("dns");
    }
    if let Some(client) = config.get_mut("client").and_then(Value::as_object_mut) {
        for field in LEGACY_POLICY_CLIENT_FIELDS {
            client.remove(field);
        }
    }
}

/// Prepares a policy v2 configuration for the runtime directory: drops the
/// v1 fields and anchors relative rule, rule-set and fake-IP paths to the
/// GUI-managed `policy_dir`. The kernel resolves them against the directory
/// of the generated config otherwise, where no rule files live.
pub fn prepare_policy_v2(config: &mut Value, policy_dir: &Path) {
    if !uses_policy_v2(config) {
        return;
    }
    strip_legacy_policy(config);
    let Some(policy) = config.pointer_mut("/client/policy") else {
        return;
    };
    let anchor = |value: Option<&mut Value>| {
        if let Some(value) = value {
            if let Some(path) = value.as_str().filter(|path| !path.is_empty()) {
                if Path::new(path).is_relative() {
                    *value = Value::String(policy_dir.join(path).to_string_lossy().into_owned());
                }
            }
        }
    };
    anchor(policy.pointer_mut("/rules/path"));
    anchor(policy.pointer_mut("/dns/fake-ip/storage"));
    if let Some(sets) = policy.get_mut("rule-sets").and_then(Value::as_object_mut) {
        for set in sets.values_mut() {
            anchor(set.pointer_mut("/source/path"));
        }
    }
}
