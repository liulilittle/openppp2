use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LaunchOptionsError {
    #[error("节点启动参数必须是 JSON object")]
    InvalidNodeOptions,
    #[error("启动参数 {0} 必须是字符串")]
    InvalidString(String),
    #[error("启动参数 {0} 必须是布尔值")]
    InvalidBoolean(String),
    #[error("启动参数 mux 必须是 0 到 65535 之间的整数")]
    InvalidMux,
    #[error("启动参数 muxMode 必须是 compat、flow、balance 或 stripe")]
    InvalidMuxMode,
    #[error("启动参数 tcpStack 必须是 native、lwip 或 xtcp")]
    InvalidTcpStack,
    #[error("启动参数 tunIpv6 必须是 IPv6 地址")]
    InvalidTunIpv6,
    #[error("启动参数 proxyForwards 必须是逗号分隔的 端口 或 端口:本机端口（1-65535）")]
    InvalidProxyForwards,
}

pub fn merge_launch_options(
    global: &BTreeMap<String, Value>,
    node: Option<&Value>,
) -> Result<BTreeMap<String, Value>, LaunchOptionsError> {
    let mut merged = global.clone();
    if let Some(node) = node {
        let values = node
            .as_object()
            .ok_or(LaunchOptionsError::InvalidNodeOptions)?;
        for (key, value) in values {
            merged.insert(key.clone(), value.clone());
        }
    }
    Ok(merged)
}

pub fn append_launch_args(
    options: &BTreeMap<String, Value>,
    args: &mut Vec<String>,
) -> Result<(), LaunchOptionsError> {
    for (field, flag) in [
        ("tunIp", "--tun-ip"),
        ("tunMask", "--tun-mask"),
        ("gateway", "--tun-gw"),
    ] {
        if let Some(value) = optional_string(options, field)? {
            args.push(format!("{flag}={value}"));
        }
    }

    let dns = [
        optional_string(options, "dns1")?,
        optional_string(options, "dns2")?,
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !dns.is_empty() {
        args.push(format!("--dns={}", dns.join(",")));
    }

    if let Some(value) = options.get("mux") {
        let mux = value.as_u64().filter(|value| *value <= u16::MAX as u64);
        let mux = mux.ok_or(LaunchOptionsError::InvalidMux)?;
        args.push(format!("--tun-mux={mux}"));
    }
    if let Some(mode) = optional_string(options, "muxMode")? {
        if !["compat", "flow", "balance", "stripe"].contains(&mode) {
            return Err(LaunchOptionsError::InvalidMuxMode);
        }
        args.push(format!("--mux-mode={mode}"));
    }
    if let Some(stack) = optional_string(options, "tcpStack")? {
        if !["native", "lwip", "xtcp"].contains(&stack) {
            return Err(LaunchOptionsError::InvalidTcpStack);
        }
        args.push(format!("--tcp-stack={stack}"));
    }
    if let Some(address) = optional_string(options, "tunIpv6")? {
        // A request hint only; the server owns IPv6 allocation.
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(LaunchOptionsError::InvalidTunIpv6);
        }
        args.push(format!("--tun-ipv6={address}"));
    }
    for (field, flag) in [
        ("vnet", "--tun-vnet"),
        ("blockQuic", "--block-quic"),
        ("staticMode", "--tun-static"),
        ("muxTurbo", "--mux-mode-turbo"),
        // Proxy mode only: join the virtual subnet / proxy Internet destinations.
        ("proxySubnet", "--proxy-subnet"),
        ("proxyInternet", "--proxy-internet"),
    ] {
        if let Some(value) = optional_bool(options, field)? {
            args.push(format!("{flag}={}", if value { "yes" } else { "no" }));
        }
    }
    if let Some(forwards) = optional_string(options, "proxyForwards")? {
        args.push(format!("--proxy-forward={}", normalize_proxy_forwards(forwards)?));
    }
    Ok(())
}

/// Validates `22,8080:3000`: virtual-IP ports, each optionally mapped to a local port.
fn normalize_proxy_forwards(value: &str) -> Result<String, LaunchOptionsError> {
    let port = |text: &str| text.trim().parse::<u16>().ok().filter(|port| *port > 0);
    let mut items = Vec::new();
    for item in value.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        let normalized = match item.split_once(':') {
            Some((remote, local)) => format!(
                "{}:{}",
                port(remote).ok_or(LaunchOptionsError::InvalidProxyForwards)?,
                port(local).ok_or(LaunchOptionsError::InvalidProxyForwards)?
            ),
            None => port(item).ok_or(LaunchOptionsError::InvalidProxyForwards)?.to_string(),
        };
        items.push(normalized);
    }
    Ok(items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proxy_subnet_maps_to_kernel_flag_only_when_set() {
        let mut args = Vec::new();
        append_launch_args(&BTreeMap::new(), &mut args).unwrap();
        assert!(!args.iter().any(|arg| arg.starts_with("--proxy-subnet")));

        let options = BTreeMap::from([("proxySubnet".to_string(), json!(false))]);
        append_launch_args(&options, &mut args).unwrap();
        assert_eq!(args, vec!["--proxy-subnet=no".to_string()]);

        let invalid = BTreeMap::from([("proxySubnet".to_string(), json!("yes"))]);
        assert!(append_launch_args(&invalid, &mut Vec::new()).is_err());
    }

    #[test]
    fn proxy_forwards_are_validated_and_normalized() {
        let mut args = Vec::new();
        let options = BTreeMap::from([("proxyForwards".to_string(), json!(" 22, 8080:3000 "))]);
        append_launch_args(&options, &mut args).unwrap();
        assert_eq!(args, vec!["--proxy-forward=22,8080:3000".to_string()]);

        for bad in ["0", "70000", "22:", "abc", "22:x"] {
            let options = BTreeMap::from([("proxyForwards".to_string(), json!(bad))]);
            assert!(append_launch_args(&options, &mut Vec::new()).is_err(), "{bad}");
        }
    }
}

fn optional_string<'a>(
    options: &'a BTreeMap<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, LaunchOptionsError> {
    match options.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok((!value.trim().is_empty()).then(|| value.trim())),
        Some(_) => Err(LaunchOptionsError::InvalidString(field.into())),
    }
}

fn optional_bool(
    options: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Option<bool>, LaunchOptionsError> {
    match options.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(LaunchOptionsError::InvalidBoolean(field.into())),
    }
}
