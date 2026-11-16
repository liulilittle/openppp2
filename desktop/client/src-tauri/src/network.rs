use serde_json::Value;

pub fn validate(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("Network overrides must be an object")?;
    if object
        .keys()
        .any(|k| !["client", "dns", "udp", "routing", "geo-rules", "p2p"].contains(&k.as_str()))
    {
        return Err("Unsupported network override".into());
    }
    if value.to_string().len() > 2 * 1024 * 1024 {
        return Err("Network configuration exceeds 2 MiB".into());
    }
    for (key, item) in object {
        if !item.is_object() {
            return Err(format!("{key} must be an object"));
        }
    }
    if let Some(client) = value.get("client").and_then(Value::as_object) {
        if client
            .keys()
            .any(|key| !["routing", "http-proxy", "socks-proxy"].contains(&key.as_str()))
        {
            return Err("Network overrides cannot change node identity".into());
        }
    }
    for pointer in [
        "/client/routing/ip/bypass",
        "/client/routing/ip/routes",
        "/client/routing/ip/peer-routes",
        "/client/routing/dns/rules",
    ] {
        if value.pointer(pointer).is_some_and(|v| !v.is_array()) {
            return Err(format!("{pointer} must be an array"));
        }
    }
    if let Some(p2p) = value.get("p2p").and_then(Value::as_object) {
        if p2p.keys().any(|key| !["enabled", "mode"].contains(&key.as_str())) {
            return Err("Unsupported P2P override".into());
        }
        if p2p.get("enabled").is_some_and(|v| !v.is_boolean()) {
            return Err("P2P enabled must be a boolean".into());
        }
        if p2p
            .get("mode")
            .is_some_and(|v| !matches!(v.as_str(), Some("relay" | "direct-preferred")))
        {
            return Err("P2P mode must be relay or direct-preferred".into());
        }
    }
    if let Some(ttl) = value.pointer("/udp/dns/ttl") {
        if ttl.as_u64().is_none() {
            return Err("DNS TTL must be a non-negative integer".into());
        }
    }
    if let Some(ip) = value
        .pointer("/dns/ecs/override-ip")
        .and_then(Value::as_str)
    {
        if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
            return Err("Invalid ECS IP address".into());
        }
    }
    if let Some(range) = value.pointer("/dns/fake-ip/range").and_then(Value::as_str) {
        let valid = range.split_once('/').is_some_and(|(ip, bits)| {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
                && bits
                    .parse::<u8>()
                    .is_ok_and(|bits| (1..=32).contains(&bits))
        });
        if !valid {
            return Err("Invalid fake-IP IPv4 range".into());
        }
    }
    for name in ["http-proxy", "socks-proxy"] {
        if let Some(proxy) = value.get("client").and_then(|c| c.get(name)) {
            let bind = proxy
                .get("bind")
                .and_then(Value::as_str)
                .ok_or("Proxy bind address is required")?;
            let address: std::net::IpAddr =
                bind.parse().map_err(|_| "Invalid proxy bind address")?;
            if !address.is_loopback() {
                return Err("Desktop proxy listeners must bind to loopback".into());
            }
            if !proxy
                .get("port")
                .and_then(Value::as_u64)
                .is_some_and(|p| (1..=65535).contains(&p))
            {
                return Err("Proxy port must be 1..65535".into());
            }
        }
    }
    Ok(())
}
