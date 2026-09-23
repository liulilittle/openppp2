# Proxy-only mode
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-31.
> **Parent index:** [Back to index](README.md) · **Chinese:** [纯代理模式](PROXY_MODE_CN.md)


Proxy-only mode connects to an OpenPPP2 server and exposes **local HTTP and SOCKS5 forward proxies** without installing host-system route entries or system DNS settings. It still loads the canonical routing policy into the native client. Desktop startup uses `TapStub`; mobile platforms keep only the minimal tunnel interface needed by the runtime. Not installing a host rule does not disable the corresponding native policy.

## Quick start

```bash
./ppp --mode=proxy --config=./appsettings.json
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

Prefer the canonical `client.routing` object for IP/DNS policy. When present, it is authoritative for those policy sources; runtime mode remains independent:

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://your-server:20000/",
    "proxy-only": true,
    "routing": {
      "ip": {
        "bypass": [],
        "routes": [],
        "peer-routes": []
      },
      "dns": {
        "rules": []
      }
    },
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

`client.proxy-only` is an independent top-level runtime flag and is read even when `client.routing` is present. Legacy `client.routes` and `client.peer-routes` are fallback inputs only when the canonical object is absent; an old nested mode key is ignored and never serialized. Use `--mode=client` or `--mode=proxy` to select the command-line runtime mode; `--mode=proxy` is equivalent to enabling proxy-only behavior.

When ports or bind addresses are omitted, defaults are applied automatically:

| Listener | Default bind | Default port |
|----------|--------------|--------------|
| HTTP     | 127.0.0.1    | 8080         |
| SOCKS5   | 127.0.0.1    | 1080         |

## Platform behavior

| Platform | What changes in proxy-only | What stays active |
|----------|---------------------------|-------------------|
| Linux / macOS / Windows | No OS routes installed; no system DNS override; `TapStub` used instead of a real TUN | Native bypass, routes, peer-routes, and DNS rules still load. Local HTTP/SOCKS proxies are available. No root required. |
| Android | `VpnService.Builder` installs only the VPN interface subnet route; no IPv6 capture; no tunnel DNS | Native bypass, routes, peer-routes, and DNS rules still load. Requires VpnService permission. |
| iOS | `PacketTunnelProvider` installs only the tunnel-subnet included route; no bypass exclusions; no `NEDNSSettings` | Native routing and DNS policy still loads. Requires Network Extension entitlement. |

Both TUN and proxy-only load `routing.ip.bypass`, `routing.ip.routes`, `routing.ip.peer-routes`, and `routing.dns.rules` into the native policy. The difference is only in what gets projected to the host OS.

**Android:** Enable proxy-only in the app under **仅代理模式** (`vpnOptions.proxyOnly=true`). A minimal TUN is still created for `protect()` calls.

**iOS:** The extension reads `client.proxy-only` from the prepared config JSON and adjusts the `NEPacketTunnelNetworkSettings` accordingly.

## Static transport

Proxy-only mode forces static transport off. This means:

- The `STATIC`/`STATICACK` exchange does not happen.
- If `--tun-ip` would normally enable static transport, it is overridden.
- IPv4 address allocation uses automatic mode instead of submitting the local TUN address.

## CLI flags

| Flag | Description |
|------|-------------|
| `--mode=proxy` | Select proxy-only runtime |
| `--proxy-http-port=N` | Override HTTP listen port |
| `--proxy-socks-port=N` | Override SOCKS listen port |

See [CLI_REFERENCE.md](../reference/CLI_REFERENCE.md) and [CONFIGURATION.md](../reference/CONFIGURATION.md) for full details.

## Related docs

- [Routing And DNS](ROUTING_AND_DNS.md) — normalized routing policy and DNS behavior
- [Platform Integration](PLATFORMS.md) — desktop, Android, and iOS boundaries
- [CLI Reference](../reference/CLI_REFERENCE.md) — all command-line flags
- [Configuration Reference](../reference/CONFIGURATION.md) — all config fields
