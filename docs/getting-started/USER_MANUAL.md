# User Manual
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [用户手册](USER_MANUAL_CN.md)


[中文版本](USER_MANUAL_CN.md)

## Position

This is the user-facing guide to OPENPPP2 as a network runtime.
It covers what OPENPPP2 is, how to run it, how to configure it for common scenarios, and what host changes to expect.

---

## What OPENPPP2 Is

OPENPPP2 is a single-binary, multi-role, cross-platform virtual networking runtime. It can run as client or server and can combine routing, DNS steering, reverse mappings, static packet paths, MUX, platform integration, and an optional management backend.

```mermaid
flowchart TD
    A[OPENPPP2] --> B[Client Mode]
    A --> C[Server Mode]
    B --> D[Virtual NIC + tunnel]
    B --> E[Split or full tunnel routing]
    B --> F[DNS steering]
    B --> G[MUX / static UDP]
    C --> H[Session routing]
    C --> I[TCP + UDP forwarding]
    C --> J[IPv6 transit]
    C --> K[Optional Go backend]
```

---

## What To Decide First

Before writing config or running commands, decide:

| Decision | Options | Guidance |
|----------|---------|---------|
| Node role | `client`, `proxy-only` client, or `server` | Run a **server** on a machine with a public IP. Run a **client** on machines that should route traffic through that server. Use **proxy-only** if you want local HTTP/SOCKS proxies without changing system routes. |
| Host platform | Linux, Windows, macOS, Android, iOS | Affects which binary to download and what permissions you need |
| Tunnel mode | full tunnel or split tunnel | **Full tunnel**: all traffic goes through the server. **Split tunnel**: only selected IPs (e.g. non-China) go through; the rest go direct. |

---

## Basic Run Model

| Scenario | Command |
|----------|---------|
| Start as server (default) | `./ppp` |
| Start as server with explicit config | `./ppp --config=/etc/openppp2/appsettings.json` |
| Start as client | `./ppp --mode=client` |
| Start as client with explicit config | `./ppp --mode=client --config=./appsettings.json` |
| Start as proxy-only client | `./ppp --mode=proxy --config=./appsettings.json` |

Requirements:
- Full-tunnel client/server host integration needs Administrator on Windows and root/CAP_NET_ADMIN on Linux/macOS.
- Desktop proxy-only uses `TapStub` and does not install host routes; it normally does not require root for network takeover. Android/iOS still require the platform VPN approval/entitlement flow.
- Configuration file at an accessible path.

---

## What The Host Will Change

Depending on platform, role, and routing mode, OPENPPP2 may change:

| Host element | Client (TUN) | Client (proxy-only) | Server |
|-------------|--------------|---------------------|--------|
| Virtual NIC | Created | Desktop uses `TapStub`; mobile uses the framework interface | Not created |
| OS routing table | TUN and policy routes may be added/protected | No desktop host routes; mobile keeps only the minimal interface/subnet route | Not modified |
| DNS configuration | Tunnel/system DNS may be configured | Native DNS rules remain active, but system DNS is not taken over | Not modified |
| System HTTP proxy | Only if explicitly configured by the platform/helper path | Not published automatically; use local HTTP/SOCKS listeners manually | Not set |
| IPv6 settings | If TUN IPv6 is enabled | No host IPv6 capture or system DNS takeover | If `server.ipv6` enabled |
| Firewall rules | Not modified | Not modified | May set rules |

The routing mode changes host integration, not the native client policy. `client.routing`
bypass, ordinary routes, peer-prefix routes, and DNS rules are consumed in both modes.
Proxy-only only suppresses desktop host-route and system-DNS takeover.

**On Android and iOS (proxy-only):**

- The VPN framework keeps only the minimal interface/subnet route.
- Default routes, system DNS, and the local HTTP proxy are not published automatically.
- Native bypass and DNS policy still loads.
- Android cannot publish its local HTTP proxy as the VPN system proxy — the native listener cannot reserve the port until after the VPN is established, so earlier publishing risks another local app intercepting proxy traffic. Use full-tunnel mode, or configure trusted clients to connect to the local HTTP/SOCKS endpoint directly.

---

## Recommended Reading Order

1. [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) — overall system design
2. [`STARTUP_AND_LIFECYCLE.md`](../architecture/STARTUP_AND_LIFECYCLE.md) — how the process starts and stops
3. [`CONFIGURATION.md`](../reference/CONFIGURATION.md) — configuration file reference
4. [`CLI_REFERENCE.md`](../reference/CLI_REFERENCE.md) — command-line arguments
5. [`PLATFORMS.md`](../guides/PLATFORMS.md) — platform-specific notes
6. [`DEPLOYMENT.md`](../operations/DEPLOYMENT.md) — deployment checklist
7. [`OPERATIONS.md`](../operations/OPERATIONS.md) — troubleshooting

---

## Quick Start

### Server Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Obtain the release package | `openppp2-linux-amd64-simd.zip` |
| 2 | Extract and enter the directory | `mkdir -p openppp2 && cd openppp2` |
| 3 | Edit the server config | Set `tcp.listen.port`, `key.*` fields |
| 4 | Start the runtime | `sudo ./ppp` |

Minimal server config:

> **⚠ Security:** Replace the example `protocol-key` and `transport-key` values before deploying. The values below are placeholders and must not be used in production.

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true
  }
}
```

### Client Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Create an install directory | `mkdir -p /opt/openppp2` |
| 2 | Extract the release package | `unzip openppp2-linux-amd64.zip -d /opt/openppp2` |
| 3 | Edit the client config | Set `client.guid`, `client.server`, `key.*` to match server |
| 4 | Start as root | `sudo ./ppp --mode=client` |

Minimal client config:

> **⚠ Security:** Use the same `protocol-key` and `transport-key` as your server, and generate your own unique values.

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "client": {
    "guid": "{F4519CF1-7A8A-4B00-89C8-9172A87B96DB}",
    "server": "ppp://192.168.0.1:20000/"
  }
}
```

---

## Tunnel Mode Selection

```mermaid
flowchart TD
    A[Choose runtime mode] --> B{--mode=proxy or client.proxy-only?}
    B -->|yes| C[Proxy-only mode]
    B -->|no| D[TUN client mode]
    C --> E[Local HTTP/SOCKS + native policy\nNo host route/DNS takeover]
    D --> F{All traffic via tunnel?}
    F -->|yes| G[Full tunnel mode]
    F -->|no| H[Split tunnel / DNS steering]
    G --> I[Configure canonical IP/DNS policy]
    H --> I
```

| Mode | Description | Key config |
|------|-------------|-----------|
| Full tunnel | All traffic goes through the TUN policy | `--mode=client` with no bypass entries |
| Split tunnel | Selected IPs bypass the tunnel while native route policy remains active | `--mode=client`; `client.routing.ip.bypass`, `ip.routes`, or `ip.peer-routes` |
| DNS steering | Domain-based resolver selection in native DNS policy | `client.routing.dns.rules` |
| Proxy-only | Local HTTP/SOCKS entry points use native bypass/route/DNS policy; no desktop host route or system DNS takeover | `--mode=proxy` or `client.proxy-only: true` |
| Service publishing | Server publishes local services via FRP | `server.mappings` |
| IPv6 serving | Server provides IPv6 transit | `server.ipv6` |

---

## Configuration Reference Highlights

### Core Fields

| Parameter | Type | Example | Description | Applies to |
|-----------|------|---------|-------------|-----------|
| `concurrent` | int | `4` | IO thread concurrency | both |
| `key.kf` | int | `154543927` | Protocol key factor | both |
| `key.protocol` | string | `"aes-128-cfb"` | Encryption cipher | both |
| `key.transport` | string | `"aes-256-cfb"` | Transport cipher | both |

### Client Fields

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `client.guid` | string | `"{F4519CF1-...}"` | Client unique identifier |
| `client.server` | string | `"ppp://192.168.0.1:20000/"` | Server connection address |
| `client.server-proxy` | string | `"http://user:pass@proxy:8080/"` | Proxy to reach server |
| `client.bandwidth` | int | `10000` | Bandwidth limit in Kbp/s |
| `client.proxy-only` | bool | `false` | Independent runtime flag; suppresses host takeover but not native policy; `--mode=proxy` selects the same behavior |
| `client.routing` | object | `{ "ip": ..., "dns": ... }` | Canonical IP/DNS policy only; an old nested mode key is ignored and not serialized |
| `client.routing.ip.bypass` | array | `["file:///etc/bypass.txt"]` | Native bypass policy sources, active in both modes |
| `client.routing.ip.routes` | array | `[]` | Native ordinary route sources; desktop host projection is separate |
| `client.routing.ip.peer-routes` | array | `[]` | Native peer-prefix route sources |
| `client.routing.dns.rules` | array | `["file:///etc/dns.txt"]` | Native DNS policy sources, active in both modes |

### Server Fields

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `server.node` | int | `1` | Server node ID |
| `tcp.listen.port` | int | `20000` | TCP tunnel listener port |
| `websocket.listen.ws` | int | `20080` | WebSocket listener port (0 = disabled) |
| `websocket.listen.wss` | int | `20443` | TLS WebSocket listener port (0 = disabled) |
| `server.backend` | string | `"ws://backend:80/ppp/webhook"` | Optional management backend |
| `server.ipv4-pool.network` | string | `"10.0.0.0"` | IPv4 address pool for client assignment |
| `server.ipv4-pool.mask` | string | `"255.255.255.0"` | IPv4 pool subnet mask |

---

## DNS Rules

| Item | Description | Link |
|------|-------------|------|
| Main DNS rules list | Regularly updated Mainland China domain direct-connect rules | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

DNS rules file format — two styles are supported:

**Legacy IP-target format** (routes a domain directly to a DNS server IP):
```
# Route these domains to a specific DNS IP
.example.com 192.168.1.1
.google.com 8.8.8.8
```

**Recommended provider format** (routes a domain to a named provider; supports DoH/DoT):
```
# Domain routed through the built-in cloudflare provider
.google.com /cloudflare/tun
# Domain routed through doh.pub
.cn /doh.pub/tun
```

The provider format is preferred. Provider names are configured in the `dns` block. See [Routing and DNS](../guides/ROUTING_AND_DNS.md) for details.

---

## HTTPS Certificates

| Item | Description | Location |
|------|-------------|----------|
| Runtime root certificate | Place `cacert.pem` in the runtime directory | `cacert.pem` next to `ppp` |
| Mirror repository | Alternate certificate source | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | Official CA extract page | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

---

## Common Scenarios

### Scenario 1: Full Tunnel Client On Linux

```bash
# 1. Install
mkdir -p /opt/openppp2
cd /opt/openppp2
unzip openppp2-linux-amd64-simd.zip

# 2. Edit appsettings.json — set client.server, key fields

# 3. Run
sudo ./ppp --mode=client
```

Expected result: all traffic routes through the server.

### Scenario 2: Split Tunnel With China Bypass

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://server-ip:20000/",
    "proxy-only": false,
    "routing": {
      "ip": {
        "bypass": ["file:///opt/openppp2/rules/china-cidr.txt"],
        "routes": [],
        "peer-routes": []
      },
      "dns": { "rules": [] }
    }
  }
}
```

Expected result: Mainland China IPs go direct; all other traffic through tunnel.
The same native bypass/route/DNS policy is used in proxy-only mode when `--mode=proxy`
or `client.proxy-only` is enabled, but desktop host routes and system DNS are not taken
over; configure trusted clients to use the local HTTP/SOCKS listener.

### Scenario 3: Server With Management Backend

```json
{
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true,
    "backend": "ws://192.168.0.100/ppp/webhook"
  }
}
```

Expected result: client sessions authenticated and accounted by Go backend.

### Scenario 4: WebSocket Server Behind Nginx

```json
{
  "websocket": {
    "host": "your-domain.com",
    "path": "/tun",
    "listen": {
      "ws": 8080
    }
  }
}
```

Then configure Nginx to proxy WebSocket to port 8080.

Client connection string:

```
ppp://ws/192.168.0.1:443/
```

---

## Connection URL Formats

| Format | Protocol | Example |
|--------|----------|---------|
| `ppp://host:port/` | Raw TCP | `ppp://1.2.3.4:20000/` |
| `ppp://ws/host:port/` | WebSocket | `ppp://ws/1.2.3.4:443/` |
| `ppp://wss/host:port/` | TLS WebSocket | `ppp://wss/1.2.3.4:443/` |

---

## Appendix 1: UDP Static Aggregator

UDP static aggregator bonds multiple UDP paths to a single tunnel for higher throughput and redundancy.

| Parameter | Type | Example | Description | Applies to |
|-----------|------|---------|-------------|-----------|
| `udp.static.aggligator` | int | `4` | Aggregator link count | `client` |
| `udp.static.servers` | array | `["1.0.0.1:20000"]` | Aggregator or forwarding server list | `client` |

| Condition | Meaning |
|-----------|---------|
| `udp.static.aggligator > 0` | Enable aggregator mode; `servers` required |
| `udp.static.aggligator <= 0` | Enable static tunnel mode |

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

---

## Appendix 2: Linux Routing Forwarding

### Enable IPv4 and IPv6 Forwarding

Add to `/etc/sysctl.conf`:

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
```

Apply:

```bash
sysctl -p
```

### Dual-NIC Routing Example

```bash
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### Bypass SNAT Example

```bash
iptables -A FORWARD -s 192.168.0.0/24 -d 0.0.0.0/0 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -d 192.168.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to 192.168.0.20
```

---

## Appendix 3: Windows Soft Router Forwarding

| Item | Example |
|------|---------|
| Virtual gateway tool | VGW |
| Download | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

VGW example parameters:

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `--ip` | string | `192.168.0.40` | Virtual gateway IP |
| `--ngw` | string | `192.168.0.1` | Main router gateway |
| `--mask` | string | `255.255.255.0` | Subnet mask |
| `--mac` | string | `30:fc:68:88:b4:a9` | Custom virtual MAC |

---

## Appendix 4: Android Deployment

Android deployment uses the VPNService API. OPENPPP2 is embedded as a native library:

```mermaid
flowchart TD
    A[Android App] --> B[VPNService]
    B --> C[JNI Bridge]
    C --> D[OPENPPP2 C++ Runtime]
    D --> E[Tunnel to server]
```

Key points:
- Requires `BIND_VPN_SERVICE` and `INTERNET` permissions in `AndroidManifest.xml`.
- JNI functions: `run(config_json)`, `stop()`, `release()`.
- No root required; uses Android VPNService framework.
- Error codes returned as integers mapping to `ppp::diagnostics::ErrorCode`.

---

## Appendix 5: IPv6 Transit (Server)

To enable IPv6 transit on the server:

```json
{
  "server": {
    "ipv6": {
      "cidr": "fdec:1234::/64"
    }
  }
}
```

This allows clients to receive IPv6 addresses and reach IPv6 destinations through the server.

See [`IPV6_TRANSIT_PLANE.md`](../guides/IPV6_TRANSIT_PLANE.md) for full details.

---

## Appendix 6: FRP Reverse Mapping (Service Publishing)

To publish a local service through the server:

```json
{
  "server": {
    "mappings": [
      {
        "local-ip": "127.0.0.1",
        "local-port": 22,
        "remote-port": 10022,
        "protocol": "tcp"
      }
    ]
  }
}
```

This publishes `localhost:22` on the server as `server-ip:10022`.

---

## Troubleshooting Quick Reference

| Symptom | Most likely cause | Fix |
|---------|-----------------|-----|
| Process exits immediately | Missing privilege | Run as root/administrator |
| "configuration not found" | Wrong config path | Use `--config=/absolute/path` |
| Cannot reach server | Network or firewall | Test with `nc` or `telnet` first |
| DNS not working through tunnel | DNS route missing | Check bypass list covers DNS servers |
| Sessions drop | Keepalive failure | Check `keepalive.*` config values |
| Routes not restored after exit | Forced kill | Use SIGTERM for graceful stop |

---

## Related Documents

- [`CONFIGURATION.md`](../reference/CONFIGURATION.md)
- [`CLI_REFERENCE.md`](../reference/CLI_REFERENCE.md)
- [`DEPLOYMENT.md`](../operations/DEPLOYMENT.md)
- [`OPERATIONS.md`](../operations/OPERATIONS.md)
- [`PLATFORMS.md`](../guides/PLATFORMS.md)
- [`ROUTING_AND_DNS.md`](../guides/ROUTING_AND_DNS.md)
- [`SECURITY.md`](../operations/SECURITY.md)
- [`MANAGEMENT_BACKEND.md`](../guides/MANAGEMENT_BACKEND.md)
