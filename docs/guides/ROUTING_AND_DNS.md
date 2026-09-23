# Routing And DNS

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and main verification record, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [路由与 DNS](ROUTING_AND_DNS_CN.md)

> Status: Active
> Type: Reference
> Last verified: c993753

[中文版本](ROUTING_AND_DNS_CN.md)

## Scope

This document explains the real routing and DNS steering model used by OPENPPP2.
In the code, these are not separate concerns. They form one traffic-classification system on the client,
with continued DNS handling on the server.

Main anchors:

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/route/RouteState.*`
- `ppp/app/client/route/RouteCoordinator.*`
- `ppp/app/client/route/RoutePlanInput.h`
- `ppp/app/client/dns/DnsController.*`
- `ppp/app/client/dns/Rule.*`
- `ppp/app/server/VirtualEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetDatagramPort.*`
- `ppp/app/server/VirtualEthernetNamespaceCache.*`

---

## Architecture Overview

```mermaid
flowchart TD
    A[Client application traffic] --> B[VEthernetNetworkSwitcher]
    B --> C{Native traffic classification}
    C -->|bypass list match| D[Local/native next hop]
    C -->|no bypass match| E[Tunnel or local proxy path]

    F[DNS query] --> G{DNS rule match}
    G -->|rule: use resolver X| H[Route to resolver X]
    G -->|no rule| I[Default resolver]
    H --> J{Resolver reachable?}
    J -->|yes| K[Query resolver X]
    J -->|no| L[Fallback to default]

    E --> M[Server VirtualEthernetExchanger]
    M --> N{DNS redirect?}
    N -->|yes| O[VirtualEthernetNamespaceCache]
    N -->|no| P[Forward UDP to real destination]
    O --> Q{cache hit?}
    Q -->|yes| R[Return cached result]
    Q -->|no| S[Forward to upstream resolver]
```

---

## Core Idea

The client decides what uses the local/native path, what goes to the tunnel or local proxy, and which DNS servers must remain reachable.

The server continues the DNS path by:
- answering from cache (fast path)
- redirecting to a configured upstream resolver
- forwarding normally when no special rule applies

### Canonical client routing policy

The normalized configuration surface is `client.routing`:

```json
{
  "client": {
    "proxy-only": false,
    "routing": {
      "ip": {
        "bypass": [
          "10.0.0.0/8",
          "file://./rules/custom-bypass.txt"
        ],
        "routes": [],
        "peer-routes": []
      },
      "dns": {
        "rules": [
          "example.com /cloudflare/tun",
          "file://./rules/custom-dns.txt"
        ]
      }
    }
  }
}
```

`AppConfiguration::Loaded()` applies the following precedence:

1. When `client.routing` is a JSON object, its IP/DNS policy sources are authoritative.
2. Nested `routing.ip.*` and `routing.dns.rules` values take precedence over the direct aliases `routing.bypass`, `routing.routes`, `routing.peer-routes`, and `routing.dns-rules`.
3. The independent top-level `client.proxy-only` flag is read regardless of whether `client.routing` is present; legacy `client.routes`, `client.peer-routes`, and legacy DNS/CLI sources are fallback inputs only when the canonical object is absent.
4. Canonical ordinary routes and peer-prefix routes are mirrored to legacy route fields while older platform consumers migrate. An old nested mode key is ignored and is never emitted by serialization.

`client.proxy-only` and the top-level `--mode=client`/`--mode=proxy` select runtime mode. `client.routing` carries only four native IP/DNS inputs; source strings are trimmed and empty entries are removed. `file://` is case-insensitive; an existing path is read as a file, while an unresolvable source remains inline text. An old nested mode value does not select or override runtime mode.

The canonical client policy has separate IP and DNS layers:

- `routing.ip.bypass` supplies destination prefixes that remain on the physical path or use the configured local/native next hop.
- `routing.ip.routes` supplies ordinary route-file/vBGP sources consumed by native route loading.
- `routing.ip.peer-routes` supplies `network/prefix/via` routes for peer-prefix gateway forwarding; it is not another bypass list.
- `routing.dns.rules` supplies domain-to-resolver rules. They are loaded into the native DNS policy in both `tun` and `proxy-only` modes; proxy-only does not project host-system DNS takeover or DNS reachability routes.

### Runtime decision order

```mermaid
flowchart LR
    A[JSON and CLI inputs] --> B[AppConfiguration::Loaded]
    B --> C[Load native bypass, ordinary/peer routes, and DNS rules]
    C --> D[Build native RIB/FIB and DNS policy]
    D --> E{--mode=proxy or client.proxy-only?}
    E -->|no| F[Create TUN/TAP runtime]
    F --> G[Project capture and platform reachability routes]
    E -->|yes| H[TapStub or minimal mobile VPN]
    H --> I[Local HTTP/SOCKS proxy; no host-system route/DNS takeover]
```

Both modes load and use the native bypass, ordinary routes, peer-prefix routes, and DNS rules. These inputs feed native route lookup and DNS policy; the local proxy path also uses the native classification. TUN mode additionally projects the policy into host routing and DNS handling: IP classification chooses the path, route entries keep the tunnel/server/resolvers reachable, and DNS rules choose resolver semantics. In proxy-only mode, the runtime deliberately does not take over system routes or system DNS. Desktop uses `TapStub`; Android keeps only the VPN interface subnet route; iOS keeps only the tunnel subnet route. The absence of those platform-level routes or DNS settings does not disable the loaded native policy. See [Platform Integration](PLATFORMS.md) for the platform boundary.

---

## Client-Side Ownership

`VEthernetNetworkSwitcher` composes route and DNS services but does not own their domain state. `route::RouteState` owns route data, and `dns::DnsController` owns query/session lifetime.

Before an operation, the Switcher copies TAP facts, interface snapshots, configuration flags, bypass entries, DNS
reachability, and fake-IP routing into a `RoutePlanInput`. Route managers and platform adapters receive that value
as `const` input and do not retain a Switcher pointer. The default-route protection worker captures only its plan
and an independently owned cancellation state.

### Route Information Base

| Field | Description |
|-------|-------------|
| `RouteState::rib` | Route information base — all known routes |
| `RouteState::fib` | Forwarding information base — active lookup table |
| `ribs_` | Loaded IP-list sources (files, URLs) |
| `vbgp_` | Remote route sources (vBGP) |

### DNS State

| Field / object | Description |
|----------------|-------------|
| `DnsController` | Query context, session generation, and close ordering |
| `DnsInterceptor` | Controller-owned DNS policy, resolver, rules, and fake-ip pool |
| `RouteState::dns_servers` | Native snapshots for DNS reachability; host/tunnel route projection is mode- and platform-dependent |

Packet dispatch calls `DnsController::HandleQuery()` with an immutable session snapshot. The controller delegates policy to `DnsInterceptor`; tunnel fallback uses `IDnsTunnelTransport` rather than a concrete exchanger. See [DNS_MODULE_DESIGN.md](../architecture/DNS_MODULE_DESIGN.md).

`DnsController` is the only production entry point for rule loading, negotiated session information, fake-IP
rewrite, fake-IP route projection, and resolver reachability. The Switcher no longer stores a second interceptor.

### Transaction and teardown

`RouteCoordinator` captures platform defaults, removes conflicting defaults, applies `RouteSpec` values, and records successful operations. Partial failure deletes applied routes in reverse order and restores the platform-private snapshot. `Stop()` is idempotent.

Teardown closes `DnsController` first, disposes the exchanger second, and rolls back routes last. This prevents late DNS callbacks from using a dead transport while preserving DNS route snapshots until removal.

---

## Route Construction

The client builds routes from multiple sources:

```mermaid
flowchart TD
    A[Virtual adapter subnet] --> F[RIB / FIB]
    B[Bypass IP-list files] --> F
    C[Remote IP-list URLs] --> F
    D[Tunnel server reachability] --> F
    E[DNS server reachability] --> F
    G[vBGP remote routes] --> F
    F --> H[FIB: active forwarding decisions]
```

### Key Methods

```cpp
/**
 * @brief Add all routes from all configured sources.
 * @param y  Yield context for async IP-list loading.
 * @return   true if all routes were applied successfully.
 */
bool AddAllRoute(YieldContext& y) noexcept;

/**
 * @brief Load and add routes from an IP-list source.
 * @param path_or_url  File path or HTTP/HTTPS URL of IP-list.
 * @return             Number of routes added.
 */
int AddLoadIPList(const ppp::string& path_or_url) noexcept;

/**
 * @brief Load IP-list from multiple file paths.
 * @param paths  Vector of file paths.
 * @return       Total routes loaded.
 */
int LoadAllIPListWithFilePaths(const ppp::vector<ppp::string>& paths) noexcept;

/**
 * @brief Add a reachability route for a remote endpoint.
 * @param endpoint  The remote endpoint (server or DNS server).
 * @return          true if route was added.
 */
bool AddRemoteEndPointToIPList(const IPEndPoint& endpoint) noexcept;

/**
 * @brief Add a route entry to the OS routing table.
 * @param network    Network address.
 * @param mask       Subnet mask.
 * @param gateway    Gateway address.
 * @return           true on success.
 */
bool AddRoute(UInt32 network, UInt32 mask, UInt32 gateway) noexcept;

/**
 * @brief Protect the default route from being overwritten by the tunnel.
 * @return true if default route was successfully protected.
 */
bool ProtectDefaultRoute() noexcept;
```

Source: `ppp/app/client/VEthernetNetworkSwitcher.h`

---

## DNS Rules

Client DNS rules decide which resolver to use for a domain or domain pattern. The full intercepted pipeline is documented in [DNS_MODULE_DESIGN.md](../architecture/DNS_MODULE_DESIGN.md).

### Rule Matching

```mermaid
flowchart TD
    A[DNS query enters native DNS policy] --> B[vdns cache]
    B -->|miss| C[DnsRedirectPlan::Decide]
    C --> D{rule / gateway / unmatched}
    D -->|provider| E[DnsResolver DoH/DoT/TCP/UDP]
    D -->|legacy IP| F[DnsUdpRelay]
    D -->|unmatched + intercept| E
    D -->|fake-ip A query| G[FakeIpPool instant fake A]
    G --> H[background real resolve]
    E --> I[DnsResponseHandler returns response]
    F --> I
    I -->|fail| J[Configured fallback transport]
```

### DNS Rule Format

The canonical way to specify DNS rule sources is via `client.routing.dns.rules`:

```json
"client": {
  "routing": {
    "dns": {
      "rules": ["rules://path/to/dns-rules.txt"]
    }
  }
}
```

The legacy direct alias `dns-rules` under `client.routing` is also accepted for compatibility when the canonical `ip`/`dns` sub-objects are absent:

```json
"routing": {
  "dns-rules": ["rules://path/to/dns-rules.txt"]
}
```

The rules file format uses domain suffix / wildcard entries, each mapped to a resolver address.

Source: `ppp/app/client/dns/Rule.h`

---

## DNS Server Route Assignment

DNS servers are reachability-sensitive endpoints in the native DNS policy. Resolver selection remains active in both modes; host-platform reachability is a separate projection.

In TUN mode, platform route coordination may add a direct route to a configured DNS server via the physical NIC rather than through the tunnel. This keeps that resolver reachable when the default route is redirected. In proxy-only mode, DNS rules remain active for native handling, but the runtime does not install host-system DNS takeover or host/tunnel DNS reachability routes. Mobile system builders may retain only their minimum interface/tunnel subnet route, and add DNS exception routes only when such inputs are present.

```cpp
/**
 * @brief Add routes to make DNS servers reachable directly.
 * @return true if all DNS server routes were added.
 */
bool AddRouteWithDnsServers() noexcept;

/**
 * @brief Remove DNS server reachability routes.
 * @return true if routes were removed.
 */
bool DeleteRouteWithDnsServers() noexcept;
```

These methods describe the platform reachability projection; they do not imply an unconditional host-OS route operation in proxy-only mode.

---

## Server-Side DNS Path

On the server side, DNS handling flows through:

```mermaid
sequenceDiagram
    participant Client as Client
    participant Exchanger as VirtualEthernetExchanger
    participant Cache as VirtualEthernetNamespaceCache
    participant Upstream as Upstream DNS

    Client->>Exchanger: UDP packet to port 53
    Exchanger->>Exchanger: RedirectDnsQuery()
    Exchanger->>Cache: NamespaceQuery(hostname)
    alt cache hit
        Cache-->>Exchanger: cached IP address
        Exchanger-->>Client: DNS response (synthesized)
    else cache miss
        Cache->>Upstream: Forward DNS query
        Upstream-->>Cache: DNS response
        Cache->>Cache: Store result with TTL
        Cache-->>Exchanger: IP address
        Exchanger-->>Client: DNS response
    end
```

### Server DNS API

```cpp
/**
 * @brief Redirect a DNS query through the namespace cache.
 * @param y          Yield context.
 * @param src        Source endpoint (client).
 * @param dns_data   Raw DNS query packet.
 * @param length     Length of DNS packet.
 * @return           true if query was handled.
 */
bool RedirectDnsQuery(YieldContext& y,
                      const IPEndPoint& src,
                      const Byte* dns_data,
                      int length) noexcept;
```

Source: `ppp/app/server/VirtualEthernetExchanger.h`

### Namespace Cache

`VirtualEthernetNamespaceCache` maintains a TTL-based DNS cache:

```cpp
/**
 * @brief Query the namespace cache for a hostname.
 * @param y         Yield context.
 * @param hostname  The hostname to resolve.
 * @return          Resolved IP address, or IPEndPoint::None on failure.
 */
IPEndPoint Query(YieldContext& y, const ppp::string& hostname) noexcept;

/**
 * @brief Insert a resolved entry into the cache.
 * @param hostname  The resolved hostname.
 * @param address   The IP address result.
 * @param ttl       Time-to-live in seconds.
 */
void Insert(const ppp::string& hostname, const IPEndPoint& address, int ttl) noexcept;
```

Source: `ppp/app/server/VirtualEthernetNamespaceCache.h`

---

## Path Model

```mermaid
flowchart TD
    A[Local packet or query] --> B[Classify with native policy]
    B --> C{bypass?}
    C -->|yes| D[Select local/native next hop]
    C -->|no| E{mode}
    E -->|tun| F[Send into tunnel]
    E -->|proxy-only| G[Send through local HTTP/SOCKS proxy]
    F --> H[Route / DNS steering at server]
    H --> I{DNS redirect rule?}
    I -->|yes| J[VirtualEthernetNamespaceCache]
    I -->|no| K[Forward to real destination]
    J --> L[Return cached or upstream result]
    K --> M[Destination responds]
    L --> N[Return path to client]
    M --> N
```

The local/native branch is a policy decision, not a promise that host-NIC routes are installed. In TUN mode, platform projection can send it through the physical NIC; in proxy-only mode, native lookup and the local proxy path consume the same classification without host-system route or DNS takeover. Non-bypass traffic uses the tunnel only in TUN mode and the local proxy in proxy-only mode.

---

## IP-List Sources

OPENPPP2 supports loading IP bypass lists from multiple sources:

| Source type | Example | Description |
|-------------|---------|-------------|
| Local file | `/etc/openppp2/bypass.txt` | Plain text file, one CIDR per line |
| HTTP URL | `http://example.com/bypass.txt` | Fetched on startup |
| HTTPS URL | `https://cdn.example.com/bypass.txt` | TLS-fetched on startup |
| VIRR refresh | Configured `virr.update-interval` | Periodic automatic refresh |

### VIRR Configuration

```json
"virr": {
    "update-interval": 86400,
    "url": "https://example.com/bypass-list.txt"
}
```

When the bypass list is refreshed, the native RIB/FIB is updated accordingly; any host-platform route projection is mode-dependent and is not implied in proxy-only mode.

---

## vBGP Remote Routes

The vBGP subsystem allows loading route information from a remote BGP-style source:

```json
"vbgp": {
    "update-interval": 3600,
    "url": "https://example.com/bgp-routes.txt"
}
```

Routes from vBGP are merged into the client RIB.

---

## Operational Meaning

Routing and DNS are not separate knobs. They form a unified traffic classification policy:

| Concern | How it connects |
|---------|----------------|
| Bypass list | Selects destinations for the local/native path instead of the tunnel or proxy path |
| DNS rules | Determines which resolver is used per domain in the native policy in both modes |
| Resolver reachability | Native reachability state supports resolver selection; TUN may project direct routes, while proxy-only does not imply host routes |
| Server DNS cache | Reduces repeated upstream DNS lookups |
| IPv6 transit | Can alter what "reachable" means for IPv6 destinations |
| Static echo | Can provide a separate path that bypasses DNS decisions |

---

## Configuration Reference

| Config key | Default | Description |
|------------|---------|-------------|
| `--mode=client` / `--mode=proxy` | `client` | Top-level runtime mode; `--mode=proxy` selects proxy-only host integration |
| `client.proxy-only` | `false` | Independent top-level runtime flag; suppresses host route/DNS takeover without disabling native policy |
| `client.routing.ip.bypass` | `[]` | Inline IP prefixes or `file://` sources for the native bypass policy; TUN may project them to the physical path, while proxy-only keeps the decision native |
| `client.routing.ip.routes` | `[]` | Ordinary route-file or vBGP sources loaded into native route policy; platform projection depends on runtime mode |
| `client.routing.ip.peer-routes` | `[]` | Native peer-prefix gateway routes with `network`, `prefix`, and `via` |
| `client.routing.dns.rules` | `[]` | Inline DNS rules or `file://` sources loaded into native DNS policy in both modes; TUN may project resolver reachability, while proxy-only does not take over host DNS |
| `client.routes`, `client.peer-routes` | — | Legacy route compatibility fields used only when `client.routing` is absent; `--bypass` and `--dns-rules` remain launch-local sources. An old nested mode key is ignored and not serialized |
| `geo-rules.enabled` | `false` | Generate extra bypass and DNS-rule files from local text GeoIP/GeoSite inputs |
| `geo-rules.geoip-dat` | `GeoIP.dat` | Local cache path for GeoIP dat; downloaded and parsed for the configured country |
| `geo-rules.geosite-dat` | `GeoSite.dat` | Local cache path for GeoSite dat; downloaded and parsed for the configured country |
| `geo-rules.geoip-download-url` | `""` | Optional HTTP/HTTPS URL used to download/update `geoip-dat` |
| `geo-rules.geosite-download-url` | `""` | Optional HTTP/HTTPS URL used to download/update `geosite-dat` |
| `geo-rules.geoip` | `[]` | Local text CIDR source file path or array of paths |
| `geo-rules.geosite` | `[]` | Local text domain source file path or array of paths |
| `geo-rules.append-bypass` | `[]` | Extra inline CIDRs or local CIDR files appended after generated GeoIP CIDRs |
| `geo-rules.append-dns-rules` | `[]` | Extra inline DNS rules/domains or `rules://` local files appended after generated GeoSite rules |
| `virr.update-interval` | `86400` | Bypass list refresh interval (seconds) |
| `virr.url` | `""` | Bypass list URL for periodic refresh |
| `vbgp.update-interval` | `3600` | vBGP route refresh interval (seconds) |
| `vbgp.url` | `""` | vBGP route source URL |
| `udp.dns.cache` | `true` | Enables DNS cache writes; `false` or `udp.dns.ttl=0` disables writes and server namespace cache creation |
| `udp.dns.ttl` | `60` | Maximum DNS cache TTL in seconds; positive response TTLs are honored and capped by this value |
| `dns.servers.domestic` | `doh.pub` | Default domestic provider or structured DNS server spec |
| `dns.servers.foreign` | `cloudflare` | Default foreign provider or structured DNS server spec |
| `dns.intercept-unmatched` | `true` | Intercept unmatched DNS queries and resolve through `foreign -> domestic -> cloudflare` |
| `dns.fake-ip.enabled` | `false` | Clash-style fake-ip (instant fake A, background real resolve) |
| `dns.fake-ip.range` | `198.18.0.1/16` | Fake-ip pool CIDR |

---

## Error Code Reference

Routing and DNS `ppp::diagnostics::ErrorCode` values (from `ppp/diagnostics/ErrorCodes.def`):

| ErrorCode | Description |
|-----------|-------------|
| `RouteAddFailed` | Failed to add a route to the OS routing table |
| `RouteDeleteFailed` | Failed to remove a route |
| `RouteReplaceFailed` | Failed to replace an existing route |
| `ConfigDnsRuleLoadFailed` | Failed to load DNS rules from configured source |
| `ConfigRouteLoadFailed` | Failed to load route list from configured source |
| `DnsResolveFailed` | DNS resolution failed |
| `DnsAddressInvalid` | DNS address is invalid |

---

## Usage Examples

### Configuring the canonical split-tunnel policy

```json
{
  "client": {
    "routing": {
      "ip": {
        "bypass": [
          "file:///etc/openppp2/china-cidr.txt",
          "10.0.0.0/8"
        ],
        "routes": [],
        "peer-routes": []
      },
      "dns": {
        "rules": [
          "file:///etc/openppp2/dns-rules.txt"
        ]
      }
    }
  }
}
```

Use `routing.ip.bypass` for prefixes that select the local/native path, `routing.ip.routes` for ordinary route sources, and `routing.ip.peer-routes` for peer-prefix gateway routes. These native inputs are shared by TUN and proxy-only modes; only their host-platform projection differs. The old client fields and CLI sources remain compatibility inputs when `client.routing` is absent.

DNS rules file format example:

```
# Provider rules (preferred)
example.cn /doh.pub/nic
google.com /cloudflare/tun

# Legacy IP rules remain supported
legacy-cn.example /1.2.4.8/nic
legacy-foreign.example /1.1.1.1/tun
```

For provider rules, the third segment selects resolver semantics: `/nic` means domestic and ECS-eligible; `/tun`, `/vpn`, `/cf`, and `/c` mean foreign and no ECS. For legacy IP rules, the same segment remains a native path hint: `/nic` selects local/native handling, while `/tun` selects tunnel handling when a TUN path exists. Proxy-only still loads the rule into native policy but does not install host-system tunnel routes.

### Generating GeoIP / GeoSite split rules

`geo-rules` is optional and disabled by default. When enabled, OPENPPP2 downloads/parses configured GeoIP/GeoSite dat files, reads local text inputs, writes generated bypass and DNS-rule files, and connects them to the existing route/DNS loading paths. Generated output is loaded before explicit canonical `client.routing.ip.bypass` and `client.routing.dns.rules` sources; `--bypass` and `--dns-rules` remain supported launch-local inputs. The generator runs in desktop startup and in the Android native startup path in both `tun` and `proxy-only` modes. The iOS bridge currently does not invoke `GeoRuleGenerator`, but it still loads canonical bypass and DNS policy. Proxy-only does not skip generator execution on desktop/Android or native policy loading; it skips only host-system route/DNS projection.

```json
{
  "geo-rules": {
    "enabled": true,
    "country": "cn",
    "geoip-dat": "/var/lib/openppp2/GeoIP.dat",
    "geosite-dat": "/var/lib/openppp2/GeoSite.dat",
    "geoip-download-url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    "geosite-download-url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    "geoip": [
      "/etc/openppp2/geoip-cn.txt"
    ],
    "geosite": [
      "/etc/openppp2/geosite-cn.txt"
    ],
    "dns-provider-domestic": "doh.pub",
    "dns-provider-foreign": "cloudflare",
    "output-bypass": "/var/lib/openppp2/generated/bypass-cn.txt",
    "output-dns-rules": "/var/lib/openppp2/generated/dns-rules-cn.txt",
    "append-bypass": [
      "10.0.0.0/8",
      "/etc/openppp2/custom-bypass.txt"
    ],
    "append-dns-rules": [
      "example.cn /doh.pub/nic",
      "internal.example.cn",
      "rules:///etc/openppp2/custom-dns-rules.txt"
    ]
  },
  "dns": {
    "servers": {
      "domestic": "doh.pub",
      "foreign": "cloudflare"
    }
  }
}
```

Supported input formats are intentionally simple:

```text
# geoip-cn.txt: one CIDR per line
1.0.1.0/24
1.0.2.0/23
2408:8000::/20
```

```text
# geosite-cn.txt: one domain or matcher per line
baidu.com
.qq.com
domain:taobao.com
suffix:jd.com
full:example.cn
regexp:^.*\.example\.cn$
```

Important details:

- `geoip-download-url` and `geosite-download-url` download dat files into `geoip-dat` and `geosite-dat` at startup.
- Downloaded binary `geoip.dat` / `geosite.dat` files are parsed automatically for `geo-rules.country`; local text `geoip` / `geosite` inputs and append lists are merged afterwards.
- When `geo-rules.enabled=true`, legacy `--bypass` sources are folded into generated output where the platform passes them to the generator; canonical `client.routing.ip.bypass` sources are applied explicitly after generation. When `geo-rules.enabled=false`, direct canonical bypass registration remains unchanged.
- The parser also accepts snake_case compatibility keys (`geoip_dat`, `geosite_dat`, `geoip_download_url`, `geosite_download_url`), but kebab-case is the documented form.
- `geoip` and `geosite` still support local text files only; use `geoip-download-url` / `geosite-download-url` for dat downloads.
- Generated DNS rules use `/<dns-provider-domestic>/nic`; if unset, the provider falls back to `dns.servers.domestic`, then `doh.pub`.
- `dns-provider-foreign` is parsed and reserved for future non-CN or `geolocation-!cn` generation, but is not consumed by the current generator.
- `append-bypass` is merged after GeoIP CIDRs and can contain inline CIDRs or local CIDR files.
- `append-dns-rules` is merged after GeoSite rules and can contain full rules, plain domains normalized with the domestic provider, or `rules://` local files.
- Client `vdns` and server namespace cache store only positive A/AAAA/CNAME-chain responses with positive TTL; cached TTL is `min(response TTL, udp.dns.ttl)`, and `udp.dns.cache=false` or `udp.dns.ttl=0` disables writes.
- Desktop and Android native clients run the generator in both `tun` and `proxy-only` modes; the iOS bridge currently does not invoke it but still loads canonical bypass and DNS policy. Mobile system route/DNS builders remain separate from the desktop route loader and project only platform-level state.

### Checking if a bypass route is active (code)

```cpp
// ppp/app/client/VEthernetNetworkSwitcher.cpp
bool VEthernetNetworkSwitcher::IsRoutedThroughTunnel(UInt32 dest_ip) noexcept {
    auto it = fib_.find(dest_ip & mask_);
    if (it != fib_.end()) {
        return false;  // bypass hit: use configured local/native next hop
    }
    return true;  // no bypass: use the configured tunnel/proxy path
}
```

### VIRR: Periodic Bypass List Refresh

VIRR fetches and replaces the bypass IP list on a configurable interval:

```json
{
  "virr": {
    "update-interval": 3600,
    "url": "https://cdn.example.com/bypass-latest.txt"
  }
}
```

### vBGP: Remote Route Sources

vBGP pulls remote route prefixes and merges them into the native RIB/FIB:

```json
{
  "vbgp": {
    "update-interval": 7200,
    "url": "https://cdn.example.com/bgp-routes.txt"
  }
}
```

---

## Routing Decision Flow

```mermaid
sequenceDiagram
    participant APP as Application
    participant DNS as DNS Interceptor
    participant RIB as Native RIB/FIB
    participant TUN as Tunnel
    participant PRX as Local Proxy

    APP->>DNS: DNS query (hostname)
    DNS->>RIB: Rule lookup
    RIB-->>DNS: kUdpRelay / kResolveProvider / kDeferToTunnel
    DNS-->>APP: Resolved IP

    APP->>RIB: Route lookup (IP)
    alt bypass hit
        RIB-->>APP: native/local path
        APP->>PRX: Send via local proxy (proxy-only)<br/>or native NIC (TUN)
    else no bypass
        RIB-->>APP: tunnel path
        APP->>TUN: Send via tunnel
    end
```

---

## DNS Route Assignment State Machine

```mermaid
stateDiagram-v2
    [*] --> RuleMatch: incoming DNS query
    RuleMatch --> kUdpRelay: rule has Server IP
    RuleMatch --> kResolveProvider: rule has ProviderName (resolver available)
    RuleMatch --> kDrop: rule has ProviderName (no resolver)
    RuleMatch --> kResolveUnmatched: no rule + intercept_unmatched + resolver
    RuleMatch --> kUdpRelay: no rule + no intercept (passthrough)
    kUdpRelay --> [*]: relay to target
    kResolveProvider --> [*]: resolve via provider
    kResolveUnmatched --> [*]: resolve via default resolver
    kDrop --> [*]: drop query
```

---

## Operational Notes

- Route entries are built dynamically from bypass list, route sources, and peer-route inputs — changes to these sources take effect on refresh, not just at startup.
- DNS servers in `routing.dns.rules` are treated as reachability-sensitive endpoints; the runtime adds direct routes for them to keep resolvers reachable.
- The bypass list and DNS rules refresh independently. If you change one, verify the other is still consistent.
- In proxy-only mode, DNS rules still classify traffic for the local proxy path even though system DNS is not taken over.
- IPv6 transit (`server.ipv6`) changes what "reachable" means for IPv6 destinations — ensure bypass lists account for IPv6 prefixes when using split-tunnel mode.

---

## Related Documents

- [`CONFIGURATION.md`](../reference/CONFIGURATION.md)
- [`CLIENT_ARCHITECTURE.md`](../architecture/CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](../architecture/SERVER_ARCHITECTURE.md)
- [`LINKLAYER_PROTOCOL.md`](../reference/LINKLAYER_PROTOCOL.md)
- [`DEPLOYMENT.md`](../operations/DEPLOYMENT.md)
