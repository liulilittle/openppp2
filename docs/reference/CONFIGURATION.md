# Configuration Reference

> Status: Active
> Type: Reference
> Last verified: 2026-10-11 (against `Clear()` / `Load()` / `Loaded()` in `ppp/configurations/AppConfiguration.cpp`)
>
> **Purpose:** Type, effective value when omitted, applicable side, and validation rules for every `appsettings.json` field.
> **Audience:** Users and operators who need the exact behavior of a field.
> **Parent index:** [Reference](README.md) · **Chinese:** [配置文件参考](CONFIGURATION_CN.md)

If you are writing a configuration for the first time, start with [Writing the configuration file](../getting-started/CONFIGURE.md); this page is for field lookup. Command-line flags are in the [CLI reference](CLI_REFERENCE.md).

## 1. How a configuration is loaded

1. File lookup: the readable file named by `--config=<path>` (aliases `-c`, `--c`, `-config`); otherwise `./config.json`, then `./appsettings.json`. If a candidate fails to load, the next one is tried.
2. `Clear()` writes built-in initial values.
3. `Load()` reads the JSON. **Note:** many fields are read unconditionally — a missing key reads as `0` / `false` / empty string, overwrites the initial value, and is then repaired by the next step. The "If omitted" column below is therefore the **effective value after omission**, not the `Clear()` initial value.
4. `Loaded()` normalizes: trims whitespace, zeroes out-of-range ports, falls back on invalid values, and disables listeners whose prerequisites are missing. Invalid values are **silently repaired, not rejected**; only a `client.policy` conflict, invalid `transport-auth`, or a server IPv6 mode unsupported by the platform makes the file fail to load.
5. Command-line flags override some runtime behavior (`--mux-mode`, `--mode=proxy`, `--proxy-*-port`, and others).

The file must be strict JSON (no comments, no trailing commas).

## XTCP runtime tuning

When the client selects `--tcp-stack=xtcp` in a build with XTCP enabled, the
runtime uses a 1 MiB per-connection `snd_buf` quota on Linux, Windows x64, and
Android. It is a quota, not memory preallocated for every connection. macOS and
iOS do not currently support XTCP builds. This setting is not an
`appsettings.json` field; set the process environment before starting `ppp`:

| Environment variable | Default | Meaning |
|---|---|---|
| `OPENPPP2_XTCP_SNDBUF_BYTES` | 1 MiB | Explicit send-buffer quota in bytes (values below 1024 are ignored). This overrides the default and throughput profile. |
| `OPENPPP2_XTCP_DL_GSO_PERF_PROFILE` | unset | Exact value `1` selects a 2 MiB quota when `OPENPPP2_XTCP_SNDBUF_BYTES` is unset or invalid. |

The 1 MiB default follows the Linux tuning introduced by #109 and applies to
all platforms that currently support XTCP. The profile remains opt-in.

## 2. Which side uses what

| Block | Server | Client | Notes |
|---|:-:|:-:|---|
| `key` | ✔ | ✔ | Must be identical on both sides |
| `concurrent` `tcp` `udp` `mux` `vmem` `telemetry` | ✔ | ✔ | Local to each side |
| `websocket` | ✔ | — | Server listeners only; the client's WS path is part of the `client.server` URL |
| `ip` `cdn` `server` | ✔ | partly | `server.ipv4-pool` in a client config opts in to requesting an assigned address |
| `client` `dns` `routing` `geo-rules` `virr` `vbgp` | — | ✔ | |
| `p2p` | ✔ | ✔ | |
| `transport-auth` | ✔ | ✔ | Enabled by `server.transport-auth.enabled` / `client.transport-auth.enabled` |

## 3. Top-level fields

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `concurrent` | int | CPU count | Worker threads; `< 1` becomes the CPU count. The server also creates `concurrent-1` I/O threads; on clients it only sizes the scheduler pool. |
| `cdn` | int[2] | `[0, 0]` | Two extra server TCP listen ports (CDN / SNI forwarding entry). `0` disables; out-of-range values become 0. |

## 4. `key` — encryption and obfuscation (must match on both sides)

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `kf` | int | `0` | Header obfuscation parameter. **Omitted means 0, not 154543927**; it only has to match, but write it explicitly. |
| `kx` | int | `0` | Obfuscation parameter; negatives become 0. |
| `kl` | int | `0` | Obfuscation parameter, clamped to `0..16`. |
| `kh` | int | `0` | Obfuscation parameter, clamped to `0..16`. |
| `sb` | int | `0` | Shuffle block size, clamped to `0..5536`. |
| `protocol` | string | `aes-128-cfb` | Protocol-layer (handshake/control) cipher, an OpenSSL name. Unsupported names fall back to `aes-128-cfb`. |
| `protocol-key` | string | `"ppp"` | Protocol-layer key; empty falls back to `"ppp"`. |
| `transport` | string | `aes-256-cfb` | Transport-layer (data) cipher; unsupported names fall back to `aes-256-cfb`. |
| `transport-key` | string | `"ppp"` | Transport-layer key; empty falls back to `"ppp"`. |
| `plaintext` | bool | **`true`** | `true` means **no encryption**. Omitting it means plaintext; always write `false`. |
| `masked` | bool | `true` | Payload masking. |
| `delta-encode` | bool | `true` | Delta encoding. |
| `shuffle-data` | bool | `true` | Byte shuffling. |
| `simd-auto` | bool | `true` | Automatic SIMD implementation selection; local only, need not match. |

Startup prints `[security] WARN` (warnings only, startup continues) when:

- either key equals the default `"ppp"` or is shorter than 8 bytes;
- `plaintext` is `true`;
- a cipher is RC4 / DES / Blowfish / CAST5 / SEED / IDEA or has a key shorter than 128 bits.

## 5. `transport-auth` — pre-shared-key transport authentication (optional)

Adds connection authentication with a 32-byte pre-shared key on top of `key`. Off by default.

```json
"transport-auth": {
  "handshake-timeout-ms": 5000,
  "keys": [
    { "id": "k2026a", "state": "active", "secret-file": "/etc/ppp/k2026a.hex" }
  ]
},
"server": { "transport-auth": { "enabled": true } }
```

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `transport-auth.handshake-timeout-ms` | int | `5000` | Clamped to `1000..30000`. |
| `transport-auth.keys[]` | array | empty | At most 8. A non-array `keys` or a non-object element fails the load. |
| `keys[].id` | string | — | 1–63 characters, starting with a lowercase letter or digit, containing only `a-z 0-9 . _ -`; unique. |
| `keys[].state` | string | — | `active`, `verify-only`, or `revoked`. When enabled, **exactly one** `active` key is required; at most 2 `verify-only` keys (for rotation). |
| `keys[].secret-file` | path | — | Required for `active` / `verify-only`. Must contain exactly 64 lowercase hex characters (no newline), be a regular file owned by the current user, with no group/other permissions (`chmod 600`). **Secret files cannot be loaded on Windows.** |
| `server.transport-auth.enabled` / `client.transport-auth.enabled` | bool | `false` | Enable on the server / client. |

## 6. `tcp`

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `listen.port` | int | `0` | Server TCP tunnel port, used by client `ppp://` / `tcp://` addresses. `0` or out of range = no listener. |
| `backlog` | int | `511` | Listen backlog; `< 1` becomes 511. |
| `connect.timeout` | int (s) | `5` | Outbound TCP connect timeout; `< 1` becomes 5. |
| `connect.nexcept` | int | `4` | Connect retry counter; `< 0` becomes 4. |
| `inactive.timeout` | int (s) | `300` | TCP relay idle timeout; `< 1` becomes 300. |
| `turbo` | bool | `false` | Sets `TCP_NODELAY`. |
| `fast-open` | bool | `false` | TCP Fast Open where supported. |
| `cwnd` / `rwnd` | int | `0` | Socket send / receive buffer size; `0` = system default. |

## 7. `udp`

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `listen.port` | int | `0` | Server UDP port (used by the static UDP tunnel, `--tun-static`). |
| `inactive.timeout` | int (s) | `72` | UDP relay idle timeout; `< 1` becomes 72. |
| `dns.timeout` | int (s) | `4` | Timeout for DNS queries relayed through the tunnel; `< 1` becomes 4. |
| `dns.ttl` | int (s) | `60` | DNS cache TTL cap; effective TTL is `min(response TTL, ttl)`; `0` disables cache writes. |
| `dns.cache` | bool | `true` | DNS cache switch; still requires `ttl > 0`. |
| `dns.turbo` | bool | `false` | Enables the built-in vdns fast resolver. |
| `dns.redirect` | string | empty | Server redirects client DNS queries to this `IP:port` or `domain:port`; cleared if malformed. |
| `static.keep-alived` | int[2] (s) | `[0, 0]` | Static UDP keepalive range; negatives become 0. |
| `static.dns` / `static.quic` / `static.icmp` | bool | `true` | Whether static mode carries DNS / QUIC / ICMP. |
| `static.aggligator` | int | `0` | Static UDP aggregated link count; negatives become 0. |
| `static.servers` | string[] | empty | Static UDP server `IP:port` list (legacy key `static.server` is accepted). |
| `cwnd` / `rwnd` | int | `0` | Socket buffer sizes. |

## 8. `mux` — multiplexing

Whether MUX is used, and how many connections, is set by the client flag `--tun-mux=<connections>` (default 0 = off). There is no connection-count JSON field.

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `mode` | string | `compat` | Scheduler: `compat` (default, original behavior), `flow` (latency-oriented), `balance` (per-flow ordered load balancing), `stripe` (experimental). Aliases: `legacy`/`default`→compat, `flow-v1`/`primary`/`primary-link`→flow, `balanced`/`lb`/`load-balance`→balance, `striped`/`striping`→stripe. Unknown values fall back to `compat` with a warning. Overridden by `--mux-mode`. |
| `turbo` | bool | `false` | Only meaningful with `flow`: best-link first packet plus prewarmed links. Overridden by `--mux-mode-turbo`. |
| `connect.timeout` | int (s) | `20` | Sub-connection setup timeout. |
| `inactive.timeout` | int (s) | `60` | Sub-connection idle timeout. |
| `keep-alived` | int[2] (s) | `[0, 0]` | Keepalive range; negatives become 0. |
| `congestions` | int (bytes) | `134217728` | Congestion window budget; `0` = unlimited; negatives or positives below 1 MiB fall back to the default. |
| `flow.reorder.bytes` | int | `8388608` | Per-connection reorder buffer soft cap: above it the delivering carrier is paused (backpressure); only twice the cap resets the connection. |
| `flow.reorder.timeout` | int (ms) | `400` | Gap wait timeout (per connection under flow_v2, session-wide under compat), counted from the last in-order progress. |
| `flow.session_reorder.bytes` | int | `33554432` | Session-wide reorder buffer soft cap: above it the delivering carrier is paused; only twice the cap resets a connection (flow_v2) or rebuilds the session (compat). |
| `flow.max_open` | int | `4096` | Maximum logical flows. |
| `flow.unknown_cid.max` | int | `64` | Unknown flow-ID budget. |
| `tx.queue.max` | int (frames) | `4096` | Transmit-queue high water; reads are throttled at this depth. |
| `tx.queue.stall` | int (ms) | `8000` | Session is rebuilt if the queue stays backlogged this long. |
| `tx.ctrl.budget_frames` | int | `32` | Control frames drained before data per turn. |
| `reliability.enabled` | bool | `true` | Negotiate reliable delivery (retransmission). |
| `reliability.rtx.bytes` | int | `33554432` | Session retransmit send window (unacked bytes); frames wait in the queue when full, only twice this fails the session. Throughput is bounded by window / RTT. |
| `reliability.rtx.flow_bytes` | int | `8388608` | Per-flow send window under flow_v2 (clamped to `reliability.rtx.bytes`); one connection is bounded by this / RTT. |
| `reliability.rtx.max_attempts` | int | `8` | Max retransmissions per frame. |
| `reliability.rtx.pto` | bool | `false` | Probe-timeout retransmission. Off by default: carriers are reliable streams, so a PTO mostly re-sends frames still queued behind a slow carrier. Unacked frames of a carrier that exits are always re-sent on the remaining carriers. |
| `reliability.rtx.fast` | bool | `false` | Dup-ACK fast retransmit. Off by default: reordering across carriers is not loss. |
| `reliability.ack.delay` | int (ms) | `10` | Max delayed-ACK wait. |
| `reliability.gap.timeout` | int (ms) | `3000` | Gap timeout when reliability is negotiated. |
| `fec.enabled` | bool | `false` | XOR forward error correction. |
| `fec.group` | int | `8` | Data frames per parity group. |
| `fec.flush` | int (ms) | `20` | Max age of a partial group. |
| `debug.key` | string | empty | Debug shared secret; when identical and non-empty on both peers, `--mux-mode-set` can switch the peer's scheduler. Overridden by `--debug-key`. |

Except for `keep-alived` and `congestions`, numeric fields above fall back to the listed value when `<= 0`.

## 9. `websocket` — server WS / WSS listeners

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `host` | string | empty | **Must be a domain name** (not an IP). Empty or non-domain disables both WS and WSS. |
| `path` | string | empty | Must start with `/`, e.g. `/tun`. Otherwise both WS and WSS are disabled. |
| `listen.ws` | int | `0` | Plain WebSocket port, used by client `ws://`. |
| `listen.wss` | int | `0` | TLS WebSocket port, used by client `wss://`. Disabled when certificate validation fails. |
| `ssl.certificate-file` | path | empty | Certificate file. |
| `ssl.certificate-key-file` | path | empty | Private key file. |
| `ssl.certificate-chain-file` | path | empty | Certificate chain file. |
| `ssl.certificate-key-password` | string | empty | Private key password. |
| `ssl.ciphersuites` | string | built-in TLS 1.3 suites | Empty uses the built-in value. |
| `ssl.verify-peer` | bool | `true` | Legacy location `websocket.verify-peer` is accepted. |
| `http.error` | string | empty | Error text returned to non-WebSocket requests. |
| `http.request` / `http.response` | object | empty | Custom HTTP headers (key/value). |

When `listen.ws` is 0, `host`, `path`, and `http.*` are cleared; when `listen.wss` is 0, the certificate fields are cleared.

## 10. `ip` (server)

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `interface` | string | empty | Local address listeners bind to; empty = all addresses. Cleared if not a valid IP. |
| `public` | string | empty | Server public IP, used for CDN forwarding loop detection and status display. |

## 11. `server`

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `node` | int | `0` | Node number; negatives become 0. |
| `log` | path | empty | Session log file, converted to an absolute path; empty = disabled. |
| `subnet` | bool | `true` | Allow clients to reach each other over the virtual subnet. |
| `mapping` | bool | `true` | Allow client port mappings (`client.mappings`). |
| `backend` | string | empty | Management backend WebSocket URL; see [Management backend](../guides/MANAGEMENT_BACKEND.md). |
| `backend-key` | string | empty | Management backend key. |
| `ipv4-pool.network` / `ipv4-pool.mask` | string | not configured | The presence of an `ipv4-pool` object enables it: the server assigns each session a virtual IPv4 address from this network (Windows / Linux / macOS clients apply it to the virtual adapter). An invalid network or mask is logged and nothing is assigned. |
| `ipv6.mode` | string | off | `nat66` or `gua`; anything else = off. The file **fails to load** if the platform has no server IPv6 data plane. |
| `ipv6.cidr` | string | empty | Prefix, e.g. `fd42:4242:4242::/64`. `nat66` uses a built-in ULA /64 when empty; `gua` requires a global unicast prefix. An invalid prefix disables IPv6. |
| `ipv6.gateway` | string | first address in the prefix | Ignored when outside the prefix. |
| `ipv6.dns1` / `ipv6.dns2` | string | empty | IPv6 DNS pushed to clients. |
| `ipv6.lease-time` | int (s) | `300` | Lease time; negatives become 0. |
| `ipv6.static-addresses` | object | empty | `{ "<client GUID>": "<IPv6 address>" }`; out-of-prefix or duplicate entries are dropped. |
| `peer-routing.enabled` | bool | `false` | Client prefix routing; see [Peer prefix routing](../guides/PEER_PREFIX_ROUTING.md). |
| `peer-routing.distribute` | bool | `true` | Distribute the route table to clients. |
| `peer-routing.allowed-routes[]` | array | empty | Announcement allowlist, elements `{network, prefix, guid}`: only announcements with a matching GUID and identical prefix are accepted. **Empty rejects every announcement.** |
| `session_resume.enabled` | bool | `false` | Allow a dropped session to resume within the grace period. |
| `session_resume.grace_ms` | int (ms) | `60000` | Grace period, clamped to `1000..3600000`. |
| `transport-auth.enabled` | bool | `false` | See section 5. |

See [IPv6 client assignment](../guides/IPV6.md) for IPv6.

## 12. `client`

| Field | Type | If omitted | Meaning |
|---|---|---|---|
| `guid` | string | all-F sentinel GUID | Client identity, e.g. `{F4569208-BB45-4DEB-B115-0FEA1D91B85B}`. **Must differ per client**; if omitted, every client shares the same sentinel. |
| `server` | string | empty | Server address; format in section 17. |
| `server-proxy` | string | empty | Reach the server through a proxy; only `http://[user:pass@]host:port/` or `socks://[user:pass@]host:port/`. |
| `bandwidth` | int (Kbps) | `0` | Rate limit; `0` = unlimited; negatives become 0. |
| `proxy-only` | bool | `false` | Same as `--mode=proxy`: local HTTP / SOCKS proxies only, no host route or DNS takeover. |
| `http-proxy.bind` / `http-proxy.port` | string / int | empty / `0` | Local HTTP proxy; rules below. |
| `socks-proxy.bind` / `socks-proxy.port` | string / int | empty / `0` | Local SOCKS5 proxy (CONNECT and UDP ASSOCIATE). |
| `socks-proxy.username` / `socks-proxy.password` | string | empty | SOCKS5 authentication. |
| `reconnections.timeout` | int (s) | `5` | Base reconnect interval; `< 1` becomes 5. |
| `reconnections.max_delay` | int (s) | `15` | Max backoff, never below `timeout`. |
| `reconnections.jitter_percent` | int | `20` | Backoff jitter percent, clamped to `0..100`. |
| `session_resume.enabled` | bool | `false` | Request session resumption (the server must enable it too). |
| `transport-auth.enabled` | bool | `false` | See section 5. |
| `mappings[]` | array | empty | Publish local services on server ports; see below. |
| `routing` | object | not configured | Split-routing rules (canonical legacy-policy entry); see section 13. |
| `routes[]` / `peer-routes[]` | array | empty | Legacy locations used when `client.routing` is absent. |
| `peer-route-announce[]` | array | empty | Prefixes this client announces, `{network, prefix, via, guid}`. |
| `peer-gateway-forward` | bool | `false` | Forward traffic as a gateway for peer prefixes. |
| `policy` | object | not configured | Policy v2; see section 14. |
| `paper-airplane.tcp` | bool | `true` | Windows only: Paper Airplane TCP acceleration (LSP). |

**Local proxy rules:**

- `--mode=proxy` or `proxy-only: true`: HTTP and SOCKS listen addresses are **forced to `127.0.0.1`** (configured `bind` is ignored); ports default to `8080` / `1080` when unset and can be overridden with `--proxy-http-port` / `--proxy-socks-port`. Binding is loopback-only and fails closed instead of falling back to all addresses.
- Normal TUN client: a proxy starts only if its port is configured; an empty `bind` listens on **all addresses** (reachable from the LAN). Write `127.0.0.1` for local-only use.

**`mappings[]` elements:**

| Field | Meaning |
|---|---|
| `protocol` | `tcp` (default) or `udp` |
| `local-ip` / `local-port` | The service on the client side being published |
| `remote-ip` / `remote-port` | The address opened on the server; `remote-ip` `::` means all addresses |

Ports must be 1–65535; addresses must be valid, non-multicast IPs. Invalid entries are dropped and entries with the same `protocol + remote` are de-duplicated. The server needs `server.mapping: true`.

## 13. `client.routing` — split-routing rules (legacy policy)

```json
"client": {
  "routing": {
    "ip":  { "bypass": ["./ip.txt"], "routes": [], "peer-routes": [] },
    "dns": { "rules": ["./dns-rules.txt"] }
  }
}
```

| Field | Meaning |
|---|---|
| `ip.bypass` | Sources of IPs that go direct (bypass the tunnel); string or string array. |
| `dns.rules` | DNS rule sources; string or string array. |
| `ip.routes[]` | File-based routes: `{ "path": "./cmcc.txt", "ngw": "192.168.1.1", "vbgp": "https://...", "nic": "eth1" }`. `path` and an IPv4 `ngw` are required; `vbgp` is an optional remote update URL; `nic` is Linux only. |
| `ip.peer-routes[]` | Peer prefix routes `{network, prefix, via, guid}`. |

Accepted aliases: `routing.bypass`, `routing.routes`, `routing.peer-routes`, `routing.dns-rules` (nested locations win).

**How a source string is interpreted:** an optional `file://` prefix is stripped; if the file exists it is read as a file, **otherwise the whole string is treated as inline rule text**. A wrong path is not an error — it silently becomes a useless inline rule.

**Interaction with flags:** when `client.routing` is present, the `--bypass` and `--dns-rules` flags are **ignored**. Without it, the legacy sources apply: `--bypass` (default `./ip.txt`), `--dns-rules` (default `./dns-rules.txt`), plus `client.routes` / `client.peer-routes`.

**DNS rule line format** (`#` starts a comment; `,`, `;`, and tabs act as line breaks):

```text
example.com/1.1.1.1            # suffix match, use this DNS server
full:www.example.com/8.8.8.8   # exact match
regexp:.*\.cn$/doh.pub         # regex match; built-in provider names allowed
example.org/223.5.5.5/tun      # third segment starting with t/v/f/c = query through the tunnel; omitted = via the local NIC
cloudflare                     # a lone IP or provider name = default upstream for all domains
```

Built-in DNS provider names: `doh.pub`, `alidns`, `baidu`, `360`, `114`, `tuna`, `cloudflare`, `google`, `quad9`, `adguard`, `nextdns`, `mullvad`.

See [Routing and DNS](../guides/ROUTING_AND_DNS.md) for full routing / DNS behavior.

## 14. `client.policy` — policy v2

```json
"client": { "policy": { "version": 2, "rules": { "path": "./policy.rules" }, "dns": { "resolvers": { } } } }
```

- `version` must be the integer `2`.
- With `client.policy` present, **none** of the following may exist or the file fails to load: `client.routing`, `client.bypass`, `client.dns-rules`, and top-level `routing`, `geo-rules`, `dns`, `bypass`, `dns-rules`, `udp.dns`.
- Fields, rule syntax, and the `ppp policy` subcommand are in the [Policy CLI guide](../guides/POLICY_CLI.md).

## 15. Legacy client DNS and rule fields (`dns` / `routing` / `geo-rules`)

These top-level blocks apply only when `client.policy` is **absent**.

| Field | If omitted | Meaning |
|---|---|---|
| `dns.servers.domestic` | `doh.pub` | Domestic upstream: a provider name, `IP[:port]`, a structured object `{protocol, url, hostname, address, bootstrap}` (`protocol` is `udp`/`tcp`/`doh`/`dot`; `doq` maps to `dot`), or an array of these. |
| `dns.servers.foreign` | `cloudflare` | Foreign upstream, same format. The DNS addresses pushed to the OS in TUN mode are derived from these two (foreign first); `--dns` overrides. |
| `dns.intercept-unmatched` | `true` | Unmatched queries resolve via `foreign → domestic → cloudflare`. |
| `dns.ecs.enabled` / `dns.ecs.override-ip` | `false` / empty | EDNS Client Subnet; an invalid `override-ip` is cleared. |
| `dns.tls.verify-peer` | `true` | DoH / DoT certificate verification. |
| `dns.stun.candidates` | empty | `host:port` list. |
| `dns.fake-ip.enabled` / `dns.fake-ip.range` | `false` / `198.18.0.1/16` | Fake-IP. |
| `routing.rules` | empty | Human-readable rules file path. |
| `routing.tcp-domain-sniff` | `false` | TCP domain sniffing. |
| `geo-rules.*` | `enabled: false` | Generate bypass lists and DNS rules from GeoIP / GeoSite: `country` (default `cn`), `geoip-dat`, `geosite-dat`, `geoip-download-url`, `geosite-download-url`, `geoip`, `geosite`, `dns-provider-domestic`, `dns-provider-foreign`, `output-bypass`, `output-dns-rules`, `append-bypass`, `append-dns-rules`. |

## 16. Other blocks

| Field | If omitted | Meaning |
|---|---|---|
| `p2p.enabled` | `true` | Client-to-client direct channel; `false` forces `relay`. |
| `p2p.mode` | Linux / Android: `direct-preferred`; Windows / macOS: `relay` | Only `direct-preferred` is recognized; anything else is `relay` (via the server). |
| `p2p.punch-timeout` / `p2p.keep-alived` | `5` / `15` (s) | Minimum 1. |
| `p2p.stun.servers` / `p2p.stun.request-profile` | empty / `standard` | Profile is `standard` or `tailnode`. |
| `p2p.max-probes` | `2` | Clamped to `1..10`. |
| `p2p.probe-timeout-ms` | `2000` | Clamped to `500..10000`. |
| `p2p.heartbeat-interval-ms` / `p2p.heartbeat-miss-max` | `1000` / `2` | Clamped to `500..5000` and `1..10`. |
| `p2p.suspect-timeout-ms` / `p2p.migration-grace-ms` | `2000` / `5000` | Clamped to `500..10000` and `1000..30000`. |
| `p2p.buffer-pool-count` | `64` | Clamped to `8..256`. |
| `vmem.path` / `vmem.size` | empty / `0` | File-backed buffer pool. `size` is in **MB**, at least 32 MB in effect; disabled if either is empty / 0 (Windows only checks `size`). |
| `virr.update-interval` / `virr.retry-interval` | `86400` / `300` (s) | IP-list auto-update interval used with `--virr`; minimum 1. |
| `vbgp.update-interval` | `3600` (s) | Refresh interval for `ip.routes[].vbgp`; minimum 1. |
| `telemetry.enabled` / `level` / `count` / `span` | `false` / `0` / `false` / `false` | Telemetry switches and level. |
| `telemetry.endpoint` / `log-file` | empty | OTLP endpoint, log file. |
| `telemetry.console-log` / `console-metric` / `console-span` | `true` | Console output. |

## 17. Server address (`client.server`) format

The URL is lowercased before parsing.

| Form | Carrier | Default port | Server field |
|---|---|---|---|
| `ppp://host:port/` or `tcp://host:port/` | Native TCP | port required | `tcp.listen.port` |
| `ws://host[:port]/path` | WebSocket | 80 | `websocket.listen.ws` + `websocket.path` |
| `wss://host[:port]/path` | TLS WebSocket | 443 | `websocket.listen.wss` + `websocket.path` |

- `host` may be a domain or an IP; write IPv6 literals as `[2001:db8::1]`.
- `domain[IP]:port` connects to the bracketed IP while using the domain as the host name (useful with CDNs or custom resolution), e.g. `wss://vpn.example.com[203.0.113.10]:443/tun`.
- The WS / WSS path must equal the server's `websocket.path`.

## 18. Full samples

The repository-root [`appsettings.json`](../../appsettings.json) shows sample values for most fields (its addresses and keys are examples only); [`appsettings-server-minimal.json`](../../appsettings-server-minimal.json) is a minimal server sample.

## Related documents

- [Writing the configuration file](../getting-started/CONFIGURE.md)
- [CLI reference](CLI_REFERENCE.md)
- [Routing and DNS](../guides/ROUTING_AND_DNS.md) · [Proxy mode](../guides/PROXY_MODE.md) · [Policy CLI](../guides/POLICY_CLI.md)
- [Error codes](ERROR_CODES.md)
