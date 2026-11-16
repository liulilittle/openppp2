# Routing and DNS (Split Tunneling)

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `AppConfiguration.cpp`, `ppp/app/client/policy/LegacyPolicyAdapter.cpp`, `ClientRoutingSources.h`, `ClientBypassRouteLoader.cpp`, `ppp/net/native/rib.cpp`, `ppp/app/client/dns/Rule.cpp`, `GeoRuleGenerator.cpp`, `ApplicationNetwork.cpp`, `ApplicationMainLoop.cpp`)
>
> **Purpose:** Use `client.routing` to decide which traffic goes direct and which uses the tunnel, and which DNS server resolves each domain.
> **Audience:** Client users who need split tunneling.
> **Parent index:** [Guides](README.md) · **Chinese:** [路由与 DNS（分流）](ROUTING_AND_DNS_CN.md)

This page covers the legacy (and default) split mechanism, `client.routing`. If you need direct / proxy / reject actions, keyword and regex matching, or auto-updating rule sets, use [policy v2](POLICY_CLI.md) instead. The two cannot be in the same configuration.

## 1. How traffic is classified

| Traffic | Decided by | Result |
|---|---|---|
| IP packets | Whether the destination matches the **bypass list** or a **route file** | Match: sent directly via the physical NIC (or the route file's gateway). No match: tunnel (TUN mode) or forwarded through the tunnel (proxy mode) |
| DNS queries | Whether the domain matches a **DNS rule** | Match: the rule's upstream, queried via the local NIC or the tunnel. No match: handled per `dns.intercept-unmatched` (section 5) |

TUN and proxy modes use the same rules; TUN mode additionally writes them into the OS route table and DNS settings, proxy mode does not.

## 2. Configuration

```json
"client": {
  "routing": {
    "ip": {
      "bypass": ["./ip.txt", "10.0.0.0/8"],
      "routes": [],
      "peer-routes": []
    },
    "dns": {
      "rules": ["./dns-rules.txt"]
    }
  }
}
```

| Field | Purpose |
|---|---|
| `ip.bypass` | Bypass list sources (section 3). |
| `ip.routes` | Routes with a per-file gateway (section 4), typically for multiple ISP egresses. |
| `ip.peer-routes` | Prefixes forwarded through another client; see [Peer prefix routing](PEER_PREFIX_ROUTING.md). |
| `dns.rules` | DNS rule sources (section 5). |

**Source strings:** each element of `bypass` and `rules` has an optional `file://` prefix stripped; if the file exists it is read, **otherwise the whole string is inline rules**. So `"10.0.0.0/8"` is a rule by itself, while a mistyped file path silently becomes a useless rule — confirm your rules took effect after startup. Bypass lists **do not accept URLs**; to download from the network use `--virr` or `ip.routes[].vbgp` (section 6).

**Precedence over flags:**

| Configuration | Sources used |
|---|---|
| Has `client.routing` | Only the sources inside `client.routing`; `--bypass` and `--dns-rules` are ignored. |
| No `client.routing` | `--bypass` (default `./ip.txt`) + `--dns-rules` (default `./dns-rules.txt`) + `client.routes` / `client.peer-routes`. |

`routing.bypass`, `routing.routes`, `routing.peer-routes`, and `routing.dns-rules` are compatibility aliases; the nested form wins when both exist.

## 3. Bypass list

One IPv4 address or CIDR per line; `#` starts a comment; several entries on one line may be separated by commas, semicolons, or whitespace. IPv4 only.

```text
# ip.txt
1.0.1.0/24
1.0.2.0/23
192.168.0.0/16, 172.16.0.0/12
```

Generate the China list:

```bash
./ppp --pull-iplist=ip.txt/CN
```

## 4. Route files (multiple egresses)

`ip.routes` sends the addresses in a list through a specific gateway instead of the default one:

```json
"routes": [
  { "path": "./cmcc.txt", "ngw": "192.168.1.1", "nic": "eth1", "vbgp": "https://example.com/cmcc.txt" }
]
```

| Field | Meaning |
|---|---|
| `path` | Required list file (format as in section 3). |
| `ngw` | Required IPv4 gateway. |
| `nic` | Linux only, egress interface. |
| `vbgp` | Optional remote list URL, downloaded into `path` every `vbgp.update-interval` (section 6). |

Entries with an invalid `path` or `ngw` are ignored.

## 5. DNS rules

### 5.1 Line format

```text
# suffix match: the domain and its subdomains
example.com/1.1.1.1
# exact match
full:www.example.com/8.8.8.8
# regex match (case-insensitive)
regexp:.*\.example\.net$/cloudflare
# third segment starting with t / v / f / c = query through the tunnel (e.g. tun, vpn); omitted or other = via the local NIC
example.org/223.5.5.5/tun
# a lone IP or provider name = default upstream for all domains
cloudflare
```

- `#` starts a comment; `,`, `;`, and tabs act as line breaks.
- The second segment is an IP address or a built-in provider name: `doh.pub`, `alidns`, `baidu`, `360`, `114`, `tuna`, `cloudflare`, `google`, `quad9`, `adguard`, `nextdns`, `mullvad`. Provider names are queried by the built-in resolver (DoH / DoT capable); IPs are relayed as plain UDP.
- For provider rules the third segment also means domestic / foreign: via the local NIC = domestic (ECS-eligible), via the tunnel = foreign.

A community-maintained China domain list: [liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt).

### 5.2 Unmatched queries and upstream settings

| Field | Default | Meaning |
|---|---|---|
| `dns.intercept-unmatched` | `true` | Unmatched queries resolve via `foreign → domestic → cloudflare`; `false` forwards them to the original destination. |
| `dns.servers.domestic` | `doh.pub` | Domestic upstream: provider name, `IP[:port]`, `{protocol, url, hostname, address, bootstrap}` object, or an array of these. |
| `dns.servers.foreign` | `cloudflare` | Foreign upstream, same format. |
| `dns.ecs.enabled` / `override-ip` | `false` / empty | EDNS Client Subnet. |
| `dns.tls.verify-peer` | `true` | DoH / DoT certificate verification. |
| `dns.fake-ip.enabled` / `range` | `false` / `198.18.0.1/16` | Fake-IP: answer a fake address at once, resolve the real one in the background. |
| `udp.dns.ttl` / `udp.dns.cache` | `60` / `true` | Client cache: TTL = `min(response TTL, ttl)`; `ttl=0` or `cache=false` disables it. |

The DNS addresses pushed to the OS in TUN mode are also derived from `dns.servers` (foreign first); `--dns` sets them directly. In TUN mode the program adds direct routes to DNS servers that rules query via the local NIC, so they remain reachable after the default route moves to the tunnel.

## 6. Automatic list updates (VIRR / vBGP)

| Mechanism | Enabled by | Behavior |
|---|---|---|
| VIRR | Flag `--virr=ip.txt/CN` | Downloads the country IP list from APNIC every `virr.update-interval` (default 86400 s); retries after `virr.retry-interval` (default 300 s) on failure. |
| vBGP | A URL in `ip.routes[].vbgp` (`--vbgp` is on by default) | Downloads the URL into its `path` every `vbgp.update-interval` (default 3600 s). |

Both write the file only when the list **actually changed**, and then **restart the whole process** to apply it, briefly interrupting connections.

## 7. Generating rules from GeoIP / GeoSite (`geo-rules`)

With `geo-rules.enabled: true`, the client generates a bypass list and DNS rule file from GeoIP / GeoSite data at startup and loads them with the other sources.

```json
"geo-rules": {
  "enabled": true,
  "country": "cn",
  "geoip-dat": "./GeoIP.dat",
  "geosite-dat": "./GeoSite.dat",
  "geoip-download-url": "https://example.com/geoip.dat",
  "geosite-download-url": "https://example.com/geosite.dat",
  "geoip": ["./geoip-extra.txt"],
  "geosite": ["./geosite-extra.txt"],
  "dns-provider-domestic": "doh.pub",
  "output-bypass": "./generated/bypass-cn.txt",
  "output-dns-rules": "./generated/dns-rules-cn.txt",
  "append-bypass": ["10.0.0.0/8"],
  "append-dns-rules": ["internal.example.cn", "rules://./my-dns-rules.txt"]
}
```

| Field | Meaning |
|---|---|
| `country` | Country / category tag to extract, default `cn`. |
| `geoip-dat` / `geosite-dat` | `.dat` paths (default `GeoIP.dat` / `GeoSite.dat`); downloaded here at startup when the matching `*-download-url` is set. |
| `geoip` / `geosite` | Extra **local text** sources: geoip has one CIDR per line; geosite one domain per line, with `.qq.com`, `domain:`, `suffix:`, `full:`, `regexp:` forms. |
| `dns-provider-domestic` | Provider used in generated DNS rules (`domain/<provider>/nic`); falls back to `dns.servers.domestic`, then `doh.pub`. |
| `dns-provider-foreign` | Not used by the current generator (reserved). |
| `output-bypass` / `output-dns-rules` | Generated file paths, default `./generated/bypass-cn.txt` and `./generated/dns-rules-cn.txt`. |
| `append-bypass` | CIDRs or local files appended after the generated list. |
| `append-dns-rules` | Full rules, bare domains (normalized with the domestic provider), or local files referenced as `rules://path`. **`rules://` is valid only here.** |

Generated output loads before explicit `client.routing` sources. Desktop and Android run the generator in both TUN and proxy mode; iOS currently does not.

## 8. DNS handling on the server

When a client's DNS query arrives at the server through the tunnel:

- with `udp.dns.redirect` set (`IP:port` or `domain:port`), it is forwarded to that upstream;
- the server keeps a name cache (also governed by `udp.dns.ttl` / `udp.dns.cache`) and answers hits directly;
- otherwise it is forwarded to the original destination.

## 9. Troubleshooting

| Symptom | Check first |
|---|---|
| A bypass address still uses the tunnel | Is the source really a file (a wrong path becomes inline text); does `client.routing` make `--bypass` ignored; is the list IPv4 |
| Domestic sites resolve to foreign addresses | Does the DNS rule match; is its third segment accidentally `tun` |
| Connections drop briefly from time to time | `--virr` / vBGP enabled — list updates restart the process |
| `geo-rules` changes have no effect | Check whether `output-bypass` / `output-dns-rules` were regenerated; not supported on iOS |

## Related documents

- [Configuration reference · client.routing](../reference/CONFIGURATION.md) · [Policy v2](POLICY_CLI.md) · [Proxy mode](PROXY_MODE.md)
- Implementation details: [Client architecture](../architecture/CLIENT_ARCHITECTURE.md) · [DNS module design](../architecture/DNS_MODULE_DESIGN.md)
