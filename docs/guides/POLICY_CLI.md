# Policy v2 and `ppp policy`

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `ppp/app/client/policy/PolicySourceLoader.cpp`, `PolicyCompiler.cpp`, `PolicyModel.h`, `ppp/app/ApplicationPolicyCommand.cpp`)
>
> **Purpose:** Describe split routing and DNS policy with a rules file (`client.policy`), and check, explain, migrate, and update it with `ppp policy`.
> **Audience:** Client users who need finer split control than `client.routing`.
> **Parent index:** [Guides](README.md) · **Chinese:** [策略 v2 与 `ppp policy`](POLICY_CLI_CN.md)

Available since v2.1.7; v2.1.6 and earlier have neither `client.policy` nor `ppp policy`.

## 1. Relationship to `client.routing`

| | `client.routing` (legacy) | `client.policy` (v2) |
|---|---|---|
| Form | IP lists + DNS rule files | One rules file: domain / IP → direct / proxy / reject, plus DNS resolver bindings |
| Capabilities | Direct or tunnel | Direct, proxy, reject; exact / suffix / keyword / regex matching; rule sets; Fake-IP; automatic updates |
| Tooling | None | `ppp policy check` / `explain` |

**They cannot be combined.** With `client.policy` present, any of these keys makes the configuration fail to load: `client.routing`, `client.bypass`, `client.dns-rules`, top-level `routing`, `geo-rules`, `dns`, `bypass`, `dns-rules`, `udp.dns`. Generate a v2 draft from a legacy configuration with `ppp policy migrate` (section 7).

## 2. Quick start

```bash
# 1. Generate a starter policy (split-cn needs GeoIP / GeoSite sources: local files or HTTP(S) URLs)
ppp policy init --out ./policy --template split-cn --runtime tun \
  --geoip ./geoip.txt --geosite ./geosite.txt

# 2. Merge the generated client.policy into the client configuration, then check
ppp policy check --config ./client.json --runtime tun

# 3. See how a target would be handled
ppp policy explain --config ./client.json --runtime tun --domain www.example.com --network tcp --port 443

# 4. Start the client normally
sudo ./ppp --mode=client --config=./client.json
```

Templates: `proxy-all`, `direct-all`, `split-cn` (China direct, everything else proxied). `init` never overwrites existing files; local source files are limited to 64 MiB; URL sources are recorded, not downloaded.

`--runtime` is `tun`, `http`, or `socks` (the TUN client and the two proxy-mode listeners); `--platform` is optional — `linux`, `windows`, `macos`, `android`, `ios` — and defaults to the current platform.

## 3. Configuration fields

Minimal example (documentation-reserved addresses):

```json
"client": {
  "policy": {
    "version": 2,
    "rules": { "path": "./policy/rules.txt" },
    "dns": {
      "mode": "auto",
      "resolvers": {
        "direct": { "via": "direct", "servers": ["udp://192.0.2.53:53"] },
        "proxy":  { "via": "proxy",  "servers": ["udp://192.0.2.53:53"] }
      }
    }
  }
}
```

The v2 configuration **rejects unknown keys**; a misspelled field name is an error.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `version` | int | required | Must be the integer `2`. |
| `rules.path` | string | required | Rules file; relative paths resolve against the configuration file's directory; local sources limited to 64 MiB. |
| `ipv6` | string | `block` | Only `block` is supported. |
| `tcp-domain-sniff` | bool | `false` | Sniff domains from TCP traffic in TUN mode; unsupported on iOS TUN, not applicable to local HTTP / SOCKS. |
| `dns.mode` | string | `auto` | `auto`, `real`, or `fake-ip`. `auto` uses Fake-IP in TUN and real resolution preserving the original domain in HTTP / SOCKS. Explicit `fake-ip` requires TUN DNS interception. |
| `dns.resolvers` | object | required | Non-empty; each resolver has `via` (`direct` or `proxy`, the egress of its upstream connection) and a non-empty ordered `servers`. Servers may be provider names, numeric IPv4 endpoint strings (e.g. `udp://IP:53`, TCP / DoT / DoH URIs), or `{uri, addresses?, bootstrap?}` objects; a hostname endpoint needs explicit numeric addresses or a direct UDP bootstrap. |
| `dns.fake-ip.range` | IPv4 CIDR | `198.18.0.0/16` | Fake-IP pool. |
| `dns.fake-ip.storage` | path | `./dns-fake-ip` | Durable mapping store, relative to the configuration file; required for `fake-ip`. |
| `dns.fake-ip.identity` | string | derived from the config path | 1–128 characters: letters, digits, `.`, `_`, `-`, `:`. |
| `rule-sets.<name>.format` | string | required | `geoip-text`, `geosite-text`, `geoip-dat`, `geosite-dat`. |
| `rule-sets.<name>.source` | object | required | Exactly one of `path` (local) or `url` (HTTP(S)). |
| `rule-sets.<name>.tag` | string | required for `.dat` | Dataset tag, e.g. `cn`. |
| `rule-sets.<name>.sha256` | hex | none | Optional 64-digit pin of the source bytes. |
| `updates.enabled` | bool | `false` | Periodically update remote rule sets at runtime. |
| `updates.interval` | string | `24h` | Positive integer plus `s` / `m` / `h` / `d`. |
| `updates.via` | string | `proxy` | Update egress, `direct` or `proxy`; must match the egress chosen for `ppp policy update`. |
| `updates.bootstrap` | string[] | empty | `udp://IPv4:port` resolvers for hostnames in direct updates; no implicit hostname resolution. |
| `updates.allow-http` | bool | `false` | Allow HTTP sources; HTTPS only by default. |

## 4. Rules file syntax

```text
default proxy              # exactly one: default direct | proxy | reject
dns direct direct          # required: resolver for direct traffic (name from dns.resolvers)
dns proxy proxy            # required: resolver for proxied traffic

[direct]
=router.lan                # exact domain
example.cn                 # suffix: the domain and its subdomains
*.corp.example             # subdomains only
keyword:intranet
regexp:^api[0-9]+\.example\.com$
192.168.0.0/16             # IPv4 CIDR
set:geosite-cn             # a rule set declared in rule-sets
set:geoip-cn

[proxy]
example.com

[reject]
ads.example

[dns:direct]               # domain exceptions that use a specific resolver
special.example
```

**Match priority:**

1. Explicit rules beat rules expanded from `set:`.
2. Domain conditions: exact > suffix / subdomain > keyword > regex.
3. The longest suffix wins; for equal length, `*.example` beats `example`.
4. IPv4 CIDRs: the longest prefix wins.
5. Equal priority follows declaration order.

Rule set example:

```json
"rule-sets": {
  "geoip-cn":   { "format": "geoip-dat",   "tag": "cn", "source": { "path": "./GeoIP.dat" } },
  "geosite-cn": { "format": "geosite-dat", "tag": "cn", "source": { "url": "https://rules.example.test/geosite.dat" } }
}
```

A URL-only rule set cannot pass offline checks until downloaded with `ppp policy update`.

## 5. DNS and Fake-IP

- The resolver `servers` protocol (UDP / TCP / DoT / DoH) only selects how the **policy engine talks upstream**; TUN intercepts queries to UDP port 53, not an application's own TCP/53 or DoH / DoT.
- Fake-IP mappings live in `dns.fake-ip.storage`. Do not delete it while clients may cache pool addresses; after changing the pool, identity, or clearing mappings, restart and clear device DNS caches. There is no online clear.

## 6. Check and explain

| Command | Purpose |
|---|---|
| `ppp policy check --config F --runtime R [--platform P] [--json]` | Validate configuration, rule syntax, local rule sets, and selected platform capabilities. Does not start the tunnel or download. |
| `ppp policy explain --config F --runtime R (--domain H \| --ip A) [--network tcp\|udp] [--port N] [--json]` | Show which rule a target matches, its egress, and resolver. No DNS lookups; IPv6 targets unsupported. |

`check` judges capabilities from code paths; passing it does not prove a working tunnel.

## 7. Migrating a legacy configuration

```bash
ppp policy migrate --config ./old-client.json --out ./policy-draft \
  --bypass ./ip.txt --dns-rules ./dns-rules.txt --runtime tun
```

- Writes a v2 draft and report; the original configuration is untouched.
- Exit code `5` means the draft has differences needing review (files are still written). DNS upstream egress, cache scope, Fake-IP, ECS, IPv6 / AAAA, Geo generation, and platform routing may not convert automatically.

## 8. Export, update, and status

| Command | Purpose |
|---|---|
| `ppp policy export --config F --out FILE [--store DIR]` | Export checked local rules or a durable bundle as a policy-only file; never the whole app config or Fake-IP mappings; no downloads. |
| `ppp policy update --config F [--store DIR] --interface IF [--bootstrap udp://IP:PORT]` | Download remote rule sets directly through an interface. `--bootstrap` is needed only when a source URL uses a hostname. |
| `ppp policy update --config F [--store DIR] --proxy-endpoint 127.0.0.1:PORT` | Download through a local SOCKS5 proxy; `--bootstrap` is rejected in this mode. |
| `ppp policy status --config F [--store DIR]` | Show update state and active / prepared versions. |

- `update` is the only downloading command. A validated download is stored as a prepared version (the report says `prepared_for_next_start`); it does **not** switch a running process and takes effect at the next start. The default store is `.ppp-policy` beside the configuration file; with a custom `--store` the runtime does not read it — `export` it.
- Runtime auto-update is separate: with `updates.enabled: true`, a running client downloads at `interval` and applies the update within the session.

## 9. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Argument, configuration, or rule error |
| `3` | Source unavailable, storage failure, or status lease held |
| `4` | Capability unsupported by the selected platform / runtime |
| `5` | Migration draft needs review |

`--json` prints a schema-1 machine-readable report.

## 10. Verification scope

Linux live testing covered HTTP, CONNECT on port 80, SOCKS UDP, DNS, Fake-IP, and controlled policy updates; HTTPS CONNECT, SOCKS HTTPS, proxy TCP, and TUN HTTPS probes did not pass at the time. Windows, macOS, Android, and iOS were not live-tested for this feature. See the [Linux live report](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md).

## Related documents

- [Routing and DNS](ROUTING_AND_DNS.md) · [Configuration reference · client.policy](../reference/CONFIGURATION.md) · [CLI reference](../reference/CLI_REFERENCE.md)
