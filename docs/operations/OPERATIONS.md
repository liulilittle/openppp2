# Operations and Troubleshooting

> Status: Active
> Type: Operations
> Last verified: 2026-10-11 (against `ppp/facade/ApplicationBootstrap.cpp`, `ApplicationInitialize.cpp`, `ApplicationMainLoop.cpp`, `ppp/app/runtime/RuntimePhase.h`, `RuntimeStatsJson.*`, `ConsoleUI.cpp`)
>
> **Purpose:** Tell whether OPENPPP2 is working, and locate problems in order when it is not.
> **Audience:** Operators and users running a server or client.
> **Parent index:** [Operations](README.md) · **Chinese:** [运维与排障](OPERATIONS_CN.md)

## 1. What you can observe

| Source | How | Shows |
|---|---|---|
| Startup failure output | On exit, stderr prints one line `[severity] number Name: description` | The failure reason; look the name up in [Error codes](../reference/ERROR_CODES.md) |
| Console UI | Shown automatically in a foreground terminal (also under Guardian) | Status bar: connection state, throughput, last error; `openppp2 info` prints the full runtime environment |
| Startup diagnostics | `[security]` and `[mux]` lines at startup | Weak key / plaintext / legacy cipher warnings; active MUX scheduler |
| `--stats-json=<file\|stdout>` | Startup flag | One JSON object per line (`type: "ppp-stats"`): rx/tx bytes, link quality, TCP stack, platform counters |
| `server.log` | Server configuration | Session log file |
| `telemetry.*` | Configuration | Telemetry logs / metrics / spans, to a file or OTLP |
| `openppp2 peer status` | Console command | P2P peer state |

There is no built-in HTTP metrics or management endpoint; `--stats-json` only writes locally.

## 2. Runtime phases

A client moves through these phases, visible in the console and runtime snapshot:

```text
idle → starting → preparing_host → connecting → handshaking → applying_policy → connected
                                                       ↘ reconnecting ↗          ↘ stopping → idle / failed
```

`connected` only means the tunnel handshake completed; it does not prove traffic flows as intended — test real access.

## 3. Troubleshoot by phase

| Stuck at / symptom | Check first |
|---|---|
| Exits immediately | The error name on stderr. Common: `AppPrivilegeRequired` (non-proxy modes need administrator / root, **the server too**), `AppAlreadyRunning` (an instance with the same mode and configuration file is running), `ConfigFileNotFound` / `ConfigLoadFailed` (path or JSON error), IPv6 unsupported on the platform |
| `preparing_host` | Virtual adapter driver (Windows Wintun / TAP, Linux `/dev/net/tun`); adapter name conflicts |
| `connecting` | `client.server` address, port, prefix; server firewall; `client.server-proxy`; reachability (`nc -vz SERVER PORT`) |
| `handshaking` | Identical `key` on both sides; WS / WSS domain, path, certificates; `transport-auth` configured on both sides |
| `applying_policy` | Route / DNS permissions; split rule files; whether `client.policy` passes `ppp policy check` |
| `connected` but no traffic | Split rules sending the target direct; DNS reachability; server egress; `openppp2 info` for the assigned address |
| Repeated `reconnecting` | Network instability, server restarts, duplicate `client.guid`; too small `--link-restart` |
| Periodic brief disconnects | `--auto-restart`, `--virr`, and vBGP list updates all restart the process |
| Managed authentication fails | `server.node >= 1`, `server.backend` / `backend-key` match the manager, manager in managed mode, node record exists (see [Management backend](../guides/MANAGEMENT_BACKEND.md)) |

## 4. Automatic restarts

| Mechanism | Meaning |
|---|---|
| `--auto-restart=<seconds>` | The process restarts itself after running this long |
| `--link-restart=<count>` | Restart when the client's reconnection count reaches this value |
| `openppp2 restart` / `reload` | Manual restart (re-reads the configuration) |
| systemd `Restart=always` / Guardian `autoRestart` | External restart after abnormal exit; see [Deployment](DEPLOYMENT.md) |

## 5. Safe operating sequence

1. Record the full start command, configuration path, and initial output.
2. Record the current phase and last error before changing configuration.
3. Change one thing at a time; route, DNS, and firewall changes can mask each other.
4. Back up configuration first; prepare manual rollback steps for host route, DNS, and firewall settings.
5. Stop clients with `Ctrl+C` / `openppp2 exit` so routes and DNS are restored.

## 6. Policy v2 troubleshooting

| Symptom | Inspect |
|---|---|
| A domain takes the wrong path | `ppp policy explain --config F --runtime tun --domain <domain>` |
| Rules fail to validate | Diagnostics from `ppp policy check --config F --runtime tun --json` |
| An update has no effect | `ppp policy status`: versions downloaded by `ppp policy update` apply at the next start (`prepared_version`); a custom `--store` needs `export` |
| Fake-IP addresses change after restart or are unavailable | Was the `dns.fake-ip.storage` directory deleted or held by another process? Do not delete the store as a first recovery step |
| Status file missing or stale | Another process may hold the status writer lock; the status file is observability only and does not drive routing |

## 7. When reporting a problem

Share only redacted information: the error line, the phase, platform and version, and configuration excerpts without addresses or keys. Never post full configurations, node addresses, subscription links, or keys.

## Related documents

- [Deployment](DEPLOYMENT.md) · [Security](SECURITY.md) · [Error codes](../reference/ERROR_CODES.md)
- [Writing the configuration file · common mistakes](../getting-started/CONFIGURE.md) · [Routing and DNS](../guides/ROUTING_AND_DNS.md)
