# Operations and Troubleshooting

> **Status:** Current
> **Type:** Operations guide
> **Last verified:** Runtime lifecycle, CLI help, stats, console UI, and diagnostic sources, 2026-07-22
> **Parent index:** [Operations](README.md) · **Chinese:** [运维与故障排查](OPERATIONS_CN.md)

## Start with observable state

Use the selected process mode and explicit configuration path first:

```bash
./ppp --mode=server --config=./server.json
./ppp --mode=client --config=./client.json
./ppp --mode=proxy  --config=./client.json
```

The runtime snapshot phase names are:

```text
idle → starting → preparing_host → connecting → handshaking →
applying_policy → connected → reconnecting → stopping → idle|failed
```

A phase is useful evidence, not proof that every host-network action or application flow works.

## Built-in local observability

| Surface | Use | Boundary |
|---|---|---|
| `--stats-json=<path|stdout>` | Write local runtime statistics as NDJSON. | It is a local output option, not a network metrics endpoint. |
| Runtime snapshot | Contains role, phase, endpoint/transport information, traffic, capabilities, and last error state. | Access follows the hosting/UI path; no public REST API is implied. |
| Console UI | Local interactive commands include `openppp2 help`, `restart`, `reload`, `exit`, and `info` when the UI is available. | Do not treat it as remote management. |
| Diagnostics | Inspect process output and the current error state; error formatting APIs are available to code that embeds the runtime. | A code-level diagnostic API is not an operator HTTP API. |

Restart controls are CLI-only:

| Flag | Meaning |
|---|---|
| `--auto-restart=<seconds>` | Auto-restart interval; `0` disables it. |
| `--link-restart=<count>` | Reconnection-attempt threshold for link restart; `0` disables it. |

## Troubleshoot by phase

| Symptom | First checks |
|---|---|
| Fails before `starting` or exits immediately | Mode/config path, process permissions, single-instance condition, and configuration parse errors. |
| Stays in `connecting` | Server URI, network reachability, local route policy, and upstream proxy configuration if used. |
| Stays in `handshaking` | Matching endpoint/transport/key configuration and the selected WebSocket/TLS path. |
| Stays in `applying_policy` | Virtual-interface availability, route/DNS permissions, and platform host state. |
| Reaches `connected` but carries no intended traffic | Host routes, bypass/DNS inputs, resolver behavior, remote server policy, and application test path. |
| Managed authentication fails | `server.node`, `server.backend`, C++/Go shared key, manager mode, and node record. |
| Server IPv6 fails | Linux-only server boundary, IPv6 mode/CIDR, host capability, TUN, routing/NDP/NAT66 prerequisites. |

## Safe operating sequence

1. Capture the exact command, selected config path, and initial output.
2. Confirm mode-specific host effects: listener bindings for server/proxy, or virtual interface/routes for normal client mode.
3. Record phase and last error before changing configuration.
4. Change one variable at a time; route/DNS and firewall changes can obscure one another.
5. Use an explicit maintenance/rollback procedure for host-managed settings rather than assuming the application can restore unrelated state.

## Do not assume

- a `connected` snapshot is not an end-to-end traffic test;
- `--stats-json` is not Prometheus or a remote observability service;
- Console UI commands are not an authenticated remote administration protocol;
- no undocumented `/metrics`, lease, or IPv6-state REST endpoint is supplied by this runtime;
- default-route protection is not a universal kill switch.

## Related pages

- [Deployment model](DEPLOYMENT.md)
- [Security model](SECURITY.md)
- [Routing and DNS](../guides/ROUTING_AND_DNS.md)
- [Management backend](../guides/MANAGEMENT_BACKEND.md)
- [Error codes](../reference/ERROR_CODES.md)