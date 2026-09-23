# Project Interface Map
> Status: Active
> Type: Reference
> Last verified: a7e9b99

> **Purpose:** Inventory every discoverable OPENPPP2 interface and identify which surfaces are supported contracts, experiments, internal implementation details, or known gaps.
> **Audience:** Users, operators, client authors, integrators, and maintainers.
> **Status:** Current. This is a discovery map, not an ABI compatibility promise.
> **Last verified against:** Repository source and tests at `a7e9b99`, 2026-07-19.
> **Parent index:** [Reference](README.md) · **Chinese:** [项目接口全景图](PROJECT_INTERFACE_MAP_CN.md)

## How To Read This Map

This page is the canonical inventory for the project's callable and serialized boundaries. Detailed field semantics remain in the linked specialist references; source paths identify the implementation truth when documentation and code disagree.

| Label | Meaning |
|---|---|
| **Stable** | User- or integration-facing behavior relied on by current clients. Changes require compatibility review and paired documentation. |
| **Experimental** | Callable today, but incompletely tested or without a settled compatibility policy. |
| **Internal** | An implementation boundary between repository components. It is documented for maintainers, not offered as a third-party SDK. |
| **Deprecated** | Retained for compatibility; new integrations should use the named replacement. |
| **Gap** | Missing contract, unsafe ambiguity, implementation defect, or untested boundary. |

`public` in a C++ class means accessible to repository code. It does **not** make that class a stable external API. The repository has no installed C++ header set, export target, ABI version, or supported native SDK.

## Surface Summary

| Domain | Provider | Primary consumer | Input / output | Stability | Canonical detail |
|---|---|---|---|---|---|
| `ppp` process and CLI | C++ executable | Users, service managers, scripts | Arguments and files / exit status, logs, TUI | **Stable** with gaps | [CLI reference](CLI_REFERENCE.md) |
| `appsettings.json` | C++ configuration loader | Users and platform clients | JSON / normalized runtime policy | **Stable** de facto | [Configuration](CONFIGURATION.md) |
| Connection URI | C++ client | Users and profile/subscription producers | `ppp://`, `ppp://ws/`, `ppp://wss/` | **Stable** | [Configuration](CONFIGURATION.md) |
| Tunnel wire protocol | C++ client/server | OPENPPP2 peers | Encrypted frames, handshake, opcodes, INFO JSON | **Stable** de facto | [Packet formats](PACKET_FORMATS.md), [link layer](LINKLAYER_PROTOCOL.md) |
| Runtime snapshot JSON v1 | C++ runtime | TUI, Android, iOS | Versioned JSON snapshot | **Stable** | [UI runtime contract](UI_RUNTIME_CONTRACT.md) |
| Go manager admin API | `go/ppp` | Embedded `/admin/`, operators | HTTP JSON and subscription JSON | **Stable** for `/api/v1`; legacy routes are internal compatibility surfaces | [Management backend](../guides/MANAGEMENT_BACKEND.md) |
| C++–Go control link | C++ server and `go/ppp` | Repository server components | Length-prefixed JSON over WebSocket | **Internal** | [Management backend](../guides/MANAGEMENT_BACKEND.md) |
| Guardian API | `go/guardian` | Guardian WebUI and operators | HTTP JSON, SSE | **Experimental** | `go/guardian/api/router.go` |
| Android Flutter bridge | Flutter/Kotlin/JNI | Bundled Android app | Method/EventChannel, Intent, JNI, private files | **Internal** | `android/lib/vpn_service.dart`, `android/libopenppp2.cpp` |
| iOS Packet Tunnel bridge | Swift/C ABI | Bundled iOS app and extension | Provider messages, C callbacks, App Group files | **Internal** | `ios/OpenPPP2PacketTunnelBridge.h` |
| TUI commands | `ConsoleUI` | Interactive operators | Line commands / rendered terminal state | **Experimental** | `ppp/app/ConsoleUI.cpp` |
| Platform adapters | Windows, Linux, Darwin, mobile code | C++ runtime | TAP/TUN, routes, DNS, socket protection | **Internal** | platform directories and [platform guide](../guides/PLATFORMS.md) |

## 1. Process Entrypoints And Modes

| Entrypoint | Contract | Lifecycle / privilege | Stability | Source truth | Known gaps |
|---|---|---|---|---|---|
| `ppp` executable | `--mode=server` (default), `client`, or `proxy`; loads configuration and starts `PppApplication` | Full tunnel normally needs root/Administrator; proxy-only retains native client routing/DNS policy while avoiding desktop host-route installation and system-DNS takeover | **Stable** | `main.cpp`, `ppp/app/ApplicationConfig.cpp`, `ppp/app/PppApplication.*` | No formal exit-code table |
| Go manager executable | Managed mode with MySQL/Redis, or no-argument standalone subscription manager | Long-running HTTP/WebSocket service; persists standalone state | **Stable** | `go/main.go`, `go/ppp/Configuration.go`, `go/ppp/ManagedServer.go` | Operational shutdown and data migration contracts are not centrally specified |
| Guardian executable/service | Supervises binaries, profiles, instances, logs, and service installation | Host administration privileges may be required | **Experimental** | `go/guardian/main.go`, `go/guardian/api/router.go` | Host-path access and most handlers lack direct API coverage |
| Android `VpnService` | Bundled Flutter UI starts/stops native tunnel in `:vpn` process | Requires user VPN approval and foreground service; service is not exported | **Internal** | `android/android/app/src/main/.../PppVpnService.kt` | Cross-process event delivery defect; see gaps |
| iOS Packet Tunnel extension | App saves a `NETunnelProviderManager` profile and starts the extension | Requires Network Extension entitlement and user approval | **Internal** | `ios/App/OpenPPP2/VPNController.swift`, `PacketTunnelProvider.swift` | No real extension/native-library integration build in Actions |

## 2. Command-Line Interface

The supported command surface is grouped below. Exact aliases, defaults, parsing rules, examples, and platform restrictions are in [CLI Reference](CLI_REFERENCE.md).

| Group | Accepted switches | Stability / notes |
|---|---|---|
| Role and configuration | `--mode`, `--config`, `--proxy-http-port`, `--proxy-socks-port` | **Stable** |
| Runtime policy | `--rt`, `--dns`, `--tun-flash`, `--auto-restart`, `--link-restart`, `--block-quic`, `--firewall-rules`, `--lwip`, `--vbgp` | **Stable** |
| Adapter and address | `--nic`, `--ngw`, `--tun`, `--tun-ip`, `--tun-ipv6`, `--tun-gw`, `--tun-mask` | **Stable** |
| Tunnel behavior | `--tun-vnet`, `--tun-host`, `--tun-static`, `--tun-promisc`, `--tun-ssmt`, `--tun-route`, `--tun-protect`, `--tun-lease-time-in-seconds` | **Stable** |
| MUX | `--tun-mux`, `--tun-mux-acceleration`, `--mux-mode`, `--mux-mode-turbo` | `compat`, `flow`, and `balance` are **Stable** de facto; `stripe` is **Experimental** |
| Live MUX debug control | `--debug-key`, `--mux-mode-set` | **Experimental**; control/auth contract is not separately versioned |
| Routing and DNS inputs | `--bypass`, `--bypass-nic`, `--bypass-ngw`, `--virr`, `--dns-rules` | **Stable**; file formats need stronger schemas |
| Utilities | `--help`, `--pull-iplist` | **Stable** |
| Windows helper actions | Driver, route, DNS, proxy, and network-reset helpers, including parser-accepted `--set-http-proxy` | **Stable**, Windows-only, frequently exit after the action |

**Gap:** the generated help banner is not the complete parser contract. `--set-http-proxy` is accepted by the parser but absent from both help and the detailed CLI reference; other switches such as `--mux-mode-turbo` have also drifted from help. Automation must check parser source until a machine-readable option registry exists.

## 3. JSON Configuration

`appsettings.json` is loaded into `AppConfiguration`, then normalized by `Loaded()`, with CLI overrides applied around that process. Unknown keys, migration behavior, and schema versioning are not formally defined.

| Top-level block | Responsibility | Consumer | Stability | Source truth |
|---|---|---|---|---|
| `concurrent`, `vmem` | Execution concurrency and memory policy | Core runtime | **Stable** | `ppp/configurations/AppConfiguration.*` |
| `key` | Cipher, transport, masking, shuffle, delta, and key material | Both peers | **Stable**, security-sensitive | same |
| `tcp`, `udp`, `websocket`, `cdn` | Carrier listeners, connect policy, TLS/WS, and port modes | Transport layer | **Stable** | same |
| `mux` | Multiplexing mode and limits | Transport/runtime | `compat`/`flow`/`balance` **Stable** de facto; `stripe` and live control **Experimental** | same |
| `server` | Pools, mappings, backend, policies, IPv6, accounting identity | Server runtime | **Stable** | same |
| `client` | Server URI, reconnection, bandwidth, proxy, and canonical `client.routing` IP/DNS policy (`ip.bypass`, `ip.routes`, `ip.peer-routes`, `dns.rules`); runtime mode is controlled by top-level `--mode` and `client.proxy-only` | Client runtime | **Stable** | same |
| `ip`, `virr`, `vbgp` | Address, route/rule, and route propagation inputs | Network switcher | **Stable** de facto | same |
| `dns` | Resolver, interception, fallback, cache, and policy | Client/server DNS runtime | **Stable** de facto | same |
| `telemetry` | Exporter, signal, sampling, and resource attributes | Diagnostics/platform bridges | **Experimental** | same |
| `p2p` | Direct-channel discovery, signaling, transport, and fallback | Client/server P2P runtime | **Experimental** | same |
| `geo-rules` | Geographical routing/rule sources and behavior | Route/DNS policy | **Experimental** | same |

`client.routing` is the canonical client IP/DNS policy. Its four sources feed native route/DNS policy in both modes, while top-level `--mode=client`/`--mode=proxy` and the independent `client.proxy-only` flag select host integration. `proxy-only` suppresses desktop host-route and system-DNS takeover; mobile bridges keep only the minimal interface/subnet route and do not publish default routes, system DNS, or the local HTTP proxy. An old nested mode key is ignored and not serialized.

Complete fields and a full template are in [Configuration](CONFIGURATION.md). Platform profile stores wrap this JSON but do not replace its contract.

**Gaps:** no published JSON Schema for the whole configuration, no `schema_version`, no migration/unknown-key policy, and no automated compatibility fixture spanning desktop, Android, and iOS profile producers.

## 4. Connection And File URIs

| Form | Meaning | Authentication / security | Stability |
|---|---|---|---|
| `ppp://host:port/` | Native tunnel over TCP | Tunnel key configuration; no carrier TLS | **Stable** |
| `ppp://ws/host:port/` | Tunnel over WebSocket | Tunnel key configuration; no carrier TLS | **Stable** |
| `ppp://wss/host:port/` | Tunnel over TLS WebSocket | TLS plus tunnel key configuration | **Stable** |
| `ws://.../ppp/webhook`, `wss://...` | C++ server to Go manager control link | Shared backend key | **Internal** |
| `http(s)://.../sub/{token}` | Public mobile subscription document | Capability-bearing token in path | **Stable** |
| Local profile import/export file | iOS profile bundle JSON | User-selected file; contains secrets | **Stable** for bundled iOS app |

## 5. Transport, Handshake, Link-Layer, And Packet Protocols

| Boundary | Input / output | Compatibility status | Source truth | Verification |
|---|---|---|---|---|
| Protected frame | First/subsequent headers, encrypted payload, masking and delta state | **Stable** de facto; both peers must match | `ppp/transmissions/ITransmission.*` | [Packet reference](PACKET_FORMATS.md) and native builds; no direct frame compatibility test |
| Handshake | NOP exchange, session ID, `ivv`, `nmux`, cipher rebuild | **Stable** de facto | same | [Session/control model](TRANSMISSION_PACK_SESSIONID.md) |
| Carrier | TCP, WS, WSS streams | **Stable** | `ITcpipTransmission.*`, `IWebsocketTransmission.*` | native build/tests |
| Link-layer opcode | One-byte action plus opcode-specific payload | **Stable** de facto | `ppp/app/protocol/VirtualEthernetLinklayer.h` | [Link-layer protocol](LINKLAYER_PROTOCOL.md) |
| INFO envelope | JSON session/capability information and extensions | Base fields **Stable**; newer extensions **Experimental** | `VirtualEthernetInformation.*` | protocol tests where present |
| Runtime snapshot | JSON schema v1, ordered by generation and monotonic time | **Stable** | `schemas/runtime-snapshot-v1.schema.json`, `RuntimeSnapshotJson.h` | Shared C++/Dart/Swift fixtures |

**Gaps:** the tunnel has no explicit protocol-version negotiation, reserved-opcode registry, formal extension negotiation, direct protected-frame/handshake golden tests, or compatibility matrix across released versions. Wire compatibility is therefore implementation-coupled even where behavior is stable in practice.

## 6. C++–Go Control Protocol

The optional manager control link uses WebSocket path `/ppp/webhook`. Each message is an 8-character hexadecimal body length followed by JSON:

```text
[8 hex characters][{"Id":1,"Node":7,"Guid":"...","Cmd":1002,"Data":"..."}]
```

| Command | Direction | Purpose | Stability |
|---|---|---|---|
| `1000` ECHO | Bidirectional | Keepalive / latency | **Internal** |
| `1001` CONNECT | C++ → Go and reply | Establish backend control session | **Internal** |
| `1002` AUTHENTICATION | C++ → Go and reply | Authorize a VPN user | **Internal** |
| `1003` TRAFFIC | C++ → Go and reply | Report traffic accounting | **Internal** |

Authentication uses the configured manager `key` matched by C++ `server.backend-key`. Source truth: `go/ppp/Packet.go`, `Handler.go`, `ManagedServer.go`, and `ppp/app/server/VirtualEthernetManagedServer.*`.

**Gaps:** no envelope version, capability negotiation, maximum-frame contract, formal error object, or cross-language golden frame suite. WebSocket origin checks currently allow all origins.

## 7. Go Manager HTTP API

### Current JSON API

All `/api/v1/*` routes require the admin bearer token. `/sub/{token}` is a separate public capability URL. The embedded UI is normally served from `/admin/`; `OPENPPP2_ADMIN_TOKEN` can override the configured token. Standalone mode persists its generated token in `manager-data.json`; managed mode generates only a process-lifetime token when none is configured.

| Method and path | Purpose | Stability |
|---|---|---|
| `GET /api/v1/status` | Counts and manager status | **Stable** |
| `GET, POST /api/v1/users` | Managed mode lists/creates VPN users; standalone returns an empty list and rejects writes | **Stable**, mode-dependent |
| `PUT, DELETE /api/v1/users/{guid}` | Managed mode updates/deletes a user; standalone returns 404 | **Stable**, managed only |
| `GET, POST /api/v1/servers` | List/create server records | **Stable** |
| `PUT, DELETE /api/v1/servers/{id}` | Update/delete a server record | **Stable** |
| `GET, POST /api/v1/subscriptions` | List/create subscriptions | **Stable** |
| `PUT, DELETE /api/v1/subscriptions/{id}` | Update/delete a subscription | **Stable** |
| `POST /api/v1/subscriptions/{id}/rotate-token` | Invalidate and replace public token | **Stable** |
| `GET /api/v1/subscriptions/{id}/preview` | Preview generated document | **Stable** |
| `GET /sub/{token}` | Publish subscription JSON | **Stable** capability URL |

The authoritative route table is `go/ppp/Admin.go`; persistence is `go/ppp/LocalStore.go` and `Subscription.go`.

### Legacy Internal API

| Routes | Status | Preferred surface / risk |
|---|---|---|
| `/ppp/consumer/set`, `/new`, `/reload`, `/load` | **Internal**, legacy compatibility | Prefer `/api/v1/users`; handlers accept arbitrary methods and encode business errors in HTTP 200 responses |
| `/ppp/server/all`, `/get`, `/load` | **Internal**, legacy compatibility | Prefer `/api/v1/servers`; the shared `key` query parameter is required, as it is for the consumer routes |

The control WebSocket and all `/ppp/*` routes exist only in managed mode. No source-level removal schedule or formal deprecation policy currently exists.

**Gaps:** origin policy is permissive; server secrets can be returned to the admin UI; a formal OpenAPI document and complete response/error schema are missing.

## 8. Subscription And Admin UI Contracts

The public subscription payload consumed by Android and iOS is:

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "nodes": []
}
```

The `type` and `version` pair is **Stable**. Node entries are translated into complete native configuration profiles. Android parser tests exist in `android/test/remote_subscription_test.dart`; the iOS parser is in `ios/App/OpenPPP2/AppModels.swift` but lacks equivalent fixture tests.

The `/admin/` WebUI is a consumer of the manager API, not a separate supported API. Its storage, route, and authentication behavior must follow the backend contract.

The manager caps generated subscription documents at 2 MiB. **Gaps:** client download limits and cross-platform consistency, redirect policy, duplicate-node policy, a shared Android/iOS fixture suite, and explicit TLS/source trust policy remain unspecified. Tokens in subscription URLs may leak through logs and referrers.

## 9. Guardian HTTP And SSE API

Guardian routes are **Experimental**. When authentication is enabled, normal `/api/*` routes require `Authorization: Bearer <token>`. Auth routes and `GET /api/v1/status` bypass the common middleware. SSE also bypasses that middleware but performs its own TokenStore/JWT validation using a query token or Bearer token; it is public only when authentication is disabled. CORS currently allows `*`.

| Group | Routes |
|---|---|
| Authentication | `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `PUT /api/v1/auth/password` |
| Instances | `GET, POST /api/v1/instances`; `GET, PUT, DELETE /api/v1/instances/{name}`; `POST .../{name}/start|stop|restart`; `GET .../{name}/logs` |
| Profiles | `GET /api/v1/profiles`; `GET, PUT, DELETE /api/v1/profiles/{name}`; `POST .../{name}/validate`; `GET .../{name}/backups`; `POST .../{name}/restore/{backupId}` |
| Binaries | `GET /api/v1/binaries`, `GET /api/v1/binaries/discover`, `POST /api/v1/binaries`, `DELETE /api/v1/binaries/{id}` |
| Guardian/service | `GET /api/v1/status`, `PUT /api/v1/guardian/config`, `GET /api/v1/service/status`, `POST /api/v1/service/install`, `POST /api/v1/service/uninstall` |
| Streaming | `GET /api/v1/sse/logs/{name}`, `GET /api/v1/sse/events` |
| UI | `GET /` catch-all static file server; no SPA history fallback |

Source truth is `go/guardian/api/router.go`, `middleware.go`, handler files, and `go/guardian/webui/src/lib/api.js`.

Guardian config and instance state are written as JSON with mode `0600`; profiles and backups are ordinary files with mode `0644`; the registered-binary map is in memory and is rebuilt through discovery after restart.

**Gaps:** discover/register can access arbitrary host paths; `PUT /api/v1/guardian/config` currently ignores its request body; most handlers have no direct API tests; SSE credentials can appear in URLs; WebUI tokens use `localStorage`; profile save/restore is not atomic; binary registrations are not persistent. Password change is also the unauthenticated bootstrap path while auth is disabled, so first-time setup must remain on loopback or a trusted network.

## 10. Android Bridge

All Android entries below are **Internal** to the bundled Flutter application. Channel names are an internal ABI, not a third-party integration promise.

| Boundary | Operations / payload | Lifecycle | Source truth |
|---|---|---|---|
| Flutter MethodChannel `supersocksr.ppp/vpn` | `connect`, `disconnect`, `getRuntimeSnapshot`, `getLastError`, `readLog`, `getLogPath`, `clearLog`, `getVpnHeartbeatAgeMs`, installed-app query, diagnostics, `requestPermission` | UI process; asynchronous calls | `android/lib/vpn_service.dart`, `MainActivity.kt` |
| Activity → service Intent | connect/disconnect actions with `config_json`, `vpn_options_json` extras | Starts foreground non-exported `:vpn` service | `MainActivity.kt`, `PppVpnService.kt` |
| Kotlin → JNI | native run/stop, state/statistics/error/snapshot, socket protection, telemetry HTTP callback | `run()` blocks a background thread; callbacks require live service | `android/android/app/src/main/kotlin/supersocksr/ppp/android/c/libopenppp2.kt`, `android/libopenppp2.cpp` |
| JNI → Kotlin | `runtime_snapshot`, `protect`, `start_exec`, `post_exec`, telemetry HTTP | Static callbacks on `libopenppp2`; invoked from arbitrary runtime threads, so each attaches the JVM and never caches `JNIEnv*` | same |
| Profile storage | `profiles_v2`, active ID, options, bounded history | App-private SharedPreferences | `android/lib/services/profile_store.dart` |
| Cross-process state | `openppp2-runtime-snapshot.json`, `openppp2-lasterror.txt`, `openppp2-linkstate.txt` | Atomic replace via temporary file plus rename; heartbeat freshness is 30 seconds | `PppStateStore.kt`, `MainActivity.kt` |

`PppVpnService` runs in `:vpn`. The EventChannel it previously published to resolved a process-local static sink and delivered nothing, so it has been removed; the service now mirrors every runtime snapshot and error to the files above and the UI process polls them once per second while visible. Native publishes reach the service through the `runtime_snapshot` JNI callback and are ordered by the snapshot's own `generation` and `monotonic_ms`.

For proxy-only profiles, Android still loads the native `client.routing` policy. `VpnService.Builder` keeps only the minimal interface/subnet route; it does not publish default routes, system DNS, or the local HTTP proxy.

**Gap:** debug builds strip `android:process` from the service (`app/src/debug/AndroidManifest.xml`), so instrumentation always runs single-process and cannot reproduce cross-process delivery. That override is why the defect above survived. The release layout is currently enforced by source-level checks in `tests/tooling/test_runtime_ui_wiring.py`, not by a device test.

Other gaps: no centralized channel/JNI ABI version, no complete method/error schema, no service kill/recreate coverage, no full JNI signature test, and profile storage has no explicit migration version.

## 11. iOS Bridge

All iOS entries below are **Internal** to the bundled app and Packet Tunnel extension unless explicitly stated.

| Boundary | Operations / payload | Lifecycle | Source truth |
|---|---|---|---|
| App → Network Extension | Save/load manager, start/stop tunnel, provider configuration | System authorization and `NETunnelProviderManager` lifecycle | `VPNController.swift` |
| Provider messages | `linkState`, `lastError`, `diagnostics`, `crashReports`, `deleteCrashReports`, JSON `uploadCrashReports` | Only a connected `NETunnelProviderSession` can exchange messages | `VPNController.swift`, `PacketTunnelProvider.swift` |
| Swift → C ABI | `openppp2_ios_version`; tap create/destroy/start/stop/input; link/snapshot/stage queries; last error; telemetry; P2P datagram callbacks | Tap and callback ownership is explicit; provider close must stop callbacks synchronously | `ios/OpenPPP2PacketTunnelBridge.h` |
| App Group state | Link heartbeat, runtime snapshot, diagnostics, defaults | App and extension share entitled container; atomic file writes | `TunnelSharedState.swift` |
| Profile bundle | `type=openppp2-profile-export`, `version=1`, active ID and profiles | User-selected security-scoped file; 2 MiB limit; secrets included | `ProfileImportExport.swift` |

Profile export v1 is **Stable** for the bundled iOS app. The C ABI and provider-message commands remain **Internal**.

For proxy-only profiles, the Packet Tunnel keeps only the minimal interface/subnet route and does not publish default routes, system DNS, tunnel DNS, or the local HTTP proxy; native `client.routing` policy remains active.

**Gaps:** provider messages use unversioned bare strings and `nil` for multiple failures; C structs have no ABI version or `struct_size`; no complete buffer truncation convention; Actions do not build the native iOS static library or execute a real Packet Tunnel integration test.

## 12. Runtime Snapshot And TUI

Runtime snapshot JSON v1 is the strongest cross-platform contract in the repository. Required ordering fields are `schema_version`, `generation`, `monotonic_ms`, and `phase`; consumers reject unknown schemas and ignore stale snapshots. Shared fixtures cover C++, Dart, and Swift. Every TUI command below must be entered with the `openppp2 ` prefix.

| TUI command | Effect | Stability |
|---|---|---|
| `openppp2 help|info|clear` | Inspect or clear console state | **Experimental** |
| `openppp2 restart|reload|exit` | Restart/reload/shutdown application | **Experimental**; `reload` currently behaves like restart |
| `openppp2 telemetry status|help` | Inspect telemetry console filter | **Experimental** |
| `openppp2 telemetry log|metric|span on|off|toggle` | Change temporary in-process filter | **Experimental** |
| `openppp2 telemetry level 0|1|2|3`, `all`, `quiet`, `clear` | Change temporary verbosity/filter state | **Experimental** |

TUI availability depends on a TTY and `PPP_NO_TUI`. Commands execute on ConsoleUI lifecycle threads and are not a remote control API. Source: `ppp/app/ConsoleUI.cpp`, `ppp/app/tui/TuiRuntimeAdapter.h`.

**Gaps:** no parser/lifecycle/concurrent-shutdown tests; the input placeholder suggests system-command execution but the dispatcher rejects it; schema omits some optional fields produced by implementations.

## 13. C/C++ Headers And Extension Points

| Interface | Role | Classification | Why it is not an external SDK |
|---|---|---|---|
| `AppConfiguration` | Parsed and normalized runtime policy | **Internal** | Layout and fields can change with source |
| `ITransmission` | Protected carrier and handshake base | **Internal** | No installed headers or ABI contract |
| `VirtualEthernetLinklayer` / information types | Tunnel opcode and INFO implementation | **Internal**; base INFO/wire fields are stable de facto, newer extension JSON is **Experimental** | C++ object layout is not the wire contract |
| `PppApplication`, lifecycle/snapshot types | Composition root and state publication | **Internal** | Repository-owned lifecycle |
| DNS, route, MUX, TAP abstractions | Subsystem extension points | **Internal** | Platform/build-specific and not exported |
| Error handler and telemetry facade | Repository callbacks | **Internal**; numeric diagnostics are externally observable | No SDK target or callback ABI guarantee |
| `OpenPPP2PacketTunnelBridge.h` | iOS extension C boundary | **Internal** | Bundled bridge only; no install/export package |

Creating a supported native SDK would require a deliberately small installed header set, export visibility, ownership rules, ABI version and feature query, semantic version policy, packaging, examples, and cross-version binary tests. None currently exist.

## 14. Platform Adapters

| Platform | Internal boundary | Privilege / ownership | Main sources | Major gap |
|---|---|---|---|---|
| Windows | Wintun/TAP, route/DNS/proxy helpers, service/process helpers | Administrator for adapter and network changes | `windows/`, `TapWindows.*` | Helper exit/error behavior lacks one contract table |
| Linux | TUN, route/rule/DNS operations, optional io_uring/SYSNAT | root/CAP_NET_ADMIN | `linux/`, `TapLinux.*` | Distribution-specific command/rollback behavior needs integration coverage |
| macOS | utun, route/DNS operations | root for desktop tunnel | `darwin/`, `TapDarwin.*` | macOS build is not iOS extension validation |
| Android | `VpnService`, protected sockets, JNI callbacks; proxy-only keeps only the minimal interface/subnet route while native `client.routing` policy remains active | user VPN approval; service owns TUN fd | `android/` | Cross-process runtime snapshot defect and sparse device tests |
| iOS | Packet Tunnel, C callback bridge, App Group; proxy-only keeps only the minimal interface/subnet route while native `client.routing` policy remains active | entitlement and provider-owned packet flow | `ios/` | Native library and provider IPC not built end-to-end in CI |

## 15. Errors, Diagnostics, Telemetry, And Persistence

| Boundary | Format / behavior | Stability | Source truth | Gap |
|---|---|---|---|---|
| Diagnostic error code | Numeric enum plus text and thread-local/atomic last-error snapshot | **Stable** de facto | `ppp/diagnostics/ErrorCodes.def`, [error codes](ERROR_CODES.md) | Append-only policy and removal rules are not enforced |
| Error callback | In-process handler dispatch | **Internal** | `ErrorHandler.*` | No external callback ABI |
| Runtime statistics/link state | JSON/text/file/channel depending on platform | **Experimental** except snapshot v1 | platform bridges | Multiple lifetime/freshness rules are inconsistent |
| Telemetry facade | Logs, metrics, spans, OTLP HTTP callbacks | **Experimental** | `ppp/diagnostics/Telemetry.h`, platform bridges | Documentation and builds disagree on default enablement |
| Manager state | `manager-data.json` with `version: 1` | **Current persisted format** for standalone manager | `go/ppp/LocalStore.go` | No published JSON Schema, migration policy, or corruption-recovery contract |
| Guardian config/instances | JSON written with mode `0600` | **Internal persisted format** | `go/guardian/config.go`, `guardian.go` | No published schema or migration contract |
| Guardian profiles/backups | Files written with mode `0644` | **Internal persisted format** | `go/guardian/profile/manager.go` | Save/restore is not atomic |
| Guardian binary registry | In-memory registration plus rediscovery | **Internal runtime state** | `go/guardian/binary/manager.go` | Explicit registrations do not survive restart |
| Android profiles | SharedPreferences JSON | **Internal** | `profile_store.dart` | No explicit storage schema/migration |
| iOS profile export | Versioned JSON bundle | **Stable** | `ProfileImportExport.swift` | No standalone JSON Schema |
| Runtime fixtures | JSON plus hash manifest | **Stable test contract** | `tests/contracts/runtime-snapshot/`, `tools/check_runtime_fixture_hashes.py` | Schema does not enumerate all optional producer fields |

## 16. Build, Test, Tooling, And CI Interfaces

| Entrypoint | Output / purpose | Stability | Coverage gap |
|---|---|---|---|
| Root CMake and `build-openppp2-by-builds.sh` | Native `ppp` and Linux variants | **Stable developer interface** | Root build is separate from unit-test CMake |
| `build_windows.bat` | Windows x86/x64 Ninja builds | **Stable developer interface** | Environment/toolchain discovery is machine-dependent |
| `android/CMakeLists.txt`, build scripts | Four Android `libopenppp2.so` ABIs | **Internal build interface** | Hard-coded third-party defaults; no JNI export check |
| `ios/CMakeLists.txt` | `libopenppp2_ios.a` | **Experimental build interface** | Not built by current Actions |
| `go test ./...`, `go build ./...` | Go manager and Guardian checks | **Stable developer interface** | Guardian handler coverage is sparse |
| `flutter test` | Android/iOS client model/UI tests | **Stable developer interface** | No PR device test for Android VPN lifecycle |
| `scripts/run-cpp-tests.sh` | Standalone C++ CTest suite | **Stable developer interface** | Full platform networking still needs integration tests |
| `scripts/test-runtime-contract.sh` | `hashes`, `cpp`, `dart`, `swift` contract checks | **Stable test interface** | Hash check is repeated indirectly rather than one explicit CI gate |
| `tools/check_docs.py` | Metadata, relative links, bilingual map checks | **Stable governance interface** | Does not validate anchors or external URLs |
| Wave-B regression/bench scripts | Correctness and host-bound performance baselines | **Experimental** | Baselines are not portable across hosts/toolchains |

## Compatibility Rules For New Work

1. Update both language versions of every stable document.
2. Treat serialized bytes, JSON fields, route/method pairs, channel method names, and persisted files as contracts even when their implementation is internal.
3. Add a version or capability field before making incompatible serialized changes.
4. Preserve unknown fields where practical and define rejection behavior where not.
5. Never infer SDK support from C++ access modifiers.
6. Add producer/consumer fixtures for cross-language contracts.
7. Document authentication, secret exposure, lifecycle/thread ownership, error behavior, source truth, and tests for every new interface.

## Consolidated Gap Register

| Priority | Gap | Affected surface | Completion evidence |
|---|---|---|---|
| P1 | Android cross-process runtime delivery has no device test because debug builds collapse `:vpn` into the app process | Android runtime UI | An instrumentation variant that keeps `android:process`, or an equivalent multi-process harness |
| P1 | No tunnel protocol version/opcode registry/cross-release matrix | Wire protocol | Version negotiation, registry, and compatibility fixtures |
| P1 | Guardian binary paths can expose arbitrary host paths; config PUT ignores body | Guardian | Path policy, correct update behavior, and API tests |
| P1 | iOS native bridge/Packet Tunnel is not built end-to-end in CI | iOS | Static library build plus provider-message integration test |
| P1 | Whole configuration has no schema/version/migration policy | Configuration/profile stores | Published schema, version field, fixtures, migration tests |
| P1 | Go APIs lack OpenAPI and complete error/response schemas | Manager and Guardian | Generated/validated OpenAPI with auth and error models |
| P2 | CLI parser and help text can drift | CLI | Single option registry generating parser/help/tests |
| P2 | JNI/provider-message/C ABI boundaries lack consistent version and error contracts | Mobile bridges | ABI query/envelope versions and integration tests |
| P2 | Error numbers and telemetry defaults lack enforced compatibility policy | Diagnostics/telemetry | Automated enum policy and one verified default |
| P2 | Persistence formats lack atomic migration and schema contracts | Go/Android/iOS | Versioned formats, atomic replacement, corruption recovery tests |

This register describes current evidence; it does not by itself authorize exposing unauthenticated or host-level operations to untrusted networks.
