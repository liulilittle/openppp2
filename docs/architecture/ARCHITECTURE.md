# System Architecture
> Status: Active
> Type: Architecture
> Last verified: native entry, runtime, transport, and platform source paths, 2026-07-22
>
> **Purpose:** Give a source-backed map of the current `ppp` runtime.
> **Audience:** Contributors and operators.
> **Current scope:** The native executable and tree-local companion surfaces; this is not a public SDK contract.
> **Parent index:** [Architecture](README.md) · **Chinese:** [系统架构](ARCHITECTURE_CN.md)

## Runtime at a glance

The root CMake target builds the native `ppp` executable and links the in-tree `openppp2_lib` static library. The executable is deliberately thin:

```text
main.cpp
  -> ppp::facade::RunApplication(argc, argv)
  -> PppApplication::GetInstance().Run(argc, argv)
  -> argument/configuration preparation
  -> Executors::Run(...)
  -> PppApplication::Main(...)
  -> client or server bootstrap
```

`main.cpp` does not own networking, configuration, or shutdown. `PppApplication` owns the process-level configuration, runtime objects, periodic maintenance, and `RuntimeLifecycle` publication.

## Major implementation areas

| Area | In-tree paths | Current responsibility |
|---|---|---|
| Native runtime | `ppp/` | Application lifecycle, client/server roles, protocol, transport, DNS, routing, diagnostics |
| Shared low-level code | `common/` | Embedded and shared support code used by the native target |
| Platform adapters | `windows/`, `linux/`, `darwin/` | Platform-specific device, route, and host integration selected at build time |
| Android and iOS integration | `android/`, `ios/` | Platform hosts that embed or bridge the native runtime |
| Desktop client | `desktop/client/` | Separate desktop UI that launches the native process and consumes its stats output |
| Go services | `go/` | Optional management-related services; not required for an unmanaged native tunnel |

These are all parts of this tree, but they are not interchangeable owners of the C++ tunnel runtime. The canonical session owners remain the native `VEthernet*` and `VirtualEthernet*` classes.

## Role selection and owners

The command-line mode chooses the application role; an omitted `--mode` resolves to `server`.

| Role | Selection | Primary runtime owner |
|---|---|---|
| Server | `--mode=server` or no mode | `VirtualEthernetSwitcher` |
| Client | `--mode=client` | `VEthernetNetworkSwitcher` |
| Proxy | `--mode=proxy` | Client runtime in proxy-oriented shape |

`client.proxy-only` applies proxy-oriented defaults after mode resolution; it does **not** itself choose client or proxy mode. `--mode=proxy` also has distinct privilege and Windows-preflight behavior from a client role with `client.proxy-only: true`.

A client switcher owns host-facing work such as the tunnel device, routes, DNS policy, local proxy listeners, and its active exchanger. A server switcher owns listeners and per-session `VirtualEthernetExchanger` instances. A server may also create a Linux IPv6 transit device when that feature is configured, so “server has no TAP/TUN” is too broad.

## Runtime state and presentation

`RuntimeLifecycle` publishes copyable `RuntimeSnapshot` values. `OnTick()` samples client or server state, updates readiness, traffic, MUX, and P2P presentation, and then updates the terminal UI and optional stats output.

The observed normal progression includes `starting`, `preparing_host`, `connecting`, `handshaking`, `applying_policy`, `connected`, `reconnecting`, `stopping`, and a final `idle` or `failed` when cleanup reports completion. This is a presentation and coordination model, not an enforced transition table: `RuntimeLifecycle::Transition()` validates generation/stop state and gates `connected` through readiness, but does not encode a complete legal-transition matrix.

For a client, `connected` is gated by session, adapter, route, DNS, and policy readiness. For a server, the process-facing signal is based on whether listener runtime is running; it is not a summary of every client session or of an optional management-backend connection.

## Data-plane layers

```text
TCP / WS / WSS carrier
  -> ITransmission (handshake and frame protection/transforms)
  -> VirtualEthernetLinklayer (opcode dispatch)
  -> client or per-session server exchanger
  -> host device / virtual stack / relay / forwarding path
```

`ITransmission` is below the tunnel action layer. The shared `VirtualEthernetLinklayer` parses an action opcode from each decoded payload, while concrete client and server exchangers implement the side-specific handling. The active carrier, handshake, and frame behavior are documented in [Transport and Protected Transmission](TRANSMISSION.md); opcode-level facts belong in the reference material rather than this overview.

## Important limits

- Normal direct P2P data-plane operation remains fail-closed: `ProductionAuthenticatedControlV1Ready` is `false`. Source contains P2P work, but it must not be documented as a production direct path.
- A proxy-only desktop runtime may use `TapStub`, whose output is intentionally discarded. Android and iOS have different platform device paths; do not generalize the desktop stub behavior to them.
- The tree contains optional UIs and management surfaces, but their presence does not turn the C++ runtime into a stable cross-language SDK or remote-control API.
- Use [Reference](../reference/README.md) for supported configuration and interface facts, and [ADRs](../adr/README.md) or [Archive](../archive/README.md) for historical rationale.

## Read next

- [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md)
- [Client Architecture](CLIENT_ARCHITECTURE.md) and [Server Architecture](SERVER_ARCHITECTURE.md)
- [Tunnel Design](TUNNEL_DESIGN.md) and [Packet Lifecycle](PACKET_LIFECYCLE.md)
- [EDSM State Machines](EDSM_STATE_MACHINES.md) and [TUI Design](TUI_DESIGN.md)
