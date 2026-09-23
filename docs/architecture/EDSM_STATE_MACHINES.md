# EDSM State Machines
> Status: Active
> Type: Architecture
> Last verified: runtime lifecycle, client exchanger, and server switcher sources, 2026-07-22
>
> **Purpose:** Separate the process state shown to operators from session and server ownership state.
> **Audience:** Contributors diagnosing state presentation.
> **Parent index:** [Architecture](README.md) · **Chinese:** [EDSM 状态机](EDSM_STATE_MACHINES_CN.md)

## Do not collapse these layers

Current code has several related but different state surfaces:

| Surface | Owner | Meaning |
|---|---|---|
| `RuntimePhase` in `RuntimeSnapshot` | `RuntimeLifecycle` | Process-facing lifecycle presentation |
| `VEthernetExchanger::NetworkState` | Client exchanger | Client tunnel-session state |
| `RuntimeReadiness` | Client switcher / server helper | Gate between a requested and a published connected state |
| `VirtualEthernetExchanger` instances | Server switcher | Per-client server session ownership, not one shared state enum |

Treating these as one state machine loses useful distinctions.

## Process-facing runtime phase

`RuntimeLifecycle` publishes snapshots with phases including `idle`, `starting`, `preparing_host`, `connecting`, `handshaking`, `applying_policy`, `connected`, `reconnecting`, `stopping`, and `failed`.

It gives each `Begin()` call a new generation, rejects updates for stale or stopping generations, preserves a monotonically increasing timestamp, and publishes snapshot copies through `RuntimeSnapshotPublisher`. Listeners are invoked outside its internal mutex.

`Transition()` does **not** define a complete allowed-transition table. The diagrams and phase sequence in this documentation are observed application flow, not a protocol grammar enforced by the lifecycle class.

## Client session input and readiness

The client exchanger has three network states: `Connecting`, `Established`, and `Reconnecting`. During `OnTick()`:

```text
no exchanger        -> connecting
reconnecting        -> reconnecting
established         -> update readiness, then request connected
other exchanger state -> handshaking
```

When `connected` is requested, `RuntimeLifecycle` gates it with five readiness facts: session, adapter, route, DNS, and policy. An established tunnel can therefore remain represented as `applying_policy` until client host policy has completed.

The current client readiness path does not make `INFO` a universal prerequisite. It is assembled after the switcher’s open/policy path rather than requiring managed-session information in every mode.

## Server session ownership and readiness

The server owns one `VirtualEthernetSwitcher` and creates per-client `VirtualEthernetExchanger` objects. This is an ownership topology, not the client `NetworkState` machine.

At process level, `OnTick()` uses `server_->IsRunning()` to build server readiness and request `connected`. That signal describes active listener runtime; it is not a health roll-up for every client, the optional management bridge, or Linux IPv6 transit state.

## Stop presentation

`Dispose()` calls `TryBeginStop()` for the active generation, stops optional UI, and asynchronously tears down client/server objects. Cleanup completion calls `CompleteStop()` to publish `idle` or `failed`.

This path is coordinated by `RuntimeLifecycle`, but it is not a guarantee that all startup failures or executor exits publish a final terminal snapshot. See [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md).

## Consumers

`OnTick()` obtains the latest snapshot and uses it to build phase/MUX/P2P status lines for the native TUI. The overall displayed status also contains separately sampled traffic and link-quality text, so the rendered console line is not a raw one-to-one renderer of `RuntimePhase`.

Consumers that need an initial snapshot must call the snapshot getter; subscription does not replay the latest snapshot at subscription time.
