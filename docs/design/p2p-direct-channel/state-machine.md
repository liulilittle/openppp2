# P2P Direct Channel State Machine

> **Purpose:** Define P2P direct-channel states, transitions, and failure behavior.
> **Audience:** Protocol, networking, and platform maintainers.
> **Status:** Current design evidence; not an enabled production data path.
> **Last verified against:** P2P integration and fail-closed production capability gate, 2026-07-22.
> **Parent index:** [Design Documents](../README.md)

> Status: Draft
> Type: Design
> Last verified: 8c8a888

## States

The direct-channel design reserves these stable values. The current
fail-closed scaffold does not expose an enabled production path or currently
emit `Failed`; do not read every listed transition as present runtime behavior.

| State | Meaning | Effective path |
|---|---|---|
| `Disabled` | Experimental configuration is off | `relay` |
| `Unavailable` | Exporter, peer capability, or platform protection is absent | `relay` |
| `Relay` | Base tunnel is healthy; no direct attempt is active | `relay` |
| `Eligible` | Both peers and local policy permit a bounded attempt | `relay` |
| `Probing` | Authenticated probes are in flight | `relay` |
| `Direct` | An authenticated probe ACK established the UDP channel | `direct` |
| `Suspect` | Direct liveness is uncertain | `relay` |
| `FallingBack` | Direct state is being discarded | `relay` |
| `Failed` | Target state for a recorded failed attempt; relay remains healthy | `relay` |

`effective_path` has only `relay` or `direct`. `Direct` is the only state that
may publish `direct`. P2P failure does not change a healthy base runtime phase
from `Connected`.

## Target Transitions

```text
Disabled -> Relay                 experimental flag enabled
Relay -> Unavailable             eligibility prerequisite missing
Unavailable -> Relay             prerequisites recover; no valid offer yet
Unavailable -> Eligible          prerequisites recover with a valid fresh offer
Relay -> Eligible                exporter, peer capability, policy, protection ready
Eligible -> Probing              valid unexpired relay offer accepted
Probing -> Direct                authenticated probe ACK accepted
Probing -> FallingBack           timeout, auth failure, UDP blocked, cancellation
Direct -> Suspect                liveness loss, endpoint change, socket warning
Suspect -> Direct                authenticated recovery ACK or valid authenticated peer data
Suspect -> FallingBack           timeout, auth failure, migration failure
FallingBack -> Relay             state erased and prerequisites remain available
FallingBack -> Unavailable       state erased and a prerequisite is unavailable
FallingBack -> Disabled          state erased and feature or generation is stopped
Relay -> Failed                  attempt error recorded while relay remains healthy
Failed -> Eligible               a fresh authenticated offer becomes eligible
Relay/Failed/Unavailable -> Disabled   feature disabled or generation stops
Disabled/Relay/Failed -> Unavailable   exporter or platform prerequisite absent
Eligible/Probing/Direct/Suspect -> FallingBack
                                      feature, generation, or prerequisite revoked
```

The relay forwarding path stays active through `Eligible`, `Probing`,
`Suspect`, `FallingBack`, and `Failed`. A coordinator may suppress duplicate
delivery while Direct is healthy, but it cannot dispose the relay session.
After authenticating a peer Probe and producing its ACK, `Probing` may accept
authenticated inbound data from that exact peer endpoint; it must not send
direct data or suppress outbound relay delivery until its own Probe ACK is
authenticated and the state reaches `Direct`.
Direct data is scoped to the authenticated IPv4 virtual-peer pair. Traffic for
other destinations, including Internet and IPv6 traffic, continues over relay
and does not trigger `FallingBack`.
Every transition that destroys an active attempt passes through `FallingBack`,
which closes the UDP socket and erases direct keys, tokens, endpoint bindings,
timers, and replay state before publishing `Relay`, `Unavailable`, or
`Disabled`. `Direct -> Suspect` is a recovery transition that retains this
material temporarily; it must enter `FallingBack` if recovery does not
authenticate in time.

## Generation And Teardown

P2P state is owned by the current runtime generation. Completions from older
generations are ignored. Stop prevents new probes, cancels timers, closes the
protected UDP socket, erases keys/tokens/replay state, publishes `relay`, and
then participates in the normal runtime teardown. Repeated stop is idempotent.

Process restart always begins at `Disabled`, `Unavailable`, or `Relay`; it never
restores `Direct`. UI consumers render snapshots and do not infer a direct path
from socket callbacks, offers, or traffic counters.

The packet authentication rules are in the [protocol](protocol.md), with abuse
cases in the [threat model](threat-model.md).
