# P2P Direct Channel State Machine

> **Purpose:** Define P2P direct-channel states, transitions, and failure behavior.
> **Audience:** Protocol, networking, and platform maintainers.
> **Status:** Current production state machine; cross-platform runtime acceptance remains incomplete.
> **Last verified against:** P2P v2 isolated tests and production capability wiring, 2026-10-07.
> **Parent index:** [Design Documents](../README.md)

> Status: Implemented; production entry wired
> Type: Design
> Last verified: 2026-10-07; isolated implementation acceptance and production gate wiring.

The v2 implementation is wired into the production client and server source.
The capability gate defaults to enabled in `ppp/p2p/P2PCapabilityGate.h` and is
explicitly injected by each production build system. The sixteen-context cap is
in `ppp/app/client/VEthernetExchanger.h`; queueing and recovery are in
`ppp/app/client/VEthernetP2PV2.cpp`.

## States

The direct-channel design reserves these stable values. The implementation
is capability-gated at runtime and fails back to relay on any failed transition;
isolated v2 tests do not establish cross-platform device availability.

| State | Meaning | Effective path |
|---|---|---|
| `Disabled` | Experimental configuration is off | `relay` |
| `Unavailable` | Exporter, peer capability, or platform protection is absent | `relay` |
| `Relay` | Base tunnel is healthy; no direct attempt is active | `relay` |
| `Eligible` | Both peers and local policy permit a bounded attempt | `relay` |
| `Probing` | Authenticated probes are in flight | `relay` |
| `Direct` | v1 authenticated probe ACK, or v2 bilateral Ready and Commit confirmation | `direct` |
| `Suspect` | Direct liveness is uncertain | `relay` |
| `FallingBack` | Direct state is being discarded | `relay` |
| `Failed` | Target state for a recorded failed attempt; relay remains healthy | `relay` |

`effective_path` has only `relay` or `direct`. `Direct` is the only state that
may publish `direct`. P2P failure does not change a healthy base runtime phase
from `Connected`.

For v2 these states belong to each virtual IPv4 peer context, with at most
sixteen contexts per client. The aggregate runtime state is `Direct` when
any peer is Direct, otherwise `Probing` when any peer is Probing, otherwise
`Relay`. Aggregate Direct does not authorize direct delivery to other peers:
outbound traffic selects its destination VIP context and falls back to relay
unless that peer is Direct. Keys, probes, liveness and renew/report timers are
independent; protected UDP, STUN, candidate history and socket recovery are
shared. A shared socket failure resets all peer direct state.
Known peer control admission and egress budgets are also independent; unknown
sources remain subject to shared admission. Exhausting one peer's control
budget does not consume another peer's reserved budget.

## Target Transitions

For v2, an ACK alone does not establish Direct. Both sides prime candidate
pairs, the initiator nominates with Commit, and bilateral Ready plus
CommitACK (or matching new-key data) authorizes promotion. Responder ACKs
before Commit only cache transactions. Healthy current data remains usable
while pending probes run. Pending failure before Commit preserves current;
an uncertain committed transaction falls back by its ten-second deadline.
Previous receives for at most five seconds and never extends current liveness.
The client/server wiring publishes the channel state without changing the
healthy base relay phase, and continues FRP and relay maintenance in v2 and
socket recovery branches. Production remains gated off.

```text
Disabled -> Relay                 experimental flag enabled
Relay -> Unavailable             eligibility prerequisite missing
Unavailable -> Relay             prerequisites recover; no valid offer yet
Unavailable -> Eligible          prerequisites recover with a valid fresh offer
Relay -> Eligible                exporter, peer capability, policy, protection ready
Eligible -> Probing              valid unexpired relay offer accepted
Probing -> Direct                v1 authenticated probe ACK; v2 bilateral Ready and Commit confirmed
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
For v1, after authenticating a peer Probe and producing its ACK, `Probing` may accept
authenticated inbound data from that exact peer endpoint; it must not send
direct data or suppress outbound relay delivery until its own Probe ACK is
authenticated and the state reaches `Direct`.
For v2, pending-key application data is not delivered before promotion.
Authenticated pending-key data confirms a lost CommitACK only when its
offer, epoch, hashes and nominated pair match the committed transaction and
bilateral Ready is complete. A cached responder ProbeACK does not nominate a
pair or permit application delivery.
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
