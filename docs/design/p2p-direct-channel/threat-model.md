# P2P Direct Channel Threat Model

> **Purpose:** Define threats and required controls for P2P direct channels.
> **Audience:** Security, protocol, and platform maintainers.
> **Status:** Current design evidence; not an enabled production data path.
> **Last verified against:** P2P integration and fail-closed production capability gate, 2026-07-22.
> **Parent index:** [Design Documents](../README.md)

> Status: Draft
> Type: Design
> Last verified: 8c8a888

## Assets And Trust Boundaries

Protected assets are relay availability, peer identity, Ethernet payloads,
session exporter material, derived keys, offer tokens, endpoint bindings, and
replay state. The network, NAT mappings, candidate addresses, and unsolicited
UDP packets are untrusted. The authenticated relay session coordinates offers
but direct peers still authenticate every UDP control and data packet.

Compromise of a client endpoint or relay server is outside protection for that
active session. The design still limits cross-session token reuse and prevents
one compromised session from deriving another session's direct keys.

## Threats And Controls

> **Implementation boundary:** This table states controls required before any production enablement. The current P2P path remains fail-closed; the table is not proof that every listed control—especially per-source and per-session rate limiting—is enforced today.

| Threat | Required control | Failure behavior |
|---|---|---|
| Raw TCP or plaintext session claims P2P | Require an authenticated exporter and final production capability gate | Relay-only |
| Version downgrade | Authenticate version and required features; never negotiate an unbound v0 | Relay-only |
| Stolen or replayed offer token | Bind token to peers, both sessions, epoch, direction, candidates, offer and bounded receipt TTL | Drop silently |
| Packet replay or uint32 ambiguity | Directional key, nonce uniqueness, 1024-bit window, half-range rejection | Drop packet; fall back on exhaustion |
| Endpoint spoofing | Authenticate candidate pair and challenge any migration endpoint | Keep relay; reject migration |
| Reflection | Do not answer invalid tokens; ACK no larger than authenticated request | Drop and rate limit |
| Amplification or probe flood | Candidate/round caps; source 4/s burst 8; session 8/s burst 16 | Suppress probes; keep relay |
| One relay exporter used as a peer secret | Server wraps one fresh pair seed separately under each session exporter | Fail offer setup |
| Cross-direction nonce reuse | Independent directional keys and nonce salts | Fail channel setup |
| Old process state reused | Fresh epoch; erase keys/tokens/replay on stop and restart | Relay-only until new offer |
| UDP blocked or symmetric NAT | Bounded probing and timeout | Relay fallback |
| Socket enters VPN route | Protect before first probe; fail closed if protection fails | Relay-only |
| UI reports success early | Publish `direct` only after authenticated ACK | Continue to show relay |
| Direct path failure tears down VPN | Relay is an invariant independent of P2P state | Base runtime stays Connected |

## Adversarial Tests Required Before Enablement

- expired, wrong-peer, wrong-session, wrong-direction, wrong-candidate, and
  old-epoch tokens;
- duplicate, stale, far-ahead, wrap-boundary, and half-range sequences;
- malformed lengths, reserved bits, unknown versions, and parser truncation;
- spoofed endpoints and migration challenges from old and new addresses;
- reflection and amplification ratios under invalid probe floods;
- per-source and per-session rate-limit isolation;
- UDP blocked, symmetric NAT, socket protection failure, and process restart;
- relay continuity through Probing, Suspect, FallingBack, and Failed;
- Android `VpnService.protect`, iOS packet-tunnel routing, and Linux policy
  routing before the first send.

ASan/UBSan must cover parsers, replay, token validation, state transitions, and
100-cycle start/fallback/stop. Platform evidence is required before the
experimental capability can be enabled outside tests.

See the [protocol](protocol.md), [state machine](state-machine.md), and accepted
[ADR](../../adr/0002-p2p-direct-channel-security.md).
