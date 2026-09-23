# ADR 0002: Gate P2P Direct Channels on an Authenticated Session Exporter

> **Purpose:** Record the durable security boundary for P2P direct channels.
> **Audience:** Protocol, security, and platform maintainers.
> **Status:** Current architecture decision.
> **Last verified against:** Exchanger/switcher wiring + production gate, 2026-07-22.
> **Parent index:** [Architecture Decision Records](README.md) · **Chinese:** [ADR 0002](0002-p2p-direct-channel-security_CN.md)

> Status: Accepted
> Type: ADR
> Last verified: 8c8a888

## Context

P2P direct-channel types (offer session, control datagrams, direct data path,
replay helpers) are integrated into `VEthernetExchanger` and
`VirtualEthernetSwitcher`, but production authenticated control remains
**fail-closed** (`ProductionAuthenticatedControlV1Ready = false` in
`P2PCapabilityGate.h`). `ITransmission` now defines an authenticated
session-exporter boundary, and authenticated TLS WebSocket implements it after
the application handshake through the standard TLS exporter. This does not
enable direct P2P: the final production-control gate remains false. Raw TCP,
plaintext WebSocket, and any transport without an available exporter remain
ineligible.

Enabling a direct UDP path with keys derived from configuration secrets,
unauthenticated control messages, or a raw TCP session would create a second
channel that is not cryptographically bound to the authenticated relay session.

## Decision

P2P capability is false by default. An experimental direct attempt is eligible
only when the final authenticated-control gate is explicitly enabled and its
transport supplies an authenticated, per-session exporter through an explicit
transport-independent interface. The exporter must be available only after the
relay handshake succeeds and must bind the authenticated peer, relay session
identifier, negotiated protocol version, and a fresh connection epoch.

The two clients do not share a TLS exporter. After both relay sessions qualify,
the server generates a fresh random pair seed. It derives a different wrapping
key from each client's session exporter and sends the same pair seed to each
client in a separately authenticated and encrypted relay offer. Direct-channel
keys are derived from the pair seed, not directly from either TLS exporter. The
pair seed is scoped to the two peer identities, both relay session identifiers,
the offer, version, and connection epoch. It is never sent in plaintext or
reused across offers.

Authenticated TLS WebSocket implements this interface with the standard TLS
exporter after certificate and application authentication complete. Raw TCP,
plaintext WebSocket, TLS implementations without an exposed exporter, and any
exporter failure are relay-only. The offer-v1 path must not read or assume access
to a TLS master secret. A compiled legacy P2P helper still has a
`tls_master_secret` input; it is outside offer-v1 and must not be used to
satisfy this decision.

The server may coordinate candidates and issue bounded offers, but it cannot
override exporter eligibility. Both peers must authenticate a protected UDP
probe and acknowledgment before either reports or forwards on `direct`.
Probing, suspect recovery, and fallback retain the relay data path.

The wire and lifecycle requirements are defined in the
[protocol](../design/p2p-direct-channel/protocol.md),
[state machine](../design/p2p-direct-channel/state-machine.md), and
[threat model](../design/p2p-direct-channel/threat-model.md).

## Alternatives

- Derive from configured protocol or transport keys: rejected because those
  keys are deployment-wide and do not bind a direct channel to one authenticated
  relay session.
- Pass a TLS master secret into P2P: rejected because raw TCP has no such value,
  exposing it expands the trust boundary, and a standard exporter is the correct
  TLS interface.
- Enable direct mode from a server token alone: rejected because a bearer token
  does not prove both endpoints possess session-bound key material.
- Disable P2P permanently: safe, but it prevents a future authenticated direct
  path. The exporter gate preserves relay safety while allowing incremental work.

## Consequences

- Existing deployments and wire formats remain compatible and relay-only.
- The current P2P scaffold is not production evidence and must stay unreachable
  until coordinator, authenticated-control capability, and platform gates are
  complete.
- Authenticated TLS WebSocket exporter support exists, but it does not by itself
  satisfy those gates. Supporting raw TCP would require a separately accepted
  authenticated key agreement; it is not part of this decision.
- Failure, timeout, downgrade, restart, or unsupported peers never tear down the
  base VPN session.
