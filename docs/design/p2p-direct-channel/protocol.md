# P2P Direct Channel Protocol

> **Purpose:** Define the authenticated P2P direct-channel wire protocol.
> **Audience:** Protocol, networking, and security maintainers.
> **Status:** Current production protocol; cross-platform runtime acceptance remains incomplete.
> **Last verified against:** P2P v2 isolated tests and production capability wiring, 2026-10-07.
> **Parent index:** [Design Documents](../README.md)

> Status: Implemented; production entry wired
> Type: Design
> Last verified: 2026-10-07; isolated implementation acceptance and production gate wiring.

## Scope And Eligibility

This document specifies the authenticated protected UDP channel used by the
production v2 path. The relay path remains authoritative whenever capability
negotiation, socket protection, authentication, or probing fails.

The v2 implementation is wired into the production client and server source.
`ppp/p2p/P2PCapabilityGate.h` defaults to enabled and each production build
system injects `OPENPPP2_P2P_V2_PRODUCTION=1`; the server v2 offer path in
`ppp/app/server/VirtualEthernetP2PV2.cpp` checks it before creating offers.
Set `ENABLE_P2P_V2_PRODUCTION=OFF` only for an emergency build rollback.

A peer advertises `p2p.direct.v1` only when all of these are true:

- the experimental configuration flag is enabled;
- the authenticated relay session exposes a session exporter;
- socket protection is available for the platform;
- the final authenticated-control production gate is enabled by default through
  `ENABLE_P2P_V2_PRODUCTION`;
- the peer implements this version and its required cipher and parser rules.

Missing capability, missing exporter, a disabled production gate, raw TCP,
plaintext WebSocket, exporter failure, or policy denial means relay-only. An old
peer ignores the optional capability and offer fields. No downgrade can enable
an older or unbound direct protocol.

## Version And Messages

### Version 2 Isolation Implementation

Version 2 is explicitly negotiated through INFO `supported-versions` and
`offer-v2`; a selected v2 session cannot fall back to the v1 wire protocol.
The production gate is `ProductionAuthenticatedControlV1Ready = true` in release
builds. A build may set `ENABLE_P2P_V2_PRODUCTION=OFF` for emergency rollback;
runtime `p2p.enabled=false` still selects relay mode.
The v1 layout and TTL semantics below remain unchanged.

The v2 common offer is 193 bytes, the recipient encoding 270 bytes, and the
typed exporter context 145 bytes (v1 remains 113). Independent exporter,
HKDF, HMAC and AEAD domains bind identities, sessions, epoch, key generation,
predecessor hash and both frozen candidate revisions. Revisions are nonzero
uint64 decimal strings with no leading zero. Each peer advertises at most two
canonical IPv4 endpoints: host and STUN from the same protected transport.
The relay's observed endpoint is excluded. Latest registration changes do
not rewrite active or pending snapshots.

The client holds at most sixteen peer contexts keyed by virtual IPv4 address.
Each peer has independent channel keys, probes, liveness and renew/report
timers. All peers share one protected UDP transport, STUN gatherer, local
candidate revision history and socket recovery. STUN maintenance retries
gathering every fifteen seconds without rewriting frozen peer snapshots.
Server status replies echo the peer virtual IPv4 address so key-active
confirmation is applied to the corresponding context.

`p2p.stun.request-profile` defaults to `standard`, a 20-byte Binding Request.
Explicit `tailnode` selects a 40-byte request with SOFTWARE `tailnode` and a
CRC32 FINGERPRINT for Tailscale STUN compatibility. Configuration trims and
lowercases this value; unknown values normalize to `standard`. SOFTWARE and
FINGERPRINT provide compatibility and packet integrity checking, not an
authenticated identity or permission to enable direct traffic.

Both peers prime all four candidate pairs simultaneously. Each authenticated
Probe has one original transmission and one identical-byte retry after two
seconds, within a four-second probe window. Only the stable initiator
nominates the first authenticated ACK pair. The responder caches ACKs until
Commit and only promotes after bilateral Ready on the chosen pair. Commit
also has at most two transmissions, two seconds apart. Probe/ACK are 158
bytes, Commit/ACK 190 bytes, and migration challenge/ACK 126 bytes. A delayed
CommitACK answers the cached authenticated Commit, even when a ProbeACK is
the last received packet.

Setup ends ten seconds after first receipt; keys expire sixty seconds after
first receipt and request refresh at forty seconds. Duplicate offers and
retransmissions cannot move these deadlines. At most current, pending and
previous slots exist, with independent sequences and replay windows.
Previous is receive-only until the earlier of promotion plus five seconds
and its original expiry. Matching authenticated new-key data can replace a
lost CommitACK only after bilateral Ready. Sequence exhaustion forbids reuse;
refresh starts at `UINT32_MAX-4096`, and v2 RX rejects sequence wrap. An
authenticated numerically larger sequence remains valid even when it advances
by more than half the uint32 range; it discards older replay-window entries
without resetting the sender's key or counter. Failed authentication never
commits the proposed receive-window change. Older out-of-window packets and
duplicates remain rejected.

Source and session control buckets are 4/s burst 8 and 8/s burst 16, with
256 entries per table and sixty-second idle reclamation. A known offer hash
and matching registered/selected peer endpoint select that peer's independent
ingress buckets; this routing check does not replace packet authentication.
Unknown sources and STUN share the client-level admission budget. Peer control
egress has an independent 8/s burst 16 session bucket per context, bounded by
the sixteen-peer context cap. STUN-shaped packets
also pass admission before copying or posting. Selected-path data is exempt
from control rate limits. New endpoints must pass noncommitting AEAD/replay
validation before one bounded migration challenge; migration and Commit are
serialized. Application data is limited to the registered virtual IPv4 peer
pair; Internet and IPv6 traffic remain on relay.

The client keeps a per-peer queue of at most 32 distinct deferred control
datagrams, deduplicated by destination and bytes. Expiry is bounded by two
seconds and the applicable offer/key deadline. Queue overflow or expiry
cancels probing and clears queued output; an uncommitted refresh preserves a
healthy current key. A transport send failure resets direct state and starts
shared socket recovery. This queue behavior is isolated implementation
evidence from `ppp/app/client/VEthernetP2PV2.cpp`, not evidence that the
production path is enabled.

The server merges renew requests and accepts idempotent bilateral key-active
reports. Exporter generation has a ten-second bound; pending coordination is
retained for at most sixty seconds after generation, independently of client
setup. Lost-current zero-predecessor recovery waits for the server's
conservative old-key deadline. Socket failures close and clear direct state
immediately, then rebuild with 1/2/4/8/10-second backoff. These rules have
isolated tests. A root-linked test additionally runs the actual Exchanger
recovery implementation: nine cases passed in normal, ASan/UBSan/LSan and
separate TSan builds. Registration, transport and relay output are injected
dependencies. Real INFO delivery, native socket protection, real NAT and
device transitions still require additional acceptance; capability or probe
failure keeps the production runtime on relay.

Version 1 uses a versioned relay offer plus protected UDP control and data
messages. Every parsed message is length checked before field access. Reserved
bits and nonzero reserved bytes are rejected.

The relay offer has a common canonical transcript:

```text
version, offer_id, initiator_relay_session_id, responder_relay_session_id,
initiator_peer_id, responder_peer_id, connection_epoch, ttl_seconds, cipher,
candidate_set_hash
```

Each recipient also receives a separate envelope containing `recipient_peer_id`,
`wrap_nonce`, and `wrapped_pair_seed`. The envelope is authenticated with the
common transcript hash as AEAD additional data. It is not part of the common
transcript used by direct-channel tokens.

Version 1 canonical encoding uses network byte order and fixed widths:

```text
version u8 (1), offer_id 16B, initiator_session_id 16B,
responder_session_id 16B, initiator_peer_id 16B, responder_peer_id 16B,
connection_epoch 16B, ttl_seconds u8, cipher u8 (1),
candidate_set_hash 32B
```

Peer and session order is always initiator then responder as assigned by the
authenticated relay offer. Candidate entries are encoded as address-family u8,
IPv4-mapped IPv6 address 16B, and port u16 big-endian, sorted bytewise before
SHA-256. Variable-length text is never part of a version 1 transcript.

UDP control messages are `PROBE`, `PROBE_ACK`, `MIGRATE_CHALLENGE`, and
`MIGRATE_ACK`. Data messages are accepted only after a valid `PROBE_ACK` for the
same offer, epoch, direction, and endpoint pair. Unknown versions or required
features produce a local relay fallback; no negative response is sent to an
unauthenticated source.

The offer-v1 data codec uses this fixed authenticated header. The entire header
is AEAD additional data, followed by `payload_length` bytes of ciphertext and a
16-byte ChaCha20-Poly1305 tag:

```text
version u8 (1), type u8 (5), flags u8 (0), reserved u8 (0),
offer_hash 32B, sender_role u8, receiver_role u8,
direction u8 (equal to sender_role), reserved u8 (0),
connection_epoch 16B, sequence u32 big-endian,
payload_length u16 big-endian
```

Version 1 accepts payload lengths from 1 through 1514 bytes. The parser rejects
unknown flags, nonzero reserved bytes, role/direction mismatches, empty payloads,
length mismatches, trailing bytes, and oversized frames before returning data.
Control and data share one sequence and replay domain per direction. The same
protected UDP transport dispatches control types 1 through 4 and data type 5;
length alone never selects the parser. Data may be opened in `Probing` after the
session authenticated the peer Probe and produced its ACK, or in `Direct`; this
prevents the peer that receives the ACK first from losing its first direct
packet. Outbound direct sends and relay suppression remain forbidden until the
local Probe ACK is authenticated and the state reaches `Direct`. In either
state the observed sender must exactly match the authenticated peer candidate
for the current transport registration and runtime generation. The decrypted
payload must also be IPv4 and match the authenticated virtual-peer binding:
outbound packets require `src == virtual_ip` and `dst == peer_virtual_ip`, while
inbound packets require the reverse. Both fields use network byte order. IPv6,
Internet, malformed, and unrelated-peer traffic remains on relay without
tearing down a healthy Direct path. Authenticated matching plaintext then
passes through the existing inbound NAT policy before TAP output. A matching
direct send failure tears down the direct attempt and sends the current packet
through relay.

The codec, session-owned key boundary, protected transport, and TAP forwarding
are implemented. Release builds advertise the production capability by
default; incomplete cross-NAT or platform evidence does not disable the gate,
because capability, socket-protection, and probe failures fall back to relay.

`ttl_seconds` is an integer from 1 through 30. It is authenticated by the relay
offer. A client starts a local steady-clock deadline when the offer is received;
forwarding, retransmission, or wall-clock changes cannot extend it. Both relay
session identifiers and the connection epoch must match the current live
sessions, so an offer replayed after reconnect or restart is rejected.

## Key Schedule And Pair Seed Delivery

Each client-to-server transport provides different opaque exporter bytes using
the fixed label `EXPORTER-OPENPPP2-P2P-WRAP-v1` and this context:

```text
local_relay_session_id || ordered_peer_ids || both_relay_session_ids ||
connection_epoch || offer_id || version
```

The server generates a random 32-byte `pair_seed`. Let `offer_hash` be SHA-256 of
the canonical offer bytes. For each client, HKDF-SHA-256 uses the session
exporter as IKM, `offer_hash` as salt, and the ASCII info
`openppp2 p2p v1 wrap key` followed by recipient role byte (`0` initiator, `1`
responder) to derive a 32-byte wrapping key. The server generates a random
12-byte `wrap_nonce` and ChaCha20-Poly1305-wraps the same pair seed separately
for each client, using `offer_hash || recipient_peer_id` as AAD. Each client can
unwrap only its own copy. A wrapper cannot be moved between offers or peers.

Version 1 requires ChaCha20-Poly1305 with a 32-byte key, 12-byte nonce, and
16-byte tag. Cipher value `1` identifies it; other values are unsupported in
version 1. Direct keys use HKDF-Extract-SHA-256 with IKM `pair_seed` and salt
`offer_hash`. HKDF-Expand uses these exact ASCII info values and lengths:

```text
openppp2 p2p v1 initiator to responder key   -> 32B
openppp2 p2p v1 responder to initiator key   -> 32B
openppp2 p2p v1 initiator to responder nonce -> 8B
openppp2 p2p v1 responder to initiator nonce -> 8B
openppp2 p2p v1 offer token                  -> 32B
```

Direction is determined by stable ordered peer identifiers, not local role
names. Transmit and receive keys are never reused in the opposite direction.
Exporter bytes and derived keys are never serialized, logged, or placed in a
runtime snapshot.

## Nonces And Replay

The server assigns one random 128-bit connection epoch to the offer. Each
direction starts at sequence zero. HKDF produces a distinct 8-byte nonce prefix
for each direction. The 12-byte AEAD nonce is exactly:

```text
nonce_prefix[8] || sequence_uint32_big_endian[4]
```

The prefix is fixed for one direction, offer, and epoch. A key/epoch pair must
stop before sequence exhaustion; wrapping under the same key is forbidden and
triggers relay fallback followed by a new authenticated offer.

The receiver uses a 1024-packet replay bitmap with modular uint32 comparison.
Exactly half-range (`0x80000000`) ordering is ambiguous and rejected. Packets at
`window_size - 1` behind the base may be accepted once; packets at
`window_size` behind are stale. Restart discards keys, tokens, endpoints,
sequence counters, and replay state. Cached zero-RTT direct data is not allowed
in version 1.

## Offer Token And Candidate Binding

An offer token is an authentication tag, not a bearer authorization detached
from the relay session. It covers `offer_hash`, direction, and the canonical
candidate set, but not either recipient-specific wrapped-seed envelope. Its
authenticated `ttl_seconds` is at most 30 seconds,
measured by each recipient's local steady clock from receipt, and it never
outlives either relay session or the connection epoch. Tokens are single-offer
and cannot survive process restart.

Each probe authenticates:

```text
version, message_type, offer_id, both_relay_session_ids, sender_peer_id,
receiver_peer_id, direction, connection_epoch, source_candidate,
destination_candidate, sequence, nonce, ttl_seconds
```

Control headers use the fixed-width version 1 field encoding above. Their HMAC
input is a one-byte message type followed by `offer_hash`, sender role u8,
receiver role u8, direction u8, connection epoch 16B, canonical source candidate
19B, canonical destination candidate 19B, sequence u32 big-endian, nonce 12B,
and ttl_seconds u8. The 16-byte token is the first 16 bytes of HMAC-SHA-256.

The receiver validates the token, expiry, peer/session/direction bindings,
candidate membership, replay window, and endpoint before replying. A probe ACK
adds the observed endpoint pair and the probe transcript hash. Both sides enter
Direct only after validating the authenticated ACK.

## NAT Migration

Packets from a new endpoint never migrate a live channel by themselves. During
a migration grace period configured from 1 through 5000 ms, a valid packet may
start one bounded
challenge to the new endpoint while the old direct path and relay remain
available. Migration succeeds only after an authenticated challenge/ACK bound to
the offer, epoch, new endpoint pair, and fresh nonce. Failure returns to relay.

## Required Resource Limits Before Enablement

The following are design requirements for a future enabled direct channel. They
are not evidence that the current fail-closed receive path enforces every limit,
particularly the per-source and per-session rate limits.

- At most 4 candidates and 2 probe rounds per offer.
- At most one outstanding offer per peer pair and one migration challenge per
  channel.
- Before authentication work, each source IP is limited to 4 control packets per
  second with burst 8. Each authenticated relay session is limited to 8 control
  packets per second with burst 16. Configuration may lower but not raise these
  limits. Candidate and round caps still apply.
- An unauthenticated request receives no response larger than the request.
- Control packets are capped at the fixed protocol maximum; data and coalesced
  frames retain existing bounded parser limits.

The lifecycle and visible path rules are specified in the
[state machine](state-machine.md). Security rationale is in the
[threat model](threat-model.md) and governing
[ADR](../../adr/0002-p2p-direct-channel-security.md).
