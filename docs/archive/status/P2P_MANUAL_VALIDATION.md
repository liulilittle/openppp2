# P2P Networking — Manual Validation Scenarios
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle, Git history, and the latest main verification record, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.

**Status:** authenticated offer/data integration is implemented but production
direct mode remains fail-closed pending protocol approval and physical-network evidence.

**Last verified:** 2026-07-17, `main@5bcccce`.

This document describes manual test scenarios for validating the P2P direct-path
networking feature. Automated C++ and tooling tests cover protocol components and
production wiring; these scenarios remain the validation gate for real NAT,
backgrounding, roaming, and physical-device behavior.

---

## Integration Status

The production integration is intentionally guarded by:

```cpp
ProductionAuthenticatedControlV1Ready = false;
```

Consequently, `p2p.enabled=true` with `direct-preferred` currently evaluates to
`Unavailable`; clients do not register direct capability and the server does not
issue production offers. Raw TCP and plain WebSocket transports also remain
relay-only because their base `ITransmission` has no authenticated exporter.
The existing `DoNat()` relay path remains authoritative.

The following integration is already wired behind that gate:

1. **Authenticated exporter:** SSL WebSocket transmissions implement the
   asynchronous session-key exporter. Server and client offer paths require it;
   unauthenticated transports fail closed.
2. **Authenticated offer/ACK:** the server creates paired `offer-v1` envelopes;
   the client verifies the offer, sends an authenticated probe, and cannot
   activate the direct path before an authenticated ACK.
3. **Direct data/fallback:** `P2PDirectDataPath` owns sequencing, replay checks,
   peer/generation policy, send/open, timeout, socket-error fallback, and relay
   fallback. Accepted inbound frames re-enter the existing NAT forwarding path.
4. **Platform datagram ownership:** Android uses the VPN socket-protection bridge;
   iOS uses a Packet Tunnel provider-owned UDP session.
5. **Runtime projection:** requested capability, effective P2P state, network
   state, and fallback reason reach the runtime snapshot.

Remaining enablement work is evidence-driven: approve authenticated control v1
and complete the physical device/NAT matrix below. The production gate must not
be changed until those checks pass.

## Automated Evidence

- C++ tests cover capability gating, key derivation, offer/token binding,
  authenticated control ACK, data AEAD/replay, direct activation/fallback,
  channel lifecycle, datagram transport, and NAT classification.
- `tests/tooling/test_p2p_capability_wiring.py` checks the production exporter,
  offer/data wiring, relay fallback, Android protection, iOS provider transport,
  and the fail-closed production gate.
- Android API 34 x86-64 instrumentation uses a real UDP descriptor and an
  established `VpnService` TUN. It verifies protect failure before activation,
  success while the VPN is active, and readiness cleanup after teardown.
  GitHub Actions run [29526592987](https://github.com/Miaocchi/openppp2/actions/runs/29526592987)
  completed successfully at `ef97c8c`.
- The same `ef97c8c` main SHA completed all nine repository workflows.

The emulator result proves the JNI/VPN protection path, not full P2P traffic or
physical device behavior. Android/iOS backgrounding, UDP-blocked networks,
full-cone and symmetric NAT, rebind, restart, and forced relay fallback still
require the scenarios below.

## NAT Classifier Behavior (H2)

The server-side NAT classifier (`P2PNatClassifier`) is designed to infer
UDP NAT types from actual relay traffic patterns.  It requires observations
from real UDP relay paths (static-echo, UDP sendto).  TCP control channel
endpoints are intentionally NOT used because they reflect TCP NAT mapping,
which does not predict UDP NAT behavior.

**Current state:** Authenticated StaticEcho ingress is wired as a UDP
observation source. Before recording an endpoint, the switcher verifies that
the virtual source IP belongs to the sending connection in the authoritative
NAT table. Valid source endpoints are deduplicated, stored on the registered
peer, and included in later offer candidates. TCP control endpoints remain
excluded.

A single observed UDP mapping remains `Unknown`. The classifier requires
observations through at least two distinct outer UDP destinations before it
infers endpoint-independent or symmetric mapping behavior. The inner
application destination is deliberately not counted because it does not affect
the outer NAT mapping. Production offers remain suppressed by the capability
gate described above.

**Conservative behavior:**
- `Unknown` → probing is allowed (server sends offers, clients attempt
  hole-punching; the probe path itself determines reachability).
- `Symmetric + Symmetric` → skip (only when both are positively classified
  from actual observations).
- `UdpBlocked` → skip (only when positively classified).
- `Unknown + Unknown` → allow (conservative: let probes decide).

Once the production gate is enabled, this ensures that the classifier never
blocks P2P attempts based on absence of data — only based on positively observed
incompatibility.

---

## Scenario 1: Relay Baseline (p2p.enabled=false)

**Goal:** Verify that disabling P2P produces byte-identical behavior to the current release.

**Setup:**
```json
{
  "p2p": {
    "enabled": false
  }
}
```

**Steps:**
1. Start server with `p2p.enabled=false`.
2. Connect two clients.
3. Send ping between clients via virtual subnet.
4. Verify NAT relay forwarding works.

**Expected:** All traffic flows through server relay. No P2P control messages in INFO. No UDP sockets created for P2P.

---

## Scenario 2: Direct LAN Success (<200ms)

**Goal:** Two clients on the same LAN establish direct path within 200ms.

**Setup:**
```json
{
  "p2p": {
    "enabled": true,
    "mode": "direct-preferred"
  }
}
```

Both clients on the same subnet (e.g., 192.168.1.x).

**Steps:**
1. Connect both clients to the server.
2. Observe P2P registration in server logs.
3. Trigger NAT traffic between clients.
4. Observe P2P offer with LAN candidates.
5. Observe state transition: Relay → Probing → Direct.

**Expected:**
- Server sends offer with LAN candidate (observed endpoint source = "observed").
- Client sends probes to LAN endpoint.
- First ACK received within ~50ms.
- State transitions to Direct.
- Subsequent data packets use Tier 2 minimal header (16 + 16 = 32 bytes overhead).

---

## Scenario 3: Full-Cone NAT Direct Success (<500ms)

**Goal:** Both clients behind full-cone NAT establish direct path.

**Setup:** Both clients behind different full-cone NATs.

**Steps:**
1. Connect both clients.
2. Server classifies NAT type as FullCone from relay traffic.
3. Server sends offer with observed endpoints.
4. Clients probe each other's observed endpoints.
5. First ACK wins.

**Expected:**
- NAT classification: FullCone (consistent IP:port).
- Single probe sufficient.
- Direct path established within 500ms.

---

## Scenario 4: Symmetric NAT Fallback (0ms, no attempt)

**Goal:** Skip hole punching for symmetric-symmetric NAT pair.

**Setup:** Both clients behind symmetric NAT (varies IP:port per destination).

**Steps:**
1. Connect both clients.
2. Generate relay traffic to classify NAT types.
3. Server classifies both as Symmetric.
4. Observe that OfferP2PPeerHints returns false.

**Expected:**
- NAT classification: Symmetric for both.
- `ShouldAttemptPunch()` returns false.
- Server log: "NAT classification skip offer ... Symmetric"
- No P2P offer sent. Traffic continues via relay with zero added latency.

---

## Scenario 5: Stale/Forged Token Rejection

**Goal:** Verify that packets with invalid tokens are rejected.

**Steps:**
1. Establish a direct P2P channel.
2. Manually send a Tier 1 packet with a corrupted token.
3. Observe that the packet is silently dropped.

**Expected:**
- Token verification fails (constant-time comparison mismatch).
- Packet is dropped without response.
- No state change on the receiving peer.

---

## Scenario 6: Replay Packet Rejection

**Goal:** Verify that replayed packets are dropped by the bitmap replay window.

**Steps:**
1. Establish a direct P2P channel.
2. Capture a valid Tier 2 data packet.
3. Replay the same packet.
4. Observe that the replayed packet is silently dropped.

**Expected:**
- First packet: accepted (replay_window_.Accept returns true).
- Second packet (same sequence): IsDuplicate returns true.
- Replayed packet is dropped.

---

## Scenario 7: Direct → Suspect → Relay Fallback (4s worst case)

**Goal:** Verify the worst-case failure detection time.

**Setup:** Use default timers: heartbeat_interval=1000ms, miss_max=2, suspect_timeout=2000ms.

**Steps:**
1. Establish a direct P2P channel.
2. Simulate peer loss (e.g., disconnect peer's network).
3. Measure time from last successful heartbeat to relay fallback.

**Expected:**
- Heartbeat miss detected after 2 × 1000ms = 2000ms.
- State: Direct → Suspect.
- Suspect timeout after 2000ms.
- State: Suspect → Relay.
- Total: 4000ms worst case.

---

## Scenario 8: NAT Rebind Migration (5s grace)

**Goal:** Verify connection migration on NAT rebind.

**Steps:**
1. Establish a direct P2P channel.
2. Trigger NAT rebind (e.g., WiFi→cellular handoff).
3. Peer receives packet from new source endpoint.
4. Peer sends challenge to new endpoint.
5. Challenge is ACKed within grace period.

**Expected:**
- Peer endpoint updated to new source.
- No data loss during migration.
- Migration completes within 5s grace period.

---

## Scenario 9: Zero-RTT Reconnect

**Goal:** Verify cached session reconnect.

**Steps:**
1. Establish a direct P2P channel.
2. Briefly disconnect (WiFi flap).
3. Client reconnects and sends first data packet using cached key.
4. Peer accepts (valid auth tag, sequence within window).

**Expected:**
- Direct channel resumes within 1 RTT.
- No server round-trip needed.
- Cache expires after 300s.

---

## Scenario 10: Coalesced Packet Demux

**Goal:** Verify coalesced Ethernet frames are correctly demuxed.

**Steps:**
1. Send 3 small Ethernet frames rapidly.
2. Observe that they are coalesced into 1 UDP datagram.
3. Verify all 3 frames are demuxed and injected on the receiving side.

**Expected:**
- 1 `sendto()` call instead of 3.
- All 3 frames delivered to the virtual Ethernet adapter.
- No frame loss or corruption.

---

## Scenario 11: Heartbeat Piggyback

**Goal:** Verify heartbeat ACK is piggybacked on data packets.

**Steps:**
1. Establish direct channel with active data flow.
2. Observe that dedicated heartbeat packets are NOT sent during active transfers.
3. Observe that HEARTBEAT_ACK is set on data packets when requested.

**Expected:**
- During idle: 1 heartbeat/s.
- During active: 0 dedicated heartbeats (piggybacked).
- Heartbeat overhead: zero when data is flowing.

---

## Scenario 12: Buffer Pool Zero-Allocation

**Goal:** Verify no malloc/free on the steady-state hot path.

**Steps:**
1. Establish direct channel.
2. Send 1000 packets.
3. Monitor heap allocation count (e.g., via jemalloc stats).

**Expected:**
- Pool pre-allocates 64 × 2048B = 128KB per channel.
- Hot path: zero malloc/free calls.
- Fallback allocation: only when pool exhausted.

---

## Build Verification Notes

Automated verification must include:

1. `python tests/tooling/test_p2p_capability_wiring.py`.
2. The C++ P2P targets in `tests/cpp/CMakeLists.txt`.
3. Android API 34 `connectedDebugAndroidTest` for socket protection.
4. Repository main-branch CI across all nine workflows.

Manual validation must still verify that `p2p.enabled=false` preserves relay
behavior and must execute Scenarios 2–12 on the stated physical/NAT environments
before changing `ProductionAuthenticatedControlV1Ready`.
