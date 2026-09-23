# P2P Networking Plan
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


## Summary

OpenPPP2 already supports server-relayed virtual-subnet traffic via `LAN`/`NAT` and `server.subnet`. Add a direct-preferred P2P path on top of that baseline: clients keep using server relay by default, register P2P capability with the server, try UDP hole punching when both peers are eligible, and fall back to relay on any failure.

**Implementation status (2026-07-17):** authenticated offer/ACK, encrypted data,
fallback, runtime projection, Android socket protection, and iOS provider-owned
UDP transport are integrated behind a fail-closed capability gate. Production
direct mode remains disabled by `ProductionAuthenticatedControlV1Ready = false`
until authenticated control v1 is approved and the physical NAT/device matrix
passes. Android API 34 socket-protection evidence is green in Actions run
[29526592987](https://github.com/Miaocchi/openppp2/actions/runs/29526592987)
at `ef97c8c`; this does not constitute end-to-end direct-path evidence.

## Current Baseline

OpenPPP2 already has Phase 0 server-relay virtual networking. Clients announce their virtual IPv4 LAN with `PacketAction_LAN`, the server stores ownership in `VirtualEthernetSwitcher::nats_`, and `VirtualEthernetExchanger::ForwardNatPacketToDestination()` relays `PacketAction_NAT` frames between clients when `server.subnet` is enabled.

## Implemented Behind The Gate

- Added `p2p` configuration with `enabled`, `mode`, `punch-timeout`, `keep-alived`, and `stun.servers`.
- Extended the `INFO` JSON envelope with a `p2p` control message instead of reusing `LAN` in the client direction.
- Eligible clients register P2P intent after the existing LAN announcement and IPv4/IPv6 request flow.
- The C++ server records peer virtual IPs, client mode, client candidates, and a coordinator-observed endpoint.
- When server-relayed NAT traffic identifies two P2P-capable peers, the server sends throttled `offer` hints to both clients while preserving the existing relay path.

---

## Performance-First Design Principles

All design decisions below are driven by a single question: **can we make the direct path faster, leaner, and more responsive?**

| Principle | Rationale |
|---|---|
| **Classify NAT from relay traffic** | Avoid a separate STUN round-trip; relay packet source IPs already reveal the NAT mapping |
| **Race candidates in parallel** | Send probes to all candidates simultaneously; first ACK wins |
| **Lean crypto with hardware offload** | ChaCha20-Poly1305 on ARM/mobile; AES-256-GCM on x86 with AES-NI |
| **Two-tier packet header** | 16 B for steady-state data vs 46 B for control; eliminate per-packet HMAC overhead |
| **Coalesce packets** | Batch multiple Ethernet frames into one UDP datagram to amortize syscall + encryption cost |
| **Bitmap replay window** | 2-byte header for 1024-packet window vs 128-byte set; cache-line friendly |
| **Pre-allocated buffer pools** | Zero allocation on fast path |
| **Tight timers** | Worst-case failure detection in 4 s, not 9 s |
| **Heartbeat piggyback** | Carry heartbeat ACK on data packets; no separate timer-driven empty packets |

---

## NAT Type Support Matrix

| NAT Type (local) | NAT Type (remote) | Expected Outcome | Time Budget |
|---|---|---|---|
| Full-cone | Any | Direct (single probe) | <500 ms |
| Restricted-cone | Full-cone / Restricted-cone | Direct (parallel probes) | <1.5 s |
| Port-restricted | Port-restricted | Direct (simultaneous-open) | <2 s |
| Symmetric | Symmetric | Immediate fallback to relay | 0 s (no attempt) |
| Any | UDP-blocked | Immediate fallback to relay | 0 s (no attempt) |
| LAN (same subnet) | LAN | Direct (LAN broadcast / mDNS) | <200 ms |

> **Optimization:** The server classifies both peers NAT types from observed relay traffic (source IP:port mapping patterns) **before** offering hints. No separate STUN round-trip is required in the common case. Symmetric-symmetric and UDP-blocked scenarios skip hole punching entirely.

### Early NAT Classification from Relay Traffic

The server observes the `source_ip:source_port` of relayed packets from each peer and classifies NAT type without requiring an explicit STUN probe:

| Observed Pattern | Inferred NAT Type |
|---|---|
| Consistent external IP:port across all destinations | Full-cone |
| External IP consistent, port varies by destination IP | Restricted-cone |
| External IP consistent, port varies by destination IP:port | Port-restricted |
| External IP:port changes per destination (randomized) | Symmetric |
| No UDP relay traffic observed within 5 s of session start | Assume UDP-blocked |

When classification confidence is low (<3 distinct relay destinations observed), the server MAY send a single STUN Binding Request via the relay to refine the classification. This is a background task and MUST NOT delay the hint offer.

---

## State Machine Details

```
              ┌──────────────────────────────────────────┐
              │                                          │
  ┌───────┐   │  ┌──────────┐   ACK rx    ┌──────────┐  │
  │ Relay ├───┼─►│ Probing  ├────────────►│  Direct  │  │
  └───┬───┘   │  └────┬─────┘             └────┬─────┘  │
      │       │       │ timeout/retry           │        │
      │       │       ▼                         │        │
      │       │  (retry ≤ N, else Relay)        │        │
      │       │                         heartbeat miss   │
      │       │                         or packet loss   │
      │       │                                 ▼        │
      │       │                           ┌──────────┐   │
      └───────┼───────────────────────────┤  Suspect  │  │
              │  recovery timeout expires  └────┬─────┘  │
              │                                │        │
              │           probe ACK received   │        │
              │◄────────────────────────────────┘        │
              └──────────────────────────────────────────┘
```

| Transition | Trigger | Action |
|---|---|---|
| Relay → Probing | Server offers hints with candidate list | Allocate UDP socket; call `protect(fd)`; send probes to **all** candidates in parallel (racing) |
| Probing → Direct | First probe ACK received from peer | Bind winning candidate; drop other probes; begin forwarding data |
| Probing → Relay | All probes timed out; retry count exceeded (`p2p.max_probes`, default **2**) or total timeout (`p2p.probe_timeout_ms`, default **2000** ms) | Tear down UDP socket; continue with relay |
| Direct → Suspect | `p2p.heartbeat_interval_ms` (default **1000** ms) missed × `p2p.heartbeat_miss_max` (default **2**) | Mark path suspect; send immediate probe |
| Suspect → Direct | Probe ACK received | Resume direct forwarding |
| Suspect → Relay | `p2p.suspect_timeout_ms` (default **2000** ms) elapsed without recovery | Tear down UDP socket; fall back to relay |

**Worst-case failure detection:** `heartbeat_interval_ms × heartbeat_miss_max + suspect_timeout_ms` = **1000×2 + 2000 = 4 s** (vs 9 s with previous defaults).

### Parallel Candidate Racing

When the server offers N candidates, the client sends a probe to **all** N simultaneously rather than trying them sequentially:

```
t=0ms:   send probe → candidate_A (LAN)
t=0ms:   send probe → candidate_B (public IP)
t=0ms:   send probe → candidate_C (STUN-derived)
t=45ms:  ACK from candidate_A → WINNER; cancel B, C
```

This collapses the best-case LAN detection to a single RTT (~1–50 ms on local network) and eliminates serial timeout penalties for unreachable candidates.

### Heartbeat Piggyback

Heartbeat probes MUST be piggybacked on data packets when data is flowing. A dedicated heartbeat packet is sent only when the channel is idle for `heartbeat_interval_ms`. This eliminates heartbeat overhead during active transfers.

**Protocol:** Each data packet carries a 1-byte `flags` field with bit 0 = `HEARTBEAT_REQ`, bit 1 = `HEARTBEAT_ACK`. When a peer receives `HEARTBEAT_REQ`, it sets `HEARTBEAT_ACK` on its next outgoing packet (data or heartbeat).

---

## P2P Packet Header — Two-Tier Design

### Tier 1: Control Packets (probes, heartbeats, token requests)

Full header — 46 bytes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Flags (1B)  |               Magic (0x50325031, 3B)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Session ID (16 bytes, full UUID)              |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Nonce (8B, monotonically increasing)      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Sequence (4B, per-channel)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Token (16B, HMAC-SHA256 truncated)                           |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Payload (encrypted or plaintext for probes) ...              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Auth Tag (16B)                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Tier 2: Data Packets (steady-state, after channel established)

Minimal header — **16 bytes**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Flags (1B)  |      Channel ID (1B)    |   Reserved (2B)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Sequence (4B, per-channel)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Nonce (8B, per-packet unique)             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Payload (encrypted Ethernet frame) ...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Auth Tag (16B)                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total overhead: 16 (header) + 16 (auth tag) = 32 bytes per data packet** (vs 46+16 = 62 bytes with single-tier design). Saves **30 bytes per packet** in steady state.

The receiver maintains a `channel_id → (session_key, session_id)` lookup table. The 1-byte `channel_id` (assigned by the server in the hint offer) replaces the 16-byte session ID for demux.

### Flags Byte Layout

```
Bit 0: HEARTBEAT_REQ
Bit 1: HEARTBEAT_ACK
Bit 2: TIER (0 = minimal data header, 1 = full control header)
Bit 3: COALESCED (payload contains multiple length-prefixed frames)
Bit 4-7: Reserved
```

### Packet Coalescing

When `COALESCED` flag is set, the payload contains multiple Ethernet frames, each prefixed with a 2-byte length:

```
+--------+-------------------+--------+-------------------+-----
| Len(2B)| Frame 1 (N bytes) | Len(2B)| Frame 2 (M bytes) | ...
+--------+-------------------+--------+-------------------+-----
```

The receiver MUST demux frames by length prefix and inject each into the virtual Ethernet adapter independently.

**Coalescing policy:** If 2+ frames are queued within a 1 ms window, coalesce them into a single UDP datagram. This reduces the number of `sendto()` syscalls and amortizes encryption overhead across frames. On high-throughput paths, this can reduce syscall count by 3–5×.

**GRO/GSO on Linux:** On kernels ≥ 4.18, enable `UDP_GRO` (`setsockopt(fd, IPPROTO_UDP, UDP_GRO, &one, sizeof(one))`) on the receive side. The coalescing above mirrors GSO on the send side.

---

## Cipher Selection

| Platform | Cipher | Rationale |
|---|---|---|
| ARM / Android / iOS | **ChaCha20-Poly1305** (default) | 3–5× faster than AES-GCM without hardware AES; dominant cipher on mobile |
| x86 / x86_64 with AES-NI | **AES-256-GCM** | Hardware-accelerated; ~1 cycle/byte throughput |
| Fallback | ChaCha20-Poly1305 | Safe default on all platforms |

**Selection at channel setup:** Client advertises supported ciphers in the P2P INFO message. Server selects the optimal cipher and includes it in the hint offer. Both peers derive the session key via HKDF from the TLS handshake master secret.

### Key Derivation

```
session_key = HKDF-SHA256(
    ikm  = TLS_master_secret,
    salt = session_id || "p2p-v1",
    info = "direct-channel-key",
    len  = 32
)
token_key = HKDF-SHA256(
    ikm  = session_key,
    salt = "token-generation",
    info = "p2p-token",
    len  = 32
)
```

No additional key exchange is needed; keys are derived from the existing TLS session.

---

## Replay Protection — Bitmap Window

Replace the set-based replay window with a **compact bitmap**:

```
struct ReplayWindow {
    uint64_t base;          // Highest accepted sequence number
    uint8_t  bitmap[128];   // 128 bytes = 1024 bits, one per sequence
};
```

**Total: 136 bytes per channel** (vs ~8 KB for a hash-set of 1024 entries).

| Operation | Complexity | Description |
|---|---|---|
| Accept packet with seq `s` | O(1) | Set bit `base - s` in bitmap; advance `base` if `s > base` |
| Check duplicate | O(1) | Test bit `base - s`; drop if already set |
| Memory | 136 B fixed | No allocation; cache-line friendly |

**Cache optimization:** The bitmap fits in 2 cache lines. Hot path (check + set) touches at most 1 cache line.

---

## Buffer Pool & Zero-Allocation Fast Path

```
┌─────────────────────────────────────────────┐
│              PacketBufferPool               │
│  ┌─────┐ ┌─────┐ ┌─────┐     ┌─────┐      │
│  │Buf 0│ │Buf 1│ │Buf 2│ ... │Buf N│      │
│  └─────┘ └─────┘ └─────┘     └─────┘      │
│  Free list: atomic MPSC queue               │
│  Buffer size: 2048 B (fits typical frame)   │
│  Pool size: 64 buffers per channel          │
└─────────────────────────────────────────────┘
```

- **Allocate once** at channel creation (64 × 2048 B = 128 KB per channel).
- **Borrow** from free list on receive (lock-free `try_pop`).
- **Return** to free list after injection into the virtual Ethernet adapter.
- **Zero malloc/free** on the hot path during steady-state operation.

---

## Concurrency & Thread Safety

- The server-side `P2PPeerTable` (`p2p_peers_`) and `p2p_virtual_ips_` are already accessed from the exchanger coroutine context. All mutations MUST occur on the exchanger strand to avoid races.
- Client-side peer channels run on the client event loop. The state machine object MUST be `shared_ptr`-managed and capture a weak reference to the parent `VirtualEthernetExchanger` to handle teardown safely.
- The local UDP socket MUST be protected by a `std::atomic<bool> closed_` flag; all async read/write handlers MUST check this flag before proceeding.
- The buffer pool free list MUST use a lock-free MPSC queue (e.g., `moodycamel::ConcurrentQueue` or hand-rolled Michael-Scott queue) to avoid contention between the receive and inject paths.

---

## Connection Migration & NAT Rebind

When a NAT rebinding changes the peer external IP:port, the direct path SHOULD NOT drop if the peer is still reachable:

1. The receiver accepts probe/data packets from **any** source address for an established channel during a grace period (`p2p.migration_grace_ms`, default **5000** ms).
2. Upon receiving a packet from a new source, the receiver sends a challenge (random nonce) to the **new** source.
3. If the challenge is ACKed, the channel is migrated to the new endpoint.
4. If the challenge times out, the packet is dropped (possible spoofing).

This handles common scenarios like mobile network roaming, WiFi↔cellular handoff, and NAT table entry expiry.

---

## Zero-RTT Reconnection

When a peer reconnects after a brief disconnect (e.g., WiFi flap), it MAY send the first data packet immediately using the **previous** session key, without waiting for the server to re-issue hints:

1. Client caches `(session_id, session_key, last_sequence, token_key)` in memory after a successful direct channel.
2. On reconnect, client sends a Tier 2 data packet to the last-known peer endpoint using the cached key.
3. If the peer accepts it (valid auth tag, sequence within window), the direct channel resumes immediately.
4. If rejected (stale key or wrong endpoint), fall back to the normal hint-based flow.

**Cache TTL:** 300 s. After expiry, cached keys are purged.

---

## Platform-Specific: Android/Linux Socket Protect

On Android, all sockets created inside the VPN service MUST call `VpnService.protect(fd)` to prevent routing loops. On Linux with `tun2socks`, equivalent protection is achieved via `SO_MARK` or policy routing.

**Implementation plan:**

1. Define an abstract `SocketProtector` interface with `bool protect(int fd)`.
2. On Android, implement via JNI `VpnService.protect()`.
3. On Linux, implement via `setsockopt(SO_MARK)` with a dedicated fwmark (e.g., `0x5032`).
4. On Windows, implement as no-op (not required).
5. Pass `SocketProtector` to the P2P UDP channel factory; call `protect()` immediately after socket creation and before any `sendto()`.
6. **Hot socket pool:** Maintain a small pool of pre-protected UDP sockets (default: 2 per peer) to avoid the `protect()` syscall on every new channel. Reuse sockets across reconnections when possible.

---

## Performance Targets

| Metric | Target | Measurement |
|---|---|---|
| Hole-punch setup latency (non-symmetric NAT) | **p95 < 2 s** | Time from Probing entry to first Direct ACK |
| LAN direct setup latency | **p95 < 200 ms** | Same-subnet detection via parallel LAN probe |
| Direct path throughput overhead vs relay | **≤2%** | iperf3 over relay vs direct, same MTU |
| Direct path RTT improvement vs relay | **≥50% reduction** | ICMP ping via relay vs direct |
| Encryption overhead per packet | **<20 μs** | ChaCha20-Poly1305 encrypt+auth on 1400-byte payload |
| Encryption overhead per packet (AES-NI) | **<10 μs** | AES-256-GCM encrypt+auth on 1400-byte payload |
| Steady-state header overhead | **32 bytes** | Tier 2 minimal header + auth tag |
| Memory per P2P channel | **<256 KB** | Buffer pool (128 KB) + replay window (136 B) + state (<1 KB) |
| Syscall reduction via coalescing | **3–5× fewer `sendto()`** | Burst traffic: 10 small frames → 2 coalesced datagrams |
| Heartbeat overhead when idle | **1 packet/s** | Piggyback on data when active; 1 small packet when idle |
| Worst-case failure detection | **4 s** | `heartbeat_interval_ms × miss_max + suspect_timeout_ms` |
| Token re-request latency | **<100 ms** | INFO round-trip for token refresh |
| Zero-RTT reconnect latency | **1 RTT** | Cached key; no server round-trip needed |

---

## Acceptance Criteria

- [ ] `p2p.enabled=false` produces byte-identical behavior to the current release (no regressions).
- [ ] With both peers behind full-cone NAT, direct path establishes within **500 ms** and data flows correctly.
- [ ] With both peers on the same LAN, direct path establishes within **200 ms**.
- [ ] With both peers behind symmetric NAT, hole punching is skipped and relay is used without added latency.
- [ ] Stale or forged tokens are rejected; replayed packets are dropped.
- [ ] P2P UDP sockets on Android are protected and do not loop traffic into the VPN tunnel. The real-fd emulator bridge test is green; full direct-path and physical-device evidence remain required.
- [ ] Direct→Suspect→Relay fallback completes within **4 s**.
- [ ] Server-side P2P peer table is cleaned up within 1 s of session disconnect.
- [ ] Coalesced packets are correctly demuxed and all frames are injected.
- [ ] NAT rebind triggers connection migration within **5 s** grace period.
- [ ] Zero-RTT reconnect succeeds within 1 RTT when cached key is valid.
- [ ] Buffer pool eliminates malloc/free on steady-state hot path.
- [ ] ChaCha20-Poly1305 is selected on ARM; AES-256-GCM is selected on x86 with AES-NI.

## Suggested Sub-Issues

1. **feat(p2p): NAT classification from relay traffic** — Server-side NAT type inference from observed relay packet source patterns.
2. **feat(p2p): STUN mapped-endpoint detection on P2P UDP socket** — Reusable STUN bind utility for the fallback case.
3. **feat(p2p): UDP peer channel & state machine** — `Relay→Probing→Direct→Suspect→Relay` lifecycle with parallel candidate racing.
4. **feat(p2p): Two-tier packet header & coalescing** — Minimal data header, coalesced frames, GRO/GSO support.
5. **feat(p2p): ChaCha20-Poly1305 / AES-256-GCM encryption** — HKDF key derivation, platform-adaptive cipher selection, bitmap replay window.
6. **feat(p2p): Android/Linux socket protect & hot pool** — `SocketProtector` abstraction, pre-protected socket pool.
7. **feat(p2p): Connection migration & zero-RTT reconnect** — NAT rebind grace period, cached key reconnection.
8. **test(p2p): E2E scenarios** — Relay baseline, LAN direct, public direct, symmetric NAT fallback, token rejection, replay rejection, NAT rebind migration, zero-RTT reconnect.

## Compatibility

The relay path remains authoritative. When `p2p.enabled=false`, behavior should match the current release. When `p2p.enabled=true`, direct setup must never block or break existing `DoNat()` relay forwarding.
