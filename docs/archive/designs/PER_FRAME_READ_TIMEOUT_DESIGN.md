# Per-Frame Read Timeout Design
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [逐帧读取超时设计](PER_FRAME_READ_TIMEOUT_DESIGN_CN.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


[中文版本](PER_FRAME_READ_TIMEOUT_DESIGN_CN.md)

## Status

| Field | Value |
|-------|-------|
| **Priority** | P1 (slow-read DoS hardening) |
| **Decision** | **Deferred — design documented, not implemented** |
| **Governance ref** | `p1-governance-decisions-cn.md` P1-1 |
| **Audit ref** | `openppp2-deep-code-audit-cn.md` §5.1, §8 P1 #10 |
| **Date** | 2026-05-11 |

---

## 1. Problem Statement

Every `async_read` in the transmission read pipeline blocks the calling coroutine
indefinitely until the peer delivers the requested byte count.  A slowloris-style
attacker can hold a connection open by sending one byte every few minutes, keeping
a coroutine stack, a socket fd, cipher state, and QoS context alive for hours.

The three read paths that need protection:

| Path | Entry point | Underlying read |
|------|-------------|-----------------|
| **TCP** | `ITcpipTransmission::ReadBytes()` | `ppp::coroutines::asio::async_read(*socket, ...)` |
| **WebSocket** | `templates::WebSocket<IWebsocket>::ReadBytes()` | `IWebsocket::Read()` → `ppp::coroutines::asio::async_read(websocket_, ...)` |
| **ITransmission framing** | `ITransmission::Read()` → `ITransmissionBridge::Read()` → `DoReadBytes()` | Virtual dispatch to one of the above |

A frame read in the current code is a multi-step coroutine sequence:

```
ITransmission::Read()
  └─ ITransmissionBridge::Read()
       ├─ [pre-handshake] base94_decode_length()   ← ReadBytes(4 or 7 bytes)
       │                   base94_decode()          ← ReadBytes(payload_length bytes)
       └─ [post-handshake] Transmission_Packet_Read()
                             ├─ ReadBytes(3 bytes)   ← header
                             └─ ReadBytes(N bytes)   ← payload
```

Each `ReadBytes` call can stall independently.  The timeout must cover the
**entire frame read** (header + payload), not individual sub-reads, because
an attacker who delivers the 3-byte header quickly but then stalls on the
payload is just as dangerous.

---

## 2. Design

### 2.1 Architecture: Timer at ITransmission Level

```
                  ITransmission::Read(y, outlen)
                         │
          ┌──────────────┴──────────────┐
          │  Arm per-frame timer         │
          │  (steady_timer, T ms)        │
          │                              │
          ▼                              │
   ITransmissionBridge::Read()           │
     ├─ ReadBytes(header)  ◄─── may     │
     ├─ ReadBytes(payload) ◄─── stall   │
     │                              │
     │  On success:                 │
     │   Cancel timer ─────────────►│
     │   Return packet              │
     │                              │
     │  On timer expiry:            │
     │   Cancel socket reads ───────┘
     │   Dispose transmission
     │   Return null + ErrorCode
```

The timer is armed **once** before the frame read begins and cancelled
**once** after the complete frame (header + payload) is assembled.  This
bounds the total time for one `ITransmission::Read()` call.

### 2.2 Why Not Per-Sub-Read Timeout

Per-sub-read timeouts would require:
- Multiple timer create/cancel cycles per frame (2-3x overhead).
- Different timeout values for header vs. payload reads.
- Complex state tracking if a sub-read succeeds but the next one stalls.

A single per-frame timeout is simpler, sufficient for the threat model,
and matches how the existing handshake timeout works (single timer for
the entire handshake sequence).

### 2.3 Timer Type and Ownership

```cpp
// In ITransmission (already has this typedef):
typedef boost::asio::steady_timer  DeadlineTimer;
typedef std::shared_ptr<DeadlineTimer> DeadlineTimerPtr;
```

The timer is created on the same `io_context` and strand as the transmission.
It is a member of `ITransmission` (like `timeout_` for handshake), not a
local variable, because:

1. **Cancellation safety**: The timer callback must access `this->Dispose()`,
   which requires the transmission to still be alive.  A member ensures the
   lifetime extends until `Finalize()` cancels it.
2. **Single-writer pattern**: Only one frame read is in flight at a time
   (the coroutine model guarantees this), so a single timer member suffices.

### 2.4 New Member and Configuration

```cpp
// ITransmission.h — new private members
DeadlineTimerPtr    frame_read_timer_;     // Per-frame read deadline timer.
std::atomic_bool    frame_read_armed_{false}; // Guards against double-arm.

// AppConfiguration.h — new field (under tcp.connect or a new tcp.frame section)
struct {
    int timeout;  // Per-frame read timeout in seconds; 0 disables.
} frame_read;
```

Default value: `0` (disabled) until validated.  Operators can enable it
via `appsettings.json`:

```json
{
  "tcp": {
    "frame_read": {
      "timeout": 30
    }
  }
}
```

### 2.5 Implementation Sketch (ITransmission::Read)

```cpp
std::shared_ptr<Byte> ITransmission::Read(YieldContext& y, int& outlen) noexcept {
    outlen = 0;
    if (disposed_.load(std::memory_order_acquire)) {
        return NULLPTR;
    }

    // ── Arm per-frame read timer ──
    int frame_timeout_s = configuration_->tcp.frame_read.timeout;
    bool timer_armed = false;
    if (frame_timeout_s > 0 && context_ && strand_) {
        frame_read_timer_ = make_shared_object<DeadlineTimer>(*strand_);
        if (frame_read_timer_) {
            auto self = std::static_pointer_cast<ITransmission>(shared_from_this());
            frame_read_timer_->expires_after(
                std::chrono::seconds(frame_timeout_s));
            frame_read_timer_->async_wait(
                [self, frame_timeout_s](boost::system::error_code ec) noexcept {
                    if (ec == boost::system::errc::operation_canceled) {
                        return;  // Normal: frame read completed in time.
                    }
                    // Timer expired — the frame read is stalled.
                    ppp::telemetry::Count("transmission.frame_read_timeout", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "transmission",
                        "per-frame read timeout after %ds", frame_timeout_s);
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::TunnelReadTimeout);
                    self->Dispose();
                });
            frame_read_armed_.store(true, std::memory_order_release);
            timer_armed = true;
        }
    }

    // ── Actual frame read (header + payload) ──
    std::shared_ptr<Byte> result = ITransmissionBridge::Read(this, y, outlen);

    // ── Cancel timer on success or failure ──
    if (timer_armed) {
        frame_read_armed_.store(false, std::memory_order_release);
        DeadlineTimerPtr t = std::move(frame_read_timer_);
        if (t) {
            Socket::Cancel(*t);
        }
    }

    if (NULLPTR == result && ppp::diagnostics::ErrorCode::Success ==
            ppp::diagnostics::GetLastErrorCode()) {
        if (disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SessionDisposed);
        } else {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::TunnelReadFailed);
        }
    }

    return result;
}
```

### 2.6 Timer/Cancellation Lifecycle

```
State         Action                    Who
────────────  ────────────────────────  ──────────────────────
IDLE          Create steady_timer       ITransmission::Read
              Set expiry to T seconds
              Post async_wait callback
ARMED         Frame read in progress    Coroutine (via DoReadBytes)
────────────  ────────────────────────  ──────────────────────
COMPLETED     Frame read succeeds       Coroutine
              Cancel timer              ITransmission::Read
              Timer callback gets       (operation_canceled → no-op)
              operation_canceled
────────────  ────────────────────────  ──────────────────────
EXPIRED       Timer fires first         io_context thread
              Dispose() called          Timer callback
              Socket cancelled          Finalize()
              Coroutine read returns    (ec != success → null)
              error on resume
────────────  ────────────────────────  ──────────────────────
DISPOSED      Finalize() cancels timer  Destructor / Dispose path
              (same as COMPLETED path)  Socket::Cancel(*t)
```

Key invariants:
- The timer is always cancelled before `Finalize()` runs, either by the
  read-completion path or by `Finalize()` itself (which already calls
  `Socket::Cancel(*t)` on `timeout_`; the same pattern applies to
  `frame_read_timer_`).
- The timer callback captures `shared_from_this()`, preventing the
  transmission from being destroyed while the callback is queued.
- `frame_read_armed_` prevents double-arm if `Read()` is called
  re-entrantly (should not happen with coroutine model, but defensive).

### 2.7 Interaction with QoS Layer

The QoS layer (`ITransmissionQoS::ReadBytes`) can **delay** the start of a
read by suspending the coroutine until bandwidth budget opens.  This delay
counts against the per-frame timeout.  Two options:

| Option | Behavior | Risk |
|--------|----------|------|
| **A. Timer starts before QoS** | QoS suspension time counts toward timeout | False positives under heavy throttling |
| **B. Timer starts after QoS** | Only actual I/O time is bounded | Attacker can stall in QoS queue |

**Recommended**: Option A (timer starts before QoS).  Rationale:
- QoS suspension is bounded (resumes every second on `Update()`).
- The timeout value should be generous enough to tolerate QoS delays.
- Option B requires changing the QoS API to signal "read starting",
  which increases invasiveness.

### 2.8 Interaction with Handshake Timeout

During handshake, `ITransmission::HandshakeClient/Server` already arms
`timeout_` (the handshake deadline timer).  The per-frame timer should
**not** be armed during handshake reads because:
1. Handshake timeout already covers this case.
2. `handshaked_` is false, so `Read()` is only called from handshake code.

Guard: skip per-frame timer when `!handshaked_`:

```cpp
if (frame_timeout_s > 0 && handshaked_.load(std::memory_order_acquire)) {
    // Arm per-frame timer
}
```

---

## 3. Path-Specific Analysis

### 3.1 ITcpipTransmission

```
ITcpipTransmission::ReadBytes(y, length)
  └─ ppp::coroutines::asio::async_read(*socket, buffer, y)
       └─ boost::asio::async_read(stream, buffers, yield[ec])
```

Cancellation: `Socket::Cancel(socket)` calls `socket->cancel()` which
cancels all pending async operations on the socket.  The `async_read`
callback receives `boost::asio::error::operation_aborted`.  The coroutine
resumes with `len = -1` (failure).

**Risk**: TCP `cancel()` is safe on all supported platforms (Linux epoll,
Windows IOCP, macOS kqueue).  Buffered data already received by the kernel
is preserved; only pending `recv()` calls are cancelled.  The framing layer
handles partial reads correctly because `async_read` returns an error
(short read), and the caller discards the partial buffer.

**Risk level**: **Low**.  This is the same mechanism used by the handshake
timeout today.

### 3.2 WebSocket (Plain)

```
templates::WebSocket<websocket>::ReadBytes(y, length)
  └─ socket->Read(buffer, 0, length, y)
       └─ ppp::coroutines::asio::async_read(websocket_, buffer, y)
            └─ boost::beast::websocket::stream::async_read(...)
```

Cancellation: The Beast websocket stream wraps a TCP socket.  Cancelling
the underlying socket (`websocket_.next_layer().cancel()`) cancels pending
Beast operations.

**Risk**: Boost.Beast documentation warns that cancelling a websocket stream
mid-operation can leave it in an **indeterminate state**.  Specifically:
- A partial control frame may be buffered.
- The stream's internal read buffer may contain unprocessed data.
- Subsequent reads may fail or produce corrupt frames.

However, in our code, a per-frame timeout **disposes the entire transmission**,
so the stream is never reused after cancellation.  This eliminates the
"indeterminate state" concern.

**Risk level**: **Low-Medium**.  Safe because we always dispose on timeout.
Would be **High** if we tried to reuse the stream after cancellation.

### 3.3 WebSocket (TLS / WSS)

Same as §3.2 but with an additional TLS layer:

```
templates::WebSocket<sslwebsocket>::ReadBytes(y, length)
  └─ socket->Read(buffer, 0, length, y)
       └─ ppp::coroutines::asio::async_read(ssl_websocket_, buffer, y)
```

Cancelling the underlying TCP socket also cancels the TLS read.  The TLS
session state is corrupted, but again, we dispose on timeout.

**Risk level**: **Low-Medium** (same reasoning as §3.2).

### 3.4 MUX Sub-Channels

MUX channels (`ppp/app/mux/`) read from an already-decrypted in-memory
buffer, not from a socket.  Per-frame read timeout does not apply to MUX
sub-channels because:
1. MUX reads are non-blocking (memory copy).
2. MUX has its own idle timeout (`mux.inactive.timeout`).

No changes needed for MUX paths.

---

## 4. New Error Code

Add to `ppp/diagnostics/ErrorCodes.def` (**proposed/design item, not yet in current ErrorCodes.def**):

```cpp
X(TunnelReadTimeout,
    "Per-frame read timeout exceeded; connection disposed", ErrorSeverity::kWarning)
```

This distinguishes a slow-read timeout from a generic `TunnelReadFailed`.

---

## 5. Telemetry

On timer expiry, emit:

```cpp
ppp::telemetry::Count("transmission.frame_read_timeout", 1);
ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "transmission",
    "per-frame read timeout after %ds remote=%s:%u",
    frame_timeout_s,
    remoteEP_.address().to_string().c_str(),
    remoteEP_.port());
```

This enables operators to monitor slow-read attacks via the existing
telemetry pipeline (OpenTelemetry / log aggregation).

---

## 6. Test Requirements

**There are currently zero automated tests in this project.**  The following
test plan is written for when test infrastructure exists.  Until then,
validation is manual.

### 6.1 Unit Tests (requires test harness)

| ID | Test | Expected |
|----|------|----------|
| T-1 | Frame read completes within timeout | Timer cancelled, no disposal |
| T-2 | Frame read exceeds timeout | Timer fires, `Dispose()` called, `TunnelReadTimeout` error |
| T-3 | Timer cancellation on successful read | No spurious disposal after frame completes |
| T-4 | Timer cancellation on `ITransmission::Dispose()` | No dangling timer callback after disposal |
| T-5 | Double-arm guard | Second `Read()` call while first is in flight does not create second timer |
| T-6 | Handshake reads skipped | Timer not armed when `handshaked_ == false` |
| T-7 | QoS delay counts toward timeout | Frame times out if QoS delay + I/O time > timeout |

### 6.2 Integration Tests (requires peer process)

| ID | Test | Expected |
|----|------|----------|
| I-1 | TCP: slowloris attack (1 byte/sec) | Session torn down after timeout |
| I-2 | TCP: normal burst transfer | No false timeouts under 100 Mbps |
| I-3 | WS: slowloris attack | Session torn down after timeout |
| I-4 | WSS: slowloris attack | Session torn down after timeout |
| I-5 | TCP: timeout during header read only | Disposal after header stall |
| I-6 | TCP: timeout during payload read only | Disposal after payload stall |
| I-7 | WS: timeout during payload read only | Disposal after payload stall |
| I-8 | Timer value 0 (disabled) | No timeouts, existing behavior preserved |

### 6.3 Stress Tests

| ID | Test | Expected |
|----|------|----------|
| S-1 | 1000 concurrent connections with timeout=5s | No fd leaks, no timer leaks |
| S-2 | Rapid connect/disconnect cycle | No stale timer callbacks |
| S-3 | Timer expiry during QoS throttle | Graceful disposal, no crash |

### 6.4 Platform-Specific Validation

| Platform | Concern | Validation |
|----------|---------|------------|
| Linux | `epoll` + `cancel()` interaction | I-1, I-5, I-6 |
| macOS | `kqueue` + `cancel()` interaction | I-1, I-5, I-6 |
| Windows | IOCP + `cancel()` interaction | I-1, I-5, I-6 |
| Android | NDK `cancel()` behavior on older API levels | I-1 with API 21 |

---

## 7. Configuration Schema

### 7.1 New Field

```json
{
  "tcp": {
    "frame_read": {
      "timeout": 30
    }
  }
}
```

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `tcp.frame_read.timeout` | int | 0 | 0–300 | Per-frame read timeout in seconds. 0 = disabled. |

### 7.2 Backward Compatibility

- Default is `0` (disabled), so existing deployments are unaffected.
- The field is optional; missing `frame_read` section means disabled.
- No schema migration needed.

### 7.3 Recommended Values

| Scenario | Recommended | Rationale |
|----------|-------------|-----------|
| Production server | 30s | Long enough for QoS delays, short enough to limit slowloris |
| High-latency links | 60s | Satellite / cross-continent paths |
| Development/testing | 0 (disabled) | Avoid false timeouts during debugging |
| High-security | 15s | Aggressive slowloris mitigation |

---

## 8. Implementation Checklist

When implementation is approved:

- [ ] Add `tcp.frame_read.timeout` to `AppConfiguration.h` struct
- [ ] Add `frame_read.timeout` to JSON schema / config loader
- [ ] Add `TunnelReadTimeout` to `ErrorCodes.def`
- [ ] Add `frame_read_timer_` and `frame_read_armed_` to `ITransmission.h`
- [ ] Implement timer arm/cancel in `ITransmission::Read()`
- [ ] Cancel `frame_read_timer_` in `ITransmission::Finalize()`
- [ ] Add telemetry counters and log lines
- [ ] Manual test: TCP slowloris (I-1)
- [ ] Manual test: WS slowloris (I-3)
- [ ] Manual test: WSS slowloris (I-4)
- [ ] Manual test: normal traffic (I-2)
- [ ] Manual test: timeout=0 preserves existing behavior (I-8)
- [ ] Platform test: Linux (I-1)
- [ ] Platform test: macOS (I-1) — if CI runner available
- [ ] Platform test: Windows (I-1) — if CI runner available
- [ ] Document in `CONFIGURATION.md` and `CONFIGURATION_CN.md`

---

## 9. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Timer leak (callback fires after dispose) | Low | Medium | `shared_from_this()` capture + `Finalize()` cancels timer |
| False timeout under heavy QoS | Medium | Low | Default 0 (disabled); operators choose value |
| Socket state corruption after cancel | Very Low | High | Always dispose after cancel; never reuse stream |
| Coroutine re-entrancy | Very Low | Medium | `frame_read_armed_` atomic guard |
| Config parsing error for new field | Low | Low | Default 0 on parse failure |

---

## 10. Why Deferred

This feature is deferred (design-only, no code changes) for the following reasons:

1. **No automated test infrastructure**: The project has zero tests.  Per-frame
   read timeout modifies the core read path used by every connection.  Without
   automated regression tests, a subtle bug (e.g., timer not cancelled on one
   error path) could cause all connections to be torn down spuriously.  Manual
   testing alone is insufficient for a change this central.

2. **Socket cancellation cross-platform variance**: While `socket::cancel()` is
   well-defined on Linux/epoll, Windows/IOCP, and macOS/kqueue, the interaction
   with Boost.Beast websocket streams is less tested in this codebase.  The
   project currently has no WebSocket transport tests at all.

3. **QoS interaction needs real-world profiling**: The per-frame timer must be
   tuned against actual QoS behavior.  Setting it too low causes false positives
   under bandwidth throttling; setting it too high provides no protection.  This
   requires production-like traffic profiles.

4. **Configuration surface area**: Adding `tcp.frame_read.timeout` changes the
   configuration schema.  This should be coordinated with any other pending
   config changes (e.g., multi-level frame limits from §5.1).

5. **Existing handshake timeout provides partial mitigation**: The handshake
   timeout (`tcp.connect.timeout`) already bounds the time an attacker can hold
   a connection during the most vulnerable phase (before encryption is
   established).  Post-handshake, the keepalive mechanism (`PacketAction_KEEPALIVED`)
   provides a secondary liveness check, though it operates at a longer interval.

6. **Feature flag approach required**: Given the risk profile, the feature must
   ship disabled by default (`timeout: 0`) and be explicitly opted into.  This
   means it provides no protection until operators configure it, reducing the
   urgency of shipping it before validation is complete.

### When to Implement

The feature should be implemented when **all** of the following are true:

- [ ] At least basic integration tests exist for the transmission read path
- [ ] Socket cancellation has been validated on target platforms (Linux at minimum)
- [ ] QoS layer behavior under throttling has been profiled
- [ ] The configuration schema change is coordinated with other pending work
- [ ] A release candidate build is available for manual slowloris testing

---

## 11. Alternative Approaches Considered

### 11.1 TCP SO_RCVTIMEO

Set a socket-level receive timeout.  Rejected because:
- Platform-specific (not available on all Boost.Asio socket types).
- Applies to individual `recv()` calls, not to the logical frame read.
- Cannot be changed per-frame (would need to be set/unset around each read).

### 11.2 Boost.Beast WebSocket Stream Timeout

Beast provides `stream_base::timeout` for websocket streams.  Rejected because:
- Only applies to websocket paths, not TCP paths.
- Operates at the websocket frame level, not the PPP frame level.
- Already set to "suggested" defaults in the server-side handshake code
  (see `ppp/net/asio/templates/WebSocket.h:139-141`), but these cover the
  Beast-level read/write, not the PPP framing level.

### 11.3 Coroutine-Level Deadline

Use `ppp::coroutines::asio::async_sleep` as a racing coroutine alongside the
read.  Rejected because:
- Requires spawning a second coroutine per read (stack allocation overhead).
- Race condition: both coroutines resume on the same `YieldContext`, which
  is not designed for concurrent resumption.
- The `steady_timer` approach is simpler and uses existing infrastructure.

### 11.4 Idle Connection Sweeper (Out-of-Band)

A periodic timer that scans all connections and disposes those with no
traffic for > T seconds.  Rejected as the primary mechanism because:
- Requires iterating all connections (O(n) per sweep).
- Cannot distinguish "idle but legitimate" from "slowloris stall" during
  a frame read.
- Better as a **complementary** mechanism (already partially implemented
  via keepalive timeouts).

---

## 12. Related Work

| Item | Status | Description |
|------|--------|-------------|
| P0-4A frame length limit | ✅ Done | `PPP_BUFFER_SIZE` (65536) cap on decoded payload |
| Handshake timeout | ✅ Done | `ITransmission::InternalHandshakeTimeoutSet/Cancel` |
| Keepalive mechanism | ✅ Done | `PacketAction_KEEPALIVED` periodic heartbeat |
| TCP idle timeout | ✅ Done | `tcp.inactive.timeout` config |
| Per-frame read timeout | **This doc** | P1 deferred |
| Multi-level frame limits | P1 deferred | Pre-handshake/control/data max lengths |
