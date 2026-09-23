# VMUX Defect Ledger and Fix / Optimization Plan
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [VMUX 设计缺陷台账与修复 / 优化方案](MUX_DEFECTS_AND_FIXES_CN.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> **Recorded status:** “in progress” is this ledger’s historical snapshot, not a current development state. It records the then-confirmed/suspected defects, root causes, fixes, and priorities. Chinese pair: `MUX_DEFECTS_AND_FIXES_CN.md`.

## Background and trade-off (what VMUX is)

VMUX multiplexes arbitrarily many logical connections (vmux_skt) over a small set of long-lived carrier TCP sub-links (linklayer). What it buys:

- **Burst capacity**: multi-link parallelism plus the acceleration pipeline can push many frames in a short window.
- **Connection timeliness**: sub-links are pre-established and kept alive, so a new logical connection skips its own TCP/TLS cold-start handshake — low first-byte latency.

The cost is structural and cannot be removed, only mitigated:

- **TCP-over-TCP (nested reliable transport)**: the tunneled application TCP and the carrier TCP each run their own retransmit/congestion control. When a carrier link loses a packet or backs off, it injects latency spikes into the inner TCP, which then mis-detects congestion and backs off too — the two control loops fight, showing up as loaded-latency spikes and bufferbloat. The fuller a carrier link is, the worse it gets.
- **double control (two control planes)**: two layers of ACK clocks/windows/timeouts stack up, and VMUX adds its own control frames (syn/syn_ok/fin/keep_alived/acceleration) plus flow v2's per-flow DSN and reorder timeout. More control layers means more timing coupling and more fragility under teardown/races.

**Guiding principles (derived from the trade-off):**

1. Spread load across carrier links to lower the chance any single one saturates.
2. No mechanism may let a carrier queue grow unbounded or run without backpressure.
3. Keep the control plane thin; the control-frame path must be independent of data floods.
4. The only real cure for TCP-over-TCP is a non-congestion-controlled carrier (UDP/KCP), not more scheduling on a TCP carrier.

---

## Direction correction: back to the competition model (2026-06, per maintainer review)

This section records an important course correction to prevent repeating the mistake.

### Review conclusion (maintainer)

Early versions of the multi-link flow rework used **per-connection → link binding (affinity)** to spread load (the early `flow`/`balance` strict affinity). The maintainer flagged this as a **negative optimization**:

1. **Binding makes load unpredictable**: a link is lightly loaded at assignment time, but once a connection is pinned to it and that connection turns into a heavy flow (download/streaming), it is locked to that link; the link may have several heavy flows bound to it → backlog → drags the whole system down.
2. **Worst-case degeneration to a single TCP**: several heavy flows happening to bind to the same carrier TCP → effectively a single-TCP VMUX, losing the multi-link advantage entirely (the common failure of mainstream proxy VMUX schemes).
3. **Flow state is unpredictable; there is a race window**: A sends first, B sends later, yet B may arrive first on a real network. Pinning/reordering by send order only manufactures needless waiting. Migrating a link takes ≥2 RTT and congestion is dynamic, so prediction is unreliable.
4. **The right approach is competition**: let multiple TCP links **compete** for the current send opportunity (whoever is free sends). Load and speed are then adaptive and controllable, with no single link's backpressure dragging the whole system. This is exactly what earlier VMUX did, and it is the most efficient.
5. **TCP-over-TCP is an inherent flow-control limitation**: not solvable at the VMUX scheduling layer, nor by switching to QUIC; scheduling tricks are the wrong direction.

### Corrected design

- **Keep competition as the send-side policy for all modes**; remove per-connection binding (affinity).
- **Decouple "binding" from "per-flow ordering"**: the maintainer objected to *binding*, not *receiver-side per-flow ordering*. They are separable — competition on send (full, adaptive, no binding) + per-flow DSN reordering on receive (isolating head-of-line blocking to a single connection). Combined, this satisfies the competition model AND removes cross-flow HoL. That is the corrected `balance`.
- **Mode redefinition** (commit `aa3bbdc`):
  - `compat` = original upstream (competition + global ordering).
  - `flow` = latency-oriented new direction (competition + global ordering + optional turbo).
  - `balance` = competition send + per-flow ordering (former flow_v2, binding removed).
  - `stripe` = experimental per-packet round-robin + per-flow ordering.
- **Removed config `mux.flow-v2`**; per-flow ordering is auto-negotiated by `mode∈{balance,stripe}`.
- **Added `mux.turbo` / `--mux-mode-turbo`**: flow's latency optimization (best-link-first first packet + prewarm carriers to widen the **competition pool**, not bind/migrate).

### turbo design boundaries (important)

turbo must **conform to the competition model** and must not reintroduce the anti-pattern:

- **Best-link-first first packet**: a new connection's first packet is sent over the currently best-quality carrier link (by heartbeat signal) only to cut first-byte latency; it does **not** pin the connection to that link — later frames return to the competition pool. Only "forward" quality (current/historical heartbeat) is used; no backward prediction.
- **Prewarm carriers**: asynchronously open additional carrier TCP in the background; once ready they **join the competition pool** (more links to compete), with **no** connection migration (migration needs ≥2 RTT and is unreliable).
- Goal: latency first, throughput second (75–95%). No connection splitting (cannot avoid the race).

### turbo implementation status

- **Best-link-first first packet — implemented**: `vmux_linklayer.last_active_` is stamped in `linklayer_update()` on every inbound frame; `select_turbo_linklayer()` picks the most-recently-active live link; `post_internal` routes a `cmd_syn` over it when `mux.turbo` is on and flow mode is active, **without binding** (later frames compete normally). The signal is recency, not RTT — deliberately approximate, zero extra control frames. Fail-open to competition when no free turbo link exists.
- **Background carrier prewarming — implemented**: turbo splits base / hard / current pool state, raises a hard carrier ceiling for flow-mode sessions, and lets the runtime controller grow or retire one carrier link per cooldown window. Extra links join the same competition pool; shrink uses per-link `retiring_` + `inflight_` drain before Dispose. No resize control frame is added and `max_connections` remains the base session invariant.

---

## Defect ledger

Severity: 🔴 blocking / 🟠 high / 🟡 low-med / ✅ closed.

### D1 — teardown heap corruption (malloc abort / process exit) 🔴 confirmed structurally (crash site pending ASan)

- Root cause: the `syncobj_` lock domain and the vmux strand domain do not overlap. `finalize()` is the only place that touches `tx_links_/tx_queue_/skts_/flows_/affinity_links_` under `syncobj_`; the send drain, completion callbacks, and `add_linklayer` rely only on strand serialization, lock-free. `~vmux_net()` calls `finalize()` directly (possibly off-strand), so the two domains mutate the same `std::list`/maps concurrently → double-free / UAF.
- Amplifier: the flow multi-link change raised in-flight write completions at teardown from 1 to N (~N× window); acceleration's high-rate pump amplifies further.

### D2 — send-completion callback lacks in-flight/epoch protection 🔴 confirmed

- Even with the `disposed_` guard, the `underlyin_sent` completion is a TOCTOU; with no in-flight count, teardown cannot know how many async_write/async_read completions are still outstanding.

### D3 — read-path completion vs transmission Dispose 🟠 suspected (pending ASan stack)

- `forwarding` reads on the connection strand; `ITcpipTransmission::Dispose` posts `Finalize` (socket close) to the same strand (that pair is safe). But the per-read `base94_decode`/`make_shared_alloc` allocations plus the Asio async_read completion stack point to "completion touches freed object". Whether D2/D3 fixes land in vmux_net or the transmission layer must follow the ASan stack.

### D4 — flow_v2 strict-affinity direction was removed ✅ superseded by competition send

- The earlier suspected defect assumed flow-v2 required "same connection, same link" affinity. Maintainer review rejected binding as a negative optimization.
- Current `balance` intentionally uses the same competition send policy as `compat`; flow-v2 only changes receiver-side ordering to per-flow DSN. Cross-link DSN reordering within one connection is accepted and bounded by the per-flow reorder buffer/timeout.

### D5 — DSN monotonicity ✅ reviewed, no defect (exclusion)

- DSN is assigned before enqueue and `tx_flow_seq_[cid]++` runs entirely on the mux strand; acceleration is a serial pipeline. DSN is strictly increasing per connection regardless of acceleration.

### D6 — acceleration has no backpressure, worsening TCP-over-TCP bufferbloat 🟠 mechanism confirmed

- Acceleration pumps the next read→post inside the completion without checking carrier queue depth, saturating the carrier TCP faster and amplifying nested congestion feedback.

### D7 — flow v1 (compat fallback) single-primary-link funnel 🟠 partially resolved

- Legacy flow funneled all connections through one link; first packets were HoL-blocked by bulk data (observed `tx.queue.depth` in the thousands, ~10s page stalls). The multi-link rework resolves the "both peers support flow_v2" case; against an older peer (negotiation falls back to compat) it still degrades to the single-link funnel.

### D8 — reorder timeout default 2000ms is too large 🟡 confirmed

- `PPP_MUX_FLOW_REORDER_TIMEOUT=2000`. On real loss or a D4-induced gap, delivery waits a full 2s → second-scale stall. Configurable but the default is too high; should be near link RTT (hundreds of ms).

### D9 — flow_v2 requires both ends upgraded 🟡 design constraint (deployment trap, not a defect)

- Negotiation is an intersection; one older peer falls back to compat. Handled fail-safe in docs and negotiation logic.

### D10 — duplicate ICMP echo ✅ fixed

- `EchoOtherServer` still sent a second standard ECHO after a successful static echo → ping DUP. Fixed by `49956b3 fix(icmp): avoid duplicate static echo replies` (return on `se_ok`).

### D11 — tx_queue_ unbounded, no backpressure, control frames share the data queue 🔴 confirmed (telemetry-proven, top priority)

- Symptom (stress-logs/until-fail-20260601-124147): ppp does not crash but everything fails. `mux.link.send=12528 / recv=8`, `tcpip.peer_connect.fail.mux=533`, `mux.tx.queue.depth=46113-57943`, many outbound SYN with no SYN-ACK, HTTP 96/96 failed, ping fine with no DUP.
- Causal chain: RX stalls (e.g. a D4-induced DSN gap) → peer SYN-ACK/data/ACK cannot return → the send side `tx_queue_` has no cap and no backpressure, keeps `emplace_back` → queue explodes → new-connection `cmd_syn` and heartbeats share the same FIFO as data and are starved → all new TCP connects fail; ping is fine because gateway echo bypasses the per-connection queue.
- The only "brake", `rx_congestions`/`tx_acceleration_`, is a receive-side per-connection congestion window that depends on peer feedback; once RX stalls that loop breaks too, and it never bounds total `tx_queue_` depth.
- Rated above the intermittent crash: it does not crash, does not self-heal, and presents to the user as "the whole tunnel is dead to new connections".

---

## Fix plan

### Phase A: send-side resilience (fixes D11, top priority, ASan-independent)

**A1 separate control frames from data (priority queue)**
- In `post_internal`, distinguish `is_session_control`/`is_connection_control` (syn/syn_ok/fin/keep_alived/acceleration/mux_mode_set) from `is_per_flow_data`.
- Control frames go to the queue head or a dedicated high-priority `tx_ctrl_queue_`, always drained before data.
- Goal: even under a data flood with an exploded `tx_queue_`, new-connection SYN and heartbeats still get out, avoiding "heartbeat starved → mux judged timed-out → close_exec → cascade".
- Constraint: no wire-format or negotiation change; send-side queuing only.

**A2 tx_queue_ backpressure cap**
- Cap the data queue (by bytes or frames; default derivable from `mux.congestions` or a new `mux.tx.queue.max`).
- On overflow, apply backpressure to **data**: pause the `forward_to_rx_socket` read pump (stop reading the local socket so the tunneled application TCP backs off itself — using the inner control loop of TCP-over-TCP to push back), instead of enqueueing unboundedly. Control frames are exempt.
- Resume reads after the queue drains to a low-water mark — symmetric high/low-water backpressure (TCP-window-like).

**A3 RX-stall self-healing**
- Verify `flow_evict_expired` advances in both "RX coroutine running but one flow stuck" and "RX coroutine stalled entirely"; if needed add a watchdog: when `recv` is flat for a long time while `tx_queue_` stays high, proactively downgrade the session (close_exec → rebuild) rather than hang forever.

### Phase B: receiver-ordering tuning (fixes D8)

**B1 lower the reorder-timeout default**
- Drop the default `flow.reorder.timeout` from 2000ms toward RTT scale (suggest 300–500ms, still configurable) to shorten stuck→self-heal when a per-flow DSN gap is skipped.

### Phase C: lifecycle-model correction (fixes D1/D2/D3, pending ASan stack)

**C1 atomic disposed** ✅ landed (see below).

**C2 strand-only finalize**
- `~vmux_net()` no longer calls `finalize()` directly; guarantee `finalize` always runs on the vmux strand before the last shared_ptr drops; the destructor only releases trivial members.
- Audit all owner/release points (exchanger `mux_.reset()`) so reset is preceded by `close_exec()` and a strand-completed finalize.

**C3 in-flight / epoch count**
- Maintain an in-flight I/O count (async_read/async_write +1, completion −1) and/or an epoch number.
- Teardown waits for in-flight to reach zero before freeing containers/transmission; or epoch lets a late completion recognize "previous epoch" and drop itself.
- **Must cover three paths**: normal drain, acceleration fast-path, read path (forwarding async_read completion).
- Exact shape (count in vmux_net vs transmission layer) follows the free site the ASan stack points to.

### Phase D: performance optimization (fixes D6, non-blocking, scheduled)

**D-opt1 acceleration backpressure awareness**
- Before pumping, check carrier queue depth / in-flight; throttle when high to avoid saturating the carrier TCP. Coordinates with A2's water marks.

**D-opt2 (exploratory) remove TCP-over-TCP at the carrier**
- For loaded-latency-sensitive deployments, run mux over a UDP/KCP carrier so reliability is handled once by the inner TCP. A deployment recommendation / long-term direction, not part of this code round.

---

## Priority and dependencies

| Defect | Severity | Phase | Depends on |
|--------|----------|-------|------------|
| D11 unbounded tx / control starvation | 🔴 | A1/A2/A3 | none (evidence ready, do now) |
| D1/D2/D3 crash | 🔴 | C2/C3 | **ASan stack** |
| D4 strict affinity | ✅ | superseded | competition-send direction |
| D8 timeout too large | 🟡 | B1 | independent tuning |
| D6 acceleration backpressure | 🟠 | D-opt1 | scheduled |
| D7/D9 compatibility | 🟡 | documented | — |
| D5/D10 | ✅ | closed | — |

**Suggested order**: A (D11 resilience — stop "no crash but all-fail") → B (D4/D8 correctness — remove the stall trigger) → C (D1/D2/D3 crash, pending ASan) → D (perf). A and B are ASan-independent and can go first; C must wait for the stack.

---

## Landed fixes (as of this document)

- `49956b3` fix(icmp): avoid duplicate static echo replies — D10.
- `d8fe453` fix(mux): make session disposed_ flag atomic — C1, probabilistic mitigation of D1/D2 (not root cause).
- `cefbc6f` fix(mux): guard send-completion callback against post-teardown reentry — D1/D2 probabilistic mitigation.
- `a96d9aa` feat(mux): flow mode spreads frames across links via auto-negotiated flow-v2 — introduced multi-link (resolves the both-new-peer case of D7, also surfaced D4).

## Re-test summary

- until-fail-20260601-124147: stall reproduced. send=12528/recv=8, fail.mux=533, tx.queue.depth≈46113–57943, outbound SYN with no SYN-ACK, HTTP 96/96 failed, ping fine. → confirms D11 (triggered by D4).
- until-fail-20260601-125620: not reproduced. Fresh restart, 10 rounds, alive, max loss 7.5%, HTTP max bad 7/96, no crash/double-free. → D11 is a timing-specific self-locking state, not deterministic.
