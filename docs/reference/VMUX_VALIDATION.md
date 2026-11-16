# VMUX Validation and Rollout Gate

> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer link: [中文](VMUX_VALIDATION_CN.md)
> Related: [UI runtime contract](UI_RUNTIME_CONTRACT.md)

`compat` is the current VMUX default. `stripe` is experimental. This page
states implemented negotiation/presentation behavior and the evidence required
for a default change; it does not claim that a performance gate has passed.

## Runtime state contract

`ppp::app::mux::MuxRuntimeState` reports these facts:

| Field | Meaning |
|---|---|
| `requested_mode` | Configured/requested preset: `compat`, `flow`, `balance`, or `stripe`. |
| `effective_mode` | Negotiated preset after capability handling. |
| `receiver_ordering` | Separately negotiated `compat` or `flow_v2` receive ordering. |
| `scheduler` | Derived presentation: `round_robin` for `stripe`, otherwise `competition`. |
| `pool_policy` | Derived presentation: `adaptive` only for effective `flow` with turbo; otherwise `fixed`. |
| `turbo` | Active flow-turbo flag; it is an option, not a fifth mode. |
| `reliability` | Negotiated reliability sub-protocol (ACK + carrier-exit re-injection; PTO and fast retransmit are opt-in); orthogonal to ordering, also runs in compat. |
| `fec` | Negotiated XOR parity FEC (implies `reliability`). |
| `active_links` | Handshake-complete, non-retiring links, clamped for presentation. |
| `fallback_reason` | Machine-readable reason for a capability or inactive-session fallback. |

`receiver_ordering` is not a synonym for `effective_mode`; consumers must use
the separately reported ordering fact.

## Ordering negotiation (FLOW_V2 request)

`ordering_caps` bit0 (`FLOW_V2`) is an implementation capability that clients
always advertise. bit3 (`FLOW_V2_REQUEST`) is sent only by a client whose own
preset needs per-flow ordering (`flow` with turbo, `balance`, `stripe`). The
server agrees `flow_v2` when its own preset needs it **or** the client
requested it, provided both ends advertise `FLOW_V2`. The server keeps its own
scheduler preset; only receiver ordering, which both ends share, changes.
Older servers ignore bit3 and keep the previous behavior.

## Receive backpressure

Reorder caps (`mux.flow.reorder.bytes`, `mux.flow.session_reorder.bytes`) are
soft, and default to at least the matching send windows (8 MiB per flow,
32 MiB per session): out-of-order frames are selectively ACKed, so the sender
keeps sending while a gap persists and a smaller receive budget resets flows. When buffering an out-of-order frame would exceed a cap, the receiver
still buffers it but stops reading the carrier that delivered it, so that
carrier's TCP flow control throttles the sender until the lagging frame
arrives. Paused carriers resume when the buffers drain to half the cap. The
receiver never pauses every live carrier, and a single pause lasts at most
`PPP_MUX_RX_PAUSE_MAX_MS` (200 ms) before the carrier reads again, because the
missing frame may be queued on any carrier, including a paused one. Only twice the cap (`PPP_MUX_REORDER_HARD_FACTOR`) resets a flow
(flow_v2) or rebuilds the session (compat). The gap timeout restarts on every
in-order delivery, so sustained reordering with progress does not time out.
Telemetry: `mux.rx.backpressure.pause` / `resume` / `release_all` /
`lease_expired`.

## Send scheduling

A carrier stays in the scheduling list while its bytes in flight are under
`PPP_MUX_LINK_BYTE_HIGH_WATER` (256 KiB), so several frames can be in flight on
it and the carrier write queue gathers them into one socket write; previously a
carrier took one frame per write-completion round trip. Each frame goes to the
listed carrier with the fewest bytes in flight (ties: lower SRTT), because a
carrier whose socket buffer is bloated reports local write completions as fast
as a healthy one. Under compat the global sequence is assigned when a frame is
handed to a carrier, not when it is queued: DRR serves flows out of posting
order, so enqueue-time numbering reordered frames even on a single carrier.
DRR keeps cycling until a flow's head frame fits its deficit (frames can be up
to 64 KiB, the quantum is 16 KiB), instead of returning and waiting for an
unrelated event. Pushes that fill at least half of their read buffer are sent
from that buffer without a copy; smaller reads are copied into an exact-size
frame so frame memory stays close to the length the send window counts.

## Per-flow transmit queue and XON/XOFF ordering

With acceleration a push completes before it is written, so a stream's read
pump can run ahead of the carrier. It is re-coupled to write completions when
the session queue reaches `mux.tx.queue.max`, when its flow is parked on the
send window, or when the flow's own queue is half way to its cap
(`PPP_MUX_TX_FLOW_MAX_FRAMES` / `PPP_MUX_TX_FLOW_MAX_BYTES`). If a frame still
hits the cap it is never dropped silently: flow_v2 resets only that flow, and
compat (whose global sequence is already spent) rebuilds the session at once
instead of after a gap timeout (`mux.tx.flow_overflow`).

`cmd_acceleration` (XON/XOFF) carries `[state][4-byte version]`. Control frames
are unordered under flow_v2 and may overtake each other across carriers, so a
receiver ignores a versioned XON/XOFF that is not newer than the last one it
applied. Older peers send and read only the state byte and keep working.
A receiver stops the peer when a stream's backlog reaches `mux.congestions`
and resumes it at half that (resuming only at zero drained the pipe each cycle).

## Reliability sub-protocol (ACK + re-injection + FEC)

The MUX handshake `ordering_caps` byte gains bit1 (`RELIABILITY`) and bit2
(`FEC`): the client advertises them per `mux.reliability.enabled` (default
true) / `mux.fec.enabled` (default false), and the server intersects both ends
and echoes the authoritative result. Reliability runs in both compat and
flow_v2: the receiver cumulatively reports received ranges per sequence space
(global under compat, per-flow DSN under flow_v2), and the sender keeps
unacked frames in a retransmit buffer whose cap (32 MiB default) is a send
window (see below). Carriers are
reliable streams, so by default a frame is re-sent only when its carrier
exits: every unacked frame last written to that carrier is re-injected with
its ORIGINAL sequence number on the remaining carriers (`mux.rtx.reinject`).
A carrier exits once: the exit retires it, so writes still in flight on it
never list it for new frames again and a second report (failed write, then
the end of its forwarding loop) is ignored.
Fast retransmit at dup-ACK distance >= 3 (`mux.reliability.rtx.fast`) and PTO
200 ms–3 s (`mux.reliability.rtx.pto`) are opt-in, because on reliable
carriers they mostly re-send frames that are only queued behind a slower
carrier. Exhausting per-frame attempts or the buffer's hard bound degrades to
the existing `fail_flow` / session-rebuild behavior.
`cmd_ack`/`cmd_fec` are unordered control frames sent only after negotiation
succeeds (older peers kill the session on unknown commands). FEC is an XOR
parity group (default 8 frames); one loss per group is recovered immediately,
two or more are left to retransmission. Protocol details:
[VMUX reliability sub-protocol design](../design/MUX_RELIABILITY_FEC_DESIGN_CN.md)
(Chinese).

## Send backpressure (retransmit window)

Unacked bytes are roughly BDP plus the carriers' kernel send buffers, so a
fast, high-RTT path can legitimately hold more than the retransmit cap in
flight. The caps are therefore send windows checked before a frame leaves the
DRR queue, not terminal limits: the session window is
`mux.reliability.rtx.bytes` (32 MiB) and, under flow_v2, each flow also has
`mux.reliability.rtx.flow_bytes` (8 MiB). Throughput is bounded by window / RTT
(a field test with the former 8 MiB / 2 MiB sat at ~165 Mbps per flow and
~516 Mbps for 8 flows). A frame that would cross either window
stays queued and its flow is parked off the DRR ring, so other flows keep
sending (`mux.tx.rtx_window.hold` / `hold_flow`). A parked flow also re-couples
its socket read-pump to send completions, so it waits instead of overflowing
its per-flow TX queue. The ACK that releases bytes resumes parked flows and
re-drives the scheduler (`mux.tx.rtx_window.resume`); the reliability tick
retries as a backstop for bytes freed by a flow reset. An empty window always
admits one frame, so an oversized frame cannot wedge the sender. Only frames
that bypass the window (the turbo SYN) can push the buffer past it, and only
twice the window (`PPP_MUX_RTX_HARD_FACTOR`) still fails the flow (flow_v2)
or rebuilds the session (compat), logged as `rtx hard cap exceeded` /
`rtx flow hard cap exceeded`. `cmd_ack`/`cmd_fec` take the priority control
queue in compat as well, so an ACK never waits behind parked data.

## Fallback behavior

The implementation distinguishes these cases:

| Request/condition | Effective result |
|---|---|
| Unknown requested mode | `compat` with `receiver_ordering=compat`, `turbo=false`, and `unsupported_requested_mode`. |
| `balance` or `stripe` without local or peer FLOW_V2 | `compat` and compat ordering, with `local_missing_flow_v2` or `peer_missing_flow_v2`. |
| Plain `flow` | Remains effective `flow`; ordering may be `compat`. |
| `flow` with turbo but no required FLOW_V2 support | Remains effective `flow`, uses compat ordering, and reports the missing-FLOW_V2 reason. |
| Client sends `FLOW_V2_REQUEST`, server preset does not need flow_v2 | Server keeps its preset and agrees `flow_v2` ordering when both ends advertise `FLOW_V2`. |
| No active client VMUX session | Effective/ordering are `compat`; a non-compat configured request reports `mux_inactive`. |

An authoritative peer handshake reply supplies its negotiated ordering, so UI
and operators must inspect both `effective_mode` and `receiver_ordering`.

## Rollout evidence required for a default change

The harness and parser in `benchmarks/vmux/` define a rollout gate. Qualifying
results require, at minimum:

- physical Linux x86-64 (not WSL) and physical Android or iOS client evidence;
- endpoint manifest attestation, raw result JSON, matching environment
  fingerprints and durations, and a Linux client commit matching the runner;
- paired `off-one-flow` and `flow-one-flow` results for each client;
- `flow-one-flow` mean throughput at least 95% of mux-off;
- `flow-one-flow` mean p99 latency no more than 110% of mux-off;
- zero disconnects and buffered-byte/reorder-entry values within submitted
  configured bounds.

Run the validator against a complete result bundle:

```bash
python3 benchmarks/vmux/parse_results.py --rollout-gate <results...>
```

The current benchmark matrix covers `off`, `compat`, `flow`, and `balance`
scenarios; it does not provide a `stripe` promotion scenario.

## What the harness proves

The default `run.sh` invocation is a dry-run: it validates a plan but changes
no network state and writes no result. A real run requires `--execute`, an
external `iperf3` server, executable preparation hook, endpoint manifest, and
telemetry captured from that run. The parser validates supplied artifacts and
thresholds; it does not itself establish that a physical-device measurement or
tunnel setup occurred.

Repository sources provide the harness, parser, and correctness/tooling tests.
They do not contain a qualifying Linux-plus-mobile throughput/p99 evidence
bundle. Commit `ded25d6` remains the documented compatibility/correctness
baseline; it is not a qualifying rollout performance bundle or evidence that
the default-change gate passed. Therefore this reference makes no
performance-pass claim and cites no historical raw commit or sanitizer-run
result as rollout evidence.

## Default-change rule

Keep `compat` as the default until qualifying evidence satisfies the rollout
gate. Treat `stripe` as experimental unless a separately defined and evidenced
promotion decision changes that status.

## Source references

- `ppp/configurations/AppConfiguration.cpp`
- `ppp/app/mux/MuxRuntimeState.h`
- `ppp/app/mux/MuxRxBackpressure.h`
- `ppp/app/mux/MuxTxBackpressure.h`
- `ppp/app/client/VEthernetExchanger.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
- `benchmarks/vmux/README.md`, `run.sh`, and `parse_results.py`
