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
| `reliability` | Negotiated reliability sub-protocol (ACK + fast retransmit + PTO); orthogonal to ordering, also runs in compat. |
| `fec` | Negotiated XOR parity FEC (implies `reliability`). |
| `active_links` | Handshake-complete, non-retiring links, clamped for presentation. |
| `fallback_reason` | Machine-readable reason for a capability or inactive-session fallback. |

`receiver_ordering` is not a synonym for `effective_mode`; consumers must use
the separately reported ordering fact.

## Reliability sub-protocol (ACK + fast retransmit + FEC)

The MUX handshake `ordering_caps` byte gains bit1 (`RELIABILITY`) and bit2
(`FEC`): the client advertises them per `mux.reliability.enabled` (default
true) / `mux.fec.enabled` (default false), and the server intersects both ends
and echoes the authoritative result. Reliability runs in both compat and
flow_v2: the receiver cumulatively reports received ranges per sequence space
(global under compat, per-flow DSN under flow_v2), and the sender re-sends
lost frames with their ORIGINAL sequence numbers on any live carrier from a
bounded retransmit buffer (8 MiB default) — fast retransmit at dup-ACK
distance >= 3, PTO 200 ms–3 s as backstop. Exhausting per-frame attempts or
the buffer degrades to the existing `fail_flow` / session-rebuild behavior.
`cmd_ack`/`cmd_fec` are unordered control frames sent only after negotiation
succeeds (older peers kill the session on unknown commands). FEC is an XOR
parity group (default 8 frames); one loss per group is recovered immediately,
two or more are left to retransmission. Protocol details:
[VMUX reliability sub-protocol design](../design/MUX_RELIABILITY_FEC_DESIGN_CN.md)
(Chinese).

## Fallback behavior

The implementation distinguishes these cases:

| Request/condition | Effective result |
|---|---|
| Unknown requested mode | `compat` with `receiver_ordering=compat`, `turbo=false`, and `unsupported_requested_mode`. |
| `balance` or `stripe` without local or peer FLOW_V2 | `compat` and compat ordering, with `local_missing_flow_v2` or `peer_missing_flow_v2`. |
| Plain `flow` | Remains effective `flow`; ordering may be `compat`. |
| `flow` with turbo but no required FLOW_V2 support | Remains effective `flow`, uses compat ordering, and reports the missing-FLOW_V2 reason. |
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
- `ppp/app/client/VEthernetExchanger.cpp`
- `benchmarks/vmux/README.md`, `run.sh`, and `parse_results.py`
