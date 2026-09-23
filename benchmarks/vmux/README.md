# VMUX benchmark harness

This harness records repeatable VMUX scheduler evidence without changing the
wire protocol or the default mode. `compat` remains the production default.

## Scenario matrix

| Scenario | Mode / load | Fault or action |
| --- | --- | --- |
| `off-one-flow` | mux off, one flow | none; valid only when `active_links == 0` |
| `compat-one-flow` | compat, one flow | none |
| `flow-one-flow` | flow, one flow | none |
| `compat-eight-flows` | compat, eight flows | none |
| `flow-eight-flows` | flow, eight flows | none |
| `balance-eight-flows` | balance, eight flows | none |
| `carrier-delay` | balance, eight flows | one carrier: delay 40 ms, rate 100 Mbit/s |
| `carrier-loss` | balance, eight flows | one carrier: random loss 2%, correlation 0%, rate 100 Mbit/s, seed 71214 |
| `carrier-removal` | balance, eight flows | remove one carrier at runtime |
| `turbo-churn` | flow, eight flows | repeated grow/shrink action hook |
| `reliability-loss-0.5` | balance, eight flows, reliability on | one carrier: random loss 0.5%, seed 51503 |
| `reliability-loss-2` | balance, eight flows, reliability on | one carrier: random loss 2%, seed 71214 |
| `reliability-loss-5` | balance, eight flows, reliability on | one carrier: random loss 5%, seed 90512 |
| `fec-loss-2` | balance, eight flows, reliability + FEC on | one carrier: random loss 2%, seed 71214 |

`one-flow` is a convenience alias for `compat-one-flow`.

The `reliability-*` and `fec-*` scenarios compare the negotiated reliability
sub-protocol (ACK + fast retransmit + PTO) and the optional XOR parity FEC
against the `carrier-loss` baseline at the same loss rates. The prepare hook
receives the scenario name and must enable `mux.reliability.enabled` (all
`reliability-*` and `fec-*` runs) and `mux.fec.enabled` (`fec-*` runs only)
when configuring the tunnel.

## Safe local validation

The default is a dry-run. It validates the scenario and duration, prints the
resolved plan, does not require root, does not touch an interface, and does not
write a result:

```bash
benchmarks/vmux/run.sh --scenario one-flow --duration 10
benchmarks/vmux/run.sh --list-scenarios
benchmarks/vmux/netem.sh profiles
python3 benchmarks/vmux/parse_results.py build/benchmarks/vmux/*.json
```

CI runs only correctness/smoke checks. Performance thresholds are evaluated
only on the fixed Linux x86-64 benchmark host; laptop, VM, WSL, and shared CI
measurements are diagnostic evidence, not rollout gates.

## Real runs

Use `--execute`, an iperf3 server, an executable `--prepare-hook`, an endpoint
manifest, and telemetry captured from the same run. The manifest identifies
both tested endpoints; use a stable, non-secret device ID and the full 40-hex
commit actually installed on each endpoint:

```json
{
  "client": {
    "platform": "android",
    "device_class": "physical",
    "device_id": "pixel-lab-01",
    "git_commit": "0123456789abcdef0123456789abcdef01234567"
  },
  "server": {
    "platform": "linux",
    "device_class": "physical",
    "device_id": "fixed-bench-01",
    "git_commit": "89abcdef0123456789abcdef0123456789abcdef"
  }
}
```

The manifest is validated before the prepare hook can change tunnel or network
state. The hook receives `scenario mode flows`; it must configure and verify the
real tunnel or return non-zero. The telemetry file supplies measurements iperf3
cannot report, including the configured reorder bounds:

```json
{
  "metrics": {
    "p50_latency_ms": 1.2,
    "p99_latency_ms": 2.7,
    "reorder_depth": 0,
    "buffered_bytes": 0,
    "reorder_entries": 0,
    "active_links": 2,
    "disconnects": 0
  },
  "reorder_limits": {
    "bytes": 4194304,
    "entries": 2048
  },
  "runtime_state": {
    "requested_mode": "flow",
    "effective_mode": "flow",
    "fallback_reason": ""
  }
}
```

```bash
benchmarks/vmux/run.sh --execute --scenario flow-one-flow --duration 10 \
  --server 192.0.2.10 --prepare-hook ./prepare-vmux.sh \
  --telemetry build/vmux-telemetry.json \
  --endpoint-manifest build/vmux-endpoints.json
```

Fault scenarios additionally require root, `ip`, `tc`, `iperf3`, and an
explicit non-loopback `--interface`. `carrier-removal` and `turbo-churn`
require an executable `--hook`; the harness invokes it midway through the run
with the action name. Missing tools, unsafe interfaces, iperf errors, missing
telemetry, and hook failures stop with a non-zero status and no benchmark
result. Do not use the control interface or an interface carrying SSH.

For every non-off matrix result, telemetry `requested_mode` and `effective_mode`
must both equal the scenario mode and `fallback_reason` must be empty. A
negotiated fallback is compatibility evidence, not a result for the requested
scheduler, and is rejected. `off-one-flow` instead requires only
`active_links == 0`; its runtime modes may remain `compat`, and its fallback
reason may be empty or `mux_inactive`.

`netem.sh` applies only to the exact interface argument. It rejects empty,
loopback, option-like, and shell-metacharacter names. Its fixed profiles are:

```text
carrier-delay: delay 40ms 0ms rate 100mbit
carrier-loss: loss random 2% 0% rate 100mbit seed 71214
carrier-loss-0.5: loss random 0.5% 0% rate 100mbit seed 51503
carrier-loss-5: loss random 5% 0% rate 100mbit seed 90512
```

Both `run.sh` and `netem.sh run` install cleanup traps so their qdisc is
removed on success, failure, interruption, or termination. Never run real
fault injection against an interface whose ownership is unclear.

## Result contract

`result.schema.json` defines the versioned JSON contract. The environment fingerprint
hashes architecture, kernel, CPU, and Git commit. The separate configuration fingerprint
hashes the resolved mode, flow count, netem profile,
scenario, and duration. Every result also contains throughput; p50/p99 latency;
reorder depth; buffered bytes; active links; disconnects; and requested,
effective, and fallback runtime state. `parse_results.py` validates every input
before printing per-scenario min/mean/max summaries. Invalid JSON, missing or
wrong-typed fields, and iperf error objects return non-zero.

Old diagnostic schema-v1 results without endpoint attestation remain readable.
Rollout evidence must include physical Linux-client and Android/iOS-client
`off-one-flow` + `flow-one-flow` pairs captured with matching environments and
durations. The rollout gate enforces the 95% throughput and 110% p99 thresholds,
zero disconnects, both reorder limits, Linux x86-64/non-WSL execution, and a
Linux client commit matching the runner checkout:

```bash
python3 benchmarks/vmux/parse_results.py --rollout-gate \
  build/benchmarks/vmux/*.json
```
