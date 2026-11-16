# XTCP platform build notes

> Status: Active
> Type: Design
> Last verified: 2026-10-20 (against root `CMakeLists.txt`, `ppp.vcxproj`, `android/build.sh`, `tools/run_windows_xtcp_loopback_benchmark.ps1`)

## SYN-cookie MAC widening (0054)

Patch 0054 replaces the multiply-mix hash of the stateless SYN cookie with
keyed SipHash-2-4 (128-bit CSPRNG secret) over the full 128-bit addresses,
ports, peer ISN, MSS index and time epoch. The 32-bit cookie ISN is now
`[31..8]` 24 verified hash bits, `[7..3]` a 5-bit time-counter slot masked
with independent hash bits, `[2..0]` the MSS index (now covered by the hash,
so a captured cookie cannot be re-encoded with another MSS). The counter ticks
every 16 s, so the 60 s window accepts at most 5 of 32 slots: blind forgery
drops from about 2^-23 to about 2^-25 per attempt, and cookies can no longer be
replayed one 512 s counter wrap later (the epoch is hashed; `Verify` tries the
current and previous epoch). The freshness window is quantized to the tick: a
cookie within the window is always accepted, one up to about 15 s older may be.
`test_syncookies` and `test_cookie_expiry` cover every verified bit, MSS
authentication, all four IPv6 words, wrap replay and epoch-boundary round trip.

## Core review batch 2 (0052)

Patch 0052 disables WSOPT and SACK-permitted in stateless cookie SYN+ACKs:
the cookie cannot restore either negotiated state. Pool-limited pending TX
uses a 1 ms retry deadline. RST processing requires an exact RCV.NXT match
and otherwise uses the existing rate-limited challenge ACK path. IPv4/IPv6
input is bounded by IP length, GSO keeps CWR only on the first segment and
clears expired URG pointers, and a retransmitted FIN restarts TIME_WAIT.
Regression coverage includes a WSOPT cookie handshake with padded ACK data
and exact/non-exact RSTs in established and closing states. Patch 0053
updates three pre-existing tests (`test_seqwrap_rst`, `test_rst_keepalive`,
`test_window_edge_rst`) that asserted the old in-window-inexact RST close.

PPP additionally checks coroutine post results, bounds HTTP headers to 16 KiB,
makes UDP finalization idempotent and identity-checked, and caps per-session
UDP ports and mux carriers (including the turbo hard maximum) at 1024 each.
The Android fallback now interprets Sendfd's zero result as success; its
blocking connect/recv path (up to approximately 6 seconds) is not redesigned.
Validation results must come from the isolated lab run, not prior batch counts.

## CUBIC epoch wrap hardening (0070)

Patch 0070 hardens `plugins/cc_cubic.cpp`. The connection-migration restore
resets `delivered` to 0 and re-runs the plugin `init`, which already reset
`epoch_base`, so the reported infinite loop is not reachable on that path;
however `init` kept stale `recovery_base`, `cnt` and `wmax`. Init now resets
the whole state, `delivered < epoch_base/recovery_base` re-anchors instead of
wrapping the unsigned difference, and the growth accumulator is clamped to
1e6 and applied as one integer increment instead of a decrement loop. BBRv1
and KCC have no such delivered-minus-base pattern that survives their init.
`test_cc_bbr` gains a delivered-reset case. IDs 0052-0061 stay reserved.

## Core review batch 1 (0050-0051)

Patch 0050 guards overlapping retransmissions while a rejected receive
frontier is retained, reopens the receive window after successful overlap
delivery, and notifies state changes for overlap/retained FIN consumption.
The frontier test adds pending-frontier, overlap-FIN and retained-FIN cases,
including sequence wraparound. Patch 0051 restores stack order before
republishing a residual TX retry FIFO in both shard sweep paths.
Existing patches 0012 and 0043 have context-only refreshes for c9dd560;
patch IDs and their semantic changes are unchanged. The complete stack is
required to apply with `patch -p1 --fuzz=0`.

The associated coroutine fix preserves the explicit Spawn stack size and
rearms the same Anchor after a rejected post without overwriting a newer
anchor. AnchorCell still borrows its io_context/strand: callers must keep
both alive until all asynchronous wake sources are cancelled/drained.
Spawn accepts references/raw pointers, including stack-owned contexts;
converting these to shared_ptr is not a local ownership-safe change.
The server limits each session to 64 FRP mappings (not a configuration key),
locks table access, and disposes/updates snapshots outside the table lock.

Rebase validation (2026-10-18): the new pin passes Linux product, contracts
(188/188), assertion-enabled general tests (179/179), fault (20/20), and full
standalone tests (241/241). Windows x64 static Release builds with zero errors;
both offline tests pass (2/2), and all ten packaged Driver files match. No
Windows client or driver was started or installed.

Runtime acceptance is blocked. The isolated before/after stall campaign
qualifies 160/160 cells, but the three-round P16/P64 DL/UL, one/two-shard,
GSO-off/on matrix qualifies only 83/96. Thirteen cells contain zero-completion
flows: seven before and six after (107/104 individual flows). They occur in
P64/GSO-off uploads on both binaries and shard counts, plus one old-binary
download cell. Positive aggregate throughput and zero all-stream-zero intervals
do not satisfy per-flow completion. Read-only samples show kernel TUN TX drops
and BBR retransmission backoff on both versions; the complete recovery cause
and any rebase-specific contribution remain unverified. Original failures and
additional matched comparisons are retained separately in the local execution
report under `build/plan15/`; no CC, queue, default or feature gate is promoted.

Root cause found (2026-10-18): the zero-completion flows are an upstream xtcp
bug. `BuildSegmentPacket` allowed 4 SACK blocks next to the 12-byte TSopt, so
ACKs for flows with many out-of-order ranges had 48 bytes of options and a
68-byte TCP header; the 4-bit data offset wrapped (17 -> 1) and the kernel
dropped every such ACK, leaving the sender in RTO backoff. A header-only TUN
capture plus a diagnostic build (per-flow ingress/egress counters and the last
output headers; not committed) showed XTCP received every retransmission and
wrote an ACK to the TUN each time, each with IP total length 88 and data offset
1. Patch 0036 sizes SACK blocks to the remaining 40-byte option space (3 with
timestamps, as Linux; 2 with MD5); its `test_sack_option_budget` fails on
upstream main and passes with the fix, and it is upstreamed as
liulilittle/xtcp#2. Patch 0035 separately fixes ACK/window state being cleared
when ACK construction fails on buffer exhaustion; it alone did not remove the
P64 stalls.

P64 UL GSO-off A/B on the shared remote VM, diagnostics off, three alternating
rounds (median Mbps; zero-completion flows summed over rounds, of 64 per round):

| Cell | 0035 only | Zero flows | 0035 + 0036 | Zero flows |
| --- | ---: | ---: | ---: | ---: |
| One shard | 288.2 | 60 | 250.4 | 0 |
| Two shards | 769.2 | 36 | 707.2 | 1 |

The native control ran at 289.7 Mbps with no zero flows. Open items: one zero
flow remains in one two-shard round; aggregate throughput drops 8-13% because
previously stalled flows now compete (retransmissions rise from about 90-106k
to about 152k in the one-shard cell); P16/P64 DL, GSO-on and the stall
campaign have not been re-run with 0036. See XTCP_INTEGRATION_CN.md §11.186.

XTCP is opt-in on Windows and Android. Linux desktop retains its current
default. All platforms use the pinned source in `third-party/xtcp` and the
same production target settings from the root CMake build (revision
`c9dd5601384201b396b1b6599c6c868097da5dcf`). The verified archive SHA256 is
`6a9988d5bf5a039bd9bd0d0c7162e33afc1c60013af10f73abc82d0dc82b2631`.

### Rebase Onto c9dd560 (2026-10-31)

Upstream PRs #3-#8 absorb the main changes from 0037-0040, 0042-0043,
0045-0046 and 0048. Fully absorbed patches 0037, 0038, 0039, 0040 and 0048
are removed. Four smaller integration residuals remain: 0042 preserves the
local timer-deadline assertion; 0043 preserves pending-send-offset waiter
cancellation and unused pacing-tick restoration; 0045 preserves receive-resume
backpressure coverage; 0046 preserves the timestamp anchor across the local
ResumeReceive drain paths. These paths do not exist in the upstream API.
0034 and 0041 no longer modify the upstream timestamp fixture, superseded by
the upstream version and residual 0045. Historical sections below describe
their original patch stacks and measurements, not the current inventory.

Final rebased-stack validation ran only under `/home/ppp-m2/xbump` on the
shared lab machine, with the prescribed build lock, CPUs 0-15 and nice 10:
checksum-enabled ctest passed 246/246 three times; TSan ctest passed 246/246;
`scripts/run-cpp-tests.sh` passed 195/195; the fault suite passed 20/20.
The Release product build completed 335/335 steps; the binary was not launched.
No local compilation or software tests ran. The UL A/B follow-up below supersedes
the earlier pending-adapter status; DL remains unverified.
Evidence: `build/private/xtcp-c9dd560-validation/`.

#### UL Throughput A/B (2026-11-01)

A = main `a9cc7765` (xtcp c1fc9d6, 38 patches); B = main
`2b4d720e16f9534e76c444c9c6e04fef868c0156` (xtcp c9dd560, 33 patches).
Both clean committed trees were built afresh in the lab task directory
`/home/ppp-m2/ab128-20261101/{A,B}`: Release, default CMake feature options
(including SIMD ON), provisioned dependencies from `/home/ppp-m2/deps`.
Each build completed 335/335 actions under
`flock /tmp/ppp-m2-build.lock taskset -c 0-15 nice -n 10`, maximum -j16.
No local build or software test ran. Root free space stayed at least 42 GB.

The approved wrapper below imports the original `/home/ppp-m2/measure.py`,
rebinds ROOT/BIN/OUT and verification metadata only, then calls unchanged
`run()`. Controller SHA256 before/after:
`33776f7465797e67b39144263b6a8d2af819b3df58e7536f745626e442264d9b`.
UL only: 64 KiB xtcp sndbuf, P1/P16/P64, native then xtcp, client-single-core
CPU49 from the existing cpu-choice, 10 s duration, 2 s omit, AES-256-CFB,
GSO on/32 segments, one shard, KCC, memory bridge, GRO 12288 and gather 61440.
These are driver defaults, not an unrestricted default-runtime or DL test.
The wrapper was invoked through the repository's existing
`B/tools/run_m3_isolated.sh --run-dir TASK -- python3 TASK/wrapper.py`
under taskset 0-15 and nice 10. The driver applies its own client affinity
and measurement/build locks; no host routes, DNS or other processes were changed.

Two complete ABBA rounds yielded four accepted samples per version per cell.
Within each version the lists below are chronological: round 1 first/second
appearance, then round 2 first/second appearance. Delta uses unrounded medians.
The planned third round was stopped while waiting for idle, before any flow,
to keep the approximately one-hour budget; the wrapper's range(1, 4) is retained
verbatim, not a claim of three completed rounds.

| Stack / P | A runs (Mbps) | B runs (Mbps) | Median A | Median B | B/A - 1 | Range/median A; B |
|---|---|---|---:|---:|---:|---:|
| xtcp / 1 | 1101.63, 1072.12, 1062.91, 1074.33 | 1023.67, 1102.54, 1081.04, 1083.60 | 1073.22 | 1082.32 | +0.85% | 3.61%; 7.29% |
| xtcp / 16 | 984.45, 980.93, 974.66, 980.25 | 974.30, 994.46, 961.40, 966.78 | 980.59 | 970.54 | -1.03% | 1.00%; 3.41% |
| xtcp / 64 | 874.78, 783.45, 837.81, 854.17 | 835.88, 778.53, 865.10, 861.45 | 845.99 | 848.66 | +0.32% | 10.79%; 10.20% |
| native / 1 | 1104.33, 1087.31, 1096.22, 1100.69 | 1076.16, 1111.93, 1112.89, 1103.61 | 1098.45 | 1107.77 | +0.85% | 1.55%; 3.32% |
| native / 16 | 1066.16, 1079.62, 1083.66, 1076.25 | 1095.38, 1066.82, 1065.01, 1093.23 | 1077.94 | 1080.02 | +0.19% | 1.62%; 2.81% |
| native / 64 | 936.28, 916.72, 878.67, 915.86 | 896.85, 877.22, 883.32, 903.01 | 916.29 | 890.09 | -2.86% | 6.29%; 2.90% |

All 48 accepted cells passed qualification with zero zero-rate flows.
Every accepted invocation exited 0, restored namespace listings and retained
its binary hash. Three excluded invocations were preserved: A attempts 1/2
failed before traffic (required isolation entry; then missing Git provenance,
fixed by importing actual commit history); B round-1 position-2 attempt-1
failed native qualification for PPP/iperf CPU migrations, with zero zero-rate
flows, and was rerun successfully as attempt-2. No failed invocation contributes
to the table. SIGINT did not stop the third-round idle wait; TERM ended only
this wrapper, with no active runner, and the isolation entry cleaned up.

Conclusion: no clear throughput change beyond observed run-to-run noise in
these UL cells. xtcp changes are +0.85%, -1.03%, +0.32%, versus within-version
ranges of about 1-11%; native controls also vary. This is not proof of
equivalence or a guaranteed <=3% regression bound. DL, other send buffers,
long-duration stability and other platforms were not measured.
Binary SHA256 A:
`c93c36ec4a1bf57c6efbc1cfa10a6f14e11666f800b0fbfea07d5ba0efb078cf`;
B: `a3497b27472000ff6cb8c55ac883f7115b44aad2ce347bd2dcc45cd06146257c`.
Private evidence: `build/private/xtcp-c9dd560-ab/{evidence.tar.gz,summary.txt}`.
The evidence archive contains the exact wrapper, logs, raw per-cell results,
qualifications and completion/provenance records; it is not a public fixture.
Remote task build/source directories were removed after evidence retrieval.

Approved wrapper, verbatim (including retry/resume handling):
```python
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, '/home/ppp-m2')
import measure as m

TASK = Path(__file__).resolve().parent
original_verify = m.verify

def verify():
    metadata = json.loads((m.ROOT / 'ab-manifest.json').read_text())
    for name, digest in metadata['files'].items():
        assert m.sha(m.ROOT / name) == digest, name
    return dict(metadata, binary_sha256=m.sha(m.BIN),
                controller_sha256=m.sha(Path(m.__file__)),
                ordered_runner_sha256=m.sha(m.BASE / 'ordered-runner.py'))

m.verify = verify
m.OUT = TASK / 'runs'
cpu = json.loads((m.BASE / 'cpu-choice.json').read_text())['cpu']
for version in ('A', 'B'):
    root = TASK / version
    files = {str(p.relative_to(root)): m.sha(p) for p in root.rglob('*')
             if p.is_file() and p.name != 'ab-manifest.json' and not any(x in p.relative_to(root).parts
                                       for x in ('build', 'bin', '.cache', '.git'))}
    (root / 'ab-manifest.json').write_text(json.dumps(dict(version=version,
        commit={'A': 'a9cc7765', 'B': '2b4d720e'}[version], files=files)))
for round_no in range(1, 4):
    for position, version in enumerate('ABBA', 1):
        m.ROOT = TASK / version
        m.BIN = m.ROOT / 'bin/ppp'
        for attempt in range(1, 4):
            assert int(m.cmd(['df', '--output=avail', '-BG', '/']).splitlines()[-1].strip().rstrip('G')) >= 20
            name = f'round-{round_no}/{position}-{version}-attempt-{attempt}'
            if (m.OUT / name / 'completed.json').exists():
                previous = json.loads((m.OUT / name / 'completed.json').read_text())
                if previous['exit'] or previous['runtime_faults']:
                    continue
            try:
                m.run(name, cpu, parallel='1,16,64')
                break
            except RuntimeError:
                completed = m.OUT / name / 'completed.json'
                if not completed.exists():
                    raise
                result = json.loads(completed.read_text())
                if not result['cleanup_ok'] or not result['runtime_faults'] or attempt == 3:
                    raise
```

### Rebase Onto c1fc9d6 (2026-10-29)

Upstream serializes backend TX, including closed-port RST emission, and adds
`test_ndi_tx_concurrency`. None of the 38 local patches is absorbed by this
update. All sparse IDs remain unchanged; 0037 and 0038 remain local while
[xtcp#3](https://github.com/liulilittle/xtcp/pull/3) and
[xtcp#4](https://github.com/liulilittle/xtcp/pull/4) are pending.

Every patch was regenerated against its predecessor on the new tree. The
0031 CMake hunk now includes upstream's new NDI test. A fresh, checksum-verified
archive accepts the entire series in filename order with `patch -p1 --fuzz=0`,
without offsets. In the full series, 0039/0040/0042/0043 retain their preceding
local APIs and fixtures. Their standalone upstream submissions need separate
adaptation: pool reserve uses upstream's send/flush interfaces; fair waiters
build on that pool branch without local burst-pacing or timer-deadline APIs;
timestamp coverage uses upstream's established/closing receive paths without
the local `ResumeReceive` API. The full local series retains resume coverage.
Comparing old-pin/full-series and new-pin/full-series trees changes only the
four upstream paths (CMake, `stack.h`, `stack.cpp`, and the new NDI test).

All compilation and runtime validation takes place on the lab host, in a new
task directory, under the shared build lock, CPUs 0-15, nice 10, and at most
16 build jobs. Release with tests and checksum validation passed 246/246 in
each of three rounds (738/738). The documented fully instrumented XTCP TSan
workflow passed 246/246 with no race or lock-order warnings. Historical
sections below retain their original revisions and measurement conditions.

The standalone C++ Release run with `ENABLE_XTCP_TESTS=ON` passed 200/201;
`spinlock_test` exceeded its existing 120-second watchdog. That target links
Threads/OpenSSL and SpinLock/diagnostics sources, without XTCP; those files
and its build definition are unchanged by this bump. This initial timeout
is retained in the evidence rather than reported as an all-green C++ run.
A focused `spinlock_test` recheck also timed out at 120 seconds (0/1).
The unmodified upstream Release/checksum control passed 239/240, failing only
the original fixed-timestamp `test_ts_ooo_drain` fixture.

Standalone upstream candidates each have one local commit above their stated
base: pool reserve (0039+0040), fair waiters (0042+0043, based on the pool
branch), timestamp gap fill (0045+0046), and TX retry shard direction (0048).
Release/checksum ctest results are respectively 240/241, 240/241, 240/240,
and 239/240. The only failure on the three non-timestamp branches is the
same original `test_ts_ooo_drain` failure as the upstream control. Every
candidate's own regression passes. English drafts and branches are retained
in `build/private/xtcp-upstream-next/`; none was pushed or submitted.

Default-runtime A/B compares main `43fab3e455f49e14d868e56a77aa172a051b71cd`
(old pin/full stack) with the same source plus this pin/rebase. Two rounds
cover DL/UL P1/P16/P64, 30 seconds per cell, omit 2 seconds; main runs first
in round 1 and candidate first in round 2. Both use CPUs 0-15, client
concurrency 1, AES-256-CFB and GSO on. Shard, sndbuf, GRO, gather and CC tuning
overrides are omitted, retaining runtime defaults (one shard, 1 MiB sndbuf,
KCC, memory bridge on). Runs use the shared `measure.py` guard/run functions,
private net/mount namespaces and host kernel steering off. Actual launch
arguments are retained alongside the shared controller's nominal arguments.

Mbps; change is the ratio of the two-round arithmetic means:

| Cell | Main Round 1 / 2 | c1fc9d6 Round 1 / 2 | Mean Change |
| --- | ---: | ---: | ---: |
| DL P1 | 1790.274 / 1720.156 | 1794.289 / 1787.338 | +2.03% |
| DL P16 | 1798.941 / 1746.454 | 1763.215 / 1765.175 | -0.48% |
| DL P64 | 1879.607 / 1877.860 | 1904.598 / 1834.660 | -0.48% |
| UL P1 | 1483.673 / 1453.640 | 1455.579 / 1447.325 | -1.17% |
| UL P16 | 922.902 / 981.997 | 949.114 / 999.827 | +2.31% |
| UL P64 | 537.286 / 554.939 | 563.268 / 565.549 | +3.35% |

All 24 cells pass, with zero zero-rate flows, no runtime faults, unchanged
binary hashes and successful namespace cleanup/monitoring checks. Two rounds
on a shared host do not prove statistical equivalence or gains from any
individual upstream candidate. Those candidates have no separate throughput
A/B or TSan run. Windows, mobile platforms and production-network behavior
remain unverified. Evidence is in `build/private/xtcp-c1fc9d6-validation/`;
the task's remote build directories were removed. No main-repository commit,
push or PR submission was made.

Rebase onto upstream f71548f (2026-10-25): upstream added KCC v2
(kernel-faithful delivery/recovery), CA state-machine, RACK/SACK/undo/RTO
fixes, O(1) pipe queries and SIMD copy+checksum, and merged former local 0036
(liulilittle/xtcp#2), whose patch file is removed. The remaining 26 patches
keep their IDs. Adapted during the rebase: 0004 (keeps upstream's
app-limited marking at the send entry), 0012 (rate-change telemetry is now
sampled after the ACK flush, which upstream moved behind the CC hook), 0023
(offset-aware pending-send accessors in the new upstream app-limited check,
ACK flush and fast-open paths), 0026 (KCC v2 no longer aggregates per-round
samples; `round_sample_*` telemetry fields stay and report 0) and 0034 (new
upstream tests follow the timestamp-aware payload cap and burst pacing).
Offline ctest (WSL GCC 12, Release, checksum validation, -j1): upstream main
238/239, rebased 241/243. Both fail `test_ts_ooo_drain` (also failing on the
old pin). The rebased tree initially failed the KCC ECE assertion in
`test_ecn_cc`. Investigation showed that upstream passed only by coincidence. Under
the frozen virtual clock, per-segment pacing sends one segment per round after
warm-up. KCC's max-bandwidth filter then ages out and cwnd falls to the floor
(90 -> 4) on the same ACK *without* ECE as well. With 0005 burst pacing, the
bandwidth model stays fresh and cwnd stays at the BDP target. This legacy
BBRv1-style KCC port has no ECN model response beyond `tcp_enter_cwr` running the pass-through
`ssthresh` hook (`tcp_cong_control` returns early for `cong_control`), so the
port's only effect is the clamp to that threshold (178 > 90 here). 0034 now
asserts that contract with seeded twin runs: the threshold is real, cwnd <=
threshold after the ECE ACK, and the ECE window is <= the plain-ACK window. The
wire-level CUBIC case still proves that a CE mark cuts cwnd under burst pacing.
New patch 0037 (`0037-rcv-mss-immediate-ack.patch`) makes the receiver ACK at
once when one in-order segment carries more than the advertised MSS (1460).
This matches Linux `__tcp_ack_snd_check`, whose `rcv_nxt - rcv_wup > rcv_mss`
test counts bytes. Before 0037, a GRO/LRO super-segment counted as one segment
and waited for the 40 ms delayed ACK. `test_rcv_mss_ack` fails without the fix
and passes with it. This is an upstream receiver behavior: 0005 itself emits
only segments no larger than the MSS. Final stack (27 patches): 243/244, with
only `test_ts_ooo_drain` failing. See XTCP_INTEGRATION_CN.md §11.187.

Patch 0038 (`0038-kcc-cwnd-ack-aggregation-quantization.patch`) restores cwnd
headroom in KCC v2. Upstream KCC v2 caps cwnd at `cwnd_gain * max_bw * min_rtt`.
On the OpenPPP2 tun path, min_rtt is about 35-90 us, but ACKs arrive in batches.
With a 1 MiB snd_buf, P4/P16 DL cwnd collapsed to 2-12 packets: DL fell from
about 1.9 to 0.85 Gbps. 0038 adds the Linux `bbr_set_cwnd` ack-aggregation
term (`extra_acked`) and quantization budget to the cwnd target, and mirrors
them in `plugins/ref/kcc_core.c`. Remote A/B (1 MiB, 2 passes, 20 s): P4 DL
0.89/0.84 -> 2.11/2.19 Gbps and P16 DL 0.79/0.89 -> 1.88/1.83 Gbps; P1 is unchanged.
The 1 MiB P64 DL wedge was a separate issue that 0038 does not fix; 0039
fixes it. The fixed xtcp packet pool (2K x 8192 + 4K x 4096 + 32K x 128,
about 36 MiB) was shared by unACKed transmit retention and by ingress. When
active flows x snd_buf exceeded it (64 x 1 MiB; with the 64 KiB default,
about 500 or more busy flows), retention took every block. Ingress copies in
`XtcpRuntime::Submit`, including the pure ACKs that would free retention, then
failed (`ingress_drop_reason.buffer`). All flows stayed blocked on
`sndbuf_quota` and the tunnel never recovered.

Patch 0039 (`0039-pool-tx-reserve-and-bounded-heap-overflow.patch`) splits
the pool, much as the kernel separates `tcp_memory_pressure` /
`sk_wmem_schedule` from receive:

- New data segments (SendData direct path and FlushPendingSend) are built
  inside `buf::TxAcquireScope`. In that scope a tier at or below 1/8 of its
  blocks is skipped and the heap overflow is never used. A denied segment
  stays in `pending_send_` (bounded by snd_buf), and the dirty poll flushes
  it after ACKs free blocks.
- Every other acquisition (ingress, ACKs, control segments,
  retransmissions and MTU splits) still uses the full pool. When every
  fitting tier is empty, it gets a block from a bounded heap overflow
  (`kHeapOverflowCapBytes` = 8 MiB in total, blocks freed on release).
- `buf::GetPoolPressureStats()` reports TX deferrals and overflow
  acquires, denials, current bytes and peak.

Nothing changes while every tier is above its reserve. OpenPPP2 code is
unchanged.

Patch 0040 adds `test_pool_pressure`. It checks three things: TX stops at the
reserve and ordinary acquisitions still succeed; the overflow is capped, never
used by TX, and fully returned; and 1600 connections retaining more than the
arena still get ACK buffers and all finish. Full ctest: 244/245 locally and
remotely, with only `test_ts_ooo_drain` failing (pre-existing).
`test_sack_gap_edge` is timing-flaky on the base stack as well. Its
pool-pressure counters stay at zero, so the new gate never fires there.

Remote A/B against the #106 binary: 1 MiB P64 DL passed 3/3 (1345, 1481 and
1181 Mbps; zero-rate flows 0; `ingress_dropped` 0). The old binary hit the
watchdog. 2 MiB P64 DL passed at 1384 Mbps. P1/P4/P16 DL+UL at 1 MiB and
64 KiB, 2 alternating passes, stayed within noise. 64 KiB P64 UL hits the
iperf watchdog on both old and new binaries, so it predates this change.
See XTCP_INTEGRATION_CN.md §11.188 for the table and residual risks.

### Sustained pool pressure and per-flow starvation (2026-10-28)

Patch 0039 prevents the ACK-ingress wedge, but does not make TX admission
fair. A busy connection can consume released blocks in its ACK callback
before a connection with no data in flight is polled. Polling still happens:
in the new default-buffer P64 DL diagnostic, six zero-rate flows had open
peer windows, adequate cwnd, zero inflight and tens of thousands of flush
attempts, while their ACKed bytes stayed unchanged. Aggregate pending-flush
allocation failures exceeded 116,000 in a one-second sample. This is
allocation starvation, not a missing per-connection timer or a cwnd collapse.

The lab campaign uses main `7766d87f` (including #111 tooling), one shard,
GSO on, 30 s plus 2 s omit, and the default 1 MiB send quota. All cells use
the shared measurement/build locks and idle guard, private network/mount
namespaces, and `--kernel-steering off`. Diagnostic controls:

| Binary / snd_buf | P64 DL Mbps | Zero-rate flows |
| --- | ---: | ---: |
| main / default 1 MiB | 1630 | 6 |
| main / 256 KiB | 1535 | 0 |
| main / 64 KiB | 1439 | 0 |
| #115 `0091600e` / default 1 MiB | 1681 | 8 |
| main without 0039/0040 / default 1 MiB | watchdog at 62 s | no completed result |

Thus #115's half-close and GSO FIN fixes do not resolve this starvation.
Rechecking the earlier poolfix artifacts confirms zero-rate counts 0/0/0;
however, pass 2's slowest flow was only 52,251 bit/s (max/min 746).

Patch `0042-tests-pool-release-without-own-ack.patch` checks restart through
the real stack timer sweep after unrelated pool users release memory, with
no data ACK available to the waiting connection. It passes on the old stack.
Patch `0043-fair-tx-pool-waiters.patch` adds an intrusive waiter per connection.
After 256 consecutive allocation denials, later TX attempts reserve up to 32
arena blocks for each older eligible waiter before refilling the caller. Successful
allocation resets the denial count, preserving existing admission for brief
pressure. Unavailable large tiers do not block MSS requests. A flush returns
unused burst blocks when it stops, retaining at most one protected packet
across a window/pacing stop. Close, destruction and an empty pending buffer
cancel it. Burst metadata is allocated lazily; packets stay in the arena.
An atomic release/acquire handoff publishes an unlinked, fully populated
grant to its connection. That owner consumes the burst without taking the
global queue mutex for every packet; queue mutation, publication and
cancellation remain protected by the mutex. Acquire/Cancel on the same
connection remain serialized by the caller.

Fair admission alone was insufficient. An aged single-packet candidate still
had three iperf zero-rate flows: ACKs advanced occasionally, but KCC pacing
fell as low as 11 kbit/s, below iperf's complete-read reporting threshold.
When allocation fails with an empty pipe or an aged waiter, the connection
marks newly emitted delivery as locally limited using the existing
app-limited mechanism. Brief pressure with data in flight keeps the existing
sampling behavior. The watermark
includes current packets in flight; existing segments keep their send-time
flags. The bandwidth
estimator already rejects lower limited samples and accepts higher ones;
its policy is unchanged. Earlier immediate-FIFO/burst candidates were rejected for
zero-rate flows or throughput loss; their artifacts remain available.
The adjacent P64 gates rejected `fixed5` (64-denial, 32-packet, no sampling
fix: zero flows 1/0, mean throughput +10.9%), `fixed7` (64-denial, one-packet,
sampling fix: 2/0, -20.3%), and `fixed8` (64-denial, 32-packet, sampling fix:
0/0, -12.5%). `fixed9` (512-denial, 32-packet, sampling fix) had 1/0 zero
flows and -0.5% mean throughput. The 256-denial threshold reduces interference with ordinary
ACK-clocked bursts; it is an allocation-attempt count, not a time guarantee.
`fixed10` (256-denial, empty-pipe-only sampling fix) still had 1/3 zero
flows despite +0.3% mean throughput; its diagnostic captured pacing collapse
with an open window and no retransmissions. The final sampling fix also
covers partial inflight allocation failure, with a failing KCC regression.

Allocation failure additionally restores a newly opened pacing tick's prior
deadline if that tick has not emitted any packet. The old flush prepaid wire
time before construction, so a memory denial could repeatedly delay retries
despite transmitting nothing. Ticks that already emitted data retain their
deadline. A regression releases one arena block and polls at the same time,
without a data ACK: it fails before this correction and sends afterward.
`fixed12` eliminated zero flows in both adjacent P64 passes, but lost 2.6%
mean throughput and was rejected before the grant-consumption optimization.
`fixed13` also had zero flows 0/0 but lost 1.9% mean throughput. Restricting
the sampling marker to an empty pipe or an aged waiter preserves the healthy
ACK clock; the regression verifies brief and sustained pressure separately.

The intermediate `fixed14` adjacent P64 gate passed: main 1865/1845 Mbps with 5/7
zero flows; fixed 1877/1839 Mbps with 0/0 zero flows. Mean throughput changed
by +0.17% (within shared-host noise); the slowest fixed flows were 2.41/1.64
Mbps. This is progress protection, not equal bandwidth or a time guarantee.
Its complete two-pass matrix had zero flows in every fixed cell, but DL P16
mean throughput fell 2.06% (DL P1 -0.61%, P4 +0.73%, UL P16 +1.62%). The final
candidate moves the new waiter to the end of the connection to preserve
existing hot-field offsets, and constructs successful arena results directly
instead of returning an intermediate buffer. A local no-pressure allocation
microbenchmark improved from about 23 to 19 ns/op (base about 16 ns/op); only
product A/B determines the performance result.

Final adjacent A/B (`fixed15`, same default 1 MiB, one shard, GSO on,
30 s plus 2 s omit; main/fixed then fixed/main for each cell), Mbps:

| Cell | main pass 1 / 2 | fixed pass 1 / 2 | Mean change | Fixed zero flows |
| --- | ---: | ---: | ---: | ---: |
| DL P1 | 1843.887 / 1776.111 | 1788.836 / 1791.773 | -1.09% | 0 / 0 |
| DL P4 | 1604.565 / 1530.884 | 1561.787 / 1631.617 | +1.85% | 0 / 0 |
| DL P16 | 1722.853 / 1757.070 | 1735.679 / 1725.893 | -0.53% | 0 / 0 |
| DL P64 | 1832.526 / 1855.350 | 1878.478 / 1840.705 | +0.85% | 0 / 0 |
| UL P16 | 878.541 / 909.122 | 979.844 / 909.890 | +5.71% | 0 / 0 |

Main P64 had 7/3 zero flows; the slowest fixed P64 flows were 0.769/0.699
Mbps. P1/P16 have small negative point estimates; main's pass-to-pass
variation was 3.7%/2.0% respectively. Two passes on a shared host do not
establish statistical performance equivalence. All 20 cells completed with
cleanup and monitoring checks passing, no remaining private netns, and no
disk-guard stop. All ten fixed cells had no runtime qualification faults and
the same binary SHA-256:
`e9f100193d18d01eaa7f25c99b7342d28d982c6157b0a60aadc8b90e762a01db`.
Ingress, controls, retransmissions, the 1/8 reserve and the 8 MiB overflow cap
retain their existing allocation rules. With no waiters and no pool pressure,
TX takes the existing arena path without the waiter mutex.

The overtaking regression fails before 0043 and passes after it. Tests also
cover queue order, cancellation of queued/reserved waiters, mixed sizes,
brief-pressure admission, retaining one grant across a closed window, and
the existing 1600-connection completion scenario. A separate regression
holds ACKed wire buffers to force allocation failure with KCC attached, both
with data in flight and after the pipe drains; the delivery marker fails to
advance before the fix and advances afterward.
Eight concurrent senders also exercise grant publication, consumption and
cancellation under pressure. TSan compiled, but its runtime stopped before
the test with `unexpected memory mapping`; it provides no race-check result.
The complete patch series
applies to a fresh pinned archive with `patch -p1 --fuzz=0`. Full CTest is
243/245 on the initial baseline; `test_ts_ooo_drain` fails consistently and
`test_sack_gap_edge` is timing-flaky. The current candidate passed 244/245,
with only the existing `test_ts_ooo_drain` failure. Ordinary PIE ASan/UBSan binaries intermittently crashed at startup
or timed out with repeated `DEADLYSIGNAL` output; bounded churn repeats also
timed out on the unmodified baseline. Disabling the ASan SIGSEGV handler did
not make these runs stable. A separate non-PIE Debug build
(`XTCP_SANITIZE=ON`, `CMAKE_CXX_FLAGS=-fno-pie`,
`CMAKE_EXE_LINKER_FLAGS=-no-pie`, default ASan signal handling) passed the
pool-pressure, MPSC TX-retry and connection-churn tests 3/3 with 45 s limits.
Artifacts:
`/home/ppp-m2/starve-20261028/` (diagnostics under `runs/diagnostic/`, including
rejected candidate `fixed`; final A/B under `runs/qualified-fixed15/`).
`qualification-fixed15.json` and `summary.json` contain the metric summaries;
`manifest-fixed15.json` freezes the common main runner, while
`source-manifest-fixed15.json` and the XTCP patch stamp identify the variant
source. Validation logs are under `validation/`; local logs are also retained
under `/tmp/starve-xtcp/`. GitHub cloning failed, so frozen Git archives were
transferred using the authorized fallback. No host network settings were
changed. Windows and mobile runtime behavior was not tested in this campaign.

Patch 0044 (`0044-kcc-bbr2-ecn-response.patch`, 2026-10-29) adds an actual
KCC ECN model response, superseding the limited ECE contract described above.
The FSM counts newly delivered packets on ECE ACKs, including SACK delivery,
the first sample and same-tick ACK batches; duplicate ACKs add no delivery.
Rate samples carry the cumulative count and the negotiated-ECN gate.
At packet-timed round boundaries, KCC computes the marked fraction and updates
Q8 alpha using the Linux BBRv2 formula: `(240 * alpha >> 8) +
(16 * fraction >> 8)`, with alpha initially 256 and gain 1/16.
A round with more than 50% marked delivery tightens `inflight_hi` and the
bandwidth-probing ceiling by `1 - ((alpha * 85) >> 8) / 256`; 100% marks
initially bound 100 packets to 66, rather than Reno's 50. The cwnd floor is
four packets. Congestion ends upward probing and exits STARTUP through DRAIN;
low-marked PROBE_UP rounds permit additive ceiling recovery. Both regular and
idle-restart pacing obey the ceiling. No marks leave both ceilings unbounded;
unnegotiated connections bypass the ECN model. Loss hooks and recovery remain
unchanged.

This ports BBRv2's ECN estimator and proportional bounding into KCC's existing
cycle, not its entire PROBE_BW state machine. BBRv2 applies its alpha/factor
bound to `inflight_lo`; this KCC adaptation uses the requested `inflight_hi`
and bandwidth ceiling. Reference: Google's
[tcp_bbr2.c](https://github.com/google/bbr/blob/v2alpha/net/ipv4/tcp_bbr2.c),
`bbr2_update_ecn_alpha` and `bbr2_adapt_lower_bounds`.
The receiver retains RFC3168 sticky ECE/CWR feedback: the fraction measures
packets delivered on ECE ACKs, not exact router CE prevalence. Accurate DCTCP
CE-transition feedback, RTT eligibility policy and the full BBRv2 state machine
are outside this patch.

`test_ecn_cc` now checks 0%, 10%, 50% and 100% fractions, the negotiation gate,
same-round suppression, subsequent-round EWMA and decay to zero. Its seeded
FSM twins require a strict marked-vs-unmarked KCC window reduction, and equal
windows for unnegotiated twins. ACK-accounting tests cover first samples,
same-tick mixed ECE ACKs and duplicate ACKs; existing CUBIC wire tests remain.
Validation and A/B evidence are recorded in XTCP_INTEGRATION_CN.md section
11.190.

The lab's Release/checksum-enabled XTCP CTest passed 245/245; the assertion-enabled
`tests/cpp` suite passed 191/191. Resume validation matched the final patch and
tested sources and replayed all 34 patches with `patch -p1 --fuzz=0` in a new
lab directory; no local builds or tests were run during the resume.
The completed 24-cell default-config A/B used frozen task baseline
`bfd5b88101943ba370bb9f04858af54787a5a461` versus that baseline plus 0044,
with two rounds in opposite variant order. Mean throughput changes for
DL P1/P16/P64 were +2.31%/-1.38%/+0.22%; UL changes were -0.45%/+8.38%/-2.09%.
All cells passed with no zero-rate flows or runtime faults. This small shared-host
sample shows no clear default-path regression, not statistical equivalence.
The default integration does not enable ECN negotiation; this measures the
non-ECN path without injected CE. Negotiated zero-mark behavior is unit-tested;
real marked-network convergence, fairness and recovery remain unverified.
Measurements used the shared `/home/ppp-m2/measure.py` guard/run functions with
private network/mount namespaces and host kernel steering disabled. Task build
directories were removed; logs and frozen sources were retained. Windows,
mobile and sanitizer validation were not performed. No commit or push was made.

The current local series has 33 patches with stable, sparse IDs: 0001-0015,
0023, 0025-0029, 0031-0035 and 0041-0047 (0035: retry ACK/window construction after
allocation failure; 0037-0040 and 0048 are now upstream; former
0036, SACK blocks fit the option space, is upstream as liulilittle/xtcp#2 and
its ID is not reused). Upstream absorbs former local 0016 (PSH tail),
0017 (loss-test helpers), 0018-0022 (KCC), 0024 (pool counts), and 0030
(duplicate-ACK classification). Their local patch files are removed; this
rebase introduces no new KCC policy, pool sizing, bridge or GSO defaults.

Patch 0041 aligns `test_sack_gap_edge` with the 1448-byte timestamp-aware
payload cap and makes its loss injector track every first-sent byte range, so
retransmissions do not change the drop cadence. The two-gap profile checks the
actual retransmitted ranges against observed SACK blocks instead of inferring
them from the aggregate retransmit counter. It also derives `test_ts_ooo_drain`
timestamps from the live handshake to avoid PAWS rejecting stale synthetic
TSvals.

### Timestamp drain and TSan follow-up (0045-0048)

The original upstream `f71548f` OOO timestamp test injects fixed TSvals
`0x10000001/2`. On a sufficiently advanced monotonic clock these precede the
handshake timestamp in TCP serial arithmetic, so PAWS correctly drops the
synthetic data. On the lab host, the upstream test failed three assertions;
using the live timestamp derivation already present in 0041 passed against
the unchanged upstream library.
The pre-0045 patch series' unchanged OOO test passed 30 consecutive runs.
Thus the reported vendored failure was not reproduced with a fresh
extraction of that series. The upstream library also passed 30 consecutive
runs with the pre-0045 fixture (0034 ACK capture and 0041 clock derivation).

0045 also fixes the fixture's ACK capture: record the probe's ACK inside the
pump instead of separately draining the same queue, track ACK presence rather
than treating sequence zero as invalid, and use the established peer ACK
number. After switching to synthetic peer data, do not forward its ACKs into
the real sender, which never sent those bytes. The checked receive callback
allows explicit application backpressure.

The old assertion itself concealed a stack bug: draining cached OOO data
replaced TS.Recent with that data's timestamp. A newer retransmission filling
the hole could therefore be followed by a backwards PAWS anchor and acceptance
of stale data. [RFC 7323 section 4.3(C)](https://www.rfc-editor.org/rfc/rfc7323.html#section-4.3)
requires echoing the hole-filler's timestamp. Linux v6.6
[`tcp_replace_ts_recent` and `tcp_ofo_queue`](https://github.com/torvalds/linux/blob/v6.6/net/ipv4/tcp_input.c)
likewise anchor on reception, not cached-data delivery. 0046 preserves that
anchor through established/closing drains and ResumeReceive, and applies the
arrival update to closing states as well, including timestamped pure FINs.
The regression also rejects a stale pure FIN and checks the valid FIN's
timestamp echo in both connection states. It does not redesign unrelated
delayed-ACK timestamp selection. The new regression checks both the echo and
PAWS rejection in Established and FIN-WAIT-2, with and without backpressure:
all four cases fail four assertions against the old library (16 total,
including pure FIN checks) and pass after 0046.

The pre-0047 TSan control failed all three selected fixture tests: one map
data race and lock-order inversions in both fake NIC tests. 0047 fixes the
test data race (`crc_b.size()` read concurrently with the pump's map
insertion) and makes the single-thread
TSO/backpressure fake NICs queue accepted packets until the pump delivers
them, following `test_tx_retry_mpsc`. Synchronous cross-stack delivery had
created reverse lock-order graphs. No additional TSan suppression is added;
TSO, rejection, metadata, and byte-delivery assertions remain enabled.

This fixture change exposed a real TX routing bug: `ShardOfPacket`, called by
`RetryBatchSharded` for outgoing qdisc/DMA rejections, reversed the wire tuple
as if it were receiving. 0048 uses source=local, destination=remote. The
regression checks 64 IPv4 plus 64 IPv6 flows against their connection-ID shard
(113/128 mismatched before the fix) and retains the backpressure fixture's
attribution check through final delivery. This changes retry placement, not
the RX lookup, shard count, or congestion-control policy.

Final 0045-0048 validation (2026-10-29) ran only on the shared lab host:
Debian Linux 6.12.73 / GCC 14.2, `vm.mmap_rnd_bits=28`. Normal XTCP CTest
passed 245/245 in each of three full rounds of the final source, including
pure FIN (plus one passing round before that addition). Fully instrumented
XTCP TSan passed 245/245 without warnings; `test_shard`,
`test_conn_churn_threads`, `test_thread_data`,
`test_thread_send_abort`, and `test_tx_retry_mpsc` each passed five TSan runs
(25 invocations). All 37 patches apply in order with `patch -p1 --fuzz=0` to
a fresh prepare extraction, whose sources match the tested tree. ECN 0044 was
not present and is not included in that verification.

The modified standalone C++ TSan script passed 201/201 targets with XTCP
enabled, followed by five runs each of the six M3 targets listed in the
testing guide (30 invocations). Its build used `-O1 -g1 -DNDEBUG`; the XTCP
suite used the normal RelWithDebInfo flags. The existing libcrypto suppression
was retained for C++ tests; no new suppression was added, and the XTCP suite
used none. All acceptance sanitizer runs used `setarch -R`.

The startup diagnostic ran the current SPSC test five times in each of four
PIE/non-PIE and ASLR on/off combinations: all 20 invocations passed all seven
groups on this lab host. This does not reproduce the older WSL startup
failure. Local read-only inspection confirmed WSL2 6.6.87.2 with
`vm.mmap_rnd_bits=32` and ASLR enabled; no local build, test, or sanitizer
was run during this resume. No host sysctl was changed. Logs and commands
are retained locally under `build/private/ts-ooo-tsan-20261029/`; all build
directories created by this task on the lab host were removed afterward.

See [the TSan workflow](../development/TESTING.md#threadsanitizer) for both
instrumented suites and the WSL ASLR startup diagnosis. These are isolated
unit tests; no VPN client, privileged network E2E, lab throughput measurement,
Windows or mobile runtime was exercised.

Upstream owns OOO frontier reclamation. Residual 0013 retains
`drained_gap |= TrimOooToFrontier()` for the local ACK integration and the
rejected receive-callback/resume scenario. Patches 0014/0015 preserve
backpressured OOO and in-order frontier data. Patch 0031 preserves both
upstream CLOSE-WAIT notifications while restoring FIN-first ordering after
0005; its focused regression covers 16 callback/close/wrap scenarios.
Patch 0034 retains nine local-semantic test adaptations (including the
`test_ecn_cc` KCC ECE contract). Patch 0027 only
needs a context repair during this rebase; its behavior is unchanged.
Historical revisions, binary hashes and measurements below retain their
original provenance. See the separately dated migration record in
[the Chinese integration notes](XTCP_INTEGRATION_CN.md), section 11.185.

## Direct Bridge Policy (2026-10-18)

For XTCP sessions on Linux desktop/server builds (`__linux__`, excluding
Android), an unset or empty `OPENPPP2_XTCP_MEMORY_BRIDGE` now tries the direct
memory bridge. Exact `1` enables it on every platform; `0` or any other
non-empty value selects the legacy socket pump. Windows, Android, macOS and
other platforms retain their opt-in default: unset/empty disables the bridge.
The process caches this choice on first use; set the variable before startup.

The existing carrier capability gate still applies: carriers without real
half-close support, including WebSocket/TLS, fall back to the socket pump.
This does not enable the XTCP stack itself. The controlled datapath acceptance
contract continues to pin `=1`; the Linux matrix runner's default leaves the
variable unset, and its explicit bridge flags set `1` or `0`.
The synthetic `xtcp_runtime_bridge_test` throughput switch documented below
remains explicit and is separate from this production policy.

### Experimental Runtime Execution Context

On Linux, set `OPENPPP2_XTCP_PRIVATE_IO=1` before startup to run even a single XTCP
shard on its own `io_context` and one `xtcp-io` worker. Unset, empty, and other
values preserve the supplied context for one shard. Multiple shards already
use private workers. This experimental switch changes execution placement,
not shard count, output lanes, carrier encryption, or gather policy. Its one
queue effect: with one shard, TAP GSO active, and
`OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES` unset, the shared upload budget defaults to
2 MiB instead of 32 MiB. The worker otherwise
ACKs upload data that the main thread has not yet encrypted, so the sender's
window outruns carrier progress and overflows the TUN queue (P64 upload: 10k-40k
TUN drops, 100k-220k retransmits). With 2 MiB, P64 GSO-on upload measured
+10-15% with TUN drops two orders lower and P16 unchanged; 1 MiB slowed P16.
With TAP GSO off the main thread drains 1500-byte packets more slowly, and
2 MiB cut P64 upload from about 720 to 340 Mbit/s, so GSO-off keeps 32 MiB.
An explicit `OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES` always wins.
It adds a CPU execution domain and does not establish single-core performance.
Keep the setting fixed for the lifetime of a runtime instance. No default
change or throughput qualification is implied.
Other platforms ignore this switch. This experimental execution context and
its queue-budget default, together with the direct bridge test stability fix,
first ship with release v2.1.9.0.

## Windows

Prepare the pinned source, then build with the repository's CMake/Ninja
wrapper from a Visual Studio developer shell:

```bat
bash tools/prepare_xtcp.sh
build_windows.bat Release x64 xtcp
```

For a Visual Studio project build, build the dependency separately and pass its
library path to MSBuild:

```bat
cmake -B build-xtcp-win -S third-party/xtcp -G "Visual Studio 17 2022" -A x64 "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>" -DXTCP_BUILD_TESTS=OFF -DXTCP_BUILD_BENCH=OFF -DXTCP_BUILD_SAMPLES=OFF -DXTCP_BUILD_PLUGINS=OFF -DXTCP_BUILD_LWIP=OFF -DXTCP_BUILD_CC_PLUGINS=ON -DXTCP_CHECKSUM_VALIDATE=ON
cmake --build build-xtcp-win --config Release --target xtcp_static
MSBuild ppp.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /p:VcpkgTriplet=x64-windows-static /p:PppEnableXtcp=true /p:PppXtcpLibrary=build-xtcp-win\Release\xtcp_static.lib /p:OutDir=build\msbuild-xtcp\ /p:IntDir=build\msbuild-xtcp-int\ /m:2
```

`PppXtcpLibrary` can be an absolute path when the MSBuild working directory is
not the repository root. Windows XTCP currently requires the Wintun L3 adapter;
the legacy TapWindows L2 adapter is rejected with a logged explanation.

The MSVC CMake path explicitly uses `/utf-8` and `NOMINMAX`, matching the
vcxproj. These prevent local code pages from misreading Chinese comments and
Windows min/max macros from corrupting Boost.UUID declarations.

### Windows data path and offline validation (2026-10-17)

Windows XTCP is x64-only and uses Wintun L3 plus an internal loopback TCP
bridge. Wintun supplies raw IP packets, without Ethernet headers. The current
XTCP ingress accepts only unfragmented IPv4 TCP; IPv6, UDP and fragmented IPv4
are outside XTCP support. Wintun does not advertise TX GSO, so neither TSO nor
partial-checksum output can be enabled by the diagnostic environment gates;
XTCP emits normal MSS-sized packets with checksums through `Output`.

The bridge binds `127.0.0.1:0`, obtains its actual ephemeral source port and
registers that port with the external-client table before connecting to
`127.0.0.1:<local-listener-port>`. Windows rejects a non-IPv4/non-loopback
listener. This local bridge does not need physical-interface binding or remote
socket protection: such binding would interfere with loopback. Remote carrier
and bypass connections still use the existing forwarding/protection paths.
This is a source-level conclusion; route interaction has not been tested live.

With more than one shard, XTCP owns its I/O workers. Windows uses the existing
thread-name helper; no CPU affinity is imposed. Teardown runs on each owning
strand, cancels timers and closes flows before releasing the pool lease. The
workers must drain cancelled handlers before exit, and destruction on a worker
must avoid joining itself. Stop checks running state under the startup mutex
so repeated Stop/destruction cannot post teardown into an exited pool. These lifecycle rules also correct the shared
implementation on Linux without changing its packet or bridge selection.
`fcntl`, `socketpair`, POSIX `close`, and pthread naming remain behind platform
guards. The remaining `getenv` calls use the portable CRT API with exact value
checks; set diagnostics before startup and do not mutate the process environment
concurrently with runtime startup.

The Windows lifecycle regression is opt-in and links the production library:

```bat
rem In an x64 VS developer shell, with the provisioned x64-windows-static triplet:
cmake -S . -B build\ninja-xtcp-validation -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static "-DPPP_OUTPUT_DIR=%CD%/build/ninja-xtcp-validation/bin" -DENABLE_XTCP=ON -DENABLE_XTCP_WINDOWS_TESTS=ON
cmake --build build\ninja-xtcp-validation --parallel 2
ctest --test-dir build\ninja-xtcp-validation -R xtcp_windows_lifecycle_test --output-on-failure
```

Replace dependency/output paths with local paths; keep output separate from any
active installation. This is equivalent to the wrapper's Release/x64/XTCP
configuration, while retaining an isolated build directory. The test performs
16 two-shard startup/stop/release cycles, alternating immediate destruction
with delayed repeated Stop, without adapters or network traffic.
Production publishes a runtime only after Start succeeds and creates a fresh
instance on reconnect. This change does not extend the existing boundaries for
concurrent Start/Stop on one instance or changing shard count between restarts.
The token checks Impl release; it does not claim that the detached current
worker has synchronously exited, since that worker still owns its context.
The standalone `tests/cpp` XTCP suite is still Linux-only; this focused target
does not claim to port that suite.

The missing `pwsh.exe` message comes from vcpkg's imported
`AppLocalFromInstalled` target (`scripts/buildsystems/msbuild/vcpkg.targets`),
not `CopyDriverRuntime`. The installed target already retries the system
Windows PowerShell when pwsh exits with 9009. No repository fallback or external
vcpkg modification is needed. Local duplicate-vcpkg-import warnings are separate
from XTCP compiler warnings.

Live validation still requires explicit authorization: Wintun packet/MTU/checksum
handling, bidirectional bridge traffic and half-close/RST, loopback under tunnel
routes, reconnect and multi-shard exit. No PPP application, route/DNS/adapter,
driver or proxy changes are part of the offline validation.

Validation on 2026-10-17: MSBuild Release/x64 with XTCP enabled and the default
XTCP-disabled build both passed (exit 0). The equivalent isolated VS x64
CMake/Ninja build passed all 342 steps (exit 0). The production-linked Windows
lifecycle test passed 1/1 (16 internal cycles, 0.49 seconds). Include boundaries,
vcxproj source-list matching (259/259), and `git diff --check` passed. No new
XTCP compiler warnings remain, including C4018; existing C4005/C4099,
local MSB4011 and CMake compatibility/policy warnings remain. Linux runtime
regressions were not run in this Windows-focused pass. No live VPN session
was started or validated.

### Windows loopback regression (2026-10-17)

The opt-in `ENABLE_XTCP_WINDOWS_TESTS` build also includes
`xtcp_runtime_bridge_test`, linked to the production library. It injects
synthetic IPv4/TCP packets into XtcpRuntime and uses a real ephemeral-port
`127.0.0.1` TCP echo server; no PPP application or Wintun adapter is started.
Windows runs the TCP bridge and excludes only the POSIX descriptor-ownership
case. Its environment helpers and Asio work guard use Windows-compatible APIs;
the POSIX relay and Linux execution behavior are preserved.

```bat
cmake --build build\ninja-xtcp-validation --target xtcp_runtime_bridge_test xtcp_windows_lifecycle_test --parallel 2
ctest --test-dir build\ninja-xtcp-validation -R "^xtcp_(runtime_bridge|windows_lifecycle)_test$" --output-on-failure
```

MSVC compilation/linking passed (exit 0). CTest passed 2/2: lifecycle 0.48 s,
bridge 12.84 s, total 13.32 s. Bridge coverage includes endpoint byte order,
handshake, byte-exact bidirectional data, half-close, RST before readiness,
direct-read reservations, backpressure/resume, stale callbacks, restart/global
upload budget, FIN idempotence, queue accounting and 256 connect/close cycles.
These are functional test durations, not throughput measurements.

The user authorized isolated tests only, preserving existing connections. No
usable Windows Sandbox or Windows VM tooling/inventory was found; none was
installed or enabled. Live PPP/Wintun native-versus-XTCP performance remains
unmeasured. Comparing this synthetic packet harness directly with ordinary
Winsock loopback would use different workloads and cannot establish VPN speed.

### Windows loopback throughput (2026-10-17)

Run the optional benchmark after building `xtcp_runtime_bridge_test`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/run_windows_xtcp_loopback_benchmark.ps1 -Seconds 3 -Rounds 3
```

The script launches only the test executable, alternates reference/XTCP order,
clears XTCP overrides in each child process and saves samples, stderr, binary
SHA-256 and medians. Each connection has a 1-second warmup followed by a
3-second measurement window. Setup and final integrity drain are excluded.
Both paths use a 32 KiB application flight limit, 1360-byte write chunks and
the same deterministic payload; reported goodput counts echoed payload once,
not the sum of upload and download. XTCP uses KCC, one shard, no GSO, and an
explicit synthetic peer MSS of 1460. Winsock negotiates its own loopback MSS.

| Component path | Three runs, Mbps | Median, Mbps | Median process CPU ns/B |
| --- | --- | --- | --- |
| Winsock TCP loopback reference | 779.381 / 1023.176 / 967.785 | 967.785 | 14.208 |
| XTCP Runtime + synthetic IPv4/TCP + loopback echo | 22.634 / 20.480 / 19.486 | 20.480 | 417.082 |

All six samples passed byte-exact echo and full-drain checks, with zero XTCP
entry-admission drops. XTCP emitted 536/532/559 complete old payload packets
per connection (including warmup/drain), which were counted as duplicates and
excluded from goodput. Their cause is unproven. The earlier no-MSS diagnostic
(default peer MSS 536) measured 34.607 Mbps XTCP / 1018.449 Mbps Winsock medians;
that is a different profile and is not pooled into this result.

**XTCP is substantially slower in this harness.** The reference is ordinary
Winsock TCP, not OpenPPP2 native mode. XTCP additionally performs synthetic
packet construction/checksums, queueing, output copies, parsing and manual
ACK driving; process CPU includes those costs, the echo server and polling.
The small application window also constrains the closed-loop test. These
measurements cannot establish a PPP/Wintun speed ratio or identify whether
pacing, timer scheduling, retransmissions or harness work dominates. No PPP,
Wintun, routes, DNS or adapter settings were changed.

Results: `build/xtcp-validation/throughput-mss1460/results.json` (binary SHA-256
`7c021c03bacb4ff3d4e7b0b862336781cafe916818155ff30197267f4c1943bc`).
The subsequent functional regression passed 2/2 in 13.49 seconds. The Windows
harness now waits for runtime teardown before stopping its external context,
preventing the test itself from retaining pending Stop handlers.

### Windows throughput follow-up: root causes and parity (2026-10-17)

The 20 Mbps result above had four compounding causes, found with an
in-process stack sampler (`XTCP_BENCH_PROFILE=io|main`) and per-thread CPU
accounting (`XTCP_BENCH_THREADS=1`) added to the benchmark:

1. **`getenv` on the hot path.** `ConnectorWriteCap()`, `ConnectorBatchBytes()`,
   `GlobalQueueBudget()`, `SendRetryDelay()` and the GRO size helper called
   `getenv` per write/packet. The Windows CRT locks and scans the environment
   block, which cost about 36% of the runtime I/O thread. These values are now
   read once when the runtime is constructed (a new runtime still picks up
   changed variables). This helps every platform.
2. **Data segments counted as duplicate ACKs** (upstream `0255dae`, formerly
   local `0030-dupack-excludes-data-segments.patch`). On a bidirectional flow every
   peer data segment repeats the cumulative ACK; xtcp counted them as dupacks,
   triggering spurious fast retransmits (the "duplicate packets") and cwnd
   collapse. Data/SYN/FIN segments are no longer counted (RFC 5681 section 2,
   Linux `FLAG_DATA`). A window change alone is intentionally not excluded,
   because xtcp's own receiver shrinks its window per buffered out-of-order
   segment.
3. **KCC on coarse Windows timers.** KCC send paths are timer driven; Windows
   waits round up to about 15.6 ms. Windows now defaults to `cubic`;
   `OPENPPP2_XTCP_CC=kcc` restores KCC. Patch
   `0029-pacing-late-wake-catch-up.patch` credits late pacing wakes (bounded to
   20 ms); it showed no measurable change by itself in this harness.
4. **Harness confound.** The echo server shared the runtime I/O thread, while the
   Winsock reference gives it its own thread. The benchmark now runs the echo
   server on a separate thread.

Benchmark script, 3 interleaved rounds, default CC (cubic):

| Component path | Median Mbps | Range Mbps | Median CPU ns/B | Duplicates |
| --- | --- | --- | --- | --- |
| Winsock TCP loopback reference | 1061.767 | 1005.985-1076.121 | 13.343 | 0 |
| XTCP Runtime + synthetic IPv4/TCP + loopback echo | 1096.883 | 1074.658-1110.883 | 18.791 | 0 |

With `XTCP_BENCH_CC=kcc` the same build measured 309-400 Mbps. XTCP throughput
now matches the reference in this closed-loop harness; it still spends about
40% more process CPU per byte. This remains a component benchmark, not a
PPP/Wintun VPN measurement.

### Linux loopback throughput and direct bridge (2026-10-17)

`xtcp_runtime_bridge_test --throughput xtcp|native <seconds>` now also builds
on Linux (`ENABLE_XTCP_TESTS=ON`). `native` is the kernel TCP loopback there.
`OPENPPP2_XTCP_MEMORY_BRIDGE=1` (or `XTCP_BENCH_DIRECT=1`) replaces the
loopback-TCP echo with an in-process direct second leg that echoes through
`SendToPeer` / `OnSecondLegPayload` from its own pump thread.
`XTCP_BENCH_WINDOW` changes the 32 KiB flight limit and `XTCP_BENCH_PROFILE`
also works on Linux (signal sampler plus `addr2line`; build with `-g`).

Runtime changes from this pass: connector writes and poll-timer kicks are
deferred to the end of each ingress batch (one gather-write and one timer
re-arm per batch), and `XtcpSecondLegHooks` gained an opt-in
`BatchesPeerSend()` / `FlushPeerSend()` pair so a second leg can wake its
writer once per batch instead of once per segment. The production
`VEthernetNetworkTcpipConnection` second leg has not opted in yet.

WSL2 Debian, 32 KiB window, single connection, 3 runs each:

| Path | Mbps |
| --- | --- |
| Kernel TCP loopback reference | 7186-9561 |
| XTCP, loopback TCP bridge (before batching) | 951-1199 |
| XTCP, loopback TCP bridge (batched writes) | 1305-1389 |
| XTCP, direct bridge, per-segment wake | 1496-1543 |
| XTCP, direct bridge, `FlushPeerSend` batching | 1878-1987 |

On Windows the same build measured about 1000 Mbps Winsock, 1130 Mbps TCP
bridge and 1240-1250 Mbps direct bridge. On Linux XTCP reaches about 22% of
the kernel loopback. The runtime I/O thread is saturated; the remaining cost
is cross-thread wake-ups on every small batch plus per-1360-byte userspace
segment processing on one thread. Closing the gap needs larger units of work
(GSO/TSO-sized segments) or a multi-thread pipeline, not further local fixes.
With a 64 KB window XTCP reaches about 1.84 Gbps over the TCP bridge; larger
windows are capped because the synthetic peer does not negotiate window
scaling.

### Linux per-shard GSO output lanes and default segment cap (2026-10-18)

With `OPENPPP2_XTCP_SHARDS` above 1, every shard used to push its TUN output
through the single `TunGsoCoalescer` in `TapLinux`. That coalescer sits behind
one mutex and writes one queue fd. Shards serialized on the lock, and flows
from different shards interleaved in one merge buffer, which forced early
flushes. Two shards with GSO on reached only about 900 Mbps at P64 DL.

Changes:

- `ppp/tap/TapOutputLane.h` adds a thread-local lane hint. When there is
  more than one shard, `XtcpRuntime` wraps shard i's output handlers in
  `TapOutputLaneScope(i)`.
- On first use of a lane, `TapLinux` opens a dedicated `IFF_MULTI_QUEUE` queue
  fd for it, with its own coalescer, hold timer and read loop. Lanes share no
  lock. Each queue fd needs a reader because the kernel's tun automq steers a
  flow's return packets to the queue that last wrote that flow.
- If a lane cannot be created, only that shard falls back to the shared path.
  When the TAP switches to SSMT or fails, every lane is flushed and merging
  stops. An existing lane then writes unmerged frames on its own fd, so a flow
  never changes queue.
- `OPENPPP2_TAP_GSO_LANES_DISABLE=1` forces the shared path for comparison.
- Default XTCP per-connection snd_buf: 1 MiB on all supported XTCP platforms
  (Linux, Windows and Android; a quota, not preallocated). macOS and iOS do not
  currently support XTCP builds. `OPENPPP2_XTCP_SNDBUF_BYTES` overrides the
  default, and `OPENPPP2_XTCP_DL_GSO_PERF_PROFILE=1` selects 2 MiB when no
  explicit byte value is set. At 64 KiB single-flow DL was capped near 410 Mbps
  (0.22x native); at 1 MiB it is ~0.95x. Patch 0039's pool reserve keeps many
  busy flows from starving ACK ingress.
- M3 opt-in switches (default off; unset keeps the behaviour above):
  `OPENPPP2_XTCP_DIRECT_SPSC=1` moves the direct-upload data queue to a
  fixed 4096-slot SPSC handoff (same caps and gather; ring allocation
  failure keeps the relay path). `OPENPPP2_XTCP_AFFINITY=queues` with
  `OPENPPP2_XTCP_SHARDS>1` and an exact `OPENPPP2_XTCP_IO_CPUS` map gives each
  shard its own io_context and pinned worker, binds GSO lane i to shard i,
  and stages lane reads (1024 items / 8 MiB) back to the TAP context for the
  unchanged `OnInput`; it is rejected with SSMT and reported as unsupported
  for one shard. `OPENPPP2_XTCP_AFFINITY_STRICT=1` refuses to start when a
  pin fails.
- M3 B-stage measurement (2026-10-26, shared remote host, paired native, 30 s x2 ABBA):
  2 shards + SPSC ingress lift multi-flow DL 1.18-1.40x and UL P16 1.59x but plateau
  at ~2.2 Gbps (4 shards add nothing) and regress single-flow DL 16-25% (40% on one
  core). Queue mode cuts CPU per byte and halves the P1 DL loss but regresses UL
  13-22%; worker affinity and DIRECT_SPSC show no measurable gain. Defaults stay
  unchanged. Single-shard baseline P64 DL showed 7-8 zero-rate flows per run.
  Details: THROUGHPUT_OPTIMIZATION_PLAN_CN.md section 2.4.4.
- The default `TunGsoCoalescer::kSegmentCap` is now 32 instead of 4.
  `OPENPPP2_TAP_GSO_SEGMENTS` (1-48) still overrides it, and
  `OPENPPP2_XTCP_DL_GSO_PERF_PROFILE=1` still selects 48 when no explicit cap
  is set. The production-builder contract in `tun_gso_output_probe` pins
  cap 4.

#### M3 queue-mode reconnect lifecycle (2026-10-26)

`ClientConnectionOpener::Open` creates and starts one `XtcpRuntime` for the
switcher's attached TAP, then registers the lane-binding provider. The
`VEthernetExchanger` reconnect loop replaces carrier/session state in place;
it does not stop or recreate the XTCP runtime or TAP. Runtime stop is performed
by switcher teardown, alongside TAP disposal. Therefore a runtime restart
without TAP rebuild is not a production reconnect path in this revision.

There is still a lifecycle hazard if a future caller adds that sequence:
`TapLinux::CreateGsoOutputLane` asks the provider only when a lane is first
created, and the lane retains its shard `io_context`, descriptor, timer and read
loop. An XTCP Stop/Start would build new shard contexts without rebinding those
existing TAP lanes. The netns reconnect check below exercises the production
carrier reconnect with the same PPP process and TAP, and checks bidirectional
multi-flow traffic plus stable runtime identity and bound-lane count. It does
not claim to exercise a direct runtime Stop/Start while retaining the TAP.

The isolated lab build at `add778946e268ad765a284b682dda02a5cba1b85` used
`OPENPPP2_TAP_GSO_MERGE=1`, strict affinity maps, 512 churn flows, and a 10 s
or 5 s soak. Results:

| Mode | Restart / lane result | Full E2E |
| --- | --- | --- |
| `queues`, 2 shards, CPUs `0,1` | reconnect passed; runtime ID stayed 1; 2/2 bound lanes; both shards received traffic | PASS, including netem and rollback |
| `queues`, 4 shards, CPUs `0,1,2,3` | reconnect passed; runtime ID stayed 1; 4/4 bound lanes; all shards received traffic | PASS, including netem and rollback |
| `workers`, 4 shards, strict CPUs `0,1,2,3` | reconnect and 128 post-reconnect bidirectional flows passed; runtime ID stayed 1 | FAIL: half-close integrity (server saw 106215/131072 bytes once, 131071 another time; a third run detected corrupted echo data) |
| `workers`, 4 shards, strict CPUs `8,9,10,11` | reconnect and 128 post-reconnect bidirectional flows passed; runtime ID stayed 1 | FAIL: half-close integrity check |
| `workers`, 4 shards, strict CPUs `8,9,10,11`, no server restart | not applicable | PASS; netem skipped |
| `off`, 4 shards, no CPU map | reconnect passed; runtime ID stayed 1 | PASS, including netem and rollback |

The workers-mode half-close failure reproduced with two CPU maps only when the
server restart/reconnect phase was enabled; without that phase the same worker
configuration passed. This is a separate reconnect regression signal and its
cause is not established here. It is not evidence of stale lane callbacks:
workers mode bound no lane to a shard, and the queue-mode reconnect cells kept
all lane readers active. No direct runtime Stop/Start-with-live-TAP test was
run because that lifecycle is absent from production. Artifacts, including
failed runs, are retained under `/home/ppp-m2/luna6-20261026/artifacts/`.

#### Reconnect half-close data loss: root causes and fix (2026-10-26)

**Status: fixed.** The failing check was the client-initiated half-close
(`sendall(128 KiB)` + `shutdown(SHUT_WR)`). Two independent data-path bugs
produced the two observed signatures; neither is a harness artifact (the
checker waits for EOF/RST and the echo service logs its own byte count) and
neither involves stale state from the previous session. The reconnect phase
only changed timing. Both mechanisms are configuration independent; the
default configuration (1 shard, no M3 switches) never failed in this
campaign (5 runs before any fix, 17 with only the server-side change), but it
runs the same relay and split code.

1. **Truncated upload (server side).** With `XTCP_E2E_PCAP=1` the client TUN
   capture shows XTCP ACKing all 131072 bytes plus FIN, and the server log
   shows all 131072 bytes written into the target socket, yet the target veth
   capture shows the server PPP sending **RST** after 122951 bytes (the echo
   app had read 108039). On carrier EOF (the client direct bridge's
   `ShutdownSend`), `ForwardTransmissionToSocket` disposed the bridge and
   closed the target socket while echo bytes sat unread; Linux answers
   `close()` with unread data by sending RST and discarding the unsent send
   queue. The QoS read path (`ITransmissionQoS::DoReadBytes`) also disposed
   the server carrier on that EOF, so nothing could flow back.
   Fix: the server per-flow relay opts its raw TCP carrier into receive
   half-close (`ITransmission::EnableReceiveHalfClose`; `ITcpipTransmission`
   then marks `IsReceiveClosed()` on a clean FIN instead of disposing). The
   relay half-closes the target socket after every forwarded write completed
   and keeps the socket->carrier pump running until the target closes; owner
   port aging bounds a peer that never closes. WebSocket/TLS carriers and mux
   links are unchanged.
2. **One-byte deletion (client side).** A lab-only delivery trace in the XTCP
   receive callback showed a 12236-byte chunk at stream offset 108765 delivered
   with `RCV.NXT` one past its end, followed in CLOSE-WAIT by the tail chunk
   starting at 121002 instead of 121001. The client kernel had handed the TUN
   one super-frame `[108765, 131072)+FIN`; `GsoSplit` in `XtcpRuntime.cpp`
   copied the TCP flags into every split, so the first split carried FIN. XTCP
   consumed the FIN mid-stream, entered CLOSE-WAIT and trimmed the first byte
   of the real tail as already received. All recorded deletion offsets
   (112172, 116657, 121001, 121427, 122960) are split boundaries of that kind.
   Fix: `XtcpGsoSplitSegmentFlags` keeps FIN/PSH/URG on the last split only
   and CWR on the first (RFC 793/1122, Linux `tcp_gso_segment`).

Regression tests: `xtcp_runtime_adapter_test` splits a FIN|PSH super-frame
across the sequence wrap and checks that only the last split carries FIN/PSH;
`transport_auth_lifecycle_test` checks the receive half-close opt-in on the QoS
read path. Both fail without their fix and pass under normal, ASan/UBSan and
TSan builds.

Reconnect E2E (lab netns, reconnect phase on, 512 churn, 5 s soak):

| Mode | Before fix | Server fix only (`v2`, `dg`) | Final (`v3`) |
| --- | --- | --- | --- |
| default (1 shard) | 5/5 (pcap on) | 11/11 | 6/6 |
| `off`, 4 shards | 2/5 (earlier run), 7/8 | 11/11 | 6/6 |
| `workers`, 4 shards, strict CPUs `8-11` | 1/5 (earlier run) | 11/11 | 6/6 |
| `queues`, 4 shards, `TAP_GSO_MERGE=1` | 5/5 (earlier run) | 9/11 (two one-byte deletions at 121001) | 16/16 |

Every final run drained the full 131072-byte echo before EOF; before the
server fix the drain stopped at a random prefix.

The `OnState` strand handoff also captures the `Flow` and its runtime/flow
generation before posting and rejects the callback if that identity is no
longer current (`IsCurrentXtcpFlowCallback`). This is lifecycle hardening
against `connection_id` reuse, not a cause of the data loss.

Artifacts: `/home/ppp-m2/claude-reconnect-20261026/art/` (`off4p-01`: RST
capture; `dg-queues4-02`: delivery trace; `v3-*`: final build).

WSL2 Debian, three isolated netns, XTCP, 2 rounds of 15 s plus 2 s per cell,
median Mbps:

| P / direction | 1 shard GSO off | 1 shard cap 4 | 1 shard cap 32 | 1 shard cap 48 | 2 shards GSO off | 2 shards cap 4 | 2 shards cap 32 | 2 shards cap 48 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P1 DL | 488 | 497 | 497 | 494 | 389 | 316 | 390 | 402 |
| P1 UL | 724 | 1610 | 1630 | 1533 | 1433 | 1370 | 1350 | 1352 |
| P16 DL | 1761 | 2112 | 3129 | 3074 | 3292 | 1755 | 4919 | 4725 |
| P16 UL | 988 | 2124 | 2022 | 1718 | 1567 | 2094 | 2011 | 2010 |
| P64 DL | 1713 | 2472 | 3005 | 2957 | 3766 | 1963 | 4571 | 4630 |
| P64 UL | 697 | 1786 | 1852 | 1823 | 1467 | 1918 | 1905 | 1871 |

- Same binary, 2 shards, cap 4, P64 DL: 915 Mbps with lanes disabled, 1983
  Mbps with lanes.
- Caps 32 and 48 perform alike on downloads, and both let two shards with GSO
  on beat GSO off at P16 and P64 DL. Cap 48 was lower for one shard at P16 UL
  (1718 vs 2022), so the default is 32. Most of the gain from cap 4 to 32 is
  on downloads; uploads are about flat.
- Upload retransmits are far lower with GSO on at every cap than with GSO off
  (for example, one shard at P64 UL averaged 47790 with GSO off and 4219 at
  cap 32). The download iperf results carry no retransmit count.
- `XTCP-GSO-STALL-001` (P16 DL, GSO on, cap 48, 10 s plus 2 s, 42 s watchdog)
  passed 20 of 20 rounds with one shard and with two shards (median 2928 and
  4775 Mbps), with no watchdog trips. That run was not repeated at cap 32.
- C++ unit tests: 174/174 pass.
- Not verified: lanes together with the `--stall-diagnostics` ledger, lanes
  with NDI TSO, and latency distribution. These are directional results from
  a shared WSL2 host with only 2 rounds per cell.

### Future AF_UNIX option (assessment only)

Windows 10 1803+ AF_UNIX stream sockets are a possible follow-up, but cannot
reuse the POSIX `socketpair` branch directly: Winsock has no `socketpair`, and
Asio's Windows `local::connect_pair` is unsupported. A Windows implementation
would need bind/listen/connect/accept, filesystem-name/permission cleanup,
Winsock `SOCKET` ownership without truncation to `int`, and an appropriate Asio
local/generic stream socket rather than assigning AF_UNIX to a TCP socket.
Retain loopback TCP and runtime fallback until those paths are tested. No
performance improvement has been measured. See [Microsoft's AF_UNIX notes](https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/)
and [Asio local-socket documentation](https://www.boost.org/doc/libs/latest/doc/html/boost_asio/overview/posix/local.html).

## Android

Set `PPP_ENABLE_XTCP=ON` when invoking the Android build script. It prepares the
pinned source before configuring the NDK build:

```sh
cd android
PPP_ENABLE_XTCP=ON NDK_ROOT=/path/to/android/ndk ./build.sh arm64
```

XTCP ingress uses Android's Linux `TapLinux` packet path. Its bridge socket is
only a loopback connection to the in-process TCP stack. Remote TCP connections
are established by the existing client forwarding layer, which calls the
`VpnService.protect` bridge before connecting.

Both Windows and Android default to XTCP disabled. Linux desktop behavior and
its existing default are unchanged.
