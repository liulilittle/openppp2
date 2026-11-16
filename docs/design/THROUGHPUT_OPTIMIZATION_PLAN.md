# Throughput Performance Remeasurement

> Status: Measurement record
> Type: Performance report
> Last verified: 2026-11-01

Chinese plan and historical results:
[THROUGHPUT_OPTIMIZATION_PLAN_CN.md](THROUGHPUT_OPTIMIZATION_PLAN_CN.md), section 2.4.3a.
This companion covers the October remeasurement, not the entire historical plan.

Current pin: c9dd56013842 (2026-10-31), with 33 local patches. PRs #3-#8
fully absorb 0037-0040 and 0048; 0042/0043/0045/0046 retain local integration
residuals only. The old pin and measurements below remain historical.

## TUN Write Diagnostics (2026-11-01)

Chinese section 2.4.7 records diagnostic-only relaxed counters exposed in
`tap_linux` stats-json: writev attempts, requested bytes/segments (sum/max), and
nonempty flush counts by reason. One isolated P1 DL 30s run reached 1721.656 Mbps:
235,906 writev calls, mean 28,353.69 bytes / 19.5469 segments, maxima 46,386 / 32;
PSH accounted for 99.8789% of 236,109 flushes. Totals include omit/startup/tail.

Two matched-HEAD ABBA rounds passed all 8 cells: baseline/counters means
1731.724/1721.895 Mbps (-0.568%), versus sample SD 1.12%/1.73%; client CPU ns/B
increased 0.69%. This is within observed noise, not proof of strict equivalence.
Literal local main has a different XTCP pin: its second ABBA round remained
unqualified after retries, so it cannot establish counter overhead. All failed
attempts are retained. Remote Release builds and 195/195 C++ tests passed;
no local builds/tests, commits, or pushes. Evidence: `build/private/tunctr-20261101/`.
No batching, PSH, timeout, or fallback behavior was changed.

## Unprofiled Single-Flow DL Remeasurement (2026-11-01)

See Chinese section 2.4.8. Current main `b76d3ba7`, independent remote Release,
no profiler; three paired 30 s DL P1 rounds, N/X then X/N then N/X, matching the
historical one-shard, SPSC-off, five-CPU, KCC/AES-256-CFB/GSO-cap32/memory-bridge,
65536-byte/1-ms gather settings. Native: 1652.24/1625.19/1684.33 Mbps;
XTCP: 1771.05/1738.57/1763.46 Mbps. Mean ratio **1.063**, versus historical
1801/1690 = **1.066**: no clear relative regression, so the conditional add77894
ABBA was not triggered. Unprofiled XTCP averaged **1757.69 Mbps**, 2.9% above
the profiled 1708.73, but native also fell versus history. Different revisions,
times and long shared-host queue gaps preclude attributing the entire gap to
profiler overhead or quantifying it without a same-binary on/off experiment.
No local builds/tests or product changes. Each stack used shared locks, an idle
process check and run_m3_isolated.sh. Throughput results passed with no zero-rate
flows or runtime faults and clean isolation rollback; runner exit 1 and CPU
qualification failures were retained because perf core/migration metrics are
intentionally absent. This is not a new 1.2x acceptance or CPU-profile result.
Three supplementary P16 pairs averaged native **1535.08**, XTCP **1699.00 Mbps**,
ratio **1.107** (historical 1.134, about -2.4%); this small multi-flow difference
is not established as a regression without a dedicated old/new comparison.
All 12 throughput results passed, with CPU qualification failures retained.
Private evidence: `build/private/p1-clean-20261101/`; dedicated remote source,
build and binary directories were cleaned after retrieval. No commit or push.

## Single-Flow DL Profile (2026-11-01)

See Chinese section 2.4.5 for the full ranked profile and proposals. Frozen worktree
HEAD `2b4d720e` (the local `main` ref was stale), independent remote Release build,
XTCP one shard, P1 DL 30 s: **1708.73 Mbps**, result/qualification PASS.
The hottest client thread used **99.74% of one CPU**, versus server **71.95%**.
Client exclusive samples: kernel networking/TUN/syscalls 33.27%, locking 12.84%
(mainly kernel spin operations, not demonstrated contention), XTCP 11.99%, crypto
9.16%, identifiable copies/fused copy-checksum 7.95%, other/unresolved 24.79%.
Server crypto was 67.40%, but the server was not saturated. Prioritize reducing
client TUN flush/syscall frequency, then XTCP per-segment work; faster server AES
alone does not establish a single-flow gain. Proposed changes, not implemented,
have conditional estimates and need separate A/B validation.

Both PPP processes had simultaneous perf record/stat over an approximately 24 s
window. Hardware cycles/instructions were unsupported; client lost 41 samples and
10.51% of client samples were unresolved libc. One profiled run, no native pair or
unprofiled control: neither a throughput regression nor the 1.2x target is proven.
No local builds/tests or product changes. Shared locks and an explicit idle process
check prevented concurrent benchmark runs. Evidence is private under
`build/private/dl-single-flow/`; the dedicated remote build is cleaned afterward.

## M3 Linux Default Re-evaluation (2026-11-01)

Keep defaults off. See the Chinese plan section 2.4.6 for the complete method,
paired native results, limitations and source-path analysis. Main `2b4d720e`,
XTCP `c9dd560`; remote Release binary SHA-256
`c3295492703eda17a086cb3c11ff9d58177ee08be41bb60f6f0c605c0f556f23`.
Two paired 30-second ABBA passes, DL/UL P1/P16/P64, 36 paired cells, all successful.
No local build/test ran. Shared-host queueing exceeded the approximate hour budget.

XTCP mean Mbps, columns DL P1/P16/P64 then UL P1/P16/P64:

| Configuration | DL P1 | DL P16 | DL P64 | UL P1 | UL P16 | UL P64 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 1735.8 | 1754.9 | 1814.7 | 1445.8 | 940.2 | 568.6 |
| s2+SPSC | 1532.3 | 2195.2 | 2169.9 | 1485.8 | 1399.1 | 911.4 |
| s2+SPSC+queues+DIRECT_SPSC | 1631.8 | 2187.9 | 2132.9 | 1278.9 | 1193.7 | 1525.7 |

P1 DL still regresses 11.7% / 6.0%; queues also regresses P1 UL 11.5%.
Baseline P64 DL had zero zero-rate flows in both passes, but minimum flow rates
were only 0.175/1.223 Mbps. This does not prove starvation permanently fixed.
Shards move stack work onto dedicated contexts; DL payload blocks are posted to
the owning strand. Ingress SPSC batches wakeups, while DIRECT_SPSC controls the
upload queue. Dynamic flow-count switching would require ownership/lifetime
changes, not a clearly safe small patch, so no product change was implemented.
Historical soak/correctness/single-core gates were not rerun. Remote build trees
were cleaned; evidence is retained in `/home/ppp-m2/m3-default-20261101` and local
ignored `build/private/m3-default-20261101`.

## 2026-10 Remeasurement (After Main 027b398d)

Tested main: `18b02f8cab224d214998ef2286c5c29ff1ecf61d`, including #116,
#117, #118 and #121. Release, `ENABLE_XTCP=ON`, SIMD on; pinned XTCP
`c1fc9d6b6ead239043d7a7608eaea7e0cb143fe6`, prepared with
`tools/prepare_xtcp.sh` and the current patch stack. Product build: 335/335.
Binary SHA-256:
`e2060fc3016f4db0c7b963110f3eb0a2e29f5c8203a2ffe051cc6ea1c0857d2d`.

All compilation and measurement ran in the new lab directory
`/home/ppp-m2/m2-remeasure`; no local compilation or tests ran. Initial free
root disk space was 48GB. Builds used the prescribed shared flock, CPUs 0-15,
nice 10 and 12 jobs. The local Windows worktree path prevented Linux Git
commands; Windows Git interoperability also failed. No alternate gitdir was
used. The original `c232f892` change was inspected through the GitHub API.

The same shared VM, CPU49 client single-core profile and #107 settings were
used: native/XTCP, UL/DL x P1/P4/P16, 45-second formal interval, 2-second omit,
AES-256-CFB, KCC, one shard, memory bridge on, GRO 12288, gather 65536,
wait 1ms and GSO cap32. Send buffer was explicitly set to the current default
1MiB, versus the historical 64KiB. Client PPP and iperf shared CPU49.
An outer private network/mount namespace contained the three endpoint netns.
Steering on touched only private virtual-device RPS/XPS; physical IRQ writes
were prohibited. Measurements exclusively used the unchanged shared
`/home/ppp-m2/measure.py` guard/run, including build/measurement locks, load <=4,
foreign build/measurement exclusion, disk guard and frozen-source verification.

**Time-priority scope, not a complete reproduction of #107:** GSO-on, two
passes, native then XTCP in pass 1 and the reverse in pass 2, with P64 DL after
each main pass. GSO-off and pass 3 were not run. The historical alternating
GSO on/off, off/on, on/off sequence was therefore not reproduced.

Mbps. Current columns are two-pass arithmetic means; historical values are
#107 three-pass medians. Changes are descriptive, not significance tests.

| Direction / P | Native Mean | XTCP Mean | Pass 1 / 2 XTCP/Native | #107 XTCP | XTCP Change |
| --- | ---: | ---: | ---: | ---: | ---: |
| UL / 1 | 1114.418 | 1227.308 | 1.111 / 1.092 | 1301 | -5.66% |
| UL / 4 | 1110.741 | 1091.139 | 0.988 / 0.977 | 1177 | -7.29% |
| UL / 16 | 1084.898 | 997.018 | 0.922 / 0.916 | 1070 | -6.82% |
| DL / 1 | 1836.234 | 1817.772 | 0.975 / 1.006 | 414 | +339.08% |
| DL / 4 | 1726.207 | 2120.729 | 1.214 / 1.244 | 1269 | +67.12% |
| DL / 16 | 1680.812 | 1742.771 | 1.061 / 1.014 | 1528 | +14.06% |
| DL / 64 (extra) | 1332.289 | 1311.644 | 0.944 / 1.038 | N/A | N/A |

P64 DL per pass: native 1519.588/1144.990, XTCP 1434.484/1188.804 Mbps.
Both stacks had zero zero-rate flows in both passes. XTCP's slowest flows
were 8.250/6.002 Mbps. Neither starvation nor watchdog reproduced, but the
substantial between-pass variation and two-pass sample do not exclude
long-term starvation. #107's main table did not include P64, so no historical
percentage is supplied for it.

Overall: **28/28 result and strict qualification passes; zero zero-rate flows**.
All four groups exited 0 with empty runtime faults, successful namespace
cleanup, complete monitoring and unchanged binary hashes. Final free root
disk space was 47GB. Failed/interrupted preliminary attempts are excluded.

Main matrix: 24/24 result and strict qualification passes. The single-flow
DL gap narrowed from about 0.22x to 0.975/1.006x, but did not reach a stable
1.2x. Only DL P4 exceeded 1.2x in both passes. G2 remains unmet.

**Observed regressions exceed 3%:** UL P1/P4/P16 are down
5.66%/7.29%/6.82% against #107. Do not report this as no regression.
Shared-host variation, non-contemporaneous controls and the changed send buffer
prevent attribution to an individual patch. Against the newer section 2.4.2
historical XTCP medians, those UL means differ by approximately
-0.30%/+1.94%/-1.58%; that does not erase the #107 comparison.

Evidence root on the lab host: `W=/home/ppp-m2/m2-remeasure`.
It retains `main.tar.gz`, `frozen-source.json`, build logs,
`campaign-priority.py`, `ordered-runner.py`, `summary.json` and per-cell results,
qualifications, actual argv, provenance, completion and contention records in
`runs-priority/`. The initial steering-off qualification failure and the
interrupted pre-priority attempt remain in `runs/` and `runs-qualified/`,
excluded from the table. Product sources and host network settings were not
changed. Windows, mobile platforms and real-node network paths were not tested.

## UL Contemporaneous A/B (2026-10-30)

**Decision: noise under the prescribed rule; the approximately 6% regression
was not confirmed. Stop without bisection or attribution to a PR.**
A=`c232f892`, B=`18b02f8c`; two ABBA groups, four runs per version, XTCP UL
P1/P16 only. Overall B/A is **-0.43% / +0.28%**. Neither group exceeds a 3%
drop, so the joint rule (>3% drop and larger than within-group variation)
fails. No evidence justifies blaming #116/#117/#118/#121 or proceeding to
ECN/send-buffer discrimination.

All builds and measurements ran under the new lab directory
`W=/home/ppp-m2/ul-regress`; no local builds or tests ran. Root free space
was 47GB before and after. Each revision used its own `tools/prepare_xtcp.sh`,
Release, XTCP/SIMD on, GCC14.2 and the same dependency root. Both builds
completed 335/335 with 12 jobs under
`flock /tmp/ppp-m2-build.lock taskset -c 0-15 nice -n 10`.
Binary SHA-256:

- A: `06408863be37e5255f2ec02e89876cc83b036fc91bbd9adab8fde7044714fd6a`
- B: `6416a143a7cefec222bdb7a71f1f77b7198d52e603656d748104ee6802e4ab00`

The unchanged `/home/ppp-m2/measure.py` guard/run supplied measurement and
locking. Settings match #124: CPU49 client single-core, 45-second formal
interval, omit 2 seconds, KCC, AES-256-CFB, one shard, memory bridge,
GRO12288, gather65536/wait1ms, GSO cap32 and private-device steering on.
**Both versions explicitly used snd_buf=1MiB**, controlling the default-value
confound; this is not a replay of #107's 64KiB configuration. Before each run
the guard waited for load <=4 and no foreign build/measurement processes.
Private outer net/mount namespaces and inner endpoint netns kept host network
settings untouched.

Mbps, actual execution order; each cell is one 45-second sample:

| Group | Order | Version | UL P1 | UL P16 |
| --- | ---: | --- | ---: | ---: |
| 1 | 1 | A | 1243.698 | 1000.313 |
| 1 | 2 | B | 1209.219 | 1010.726 |
| 1 | 3 | B | 1227.335 | 1002.656 |
| 1 | 4 | A | 1245.252 | 1014.579 |
| 2 | 1 | A | 1189.057 | 999.603 |
| 2 | 2 | B | 1224.145 | 1002.611 |
| 2 | 3 | B | 1226.816 | 1015.952 |
| 2 | 4 | A | 1230.488 | 1006.114 |

| Scope / P | A Mean | B Mean | B/A Change | A / B Variation |
| --- | ---: | ---: | ---: | ---: |
| Group 1 / 1 | 1244.475 | 1218.277 | -2.11% | 0.12% / 1.49% |
| Group 1 / 16 | 1007.446 | 1006.691 | -0.07% | 1.42% / 0.80% |
| Group 2 / 1 | 1209.772 | 1225.481 | +1.30% | 3.42% / 0.22% |
| Group 2 / 16 | 1002.858 | 1009.281 | +0.64% | 0.65% / 1.32% |
| Overall / 1 | 1227.124 | 1221.879 | -0.43% | 4.58% / 1.48% |
| Overall / 16 | 1005.152 | 1007.986 | +0.28% | 1.49% / 1.32% |

Variation is `(maximum-minimum)/arithmetic mean` for the same version within
the stated scope. P1 reverses direction between groups; A itself spans 4.58%
overall. Group 1 P1 exceeds its within-version ranges but is only 2.11%, below
the 3% threshold. This is not a statistical equivalence proof.

All 16 result/strict qualification checks passed, with zero zero-rate flows.
All eight runs exited 0 with empty runtime faults, successful cleanup,
complete monitoring and unchanged binary hashes. No foreign build/measurement
processes were detected; other shared-VM contention remains possible.
The initial A attempt exited 1 without samples because the old
`os.path.ismount` check misses same-filesystem bind mounts; evidence remains
in `runs/group-1/slot-1-A`. External `isolated.sh` mounted tmpfs on the
isolation directory only inside the private mount namespace, allowing both
unmodified revisions' checks to pass. The failed attempt is excluded.

Evidence: `W/{A,B}/{src,build,bin/ppp,frozen.json}`, prepare/build logs,
`campaign-qualified.py/.log`, `isolated.sh`, `ordered-runner.py`,
`summary.py/.json`, and `runs/qualified/` with actual argv, per-cell
result/qualification, provenance, completion and contention records.
The broken local worktree metadata required the authorized alternate gitdir
for read-only archives; no commits were directed there.

Recommendation: do not revert or modify a suspect patch on this evidence.
Keep contemporaneous ABBA gates for future changes. To exclude smaller
effects, expand samples on dedicated CPUs/hosts and separately compare
64KiB/1MiB. P4, GSO-off, other configurations/platforms and the precise
source of historical noise remain unverified.
