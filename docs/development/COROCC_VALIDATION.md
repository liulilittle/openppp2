# corocc Validation Record

[Chinese](COROCC_VALIDATION_CN.md) | [Build guide](COROCC_BACKEND.md) |
[Design](../adr/0003-corocc-coroutine-backend.md)

Validation date: 2026-10-29. Base: `bfd5b88101943ba370bb9f04858af54787a5a461`,
with the uncommitted corocc implementation. Default remains OFF.

## Environment And Method

All compilation and test execution takes place on the authorized shared Linux
x86_64 lab host, in a new task directory. No local compilation or test suite
execution was performed. Builds use the shared build lock, CPUs 0-15, nice 10,
and at most 16 jobs. Root free space must remain at least 20 GB. Test/build
directories are removed after preserving evidence.

The host provides GCC 14.2 and Clang 19. GitNexus is unavailable; impact analysis
uses source/caller inspection, build definitions, diffs and focused tests.
The dependency pin and archive checksum are in the build guide and ADR.
A fresh download matched the checksum and the prepared source tree; an
idempotent preparation check also passed.

## Completed Checks

| Check | Result |
| --- | --- |
| Boost standalone C++ suite, including XTCP contracts | 205/205 passed |
| corocc standalone C++ suite, including XTCP contracts | 205/205 passed |
| Optimized corocc switch/Anchor/exception/stack/multi-context tests | 5/5 passed |
| corocc four-live-worker migration follow-up | 1/1 passed, 101 handoffs |
| corocc ASan/LSan full suite after fixture cleanup correction | 205/205 passed; no address/leak errors |
| Boost ASan/LSan related fixtures after cleanup correction | 4/4 passed |
| Clang 19 corocc TSan full suite after the L0 bridge patch | 205/205 passed |
| ASan/LSan focused coroutine suite after the L0 patch | 5/5 passed |
| GCC 14 corocc TSan raw switch/migration test | 1/1 passed |
| corocc guard-stack focused suite, including child-process guard fault | 5/5 passed |
| Independent XTCP upstream fault suite | 20/20 passed |
| Include boundaries and vcxproj source layout | Both passed; 268/268 source entries |
| Default missing-source, enabled missing-source, iOS fallback policies | 3/3 passed |

CTest counts above are executable/test registrations, not individual assertions.
Switch coverage includes a million switches, nesting, three-way transfer relay,
terminal handoff and sequential cross-thread migration. Anchor coverage includes
early, duplicate, stale, racing and post-completion wakeups, including randomized
four-worker schedules. Independent io_context coverage uses 1 and 4 workers.
The optimized switch timing is a diagnostic only, not a throughput benefit claim.

Both Release kernels built successfully. All 332 common compilation commands
match after removing the backend macro and corocc include path; the 16 extra
commands belong to corocc. The default YieldContext disassembly exactly matches
the original baseline (SHA-256
`553834156d25d0143d72673d061939a83f382528f518095089f1ebd0731a5578`).
Symbol inspection found no duplicate definitions and only L0 corocc symbols;
Boost make/jump symbols remain present. This checks this Linux/compiler build,
not binary identity of the entire executable on every platform.

Initial ASan link attempts exposed missing dependencies in partial offline test
fixtures. Their logs are preserved. Allocator definitions and a link-only stub
for the connector fixture's unused optional logger resolve those fixture links;
the production logger and production allocator are unchanged. The first ASan
execution passed 202/205 and reported three WSS fixture leaks. A minimal
construct/dispose diagnostic using no coroutine reproduced the same 13,279 bytes
in 42 allocations under both backends. The three fixtures now drain asynchronous
disposal/cancellation after stopping and joining their runners. Final ASan/LSan
results above retain leak detection and stack-use-after-return detection.

This is **not a clean UBSan pass**: the combined ASan/UBSan configuration reports
three null-reference diagnostics in the existing `nullof<YieldContext>()`
synchronous convention (`ppp/stdafx.h` and the connector fixture). The Boost
baseline reproduces the same diagnostics. That convention and its production
call sites are unchanged as required; no new sanitizer suppression was added.

The initial TSan run passed 197/205 and crashed in eight coroutine consumers.
The pinned L0 patch fixes cross-fiber entry/exit instrumentation in two switching
helpers by forcing them inline, retaining load/store checks. The corrected full
suite passed 205/205 in 103.96 seconds; native object inspection confirms the
helpers have no separate symbols and memory instrumentation is present.
TSan uses the repository's existing `libcrypto.so.3` suppression. The GCC TSan
test runs with per-process `setarch -R`; no host ASLR setting is changed.
The lab is native Linux, not WSL. Sanitizer scripts include the requested WSL
`setarch $(uname -m) -R` path; WSL execution itself remains unverified.

## A/B Results

The interrupted controller continued and finished all 48 samples. No completed
sample was rerun. A is Boost, B corocc, with identical Release inputs apart from
`ENABLE_COROCC`. Each native/XTCP, DL/UL, P1/P16/P64 cell ran A1/B1/B2/A2,
30 seconds per sample with 2 seconds omitted. The task-local adapter calls the
shared `measure.py` controller, which owns the measurement/build locks, and its
reviewed isolated runner. It selects a two-core client cpuset, disables kernel
steering and preserves host network settings. The shared VM is quasi-isolated;
these are lab measurements, not production or platform-wide performance claims.

| Stack | Direction | P | A1 / A2 Mbps | B1 / B2 Mbps | Mean change | Round spread* |
| --- | --- | --- | --- | --- | --- | --- |
| native | DL | 1 | 1657.66 / 1670.17 | 1668.11 / 1665.66 | +0.18% | 0.75% |
| native | DL | 16 | 1532.25 / 1538.47 | 1531.80 / 1511.59 | -0.89% | 1.32% |
| native | DL | 64 | 1281.64 / 1332.77 | 1332.77 / 1354.79 | +2.80% | 3.91% |
| native | UL | 1 | 1317.54 / 1335.45 | 1311.68 / 1298.68 | -1.61% | 1.35% |
| native | UL | 16 | 1124.94 / 1116.86 | 1128.53 / 1124.65 | +0.51% | 0.72% |
| native | UL | 64 | 887.58 / 947.04 | 877.78 / 923.44 | -1.82% | 6.48% |
| XTCP | DL | 1 | 1689.36 / 1712.47 | 1722.22 / 1661.23 | -0.54% | 3.59% |
| XTCP | DL | 16 | 1649.17 / 1659.65 | 1685.76 / 1580.04 | -1.30% | 6.39% |
| XTCP | DL | 64 | 1562.06 / 1547.63 | 1543.81 / 1587.89 | +0.71% | 2.83% |
| XTCP | UL | 1 | 1381.33 / 1370.40 | 1355.38 / 1389.20 | -0.26% | 2.46% |
| XTCP | UL | 16 | 888.04 / 914.26 | 907.43 / 916.28 | +1.19% | 2.91% |
| XTCP | UL | 64 | 553.45 / 567.97 | 528.20 / 558.86 | -3.06% | 5.47% |

*Maximum within-backend two-round range, divided by the A mean. With only two
rounds this is a variation diagnostic, not an estimate of statistical confidence.
Eleven cells have variation larger than the mean difference. Native UL P1 shows
a loss; XTCP UL P64 exceeds the plan's 3% loss gate and also has larger variation.
There is **no demonstrated benefit**; default stays OFF.

All 48 samples passed, with zero runtime faults, zero-rate flows or backend
identity failures; cleanup and monitoring completed. CPU, RSS and retransmits
are present for every sample in the public [numeric CSV](COROCC_AB_RESULTS.csv).
CPU is client task-clock divided by the formal wall interval (100% = one core).
RSS is the sampled peak sum for both PPP processes during that interval, not a
continuous high-water mark; retransmits are the iperf sender count. For XTCP UL
P64 the two-round A/B means are CPU 99.54/99.62%, RSS 124.86/123.51 MiB and
retransmits 85249.5/74251.5. These metrics do not overturn the throughput gate.

Frozen binary SHA-256:

- A: `6000cbe7efb4ac321ede26219d91e149ee05e8a1ead2175f170565f75a4696ed`
- B: `81e52ae8ad5517a02b31c6fa0433d7e7a822733359cd3ad3b116cb48442550ed`

The final local implementation matches the measured source manifest. Only
documentation and numeric results were updated after the campaign. The worktree
was not rebased onto subsequent main changes (0044-0048).

## Platforms

Linux x86_64 is the native validation target. Windows, macOS and Android SDKs
and suitable cross toolchains are unavailable, so compilation and native runtime
behavior remain unverified. Windows SEH/TIB tests are present but have not run.
Linux aarch64 and musl are also unverified. The iOS fallback check sets a CMake
policy flag on Linux; it is not an iOS compile test.

## Evidence

Task logs, CMake caches, detailed CTest logs and measurement provenance are kept
under the ignored local `build/private/corocc-validation/` directory. Private
runtime configurations and lab infrastructure details are excluded from these
public documents. No commit or push is performed.
