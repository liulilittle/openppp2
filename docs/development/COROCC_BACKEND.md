# corocc Backend: Build And Validation

[Chinese](COROCC_BACKEND_CN.md) | [Design ADR](../adr/0003-corocc-coroutine-backend.md)

corocc is an optional, experimental L0 backend. Default builds continue to use
Boost fcontext and do not fetch or configure corocc. All existing YieldContext
public APIs and Anchor call sites remain valid. corocc runtime stats add
`coroutine_backend: "corocc"`. Default Boost builds omit the field to preserve
the original serialized bytes; absence retains the legacy Boost meaning.

## Build

```sh
bash tools/prepare_corocc.sh
cmake -S . -B build/corocc -DENABLE_COROCC=ON \
  -DTHIRD_PARTY_LIBRARY_DIR=/path/to/provisioned/dependencies
cmake --build build/corocc --parallel 4
```

Provision native dependencies using the existing platform build instructions;
enabling corocc does not remove Boost or OpenSSL requirements. Use a separate
output directory from any active PPP installation. Compilation does not require
starting a client or changing routes/DNS/drivers.

The preparation script verifies a pinned archive SHA-256, caches it under
`third-party/.cache`, applies `tools/corocc-patches/*.patch` in filename order,
and writes revision and patch markers. It refuses an existing mismatched tree;
inspect and move that tree aside or set `COROCC_SOURCE_DIR` to a new destination.
At configure time `-DCOROCC_SOURCE_DIR=/path/to/prepared/corocc` selects an
alternative tree. Dependency sources remain ignored. Treat upgrades as an ABI
review, including borrowed stack range fields and sanitizer layout.
Preparation requires Bash, curl, tar, patch and sha256sum (install coreutils
where sha256sum is not provided, including macOS).

`-DPPP_COROCC_GUARD_STACK=ON` uses page-protected stacks instead of the regular
allocator. It is OFF by default. `-DCOROCC_FORCE=ON` permits experimental
platforms outside the whitelist; it does not enable unsupported iOS.
The standalone MSBuild project does not enable this backend; Windows opt-in
builds use CMake/MSVC. macOS requires its native SDK and Android the NDK plus
target Boost/OpenSSL. Native Windows SEH/TIB behavior and mobile runtime behavior
cannot be established by a Linux build.
The separate `android/CMakeLists.txt` accepts the same option and links a PIC
corocc archive into the shared library. The separate iOS entry point warns and
disables the option, retaining its existing Boost assembly/shim.

## Offline Tests

```sh
bash scripts/run-cpp-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-asan-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tsan-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tests.sh -DPPP_COROCC_GUARD_STACK=ON
bash tools/check_include_boundaries.sh
bash tools/check_vcxproj_sources.sh
```

`CPP_TEST_BUILD_DIR` overrides the build directory, `CPP_TEST_JOBS` the build
parallelism (default 4). Default, corocc, ASan and TSan builds have independent
directories. ASan/UBSan and TSan cannot be combined. On WSL sanitizer scripts run
CTest under `setarch $(uname -m) -R`; inability to set the personality is an
environment failure, not a passing test. ASan enables stack-use-after-return and
leak detection. No privileged network E2E is part of these scripts.

The switch test checks one million switches, nested call chains, a three-way
relay, terminal handoff, migration through 101 distinct joined worker threads,
and a second migration pass rotating between four simultaneously live workers.
The existing
Anchor suite exercises duplicate, stale, early, post-completion and four-worker
racing wakeups. Additional tests cover standard/unknown handler exceptions,
24 KiB stack persistence, 1/4 independent io_context workers and guard-page faults
in a child process (POSIX guard builds only).

For XTCP contract tests, prepare XTCP and pass `-DENABLE_XTCP_TESTS=ON` to the
standalone test script. `tools/run_xtcp_fault_suite.sh` tests the independent
upstream XTCP C library: it does not call YieldContext and therefore cannot
distinguish coroutine backends. Run it alongside the corocc-enabled integration
tests rather than treating it as coroutine-switch coverage.

Inspect a linked kernel with `nm -g --defined-only`: both original Boost symbols
and renamed `corocc_asm_*` may coexist; no duplicate definitions are expected.
No corocc token/runtime/scope APIs should be referenced by the PPP backend.

## Performance Gate

Use two release binaries built from the same source, compiler, dependencies and
settings, differing only in `ENABLE_COROCC`; freeze their SHA-256 before testing.
Use the lab's approved measurement controller and lock. Never replace an active
installation or run an unapproved network runner. DL/UL P1/P16/P64 use two
interleaved rounds ordered A1/B1/B2/A2. Preserve throughput, CPU, RSS, retransmits,
controller/binary hashes and cleanup evidence. Keep at least 20 GB free and
remove this task's build directories afterward.

For each cell report both rounds, relative mean change and variation. A loss
over 3%, variation greater than the observed difference, or any correctness
failure rejects a benefit claim. Microbenchmark timings alone are insufficient.
See [validation record](COROCC_VALIDATION.md) for actual checks and limitations.
