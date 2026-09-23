# Testing
> Status: Active
> Type: Development guide
> Last verified: 2026-07-24
>
> **Purpose:** Select and run the test entry point that actually covers the changed surface.
> **Audience:** Contributors and CI maintainers.
> **Parent index:** [Development](README.md) · **Chinese:** [测试](TESTING_CN.md)

## Choose the correct C++ test boundary

The repository has two distinct C++ test paths. Do not describe one as a shortcut for the other.

| Path | What it builds | When to use it |
|---|---|---|
| `tests/cpp` | Focused standalone executables registered with CTest | Fast unit/regression work without configuring the full native runtime. |
| Root CMake + `ENABLE_TESTS=ON` | `ppp`, `openppp2_lib`, GTest-based `openppp2_tests`, and `openppp2_dns_cache_ttl_tests` | Changes that need the root native dependency graph or root-linked test behavior. |

### Standalone C++ suite

The script configures `tests/cpp` with Ninja, builds it, and runs CTest:

```bash
scripts/run-cpp-tests.sh
```

That project requires CMake 3.16 or newer, a C++17-capable compiler, OpenSSL, and Ninja because the script selects it explicitly. It writes its build tree to `build/test`.

### Root CMake tests

Prepare the root dependency layout first, then configure the root project with `ENABLE_TESTS`:

```bash
cmake -S . -B build/root-tests \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TESTS=ON \
  -DTHIRD_PARTY_LIBRARY_DIR=third-party
cmake --build build/root-tests
ctest --test-dir build/root-tests --output-on-failure
```

`ENABLE_TESTS` defaults to `OFF`. When enabled, `tests/CMakeLists.txt` fetches GoogleTest v1.14.0, so a first configuration may need network access in addition to the root native dependencies. This is separate from `tests/cpp`.

## Coverage and sanitizers

### Focused LLVM coverage

```bash
scripts/run-cpp-coverage.sh
```

The script configures `tests/cpp` with coverage enabled, builds and runs only `p2p_replay_window_test`, `dns_buffer_test`, and `base64_test`, then writes `build/coverage/summary.txt`. It requires `llvm-profdata` and `llvm-cov` in addition to the standalone-suite prerequisites.

### Root runtime coverage

```bash
THIRD_PARTY_LIBRARY_DIR=third-party scripts/coverage.sh
```

This script configures the root project with Clang, `ENABLE_TESTS=ON`, and `ENABLE_COVERAGE=ON`; it therefore requires the full native dependency layout. Root coverage instrumentation is not supported with MSVC.

### Lifecycle sanitizer targets

```bash
scripts/run-lifecycle-sanitizers.sh
```

The script configures the standalone C++ project with `ENABLE_SANITIZERS=ON`, defaults to `clang++`, and builds/runs five named lifecycle, route, and DNS targets. Use it for lifecycle-sensitive changes; it is not a build of the complete native executable.

### ThreadSanitizer

```bash
CXX=clang++ scripts/run-cpp-tsan-tests.sh
```

The script configures the complete standalone C++ suite in `build/test-tsan` with `ENABLE_TSAN=ON`, then builds and runs every registered CTest target. TSan is mutually exclusive with `ENABLE_SANITIZERS` (ASan/UBSan), requires a compiler with a working ThreadSanitizer runtime, and does not build the root native executable. Use `CXX=g++` when the local Clang TSan runtime is unavailable. Every standalone test registered through `openppp2_add_cpp_test()` has a 120-second watchdog so a deadlock fails instead of hanging CI.

Key deterministic concurrency tests in this batch are `yield_context_test`, `spinlock_test`, `asynchronous_write_io_queue_test`, `dns_udp_relay_test`, `client_datagram_port_manager_test`, `protector_network_request_test`, `transmission_qos_concurrency_test`, `vdns_request_lifecycle_test`, `mapping_port_connect_reentrancy_test`, and `dns_controller_test`.

## Runtime contract prerequisite

`bash scripts/test-runtime-contract.sh cpp` assumes that `build/test` already exists. Configure the standalone project first; the script then builds and runs only `runtime_snapshot_test` after checking the shared fixture hashes.

```bash
cmake -S tests/cpp -B build/test -G Ninja
bash scripts/test-runtime-contract.sh cpp
```

## Other checked-in component tests

Run these from the stated directories when changing those components:

```bash
# Guardian Go package
( cd go/guardian && go test ./... )

# Go manager/backend package checks used by CI
( cd go && go vet ./ppp/... && go test ./ppp/... )

# Android Flutter tests
( cd android && flutter pub get && flutter test )

# iOS logic tests
( cd ios/App && ./run-tests.sh )

# Experimental Desktop Client frontend and Rust shell
( cd desktop/client && npm ci && npm test && npm run build \
  && cargo test --manifest-path src-tauri/Cargo.toml )
```

Some commands require their platform SDK/toolchain; do not treat a missing local SDK as a runtime failure.

## Root CMake test-related options

All of these options default to `OFF`:

| Option | Effect |
|---|---|
| `ENABLE_TESTS` | Enables CTest and adds the root GTest/DNS test subdirectory. |
| `ENABLE_COVERAGE` | Adds LLVM coverage instrumentation on non-MSVC toolchains. |
| `ENABLE_VMUX_CHURN_TEST` | Builds and registers the root-linked VMUX carrier-churn integration test. |
| `ENABLE_VMUX_RECEIVE_SEMANTICS_TEST` | Builds and registers the root-linked VMUX receive-semantics test. |
| `ENABLE_ASAN`, `ENABLE_UBSAN` | Enable diagnostic sanitizer flags in the root project; not production build modes. |

## CI coverage today

`.github/workflows/test.yml` is the primary unit-test workflow. It runs the standalone C++/coverage path, a separate full-suite ThreadSanitizer job, lifecycle sanitizers, Guardian and Go checks, Flutter tests, and iOS logic tests. It does **not** run the experimental Desktop Client's npm or Cargo test commands.

Native build workflows are separate from that unit workflow. Read the relevant workflow before calling a platform or feature combination CI-covered.
