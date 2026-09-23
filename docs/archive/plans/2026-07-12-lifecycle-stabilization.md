# Lifecycle Stabilization Implementation Plan

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle, Git history, and the latest main verification record, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.

> Status: Implemented
> Type: Plan
> Last verified: 5bcccce

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make startup, reconnect, stop, and teardown deadlock-free, ownership-safe, idempotent, and accurately reflected in every UI.

**Architecture:** One generation owns one lifecycle attempt. Stop atomically claims teardown responsibility. Shared callback bundles use immutable snapshots and weak ownership. Runtime phase changes are emitted through the contract introduced by the preceding plan.

**Tech Stack:** C++17, Boost.Asio, Boost.Test, ASan/UBSan, Flutter, Swift.

## Global Constraints

- Never replace the identified lock problem with `std::recursive_mutex`.
- No callback may strongly retain the switcher when the switcher stores that callback.
- Public APIs acquire locks; `*Locked` helpers require the lock already held.
- Stop and Finalize are safe when called repeatedly.
- UI only reaches Idle after host-side rollback completes.

---

### Task 1: Reproduce the Desktop Teardown Deadlock

**Files:**
- Create: `tests/cpp/client_teardown_deadlock_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Test support: reuse or extend `tests/cpp/support/dns_host_wiring_switcher_stub.cpp`

- [x] **Step 1: Write a bounded teardown test**

Create a switcher test owner that builds `DnsHostPortsFor`, then invokes `ClientConnectionTeardown::ReleaseAllObjects()` on a worker and waits with `std::future::wait_for(std::chrono::seconds(2))`.

Expected assertion:

```cpp
BOOST_TEST(future.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
```

- [x] **Step 2: Run and verify failure or timeout**

```bash
cmake -S tests/cpp -B build/test -G Ninja
cmake --build build/test --target client_teardown_deadlock_test
ctest --test-dir build/test -R client_teardown_deadlock_test --output-on-failure
```

Expected before fix: timeout/failure on desktop path.

- [x] **Step 3: Commit the red test**

```bash
git add tests/cpp
 git commit -m "test(client): reproduce teardown DNS cache deadlock"
```

### Task 2: Split Locked and Public DNS Cache Invalidation

**Files:**
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.h` or relevant private `.inc`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `ppp/app/client/ClientConnectionTeardown.cpp`

**Interfaces:**
- Produces:

```cpp
void InvalidateDnsHostPorts() noexcept;
void InvalidateDnsHostPortsLocked() noexcept;
```

- [x] **Step 1: Add private locked helper**

```cpp
void VEthernetNetworkSwitcher::InvalidateDnsHostPortsLocked() noexcept {
    dns_host_ports_cache_.reset();
    dns_host_ports_exchanger_.reset();
}
```

- [x] **Step 2: Keep lock acquisition in the public function**

```cpp
void VEthernetNetworkSwitcher::InvalidateDnsHostPorts() noexcept {
    SynchronizedObjectScope scope(/* existing platform-appropriate mutex */);
    InvalidateDnsHostPortsLocked();
}
```

- [x] **Step 3: Call locked helper from teardown**

Because teardown already holds `prdr_` on desktop, call `InvalidateDnsHostPortsLocked()` there.

- [x] **Step 4: Run deadlock and existing DNS tests**

```bash
ctest --test-dir build/test -R "client_teardown_deadlock_test|dns_host_wiring_test" --output-on-failure
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ppp/app/client tests/cpp
 git commit -m "fix(client): avoid recursive DNS cache lock during teardown"
```

### Task 3: Replace Borrowed DNS Cache Reference with Shared Snapshot

**Files:**
- Modify: `ppp/app/client/dns/DnsHost.h`
- Modify: `ppp/app/client/VEthernetNetworkSwitcherMembers.inc`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: call sites in `ClientPacketDispatchHandler.cpp` and `DnsInterceptor.cpp`
- Test: `tests/cpp/dns_host_wiring_test.cpp`

**Interfaces:**
- Replace:

```cpp
const dns::DnsHostPorts& DnsHostPortsFor(...)
```

- With:

```cpp
std::shared_ptr<const dns::DnsHostPorts> DnsHostPortsFor(...)
```

- [x] **Step 1: Add lifetime regression test**

Obtain a snapshot, invalidate the owner cache, then assert the retained snapshot remains valid and callable.

- [x] **Step 2: Change cache storage**

```cpp
std::shared_ptr<const dns::DnsHostPorts> dns_host_ports_cache_;
```

Build a new mutable value locally, then publish it as `shared_ptr<const ...>` while holding the lock.

- [x] **Step 3: Update callers**

Copy the shared pointer under lock and use it after the lock is released. Return false when the snapshot is null or invalid.

- [x] **Step 4: Run DNS and dispatch tests**

```bash
ctest --test-dir build/test -R "dns_host|dispatch" --output-on-failure
```

- [x] **Step 5: Commit**

```bash
git add ppp/app/client tests/cpp
 git commit -m "refactor(dns): publish immutable host-port snapshots"
```

### Task 4: Remove Strong Callback Ownership Cycle

**Files:**
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Test: `tests/cpp/dns_host_wiring_test.cpp`

- [x] **Step 1: Add destruction regression test**

Hold only the returned `DnsHostPorts` snapshot, release the switcher, and assert a `weak_ptr<VEthernetNetworkSwitcher>` expires.

- [x] **Step 2: Capture weak switcher in stored callbacks**

```cpp
std::weak_ptr<VEthernetNetworkSwitcher> weak_self = self;
host.get_tap = [weak_self]() noexcept {
    auto self = weak_self.lock();
    return self ? self->GetTap() : std::shared_ptr<ppp::tap::ITap>();
};
```

Apply the same rule to every callback retained by the switcher.

- [x] **Step 3: Define safe fallback behavior**

Callbacks return false, null, or no-op after owner expiry. They must not dereference an expired weak pointer.

- [x] **Step 4: Run and commit**

```bash
ctest --test-dir build/test -R dns_host_wiring_test --output-on-failure
git commit -am "fix(dns): break switcher callback ownership cycle"
```

### Task 5: Add Generation-Scoped Idempotent Stop

**Files:**
- Create: `ppp/app/runtime/RuntimeStopCoordinator.h`
- Create: `ppp/app/runtime/RuntimeStopCoordinator.cpp`
- Modify: `ppp/app/PppApplication.h`
- Modify: application shutdown implementation files
- Test: `tests/cpp/runtime_stop_coordinator_test.cpp`

**Interfaces:**

```cpp
bool TryBeginStop(uint64_t generation) noexcept;
void CompleteStop(uint64_t generation, bool success) noexcept;
bool IsStopping(uint64_t generation) const noexcept;
```

- [x] **Step 1: Test first caller wins**

```cpp
BOOST_AUTO_TEST_CASE(stop_is_claimed_once_per_generation) {
    RuntimeStopCoordinator stop;
    BOOST_TEST(stop.TryBeginStop(7));
    BOOST_TEST(!stop.TryBeginStop(7));
}
```

- [x] **Step 2: Test old generation cannot stop new session**

After generation 8 starts, a stop command for generation 7 must be rejected.

- [x] **Step 3: Integrate shutdown entry points**

Signal handlers, TUI commands, Android, and iOS all call the same coordinator path.

- [x] **Step 4: Emit phase changes**

First accepted stop emits `Stopping`; completion emits `Idle`; cleanup failure emits `Failed` with a cleanup error.

- [x] **Step 5: Run and commit**

```bash
ctest --test-dir build/test -R runtime_stop_coordinator_test --output-on-failure
git add ppp/app/runtime ppp/app tests/cpp
 git commit -m "feat(runtime): make stop generation-scoped and idempotent"
```

### Task 6: Add Lifecycle Stress and Sanitizer Coverage

**Files:**
- Create: `tests/cpp/client_lifecycle_stress_test.cpp`
- Create: `scripts/run-lifecycle-sanitizers.sh`
- Modify: `.github/workflows/test.yml`
- Modify: `docs/TESTING.md`

- [x] **Step 1: Add 100-cycle deterministic stress test**

Use fakes for platform effects. For each cycle: begin generation, enter start phases, publish connected, request stop twice, complete cleanup, assert Idle and no retained callbacks.

- [x] **Step 2: Add cancellation points**

Repeat stop during `PreparingHost`, `Connecting`, `Handshaking`, `ApplyingPolicy`, `Connected`, and `Reconnecting`.

- [x] **Step 3: Add ASan/UBSan script**

```bash
cmake -S . -B build-asan -G Ninja \
  -DENABLE_TESTS=ON -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan
ctest --test-dir build-asan -R "lifecycle|teardown|dns_host" --output-on-failure
```

- [x] **Step 4: Add CI job**

Run the sanitizer subset on pull requests touching `ppp/app/client/**`, `ppp/app/runtime/**`, or lifecycle tests.

- [x] **Step 5: Commit**

```bash
git add tests scripts .github docs/TESTING.md
 git commit -m "test(runtime): add lifecycle stress and sanitizer gate"
```

### Task 7: Align Android, iOS, and TUI Stop Behavior

**Files:**
- Modify: Android runtime store and connection controls
- Modify: iOS runtime store and connection controls
- Modify: TUI command handler
- Test: Dart, Swift, and C++ UI reducer tests

- [x] **Step 1: Test duplicate stop commands**

Each UI sends at most one active stop command for a generation and remains in `Stopping` until the runtime responds.

- [x] **Step 2: Test stale completion**

A completion event for generation 7 must not change UI state for generation 8.

- [x] **Step 3: Implement timeout presentation**

A UI-side timeout does not force Idle. It displays `Stopping is taking longer than expected` with diagnostics/force-stop actions while retaining the true runtime phase.

- [x] **Step 4: Run all UI tests** — Dart, Swift, and TUI suites passed on the `ef97c8c` evidence baseline.

```bash
cd android && flutter test
cd ../ios/App && ./run-tests.sh
cd ../..
ctest --test-dir build/test -R tui_runtime_adapter_test --output-on-failure
```

- [x] **Step 5: Commit**

```bash
git add android ios ppp/app/tui
 git commit -m "fix(ui): align stop behavior with runtime lifecycle"
```
