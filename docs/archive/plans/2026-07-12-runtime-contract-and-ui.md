# Runtime Contract and UI Implementation Plan

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

**Goal:** Create one versioned runtime state contract consumed by C++ TUI, Android Flutter, and iOS UI.

**Architecture:** The C++ runtime owns truth and publishes immutable `RuntimeSnapshot` values. Platform bridges serialize or map those values. Dart and Swift stores reduce snapshots into UI state. UI sends commands and never mutates runtime internals.

**Tech Stack:** C++17, Boost.Test, JSON, Dart/Flutter, Kotlin, Swift, XCTest.

## Global Constraints

- Schema version starts at `1`.
- Every snapshot contains `schema_version`, `generation`, `monotonic_ms`, and `phase`.
- Unknown optional fields are ignored; unknown schema versions are rejected.
- UI does not parse logs to infer state.
- `Connected` is emitted only after adapter, session, route, DNS, and policy are ready.

---

### Task 1: Define C++ Runtime Contract Types

**Files:**
- Create: `ppp/app/runtime/RuntimePhase.h`
- Create: `ppp/app/runtime/RuntimeError.h`
- Create: `ppp/app/runtime/RuntimeSnapshot.h`
- Test: `tests/cpp/runtime_snapshot_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `enum class RuntimePhase`, `struct RuntimeError`, `struct RuntimeSnapshot`.

- [x] **Step 1: Write a failing enum/string conversion test**

```cpp
#define BOOST_TEST_MODULE runtime_snapshot_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/app/runtime/RuntimePhase.h>

BOOST_AUTO_TEST_CASE(runtime_phase_round_trip) {
    using namespace ppp::app::runtime;
    BOOST_TEST(ToString(RuntimePhase::Connected) == "connected");
    BOOST_TEST(ParseRuntimePhase("reconnecting") == RuntimePhase::Reconnecting);
}
```

- [x] **Step 2: Register and run the test**

Run:

```bash
cmake -S tests/cpp -B build/test -G Ninja
cmake --build build/test --target runtime_snapshot_test
ctest --test-dir build/test -R runtime_snapshot_test --output-on-failure
```

Expected: compilation fails because `RuntimePhase.h` does not exist.

- [x] **Step 3: Implement the phase type**

```cpp
#pragma once
#include <ppp/stdafx.h>

namespace ppp::app::runtime {
enum class RuntimePhase : uint8_t {
    Idle,
    Starting,
    PreparingHost,
    Connecting,
    Handshaking,
    ApplyingPolicy,
    Connected,
    Reconnecting,
    Stopping,
    Failed,
    Unknown,
};

const char* ToString(RuntimePhase phase) noexcept;
RuntimePhase ParseRuntimePhase(const ppp::string& value) noexcept;
}
```

Add the definitions in `RuntimePhase.cpp` if non-inline implementation is preferred; register it in both CMake and MSVC project parity lists.

- [x] **Step 4: Add snapshot invariants test**

```cpp
BOOST_AUTO_TEST_CASE(default_snapshot_is_idle_and_versioned) {
    ppp::app::runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(snapshot.schema_version == 1u);
    BOOST_TEST(snapshot.generation == 0u);
    BOOST_TEST(snapshot.phase == ppp::app::runtime::RuntimePhase::Idle);
}
```

- [x] **Step 5: Implement minimal snapshot and error DTOs**

Required fields:

```cpp
struct RuntimeError {
    uint32_t code = 0;
    ppp::string severity;
    bool retryable = false;
    ppp::string user_message_key;
    ppp::string diagnostic_detail;
};

struct RuntimeSnapshot {
    uint32_t schema_version = 1;
    uint64_t generation = 0;
    uint64_t monotonic_ms = 0;
    RuntimePhase phase = RuntimePhase::Idle;
    ppp::string role;
    ppp::string server;
    ppp::string transport;
    ppp::string requested_mux_mode;
    ppp::string effective_mux_mode;
    ppp::string mux_fallback_reason;
    ppp::string p2p_state;
    ppp::string effective_path;
    RuntimeError last_error;
};
```

- [x] **Step 6: Run tests and commit**

```bash
ctest --test-dir build/test -R runtime_snapshot_test --output-on-failure
git add ppp/app/runtime tests/cpp
 git commit -m "feat(runtime): define versioned runtime snapshot"
```

### Task 2: Add JSON Serialization and Contract Fixtures

**Files:**
- Create: `ppp/app/runtime/RuntimeSnapshotJson.h`
- Create: `ppp/app/runtime/RuntimeSnapshotJson.cpp`
- Create: `schemas/runtime-snapshot-v1.schema.json`
- Create: `tests/contracts/runtime-snapshot/idle.json`
- Create: `tests/contracts/runtime-snapshot/connected.json`
- Create: `tests/contracts/runtime-snapshot/reconnecting.json`
- Create: `tests/contracts/runtime-snapshot/failed.json`
- Modify: `tests/cpp/runtime_snapshot_test.cpp`

**Interfaces:**
- Produces: `ppp::string SerializeRuntimeSnapshot(const RuntimeSnapshot&)` and `bool ParseRuntimeSnapshot(const ppp::string&, RuntimeSnapshot&)`.

- [x] **Step 1: Add failing serialization test**

```cpp
BOOST_AUTO_TEST_CASE(snapshot_json_preserves_generation_and_phase) {
    RuntimeSnapshot source;
    source.generation = 7;
    source.phase = RuntimePhase::Connected;
    const ppp::string json = SerializeRuntimeSnapshot(source);
    RuntimeSnapshot decoded;
    BOOST_REQUIRE(ParseRuntimeSnapshot(json, decoded));
    BOOST_TEST(decoded.generation == 7u);
    BOOST_TEST(decoded.phase == RuntimePhase::Connected);
}
```

- [x] **Step 2: Implement serializer/parser using the repository JSON library**

Reject input when:

```text
schema_version != 1
phase is missing
phase is unknown
```

Ignore unknown optional properties.

- [x] **Step 3: Add fixture tests**

Read all files under `tests/contracts/runtime-snapshot/` and assert they parse successfully. Add one invalid fixture with `schema_version: 99` and assert rejection.

- [x] **Step 4: Validate JSON schema locally**

Run:

```bash
python3 -m json.tool schemas/runtime-snapshot-v1.schema.json >/dev/null
python3 -m json.tool tests/contracts/runtime-snapshot/connected.json >/dev/null
```

Expected: both commands exit `0`.

- [x] **Step 5: Commit**

```bash
git add ppp/app/runtime schemas tests/contracts tests/cpp
 git commit -m "feat(runtime): serialize runtime contract v1"
```

### Task 3: Publish Snapshots from PppApplication

**Files:**
- Create: `ppp/app/runtime/RuntimeStatePublisher.h`
- Create: `ppp/app/runtime/RuntimeStatePublisher.cpp`
- Modify: `ppp/app/PppApplication.h`
- Modify: relevant `ppp/app/Application*.cpp` lifecycle files
- Test: `tests/cpp/runtime_state_publisher_test.cpp`

**Interfaces:**
- Produces:

```cpp
using RuntimeSnapshotHandler = ppp::function<void(const RuntimeSnapshot&)>;
uint64_t BeginGeneration() noexcept;
void UpdatePhase(RuntimePhase phase) noexcept;
RuntimeSnapshot GetSnapshot() const noexcept;
void Subscribe(RuntimeSnapshotHandler handler);
```

- [x] **Step 1: Test monotonic generations**

```cpp
BOOST_AUTO_TEST_CASE(begin_generation_is_monotonic) {
    RuntimeStatePublisher publisher;
    BOOST_TEST(publisher.BeginGeneration() == 1u);
    BOOST_TEST(publisher.BeginGeneration() == 2u);
}
```

- [x] **Step 2: Test subscriber receives immutable copy**

The handler must receive a value snapshot after each state transition and must not execute while the publisher mutex is held.

- [x] **Step 3: Integrate lifecycle transitions**

Map existing runtime points to phases:

```text
Run accepted -> Starting
host/TAP preparation -> PreparingHost
transport open -> Connecting
protocol handshake -> Handshaking
INFO and host policy application -> ApplyingPolicy
all required components ready -> Connected
link restart -> Reconnecting
shutdown accepted -> Stopping
cleanup complete -> Idle
non-recoverable error -> Failed
```

- [x] **Step 4: Add negative test**

Assert `Connected` cannot be published when required readiness flags are false. Implement a single `RuntimeReadiness` value rather than scattering checks through UI code.

- [x] **Step 5: Run and commit**

```bash
ctest --test-dir build/test -R "runtime_(snapshot|state_publisher)_test" --output-on-failure
git add ppp/app/runtime ppp/app tests/cpp
 git commit -m "feat(runtime): publish lifecycle snapshots"
```

### Task 4: Convert C++ TUI to RuntimeSnapshot

**Files:**
- Create: `ppp/app/tui/TuiRuntimeAdapter.h`
- Create: `ppp/app/tui/TuiRuntimeAdapter.cpp`
- Modify: `ppp/app/ConsoleUI.h`
- Modify: `ppp/app/ConsoleUI.cpp`
- Test: `tests/cpp/tui_runtime_adapter_test.cpp`

**Interfaces:**
- Consumes: `RuntimeSnapshot`.
- Produces: `ppp::vector<ppp::string> BuildStatusLines(const RuntimeSnapshot&)`.

- [x] **Step 1: Add failing renderer test**

```cpp
BOOST_AUTO_TEST_CASE(connected_snapshot_renders_effective_mode) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    snapshot.requested_mux_mode = "balance";
    snapshot.effective_mux_mode = "compat";
    snapshot.mux_fallback_reason = "peer_missing_flow_v2";
    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Connected"));
    BOOST_TEST(ContainsLine(lines, "compat"));
    BOOST_TEST(ContainsLine(lines, "peer_missing_flow_v2"));
}
```

- [x] **Step 2: Implement adapter and replace direct runtime reads**

The TUI may still render traffic detail, but lifecycle labels and negotiated modes must come from the snapshot.

- [x] **Step 3: Add failed/stopping renderer cases**

Ensure `Stopping` does not render as disconnected and `Failed` includes the error triplet.

- [x] **Step 4: Run and commit**

```bash
ctest --test-dir build/test -R tui_runtime_adapter_test --output-on-failure
git commit -am "refactor(tui): render runtime snapshots"
```

### Task 5: Add Android Runtime Model and Store

**Files:**
- Create: `android/lib/runtime/runtime_snapshot.dart`
- Create: `android/lib/runtime/runtime_store.dart`
- Create: `android/lib/runtime/runtime_bridge.dart`
- Create: `android/test/runtime_snapshot_test.dart`
- Create: `android/test/runtime_store_test.dart`
- Modify: Android native bridge/service files that currently expose link state.

**Interfaces:**
- Produces: `RuntimeSnapshot.fromJson(Map<String, dynamic>)` and `RuntimeStore.apply(RuntimeSnapshot)`.

- [x] **Step 1: Parse shared fixtures in Dart tests**

Load copied fixtures from `tests/contracts/runtime-snapshot/` through a test helper. Assert schema version, generation, phase, requested/effective mode.

- [x] **Step 2: Reject unsupported schema**

```dart
expect(
  () => RuntimeSnapshot.fromJson({'schema_version': 99, 'phase': 'idle'}),
  throwsFormatException,
);
```

- [x] **Step 3: Implement stale-generation reducer**

```dart
void apply(RuntimeSnapshot incoming) {
  if (incoming.generation < state.generation) return;
  state = incoming;
  notifyListeners();
}
```

- [x] **Step 4: Replace optimistic UI state changes**

The connect button sends a command and waits for `Starting`. The stop button sends a command and waits for `Stopping`/`Idle`. Do not set `connected = true/false` directly in widgets.

- [x] **Step 5: Run and commit**

```bash
cd android
flutter test test/runtime_snapshot_test.dart test/runtime_store_test.dart
cd ..
git add android
 git commit -m "feat(android): consume runtime contract v1"
```

### Task 6: Add iOS Runtime Model and Store

**Files:**
- Create: `ios/App/OpenPPP2/Runtime/RuntimeSnapshot.swift`
- Create: `ios/App/OpenPPP2/Runtime/RuntimeStore.swift`
- Create: `ios/App/OpenPPP2/Runtime/TunnelRuntimeBridge.swift`
- Create: `ios/App/Tests/OpenPPP2LogicTests/RuntimeSnapshotTests.swift`
- Create: `ios/App/Tests/OpenPPP2LogicTests/RuntimeStoreTests.swift`
- Modify: `ios/App/Package.swift`
- Modify: `ios/App/OpenPPP2/TunnelSharedState.swift`

**Interfaces:**
- Produces: `Codable RuntimeSnapshot` and `@MainActor final class RuntimeStore: ObservableObject`.

- [x] **Step 1: Decode shared fixtures**

```swift
func testConnectedFixtureDecodesEffectiveMode() throws {
    let snapshot = try decodeFixture("connected.json")
    XCTAssertEqual(snapshot.phase, .connected)
    XCTAssertEqual(snapshot.effectiveMuxMode, "flow")
}
```

- [x] **Step 2: Implement generation filtering**

Apply snapshots on the main actor and ignore lower generations.

- [x] **Step 3: Replace integer-only heartbeat state**

Keep heartbeat freshness for extension liveness, but store/read the latest contract JSON as the authoritative detailed state.

- [x] **Step 4: Add stale-state handling**

When heartbeat is older than the configured deadline, expose `.unknown` presentation state instead of leaving `.connected` visible.

- [x] **Step 5: Run and commit**

```bash
cd ios/App
./run-tests.sh
cd ../..
git add ios/App
 git commit -m "feat(ios): consume runtime contract v1"
```

### Task 7: Update UI Screens and Documentation

**Files:**
- Modify: Android home/settings/diagnostics widgets
- Modify: iOS connection/settings/diagnostics views
- Modify: TUI status renderer
- Create: `docs/reference/UI_RUNTIME_CONTRACT.md`
- Create: `docs/adr/0001-runtime-ui-contract.md`

- [x] **Step 1: Define presentation mapping table in the ADR**

Include exact button behavior for every phase and specify that `Reconnecting` retains Stop while disabling configuration edits.

- [x] **Step 2: Implement phase-driven controls**

Required behavior:

```text
Idle -> Start enabled
Starting/Preparing/Connecting/Handshaking/ApplyingPolicy -> Cancel enabled
Connected/Reconnecting -> Stop enabled
Stopping -> all connection actions disabled
Failed -> Retry enabled and configuration editable
Unknown -> diagnostics and force-stop available
```

- [x] **Step 3: Add widget/view tests**

Cover at least `Idle`, `Connected`, `Reconnecting`, `Stopping`, `Failed`, and stale/unknown.

- [x] **Step 4: Run complete UI suites**

```bash
cd android && flutter test
cd ../ios/App && ./run-tests.sh
```

Expected: all tests pass.

- [x] **Step 5: Commit**

```bash
git add android ios ppp/app/tui docs/reference docs/adr
 git commit -m "feat(ui): drive all surfaces from runtime snapshots"
```
