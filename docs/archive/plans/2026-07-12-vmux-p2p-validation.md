# VMUX and P2P Validation Implementation Plan

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle, Git history, and the latest main verification record, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.

> Status: In progress
> Type: Plan
> Last verified: 5bcccce

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate VMUX modes with observable requested/effective state, then prepare a secure and testable P2P direct-path implementation without weakening relay connectivity.

**Architecture:** VMUX publishes negotiated capabilities, effective mode, receiver ordering, link count, and fallback reason through `RuntimeSnapshot`. Benchmarks and fault injection determine rollout. P2P begins with protocol, state, crypto, and replay tests before any direct data path is enabled.

**Tech Stack:** C++17, Boost.Asio, Boost.Test, iperf3, tc netem, Linux namespaces, Flutter, Swift, GitHub Actions.

## Global Constraints

- Keep `compat` as default until benchmark gates pass.
- Requested mode and effective mode are separate fields.
- Unsupported peers fail safe to compatible ordering.
- `stripe` remains experimental and hidden from normal UI.
- P2P failure never tears down the base relay tunnel.
- Direct is displayed only after authenticated channel establishment.
- Never expose keys, tokens, or replay material in UI/telemetry.

---

### Task 1: Publish VMUX Negotiation State

**Files:**
- Modify: `ppp/app/mux/vmux_net.h`
- Modify: `ppp/app/mux/vmux_net.cpp`
- Modify: client/server exchanger negotiation paths
- Modify: `ppp/app/runtime/RuntimeSnapshot.h`
- Test: `tests/cpp/vmux_runtime_state_test.cpp`

**Interfaces:**

```cpp
struct MuxRuntimeState {
    ppp::string requested_mode;
    ppp::string effective_mode;
    ppp::string receiver_ordering;
    uint16_t active_links = 0;
    ppp::string fallback_reason;
};
```

- [x] **Step 1: Test compatible negotiation**

Request `flow`, advertise FLOW_V2 on both peers, and assert effective mode/order are reported correctly.

- [x] **Step 2: Test fallback**

Request `balance`, simulate a peer without FLOW_V2, and assert:

```text
effective_mode = compat
receiver_ordering = compat
fallback_reason = peer_missing_flow_v2
```

- [x] **Step 3: Publish state after handshake and link changes**

Update active link count on add, retire, and reap. Do not emit one snapshot per packet.

- [x] **Step 4: Run and commit** (`7719c5f`)

```bash
ctest --test-dir build/test -R vmux_runtime_state_test --output-on-failure
git add ppp/app/mux ppp/app/runtime ppp/app/client ppp/app/server tests/cpp
 git commit -m "feat(vmux): publish negotiated runtime state"
```

### Task 2: Render Requested and Effective VMUX State in UI

**Files:**
- Modify: Android advanced settings and diagnostics views
- Modify: iOS advanced settings and diagnostics views
- Modify: TUI runtime adapter
- Test: Dart widget, Swift view-model, and C++ renderer tests

- [x] **Step 1: Add capability-driven selector tests**

Modes unavailable in `snapshot.capabilities` are disabled or hidden. `stripe` is visible only in developer/experimental mode.

- [x] **Step 2: Add fallback presentation**

The normal UI shows `Compatibility mode` while diagnostics show requested mode and fallback reason.

- [x] **Step 3: Mark restart-required changes**

Changing negotiated mode updates configuration but displays `Takes effect on next connection`; do not hot-switch production sessions.

- [x] **Step 4: Run and commit** (`b991cd1`)

```bash
cd android && flutter test
cd ../ios/App && ./run-tests.sh
cd ../..
ctest --test-dir build/test -R tui_runtime_adapter_test --output-on-failure
git add android ios ppp/app/tui
 git commit -m "feat(ui): expose effective VMUX mode and fallback"
```

### Task 3: Build Repeatable VMUX Benchmark Harness

**Files:**
- Create: `benchmarks/vmux/run.sh`
- Create: `benchmarks/vmux/netem.sh`
- Create: `benchmarks/vmux/README.md`
- Create: `benchmarks/vmux/result.schema.json`
- Create: `benchmarks/vmux/parse_results.py`

- [x] **Step 1: Define benchmark matrix**

Required scenarios:

```text
mux off, one flow
compat, one flow
flow, one flow
compat, eight flows
flow, eight flows
balance, eight flows
one carrier with added delay
one carrier with packet loss
runtime carrier removal
turbo grow/shrink churn
```

- [x] **Step 2: Capture metrics**

Write JSON containing throughput, p50/p99 latency, reorder depth, buffered bytes, active links, disconnects, and fallback state.

- [x] **Step 3: Add deterministic netem profiles**

Profiles must include exact delay/loss/rate parameters and clean themselves up on exit.

- [x] **Step 4: Run local smoke benchmark**

```bash
sudo benchmarks/vmux/run.sh --scenario one-flow --duration 10
python3 benchmarks/vmux/parse_results.py build/benchmarks/vmux/*.json
```

- [x] **Step 5: Commit** (`62c7441`)

```bash
git add benchmarks
 git commit -m "bench(vmux): add repeatable scheduler benchmark harness"
```

### Task 4: Add VMUX Fault and Compatibility Tests

**Files:**
- Create: `tests/cpp/vmux_negotiation_test.cpp`
- Create: `tests/cpp/vmux_link_churn_test.cpp`
- Create: `tests/cpp/vmux_flow_reorder_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`

- [x] **Step 1: Test old peer fallback**
- [x] **Step 2: Test reordered per-flow frames remain isolated**
- [x] **Step 3: Test bounded reorder memory**
- [x] **Step 4: Test retiring link with in-flight writes**
- [x] **Step 5: Test actual `vmux_net` repeated grow/shrink under ASan**

  The root-linked `vmux_net_churn_integration_test` drives the production
  attach helper, live RX/TX containers, in-flight retirement gate, reap,
  exactly-once transport disposal, and runtime active-link count for 100
  grow/shrink cycles. It passed both the normal jemalloc build and the
  ASan+UBSan build with leak detection on 2026-07-15 (`ded25d6`). This is
  carrier-container lifecycle evidence; it does not claim real network I/O.
- [x] **Step 6: Commit** (`2566750`)

```bash
ctest --test-dir build/test -R "vmux_(negotiation|link_churn|flow_reorder)_test" --output-on-failure
git add tests/cpp
 git commit -m "test(vmux): cover negotiation reorder and link churn"
```

### Task 5: Define VMUX Rollout Gate

**Files:**
- Create: `docs/reference/VMUX_VALIDATION.md`
- Modify: `docs/MUX_PERFLOW_DELIVERY_DESIGN_CN.md`
- Modify: configuration docs

- [x] **Step 1: Record exact acceptance thresholds**

Initial thresholds:

```text
flow single-stream throughput >= 95% of mux-off baseline
flow-one-flow p99 <= 110% of off-one-flow p99 on equal links
reorder memory never exceeds configured bound
old peer always falls back to compatible receiver ordering; balance/stripe fall back to compat mode
no sanitizer failure during 100 grow/shrink cycles
```

- [x] **Step 2: Require two-platform evidence before default change**

At minimum Linux desktop and one mobile platform.

- [x] **Step 3: Keep compat default until evidence is attached**

A default change requires a separate PR containing benchmark artifacts and compatibility results.

- [x] **Step 4: Documentation completed against evidence baseline `2566750`**

```bash
git add docs
 git commit -m "docs(vmux): define scheduler rollout gates"
```

### Task 6: Correct P2P Replay Window Edge Cases

**Files:**
- Modify: `ppp/p2p/P2PReplayWindow.h`
- Modify: `tests/cpp/p2p_replay_window_test.cpp`
- Modify: `tests/red-manifest/p2p_replay_window.md`

- [x] **Step 1: Add failing zero-sequence test**

```cpp
BOOST_AUTO_TEST_CASE(replay_rejects_duplicate_zero) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(!window.Accept(0));
}
```

- [x] **Step 2: Add wrap and boundary tests**

Cover `UINT32_MAX`, reset followed by zero, exactly `REPLAY_WINDOW_SIZE - 1`, and exactly `REPLAY_WINDOW_SIZE` behind base.

- [x] **Step 3: Add explicit initialized state**

```cpp
bool initialized_ = false;
uint64_t base_ = 0;
```

Reset clears `initialized_`; first accepted sequence sets it.

- [x] **Step 4: Run and commit** (`df3c89c`)

```bash
ctest --test-dir build/test -R p2p_replay_window_test --output-on-failure
git add ppp/p2p tests/cpp tests/red-manifest
 git commit -m "fix(p2p): handle zero sequence in replay window"
```

### Task 7: Write and Accept P2P Protocol ADR Before Data Path

**Files:**
- Create: `docs/adr/0002-p2p-direct-channel-security.md`
- Create: `docs/design/p2p-direct-channel/protocol.md`
- Create: `docs/design/p2p-direct-channel/state-machine.md`
- Create: `docs/design/p2p-direct-channel/threat-model.md`

- [x] **Step 1: Define transport-independent session exporter or TLS-only restriction**

The ADR must explicitly choose one. It must not assume a TLS master secret exists for raw TCP sessions.

- [x] **Step 2: Define wire version and downgrade behavior**
- [x] **Step 3: Define directional keys, nonce construction, replay window, token lifetime, and restart rules**
- [x] **Step 4: Define NAT candidate authentication and migration grace**
- [x] **Step 5: Define reflection/amplification and probe rate limits**
- [x] **Step 6: Define relay fallback as mandatory invariant**
- [x] **Step 7: Review and commit design only** (`c66156b`)

```bash
git add docs/adr docs/design/p2p-direct-channel
 git commit -m "docs(p2p): specify direct-channel security and lifecycle"
```

Do not implement the direct data path in this task.

### Task 8: Add P2P State Contract and UI Before Networking

**Files:**
- Create: `ppp/p2p/P2PState.h`
- Modify: `ppp/app/runtime/RuntimeSnapshot.h`
- Modify: Android, iOS, and TUI runtime models
- Test: C++, Dart, Swift state mapping tests

**Interfaces:**

```cpp
enum class P2PState {
    Disabled,
    Unavailable,
    Relay,
    Eligible,
    Probing,
    Direct,
    Suspect,
    FallingBack,
    Failed,
};
```

- [x] **Step 1: Add phase mapping tests**
- [x] **Step 2: Add effective path field: `relay` or `direct`**
- [x] **Step 3: Ensure Probing still reports relay as effective path**
- [x] **Step 4: Ensure P2P Failed leaves base RuntimePhase Connected when relay works**
- [x] **Step 5: Render user-facing path status and diagnostic detail**
- [x] **Step 6: Commit** (`0f84662`)

```bash
git add ppp/p2p ppp/app/runtime android ios ppp/app/tui tests
 git commit -m "feat(p2p): define observable direct-path state"
```

### Task 9: Implement P2P Control Plane and Authentication Tests

**Files:**
- Create focused files under `ppp/p2p/` for token validation, packet header parsing, key derivation, and state transitions
- Create corresponding `tests/cpp/p2p_*_test.cpp`

- [x] **Step 1: Implement packet parser from test vectors only**
- [x] **Step 2: Implement key derivation from the accepted ADR**
- [x] **Step 3: Implement token expiry and peer binding tests**
- [x] **Step 4: Implement replay and endpoint spoof rejection tests**
- [x] **Step 5: Implement `Relay -> Probing -> Direct -> Suspect -> FallingBack -> Relay` as a pure state machine**
- [x] **Step 6: Run under ASan/UBSan and commit** (`ea13340`)

No socket forwarding is enabled yet.

### Task 10: Add Protected UDP Channel Behind Experimental Capability

**Files:**
- Create platform socket protection adapters for Linux/Android/iOS
- Create `ppp/p2p/P2PChannel.*`
- Modify exchangers only through an explicit P2P coordinator interface
- Add integration and adversarial tests

- [x] **Step 1: Add disabled-by-default capability flag** (`463f137`)
- [x] **Step 2: Protect socket before first probe** (`463f137`)
- [x] **Step 3: Authenticate probe/ack before Direct transition** (`1598ea4`)
- [x] **Step 4: Forward data only while state is Direct** (`669d5be`)
- [x] **Step 5: Fall back to relay on timeout, auth failure, socket error, or migration failure** (`1c5cd39`)
- [x] **Step 6: Test UDP blocked, symmetric NAT, stale token, spoofed endpoint, and process restart** (`1c9fa59`)
- [x] **Step 7: Verify UI never reports Direct before authentication** (`bb52e04`)
- [x] **Step 8: Commit platform-separated integration slices**

P2P must remain experimental until the release gate in the roadmap is satisfied.

Current production wiring at `main@5bcccce` includes the authenticated WSS
session exporter, asynchronous server-side offer coordination, client offer
validation, protected UDP candidate transports, direct-data handling, and typed
`RuntimeSnapshot` projection. Raw TCP retains the default no-exporter behavior
and therefore remains relay-only. The control-v1 path keeps the single-use
authenticated ACK proof, offer/session/peer/epoch/role/endpoint/TTL bindings,
directional keys, nonce and replay checks, and mandatory relay fallback.
`ProductionAuthenticatedControlV1Ready` deliberately remains `false`, so the
production capability gate still fails closed until the physical-device and
real-network release evidence below is complete.

Authenticated StaticEcho ingress now supplies production UDP endpoint
observations after the switcher verifies virtual-IP ownership against the
authoritative NAT table. Observed endpoints are deduplicated, update the
registered peer, and become offer candidates; TCP control endpoints are not
treated as UDP evidence. One outer UDP destination is insufficient to classify
mapping behavior and therefore remains `Unknown`. At least two distinct outer
destinations are required, and inner application destinations are deliberately
excluded because they do not influence the outer NAT mapping.

Local and CI evidence covers parser/crypto/state tests, repeated close and
callback cancellation, protected-transport failure, simulated UDP blackhole,
synthetic NAT classification, stale token/sequence/epoch rejection, spoofed
endpoints, Android API 34 socket protection, and iOS simulator type checking.
These results do not prove physical Android/iOS protection, background/roaming,
real symmetric NAT, production UDP blocking, process restart, or cross-platform
control-v1 interoperability. VMUX carrier-container churn is covered separately;
it is not a substitute for fixed-host or mobile netem evidence.

Historical Step 7 verification at `bb52e04`: C++ runtime snapshot, TUI, and authenticated
proof tests passed 3/3; UI wiring/schema tooling passed 13/13. The exact-SHA
`Test · Unit` workflow also passed its Flutter, iOS simulator, C++, Go, and
lifecycle sanitizer jobs. Android and Swift derive the displayed path only from
typed `p2p_state`, ignore a claimed wire `effective_path`, reject stale runtime
generations, and downgrade unknown snapshots to Unavailable/Relay. Suspect and
every pre-authentication state remain Relay; only Direct renders Direct.
Independent review found no Critical, Important, or Minor issue. Flutter and
Swift were not available on the local PATH, so their fresh evidence is CI, not a
local tool run. At that commit the production coordinator was not yet wired;
the current production wiring is described above and still publishes typed
Direct only after authenticated transition.

Step 8 Android progress at `0e750bd`: `AndroidSocketProtector` now reuses the
existing native-thread-safe `OpenPPP2VpnProtectBridge` instead of maintaining a
second placeholder JNI state. The bridge caches both `protect(I)Z` and an active
`PppVpnService` readiness method, the Kotlin service reference is volatile, and
socket protection pins a JNI local class reference so concurrent bridge shutdown
cannot invalidate an in-flight call. Missing service, disabled bridge, lookup or
Java exception, and `VpnService.protect` failure all remain fail-closed. Local
evidence includes Flutter 68/68, debug APK assembly, C++ 52/52, tooling 83/83,
production Linux library build, and MSVC source parity 202/202; independent
review found Critical 0 and Important 0. Exact-SHA CI at `f5919ab` passed 9/9,
including the complete Android workflow and its arm64-v8a, armeabi-v7a, x86,
and x86_64 native NDK builds. This is compilation and host-side test evidence;
no Android device protection or no-loop result is claimed.

Step 8 iOS progress at `06127c2`: `P2PChannel` now depends on an injected
`IP2PDatagramTransportFactory` and no longer owns a concrete UDP socket. Native
Linux/Android transport still protects before receiving or sending; `_IPHONE`
has no native-socket fallback. The PacketTunnel bridge accepts a provider-owned
callback table, while Swift uses `NEPacketTunnelProvider.createUDPSession` for
endpoint-specific UDP sessions. Close waits for in-flight sends before consuming
the retained Swift handle, late callbacks are dropped, and incomplete providers
fail closed. Local evidence includes C++ 54/54, tooling 84/84, focused
ASan/UBSan 3/3, MSVC source parity 203/203, and production compilation of the
new transport object. Independent review finished with Critical 0 and Important
0. Exact-SHA CI passed 9/9; its iOS simulator job typechecked the provider
adapter against the real SDK before running Swift tests. This is host/simulator
evidence only, not an iOS device protection or no-loop result.

Step 8 code integration is complete: the client consumes the iOS/native
transport factories, WSS transmissions expose the authenticated exporter, the
server coordinates paired offers, and the client updates its typed P2P runtime
projection. The release-evidence portion remains open: real Android/iOS device
protection, network switch/background behavior, real NAT/UDP-blocked behavior,
process restart, and cross-platform control-v1 interoperability. Consequently
`ProductionAuthenticatedControlV1Ready` remains `false` and production traffic
remains relay-only.
