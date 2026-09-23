# Client Route/DNS Decoupling Implementation Plan

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

**Goal:** Move client route and DNS state, orchestration, platform effects, and session lifetime out of `VEthernetNetworkSwitcher`, leaving it as a composition root with one-way ownership.

**Architecture:** `RouteState` owns route data, `RouteCoordinator` owns transactional apply/rollback, and `IRoutePlatform` isolates OS operations. `DnsController` owns DNS policy and session contexts while `IDnsTunnelTransport` replaces concrete Exchanger dependencies; callers hold immutable context values instead of references to a mutable cache. Repository checks enforce the resulting dependency direction.

**Tech Stack:** C++17, Boost.Asio, existing `ppp` containers and error conventions, CMake/CTest, Python `unittest`, GitHub Actions.

**Design:** `docs/superpowers/specs/2026-07-14-client-route-dns-decoupling-design.md`

---

## File responsibility map

### New production files

- `ppp/app/client/route/RouteState.h/.cpp`: route-domain state and immutable snapshots only.
- `ppp/app/client/route/IRoutePlatform.h`: operation-oriented OS boundary and `RouteSpec`.
- `ppp/app/client/route/RouteCoordinator.h/.cpp`: route transaction, undo log, idempotent stop.
- `ppp/app/client/route/LinuxRoutePlatform.h/.cpp`: Linux adapter over `TapLinux`.
- `ppp/app/client/route/WindowsRoutePlatform.h/.cpp`: Windows adapter over existing MIB/TapWindows calls.
- `ppp/app/client/route/DarwinRoutePlatform.h/.cpp`: Darwin adapter over `TapDarwin`.
- `ppp/app/client/route/MobileRoutePlatform.h/.cpp`: Android/iOS all-route adapter.
- `ppp/app/client/dns/IDnsTunnelTransport.h`: tunnel send boundary with no Exchanger declaration.
- `ppp/app/client/dns/IDnsTimerScheduler.h`: DNS timer scheduling/cancellation boundary.
- `ppp/app/client/dns/DnsSessionContext.h/.cpp`: immutable session dependencies and active generation.
- `ppp/app/client/dns/DnsController.h/.cpp`: DNS policy/session owner.
- `tools/check_repository_layout.py`: architecture boundary checker.
- `tests/tooling/test_repository_layout.py`: fixture-driven checker tests.

### Existing files to migrate

- `ppp/app/client/VEthernetNetworkSwitcher.h/.cpp` and member `.inc`: composition and delegation only.
- `ppp/app/client/RouteTableManager*.cpp`: source behavior for platform adapters; deleted after migration.
- `ppp/app/client/ClientConnectionOpener.cpp`: construct/start coordinators.
- `ppp/app/client/ClientConnectionTeardown.cpp`: ordered DNS close and route rollback.
- `ppp/app/client/ClientPacketDispatchHandler.cpp`: call DnsController.
- `ppp/app/client/VEthernetExchanger.h/.cpp`: implement `IDnsTunnelTransport`.
- `ppp/app/client/dns/DnsHost.h/.cpp`: removed after all callers migrate.
- `tests/cpp/CMakeLists.txt`, `ppp.vcxproj`: register new production/test sources.
- `.github/workflows/test.yml`: run architecture checker.
- paired architecture and Route/DNS documentation: describe final ownership.

---

### Task 1: Add executable repository boundary rules

**Files:**
- Create: `tools/check_repository_layout.py`
- Create: `tests/tooling/test_repository_layout.py`
- Modify: `.github/workflows/test.yml`

- [x] **Step 1: Write failing fixture tests**

Create temporary repositories and assert exact violations:

```python
class RepositoryLayoutTests(unittest.TestCase):
    def test_protocol_cannot_include_client(self):
        root = self.fixture({
            "ppp/app/protocol/Bad.h": "#include <ppp/app/client/VEthernetExchanger.h>\n",
        })
        self.assertViolation(root, "protocol -> client")

    def test_route_public_header_cannot_expose_switcher(self):
        root = self.fixture({
            "ppp/app/client/route/Bad.h": "class VEthernetNetworkSwitcher;\n",
        })
        self.assertViolation(root, "route public API exposes concrete host")

    def test_new_inc_fragment_is_rejected(self):
        root = self.fixture({"ppp/app/client/NewMembers.inc": "int value_;\n"})
        self.assertViolation(root, "new .inc declaration fragment")
```

- [x] **Step 2: Run the tests and verify RED**

Run: `python3 -m unittest tests.tooling.test_repository_layout -v`

Expected: FAIL because `tools.check_repository_layout` does not exist.

- [x] **Step 3: Implement the checker**

The checker walks source files and reports `path:line: rule` for:

```python
RULES = (
    ("ppp/app/protocol", re.compile(r"ppp/app/(client|server)/"), "protocol -> client/server"),
    ("ppp/app/client", re.compile(r"ppp/app/server/"), "client -> server"),
)

PUBLIC_HOST_PATTERNS = {
    "ppp/app/client/route": re.compile(r"VEthernet(NetworkSwitcher|Exchanger)"),
    "ppp/app/client/dns": re.compile(r"VEthernet(NetworkSwitcher|Exchanger)"),
}

def check(root: Path) -> list[str]:
    violations: list[str] = []
    for path in root.joinpath("ppp").rglob("*"):
        if path.suffix not in {".h", ".cpp", ".inc"}:
            continue
        relative = path.relative_to(root).as_posix()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_number, line in enumerate(lines, 1):
            for prefix, pattern, message in RULES:
                if relative.startswith(prefix) and pattern.search(line):
                    violations.append(f"{relative}:{line_number}: {message}")
            if path.suffix == ".h":
                for prefix, pattern in PUBLIC_HOST_PATTERNS.items():
                    if relative.startswith(prefix) and pattern.search(line):
                        violations.append(
                            f"{relative}:{line_number}: route/DNS public API exposes concrete host")
    return violations
```

Grandfather only the existing five Switcher `.inc` paths by exact name; any other new `.inc` fails.

- [x] **Step 4: Run checker tests and repository check**

Run:

```bash
python3 -m unittest tests.tooling.test_repository_layout -v
python3 tools/check_repository_layout.py
```

Expected: tests PASS; repository check reports only explicitly grandfathered debt until later tasks remove Route/DNS host references. Add a `--migration-baseline` exact-path allowlist, never a count-only baseline.

- [x] **Step 5: Add the CI command and commit**

Add `python3 tools/check_repository_layout.py` beside the existing include-boundary command, then:

```bash
git add tools/check_repository_layout.py tests/tooling/test_repository_layout.py .github/workflows/test.yml
git commit -m "ci: enforce route and DNS module boundaries"
```

---

### Task 2: Introduce RouteState as the single state owner

**Files:**
- Create: `ppp/app/client/route/RouteState.h`
- Create: `ppp/app/client/route/RouteState.cpp`
- Create: `tests/cpp/route_state_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Write RouteState tests**

Cover replacement, snapshot isolation, applied flags, and guarded reset:

```cpp
int main() {
    route::RouteState state;
    auto rib = std::make_shared<ppp::net::native::RouteInformationTable>();
    state.ReplaceRib(rib);
    state.AddDnsServer(0, 0x08080808u);
    state.MarkApplied(true);

    const route::RouteStateSnapshot snapshot = state.Snapshot();
    assert(snapshot.rib == rib);
    assert(snapshot.dns_servers[0].count(0x08080808u) == 1);
    assert(snapshot.applied);

    assert(!state.ResetAfterRollback(false));
    assert(state.Snapshot().applied);
    assert(state.ResetAfterRollback(true));
    assert(!state.Snapshot().applied);
}
```

- [x] **Step 2: Run the test and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: configure/build FAIL because `RouteState` is missing.

- [x] **Step 3: Implement RouteState**

Use private storage and value snapshots:

```cpp
struct RouteStateSnapshot final {
    RouteInformationTablePtr rib;
    ForwardInformationTablePtr fib;
    RouteInformationTablePtr peer_prefix_rib;
    ForwardInformationTablePtr peer_prefix_fib;
    RouteInformationTablePtr default_routes;
    ppp::unordered_map<uint32_t, ppp::string> nics;
    std::array<ppp::unordered_set<uint32_t>, 3> dns_servers;
    bool applied = false;
    bool apply_ready = false;
};

class RouteState final {
public:
    RouteStateSnapshot Snapshot() const noexcept;
    void ReplaceRib(RouteInformationTablePtr value) noexcept;
    void ReplaceFib(ForwardInformationTablePtr value) noexcept;
    void ReplacePeerPrefix(RouteInformationTablePtr rib, ForwardInformationTablePtr fib) noexcept;
    void ReplaceDefaultRoutes(RouteInformationTablePtr value) noexcept;
    void ReplaceNics(ppp::unordered_map<uint32_t, ppp::string> value) noexcept;
    void AddDnsServer(int bucket, uint32_t ip) noexcept;
    void ClearDnsServers() noexcept;
    void DeduplicateDnsServers() noexcept;
    void MarkApplied(bool value) noexcept;
    void MarkApplyReady(bool value) noexcept;
    bool ResetAfterRollback(bool rollback_complete) noexcept;
private:
    mutable std::mutex syncobj_;
    RouteStateSnapshot value_;
};
```

Copy all containers while holding `syncobj_`; never expose `value_` references.

- [x] **Step 4: Run focused tests and source-manifest check**

Run:

```bash
scripts/run-cpp-tests.sh
python3 tools/check_vcxproj_sources.py
```

Expected: `route_state_test` PASS and source manifests match.

- [x] **Step 5: Commit**

```bash
git add ppp/app/client/route/RouteState.* tests/cpp/route_state_test.cpp tests/cpp/CMakeLists.txt ppp.vcxproj
git commit -m "refactor(route): centralize client route state"
```

---

### Task 3: Define IRoutePlatform and transactional RouteCoordinator

**Files:**
- Create: `ppp/app/client/route/IRoutePlatform.h`
- Create: `ppp/app/client/route/RouteCoordinator.h`
- Create: `ppp/app/client/route/RouteCoordinator.cpp`
- Create: `tests/cpp/route_coordinator_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Write fake-platform transaction tests**

The fake records operations and can fail at an exact call:

```cpp
class FakeRoutePlatform final : public route::IRoutePlatform {
public:
    int fail_add_at = -1;
    int add_count = 0;
    ppp::vector<ppp::string> calls;
    route::RouteInformationTablePtr CaptureDefaults() noexcept override;
    bool Add(const route::RouteSpec&) noexcept override {
        calls.emplace_back("add");
        return ++add_count != fail_add_at;
    }
    bool Delete(const route::RouteSpec&) noexcept override {
        calls.emplace_back("delete");
        return true;
    }
    bool RestoreDefaults(const route::RouteInformationTablePtr&) noexcept override {
        calls.emplace_back("restore");
        return true;
    }
};
```

Assert successful apply marks state, failure on the second add produces
`add, add, delete, restore`, rollback failure keeps state, and calling `Stop()` twice does not repeat calls.

- [x] **Step 2: Run and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: build FAIL because `IRoutePlatform` and `RouteCoordinator` do not exist.

- [x] **Step 3: Implement the platform contract and coordinator**

```cpp
struct RouteSpec final {
    uint32_t network = 0;
    uint32_t gateway = 0;
    int prefix = 0;
    ppp::string interface_name;
};

class RouteCoordinator final {
public:
    RouteCoordinator(RouteState& state, std::unique_ptr<IRoutePlatform> platform) noexcept;
    bool Apply(const ppp::vector<RouteSpec>& routes) noexcept;
    bool Stop() noexcept;
private:
    bool Rollback(const ppp::vector<RouteSpec>& applied) noexcept;
    RouteState& state_;
    std::unique_ptr<IRoutePlatform> platform_;
    ppp::vector<RouteSpec> applied_;
    std::atomic_bool stopped_{false};
};
```

`Apply()` captures defaults before the first mutation, records only successful additions, and calls
`Rollback()` in reverse order. `Stop()` uses compare-exchange and calls `ResetAfterRollback(ok)`.

- [x] **Step 4: Run focused tests and commit**

```bash
scripts/run-cpp-tests.sh
git add ppp/app/client/route tests/cpp/route_coordinator_test.cpp tests/cpp/CMakeLists.txt ppp.vcxproj
git commit -m "refactor(route): add transactional route coordinator"
```

Expected: route state/coordinator tests PASS.

---

### Task 4: Move Linux route effects behind LinuxRoutePlatform

**Files:**
- Create: `ppp/app/client/route/LinuxRoutePlatform.h`
- Create: `ppp/app/client/route/LinuxRoutePlatform.cpp`
- Create: `tests/cpp/linux_route_platform_contract_test.cpp`
- Modify: `ppp/app/client/RouteTableManager_linux.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Add a contract test for RouteSpec mapping**

Extract pure selection logic and assert TAP gateway routes use the TAP interface, known next-hop routes use
the captured NIC map, and other routes use the underlying interface.

```cpp
assert(route::SelectLinuxInterface(tap_gateway, tap_gateway, "tap0", "eth0", nics) == "tap0");
assert(route::SelectLinuxInterface(known_gateway, tap_gateway, "tap0", "eth0", nics) == "wlan0");
assert(route::SelectLinuxInterface(other_gateway, tap_gateway, "tap0", "eth0", nics) == "eth0");
```

- [x] **Step 2: Run and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: FAIL because `SelectLinuxInterface` is absent.

- [x] **Step 3: Implement the Linux adapter**

Move `TapLinux::FindAllDefaultGatewayRoutes`, `AddRoute`, `DeleteRoute`, `AddAllRoutes`, and
`DeleteAllRoutes` calls into `LinuxRoutePlatform`. Constructor inputs are stable TAP and interface snapshots,
not a Switcher pointer.

```cpp
LinuxRoutePlatform(
    std::shared_ptr<ppp::tap::ITap> tap,
    std::shared_ptr<ClientNetworkInterface> tap_interface,
    std::shared_ptr<ClientNetworkInterface> underlying_interface,
    ppp::unordered_map<uint32_t, ppp::string> nics) noexcept;
```

- [x] **Step 4: Wire the coordinator and remove migrated Linux callbacks**

Create the platform/coordinator during client open. Replace Linux calls to `BuildRouteHostPorts()` with
`RouteState::Snapshot()` and Coordinator operations. Remove Linux use of `get_nics`,
`get_dns_server_bucket`, `get_default_routes`, and setters.

- [x] **Step 5: Verify and commit**

```bash
scripts/run-cpp-tests.sh
python3 tools/check_repository_layout.py
python3 tools/check_vcxproj_sources.py
git add ppp/app/client tests/cpp ppp.vcxproj
git commit -m "refactor(route): isolate Linux route platform effects"
```

Expected: all C++ tests PASS; Linux route source has no `RouteHostPorts` reference.

---

### Task 5: Migrate Windows, Darwin, and mobile route adapters

**Files:**
- Create: `ppp/app/client/route/WindowsRoutePlatform.h/.cpp`
- Create: `ppp/app/client/route/DarwinRoutePlatform.h/.cpp`
- Create: `ppp/app/client/route/MobileRoutePlatform.h/.cpp`
- Modify: `ppp/app/client/RouteTableManager_win32.cpp`
- Modify: `ppp/app/client/RouteTableManager_darwin.cpp`
- Modify: `ppp/app/client/RouteTableManager_mobile.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Add platform-independent contract tests**

For each adapter, test pure conversion to `RouteSpec` and idempotent coordinator stop. Mobile tests assert
that the adapter advertises `ApplyAll` capability rather than filling desktop callbacks with no-op lambdas.

- [x] **Step 2: Run and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: FAIL because platform adapters are missing.

- [x] **Step 3: Implement Windows adapter and compile**

Move MIB route creation/deletion and DNS baseline restore inputs into `WindowsRoutePlatform`. Run:

```powershell
build_windows.bat Debug x64
```

Expected: MSVC compile succeeds.

- [x] **Step 4: Implement Darwin adapter and compile**

Move `TapDarwin` route calls into `DarwinRoutePlatform`. Run the macOS CMake compile workflow command from
`.github/workflows/build-macos.yml`; expected exit 0.

- [x] **Step 5: Implement mobile adapter and compile**

Move current `AddAllRoute` behavior behind `MobileRoutePlatform::ApplyAll`. Run Android cross-compile command
from `.github/workflows/build-android.yml`; expected exit 0.

- [x] **Step 6: Commit each platform independently**

```bash
git commit -m "refactor(route): isolate Windows route platform effects"
git commit -m "refactor(route): isolate Darwin route platform effects"
git commit -m "refactor(route): isolate mobile route platform effects"
```

Stage only the relevant platform adapter, migrated source, manifest, and tests for each commit.

---

### Task 6: Remove RouteHostPorts and Switcher-owned route state

**Files:**
- Delete: `ppp/app/client/route/RouteHost.h`
- Delete: `ppp/app/client/route/RouteHost.cpp`
- Delete: `tests/cpp/route_host_ports_test.cpp`
- Delete: `tests/cpp/route_host_interface_test.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.h`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcherMembers.inc`
- Modify: `ppp/app/client/ClientConnectionTeardown.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Add an architecture test requiring zero RouteHostPorts references**

```python
def test_route_host_ports_are_removed(self):
    matches = self.search_repository("RouteHostPorts")
    self.assertEqual([], matches)
```

- [x] **Step 2: Run and verify RED**

Run: `python3 -m unittest tests.tooling.test_repository_layout -v`

Expected: FAIL listing current RouteHost files and Switcher builder.

- [x] **Step 3: Move all remaining fields and teardown into RouteState/Coordinator**

Remove `rib_`, `fib_`, `peer_prefix_rib_`, `peer_prefix_fib_`, `nics_`, `route_added_`,
`route_apply_ready_`, `dns_serverss_`, and platform default-route fields from the Switcher member fragment.
Replace teardown mutations with:

```cpp
if (route_coordinator_) {
    route_coordinator_->Stop();
}
```

- [x] **Step 4: Delete compatibility interfaces and run all gates**

```bash
scripts/run-cpp-tests.sh
python3 tools/check_repository_layout.py
python3 tools/check_vcxproj_sources.py
```

Expected: no `RouteHostPorts` match, all tests PASS, source manifests match.

- [x] **Step 5: Commit**

```bash
git add -A ppp/app/client tests/cpp ppp.vcxproj tools/check_repository_layout.py tests/tooling
git commit -m "refactor(route): remove switcher route service locator"
```

---

### Task 7: Add safe DNS session context and tunnel interface

**Files:**
- Create: `ppp/app/client/dns/IDnsTunnelTransport.h`
- Create: `ppp/app/client/dns/DnsSessionContext.h`
- Create: `ppp/app/client/dns/DnsSessionContext.cpp`
- Create: `tests/cpp/dns_session_context_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Write lifetime tests**

Use a fake transport and verify destruction/close:

```cpp
auto transport = std::make_shared<FakeDnsTunnelTransport>();
auto session = std::make_shared<dns::DnsSessionContext>(transport, 7);
assert(session->Send(source, destination, packet, size));
transport.reset();
assert(!session->Send(source, destination, packet, size));
session->Close();
assert(!session->Send(source, destination, packet, size));
```

Add a two-thread test that repeatedly copies `shared_ptr<const DnsSessionContext>` while another thread
closes the session; run under ASan in CI.

- [x] **Step 2: Run and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: build FAIL because DNS session types do not exist.

- [x] **Step 3: Implement context with explicit activity state**

```cpp
class DnsSessionContext final {
public:
    DnsSessionContext(std::weak_ptr<IDnsTunnelTransport> transport, uint64_t generation) noexcept;
    bool Send(
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        const void* packet,
        int packet_size) const noexcept;
    void Close() noexcept;
    bool IsActive() const noexcept;
private:
    std::weak_ptr<IDnsTunnelTransport> transport_;
    uint64_t generation_ = 0;
    std::atomic_bool active_{true};
};
```

`Send()` checks `active_`, locks the weak transport, then calls the interface. It never returns a reference to
internal state.

- [x] **Step 4: Run tests and commit**

```bash
scripts/run-cpp-tests.sh
git add ppp/app/client/dns tests/cpp/dns_session_context_test.cpp tests/cpp/CMakeLists.txt ppp.vcxproj
git commit -m "refactor(dns): add explicit tunnel session lifetime"
```

---

### Task 8: Introduce DnsController and migrate packet dispatch

**Files:**
- Create: `ppp/app/client/dns/IDnsTimerScheduler.h`
- Create: `ppp/app/client/dns/DnsController.h`
- Create: `ppp/app/client/dns/DnsController.cpp`
- Create: `tests/cpp/dns_controller_test.cpp`
- Modify: `ppp/app/client/ClientPacketDispatchHandler.cpp`
- Modify: `ppp/app/client/VEthernetExchanger.h`
- Modify: `ppp/app/client/VEthernetExchanger.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Write controller tests**

Test local response, tunnel response, TAP output, timer cancellation, generation replacement, and close. The
controller fixture supplies direct stable dependencies rather than getter callbacks.

- [x] **Step 2: Run and verify RED**

Run: `scripts/run-cpp-tests.sh`

Expected: build FAIL because `DnsController` is absent.

- [x] **Step 3: Implement controller ownership**

```cpp
class IDnsTimerScheduler {
public:
    virtual ~IDnsTimerScheduler() noexcept = default;
    virtual uint64_t Schedule(
        int64_t timeout_ms,
        ppp::function<void()> callback) noexcept = 0;
    virtual bool Cancel(uint64_t timer_id) noexcept = 0;
    virtual void CancelAll() noexcept = 0;
};

class DnsController final {
public:
    DnsController(
        std::shared_ptr<ppp::configurations::AppConfiguration> configuration,
        std::shared_ptr<ppp::tap::ITap> tap,
        std::shared_ptr<ppp::threading::BufferswapAllocator> allocator,
        std::shared_ptr<IDnsTimerScheduler> timers) noexcept;
    std::shared_ptr<const DnsSessionContext> OpenSession(
        const std::shared_ptr<IDnsTunnelTransport>& transport) noexcept;
    bool HandleQuery(
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
    void Close() noexcept;
private:
    std::shared_ptr<DnsInterceptor> interceptor_;
    std::atomic_uint64_t generation_{0};
    std::mutex syncobj_;
    ppp::vector<std::weak_ptr<DnsSessionContext>> sessions_;
};
```

`Close()` atomically prevents new sessions, closes all locked sessions, cancels timers, then closes the
interceptor. DNS reachability is owned by the controller and copied as a value projection into RouteState before
route application; neither module receives the other's mutable container.

- [x] **Step 4: Make Exchanger implement IDnsTunnelTransport**

Add `SendDnsDatagram()` as a narrow delegate to existing `SendTo()`. Do not include DnsController in the
Exchanger public header.

- [x] **Step 5: Migrate packet dispatch**

Replace `DnsHostPortsFor(exchanger)` calls with a session snapshot obtained from DnsController. Pass the
snapshot by `shared_ptr<const DnsSessionContext>` through asynchronous response handling.

- [x] **Step 6: Run tests and commit**

```bash
scripts/run-cpp-tests.sh
python3 tools/check_dispatch_handler_compiles.sh build/test/client_packet_dispatch_compile.o
git add ppp/app/client tests/cpp ppp.vcxproj
git commit -m "refactor(dns): move session orchestration into controller"
```

---

### Task 9: Remove DnsHost cache and concrete host interfaces

**Files:**
- Delete: `ppp/app/client/dns/DnsHost.h`
- Delete: `ppp/app/client/dns/DnsHost.cpp`
- Delete: `tests/cpp/dns_host_ports_test.cpp`
- Delete: `tests/cpp/dns_host_interface_test.cpp`
- Delete: `tests/cpp/dns_host_wiring_test.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.h`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcherMembers.inc`
- Modify: `ppp/app/client/ClientConnectionTeardown.cpp`
- Modify: `tests/cpp/CMakeLists.txt`
- Modify: `ppp.vcxproj`

- [x] **Step 1: Add zero-concrete-host architecture assertions**

Require no Switcher/Exchanger names in `ppp/app/client/dns/*.h` except the transport implementation site,
and no `DnsHostPorts`, `IDnsHost`, or `dns_host_ports_cache_` anywhere.

- [x] **Step 2: Run and verify RED**

Run: `python3 -m unittest tests.tooling.test_repository_layout -v`

Expected: FAIL with existing DnsHost and cache matches.

- [x] **Step 3: Migrate teardown ordering**

Perform exactly:

```cpp
if (dns_controller_) {
    dns_controller_->Close();
}
if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(exchanger_)) {
    exchanger->Dispose();
}
if (route_coordinator_) {
    route_coordinator_->Stop();
}
```

Delete `InvalidateDnsHostPorts`, its locked variant, cache members, concrete factory overloads, and the
non-owning `shared_ptr<DnsInterceptor>` adapter.

- [x] **Step 4: Run all local gates and commit**

```bash
scripts/run-cpp-tests.sh
python3 tools/check_repository_layout.py
python3 tools/check_vcxproj_sources.py
git add -A ppp/app/client tests/cpp ppp.vcxproj tools tests/tooling
git commit -m "refactor(dns): remove switcher DNS service locator"
```

Expected: all tests PASS and architecture checker reports no migration-baseline Route/DNS entries.

---

### Task 10: Verify cross-platform behavior and update documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ARCHITECTURE_CN.md`
- Modify: `docs/ROUTING_AND_DNS.md`
- Modify: `docs/ROUTING_AND_DNS_CN.md`
- Modify: `docs/CLIENT_ARCHITECTURE.md`
- Modify: `docs/CLIENT_ARCHITECTURE_CN.md`
- Modify: `docs/CONCURRENCY_MODEL.md`
- Modify: `docs/CONCURRENCY_MODEL_CN.md`
- Modify: `docs/TESTING.md`

- [x] **Step 1: Run the complete verification matrix**

```bash
python3 -m unittest tests.tooling.test_repository_layout -v
python3 tools/check_repository_layout.py
bash tools/check_include_boundaries.sh
python3 tools/check_vcxproj_sources.py
scripts/run-cpp-tests.sh
ctest --test-dir build/test --output-on-failure
```

Expected: every command exits 0; CTest reports 0 failed tests.

- [x] **Step 2: Run sanitizer and platform builds**

Run ASan/UBSan DNS session and route rollback tests, Windows MSVC build, Linux GCC/Clang builds, Android
cross-build, and macOS build using the exact commands in current workflows. Expected: all jobs exit 0 and
sanitizers report no UAF, data race symptom, or leak attributable to the migrated modules.

- [x] **Step 3: Verify architecture acceptance searches**

```bash
! git grep -n "RouteHostPorts\|DnsHostPorts\|IDnsHost\|dns_host_ports_cache_" -- ppp tests
! git grep -n "VEthernetNetworkSwitcher\|VEthernetExchanger" -- 'ppp/app/client/route/*.h' 'ppp/app/client/dns/*.h'
```

Expected: both searches return no matches.

- [x] **Step 4: Update paired documentation**

Document one-way ownership, RouteCoordinator transaction order, platform adapters, DNS session weak transport,
teardown order, and the commands above in both English and Chinese files.

- [x] **Step 5: Commit documentation**

```bash
git add docs
git commit -m "docs: document client route and DNS ownership"
```

---

## Completion audit

Before declaring this plan complete, verify each design acceptance item against authoritative evidence:

1. Inspect Switcher members to prove Route/DNS fields are absent.
2. Use zero-match searches to prove RouteHostPorts, IDnsHost, concrete host factories, raw container ports, and
   fake shared ownership are gone.
3. Read RouteCoordinator tests to confirm partial failure, reverse rollback, rollback failure, and idempotent stop
   are covered.
4. Read DNS lifetime tests to confirm concurrent close/lookup and expired transport are covered, then inspect
   sanitizer output.
5. Check Linux, Windows, macOS, Android/iOS build results rather than inferring portability from Linux tests.
6. Check the CI workflow contains repository-layout and include-boundary gates.
7. Check every modified stable document has a synchronized `_CN.md` pair.

The broader objective remains active after this plan: Exchanger responsibility extraction and VMUX dependency
inversion are the next separately designed subprojects.
