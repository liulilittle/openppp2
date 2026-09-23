# Architecture and CI Enforcement Implementation Plan

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

**Goal:** Turn repository conventions into executable architecture, documentation, formatting, and cross-platform CI rules.

**Architecture:** Governance documents define stable boundaries; scripts verify them; CI blocks regressions. Route and DNS refactors move toward state-owning components and operation-oriented platform interfaces without a repository-wide rewrite.

**Tech Stack:** Bash/Python validation scripts, CMake, GitHub Actions, clang-format, markdownlint, C++17, Flutter, Swift.

## Global Constraints

- Do not mass-format inherited code.
- Apply formatting to new files and changed lines/modules only.
- No new `.inc` files.
- No increase in `RouteHostPorts` callback count.
- No new client/server reverse dependency.
- Stable docs require status and last-verified metadata.
- UI contract fixtures must pass in C++, Dart, and Swift.

---

### Task 1: Add Repository Governance Files

**Files:**
- Create: `CONTRIBUTING.md`
- Create: `.editorconfig`
- Create: `.clang-format`
- Create: `.markdownlint.yml`
- Create: `docs/governance/CODE_STYLE.md`
- Create: `docs/governance/DOCUMENTATION_STYLE.md`
- Create: `docs/adr/README.md`
- Create: `docs/design/README.md`
- Modify: `docs/README.md`

- [x] **Step 1: Define code placement matrix**

Document exact ownership:

```text
ppp/app/runtime      runtime contract and lifecycle publisher
ppp/app/client/dns   client DNS policy and orchestration
ppp/app/client/route client route state/coordinator
ppp/app/mux          VMUX protocol and scheduling
ppp/p2p              direct-channel protocol primitives
platform directories OS calls and adapters
android/ios          presentation and platform bridge only
```

- [x] **Step 2: Define prohibited patterns**

Add explicit rules:

```text
no new .inc fragments
no new helper that only stores owner_ via Bind(this)
no UI log parsing for state
no raw mutable container pointer in new service interfaces
no reverse protocol -> client/server include
```

- [x] **Step 3: Add document metadata template**

```markdown
> Status: Draft
> Type: Design
> Owner: Client networking
> Created: 2026-07-12
> Last verified: <commit>
> Related issue: #123
```

- [x] **Step 4: Add formatting files**

Use 4 spaces, no tabs, 120-column target, C++17, own header first, and no global reformat requirement.

- [x] **Step 5: Commit**

```bash
git add CONTRIBUTING.md .editorconfig .clang-format .markdownlint.yml docs
 git commit -m "docs: define repository engineering governance"
```

### Task 2: Enforce Include and Placement Boundaries

**Files:**
- Modify: `tools/check_include_boundaries.sh`
- Create: `tools/check_repository_layout.py`
- Test: `tests/tooling/test_repository_layout.py`
- Modify: `.github/workflows/test.yml`

- [x] **Step 1: Add failing tooling tests**

Create temporary fixture trees and assert detection of:

```text
protocol including client
client including server
new .inc file
runtime including linux/windows implementation
UI code importing core-private paths
```

- [x] **Step 2: Implement layout checker**

The script exits non-zero and prints exact file, line, and violated rule.

- [x] **Step 3: Freeze RouteHostPorts surface**

Record the current callback member count in the checker. Fail when the count increases. The check is intentionally temporary until `RouteHostPorts` is removed.

- [x] **Step 4: Add CI step**

```bash
python3 tools/check_repository_layout.py
bash tools/check_include_boundaries.sh
```

- [x] **Step 5: Run and commit**

```bash
python3 -m unittest tests/tooling/test_repository_layout.py
python3 tools/check_repository_layout.py
git add tools tests/tooling .github
 git commit -m "ci: enforce repository architecture boundaries"
```

### Task 3: Enforce Documentation Metadata and Links

**Files:**
- Create: `tools/check_docs.py`
- Create: `tests/tooling/test_check_docs.py`
- Modify: `.github/workflows/test.yml`

- [x] **Step 1: Test missing metadata**

Design, audit, plan, ADR, and governance files must declare `Status`, `Type`, and `Last verified` or be explicitly grandfathered in a migration allowlist.

- [x] **Step 2: Test broken relative links**

Resolve Markdown links relative to each document and fail with source path and target.

- [x] **Step 3: Test bilingual reference pairing**

Stable reference documents listed as bilingual in `docs/README.md` must have both files. Draft designs are exempt.

- [x] **Step 4: Add CI and commit**

```bash
python3 -m unittest tests/tooling/test_check_docs.py
python3 tools/check_docs.py
git add tools tests/tooling .github
 git commit -m "ci: validate documentation status and links"
```

### Task 4: Introduce RouteState Without Expanding RouteHostPorts

**Files:**
- Create: `ppp/app/client/route/RouteState.h`
- Create: `ppp/app/client/route/RouteState.cpp`
- Modify: `ppp/app/client/VEthernetNetworkSwitcherMembers.inc`
- Modify: `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- Test: `tests/cpp/route_state_test.cpp`

**Interfaces:**

```cpp
class RouteState final {
public:
    RouteInformationTablePtr rib;
    ForwardInformationTablePtr fib;
    RouteInformationTablePtr default_routes;
    bool applied = false;
    bool ready = false;
    void Reset() noexcept;
};
```

- [x] **Step 1: Test Reset clears transactional state**

- [x] **Step 2: Move route-owned fields into RouteState**

Keep compatibility accessors temporarily, but make RouteState the owner.

- [x] **Step 3: Update teardown and route manager**

Use `RouteState::Reset()` only after host rollback completes.

- [x] **Step 4: Run route tests and commit**

```bash
ctest --test-dir build/test -R "route_state|route_table|route_host" --output-on-failure
git add ppp/app/client tests/cpp
 git commit -m "refactor(route): centralize client route state"
```

### Task 5: Add Operation-Oriented Route Platform Interface

**Files:**
- Create: `ppp/app/client/route/IRoutePlatform.h`
- Create: platform implementations under `linux/`, `windows/`, and `darwin/`
- Modify: `ppp/app/client/RouteTableManager*.cpp`
- Test: `tests/cpp/route_coordinator_test.cpp`

**Interfaces:**

```cpp
struct RouteSpec { uint32_t network; uint32_t gateway; int prefix; ppp::string nic; };
class IRoutePlatform {
public:
    virtual ~IRoutePlatform() noexcept = default;
    virtual bool Add(const RouteSpec&) noexcept = 0;
    virtual bool Delete(const RouteSpec&) noexcept = 0;
    virtual RouteInformationTablePtr CaptureDefaults() noexcept = 0;
    virtual bool RestoreDefaults(const RouteInformationTablePtr&) noexcept = 0;
};
```

- [x] **Step 1: Write fake-platform coordinator tests**

Verify apply order, rollback after failure, and idempotent delete.

- [x] **Step 2: Implement interface and one Linux adapter first**

Do not migrate all platforms in one PR. Preserve current behavior behind the interface.

- [x] **Step 3: Migrate Windows and Darwin in separate commits**

Each platform commit must pass its compile job.

- [x] **Step 4: Remove mutable container pointer access from migrated route paths**

- [x] **Step 5: Commit per platform**

Use messages such as:

```bash
git commit -m "refactor(route): use Linux route platform adapter"
```

### Task 6: Add Cross-Language Runtime Contract CI

**Files:**
- Create: `scripts/test-runtime-contract.sh`
- Modify: `.github/workflows/test.yml`
- Modify: Android and iOS test fixture loaders

- [x] **Step 1: Run C++ fixture tests**
- [x] **Step 2: Run Dart fixture tests**
- [x] **Step 3: Run Swift fixture tests**
- [x] **Step 4: Fail if fixture hashes differ across copied bundles**

Prefer reading the repository fixtures directly where build tools permit; otherwise copy them during test setup and verify hashes.

- [x] **Step 5: Commit**

```bash
git add scripts .github android ios tests/contracts
 git commit -m "ci: verify runtime contract across C++ Dart and Swift"
```

### Task 7: Add Platform Build and Sanitizer Matrix

**Files:**
- Modify: `.github/workflows/test.yml`
- Create or modify: Windows workflow
- Modify: `docs/TESTING.md`

- [x] **Step 1: Add Linux GCC Release job**
- [x] **Step 2: Add Linux Clang Debug job**
- [x] **Step 3: Add ASan/UBSan lifecycle subset**
- [x] **Step 4: Add Windows MSVC compile/test job**
- [x] **Step 5: Preserve Flutter and iOS jobs**
- [x] **Step 6: Upload coverage and sanitizer artifacts**
- [x] **Step 7: Commit**

```bash
git add .github docs/TESTING.md
 git commit -m "ci: expand cross-platform verification matrix"
```

### Task 8: Add Linux Route/DNS Namespace Integration Tests

**Files:**
- Create: `tests/integration/linux/route_dns_rollback.sh`
- Create: `tests/integration/linux/fixtures/`
- Create: `.github/workflows/integration-linux.yml`
- Modify: `docs/TESTING.md`

- [x] **Step 1: Create namespace and baseline snapshot**
- [x] **Step 2: Run client route/DNS application through test adapter or binary**
- [x] **Step 3: Trigger normal stop and compare final state to baseline**
- [x] **Step 4: Trigger partial-start failure and compare rollback**
- [x] **Step 5: Upload before/after diffs**
- [x] **Step 6: Commit**

Acceptance invariant:

```text
route table after shutdown == route table before startup
DNS state after shutdown == DNS state before startup
```
