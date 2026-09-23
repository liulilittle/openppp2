# Runtime, UI, and Lifecycle Roadmap

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle, Git history, and the latest main verification record, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.

> Status: In progress
> Type: Roadmap
> Last verified: 5bcccce

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish one runtime truth model shared by C++ core, TUI, Android, and iOS; stabilize lifecycle and teardown; enforce architecture and CI boundaries; then validate VMUX and design P2P safely.

Repository implementation and correctness gates were reverified on 2026-07-17 at
`main@5bcccce` with all 9 GitHub Actions workflows successful. The remaining
release gates require authoritative fixed-host or physical-device evidence:
the UDP baseline bundle, VMUX Linux/mobile netem artifacts, and the P2P
Android/iOS device and real-NAT matrix. They are intentionally left unchecked.

**Architecture:** Core runtime publishes versioned snapshots and events. Platform bridges translate those facts without inventing state. UI stores reduce snapshots/events into presentation state. Route, DNS, VMUX, and P2P remain domain subsystems behind explicit interfaces. Work is split into four independently executable plans.

**Tech Stack:** C++17, Boost.Asio, Boost.Test, Flutter/Dart, Kotlin Android bridge, Swift/SwiftUI, XCTest/Swift Package, CMake, GitHub Actions, JSON Schema.

## Global Constraints

- C++17 only.
- UI must not infer connection state from logs or process existence.
- Runtime state must carry `schema_version`, `generation`, and monotonic timestamp.
- Android, iOS, and TUI must consume the same semantic state model.
- `Connected` means session, adapter, route, DNS, and negotiated policy are usable.
- `Stop` must be idempotent.
- No new `.inc` fragments.
- No new `friend + Bind(this)` helper pattern.
- Freeze `RouteHostPorts`; do not add callbacks.
- Preserve backward compatibility unless a capability bit or schema version explicitly gates behavior.
- Every production change requires regression, boundary, or negative tests.

---

## Plan Order

1. `2026-07-12-runtime-contract-and-ui.md`
   - Defines `RuntimePhase`, snapshots, events, commands, error DTOs, fixtures, and adapters.
2. `2026-07-12-lifecycle-stabilization.md`
   - Fixes teardown deadlock, callback ownership, stale generations, and idempotent Stop.
3. `2026-07-12-architecture-and-ci-enforcement.md`
   - Creates governance, dependency checks, contract tests, sanitizers, and platform build gates.
4. `2026-07-12-vmux-p2p-validation.md`
   - Validates requested/effective VMUX state and defines a gated P2P implementation sequence.

## Release Gates

### Gate A: Runtime Contract Ready

- [x] C++ produces schema-valid snapshots.
- [x] Dart and Swift parse all fixtures.
- [x] TUI renders from snapshots instead of direct runtime object reads.
- [x] Unknown optional fields are ignored safely.
- [x] Unsupported schema versions fail explicitly.

### Gate B: Lifecycle Safe

- [x] Desktop teardown has no recursive lock path.
- [x] DNS host callbacks do not retain the switcher strongly.
- [x] Stop is idempotent in Idle, Starting, Connected, Reconnecting, and Stopping.
- [x] 100 connect/disconnect cycles pass.
- [x] ASan/UBSan lifecycle suite passes.

### Gate C: Architecture Enforced

- [x] Core-to-platform dependency rules run in CI.
- [x] Contract fixtures run in C++, Dart, and Swift jobs.
- [x] Documentation status metadata is checked.
- [x] RouteHostPorts has been removed; repository checks reject reintroduction.
- [x] No new `.inc` files are accepted.
- [x] Client Exchanger delegates keepalive timing, FRP storage, StaticEcho state,
  and VMUX session ownership to domain components; boundary tests reject those
  fields returning to `VEthernetExchanger`.

### Gate D: VMUX Verified

- [x] UI displays requested and effective modes separately.
- [x] Capability and fallback reasons are exposed.
- [ ] Equal-link, slow-link, loss, and link-churn benchmarks are stored as artifacts.
- [ ] Flow mode meets documented throughput and latency criteria.
- [x] Old peers fall back safely.

### Gate E: P2P Allowed

- [x] Wire protocol and key derivation ADR accepted.
- [x] Replay window zero and wraparound cases pass.
- [x] Direct path never becomes a prerequisite for base VPN connectivity.
- [ ] Android/iOS socket protection is verified. Android API 34 emulator evidence is green; iOS physical-device evidence remains open.
- [x] UI distinguishes Relay, Probing, Direct, Suspect, and FallingBack.

## Recommended PR Sequence

1. Contract types and fixtures only.
2. TUI adapter.
3. Android parser/store/bridge.
4. iOS parser/store/bridge.
5. Teardown deadlock regression and fix.
6. DNS host snapshot ownership.
7. Stop generation and idempotence.
8. Governance and CI checks.
9. Sanitizer and lifecycle stress jobs.
10. VMUX requested/effective telemetry and UI.
11. VMUX benchmark harness.
12. P2P protocol ADR and tests, without direct data path.

Each PR should remain independently revertible. Do not combine UI contract introduction with route-state redesign or P2P data-plane work.
