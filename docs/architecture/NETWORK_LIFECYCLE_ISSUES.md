# Network Lifecycle Issue Pack

> This file is a local issue pack for GitHub Issue #82. It is intended to be
> copied into the issue tracker when remote access is available. The repository
> does not claim that these bodies have been published or that the numbered
> child issues have the exact titles shown here.

## Publishing metadata

The following rows are the canonical titles, parent links, labels, and ordering
for publishing this pack. Copy the matching issue body below each title; keep
the dependency text in the issue so that work is not closed on a partial
implementation.

| Key | Publish title | Parent/dependencies | Labels | Close gate |
|---|---|---|---|---|
| #82 | `Epic: define and enforce the VPN network lifecycle contract` | none | `network-lifecycle`, `recovery`, `architecture` | All child issues and follow-ups have attached evidence, including explicit platform gaps. |
| #83 | `Windows DNS: restrict ownership and make restore verifiable` | #82; Wave 0 | `network-lifecycle`, `windows`, `dns`, `recovery` | Windows host evidence covers static/DHCP IPv4 and IPv6, missing adapters, write failures, and external changes. |
| #84 | `Routes: track ownership and persist complete snapshots` | #82; route snapshot contract before durable replay | `network-lifecycle`, `routing`, `recovery` | Linux and Windows route tables are compared before/after; foreign and incomplete records are rejected. |
| #85 | `Teardown: make DNS, routes, proxy, address, and adapter cleanup independent` | #82; #83/#84/#87 | `network-lifecycle`, `desktop`, `recovery` | Fault injection proves every resource is attempted and the aggregate result is truthful and retryable. |
| #86 | `Desktop/Core: hand off forced-stop cleanup to durable recovery` | #82/#85; Wave 2 | `network-lifecycle`, `desktop`, `recovery`, `windows` | Graceful stop, timeout, kill, crash, restart, and corrupted marker cases have status and recovery evidence. |
| #87 | `Host resources: apply ownership and rollback to proxy, firewall, adapter, and address changes` | #82; #85 | `network-lifecycle`, `windows`, `recovery` | Resource-specific snapshots, compare-and-restore, conflicts, and partial failures are covered. |
| A | `Recovery journal: wire every host mutation to write-ahead replay` | #82/#83/#84/#85/#87 | `network-lifecycle`, `recovery`, `storage` | Every apply has intent, confirmation, verification, atomic persistence, and retry evidence. |
| B | `IPv6 and network changes: preserve lifecycle state across adapter churn` | #82/#83/#84 | `network-lifecycle`, `ipv6`, `needs-platform-validation` | Windows/Linux/macOS evidence covers DHCP, Wi-Fi changes, adapter disappearance, and stable identity. |
| C | `DNS interception: document UDP/TCP and encrypted resolver boundaries` | #82/#83 | `network-lifecycle`, `dns`, `documentation` | Tests and docs distinguish UDP/53, TCP/53, DoT, DoH, and unmatched encrypted traffic. |
| D | `Multi-VPN coexistence: report conflicts and preserve foreign network state` | #82/#83/#84 | `network-lifecycle`, `routing`, `dns`, `needs-platform-validation` | User changes, second-VPN changes, and lease contention are observable and retryable. |
| E | `CI: add a platform-backed network lifecycle acceptance matrix` | #82 and all implementation issues | `network-lifecycle`, `ci`, `needs-platform-validation` | Required offline and privileged scenarios produce retained artifacts and explicit skips. |
| F | `Route teardown: make OS deletion and journal removal independently retryable` | #84/#85; requires platform absence confirmation | `network-lifecycle`, `routing`, `recovery`, `needs-platform-validation` | A route deleted by the OS but followed by a durable-remove failure is retried without deleting a recreated foreign route. |
| G | `Firewall rules: persist ownership and restore only unchanged OpenPPP2 rules` | #87; requires Windows COM host runner | `network-lifecycle`, `windows`, `firewall`, `recovery` | Existing, changed, duplicate, and ambiguous rules are preserved; only an exact OpenPPP2-owned rule is removed and verified. |
| H | `Wintun adapters: define supported deletion and crash-recovery lifecycle` | #87; requires bundled-driver and Windows host evidence | `network-lifecycle`, `windows`, `adapter`, `recovery` | Session cleanup uses supported driver APIs, and crash recovery either proves stable ownership or leaves the adapter pending without name-based deletion. |

**Dependency rule:** a child issue may land independently, but it cannot be
closed until its own acceptance rows pass and its dependencies are either
closed or explicitly recorded as an unimplemented boundary. A passing compile
or static contract test alone does not close a host-network issue.

## Epic #82: VPN network lifecycle contract

### Problem

OpenPPP2 changes operating-system network state while a VPN session is active.
The previous implementation treated Core process exit as evidence that DNS,
routes, proxy settings, and IPv6 state had been restored. That assumption fails
when an OS write is partial, cleanup times out, the process crashes, or another
program changes the same resource while the session is running.

The epic establishes one lifecycle contract for every host-side resource:

1. Capture a complete snapshot and resource identity before every OS write.
2. Persist write intent before the write and confirmation after the write.
3. Restore DNS, routes, proxy, addresses, and adapters independently.
4. Verify the actual OS state before deleting the recovery record.
5. Compare ownership before restoring and preserve later user or VPN changes.
6. Keep failed, conflicted, and unverified records retryable.
7. Report `recovery_pending` after a forced stop or an unverified cleanup.
8. Fail closed when the inter-process network-control lease is unavailable.

### Scope

The epic covers desktop TUN/TAP host integration, Windows DNS and routes,
system proxy state, IPv4/IPv6 addresses, desktop stop handling, persistent
recovery, and platform acceptance evidence. It does not promise that an
ordinary process can run after it has been forcibly killed. Immediate cleanup
after a forced stop requires a separate worker, service, scheduled task, or a
documented next-start recovery check.

### Work plan

- Wave 0: correct resource ownership, independent cleanup, and truthful failure
  reporting.
- Wave 1: durable snapshot and journal transaction with replay and verification.
- Wave 2: Core/Desktop stop protocol and forced-stop recovery gate.
- Wave 3: platform adapters, IPv6 parity, adapter churn, network switching,
  DNS interception boundaries, and multi-VPN conflict handling.

### Acceptance

- Static contract tests cover every changed platform path.
- Offline C++ tests cover journal serialization, corruption/owner rejection,
  write-ahead ordering, retry after callback failure, and failed durable remove.
- CTest and sanitizer jobs run the lifecycle targets.
- Windows CI or an isolated Windows host compares DNS mode, IPv4/IPv6 servers,
  routes, adapter identity, proxy values, and presence before and after each
  scenario.
- The report distinguishes offline evidence from privileged runtime evidence.
- No configuration field from the proposal is advertised until its parser and
  compatibility contract exist.

### Current implementation boundaries

These boundaries remain open and must be reflected in issue status and release
notes:

- The standalone `--network-recovery` worker can verify Windows DNS records,
  but route records require a live platform adapter with current interface
  context. Unresolved route records keep the recovery gate pending.
- Assigned IPv4 now writes a durable intent and the standalone worker performs
  GUID/LUID/index compare-and-restore for the versioned `ipv4-v2` snapshot.
  IPv6 writes an OP6S intent before its first OS mutation and the standalone
  worker performs GUID/LUID/index-checked MIB compare-and-restore for the
  unicast address, neighbor, subnet route, and DNS resources. Windows runtime
  evidence is still required before calling this platform-complete.
- Proxy recovery must fail the startup/connect gate when its record remains
  after an attempted restore; a discarded restore error is not clean recovery.
- Windows host, Linux namespace, and macOS runtime checks remain platform
  evidence work even when offline contract tests pass.
- In-process route teardown records a successful compare-delete separately
  from durable Journal removal, so a later retry only removes the Journal.
  Crash recovery still requires each platform's `created-v2` delete operation
  to treat an already-absent owned row as success while retaining conflicts;
  incomplete platform semantics keep the record pending under follow-up F.

### Dependencies and risks

The route platform must expose a complete serializable snapshot before default
routes can be safely replayed after a crash. A pointer, gateway, or guessed
interface is not sufficient. Windows and mobile lifecycle behavior needs native
CI or a test host; Linux namespace tests need explicit privilege. Concurrent
changes by another VPN cannot be eliminated, so conflicts must remain visible
and retryable.

## Child #83: Windows DNS ownership and restore

### Problem

The client previously enumerated active physical interfaces and could leave
their DNS changed after disconnect. Automatic/DHCP mode was also represented
too loosely for a reliable restore.

### Deliverables

- Default hosted DNS writes target only the authorized VPN virtual adapter.
- `NetworkDnsSnapshot` stores stable interface identity, IPv4/IPv6 values,
  automatic/static mode, attempted/apply state, and the value written by the
  session.
- Restore uses compare-and-restore. A user or another VPN change is reported as
  a conflict and is not overwritten.
- Automatic DNS is restored as automatic mode with an empty server list.
- WMI/write failures retain a retryable snapshot when the write may have taken
  effect.

### Acceptance

- `tests.tooling.test_windows_dns_snapshot_contract` passes.
- Static IPv4, static IPv6, DHCP, missing adapter, write failure, and external
  change cases have contract coverage.
- A Windows host test compares mode, address list, and adapter identity before
  and after cleanup.
- Physical interfaces not explicitly authorized remain byte-for-byte unchanged.

### Code paths

`windows/ppp/win32/network/NetworkInterface.{h,cpp}`,
`ppp/app/client/VEthernetNetworkSwitcher.cpp`, and
`ppp/app/client/ClientConnectionTeardown.cpp`.

## Child #84: Route ownership and cleanup

### Problem

Default-route protection and hosted routes must not delete routes created by the
user or another VPN. A crash also leaves no safe way to reconstruct an
incomplete route snapshot today.

### Deliverables

- Every created route has a session owner and exact target identity.
- Existing routes are not claimed as OpenPPP2-owned routes.
- Delete and restore compare the current route/interface before changing it.
- Route cleanup reports each failure independently from DNS and proxy cleanup.
- Use a versioned, complete route snapshot serialization format for durable
  default-route replay and reject incomplete or foreign records.

### Acceptance

- `network_ownership_test` and `route_coordinator_test` pass under CTest and
  lifecycle sanitizers.
- Add/delete failure injection proves unrelated DNS cleanup still runs.
- A route changed by a second actor is retained and reported as a conflict.
- Windows/Linux isolated tests compare the complete route table and interface
  identity before and after cleanup.
- Journal replay refuses incomplete or foreign route records.

### Code paths

`ppp/app/client/route/NetworkOwnership.{h,cpp}`,
`ppp/app/client/route/RouteCoordinator.{h,cpp}`, and platform route adapters.

## Child #85: Independent teardown and rollback results

### Problem

Cleanup was assembled as a single route-oriented operation. A route failure
could hide a DNS result, and a successful OS restore could be treated as
complete even when durable journal deletion failed.

### Deliverables

- Stop input, DNS, exchanger, proxy, address, route, and adapter resources in a
  defined order with independent result fields.
- Continue unrelated cleanup after a resource failure.
- Retain in-memory ownership while durable journal removal is unconfirmed.
- Return success only after every required resource has been verified.

### Acceptance

- `ClientConnectionTeardown` tests prove DNS is attempted when route cleanup
  fails and route cleanup is attempted when DNS fails.
- Journal remove failure leaves the snapshot and `recovery_pending` state.
- A normal stop with any failed resource emits a failure result and a retryable
  record; it never reports a clean stop.

### Code paths

`ppp/app/client/ClientConnectionTeardown.cpp`,
`ppp/app/runtime/RuntimeStopPipeline.*`, and switcher teardown state.

## Child #86: Desktop/Core stop and recovery gate

### Problem

A five-second Core stop timeout cannot make a killed process clean up host
network state. The desktop needs a durable handoff and an honest status.

### Deliverables

- Implement `RUNNING -> STOP_REQUESTED -> CORE_CLEANUP -> VERIFY` state
  reporting, with explicit timeout and forced-kill states.
- Persist `network-recovery.pending` atomically after forced/unclean exit.
- On startup or the next connection attempt, invoke the recovery path before
  applying new network state; fail closed if recovery cannot be verified.
- Define the boundary for a future Windows service or scheduled recovery worker.

### Acceptance

- Desktop tests cover graceful exit, timeout, forced kill, natural crash, and
  marker corruption/persistence failure.
- Core startup consumes confirmed journal entries and refuses new mutation while
  unresolved records remain.
- UI and telemetry expose `recovery_pending`; they never equate process exit
  with restored network state.
- Windows service/task behavior is either tested or listed as unimplemented.

### Code paths

`desktop/client/src-tauri/src/process.rs`,
`desktop/client/src-tauri/src/desktop.rs`, and Core journal startup wiring.

## Child #87: Proxy and remaining host resources

### Problem

System proxy, firewall, adapter, and address writes need the same ownership and
recovery rules as DNS and routes. A partial proxy write can otherwise leave a
machine in a state that is hard to diagnose.

### Deliverables

- Capture presence, value, mode, and owner before proxy/firewall/adapter writes.
- Verify each field on restore and preserve later external changes.
- Keep failed records durable and report conflicts.
- Windows assigned IPv4 and IPv6 now record intent/confirmation. Both replay
  workers use stable interface identity and preserve conflicts; IPv6 MIB
  replay still needs Windows host evidence.
- Wintun records whether this session opened or created an adapter. Cleanup
  uses the bundled API's `WintunEndSession` followed by `WintunCloseAdapter`;
  neither bundled x86 nor x64 DLL exports `WintunDeleteAdapter`. A durable
  `wintun-adapter.pending` marker records the owning PID, adapter name, LUID,
  and interface index. The independent recovery worker refuses a live owner,
  validates the stable identity, starts and ends a supported Wintun session to
  prove stale session state is gone, and removes the marker only after that
  verification. The adapter itself remains installed because this API version
  has no supported delete operation; name collisions and identity conflicts
  remain pending. Windows host acceptance remains required.
- Modern Windows application firewall rules expose explicit
  `ApplicationOwnership` capture/add/restore helpers. A pre-existing rule is
  never claimed; cleanup compares name, executable path, direction, action,
  enabled state, and description before removing a rule. Changed, duplicate,
  or ambiguous rules are preserved and leave the ownership record retryable.
  The application startup path now records intent before adding its rule and
  confirms it only after the add succeeds; the independent recovery worker
  replays `windows-firewall` entries. Windows COM host evidence remains open.
- Keep proxy-only mode from installing host route/DNS mutations unless the
  selected policy explicitly requires them.

### Acceptance

- `test_windows_network_resource_contract` and lifecycle wiring tests pass.
- Fault injection proves one proxy/firewall failure does not skip DNS or route
  cleanup.
- Windows host tests cover absent values, static values, automatic values, and
  a user change during the session.

### Code paths

`windows/ppp/net/proxies/HttpProxy.cpp`,
`desktop/client/src-tauri/src/windows.rs`,
`windows/ppp/tap/WintunAdapter.{h,cpp}`, and host adapter cleanup paths.

## Follow-up issue A: Durable journal for every apply entry

Wire the versioned `NetworkRecoveryJournal` to every supported host mutation
that has a safe cross-process identity. DNS, route, IPv4, IPv6, proxy, and
firewall replay now have durable intent and platform-specific identity-checked
restore paths. Wintun uses its separate atomic identity marker because the
bundled driver API has no adapter-delete operation. Windows host evidence is
still required before this follow-up can close.
Each entry must record intent before the OS call, confirmation after the call,
and verified removal after restore. Add crash-window tests for intent-only and
confirmed records, corruption/owner rejection, atomic rewrite failure, and
retry after a failed callback. Keep route serialization blocked until the
platform snapshot is complete.

## Follow-up issue B: IPv6 and network-change parity

Cover IPv6 DNS/address/route state, DHCP updates, adapter disappearance, and
Wi-Fi/interface changes. Revalidate stable identity before every restore and
leave a pending record when the interface is gone. Acceptance requires isolated
Windows/Linux/macOS host evidence; static tests alone are insufficient.

## Follow-up issue C: DNS interception capability boundary

Document and test the actual UDP/53 interception path separately from resolver
upstream UDP, TCP, DoT, and DoH support. Do not call `intercept-unmatched`
system-wide DNS hijacking. Define behavior for unsupported encrypted resolvers
and test fail-open/fail-closed policy explicitly.

## Follow-up issue D: Multi-VPN conflict and ownership reporting

Exercise a user change and a second VPN change during an active session. The
client must compare target identity and value, preserve the later change, keep
the recovery record, and expose a conflict reason. Add a lease contention test
that proves a second OpenPPP2 session fails closed.

## Follow-up issue E: CI and release acceptance matrix

Keep offline contracts in Linux CI and add platform jobs only for environments
that actually provide the required privileges. Publish artifacts containing
before/after snapshots and explicit unverified rows for missing platform
coverage. The matrix must include static IPv4/IPv6 DNS, DHCP, partial adapter
availability, independent DNS/route failures, forced Core termination, manual
 DNS changes, and multiple VPNs.

## Follow-up issue F: Route teardown and journal removal retry

Separate successful operating-system route deletion from removal of the
corresponding durable recovery record. A journal write or delete failure must
not cause DNS, proxy, or other resource cleanup to be skipped, and must not
make a route appear unresolved when the OS already confirmed its deletion.

The route record must retain the exact owner and complete route identity. On a
retry, an already-absent route is success only when its identity and ownership
record prove that OpenPPP2 created it; a recreated route or a route changed by
another actor is a conflict and must remain pending. Journal removal is
committed only after the route operation and the subsequent verification both
succeed.

Acceptance requires fault injection for OS delete success followed by durable
remove failure, an OS delete failure, a recreated foreign route, and an
incomplete or foreign snapshot. The retry must remove only the durable record
when the owned route is already absent, and must preserve the record for every
ambiguous or conflicting state.

Current implementation records compare-delete success independently from
journal removal and retries the latter in-process. Cross-process replay still
depends on each platform's `created-v2` absence and ownership semantics, so
Linux and Windows host evidence is required before this follow-up can close.

## Follow-up issue G: Firewall ownership and recovery

The application firewall mutation is now wired to the durable lifecycle record.
The record distinguishes an existing rule from one created by OpenPPP2 and
retains conflicts when name, path, direction, action, enabled state, or
description changes. A Windows host test must still verify exact removal and
confirm the rule is absent after removal; static and offline evidence alone
does not close this issue.

## Follow-up issue H: Wintun adapter lifecycle

The bundled Wintun DLLs expose session and handle close operations but no
adapter-delete export. Same-process cleanup remains limited to `EndSession`
and `CloseAdapter`; an adapter opened by name is never treated as owned. The
implementation now persists an atomic intent marker with the owner PID before
creation, upgrades it with the adapter LUID and interface index after creation,
and has the independent worker validate that identity before ending a stale
session marker. Windows host tests must still cover adapter reuse,
disappearance, and failed cleanup.

### Directly publishable body for issue E

**Objective**

Turn the lifecycle contract into a required CI/release evidence gate. Keep
offline tests deterministic, and run privileged host-network checks only on a
runner that provides the required OS, permissions, and isolation.

**Required work**

1. Keep repository layout, lifecycle wiring, Windows DNS/IPv6/resource
   contracts, CTest, lifecycle ASan/UBSan, and C++ TSan in the Linux test
   workflow.
2. Keep the Linux namespace Route/DNS rollback job and upload before/after
   snapshots, route tables, DNS mode/list, adapter identity, and command exit
   status as artifacts.
3. Add a Windows-host job (or a separately triggered protected environment) for
   DNS and route apply/restore. It must capture IPv4/IPv6 automatic/static
   mode, server lists, complete route rows, interface identity, proxy values,
   and presence before and after every scenario.
4. Run desktop `npm test`, `npm run build`, and locked Rust tests on Ubuntu and
   Windows. A missing dependency or skipped job must be visible as a failed or
   explicitly unsupported check, never as a green functional result.
5. Run the matrix for both pull requests and release candidates where the
   required platform is available. Upload a machine-readable summary with
   `passed`, `failed`, `skipped`, and `unverified` rows.

**Mandatory scenarios**

- static IPv4 DNS and static IPv6 DNS;
- DHCP/automatic DNS and an adapter that is down or disappears;
- route add/delete failure while unrelated DNS cleanup still runs;
- DNS failure while route cleanup still runs;
- Core timeout, forced termination, crash, restart recovery, and corrupted
  pending marker;
- user or second-VPN DNS/route changes during a session;
- two OpenPPP2 sessions contending for the network-control lease;
- network interface or Wi-Fi change during an active session.

**Acceptance checklist**

- [ ] Each scenario records the pre-state, operation result, post-state,
  ownership decision, and recovery record status.
- [ ] A failed or unverified restore leaves a retryable journal entry and a
  non-success aggregate stop result.
- [ ] A conflict preserves the later external value and is reported with a
  stable reason; the test does not silently overwrite it.
- [ ] Artifacts contain no credentials, node addresses, or private keys.
- [ ] The report states which scenarios ran with real privileged system calls
  and which remain unverified due to runner limits.
- [ ] The workflow fails when a required test binary or artifact is missing;
  optional platform coverage is marked `unverified` rather than passed.

**Current repository mapping**

| Evidence | Workflow/job | Current state |
|---|---|---|
| Static contracts and lifecycle wiring | `.github/workflows/test.yml` -> `cpp-linux` | Present; extend when new resources are added. |
| CTest and C++ coverage | `test.yml` -> `cpp-linux`; `test-linux-coverage.yml` | Present; coverage workflow may skip when `/root/dev` dependencies are absent. |
| Lifecycle ASan/UBSan | `test.yml` -> `lifecycle-sanitizers` | Present on Linux. |
| C++ TSan | `test.yml` -> `cpp-tsan` | Present on Linux. |
| Linux privileged rollback | `test.yml` -> `cpp-linux` -> namespace rollback | Present; requires `sudo`, snapshots and a machine-readable summary are uploaded even when the job fails. |
| Windows compile/package | `build-windows-x64.yml`, `build-windows-arm64.yml` | Present; not a network lifecycle test. |
| Windows host DNS/route acceptance | no current job | Required gap; the summary records this as `unverified` until a protected manual environment is added. |
| Desktop frontend/Rust tests | `test.yml` -> `desktop-rust` | Present on Ubuntu and Windows; dependency availability remains a runner prerequisite. |

**Out of scope for this issue**

This issue does not claim that a normal process can clean up after it has been
forcibly killed, nor does it treat a successful build as proof of host-network
restoration. Those guarantees require the recovery worker/service and the
platform-backed scenarios above.

## Labels and sequencing

Suggested labels: `network-lifecycle`, `recovery`, `windows`, `ipv6`,
`routing`, `desktop`, `ci`, `needs-platform-validation`.

Sequence: #83/#84/#85/#87 Wave 0; durable journal follow-up and route snapshot
serialization Wave 1; #86 Wave 2; platform, DNS boundary, coexistence, and CI
matrix follow-ups Wave 3. The publishing table above is authoritative when
issue numbers differ after publication. Close an issue only when its acceptance
evidence is attached and its unsupported platform scope is stated.
