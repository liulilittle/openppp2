# VPN Network Lifecycle Contract

> Status: Active contract and implementation roadmap
> Type: Architecture
> Last verified: 2026-10-12
>
> This page is the English counterpart of
> [VPN 网络生命周期合同](NETWORK_LIFECYCLE_CONTRACT_CN.md). It defines the
> source-backed contract for the lifecycle epic tracked by GitHub Issue #82.

## Scope

The contract covers virtual adapters, IPv4/IPv6 addresses, routes, DNS, system
proxy settings, and firewall rules. It does not claim that an ordinary process
can clean up after it has been forcibly killed. A forced stop must leave a
durable recovery path.

The following terms are used throughout the issue breakdown:

- **Resource:** an independently modified and restored control-plane object.
- **Ownership:** the session identity, token, target value, and resource identity
  used to prove that OpenPPP2 owns a write.
- **Snapshot:** the pre-change value, configuration mode, identity, and presence.
- **Recovery record:** durable write-ahead intent and confirmation state.
- **Conflict:** the current value no longer equals the value written by this
  session, or the resource identity has changed.

## Required invariants

1. Persist a complete snapshot and ownership before every OS write.
2. Restore DNS, routes, proxy, addresses, and adapters independently; one
   failed resource must not skip unrelated cleanup.
3. Delete a recovery record only after reading and verifying the actual OS state.
4. Compare the current value before restoring; preserve and report user or
   another VPN's later change instead of overwriting it blindly.
5. Keep failed writes, verification failures, and conflicts retryable. Block a
   new session from taking over unresolved resources.
6. Report `recovery_pending` after a forced stop. Process exit alone is not
   proof of clean network restoration.
7. Restrict writes and deletes to explicitly authorized resources.
8. Hold an inter-process network-control lease for the complete lifecycle;
   fail closed when the lease is unavailable.

## Lifecycle

```text
IDLE -> SNAPSHOT -> APPLYING -> VERIFYING -> ESTABLISHED
                  |                    |
                  +--> ROLLING_BACK ---+
                                      |
                         verified -> IDLE
                         conflict/failure -> RECOVERY_PENDING
```

Normal stop is: stop new traffic, execute each resource cleanup, verify every
result, then publish `stopped`. Apply failures must roll back completed writes;
an unverified rollback must result in `RECOVERY_PENDING`, never `connected`.
After a Core timeout or crash, the desktop must invoke an independent recovery
worker, service, scheduled task, or next-start recovery check.

## DNS policy boundary

The product must distinguish these policies:

| Policy | Contract |
|---|---|
| Virtual-interface DNS | Recommended default. Write only the authorized VPN adapter. Do not advertise this as strict leak protection. |
| Controlled takeover | Explicit opt-in. Capture automatic/static mode, IPv4/IPv6 servers, and stable adapter identity; compare before restoring. |
| Strict leak protection | A separate capability with explicit UDP/53, TCP/53, DoT, DoH, and unsupported encrypted resolver boundaries. `intercept-unmatched` is not system-wide DNS interception. |

DNS recovery is independent from route recovery. DHCP/automatic DNS must be
restored as automatic mode, not reconstructed from an address list or an IP
`DhcpEnabled` field.

## Current evidence and gaps

| Area | Current evidence | Status |
|---|---|---|
| Independent cleanup and retained failures | `ClientConnectionTeardown` and lifecycle contract tests | Wave 1 implemented |
| Windows DNS identity and automatic/static snapshot | `NetworkInterface` and Windows DNS contract tests | Implemented; real Windows execution still requires CI or a test host |
| Exact default-route ownership | `NetworkInterface::DeleteAllDefaultGatewayRoutes` and route contract tests | Wave 1 implemented |
| System proxy snapshot and compare-and-restore | `HttpProxy` and desktop proxy tests | Wave 1 implemented |
| Durable recovery journal | `NetworkRecoveryJournal`, resource-scoped replay, platform route replay, and focused CTest | DNS, versioned route, IPv4 v2, IPv6 MIB, proxy, and firewall replay are wired; privileged Windows host verification remains open |
| Process-wide control-plane lease | `NetworkOwnershipLease` and tests | Implemented |
| Forced-stop state and reconnect gate | Desktop `ProcessManager` and `recovery_pending` | Implemented; all supported journal resources replay with identity checks, while conflicts and Wintun markers remain a startup gate |
| Startup recovery, network changes, adapter churn | Wintun session/handle cleanup is ownership-aware; bundled DLLs have no adapter-delete export and recovery uses an atomic owner-PID/LUID/interface marker | Windows host validation |
| IPv6 parity, strict DNS interception, multi-VPN conflicts | Partial logic and static tests only | Open work; do not claim runtime coverage |

Address restoration uses durable, versioned snapshots. Windows IPv4 and IPv6
replay validate GUID/LUID/interface identity and retain conflicts or missing
interfaces as pending records. Privileged Windows host verification is still
required before calling the platform behavior complete.
Wintun adapters follow a fail-closed ownership rule: opening an existing
adapter never grants deletion rights. The bundled Wintun DLLs expose session
and handle close operations but no adapter-delete export, so cleanup ends the
session and closes only the handle held by the process. Crash recovery validates
the stable marker identity and clears only a stale session marker; an ambiguous
or live owner remains pending. Route replay likewise validates the serialized
platform identity and preserves conflicts.

## Issue decomposition and acceptance

Issue #82 is the epic. Child issues should retain these boundaries:

| Work item | Deliverable | Acceptance evidence |
|---|---|---|
| Wave 0 cleanup (#83/#84/#85/#87) | Independent resource results, authorized adapters, fail-closed apply | Static contracts and per-resource fault injection |
| Wave 1 transactions | Snapshot, journal, apply, rollback, verify wired into every entry | Crash window and journal retry tests; unverified records remain |
| Wave 2 desktop/Core stop (#86) | Timeout state machine, recovery entry point, startup gate | Core kill, desktop timeout, and restart recovery tests |
| Platform policy | Windows/Linux/macOS adapters, IPv6, DHCP, adapter changes | Isolated host snapshots before and after each scenario |
| DNS interception boundary | Separate UDP/TCP/DoT/DoH capability claims | Protocol-specific tests and explicit unsupported behavior |
| Coexistence and conflict | Ownership, compare-and-restore, conflict reporting | Manual DNS and second VPN changes are preserved |

Every child issue must name its code path, failure path, verification method,
platform limits, and uncovered scope. A function return value or process exit is
not evidence that the OS has been restored.

## CI and platform matrix

Offline tests prove serialization, ownership, and state-machine behavior only.
Release evidence must also cover static IPv4/IPv6 DNS, DHCP mode, adapter
disappearance and Wi-Fi changes, independent DNS/route failures, forced Core
termination, user DNS changes, and multiple VPNs in an isolated environment.
If a workflow does not exercise a privileged or platform-specific environment,
its report must say so explicitly.

The proposed fields `network.mode`, `restore_on_exit`, `persistent_recovery`,
`dns.mode`, and `routes.ownership_tracking` are design inputs, not supported
public configuration. Do not copy them into default configuration until the
corresponding implementation and compatibility contract exist.
