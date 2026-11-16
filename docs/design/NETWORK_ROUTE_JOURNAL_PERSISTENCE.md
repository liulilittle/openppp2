# Route Journal Persistence Gap

> Status: Open design follow-up
> Type: Architecture
> Last verified: 2026-10-12

## Status

OpenPPP2 persists Windows DNS recovery state and route mutation
intent/confirmation. Versioned snapshot codecs cover the Linux/Darwin record
shape and Windows MIB/gateway DTOs. Linux, Darwin, and Windows adapters expose
guarded cross-process replay: only complete records with platform and stable
interface identity are accepted, and an adapter compiled for a different
platform rejects the record. Legacy `created:<RouteSpec>` records remain
fail-closed because they lack enough ownership information.
Adding a journal record for only part of the route transaction would create a
false recovery guarantee and can delete or overwrite another program's route.

## Evidence in the current implementation

- `IRouteSnapshot` remains an opaque interface; platform-specific codecs carry
  stable default-route snapshots and created-route rows. The standalone
  recovery command invokes the platform replay entry points.
- Linux and macOS keep private snapshots containing a `RouteSpec`; Windows
  keeps both `MIB_IPFORWARDROW` snapshots and interface gateway snapshots.
- Windows route identity includes interface index, policy, protocol, type and
  metrics. The current `RouteSpec` does not carry all of those fields.
- `ProtectDefaultRoute` can capture and remove additional defaults while a
  connection is running. A one-time snapshot at `Apply` does not cover these
  later mutations.
- The existing platform `Delete` and `RestoreDefault` methods remain available
  for live teardown; the replay entry points use complete serialized records
  and compare the current host state before changing it.
- A route recovery record needs interface identity and enough context to
  rebuild the platform adapter after a restart. The versioned snapshot carries
  that identity; incomplete or conflicting records remain pending.

## Scope boundary

Do not add a `route` journal resource that stores only `RouteSpec` values, and
do not serialize opaque snapshots by implementation-specific casts. Such a
record could remove a route that was recreated by the user or another VPN,
while leaving captured default routes unrecovered.

The current route transaction still has an in-process rollback path. A failed
rollback keeps its existing state and reports failure; durable replay is only
claimed for complete versioned snapshots.

The standalone recovery command replays complete `route` records and fails
closed on legacy, malformed, or conflicting records. DNS recovery still runs
first because resource cleanup is independent;
the route record remains durable for a worker with the required platform
adapter and live identity checks.

## Required follow-up design

1. Define a versioned `RouteSnapshot` wire format with an explicit platform
   kind, interface identity, route identity, mutable attributes and ownership
   token. Reject unknown versions and incomplete identities.
2. Add platform adapters that can deserialize a snapshot and verify the live
   row before mutating it. Verification must use compare-and-restore semantics
   and preserve an external change as a conflict.
3. Journal every mutation before the operating-system call, including default
   route recaptures performed by the protector. Record intent, confirmation,
   ownership and the recovery context needed after restart.
4. Define recovery ordering and compensation for route conflicts. A failed
   item remains durable and retryable; unrelated DNS, proxy and firewall
   entries are handled by their own resource handlers.
5. Provide a startup or independent recovery worker that acquires the network
   ownership lease before replaying records. It must verify the final route
   table before deleting a journal entry.

## Acceptance tests for a future implementation

- Kill Core after each route mutation window and recover on the next startup.
- Cover Linux, Windows and macOS route identity fields, including IPv4 and
  IPv6 default routes where supported.
- Change a route manually while Core is stopped; recovery reports a conflict
  and does not overwrite the new route.
- Exercise protector recapture, partial remove, partial restore and retry.
- Run two VPN instances and verify the ownership lease prevents cross-process
  mutation.
- Corrupt, truncate and downgrade the journal; recovery fails closed and
  retains the record.
- Verify route recovery does not consume or mis-handle DNS/proxy/firewall
  journal resources.

## Suggested issue

**Title:** Design and implement durable, ownership-aware route recovery

**Labels:** `network-lifecycle`, `routes`, `enhancement`, `P0`

**Depends on:** Network lifecycle contract and the independent recovery worker
design. This issue should not be closed by adding only a serialized
`RouteSpec`; completion requires all route mutation paths and conflict-aware
verification to be covered.
