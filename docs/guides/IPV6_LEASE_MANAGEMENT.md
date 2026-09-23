# IPv6 Lease Management

> **Status:** Current Linux-server implementation boundary
> **Type:** Guide
> **Last verified:** Server configuration and IPv6 exchanger/lease sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [IPv6 租约管理](IPV6_LEASE_MANAGEMENT_CN.md)

## Scope

The server tracks assigned IPv6 addresses against sessions and uses those records to route packet delivery and reclaim expired dynamic assignments. This server data plane is supported on Linux excluding Android; it is not a cross-platform IPv6 lease service.

There is no implemented `/api/v1/leases` endpoint. Do not build monitoring or automation around that undocumented path.

## Parsed server configuration

Only the following `server.ipv6` fields are the current configuration surface:

| Field | Purpose |
|---|---|
| `mode` | `nat66` or `gua` server mode |
| `cidr` | Address pool/network input |
| `gateway` | IPv6 gateway input used by the server path |
| `dns1`, `dns2` | IPv6 DNS inputs returned to clients when applicable |
| `lease-time` | Dynamic-lease lifetime in seconds; default is 300 |
| `static-addresses` | Mapping of client GUID to statically assigned IPv6 address |

Fields such as `enabled`, `prefix`, `lease_duration`, `max_leases`, and `static_bindings` are not this parser's current interface.

## Allocation behavior

Allocation is server-owned:

1. A static address mapping for the client GUID has priority when configured.
2. A client may request an address through `--tun-ipv6`, but the request is only a hint.
3. Dynamic candidates are derived deterministically from the session identity and use bounded retry masks when a candidate conflicts.
4. A lease is associated with the session and used with the active IPv6 exchanger mapping.

Do not describe allocation as random, permanently sticky, or externally reserved unless the actual configured static-address mapping provides that property.

A `lease-time` of zero and static mappings use the implementation's non-expiring lease behavior. Choose this deliberately: it changes reclamation expectations and does not replace operational cleanup.

## Modes and prerequisites

- `nat66` uses the Linux server NAT66 path; an empty CIDR can normalize to the project ULA fallback.
- `gua` requires a valid global-unicast CIDR and depends on the host IPv6 route/NDP environment.
- Unsupported server platforms reject these IPv6 modes during configuration normalization.

See [IPv6 transit plane](IPV6_TRANSIT_PLANE.md) before enabling either mode.

## Operator checklist

1. Keep client GUIDs stable if using `static-addresses`.
2. Decide whether dynamic expiry or non-expiring lease semantics are appropriate for the deployment.
3. Confirm that clients can accept server-selected addresses rather than assuming their request hint succeeds.
4. Monitor the running server through available logs/host state and supported management interfaces; do not scrape a nonexistent lease REST API.
5. Test cleanup/reconnect behavior in a maintenance environment before relying on a long-lived address plan.

## Related pages

- [IPv6 client assignment](IPV6_CLIENT_ASSIGNMENT.md)
- [IPv6 NDP proxy](IPV6_NDP_PROXY.md)
- [IPv6 transit plane](IPV6_TRANSIT_PLANE.md)
- [Security model](../operations/SECURITY.md)