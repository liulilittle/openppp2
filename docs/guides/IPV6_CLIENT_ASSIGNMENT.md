# IPv6 Client Assignment

> **Status:** Current desktop implementation boundary
> **Type:** Guide
> **Last verified:** Assigned-address manager, client exchanger, and mobile platform sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [IPv6 客户端地址分配](IPV6_CLIENT_ASSIGNMENT_CN.md)

## Scope

A server can return an IPv6 assignment as part of the client/server information exchange. Native client application and cleanup are implemented through `AssignedAddressManager` on desktop Windows, Linux, and macOS.

Android and iPhone builds do not use that native negotiated-address apply/restore path. Their VPN/network-extension behavior is platform-owned and must not be interpreted as equivalent desktop managed IPv6 support.

## Requesting an address is only a hint

A client can request an IPv6 address through the CLI:

```bash
./ppp --mode=client --config=./client.json --tun-ipv6=2001:db8::42
```

`--tun-ipv6` is a request hint, not a local address assignment and not a server IPv6 enable switch. The server can reject or replace it according to its configuration and active leases.

After a successful native desktop apply, the current switcher may reuse the last applied address as an in-process request on a later reconnect. This value is not a durable user configuration or a reservation.

## Native desktop lifecycle

When the server supplies a supported assignment, the desktop manager:

1. validates the assignment/mode for the current client path;
2. captures enough host state to undo the changes it owns;
3. applies the assigned IPv6 address and related route/DNS settings through the platform helpers;
4. records successful application state; and
5. restores owned state during disconnect/cleanup.

The lifecycle is best-effort host integration. A successful tunnel handshake does not by itself prove that the host accepted every IPv6 address, route, or DNS operation.

## Operator checklist

1. Confirm that the server is configured for a supported IPv6 mode; see [IPv6 transit plane](IPV6_TRANSIT_PLANE.md).
2. Run a desktop client on Windows, Linux, or macOS when relying on native negotiated application.
3. Use `--tun-ipv6` only when a requested address is appropriate for the server policy.
4. After connection, inspect the host interface/address/route state and test the intended IPv6 path.
5. On disconnect, confirm that operator-owned IPv6 configuration was not confused with state added by the VPN client.

## Common boundaries

| Observation | Meaning |
|---|---|
| The assigned address differs from `--tun-ipv6` | Normal: the server owns allocation. |
| IPv4 works but negotiated IPv6 does not apply | Check client platform support, server mode, and host permissions/state. |
| Android/iPhone has different IPv6 behavior | Expected: those builds use platform-specific VPN handling instead of this native lifecycle. |
| An address/route change fails | Treat it as a host integration failure; do not assume fail-closed traffic behavior. |

## Related pages

- [IPv6 lease management](IPV6_LEASE_MANAGEMENT.md)
- [IPv6 transit plane](IPV6_TRANSIT_PLANE.md)
- [Platform integration](PLATFORMS.md)
- [Operations and troubleshooting](../operations/OPERATIONS.md)