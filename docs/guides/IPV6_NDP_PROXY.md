# IPv6 NDP Proxy

> **Status:** Current Linux GUA-server implementation boundary
> **Type:** Guide
> **Last verified:** Server switcher and Linux TAP/NDP sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [IPv6 NDP 代理](IPV6_NDP_PROXY_CN.md)

## Scope

NDP proxy makes individually assigned GUA client addresses reachable through a Linux server's upstream link. It is part of the Linux GUA server path; NAT66 does not use it, and it is not a portable Windows/macOS/mobile server feature.

The implementation enables/reads the Linux `proxy_ndp` setting through procfs and creates/removes per-address proxy neighbor entries through rtnetlink. It does not invoke shell `ip neigh add`/`del` commands as its core implementation path.

## How it fits the data plane

For an active GUA client address, the server needs both:

1. a server-side IPv6 route that delivers packets for that client address to the transit path; and
2. an NDP proxy entry on the upstream interface so the adjacent IPv6 network can resolve that address to the server.

The first part is covered by [IPv6 transit plane](IPV6_TRANSIT_PLANE.md). NDP only solves neighbor discovery; it does not prove that upstream routing, host forwarding, firewall policy, or client reachability is correct.

## Preconditions

Before enabling GUA mode, verify all of the following outside the application:

- the server is Linux (not Android) and has the required network administration capability;
- `server.ipv6.mode` is `gua` with a valid global-unicast CIDR;
- the selected host path has a functional IPv6 default route and reachable upstream network;
- the host permits the required procfs and rtnetlink operations; and
- upstream/router/firewall policy allows the intended traffic.

The code cannot establish delegated-prefix ownership, upstream router policy, or Internet reachability on the operator's behalf.

## Observe, do not guess

A read-only host check can show proxy entries after clients are active:

```bash
ip -6 neigh show proxy dev <uplink-interface>
```

An absent entry can indicate that the server did not establish the GUA path or that host prerequisites failed. A present entry still does not prove external reachability; test from the relevant network and inspect server/client diagnostics.

## Lifecycle boundary

- The switcher enables the NDP proxy path only for GUA mode.
- It attempts per-client entries as IPv6 exchangers become active and removes them when the associated server lifecycle cleans up.
- Existing host configuration and failure conditions matter. Treat cleanup as implementation-managed state, but do not rely on it to repair unrelated manual NDP entries.
- There is no documented manager REST endpoint for NDP entries or runtime state.

## Operator checklist

1. Confirm the Linux-only GUA mode and transit setup before examining NDP.
2. Use least privilege consistent with TUN, route, procfs, and neighbor operations.
3. Keep operator-owned sysctl/firewall/prefix-routing changes under configuration management.
4. Inspect proxy entries and the host route table after a test client receives an address.
5. If reachability fails, distinguish NDP resolution, server routing, client assignment, and upstream policy instead of changing all host settings at once.

## Related pages

- [IPv6 transit plane](IPV6_TRANSIT_PLANE.md)
- [IPv6 lease management](IPV6_LEASE_MANAGEMENT.md)
- [Platform integration](PLATFORMS.md)
- [Security model](../operations/SECURITY.md)