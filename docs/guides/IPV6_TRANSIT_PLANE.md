# IPv6 Transit Plane

> **Status:** Current Linux-server implementation boundary
> **Type:** Guide
> **Last verified:** IPv6 configuration normalization, server bootstrap, switcher, and Linux platform sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)

## Scope

The server IPv6 transit data plane is implemented only on Linux excluding Android. Unsupported server platforms reject NAT66/GUA configuration during normalization; do not document it as a harmless no-op or a portable server feature.

The implementation has two modes:

| Mode | Source-backed behavior |
|---|---|
| `nat66` | Linux host preparation uses the NAT66 path and `ip6tables`-based rules. An empty CIDR can normalize to the project ULA fallback. |
| `gua` | Uses a valid global-unicast CIDR, server IPv6 routing, and per-client NDP proxy support. |

Neither mode guarantees public reachability. It depends on host capability, TUN availability, IPv6 routing, upstream policy, and the operator's firewall/NAT environment.

## Current configuration surface

Use only the parsed `server.ipv6` fields:

| Field | Role |
|---|---|
| `mode` | `nat66` or `gua` |
| `cidr` | IPv6 network/pool input |
| `gateway` | IPv6 gateway input |
| `dns1`, `dns2` | IPv6 DNS inputs for negotiated client information when applicable |
| `lease-time` | Dynamic assignment lifetime |
| `static-addresses` | Client-GUID-to-address mapping |

There is no current `server.ipv6.enabled`, `prefix`, `uplink`, `transit_tap`, `forwarding`, or `nat66_masq` configuration contract. Do not depend on those ignored names.

## Runtime lifecycle

1. Server bootstrap prepares the Linux IPv6 host environment before opening the switcher.
2. The switcher creates a dedicated transit TAP and configures the transit path.
3. As client addresses become active, the server installs/replaces per-client `/128` IPv6 routes; it does not install one documented pool-prefix route for every client.
4. GUA mode additionally uses the NDP proxy path for active client addresses.
5. Server cleanup disposes the associated route/proxy/tunnel state in its lifecycle order.

This is operationally significant host mutation. Test on a controlled host and preserve any independently managed routes or firewall rules.

## SSMT boundary

Transit SSMT is opt-in. It requires the configured TUN SSMT and multi-queue path; it is not an automatic “one worker per CPU” facility and should not be documented as a guaranteed thread lifecycle.

## Operator checklist

1. Run the server on supported Linux (not Android) with required network-administration capability.
2. Choose `nat66` when the Linux NAT66 host prerequisites are intended, or `gua` only with a valid global-unicast CIDR and upstream IPv6 design.
3. Validate `/dev/net/tun`, IPv6 routing, and, for NAT66, the required `ip6tables` path before production rollout.
4. For GUA, validate default routing and NDP behavior using [IPv6 NDP proxy](IPV6_NDP_PROXY.md).
5. Inspect host routes and application diagnostics after adding a test client; there is no documented `/api/v1/server/ipv6/state` endpoint.
6. Keep firewall, route persistence, and external prefix delegation under operator control.

## Related pages

- [IPv6 lease management](IPV6_LEASE_MANAGEMENT.md)
- [IPv6 NDP proxy](IPV6_NDP_PROXY.md)
- [IPv6 client assignment](IPV6_CLIENT_ASSIGNMENT.md)
- [Deployment model](../operations/DEPLOYMENT.md)