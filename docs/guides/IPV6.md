# IPv6

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `AppConfiguration.cpp`, `ppp/app/server/VirtualEthernetSwitcher.cpp`, `ppp/app/client/AssignedAddressManager.cpp`)
>
> **Purpose:** Have the server assign IPv6 to clients and carry their IPv6 traffic.
> **Audience:** Operators deploying the server.
> **Parent index:** [Guides](README.md) · **Chinese:** [IPv6](IPV6_CN.md)

## 1. Support

| Side | Support |
|---|---|
| Server | **Linux only (not Android).** On other platforms a configured `server.ipv6.mode` makes the configuration fail to load. |
| Client | Windows / Linux / macOS apply the server-assigned address, routes, and DNS to the virtual adapter automatically and restore them on disconnect. Android / iOS use their own OS VPN frameworks and behave differently. |

## 2. Choose a mode

| Mode | Use when | Prerequisites |
|---|---|---|
| `nat66` | The server has a single public IPv6 or no prefix to hand out. Clients get private (ULA) addresses and the server NATs them out. | `ip6tables` available on the server; `cidr` may be omitted and defaults to `fd42:4242:4242::/64`. |
| `gua` | You own a routable global unicast prefix and want each client to have a public IPv6 address. | `cidr` must be global unicast; the server has a working IPv6 default route; upstream routes the prefix to the server or resolves it via NDP proxy (section 5). |

Neither mode guarantees Internet reachability; that depends on host routing, upstream policy, and firewalls.

## 3. Server configuration

```json
"server": {
  "ipv6": {
    "mode": "nat66",
    "cidr": "fd42:4242:4242::/64",
    "gateway": "fd42:4242:4242::1",
    "dns1": "2606:4700:4700::1111",
    "dns2": "2001:4860:4860::8888",
    "lease-time": 300,
    "static-addresses": {
      "{F4569208-BB45-4DEB-B115-0FEA1D91B85B}": "fd42:4242:4242::100"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `mode` | **Required**, `nat66` or `gua`. `cidr` alone does not enable IPv6. |
| `cidr` | Pool prefix. An invalid prefix length (e.g. `/128`) or a non-global-unicast prefix in `gua` mode disables IPv6. |
| `gateway` | Server gateway address; the first address in the prefix is used when empty or outside the prefix. |
| `dns1` / `dns2` | IPv6 DNS pushed to clients. |
| `lease-time` | Dynamic lease time in seconds, default 300; `0` means non-expiring. |
| `static-addresses` | Fixed address per client GUID; entries outside the prefix, equal to the gateway, or duplicated are dropped. |

Other names (`enabled`, `prefix`, `uplink`, `lease_duration`, …) are not read.

The server needs root (or `CAP_NET_ADMIN`) and a usable `/dev/net/tun`. At startup it creates a dedicated transit adapter and adds one `/128` route per online client.

## 4. How addresses are assigned

1. If the client GUID has a `static-addresses` entry, that address is used (non-expiring).
2. A client can request an address with `--tun-ipv6=<address>`; this is only a hint the server may reject or replace.
3. Otherwise a deterministic candidate is derived from the session ID, with bounded adjustment on conflict.
4. The address is bound to the session; dynamic addresses can be reclaimed after the lease expires. On reconnect within the same process, the client first requests the address it had last.

To keep a client on one address long-term, use `static-addresses` and keep that client's `client.guid` stable.

## 5. GUA mode and NDP proxy

In `gua` mode the server adds an NDP proxy entry on the uplink interface for each online client address (enabling `proxy_ndp` via procfs and managing entries via rtnetlink), so the upstream router can resolve those addresses. `nat66` does not use NDP proxy.

After a client connects you can inspect read-only:

```bash
ip -6 neigh show proxy dev <uplink-interface>
ip -6 route | grep <client-address>
```

An entry does not prove external reachability; a missing entry means the GUA path was not established or host prerequisites failed.

## 6. Go-live checks

1. The server is Linux and runs as root; for `nat66`, `ip6tables` is available.
2. After connecting, run `openppp2 info` on the client and confirm it has an IPv6 address.
3. Test IPv6 from the client (e.g. `ping -6 2606:4700:4700::1111`).
4. In `gua` mode, check NDP proxy entries and routes as in section 5.
5. After disconnecting, confirm the client's added addresses and routes are gone and your own IPv6 settings were not touched.

## 7. Common observations

| Observation | Meaning |
|---|---|
| Startup reports IPv6 unavailable / unsupported platform | The server is not Linux, or runs on Android. |
| `cidr` configured but clients get no IPv6 | `mode` missing, or the prefix was invalid and disabled. |
| Assigned address differs from `--tun-ipv6` | Normal; the server owns allocation. |
| IPv4 works, IPv6 does not | Check the client platform, server `ip6tables` (nat66), or upstream routing / NDP (gua). |
| Android / iOS behave differently | Expected; mobile address handling belongs to the OS VPN framework. |

## Related documents

- [Configuration reference · server](../reference/CONFIGURATION.md)
- [Platforms](PLATFORMS.md) · [Deployment](../operations/DEPLOYMENT.md) · [Security](../operations/SECURITY.md)
