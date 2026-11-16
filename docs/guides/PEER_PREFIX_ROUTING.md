# Peer Prefix Routing (Site-to-Site)

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `ppp/app/server/PeerRouteAnnouncePolicy.h`, `VirtualEthernetSwitcher.cpp`, `ppp/app/client/PeerPrefixRouteManager.cpp`, `VEthernetExchanger.cpp`)
>
> **Purpose:** Let other clients reach the whole LAN behind a "gateway client".
> **Audience:** Operators interconnecting site networks.
> **Parent index:** [Guides](README.md) · **Chinese:** [对端前缀路由（站点互联）](PEER_PREFIX_ROUTING_CN.md)

## 1. Scenario

```text
Client B (10.1.0.3) ──► server ──► gateway client A (10.1.0.2) ──► A's LAN 10.0.0.0/24
```

By default (`server.subnet: true`) clients reach each other only by virtual IP. Peer prefix routing adds "prefix → gateway client" forwarding: when B sends to `10.0.0.5`, the server hands the packet to A by longest-prefix match, and A forwards it into its LAN.

- IPv4 only.
- Route installation is fully supported on desktop (Windows / Linux / macOS); Android / iOS support is limited.
- Independent of P2P: prefix routing decides *which* client receives the traffic; P2P only optimizes *how* to reach that client.

## 2. What each role configures

| Role | Required |
|---|---|
| Server | `server.subnet: true`; `server.peer-routing.enabled: true`; an `allowed-routes` **allowlist** of the prefixes each gateway may announce |
| Gateway client A | Announce prefixes in `client.peer-route-announce`; `client.peer-gateway-forward: true`; IP forwarding on the host; a return route from the LAN |
| Access client B | Nothing (the server distributes the route table); or static routes in `client.routing.ip.peer-routes` |

## 3. Server

```json
"server": {
  "subnet": true,
  "ipv4-pool": { "network": "10.1.0.0", "mask": "255.255.255.0" },
  "peer-routing": {
    "enabled": true,
    "distribute": true,
    "allowed-routes": [
      { "network": "10.0.0.0", "prefix": 24, "guid": "{11111111-1111-1111-1111-111111111111}" }
    ]
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `peer-routing.enabled` | `false` | Enable prefix forwarding. |
| `peer-routing.distribute` | `true` | Push the current route table to all clients when gateways join / leave. |
| `peer-routing.allowed-routes[]` | empty | Announcement allowlist. Each entry is `{network, prefix, guid}`: an announcement is accepted only when the client's `client.guid` equals `guid` (case-insensitive, braces ignored) and the prefix is **identical**. **With an empty list every announcement is rejected.** |

Regardless of the allowlist, these are always rejected: the default route, `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`.

## 4. Gateway client A

```json
"client": {
  "guid": "{11111111-1111-1111-1111-111111111111}",
  "server": "ppp://vpn.example.com:20000/",
  "peer-route-announce": [
    { "network": "10.0.0.0", "prefix": 24 }
  ],
  "peer-gateway-forward": true
}
```

| Field | Meaning |
|---|---|
| `peer-route-announce[]` | Prefixes reachable behind this host, `{network, prefix}`, no `via`. Sent with the handshake; the server echoes only the accepted prefixes. |
| `peer-gateway-forward` | Must be `true`; otherwise A drops every packet not addressed to its own virtual IP. |

Host setup (Linux example):

```bash
sysctl -w net.ipv4.ip_forward=1
# If LAN devices do not know 10.1.0.0/24, SNAT or add a return route on the LAN router:
iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
```

Give A a fixed virtual IP so static routes on access clients stay valid: start it with `--tun-ip=10.1.0.2 --tun-gw=10.1.0.1 --tun-mask=24`.

## 5. Access client B

**Dynamic (recommended):** with the server's `distribute: true`, B receives and installs `10.0.0.0/24 via 10.1.0.2` on connect, no configuration needed.

**Static:** for a fixed topology, or when the server disables `distribute`:

```json
"client": {
  "routing": {
    "ip": {
      "peer-routes": [
        { "network": "10.0.0.0", "prefix": 24, "via": "10.1.0.2" }
      ]
    }
  }
}
```

`network`, `prefix`, and `via` (the gateway's virtual IP) are required; entries whose `via` equals the local virtual IP are ignored. Without `client.routing`, the legacy location `client.peer-routes` works too. Static and dynamic routes can coexist.

In proxy mode these routes apply only inside the program and are not written into the OS route table.

## 6. Server forwarding order

1. The destination is exactly a client's virtual IP → that client;
2. otherwise longest-prefix match among accepted announcements → the matching gateway client;
3. no match → not forwarded.

When a gateway disconnects, its prefixes leave the table and (with `distribute: true`) the update is pushed to other clients.

## 7. Go-live checks

1. Server: `subnet` and `peer-routing.enabled` are `true`; `allowed-routes` contains the gateway GUID with the identical prefix.
2. Gateway: `peer-gateway-forward: true`, IP forwarding on, LAN return route or SNAT in place.
3. Access client: `ip route | grep 10.0.0.0` (Windows: `route print`) shows a route via the gateway's virtual IP.
4. `ping 10.0.0.x` from the access client.

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| No route on the access client | Announcement rejected (`allowed-routes` empty, GUID or prefix mismatch, forbidden range); or `distribute: false` without static routes |
| Route present, no connectivity | Gateway offline, or wrong `via` in a static route |
| Packets reach the gateway but not the LAN | `peer-gateway-forward` off, or host IP forwarding off |
| LAN devices do not reply | No LAN return route to `10.1.0.0/24`; add SNAT or a static route |
| Server does not forward | `server.subnet` or `peer-routing.enabled` is `false` |

## Related documents

- [Configuration reference · server / client](../reference/CONFIGURATION.md) · [Routing and DNS](ROUTING_AND_DNS.md)
