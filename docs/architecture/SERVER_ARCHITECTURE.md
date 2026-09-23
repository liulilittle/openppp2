# Server Architecture
> Status: Active
> Type: Architecture
> Last verified: `ppp/app/server/` and server bootstrap sources, 2026-07-22
>
> **Purpose:** Describe server bootstrap, listener roles, session ownership, and the managed-backend boundary.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [服务端架构](SERVER_ARCHITECTURE_CN.md)

## Owner model

```text
PppApplication
  -> VirtualEthernetSwitcher
       -> acceptors and shared server state
       -> VirtualEthernetExchanger (one primary session handler per client)
            -> primary ITransmission and session forwarding state
```

`PrepareServerLoopbackEnvironment()` prepares server IPv6 host state, creates `VirtualEthernetSwitcher`, assigns its preferred interface, then calls `Open()` and `Run()`. A failed bootstrap finalizes the host preparation and disposes a partially created switcher.

`VirtualEthernetSwitcher` owns listeners, accept/registration tables, global policy, and cross-session facilities. `VirtualEthernetExchanger` handles one primary client session and its NAT, relay, ICMP, FRP, VMUX, and static-echo-related work. A non-MUX accepted child carrier can attach to an existing exchanger rather than create another primary exchanger.

## Listener model

Current TCP-family acceptors are configured with these fields:

| Category | Configuration | Carrier/result |
|---|---|---|
| Raw TCP | `tcp.listen.port` | `ITcpipTransmission` |
| WebSocket | `websocket.listen.ws` | `IWebsocketTransmission` |
| TLS WebSocket | `websocket.listen.wss` | `ISslWebsocketTransmission` |
| CDN paths | `cdn[0]`, `cdn[1]` | SNI-proxy handling, not ordinary carrier setup |

A configured value of `0` disables these acceptors. The binder can retry with an OS-selected port after a bind failure, so an observed local endpoint—not only the requested configuration—is authoritative for a running listener.

`udp.listen.port` is different: it opens a static-echo UDP socket when positive. It is not a general UDP tunnel-session listener; a session requests a static-echo allocation before using that facility.

`Run()` starts accept loops for available TCP-family acceptors and marks the switcher running only when at least one loop starts. The server's process-facing runtime readiness therefore represents active listener runtime, not the number or health of every connected client.

## Managed backend boundary

C++ managed mode is attempted only when `server.backend` is nonempty **and** `server.node >= 1`. There is no `server.managed` configuration field.

The bridge connects asynchronously and retries failed connections. A server can bring up listeners before that link is usable, but a configured backend remains a new-session gate: a managed primary session needs bridge authorization and a valid `VirtualEthernetInformation` response.

The native control channel is an internal, length-prefixed JSON protocol. Its implemented commands are ECHO (1000), CONNECT (1001), AUTHENTICATION (1002), and TRAFFIC (1003). `server.backend-key` is sent and compared as a shared string in the current implementation; do not describe it as HMAC signing. Traffic is queued and flushed by the bridge on its own interval rather than synchronously sent by every exchanger tick.

This bridge is not a general remote administration protocol for the C++ process. It has no documented version/capability negotiation and should remain treated as an internal integration boundary.

## Platform and P2P limits

Server mode normally has no client-style host tunnel runtime, but Linux can create an IPv6 transit TAP path when configured. Direct P2P remains fail-closed by the shared production capability gate. Neither feature should be described as a universal server data-plane behavior.

## Related pages

- [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md)
- [Transport and Protected Transmission](TRANSMISSION.md)
- [Tunnel Design](TUNNEL_DESIGN.md)
- [Project interface map](../reference/PROJECT_INTERFACE_MAP.md)
