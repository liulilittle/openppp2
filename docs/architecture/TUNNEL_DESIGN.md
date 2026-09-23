# Tunnel Design
> Status: Active
> Type: Architecture
> Last verified: client/server exchanger and link-layer sources, 2026-07-22
>
> **Purpose:** Map current tunnel ownership above `ITransmission`.
> **Audience:** Contributors.
> **Parent index:** [Architecture](README.md) · **Chinese:** [隧道设计](TUNNEL_DESIGN_CN.md)

## Layer and owner map

```text
carrier -> ITransmission -> VirtualEthernetLinklayer -> exchanger -> host/relay work

client: VEthernetNetworkSwitcher -> VEthernetExchanger
server: VirtualEthernetSwitcher -> VirtualEthernetExchanger (per primary session)
```

`ITransmission` turns carrier bytes into framed payloads. `VirtualEthernetLinklayer` interprets each decoded payload as an action opcode. Concrete exchangers implement the client or server action handlers; the link layer itself is not a top-level runtime owner.

## Client and server responsibilities

| Side | Top-level owner | Session owner | Main boundary |
|---|---|---|---|
| Client | `VEthernetNetworkSwitcher` | `VEthernetExchanger` | Host device/virtual stack, routes, DNS policy, proxies, and client-side actions |
| Server | `VirtualEthernetSwitcher` | `VirtualEthernetExchanger` | Listeners, per-session registration, forwarding, relay facilities, and shared policy |

An exchanger has a primary transmission path, but client TCP/proxy and VMUX paths can create child carrier transmissions. Carrier classes are therefore not interchangeable with “the entire tunnel session.”

## Session establishment boundary

A carrier must complete its `ITransmission` handshake before tunnel actions can flow. The current handshake exchange carries NOP packets, `session_id`, `ivv`, and `nmux`; see [Handshake Sequence](HANDSHAKE_SEQUENCE.md) for the method-level ordering and role-name caveat.

After framing, `VirtualEthernetLinklayer::Run()` sends action payloads into `PacketInput()`. The first byte selects an action such as information, keepalive, LAN, raw NAT/IP forwarding, TCP relay, UDP relay, echo, static mapping, FRP, or MUX. Direction and acceptance are defined by concrete handler implementations, not a single universal opcode-direction rule.

## Data-flow shape

```text
client host or virtual-stack event
  -> client exchanger Do* action
  -> ITransmission write
  -> carrier
  -> server ITransmission read
  -> server exchanger On* handler
  -> relay, forwarding, or server facility
```

Responses use the reverse owner chain. The exact host packet paths vary by protocol and platform; [Packet Lifecycle](PACKET_LIFECYCLE.md) deliberately documents those branches without claiming a single universal TAP/lwIP route.

## MUX, child links, and P2P

The handshake `nmux` bit is a carrier/session-path signal, not a complete VMUX lifecycle. Current VMUX setup starts with a link-layer `MUX` exchange, opens up to the configured number of child carrier transmissions, and uses `MUXON` on those child links. The initial server-side `MUX` handling replies with `MUX`; `MUXON` is the child-link attachment exchange.

Direct P2P implementation code exists, but the production authenticated-control capability gate is false. Normal execution should be documented as relay-only rather than as active direct delivery.

## Related pages

- [Transport and Protected Transmission](TRANSMISSION.md)
- [Packet Lifecycle](PACKET_LIFECYCLE.md)
- [Client Architecture](CLIENT_ARCHITECTURE.md)
- [Server Architecture](SERVER_ARCHITECTURE.md)
