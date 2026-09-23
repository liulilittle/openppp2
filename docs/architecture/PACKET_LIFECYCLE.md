# Packet Lifecycle
> Status: Active
> Type: Architecture
> Last verified: `ppp/tap/`, `ppp/ethernet/`, client/server exchanger, and transport sources, 2026-07-22
>
> **Purpose:** Show the major packet-path branches without inventing a universal wire or host path.
> **Audience:** Contributors debugging forwarding behavior.
> **Parent index:** [Architecture](README.md) · **Chinese:** [数据包生命周期](PACKET_LIFECYCLE_CN.md)

## The important correction

The current runtime is not accurately described by one unconditional “Ethernet/TAP → lwIP → encrypted tunnel → Ethernet/TAP” diagram. It works primarily with IP packets, has direct NAT paths, protocol-specific TCP/UDP/ICMP paths, proxy socket paths, and platform-specific device adapters. Configured plaintext behavior also means “encrypted” is not a universal statement.

## Native client ingress

```text
selected ITap implementation
  -> callback installed by VEthernet::Open()
  -> IPv4 parse / packet dispatch
  -> direct NAT branch, virtual-stack TCP, or UDP/ICMP branch
  -> VEthernetExchanger Do* action
  -> ITransmission write
```

`ITap::AsynchronousReadPacketLoops()` invokes the installed device callback. `VEthernet::Open()` parses IPv4 input before dispatch; the raw `OnPacketInput(Byte*, ...)` hook is not the unconditional first step for every packet.

Eligible virtual-network raw IPv4/IPv6 traffic can reach `VEthernetExchanger::Nat()` and `DoNat()` directly. TCP enters the virtual-stack connection path. UDP can take DNS handling, static-echo handling, or ordinary `SendTo()` relay; ICMP has a separate path. These choices are driven by packet type and current configuration.

## Tunnel and server handling

`ITransmission` frames/transforms a link-layer payload and passes it over TCP, WS, or WSS. On receipt, `VirtualEthernetLinklayer::PacketInput()` uses the first decoded byte as the action opcode and calls a concrete handler.

A server-side `VirtualEthernetExchanger` then performs the action’s session work—such as TCP/UDP relay, raw NAT/IP handling, ICMP, FRP, static echo, or MUX work—within the owning switcher/session context. This page intentionally does not duplicate the opcode and wire-format reference.

## Return path

Responses use a reciprocal branch rather than one fixed route:

```text
server relay / forwarding result
  -> server Do* action -> server ITransmission write
  -> carrier -> client ITransmission read
  -> client On* action / virtual stack / datagram manager
  -> VEthernet::Output() -> selected ITap output
```

`TapStub` accepts the output call but discards the bytes by design. Other platform adapters inject through their native device or embedding boundary.

## MUX and child carriers

VMUX is not “many logical flows inside exactly one `ITransmission`.” Current setup can open child carrier transmissions and attaches them through later `MUX`/`MUXON` exchanges. Treat the initial session and child links as separate carrier objects with shared higher-level session ownership.

## Limits for packet investigations

- The link layer parses action-specific fields after an opcode; it does not define a generic opcode-plus-16-bit-length record format.
- `KEEPALIVED` updates activity in base dispatch; no general ACK behavior is defined there.
- Direction rejection is concrete-handler-specific, not globally guaranteed for every action.
- Raw NAT carries forwarded payload bytes, not merely traversal metadata.
- Fragmentation, QoS, and platform behavior have additional branches; confirm them in the current implementation before making operational claims.

## Source map

- `ppp/tap/ITap.cpp` and platform `Tap*` implementations
- `ppp/ethernet/VEthernet.cpp` and `VNetstack.cpp`
- `ppp/app/client/ClientPacketDispatchHandler.cpp`
- `ppp/app/client/VEthernetExchanger.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp`
- [Transport and Protected Transmission](TRANSMISSION.md)
