# Link-Layer Protocol (Internal)

> Status: Internal — implementation-coupled
> Type: Source-derived tunnel implementation note
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer documents: [中文](LINKLAYER_PROTOCOL_CN.md) · [Packet formats](PACKET_FORMATS.md) · [Transmission handshake and session ID](TRANSMISSION_PACK_SESSIONID.md)

> **Boundary:** This describes the current tunnel C++ implementation and its
> wire behavior. It is not a public SDK, protocol API, or formal compatibility
> specification.

## Framing boundary

`ITransmission` owns tunnel framing and conditionally uses encryption and the
base94 envelope. `VirtualEthernetLinklayer` receives one decoded transmission
payload and dispatches it.

A link-layer message starts with a one-byte action opcode followed directly by
that action's payload. There is **no universal `uint16_t` length field** at
this layer; each action has its own parser and the enclosing `ITransmission`
frame supplies the message boundary.

## Known action codes

The following are the current `PacketAction` values in
`VirtualEthernetLinklayer.h` and the values accepted by the implementation's
known-action check. A known opcode does not make its payload valid or establish
a stable direction/compatibility contract.

| Code(s) | Action(s) | Current purpose |
|---|---|---|
| `0x20`–`0x25` | `FRP_ENTRY`, `FRP_CONNECT`, `FRP_CONNECTOK`, `FRP_PUSH`, `FRP_DISCONNECT`, `FRP_SENDTO` | FRP mapping and relay actions |
| `0x28` | `LAN` | LAN address/mask advertisement |
| `0x29` | `NAT` | Raw IP/NAT payload forwarding |
| `0x2A`–`0x2D` | `SYN`, `SYNOK`, `PSH`, `FIN` | TCP relay actions |
| `0x2E` | `SENDTO` | UDP relay action |
| `0x2F`, `0x30` | `ECHO`, `ECHOACK` | Echo request and acknowledgment |
| `0x31`, `0x32` | `STATIC`, `STATICACK` | Static query and acknowledgment |
| `0x35`, `0x36` | `MUX`, `MUXON` | MUX setup and acknowledgment |
| `0x7E` | `INFO` | Information envelope |
| `0x7F` | `KEEPALIVED` | Activity keepalive |

On a dispatcher fall-through, a known action with invalid structure records
`ProtocolFrameInvalid`; an unknown opcode records `ProtocolPacketActionInvalid`.
Individual handlers can publish more specific diagnostics.

## Selected behavior

- **`KEEPALIVED`:** receiving it updates link-layer activity time and succeeds. It does not create an acknowledgment frame.
- **`NAT`:** non-empty bytes after the opcode are passed as raw payload to `OnNat`; an empty NAT payload succeeds without calling `OnNat`.
- **`INFO`:** current client and server paths use it. The source sender is `DoInformation(...)`.

For an `INFO` payload of at least 28 bytes, the decoder reads the packed,
network-order `VirtualEthernetInformation` base, then treats remaining bytes as
extension text. An empty INFO payload succeeds without an information handler;
a non-empty payload shorter than the base falls through as an invalid known
action. Extension parsing is attempted but its failure alone does not reject a
full INFO message.

| Base field | Source type | Bytes | Meaning |
|---|---:|---:|---|
| `BandwidthQoS` | `Int64` | 8 | Bandwidth QoS value |
| `IncomingTraffic` | `UInt64` | 8 | Remaining incoming allowance |
| `OutgoingTraffic` | `UInt64` | 8 | Remaining outgoing allowance |
| `ExpiredTime` | `UInt32` | 4 | Expiration time |
| **Total** |  | **28** | Packed base payload |

The current extension parser recognizes IPv6 modes `None`, `Nat66`, and `Gua`.
Its JSON fields are implementation data, not a public schema guarantee.

## Validation boundary

`tests/cpp/CMakeLists.txt` currently has no target that sources
`VirtualEthernetLinklayer.cpp`; the CI test workflow runs `ctest` for that
manifest. This action table and parser description are source-derived, not
full frame-fixture or interoperability validation.

## Source anchors

- `ppp/transmissions/ITransmission.{h,cpp}` — transmission framing boundary
- `ppp/app/protocol/VirtualEthernetLinklayer.{h,cpp}` — opcode enum, dispatch, diagnostics, and `DoInformation`
- `ppp/app/protocol/VirtualEthernetInformation.{h,cpp}` — packed information base, extensions, and IPv6 modes
- `tests/cpp/CMakeLists.txt` and `.github/workflows/test.yml` — current test-manifest evidence

Use the source for changes; action direction and payload details are runtime
implementation behavior, not a stable external contract.
