# Packet Formats (Internal)

> Status: Internal — implementation-coupled
> Type: Source-derived wire-format implementation note
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer documents: [中文](PACKET_FORMATS_CN.md) · [Link-layer protocol](LINKLAYER_PROTOCOL.md) · [Transmission handshake and session ID](TRANSMISSION_PACK_SESSIONID.md)

> **Boundary:** These are current C++ implementation details, not a public SDK
> or formal compatibility specification. This note intentionally contains no
> raw packet fixtures.

## Normal tunnel frames

`ITransmission` owns normal tunnel framing. It frames and decrypts payloads
before `VirtualEthernetLinklayer` sees an opcode.

| Condition | Current form |
|---|---|
| Before handshake, or when `key.plaintext` is enabled | Produce the binary transmission packet, then wrap it in base94. Decode reverses that order. Base94 selection does not by itself say whether current binary cipher objects exist. |
| Initial base94 send / receive | The send side emits a 7-byte header (4-byte simple area plus 3-byte validation area); the receive side expects that form until it validates it. |
| Later base94 send / receive | Each direction uses a 4-byte simple header after its own state changes. This is stateful implementation behavior, not a negotiated header version. |
| Handshake complete with `key.plaintext` disabled | Use the direct binary path with its 3-byte length header. Payload cipher use still depends on whether both current cipher objects exist. |

The base94 header's randomized key and filler values are generated in the
printable ASCII range `0x20`–`0x7e`. The binary packet path may also apply
configuration-controlled transforms. Neither observation establishes a
security or interoperability guarantee.

## Static-echo UDP codec

`PACKET_HEADER` in `VirtualEthernetPacket.cpp` is used by current static-echo
UDP callers, including the client static-echo channel and server static-echo
paths. It is **not** the framing format for normal `ITransmission` tunnel
traffic.

The packed struct is a pre-transform representation, not a fixed final wire
layout: optional protocol-header encryption can rebuild the portion beginning
at `checksum` before shuffle, masking, and final delta encoding.

| Field | Source type | Current role |
|---|---|---|
| `mask_id` | `uint32_t` | Non-zero per-packet obfuscation input |
| `header_length` | `uint8_t` | Obfuscated header-length value |
| `session_id` | `int32_t` | Signed session/family selector |
| `checksum` | `uint16_t` | Internet checksum computed over the pre-transform header and payload |
| `posedo` endpoints | packed IPv4/port fields | UDP/IP endpoint metadata |

`mask_id` is a `uint32_t`, not a byte. `checksum` is calculated with
`ppp::net::native::inet_chksum`; it is an integrity/error check, **not
cryptographic authentication**.

A negative recovered `session_id` selects the IP path; a positive one selects
UDP handling. The decoded `VirtualEthernetPacket` records this in `Protocol`.
There is no `VirtualEthernetPacket.udp` field.

## Separation of responsibilities

- Use `ITransmission` behavior for ordinary tunnel framing and link-layer payload delivery.
- Use `VirtualEthernetPacket::Pack` / `Unpack` only for the current static-echo UDP codec paths.
- Treat all transform order, sizes, and field behavior as implementation-coupled; do not derive an external wire-compatibility contract from this note.

## Validation boundary

`tests/cpp/CMakeLists.txt` currently has no target that sources
`VirtualEthernetPacket.cpp`; the CI test workflow runs `ctest` for that
manifest. This source-derived description is not packet-fixture or
interoperability validation.

## Source anchors

- `ppp/transmissions/ITransmission.cpp` — binary and base94 frame selection; 7/4/3-byte header behavior
- `ppp/app/protocol/VirtualEthernetPacket.{h,cpp}` — `PACKET_HEADER`, transforms, checksum, and `Protocol`
- `ppp/app/client/ExchangerStaticEchoChannel.cpp`, `ppp/app/server/VirtualEthernetDatagramPortStatic.cpp`, and `ppp/app/server/VirtualEthernetSwitcher.cpp` — current static-echo UDP use
- `tests/cpp/CMakeLists.txt` and `.github/workflows/test.yml` — current test-manifest evidence
