# Transmission Handshake And Session ID (Internal)

> Status: Internal — implementation-coupled
> Type: Source-derived handshake implementation note
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer documents: [中文](TRANSMISSION_PACK_SESSIONID_CN.md) · [Link-layer protocol](LINKLAYER_PROTOCOL.md) · [Packet formats](PACKET_FORMATS.md)

> **Boundary:** This describes the current `ITransmission` C++ handshake and
> related tunnel payload behavior. It is not a public SDK, protocol API, or
> formal compatibility specification.

## Ownership

`ITransmission` owns transport framing, pre-handshake session-ID exchange,
handshake ordering, and cipher lifecycle. The link layer runs only after
`ITransmission` returns a decoded payload.

## Handshake order

The implementation uses the following role-specific local sequence:

| Side | Sequence |
|---|---|
| Client | `NOPs` → receive session ID → send `ivv` → receive `nmux` → conditionally rebuild ciphers → mark handshake complete |
| Server | `NOPs` → send session ID → send `nmux` → receive `ivv` → conditionally rebuild ciphers → mark handshake complete |

`NOPs` are dummy session-ID messages. Their count is configuration- and
random-dependent (`key.kl` / `key.kh` feed the current helper), and the
session-ID decoder skips messages marked as dummy. A real session-ID helper
message also contains randomized bytes and optional padding; do not infer a
fixed packet fixture from it.

The low bit of current `nmux` selects the server's MUX result. Its high 64
bits carry a framing-configuration canary. The client compares that canary
only when its magic is present, publishing `ObfuscationFlagsMismatch` on a
mismatch; absence of the magic is not a negotiated version or compatibility
contract.

Cipher rebuilding occurs before `handshaked_` is set only when both current
cipher objects exist and the configuration has non-empty protocol/transport
names and keys. The replacement keys append the current `ivv` representation.
These details, including the conditional canary check, are implementation
behavior rather than a wire guarantee.

## `INFO` control payload

`INFO` is a link-layer action framed by `ITransmission`, not a second
transport framing scheme. It is sent on current client and server paths through
`VirtualEthernetLinklayer::DoInformation(...)`.

Its payload starts with the packed 28-byte `VirtualEthernetInformation` base
in network byte order, followed by optional extension text.

| Field | Source type | Meaning |
|---|---|---|
| `BandwidthQoS` | `Int64` | Bandwidth QoS value |
| `IncomingTraffic` | `UInt64` | Remaining incoming allowance |
| `OutgoingTraffic` | `UInt64` | Remaining outgoing allowance |
| `ExpiredTime` | `UInt32` | Expiration time |

When extension bytes are present, the link-layer implementation retains them
as `ExtendedJson` and calls `VirtualEthernetInformationExtensions::FromJson`.
A failed extension parse does not by itself reject the `INFO` action; the
handler still receives the base and raw extension text. The current IPv6 modes
recognized by that extension parser are `None`, `Nat66`, and `Gua`. Neither
the extension fields nor their JSON spelling form an external protocol
contract.

## Validation boundary

`tests/cpp/CMakeLists.txt` currently includes a JSON unit test that sources
`VirtualEthernetInformation.cpp`, but no target sourcing `ITransmission.cpp`.
The CI test workflow builds that manifest and runs `ctest`; this is not
handshake or interoperability evidence.

## Source anchors

- `ppp/transmissions/ITransmission.{h,cpp}` — frame ownership, session-ID helper, ordering, canary, and cipher rebuild
- `ppp/configurations/AppConfiguration.{h,cpp}` — current `key.*` input names and configured-cipher predicate
- `ppp/app/protocol/VirtualEthernetLinklayer.{h,cpp}` — `INFO` dispatch and `DoInformation`
- `ppp/app/protocol/VirtualEthernetInformation.{h,cpp}` — packed base fields, extensions, and IPv6 modes
- `tests/cpp/CMakeLists.txt` and `.github/workflows/test.yml` — current test-manifest evidence

For supported use, configure and launch the `ppp` process rather than treating
these C++ or wire details as an API.
