# Handshake Sequence and Session Establishment
> Status: Active
> Type: Architecture
> Last verified: `ppp/transmissions/ITransmission.cpp`, 2026-07-22
>
> **Purpose:** Record the current `ITransmission` handshake sequence without turning implementation details into security guarantees.
> **Audience:** Contributors investigating carrier/session setup.
> **Parent index:** [Architecture](README.md) · **Chinese:** [握手序列](HANDSHAKE_SEQUENCE_CN.md)

## Scope

This is the handshake beneath the link-layer action protocol. It starts after raw TCP, WS, or WSS carrier setup and before `VirtualEthernetLinklayer` receives decoded action payloads.

## Method-level sequence

```text
InternalHandshakeClient:
  NOP -> receive session_id -> generate/send ivv -> receive nmux
      -> rebuild configured ciphers -> handshaked_

InternalHandshakeServer:
  NOP -> send session_id -> construct/send nmux -> receive ivv
      -> rebuild configured ciphers -> handshaked_
```

The names are protocol-method names, not application-role labels. Current native caller wiring is inverted relative to a conventional diagram: the client exchanger calls the `HandshakeServer` path for its primary carrier and the server accept path calls `HandshakeClient`. Diagnose call sites rather than inferring roles from the method names.

## Wire values and current meanings

| Value | Current meaning |
|---|---|
| NOP | Dummy session-id-style packets. The high bit of the prefix marks a dummy packet, which the receiver skips. |
| `session_id` | Nonzero session value sent by the `InternalHandshakeServer` path. |
| `ivv` | Fresh client-generated `Int128` value used in working-cipher reconstruction. |
| `nmux` | Low bit carries the MUX decision; high bits carry a current obfuscation-flag canary. |

The NOP count is derived from configured bounds but can be randomized when those bounds differ. Do not document it as a fixed deterministic traffic pattern.

## Cipher reconstruction boundary

The constructor creates cipher objects from configured base keys when ciphertext is enabled. After the exchange, both method paths rebuild the protocol and transport cipher objects from base-32 `ivv_str`:

```text
key.protocol_key  + ivv_str
key.transport_key + ivv_str
```

`session_id` and `nmux` are not appended to these strings. In particular, `nmux` is not a key-derivation entropy input in the current reconstruction code; its high-half canary validates compatibility flags for peers that recognize it.

`handshaked_` is set after the reconstruction path. If configured ciphertext is unavailable or plaintext behavior is selected, that does not justify documenting every post-handshake frame as encrypted.

## Failure and compatibility boundary

The public handshake wrappers arm and clear a timeout around the internal exchange. A failed read, write, validation, allocation, timeout, or disposal can make the handshake fail. The exact wire framing and compatibility transforms are implementation details; consult the current source when changing interoperation behavior.

This code uses a transformed handshake packet family and configured ciphers/transforms. It should not be represented here as a proven mutual-authentication, PFS, or formal traffic-analysis-resistant protocol.

## Read with

- [Transport and Protected Transmission](TRANSMISSION.md)
- [Tunnel Design](TUNNEL_DESIGN.md)
- `ppp/transmissions/ITransmission.cpp`
