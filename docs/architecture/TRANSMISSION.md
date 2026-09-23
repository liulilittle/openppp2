# Transport and Protected Transmission
> Status: Active
> Type: Architecture
> Last verified: `ppp/transmissions/`, carrier adapters, and handshake sources, 2026-07-22
>
> **Purpose:** Define the boundary between carrier adapters, `ITransmission`, and tunnel actions.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [传输与受保护会话层](TRANSMISSION_CN.md)

## Layer boundary

```text
TCP / WS / WSS carrier
  -> carrier adapter
  -> ITransmission: handshake, framing, configured transforms/ciphers
  -> VirtualEthernetLinklayer: action opcode payloads
```

`ITransmission` is the common protected-session/framing layer; it does not define tunnel actions. `VirtualEthernetLinklayer` receives a complete decoded payload, consumes its first byte as the action opcode, and delegates the remaining fields to concrete `On*` handlers.

## Carrier adapters

| Carrier | Adapter | Server configuration |
|---|---|---|
| Raw TCP | `ITcpipTransmission` | `tcp.listen.port` |
| WebSocket | `IWebsocketTransmission` | `websocket.listen.ws` |
| TLS WebSocket | `ISslWebsocketTransmission` | `websocket.listen.wss` |

Plain WS and WSS are sibling classes in `IWebsocketTransmission.h`; both derive from the WebSocket template rather than one inheriting from the other. The WebSocket adapter performs its wrapper handshake before delegating to the OpenPPP2 `ITransmission` handshake. WSS adds TLS before the WebSocket upgrade; it does not replace the `ITransmission` layer.

Configuration field names above are exact current names. `websocket.listen.ws.port` and `websocket.listen.wss.port` are not current configuration paths.

## Handshake boundary

The method-level exchange is:

```text
NOP prelude -> session_id -> ivv -> nmux -> optional cipher rebuild -> handshaked_
```

`InternalHandshakeClient()` sends NOP, receives the session id, generates/sends `ivv`, receives `nmux`, rebuilds ciphers when configured, then sets `handshaked_`. `InternalHandshakeServer()` sends NOP and session id, sends `nmux`, receives `ivv`, rebuilds ciphers when configured, then sets `handshaked_`.

Those method names must not be equated with application directory names: current client exchanger wiring invokes the `HandshakeServer` path for its primary carrier, while the server accept path invokes `HandshakeClient`.

`nmux` has two current responsibilities:

- its low bit carries the negotiated MUX flag;
- its high half carries an obfuscation-flag canary in current implementations, which can reject mismatched transform flags for peers that understand the canary.

It is not part of the working cipher key string. When ciphers are enabled, both sides rebuild the protocol and transport ciphers from their configured base key plus the base-32 `ivv` string:

```text
protocol key  = key.protocol_key  + ivv_str
transport key = key.transport_key + ivv_str
```

Neither `session_id` nor `nmux` is concatenated into those working key strings. NOP packets are marked as dummy by a high bit in their prefix and ignored by the receiver; their count is not universally deterministic when the configured bounds differ.

This is an implementation description, not a claim of a formal authentication or forward-secrecy protocol. Cipher and plaintext behavior remains configuration-dependent.

## Framing and action boundary

Carrier code reads and writes byte streams. `ITransmission` applies the current handshake/framing state and configured flags such as plaintext, masking, delta encoding, and shuffling. The link layer has no generic `[opcode][length][payload]` record format of its own: lower framing determines message length, then the link layer parses action-specific fields after the opcode.

`KEEPALIVED` updates link activity when received; base dispatch does not define a general keepalive-ack exchange. Action direction enforcement is likewise concrete-handler-specific rather than a universal parser rule.

## MUX and P2P limits

The handshake MUX bit is not by itself a full VMUX setup. Current VMUX setup uses later `MUX`/`MUXON` actions and can create child carrier transmissions. Direct P2P remains production-disabled by the shared capability gate.

## Re-check these sources

- `ppp/transmissions/ITransmission.cpp`
- `ppp/transmissions/IWebsocketTransmission.h/.cpp`
- `ppp/transmissions/templates/WebSocket.h`
- `ppp/app/protocol/VirtualEthernetLinklayer.h/.cpp`
- [Handshake Sequence](HANDSHAKE_SEQUENCE.md)
