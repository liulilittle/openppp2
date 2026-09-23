# Client Architecture
> Status: Active
> Type: Architecture
> Last verified: `ppp/app/client/`, client bootstrap, and device sources, 2026-07-22
>
> **Purpose:** Describe the native client runtime and its role boundaries.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [客户端架构](CLIENT_ARCHITECTURE_CN.md)

## Scope

This page concerns the native C++ client runtime. The tree also contains Android, iOS, and desktop surfaces, but those surfaces host, launch, or consume the native runtime; they do not replace the `VEthernet*` ownership model described here.

```text
PppApplication
  -> VEthernetNetworkSwitcher       host-facing client controller
       -> VEthernetExchanger         session and tunnel actions
            -> ITransmission         primary or child carrier session
```

`VEthernetNetworkSwitcher` owns the device-facing virtual Ethernet runtime, client routes and DNS policy, local proxy listeners, and the active exchanger. `VEthernetExchanger` owns session establishment and client-side link-layer action handling. TCP and proxy paths can create child `ITransmission` connections; it is incorrect to assume every client flow is carried only by one primary transmission.

## Mode selection is not a configuration shortcut

The CLI selects the role:

| Invocation | Role behavior |
|---|---|
| `--mode=client` | Client runtime; normal privilege and platform preflight rules apply. |
| `--mode=proxy` | Client-family runtime with proxy mode; `Main()` skips its privilege gate. |
| `client.proxy-only: true` with `--mode=client` | Applies proxy-only runtime settings, but remains a client role for privilege and Windows preflight. |

Without `--mode=client` or `--mode=proxy`, the process selects server mode even if `client.proxy-only` is present.

`PrepareClientLoopbackEnvironment()` derives `proxy_only_runtime` from proxy mode or the config flag. On non-Android/non-iOS targets it selects `TapStub` for that runtime; `TapStub` reports open but intentionally discards output. Android supplies a real VPN file descriptor to native code, and source does not support claiming desktop-style proxy-only behavior for iOS.

## Device and host boundary

`ITap::Create()` chooses a platform adapter: Windows uses Wintun when ready and otherwise TAP-Windows; Linux uses `TapLinux`; macOS uses utun; iOS uses embedding callbacks. A full client has a platform device plus configured routes/DNS behavior. Proxy-only behavior is deliberately narrower in the native client opener: it starts the base runtime and proxy listeners, requires at least one listener, and returns before native DNS-policy and route application steps.

A listener being open is not evidence that the tunnel session is connected: proxy acceptance checks the exchanger's established network state.

## Packet-path boundary

There is no single mandatory “TAP → lwIP → tunnel” path for every packet:

- the device callback is installed by `VEthernet::Open()` and first parses IPv4 input;
- eligible virtual-network raw IPv4/IPv6 traffic can use the direct NAT path;
- TCP uses the virtual-stack connection path;
- UDP and ICMP have their own parsing/dispatch paths, with DNS and static-echo decisions where applicable;
- inbound NAT or rebuilt UDP/TCP traffic eventually reaches `VEthernet::Output()` and then the selected `ITap` implementation.

With `TapStub`, that last output is deliberately discarded. See [Packet Lifecycle](PACKET_LIFECYCLE.md) for the bounded flow map rather than a universal packet diagram.

## Session state versus operator state

`VEthernetExchanger::NetworkState` is a session input (`Connecting`, `Established`, or `Reconnecting`). `RuntimeLifecycle` publishes the operator-facing process phase. `OnTick()` maps the former into the latter and gates `connected` through session, adapter, route, DNS, and policy readiness.

An established exchanger therefore does not always imply an externally published `connected` phase. `INFO` is not a universal prerequisite for that gate; the switcher publishes readiness after its policy application path.

## MUX and P2P limits

MUX is not enabled by the handshake bit alone. Client runtime MUX work uses later link-layer `MUX`/`MUXON` exchanges and can open child carrier transmissions. Direct P2P code exists, but the production capability gate is false, so normal production execution remains relay-only.

## Related pages

- [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md)
- [Tunnel Design](TUNNEL_DESIGN.md)
- [EDSM State Machines](EDSM_STATE_MACHINES.md)
- [Transport and Protected Transmission](TRANSMISSION.md)
