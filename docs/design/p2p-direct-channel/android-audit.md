# Android P2P v2 audit

> Status: Audit record
> Type: Platform audit
> Last verified: 2026-10-30

## Route and socket protection

Android host-candidate discovery previously used `Socket::GetBestInterfaceIP`,
whose temporary UDP socket was not protected. With VpnService routing active,
that route lookup can select the TUN address rather than the physical address.
Discovery now protects a temporary socket before UDP connect, supports both
address families, sends no packet, and fails closed on protection failure.
Native data sockets are protected before bind; IPv6 remains optional and v6-only.
Neither data socket binds to the discovered host address.

## Deployment requirements and diagnosis

The Android CMake production option defaults ON. Service.instance is assigned in
onCreate before native startup, and cleared onDestroy. JNI caches a global class
reference at load; native threads attach only for bridge calls and detach only
when that call attached them. This is not a per-packet operation.

The debug panel now displays `Gate: <reason>` from `p2p_gate_reason`.
Android's native OnTick previously synchronized only MUX, leaving P2P runtime
state stale. It now publishes P2P state, peers and the gate reason as well.
`authenticated-exporter-unavailable` means TCP/plain WS needs negotiated
noise-psk-v1 with configured matching transport-auth keyrings (disabled by
default), or use a compatible TLS/WSS authenticated exporter. Do not bypass the
gate. `socket-protection-unavailable` means the service/bridge is not ready.
`relay-only` requires checking mode on both endpoints; Windows/macOS default to
relay. `eligible` confirms only the gate, not successful NAT traversal.

STUN servers default to an empty list. Configure reachable numeric IP:port
endpoints under p2p.stun.servers for cross-NAT discovery. The current gatherer
parses literals rather than resolving hostnames; it sends STUN over the same
protected socket as probes/data. Empty STUN plus an unroutable host candidate
cannot traverse unrelated NATs. No public server is silently introduced.

The Linux-only includes in P2PChannel are not Android interface enumeration.
Android discovery uses route selection instead. Server v2 offers require v2
support and authenticated exporters on both peers, not an Android platform flag.

## Verification limits

Loopback tests cover protect-before-bind/connect, fail-closed route discovery,
same-socket STUN and runtime JSON round trips. Device acceptance must verify
the candidate is not the TUN address, a reachable STUN yields srflx candidates,
both peers opt into direct-preferred, and state reaches direct with actual data.
Use logcat tags openppp2/OpenPPP2VpnProtect for protect result/JNI failures.
IPv6-only carriers, NAT64, network changes and restrictive NATs need real devices.
