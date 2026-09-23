# Deployment Model
> Status: Active
> Type: Operations
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [部署模型](DEPLOYMENT_CN.md)


[中文版本](DEPLOYMENT_CN.md)

## Scope

This document explains how OPENPPP2 is deployed according to the source tree.
It covers the deployment surfaces, startup order, platform prerequisites, and operational expectations.

---

## Core Facts

- The C++ runtime is a single executable: `ppp`.
- It can run in `client` mode or `server` mode.
- An optional Go backend can be linked by the server through `server.backend`.
- Administrator or root privilege is always required.

---

## Deployment Is Two Layers

```mermaid
flowchart TD
    A[OPENPPP2 Deployment] --> B[Node Layer]
    A --> C[Host Layer]
    B --> D[Role: client or server]
    B --> E[Persistent config JSON]
    B --> F[Optional Go backend]
    B --> G[Service intent]
    C --> H[Virtual adapters]
    C --> I[Routing table]
    C --> J[DNS behavior]
    C --> K[Privileges]
    C --> L[Local proxy surfaces]
```

| Layer | Meaning |
|-------|---------|
| Node layer | Persistent JSON, role, backend, and service intent |
| Host layer | Adapters, routes, DNS, privileges, local proxy surfaces |

The source tree treats these as related but not identical concerns.

---

## Deployment Surfaces

OPENPPP2 deployment can be read as four surfaces:

```mermaid
flowchart TD
    A[Deployment] --> B[Host surface]
    A --> C[Listener surface]
    A --> D[Data plane surface]
    A --> E[Management surface]
    B --> F[Privileges / adapters / routes / DNS]
    C --> G[TCP / UDP / WS / WSS]
    D --> H[Sessions / mappings / IPv6]
    E --> I[Optional Go backend]
```

| Surface | Components | Notes |
|---------|-----------|-------|
| Host | Privileges, virtual adapters, OS routing, DNS settings | Must be ready before runtime opens |
| Listener | TCP, WebSocket, TLS WebSocket, static UDP | Configured in `tcp.listen/websocket.listen/udp.listen` |
| Data plane | Sessions, NAT mappings, IPv6 transit, static echo | Per-session runtime state |
| Management | Go backend via WebSocket | Optional; extends policy, not packet transport |

---

## Hard Requirements

- Administrator or root privilege is required.
- A real configuration file is required.

`LoadConfiguration(...)` searches in this order:
1. Explicit `-c` / `--config` CLI argument.
2. `./config.json` in the working directory.
3. `./appsettings.json` in the working directory.

Source: `ppp/app/PppApplication.cpp`

---

## Client Deployment

The client deployment creates a virtual adapter, prepares route/DNS/bypass inputs, opens `VEthernetNetworkSwitcher`, and establishes the remote exchanger session.

### Client Startup Sequence

```mermaid
flowchart TD
    A[Start ppp --mode=client] --> B[Acquire privilege]
    B --> C[Load configuration]
    C --> D[Prepare NIC / gateway / TAP]
    D --> E[Open VEthernetNetworkSwitcher]
    E --> F[Connect VEthernetExchanger to server]
    F --> G[Apply routes and DNS]
    G --> H[Apply bypass IP lists]
    H --> I[Enter forwarding state]
    I --> J[Tick loop: keepalive, VIRR, vBGP refresh]
```

### Client Deployment Checklist

| Step | Requirement |
|------|-------------|
| 1 | Privilege: administrator on Windows, root on Linux/macOS/Android |
| 2 | Configuration file present at known path |
| 3 | `client.guid` set to a valid UUID |
| 4 | `client.server` pointing to an accessible server address |
| 5 | Virtual adapter support available on host |
| 6 | DNS and routing change permissions available |
| 7 | Optional: `client.routing.ip.bypass` IP-list files or `--bypass` CLI files accessible |
| 8 | Optional: `client.routing.dns.rules` sources or `--dns-rules` CLI file accessible |

### Client Platform Notes

| Platform | Adapter Type | Routing Method | DNS Method |
|----------|-------------|----------------|------------|
| Windows | TAP-Windows / WinTUN | IPv4 route API | System DNS override |
| Linux | TUN/TAP | `ip route` / `rtnetlink` | `/etc/resolv.conf` |
| macOS | utun | `route` command | `scutil` |
| Android | VPNService | VPNService routes | VPNService DNS |
| iOS | Packet Tunnel (Network Extension) | `NEIPv4Settings` included routes | `NEDNSSettings` (omitted in proxy-only) |

---

## Server Deployment

The server deployment opens listeners, firewall, namespace cache, datagram socket, optional managed backend, and optional IPv6 transit plumbing through `VirtualEthernetSwitcher`.

### Server Startup Sequence

```mermaid
flowchart TD
    A[Start ppp] --> B[Acquire privilege]
    B --> C[Load configuration]
    C --> D[Open firewall]
    D --> E[Open namespace cache]
    E --> F[Open datagram socket]
    F --> G{server.backend?}
    G -->|yes| H[Connect to Go backend]
    G -->|no| I[Skip]
    H --> J{server.ipv6?}
    I --> J
    J -->|yes| K[Open IPv6 transit plane]
    J -->|no| L[Skip]
    K --> M[Open TCP listener]
    L --> M
    M --> N[Open WebSocket listener]
    N --> O{static echo?}
    O -->|yes| P[Open static echo session]
    O -->|no| Q[Server ready]
    P --> Q
    Q --> R[Accept connections]
    R --> S[Tick loop: session maintenance, backend refresh]
```

### Server Deployment Checklist

| Step | Requirement |
|------|-------------|
| 1 | Privilege: root on Linux, administrator on Windows |
| 2 | Configuration file present |
| 3 | At least one listener enabled (`tcp.listen.port` or `websocket.listen.ws`) |
| 4 | Listener port set to a valid, available value |
| 5 | Firewall config file present if `server.firewall` is set |
| 6 | Go backend reachable if `server.backend` is set |
| 7 | IPv6 capable interface if `server.ipv6` is enabled |

### Server Listener Types

| Listener | Config Key | Protocol | TLS |
|----------|-----------|----------|-----|
| TCP | `tcp.listen.port` | Raw TCP | No |
| WebSocket | `websocket.listen.ws` | HTTP WebSocket | No |
| TLS WebSocket | `websocket.listen.wss` | HTTPS WebSocket | Yes |
| Static UDP | `udp.listen.port` | Raw UDP | No |

---

## Go Backend

The Go backend is optional and is used for managed deployments — not for the core data plane.

```mermaid
sequenceDiagram
    participant Server as C++ Server
    participant Backend as Go Backend
    participant Client as Client

    Client->>Server: Connect with credentials
    Server->>Backend: Authenticate(user, token)
    Backend-->>Server: auth result + quota
    Server-->>Client: Allow or deny
    loop Traffic reporting
        Server->>Backend: ReportTraffic(session_id, in, out)
        Backend-->>Server: quota status
    end
    Server->>Backend: SessionEnd(session_id)
```

Key properties:
- Communication is over WebSocket (`ws://` or `wss://`).
- If backend is unreachable, server falls back to local cache policy.
- Backend extends policy and management; it never touches packet bytes.

Source: `ppp/app/server/VirtualEthernetManagedServer.h`

---

## Privilege Requirements By Platform

| Platform | Requirement | Notes |
|----------|-------------|-------|
| Linux | `root` or `CAP_NET_ADMIN` | TUN/TAP creation requires privilege |
| Windows | Administrator | TAP driver and route modification |
| macOS | `root` | utun creation |
| Android | VPNService permission | Declared in `AndroidManifest.xml` |

---

## Network Prerequisites

| Requirement | Client | Server |
|-------------|--------|--------|
| Virtual adapter support | Required | Not required |
| Open TCP port | Not required | Required |
| DNS modification permission | Required | Not required |
| Route modification permission | Required | Not required |
| IPv6 capable NIC | If IPv6 enabled | If `server.ipv6` enabled |

---

## Operational Expectations After Startup

Deployment is not just the first boot. After startup, these host states are expected to remain true:

```mermaid
stateDiagram-v2
    [*] --> Deployed
    Deployed --> RoutesActive : client mode
    Deployed --> ListenersActive : server mode
    RoutesActive --> BypassRoutes : IP-list applied
    RoutesActive --> DefaultRouteRedirected : full-tunnel mode
    RoutesActive --> DefaultRouteProtected : split-tunnel mode
    ListenersActive --> AcceptingSessions : open complete
    AcceptingSessions --> ManagingBackend : if backend enabled
    AcceptingSessions --> IPv6Transit : if IPv6 enabled
    RoutesActive --> VIRRRefresh : tick-driven
    VIRRRefresh --> RoutesActive : refreshed
```

Ongoing host-side expectations:

| Expectation | Description |
|-------------|-------------|
| Default routes managed | Client may redirect or protect the default route |
| DNS servers stable | DNS server routes must persist |
| Listeners bound | Server listeners must remain bound |
| Backend reachable | Go backend connection must be maintained |
| IPv6 transit active | IPv6 transit plane must stay operational |

---

## Deployment Topology Examples

### Simple Server + Client

```mermaid
flowchart LR
    A[Client host] -->|TCP/WS| B[ppp server]
    B -->|Internet| C[Destination]
```

### Server With Go Backend

```mermaid
flowchart LR
    A[Client host] -->|TCP/WS| B[ppp server]
    B -->|WebSocket| C[Go backend]
    B -->|Internet| D[Destination]
    C --> E[Database / auth]
```

### Multi-Listener Server

```mermaid
flowchart TD
    A[TCP clients] --> B[ppp server]
    C[WebSocket clients] --> B
    D[TLS WebSocket clients] --> B
    B --> E[Session routing]
    E --> F[Internet]
```

---

## Deployment Failure Classes

| Class | Symptom | Likely Cause |
|-------|---------|-------------|
| Privilege failure | Process exits immediately | Not running as administrator/root |
| Config not found | "configuration not found" error | Wrong path or missing file |
| Adapter open failure | Virtual NIC not created | Driver missing or insufficient privilege |
| Listener bind failure | Port already in use or permission denied | Port conflict or privilege issue |
| Route add failure | Traffic not flowing through tunnel | Route modification not permitted |
| Backend unreachable | Sessions denied or cached policy applied | Backend not started or wrong URL |

---

## Configuration File Reference

Minimum viable server configuration:

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key"
  },
  "tcp": {
    "listen": { "port": 20000 }
  },
  "udp": {
    "listen": { "port": 20000 }
  },
  "websocket": {
    "path": "/tun"
  },
  "server": {
    "ipv4-pool": {
      "network": "10.0.0.0",
      "mask": "255.255.255.0"
    }
  }
}
```

Minimum viable client configuration:

```json
{
  "concurrent": 2,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key"
  },
  "client": {
    "guid": "{F4519CF1-7A8A-4B00-89C8-9172A87B96DB}",
    "server": "ppp://192.168.0.1:20000/"
  }
}
```

---

## Error Code Reference

Deployment-related `ppp::diagnostics::ErrorCode` values:

| ErrorCode | Description |
|-----------|-------------|
| `AppPrivilegeRequired` | Process requires administrator/root |
| `ConfigFileNotFound` | Config file not found at any search path |
| `ConfigLoadFailed` | Config file found but failed to parse |
| `NetworkInterfaceOpenFailed` | Virtual adapter could not be opened |
| `SocketBindFailed` | TCP or WebSocket listener failed to bind |
| `FirewallCreateFailed` | Firewall subsystem failed to initialize |
| `VEthernetManagedConnectUrlEmpty` | Go backend WebSocket connection failed |
| `IPv6TransitTapOpenFailed` | IPv6 transit TAP failed to open |
| `AppAlreadyRunning` | Another instance of ppp is already running |

---

## Related Documents

- [`CONFIGURATION.md`](../reference/CONFIGURATION.md)
- [`CLI_REFERENCE.md`](../reference/CLI_REFERENCE.md)
- [`PLATFORMS.md`](../guides/PLATFORMS.md)
- [`ROUTING_AND_DNS.md`](../guides/ROUTING_AND_DNS.md)
- [`OPERATIONS.md`](OPERATIONS.md)
- [`MANAGEMENT_BACKEND.md`](../guides/MANAGEMENT_BACKEND.md)
- [`SERVER_ARCHITECTURE.md`](../architecture/SERVER_ARCHITECTURE.md)
- [`CLIENT_ARCHITECTURE.md`](../architecture/CLIENT_ARCHITECTURE.md)

---

## Main Conclusion

Deployment in OPENPPP2 is not just "run a binary." It is a staged host-plus-node setup where the executable, privileges, adapters, routes, listeners, and optional backend must all line up correctly. A deployment is healthy only when all four surfaces — host, listener, data plane, and management — are configured and operational.
