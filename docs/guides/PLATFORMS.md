# Platforms

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `ppp/app/ApplicationHelp.cpp`, `ApplicationConfig.cpp`, `ApplicationInitialize.cpp`, `ApplicationNetwork.cpp`, `windows/ppp/tap/WintunAdapter.cpp`, `AppConfiguration.cpp`)
>
> **Purpose:** Privileges, drivers, platform-specific flags, and feature differences when running OPENPPP2 on each platform.
> **Audience:** Users deploying a client or server on a specific platform.
> **Parent index:** [Guides](README.md) · **Chinese:** [平台说明](PLATFORMS_CN.md)

The implementation-level platform abstraction is described in [Platform integration (architecture)](../architecture/PLATFORM_INTEGRATION.md).

## 1. Feature matrix

| Feature | Linux | Windows | macOS | Android | iOS |
|---|:-:|:-:|:-:|:-:|:-:|
| Server | ✔ | ✔ | ✔ | — | — |
| Server IPv6 (`server.ipv6`) | ✔ | — | — | — | — |
| TUN client | ✔ | ✔ | ✔ | App (VpnService) | App (Network Extension) |
| Proxy mode | ✔ | ✔ | ✔ | App "proxy only" | ✔ |
| Applies server-assigned IPv4 / IPv6 automatically | ✔ | ✔ | ✔ | OS framework | OS framework |
| `geo-rules` generation | ✔ | ✔ | ✔ | ✔ | — |
| `transport-auth` secret-file | ✔ | — | ✔ | ✔ | ✔ |
| Default P2P mode (`p2p.mode`) | `direct-preferred` | `relay` | `relay` | `direct-preferred` | `direct-preferred` |

## 2. Linux

- **Privileges:** TUN client and server need root or `CAP_NET_ADMIN` and a usable `/dev/net/tun` (map it explicitly in containers). Proxy mode needs neither.
- **Default adapter name:** `ppp` (change with `--tun=<name>`).
- **Packages:** on x86_64 prefer `openppp2-linux-amd64-simd.zip`; use `-debian10` on older systems; `-io-uring` variants use io_uring. Other architectures are listed in the [User manual](../getting-started/USER_MANUAL.md).
- **Platform flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--tun-ssmt=<N>[/mq]` | `0` | Packet worker threads; with `/mq` each worker opens its own TUN queue, for high throughput. |
| `--tun-protect=yes\|no` | `yes` | Keep the tunnel's own connections out of the tunnel. |
| `--tun-route=yes\|no` | `no` | Route compatibility mode; try it if route installation misbehaves. |
| `--tun-promisc=yes\|no` | `yes` | Adapter promiscuous mode. |
| `--bypass-nic=<interface>` | auto | Egress interface for bypassed traffic. |

- Route files (`client.routing.ip.routes[].nic`) can pick an egress interface per list, on Linux only.
- Server IPv6 is available only on Linux; see [IPv6](IPV6.md).
- As a gateway, enable `net.ipv4.ip_forward`; see [User manual · acting as a LAN gateway](../getting-started/USER_MANUAL.md).

## 3. Windows

- **Privileges:** the TUN client must run as administrator. Proxy mode usually does not need it.
- **Virtual adapter driver:** Wintun is preferred — `wintun.dll` is looked up in the program or system directory, then `Driver\wintun.dll`, then `Driver\<x64|arm64|x86>\wintun.dll`. Without Wintun, TAP-Windows is used; if no usable adapter exists, one is installed automatically from the drivers in `Driver\`. **Keep the release package's `Driver\` directory next to `ppp.exe`.**
- **Default adapter name:** `PPP`.
- **TCP stack:** `native` with Wintun, `lwip` with TAP-Windows by default (change with `--tcp-stack`).
- **Platform flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--set-http-proxy=yes\|no` | `no` | Point the system HTTP proxy at the client's local HTTP proxy (needs `client.http-proxy.port`; not applied in proxy mode). |
| `--tun-lease-time-in-seconds=<sec>` | `7200` | Virtual adapter DHCP lease. |
| `--system-network-reset` | — | Reset the Windows network stack and exit. |
| `--system-network-optimization` | — | Apply network tuning and exit. |
| `--system-network-preferred-ipv4` / `-ipv6` | — | Prefer IPv4 / IPv6 and exit. |
| `--no-lsp <program>` | — | Let the program bypass LSP. |

- `client.paper-airplane.tcp` (default `true`) enables the Paper Airplane LSP TCP acceleration, Windows only.
- The server runs on Windows but does not support `server.ipv6` (configuring it fails the load).
- `transport-auth` secret files cannot be read on Windows, so that feature is unavailable there.
- To act as a LAN gateway, [VGW](https://github.com/liulilittle/vgw-release) can be used.

## 4. macOS

- **Privileges:** the TUN client needs root (`sudo`). Proxy mode does not.
- **Virtual adapter:** the system `utun`, default name `utun0`.
- **Packages:** `openppp2-darwin-arm64.zip` for Apple silicon, `openppp2-darwin-x86_64.zip` for Intel. A downloaded binary may need its quarantine attribute removed (`xattr -d com.apple.quarantine ./ppp`).
- **Platform flags:** `--tun-ssmt=<N>` (packet worker threads), `--tun-promisc`.
- No server IPv6; P2P defaults to `relay` — set `"p2p": { "mode": "direct-preferred" }` for direct paths.

## 5. Android

- Used through the app (source in `android/`); the native library `libopenppp2.so` ships in `openppp2-android-<ABI>.zip`. Minimum Android 6.0 (API 23).
- Works through the system VpnService: no root, but the user must grant VPN consent on first connect.
- Routes and DNS are set by the OS VPN framework: TUN mode captures `0.0.0.0/0` and `::/0` (IPv6 leak protection) and sets tunnel DNS; "proxy only" keeps only the VPN interface subnet route, sets no DNS, and does not publish the local proxy as a system proxy.
- `client.routing.ip.peer-routes` apply inside the program only and are not turned into individual system routes.
- Subscriptions accept HTTPS links only (loopback HTTP for development).

## 6. iOS

- Used through the app plus a Packet Tunnel extension (source in `ios/`); requires the Network Extension entitlement.
- TUN mode: included routes from the configuration, the bypass list converted into excluded routes, and tunnel DNS when enabled; proxy mode keeps only the tunnel subnet route and sets no DNS.
- The `geo-rules` generator does not run; peer prefix routes apply only inside the program.
- Policy v2 `tcp-domain-sniff` is unavailable in iOS TUN.

## 7. Exit and cleanup

On exit the TUN client deletes the routes it added, restores DNS settings (Windows also flushes the DNS cache), and closes the virtual adapter. Stop it with `Ctrl+C`, `openppp2 exit`, or a normal service-manager stop; killing the process can leave stale routes — restart networking, or run once more and exit normally.

## Related documents

- [User manual](../getting-started/USER_MANUAL.md) · [CLI reference](../reference/CLI_REFERENCE.md) · [Proxy mode](PROXY_MODE.md) · [IPv6](IPV6.md)
- [Platform integration (architecture)](../architecture/PLATFORM_INTEGRATION.md)
