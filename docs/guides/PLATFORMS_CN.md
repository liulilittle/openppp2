# 平台说明

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `ppp/app/ApplicationHelp.cpp`、`ApplicationConfig.cpp`、`ApplicationInitialize.cpp`、`ApplicationNetwork.cpp`、`windows/ppp/tap/WintunAdapter.cpp`、`AppConfiguration.cpp`）
>
> **用途：** 各平台运行 OPENPPP2 时的权限、驱动、专用参数和功能差异。
> **读者：** 在具体平台上部署客户端或服务端的用户。
> **上级索引：** [指南](README_CN.md) · **English:** [Platforms](PLATFORMS.md)

实现层面的平台抽象见 [平台集成（架构）](../architecture/PLATFORM_INTEGRATION_CN.md)。

## 1. 功能对照

| 功能 | Linux | Windows | macOS | Android | iOS |
|---|:-:|:-:|:-:|:-:|:-:|
| 服务端 | ✔ | ✔ | ✔ | — | — |
| 服务端 IPv6（`server.ipv6`） | ✔ | — | — | — | — |
| TUN 客户端 | ✔ | ✔ | ✔ | App（VpnService） | App（Network Extension） |
| 代理模式 | ✔ | ✔ | ✔ | App“仅代理模式” | ✔ |
| 自动应用服务端分配的 IPv4 / IPv6 | ✔ | ✔ | ✔ | 系统框架处理 | 系统框架处理 |
| `geo-rules` 生成 | ✔ | ✔ | ✔ | ✔ | — |
| `transport-auth` secret-file | ✔ | — | ✔ | ✔ | ✔ |
| P2P 默认模式（`p2p.mode`） | `direct-preferred` | `relay` | `relay` | `direct-preferred` | `direct-preferred` |

## 2. Linux

- **权限：** TUN 客户端和服务端需要 root 或 `CAP_NET_ADMIN`，并且 `/dev/net/tun` 可用（容器里需额外映射）。代理模式不需要。
- **默认网卡名：** `ppp`（`--tun=<名称>` 修改）。
- **安装包：** x86_64 推荐 `openppp2-linux-amd64-simd.zip`；旧系统用 `-debian10`；`-io-uring` 变体使用 io_uring。其他架构见 [用户手册](../getting-started/USER_MANUAL_CN.md)。
- **专用参数：**

| 参数 | 默认 | 说明 |
|---|---|---|
| `--tun-ssmt=<N>[/mq]` | `0` | 包处理线程数；`/mq` 时每个线程打开一个 TUN 队列，适合高吞吐。 |
| `--tun-protect=yes\|no` | `yes` | 保护隧道自身连接不被路由进隧道。 |
| `--tun-route=yes\|no` | `no` | 路由兼容模式，路由安装异常时可尝试。 |
| `--tun-promisc=yes\|no` | `yes` | 网卡混杂模式。 |
| `--bypass-nic=<网卡>` | 自动 | 直连流量的出口网卡。 |

- 路由文件（`client.routing.ip.routes[].nic`）可以为每个列表指定出口网卡，只在 Linux 生效。
- 服务端 IPv6 只在 Linux 上可用，见 [IPv6](IPV6_CN.md)。
- 作为网关时需要开启 `net.ipv4.ip_forward`，见 [用户手册 · 作为局域网网关](../getting-started/USER_MANUAL_CN.md)。

## 3. Windows

- **权限：** TUN 客户端需要以管理员身份运行。代理模式一般不需要。
- **虚拟网卡驱动：** 程序优先加载 Wintun——依次查找程序目录或系统目录的 `wintun.dll`、`Driver\wintun.dll`、`Driver\<x64|arm64|x86>\wintun.dll`。找不到 Wintun 时使用 TAP-Windows；如果系统里没有可用网卡，会自动用 `Driver\` 目录中的驱动安装一块。**发行包里的 `Driver\` 目录请和 `ppp.exe` 放在一起。**
- **默认网卡名：** `PPP`。
- **TCP 协议栈：** 使用 Wintun 时默认 `native`，使用 TAP-Windows 时默认 `lwip`（`--tcp-stack` 可改）。
- **专用参数：**

| 参数 | 默认 | 说明 |
|---|---|---|
| `--set-http-proxy=yes\|no` | `no` | 把系统 HTTP 代理指向客户端本地 HTTP 代理（需配置 `client.http-proxy.port`；代理模式下不生效）。 |
| `--tun-lease-time-in-seconds=<秒>` | `7200` | 虚拟网卡 DHCP 租期。 |
| `--system-network-reset` | — | 重置 Windows 网络栈后退出。 |
| `--system-network-optimization` | — | 应用网络优化后退出。 |
| `--system-network-preferred-ipv4` / `-ipv6` | — | 设置 IPv4 / IPv6 优先后退出。 |
| `--no-lsp <程序>` | — | 让指定程序绕过 LSP。 |

- `client.paper-airplane.tcp`（默认 `true`）启用“纸飞机” LSP TCP 加速，只在 Windows 生效。
- 服务端可以运行在 Windows 上，但不支持 `server.ipv6`（写了会导致配置加载失败）。
- `transport-auth` 的 secret-file 在 Windows 上无法读取，启用该功能时无法使用 Windows。
- 作为局域网网关可配合 [VGW](https://github.com/liulilittle/vgw-release)。

## 4. macOS

- **权限：** TUN 客户端需要 root（`sudo`）。代理模式不需要。
- **虚拟网卡：** 使用系统 `utun`，默认名 `utun0`。
- **安装包：** Apple 芯片用 `openppp2-darwin-arm64.zip`，Intel 用 `openppp2-darwin-x86_64.zip`。从网络下载的二进制可能需要先解除隔离属性（`xattr -d com.apple.quarantine ./ppp`）。
- **专用参数：** `--tun-ssmt=<N>`（包处理线程数）、`--tun-promisc`。
- 不支持服务端 IPv6；P2P 默认 `relay`，需要直连时设置 `"p2p": { "mode": "direct-preferred" }`。

## 5. Android

- 以 App 形式使用（源码在 `android/`），原生库 `libopenppp2.so` 由发行包 `openppp2-android-<ABI>.zip` 提供，最低 Android 6.0（API 23）。
- 通过系统 VpnService 工作，不需要 root，但首次连接需要用户授权 VPN。
- 路由和 DNS 由系统 VPN 框架设置：TUN 模式捕获 `0.0.0.0/0` 和 `::/0`（防 IPv6 泄漏）并设置隧道 DNS；“仅代理模式”只保留 VPN 接口子网路由，不设置 DNS，也不把本地代理发布为系统代理。
- `client.routing.ip.peer-routes` 只在程序内部生效，不会逐条变成系统路由。
- 订阅只接受 HTTPS 链接（本机回环 HTTP 仅用于开发）。

## 6. iOS

- 以 App + Packet Tunnel 扩展形式使用（源码在 `ios/`），需要 Network Extension 权限。
- TUN 模式：按配置设置包含路由，把直连列表转换为排除路由，并在启用时设置隧道 DNS；代理模式只保留隧道子网路由，不设置 DNS。
- 不运行 `geo-rules` 生成器；对端前缀路由只在程序内部生效。
- 策略 v2 的 `tcp-domain-sniff` 在 iOS TUN 下不可用。

## 7. 退出与恢复

TUN 客户端退出时会删除自己添加的路由、恢复 DNS 设置（Windows 还会刷新 DNS 缓存）并关闭虚拟网卡。请用 `Ctrl+C`、`openppp2 exit` 或服务管理器正常停止；强制结束进程可能留下残余路由，此时重启网络服务或重新运行一次再正常退出即可。

## 相关文档

- [用户手册](../getting-started/USER_MANUAL_CN.md) · [命令行参考](../reference/CLI_REFERENCE_CN.md) · [代理模式](PROXY_MODE_CN.md) · [IPv6](IPV6_CN.md)
- [平台集成（架构）](../architecture/PLATFORM_INTEGRATION_CN.md)
