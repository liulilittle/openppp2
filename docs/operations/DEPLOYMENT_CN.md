# 部署模型
> Status: Active
> Type: Operations
> Last verified: 63fc030

> **用途：**说明本主题的当前行为、配置或实现边界。
> **适用对象：**OPENPPP2 用户、运维人员与开发者。
> **当前状态：**当前有效。
> **最后核对依据：**当前仓库结构、实现路径与文档链接，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md) · **English：**[Deployment Model](DEPLOYMENT.md)


[English Version](DEPLOYMENT.md)

## 范围

本文解释 OPENPPP2 按源码结构如何部署，涵盖部署表面、启动顺序、平台前置条件和运行预期。

---

## 核心事实

- C++ 运行时是一个单一可执行文件：`ppp`。
- 它可以运行在 `client` 模式或 `server` 模式。
- 服务端可以通过 `server.backend` 接入可选的 Go backend。
- 始终需要管理员/root 权限。

---

## 部署分成两层

```mermaid
flowchart TD
    A[OPENPPP2 部署] --> B[Node 层]
    A --> C[Host 层]
    B --> D[角色：client 或 server]
    B --> E[持久配置 JSON]
    B --> F[可选 Go backend]
    B --> G[服务意图]
    C --> H[虚拟网卡]
    C --> I[路由表]
    C --> J[DNS 行为]
    C --> K[权限]
    C --> L[本地代理表面]
```

| 层 | 含义 |
|----|------|
| Node 层 | 持久 JSON、角色、backend 和服务意图 |
| Host 层 | 适配器、路由、DNS、权限、本地代理表面 |

源码把这两层当作相关但不完全相同的问题。

---

## 部署表面

OPENPPP2 的部署可以看成四个表面：

```mermaid
flowchart TD
    A[部署] --> B[Host 表面]
    A --> C[Listener 表面]
    A --> D[Data plane 表面]
    A --> E[Management 表面]
    B --> F[权限 / 适配器 / 路由 / DNS]
    C --> G[TCP / UDP / WS / WSS]
    D --> H[会话 / 映射 / IPv6]
    E --> I[可选 Go backend]
```

| 表面 | 组件 | 备注 |
|------|------|------|
| Host | 权限、虚拟网卡、OS 路由、DNS 设置 | 运行时打开前必须就绪 |
| Listener | TCP、WebSocket、TLS WebSocket、static UDP | 在 `tcp.listen/websocket.listen/udp.listen` 中配置 |
| Data plane | 会话、NAT 映射、IPv6 transit、static echo | 每会话运行时状态 |
| Management | 通过 WebSocket 接入 Go backend | 可选；扩展策略，不接触数据包字节 |

---

## 硬性要求

- 需要管理员/root 权限。
- 需要真实的配置文件。

`LoadConfiguration(...)` 按以下顺序搜索：
1. 显式的 `-c` / `--config` CLI 参数。
2. 工作目录下的 `./config.json`。
3. 工作目录下的 `./appsettings.json`。

源文件：`ppp/app/PppApplication.cpp`

---

## 客户端部署

客户端部署会创建虚拟网卡，准备 route / DNS / bypass 输入，打开 `VEthernetNetworkSwitcher`，然后建立远程 exchanger 会话。

### 客户端启动顺序

```mermaid
flowchart TD
    A[启动 ppp --mode=client] --> B[获取权限]
    B --> C[载入配置]
    C --> D[准备 NIC / gateway / TAP]
    D --> E[打开 VEthernetNetworkSwitcher]
    E --> F[连接 VEthernetExchanger 到服务端]
    F --> G[应用路由和 DNS]
    G --> H[应用 bypass IP 列表]
    H --> I[进入转发状态]
    I --> J[Tick loop：保活、VIRR、vBGP 刷新]
```

### 客户端部署检查清单

| 步骤 | 要求 |
|------|------|
| 1 | 权限：Windows 上需要管理员，Linux/macOS/Android 上需要 root |
| 2 | 已知路径上存在配置文件 |
| 3 | `client.guid` 设置为有效 UUID |
| 4 | `client.server` 指向可访问的服务端地址 |
| 5 | 宿主机支持虚拟网卡 |
| 6 | 具备 DNS 和路由修改权限 |
| 7 | 可选：`client.routing.ip.bypass` IP-list 文件或 `--bypass` CLI 文件可访问 |
| 8 | 可选：`client.routing.dns.rules` 来源或 `--dns-rules` CLI 文件可访问 |

### 客户端平台说明

| 平台 | 网卡类型 | 路由方式 | DNS 方式 |
|------|---------|---------|---------|
| Windows | TAP-Windows / WinTUN | IPv4 路由 API | 系统 DNS 覆写 |
| Linux | TUN/TAP | `ip route` / `rtnetlink` | `/etc/resolv.conf` |
| macOS | utun | `route` 命令 | `scutil` |
| Android | VPNService | VPNService 路由 | VPNService DNS |
| iOS | Packet Tunnel（Network Extension） | `NEIPv4Settings` included routes | `NEDNSSettings`（proxy-only 时不配置） |

---

## 服务端部署

服务端部署会打开监听器、防火墙、namespace cache、datagram socket、可选 managed backend，以及通过 `VirtualEthernetSwitcher` 提供的可选 IPv6 transit plumbing。

### 服务端启动顺序

```mermaid
flowchart TD
    A[启动 ppp] --> B[获取权限]
    B --> C[载入配置]
    C --> D[打开防火墙]
    D --> E[打开 namespace cache]
    E --> F[打开 datagram socket]
    F --> G{server.backend？}
    G -->|是| H[连接 Go backend]
    G -->|否| I[跳过]
    H --> J{server.ipv6？}
    I --> J
    J -->|是| K[打开 IPv6 transit plane]
    J -->|否| L[跳过]
    K --> M[打开 TCP 监听器]
    L --> M
    M --> N[打开 WebSocket 监听器]
    N --> O{static echo？}
    O -->|是| P[打开 static echo 会话]
    O -->|否| Q[服务端就绪]
    P --> Q
    Q --> R[接收连接]
    R --> S[Tick loop：会话维护、backend 刷新]
```

### 服务端部署检查清单

| 步骤 | 要求 |
|------|------|
| 1 | 权限：Linux 上 root，Windows 上管理员 |
| 2 | 配置文件存在 |
| 3 | 至少启用一个监听器（`tcp.listen.port` 或 `websocket.listen.ws`） |
| 4 | 监听端口设置为可用端口 |
| 5 | 如果设置了 `server.firewall`，防火墙配置文件存在 |
| 6 | 如果设置了 `server.backend`，Go backend 可达 |
| 7 | 如果启用了 `server.ipv6`，NIC 支持 IPv6 |

### 服务端监听器类型

| 监听器 | 配置键 | 协议 | TLS |
|--------|--------|------|-----|
| TCP | `tcp.listen.port` | 原始 TCP | 否 |
| WebSocket | `websocket.listen.ws` | HTTP WebSocket | 否 |
| TLS WebSocket | `websocket.listen.wss` | HTTPS WebSocket | 是 |
| Static UDP | `udp.listen.port` | 原始 UDP | 否 |

---

## Go Backend

Go backend 是可选的，用于 managed deployment，而不是核心 data plane。

```mermaid
sequenceDiagram
    participant Server as C++ 服务端
    participant Backend as Go Backend
    participant Client as 客户端

    Client->>Server: 携带凭证连接
    Server->>Backend: Authenticate(user, token)
    Backend-->>Server: 认证结果 + 配额
    Server-->>Client: 允许或拒绝
    loop 流量上报
        Server->>Backend: ReportTraffic(session_id, in, out)
        Backend-->>Server: 配额状态
    end
    Server->>Backend: SessionEnd(session_id)
```

核心特性：
- 通信使用 WebSocket（`ws://` 或 `wss://`）。
- backend 不可达时，服务端回退到本地缓存策略。
- backend 扩展的是策略和管理，永远不接触数据包字节。

源文件：`ppp/app/server/VirtualEthernetManagedServer.h`

---

## 各平台权限要求

| 平台 | 要求 | 备注 |
|------|------|------|
| Linux | `root` 或 `CAP_NET_ADMIN` | TUN/TAP 创建需要权限 |
| Windows | 管理员 | TAP 驱动和路由修改 |
| macOS | `root` | utun 创建 |
| Android | VPNService 权限 | 在 `AndroidManifest.xml` 中声明 |

---

## 网络前置条件

| 要求 | 客户端 | 服务端 |
|------|--------|--------|
| 虚拟网卡支持 | 必须 | 不需要 |
| 开放 TCP 端口 | 不需要 | 必须 |
| DNS 修改权限 | 必须 | 不需要 |
| 路由修改权限 | 必须 | 不需要 |
| IPv6 capable NIC | 如果启用 IPv6 | 如果启用 `server.ipv6` |

---

## 启动后的运维预期

部署成功不代表 host state 不再变化。实际运行中还会持续看到：

```mermaid
stateDiagram-v2
    [*] --> 已部署
    已部署 --> 路由已激活 : client 模式
    已部署 --> 监听器已激活 : server 模式
    路由已激活 --> Bypass路由 : IP-list 已应用
    路由已激活 --> 默认路由已重定向 : 全隧道模式
    路由已激活 --> 默认路由已保护 : 分流模式
    监听器已激活 --> 接受会话中 : open 完成
    接受会话中 --> 管理Backend : 如果启用了 backend
    接受会话中 --> IPv6Transit : 如果启用了 IPv6
    路由已激活 --> VIRR刷新 : tick 驱动
    VIRR刷新 --> 路由已激活 : 已刷新
```

持续的宿主侧预期：

| 预期 | 说明 |
|------|------|
| 默认路由受管理 | 客户端可能重定向或保护默认路由 |
| DNS 服务器稳定 | DNS 服务器路由必须持久存在 |
| 监听器保持绑定 | 服务端监听器必须持续绑定 |
| Backend 保持可达 | Go backend 连接必须维持 |
| IPv6 transit 活跃 | IPv6 transit plane 必须保持运行 |

---

## 部署拓扑示例

### 简单服务端 + 客户端

```mermaid
flowchart LR
    A[客户端宿主] -->|TCP/WS| B[ppp 服务端]
    B -->|互联网| C[目标]
```

### 带 Go Backend 的服务端

```mermaid
flowchart LR
    A[客户端宿主] -->|TCP/WS| B[ppp 服务端]
    B -->|WebSocket| C[Go Backend]
    B -->|互联网| D[目标]
    C --> E[数据库 / 认证]
```

### 多监听器服务端

```mermaid
flowchart TD
    A[TCP 客户端] --> B[ppp 服务端]
    C[WebSocket 客户端] --> B
    D[TLS WebSocket 客户端] --> B
    B --> E[会话路由]
    E --> F[互联网]
```

---

## 部署失败类型

| 类型 | 症状 | 可能原因 |
|------|------|---------|
| 权限失败 | 进程立即退出 | 未以管理员/root 运行 |
| 找不到配置 | "configuration not found" 错误 | 路径错误或文件缺失 |
| 网卡打开失败 | 虚拟 NIC 未创建 | 驱动缺失或权限不足 |
| 监听器绑定失败 | 端口被占用或权限不足 | 端口冲突或权限问题 |
| 路由添加失败 | 流量未经隧道 | 路由修改不被允许 |
| Backend 不可达 | 会话被拒绝或应用缓存策略 | Backend 未启动或 URL 错误 |

---

## 配置文件参考

最简服务端配置：

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

最简客户端配置：

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

## 错误码参考

部署相关的 `ppp::diagnostics::ErrorCode` 值：

| ErrorCode | 说明 |
|-----------|------|
| `AppPrivilegeRequired` | 进程需要管理员/root 权限 |
| `ConfigFileNotFound` | 任何搜索路径都找不到配置文件 |
| `ConfigLoadFailed` | 找到配置文件但解析失败 |
| `NetworkInterfaceOpenFailed` | 虚拟网卡无法打开 |
| `SocketBindFailed` | TCP 或 WebSocket 监听器绑定失败 |
| `FirewallCreateFailed` | 防火墙子系统初始化失败 |
| `VEthernetManagedConnectUrlEmpty` | Go backend WebSocket 连接失败 |
| `IPv6TransitTapOpenFailed` | IPv6 transit TAP 打开失败 |
| `AppAlreadyRunning` | 已有另一个 ppp 实例在运行 |

---

## 相关文档

- [`CONFIGURATION_CN.md`](../reference/CONFIGURATION_CN.md)
- [`CLI_REFERENCE_CN.md`](../reference/CLI_REFERENCE_CN.md)
- [`PLATFORMS_CN.md`](../guides/PLATFORMS_CN.md)
- [`ROUTING_AND_DNS_CN.md`](../guides/ROUTING_AND_DNS_CN.md)
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
- [`MANAGEMENT_BACKEND_CN.md`](../guides/MANAGEMENT_BACKEND_CN.md)
- [`SERVER_ARCHITECTURE_CN.md`](../architecture/SERVER_ARCHITECTURE_CN.md)
- [`CLIENT_ARCHITECTURE_CN.md`](../architecture/CLIENT_ARCHITECTURE_CN.md)

---

## 主结论

OPENPPP2 的部署不是"运行一个二进制"这么简单。它是一个分阶段的 host + node setup，必须让可执行文件、权限、网卡、路由、监听器和可选 backend 一起对齐。只有当所有四个表面——host、listener、data plane 和 management——都正确配置并运行时，部署才算健康。
