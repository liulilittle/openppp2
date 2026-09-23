# 服务端架构
> Status: Active
> Type: Architecture
> Last verified: `ppp/app/server/` and server bootstrap sources, 2026-07-22
>
> **用途：**说明 server bootstrap、监听器角色、会话所有权和 managed backend 边界。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [Server Architecture](SERVER_ARCHITECTURE.md)

## Owner 模型

```text
PppApplication
  -> VirtualEthernetSwitcher
       -> acceptor 与共享 server 状态
       -> VirtualEthernetExchanger（每个 client 一个主会话处理器）
            -> 主 ITransmission 与会话级转发状态
```

`PrepareServerLoopbackEnvironment()` 准备 server IPv6 宿主状态，创建 `VirtualEthernetSwitcher`，指定首选网卡，再调用 `Open()` 和 `Run()`。bootstrap 失败时会收尾宿主准备并 dispose 部分创建的 switcher。

`VirtualEthernetSwitcher` 持有监听器、接入/注册表、全局策略和跨会话设施。`VirtualEthernetExchanger` 处理一个主 client 会话及其 NAT、中继、ICMP、FRP、VMUX 和 static-echo 相关工作。非 MUX 的已接入子承载可以附着到已有 exchanger，而不是创建另一个主 exchanger。

## 监听器模型

当前 TCP 家族 acceptor 使用以下配置字段：

| 类别 | 配置 | 承载/结果 |
|---|---|---|
| 原始 TCP | `tcp.listen.port` | `ITcpipTransmission` |
| WebSocket | `websocket.listen.ws` | `IWebsocketTransmission` |
| TLS WebSocket | `websocket.listen.wss` | `ISslWebsocketTransmission` |
| CDN 路径 | `cdn[0]`、`cdn[1]` | SNI-proxy 处理，不是普通承载建立 |

配置值 `0` 会禁用这些 acceptor。bind 失败后 binder 可以重试使用系统选择的端口，因此运行中 listener 应以观察到的本地 endpoint 为准，而不是只看请求配置。

`udp.listen.port` 不同：值为正时它打开 static-echo UDP socket。它不是通用 UDP 隧道会话监听器；会话需要先请求 static-echo allocation 才会使用该设施。

`Run()` 会为可用的 TCP 家族 acceptor 启动 accept loop，且至少一个 loop 成功才将 switcher 标为 running。server 面向进程的 runtime readiness 因此代表活跃监听运行时，而不是每个已连接 client 的数量或健康度。

## Managed backend 边界

只有 `server.backend` 非空**且** `server.node >= 1` 时，C++ 才尝试 managed mode。不存在 `server.managed` 配置字段。

bridge 异步连接并重试失败连接。server 可以在该链接可用前启动监听器，但已配置 backend 仍是新会话门禁：managed 主会话需要 bridge 授权与有效的 `VirtualEthernetInformation` 回复。

原生控制通道是内部的、长度前缀 JSON 协议。当前实现的命令只有 ECHO (1000)、CONNECT (1001)、AUTHENTICATION (1002) 与 TRAFFIC (1003)。当前实现把 `server.backend-key` 作为共享字符串发送和比较，不能把它描述成 HMAC 签名。流量由 bridge 按自身周期排队/刷出，不会在每个 exchanger tick 上同步发送。

该 bridge 不是 C++ 进程的通用远程管理协议。它没有已文档化的版本/能力协商，应继续作为内部集成边界对待。

## 平台与 P2P 限制

server mode 通常没有 client 式宿主 tunnel 运行时，但 Linux 在配置后可以创建 IPv6 transit TAP 路径。直连 P2P 仍受共享 production capability gate 的 fail-closed 限制。两者都不能写成普遍适用的 server 数据面行为。

## 相关页面

- [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)
- [传输与受保护会话层](TRANSMISSION_CN.md)
- [隧道设计](TUNNEL_DESIGN_CN.md)
- [项目接口地图](../reference/PROJECT_INTERFACE_MAP_CN.md)
