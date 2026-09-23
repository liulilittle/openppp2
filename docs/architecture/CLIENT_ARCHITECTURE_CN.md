# 客户端架构
> Status: Active
> Type: Architecture
> Last verified: `ppp/app/client/`, client bootstrap, and device sources, 2026-07-22
>
> **用途：**说明原生 client 运行时及其角色边界。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [Client Architecture](CLIENT_ARCHITECTURE.md)

## 范围

本文描述原生 C++ client 运行时。本树也包含 Android、iOS 与 desktop 表面，但它们负责托管、启动或消费原生运行时，不会替代此处的 `VEthernet*` owner 模型。

```text
PppApplication
  -> VEthernetNetworkSwitcher       宿主侧 client 控制器
       -> VEthernetExchanger         会话与隧道动作
            -> ITransmission         主承载或子承载会话
```

`VEthernetNetworkSwitcher` 持有面向设备的虚拟以太网运行时、client 路由与 DNS 策略、本地代理监听器以及活跃 exchanger。`VEthernetExchanger` 持有会话建立和 client 侧链路动作处理。TCP 与代理路径可以创建子 `ITransmission` 连接，不能假定每个 client 流量都只走一个主 transmission。

## 模式选择不是配置捷径

CLI 决定角色：

| 调用方式 | 角色行为 |
|---|---|
| `--mode=client` | client 运行时；正常执行权限和平台预检规则。 |
| `--mode=proxy` | proxy mode 的 client 家族运行时；`Main()` 跳过权限门禁。 |
| `--mode=client` 加 `client.proxy-only: true` | 应用 proxy-only 运行时设置，但权限和 Windows 预检仍是 client 角色。 |

若没有 `--mode=client` 或 `--mode=proxy`，即使存在 `client.proxy-only`，进程仍会选择 server 模式。

`PrepareClientLoopbackEnvironment()` 从 proxy mode 或配置标志推导 `proxy_only_runtime`。在非 Android/非 iOS 目标上，它为该运行时选择 `TapStub`；`TapStub` 会显示为已打开，但有意丢弃输出。Android 向原生代码提供真实 VPN 文件描述符；源码不支持宣称 iOS 具有桌面式 proxy-only 行为。

## 设备与宿主边界

`ITap::Create()` 选择平台适配器：Windows 在 Wintun 可用时使用 Wintun，否则使用 TAP-Windows；Linux 使用 `TapLinux`；macOS 使用 utun；iOS 使用嵌入回调。完整 client 具有平台设备和配置的路由/DNS 行为。native client opener 中 proxy-only 路径更窄：它启动基础运行时与代理监听器，要求至少有一个监听器成功，然后在 native DNS policy 与路由应用之前返回。

监听器已打开不等于隧道会话已连接：代理接入会检查 exchanger 是否处于 established 网络状态。

## 数据包路径边界

不存在所有数据包都必须走“TAP → lwIP → tunnel”的单一路径：

- 设备回调由 `VEthernet::Open()` 安装，并先解析 IPv4 输入；
- 合适的虚拟网络原始 IPv4/IPv6 流量可走直接 NAT 路径；
- TCP 走虚拟协议栈连接路径；
- UDP 与 ICMP 各有解析/分发路径，并在适用时处理 DNS 与 static echo；
- 入站 NAT 或重建的 UDP/TCP 流量最终到达 `VEthernet::Output()`，随后交给选中的 `ITap` 实现。

使用 `TapStub` 时，最后的输出会被有意丢弃。请阅读[数据包生命周期](PACKET_LIFECYCLE_CN.md)了解有边界的流向，而不是把它当成全局数据包图。

## 会话状态与运维状态

`VEthernetExchanger::NetworkState` 是会话输入（`Connecting`、`Established` 或 `Reconnecting`）。`RuntimeLifecycle` 发布面向运维的进程 phase。`OnTick()` 把前者映射到后者，并通过 session、adapter、route、DNS 和 policy readiness 门控 `connected`。

因此 exchanger 已 established 并不总意味着对外 phase 已显示 `connected`。`INFO` 也不是该门控在所有模式下的前置条件；switcher 在策略应用路径后发布 readiness。

## MUX 与 P2P 限制

MUX 不会只因握手位而启用。client 运行时的 MUX 工作需要后续链路层 `MUX`/`MUXON` 交换，并可能打开子承载 transmission。直连 P2P 代码虽存在，但生产 capability gate 为 false，正常生产执行仍是 relay-only。

## 相关页面

- [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)
- [隧道设计](TUNNEL_DESIGN_CN.md)
- [EDSM 状态机](EDSM_STATE_MACHINES_CN.md)
- [传输与受保护会话层](TRANSMISSION_CN.md)
