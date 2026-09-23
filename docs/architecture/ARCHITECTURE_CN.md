# 系统架构
> Status: Active
> Type: Architecture
> Last verified: native entry, runtime, transport, and platform source paths, 2026-07-22
>
> **用途：**给出当前 `ppp` 运行时的、已按源码核对的总览。
> **适用对象：**贡献者与运维。
> **当前范围：**原生可执行程序与本树内的配套表面；本文不是稳定 SDK 契约。
> **上一层索引：**[架构](README_CN.md) · **English:** [System Architecture](ARCHITECTURE.md)

## 运行时概览

根 CMake 目标构建原生 `ppp` 可执行程序，并链接树内的 `openppp2_lib` 静态库。可执行入口刻意保持很薄：

```text
main.cpp
  -> ppp::facade::RunApplication(argc, argv)
  -> PppApplication::GetInstance().Run(argc, argv)
  -> 参数与配置准备
  -> Executors::Run(...)
  -> PppApplication::Main(...)
  -> client 或 server bootstrap
```

`main.cpp` 不负责网络、配置或关闭。`PppApplication` 持有进程级配置、运行时对象、周期维护以及 `RuntimeLifecycle` 发布。

## 主要实现区域

| 区域 | 树内路径 | 当前职责 |
|---|---|---|
| 原生运行时 | `ppp/` | 应用生命周期、client/server 角色、协议、传输、DNS、路由、诊断 |
| 共享底层代码 | `common/` | 原生目标使用的嵌入式与共享支持代码 |
| 平台适配 | `windows/`、`linux/`、`darwin/` | 由构建目标选择的设备、路由和宿主集成 |
| Android / iOS 集成 | `android/`、`ios/` | 嵌入或桥接原生运行时的平台宿主 |
| 桌面客户端 | `desktop/client/` | 启动原生进程并消费统计输出的独立桌面 UI |
| Go 服务 | `go/` | 可选的管理相关服务；非托管原生隧道并不依赖它 |

它们都在本树中，但不是 C++ 隧道运行时的可互换 owner。规范的会话 owner 仍是原生的 `VEthernet*` 与 `VirtualEthernet*` 类。

## 角色选择与 owner

命令行模式选择应用角色；不传 `--mode` 时解析为 `server`。

| 角色 | 选择方式 | 主要运行时 owner |
|---|---|---|
| Server | `--mode=server` 或不传 mode | `VirtualEthernetSwitcher` |
| Client | `--mode=client` | `VEthernetNetworkSwitcher` |
| Proxy | `--mode=proxy` | 代理形态的 client 运行时 |

`client.proxy-only` 在模式解析后应用代理默认值；它**不会**自行选择 client 或 proxy 模式。`--mode=proxy` 与设置 `client.proxy-only: true` 的 client 角色在权限和 Windows 预检上也不同。

client switcher 持有宿主侧工作，例如隧道设备、路由、DNS 策略、本地代理监听器与活跃 exchanger。server switcher 持有监听器和按会话创建的 `VirtualEthernetExchanger`。当相关功能被配置时，server 还可能创建 Linux IPv6 transit 设备，因此“server 没有 TAP/TUN”的说法过于绝对。

## 运行时状态与展示

`RuntimeLifecycle` 发布可复制的 `RuntimeSnapshot`。`OnTick()` 采样 client 或 server 状态，更新 readiness、流量、MUX 和 P2P 展示，然后更新终端 UI 与可选统计输出。

可观察到的正常进展包括 `starting`、`preparing_host`、`connecting`、`handshaking`、`applying_policy`、`connected`、`reconnecting`、`stopping`，以及在清理报告完成后得到的 `idle` 或 `failed`。这是展示与协调模型，不是强制的状态迁移表：`RuntimeLifecycle::Transition()` 校验 generation/stop 状态，并通过 readiness 门控 `connected`，但没有编码完整的合法迁移矩阵。

对 client，`connected` 由 session、adapter、route、DNS 和 policy readiness 共同门控。对 server，进程级信号取决于监听运行时是否在运行；它不是全部客户端会话或可选管理后端连接的汇总。

## 数据面分层

```text
TCP / WS / WSS 承载
  -> ITransmission（握手与帧保护/变换）
  -> VirtualEthernetLinklayer（opcode 派发）
  -> client 或按会话创建的 server exchanger
  -> 宿主设备 / 虚拟协议栈 / 中继 / 转发路径
```

`ITransmission` 位于隧道动作层之下。共享的 `VirtualEthernetLinklayer` 从每个已解码 payload 中解析动作 opcode，具体的 client/server exchanger 实现两侧处理。活跃承载、握手和帧行为见[传输与受保护会话层](TRANSMISSION_CN.md)；opcode 细节应以参考文档为准，而不是本文总览。

## 重要限制

- 正常运行时的直连 P2P 数据面仍 fail-closed：`ProductionAuthenticatedControlV1Ready` 为 `false`。源码包含 P2P 工作，但不能将其写成生产直连路径。
- 桌面 proxy-only 运行时可能使用 `TapStub`，其输出会被有意丢弃。Android/iOS 的平台设备路径不同，不能把桌面 stub 行为推广到它们。
- 本树含有可选 UI 与管理表面，但它们的存在并不使 C++ 运行时成为稳定的跨语言 SDK 或远程控制 API。
- 支持的配置与接口应以[参考](../reference/README_CN.md)为准；历史理由应查看 [ADR](../adr/README.md) 或[归档](../archive/README.md)。

## 下一步

- [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)
- [客户端架构](CLIENT_ARCHITECTURE_CN.md) 与[服务端架构](SERVER_ARCHITECTURE_CN.md)
- [隧道设计](TUNNEL_DESIGN_CN.md) 与[数据包生命周期](PACKET_LIFECYCLE_CN.md)
- [EDSM 状态机](EDSM_STATE_MACHINES_CN.md) 与 [TUI 设计](TUI_DESIGN_CN.md)
