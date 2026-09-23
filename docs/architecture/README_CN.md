# 架构
> Status: Active
> Type: Documentation index
> Last verified: source paths cited by the linked pages, 2026-07-22
>
> **用途：**导航原生 `ppp` 运行时的、已按源码核对的架构文档。
> **适用对象：**贡献者、运维与评审者。
> **当前文档：**本索引中的页面均描述当前仓库源码树，除非页面明确标注为其他状态。
> **上一层索引：**[文档](../README_CN.md) · **English:** [Architecture](README.md)

先阅读[系统架构](ARCHITECTURE_CN.md)了解进程和组件全貌，再按问题进入对应页面：

| 问题 | 权威页面 |
|---|---|
| 进程如何启动、运行、停止或重启？ | [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md) |
| client 或 server 会话由谁持有？ | [客户端架构](CLIENT_ARCHITECTURE_CN.md) · [服务端架构](SERVER_ARCHITECTURE_CN.md) |
| 承载、成帧和握手如何衔接？ | [传输与受保护会话层](TRANSMISSION_CN.md) · [握手序列](HANDSHAKE_SEQUENCE_CN.md) |
| 隧道动作和数据包如何流经运行时？ | [隧道设计](TUNNEL_DESIGN_CN.md) · [数据包生命周期](PACKET_LIFECYCLE_CN.md) |
| 面向运维的状态和终端 UI 如何工作？ | [EDSM 状态机](EDSM_STATE_MACHINES_CN.md) · [TUI 设计](TUI_DESIGN_CN.md) |
| 执行器、DNS、telemetry 或 Linux 队列如何工作？ | [并发模型](CONCURRENCY_MODEL_CN.md) · [DNS 模块设计](DNS_MODULE_DESIGN_CN.md) · [可观测性](OTEL_DESIGN_CN.md) · [Linux 多队列说明](MULTIQUEUE_TUN_MODEL_CN.md) |

## 当前运行时地图

- [系统架构](ARCHITECTURE_CN.md) · [English](ARCHITECTURE.md)
- [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md) · [English](STARTUP_AND_LIFECYCLE.md)
- [客户端架构](CLIENT_ARCHITECTURE_CN.md) · [English](CLIENT_ARCHITECTURE.md)
- [服务端架构](SERVER_ARCHITECTURE_CN.md) · [English](SERVER_ARCHITECTURE.md)
- [传输与受保护会话层](TRANSMISSION_CN.md) · [English](TRANSMISSION.md)
- [隧道设计](TUNNEL_DESIGN_CN.md) · [English](TUNNEL_DESIGN.md)
- [数据包生命周期](PACKET_LIFECYCLE_CN.md) · [English](PACKET_LIFECYCLE.md)
- [握手序列](HANDSHAKE_SEQUENCE_CN.md) · [English](HANDSHAKE_SEQUENCE.md)
- [EDSM 状态机](EDSM_STATE_MACHINES_CN.md) · [English](EDSM_STATE_MACHINES.md)
- [并发模型](CONCURRENCY_MODEL_CN.md) · [English](CONCURRENCY_MODEL.md)
- [TUI 设计](TUI_DESIGN_CN.md) · [English](TUI_DESIGN.md)
- [DNS 模块设计](DNS_MODULE_DESIGN_CN.md) · [English](DNS_MODULE_DESIGN.md)
- [可观测性](OTEL_DESIGN_CN.md) · [English](OTEL_DESIGN.md)
- [工程概念](ENGINEERING_CONCEPTS_CN.md) · [English](ENGINEERING_CONCEPTS.md)

## 实验性或设计边界材料

[Linux 单虚拟网卡多队列模型](MULTIQUEUE_TUN_MODEL_CN.md)记录当前 Linux 实现与建议的演进方向。它**不是**已经完成的队列对象架构，也不构成吞吐量保证；将它用于运维判断前请先阅读其状态块。

公开配置和协议字段应以[参考](../reference/README_CN.md)下的页面为准。决策与旧版设计依据请查看 [ADR](../adr/README.md)、[设计](../design/README.md) 和[归档](../archive/README.md)；它们提供证据与背景，不会自动代表当前行为。
