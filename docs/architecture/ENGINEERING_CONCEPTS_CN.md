# 工程概念
> Status: Active
> Type: Architecture vocabulary
> Last verified: current application, diagnostics, and executor sources, 2026-07-22
>
> **用途：**建立架构页面使用的、已按源码核对的简明术语。
> **适用对象：**贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Engineering Concepts](ENGINEERING_CONCEPTS.md)

## 所有权术语

| 术语 | 当前 owner / 边界 |
|---|---|
| 进程 application | `PppApplication`：配置、已选运行时、tick 调度和 `RuntimeLifecycle` |
| Client switcher | `VEthernetNetworkSwitcher`：宿主侧虚拟以太网、路由、DNS 策略、本地代理 |
| Client exchanger | `VEthernetExchanger`：活跃 client 会话和 client 侧隧道动作 |
| Server switcher | `VirtualEthernetSwitcher`：监听器、按会话注册、共享 server 设施 |
| Server exchanger | `VirtualEthernetExchanger`：一个主 client 会话及会话级转发状态 |
| Transmission | `ITransmission`：面向承载的握手和帧保护/变换 |
| 链路层 | `VirtualEthernetLinklayer`：opcode 解析和 `Do*`/`On*` 动作词汇 |

`PppApplication` 不会直接创建每一个 `ITransmission`；相应的 carrier 对象由 connect 和 accept 路径创建。

## 状态术语

- **Runtime phase** 是 `RuntimeSnapshot` 中面向进程的展示态，owner 是 `RuntimeLifecycle`。
- **Network state** 是 client exchanger 的会话状态，也是运行时展示的输入。
- **Readiness** 是可以让请求的 connected 保持为 `applying_policy` 的门控。
- **Last error** 是诊断数据，不是生命周期权威，不能替代 runtime phase。

## 异步术语

- **Default context**、**worker context** 和 **scheduler context** 是 `Executors` 提供的设施；不能把它们混写成所有对象的所有权承诺。
- **Strand** 只会为使用它的路径串行化工作。
- **`YieldContext`** 是原生有栈协程封装；VMUX 还可以使用 Boost.Asio 的 spawn 设施。
- **`Awaitable`** 会阻塞调用线程直到完成；它不是异步结果类型，也不是 cancellation-safe 原语。

不要仅仅为模仿旧调用点而围绕 `nullof<YieldContext>()` 新增代码。实现使用空地址引用约定，本文不把它当作可移植性保证。

## Diagnostics 与 telemetry 术语

`ErrorCode` 值来自 `ppp/diagnostics/ErrorCodes.def`。`SetLastErrorCode()` 会更新线程本地与进程级诊断状态，并在设置者线程上同步派发已注册 handler。注册的设计意图是初始化期使用；它不是运行时生命周期 API。

Telemetry 是独立的、运行时可选的机制。它在本树中通过始终编译的 facade 记录事件；这不能证明零二进制开销、lock-free 操作或稳定的 OpenTelemetry SDK 表面。见[可观测性](OTEL_DESIGN_CN.md)。

## 命名与配置

代码约定区分原生 client 类（`VEthernet*`）与 server 类（`VirtualEthernet*`）。配置序列化常用 kebab-case key，例如 `proxy-only` 与 `backend-key`；C++ 成员使用仓库风格标识符，例如 `proxy_only` 与 `backend_key`。

对外支持的 key 与协议字段以[参考](../reference/README_CN.md)为准。架构页面说明 owner 和边界，不替代 schema。
