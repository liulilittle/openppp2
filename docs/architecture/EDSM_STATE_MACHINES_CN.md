# EDSM 状态机
> Status: Active
> Type: Architecture
> Last verified: runtime lifecycle, client exchanger, and server switcher sources, 2026-07-22
>
> **用途：**区分运维可见的进程状态、会话状态与 server 所有权状态。
> **适用对象：**排查状态展示的贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [EDSM State Machines](EDSM_STATE_MACHINES.md)

## 不要合并这些层次

当前代码有多种相关但不同的状态面：

| 状态面 | Owner | 含义 |
|---|---|---|
| `RuntimeSnapshot` 中的 `RuntimePhase` | `RuntimeLifecycle` | 面向进程/运维的生命周期展示 |
| `VEthernetExchanger::NetworkState` | Client exchanger | client 隧道会话状态 |
| `RuntimeReadiness` | client switcher / server helper | 在“请求 connected”和“对外发布 connected”之间门控 |
| `VirtualEthernetExchanger` 实例 | server switcher | 每个 client 一个的 server 会话所有权，不是共享状态枚举 |

将它们合并成一个状态机，会丢失关键差异。

## 面向进程的运行时 phase

`RuntimeLifecycle` 发布的 snapshot phase 包括 `idle`、`starting`、`preparing_host`、`connecting`、`handshaking`、`applying_policy`、`connected`、`reconnecting`、`stopping` 和 `failed`。

每次 `Begin()` 都创建新的 generation，旧 generation 或正在 stopping 的 generation 的更新会被拒绝，时间戳保持单调递增，并通过 `RuntimeSnapshotPublisher` 发布 snapshot 副本。listener 在内部 mutex 外被调用。

`Transition()` **没有**定义完整的合法迁移表。本文的图和顺序是观察到的 application 流，不是 lifecycle 类强制执行的协议语法。

## Client 会话输入与 readiness

client exchanger 有三种网络状态：`Connecting`、`Established` 和 `Reconnecting`。`OnTick()` 中的映射为：

```text
没有 exchanger        -> connecting
正在 reconnecting     -> reconnecting
已 established        -> 更新 readiness，然后请求 connected
其他 exchanger 状态   -> handshaking
```

请求 `connected` 时，`RuntimeLifecycle` 使用五项 readiness 门控：session、adapter、route、DNS 和 policy。因此隧道已经 established 时，对外仍可能显示 `applying_policy`，直到 client 宿主策略完成。

当前 client readiness 路径不把 `INFO` 作为所有模式的必需前置条件。它在 switcher 的 open/policy 路径之后组装，而不是要求每种模式都具有 managed-session 信息。

## Server 会话所有权与 readiness

server 持有一个 `VirtualEthernetSwitcher`，并创建按 client 拆分的 `VirtualEthernetExchanger`。这是所有权拓扑，不是 client `NetworkState` 状态机。

进程层面，`OnTick()` 用 `server_->IsRunning()` 构建 server readiness 并请求 `connected`。这个信号描述活跃监听运行时；它不是全部 client、可选 management bridge 或 Linux IPv6 transit 状态的健康汇总。

## Stop 展示

`Dispose()` 对活跃 generation 调用 `TryBeginStop()`，停止可选 UI，并异步拆除 client/server 对象。清理完成时调用 `CompleteStop()` 发布 `idle` 或 `failed`。

该路径由 `RuntimeLifecycle` 协调，但不能保证所有启动失败或 executor 退出都发布最终终态 snapshot。见[启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)。

## Consumer

`OnTick()` 读取最新 snapshot，并用它为原生 TUI 构造 phase/MUX/P2P 状态行。总的控制台状态还含有单独采样的流量和链路质量文本，因此渲染行不是 `RuntimePhase` 的一对一原始展示。

需要初始 snapshot 的 consumer 应调用 snapshot getter；订阅不会在订阅时重放最新 snapshot。
