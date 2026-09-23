# ADR 0001：运行时快照是 UI 状态权威

> **用途：**记录运行时到 UI 的持久权威边界决策。
> **适用对象：**运行时、平台和 UI 维护者。
> **当前状态：**当前架构决策。
> **最后核对依据：**最新主线实现依据，2026-07-22。
> **上一层索引：**[架构决策记录](README_CN.md) · **English：**[ADR 0001](0001-runtime-ui-contract.md)

> Status: Accepted
> Type: ADR
> Last verified: 8c8a888

## 决策

`PppApplication` 拥有一个 `RuntimeLifecycle`，并发布不可变、带版本的 `RuntimeSnapshot` 值。C++ 桌面 TUI、Android UI 和 iOS UI 渲染这些快照并发送命令；它们不从 exchanger 枚举、VPN 服务回调、日志或乐观的 widget 状态变更推导生命周期状态。

独立的进程管理型 `desktop/client` 当前从 telemetry/进程事件和退出状态推导本地状态。它尚未消费 `RuntimeSnapshot`，不能被当作本决策已覆盖所有桌面表面的证据。

v1 阶段为 `idle`、`starting`、`preparing_host`、`connecting`、`handshaking`、`applying_policy`、`connected`、`reconnecting`、`stopping`、`failed`，以及仅供 UI 使用的回退值 `unknown`。

## 就绪规则

只有当会话、适配器、路由、DNS 和客户端打开策略都就绪时，运行时才能发布 `connected`。可选 INFO 不是就绪要求；当前客户端策略位在 `Open()` 之后会话建立时设置。客户端适配器必须已打开，而不只是已分配。路由和 DNS 只有在成功应用后，或当前模式明确不要求它们时，才能标记为就绪。服务端就绪状态来自活动的 accept loop，而非固定标志。

## 排序与兼容性

- `schema_version` 是必需字段；消费者拒绝不支持的版本。
- `generation` 防止旧会话事件替换当前状态。
- `monotonic_ms` 在同一 generation 内排序事件。
- 未知的可选字段为向前兼容而忽略。
- 监听器接收副本，并在发布者锁外执行。
- 既有隧道线格式和配置保持不变。

## UI 命令行为

| 阶段 | 主操作 | 配置 |
|---|---|---|
| Idle | 启动 | 可编辑 |
| Starting 到 ApplyingPolicy | 取消 | 锁定 |
| Connected、Reconnecting | 停止 | 锁定 |
| Stopping | 禁用 | 锁定 |
| Failed | 重试 | 可编辑 |
| Unknown | 强制停止 / 诊断 | 锁定 |

启动和停止命令等待匹配的运行时快照。UI 超时可以报告进度缓慢，但不能自行发布 `idle`。排序元数据有效但负载无效时显示为 `unknown`；无法排序的负载报告错误，且不得改写较新的状态。

## 后果

运行时契约为当前消费者提供一个稳定边界：C++ 桌面 TUI、Android UI 和 iOS UI。传输状态仍可用于数据平面决策和诊断，但不能成为第二个生命周期权威。进程管理型桌面 Client 要么需要明确的独立契约，要么必须迁移到 `RuntimeSnapshot` 后才能声称采用此边界。

参见[运行时 UI 契约](../reference/UI_RUNTIME_CONTRACT.md)及其[中文译文](../reference/UI_RUNTIME_CONTRACT_CN.md)。
