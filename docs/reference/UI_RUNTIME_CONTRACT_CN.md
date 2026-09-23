# UI Runtime 契约

> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer link: [English](UI_RUNTIME_CONTRACT.md)
> Related: [诊断错误系统](DIAGNOSTICS_ERROR_SYSTEM_CN.md) · [VMUX 验证](VMUX_VALIDATION_CN.md)

本文定义 `RuntimeSnapshot` 消费者使用的版本 1 边界。原生接口包括
`GetRuntimeSnapshot`、`GetRuntimeSnapshotJson`、
`SubscribeRuntimeSnapshots` 和 `UnsubscribeRuntimeSnapshots`。

## v1 必填字段

有效的 v1 JSON 必须包含以下四个字段。必填字段缺失或无效时，解码失败。

| 字段 | 要求 |
|---|---|
| `schema_version` | 无符号值，且必须等于 `1`。 |
| `generation` | 无符号 64 位 generation 排序键。 |
| `monotonic_ms` | generation 内使用的无符号 64 位排序键。 |
| `phase` | 受支持的 phase 字符串，包含字面值 `unknown`。 |

版本不支持或 phase 字符串无法识别时也会解码失败。`unknown` 是有效的线协议 phase，不能与无法识别的字符串混为一谈。

## 可选字段与前向兼容

其余 snapshot 字段对原生解析器均为可选。未知的可选根字段，以及
`traffic` 或 `last_error` 内的未知字段会被忽略。可选字段缺失或类型错误时，读取方使用默认值；只要必填字段有效，不能因此使 payload 解码失败。

重要字段形态和归属：

| 字段/分组 | 契约 |
|---|---|
| `capabilities` | JSON 字符串数组，不是对象。 |
| `role`、`server`、`transport` | 可选的运行时身份字符串。 |
| `requested_mux_mode`、`effective_mux_mode`、`mux_receiver_ordering`、`mux_fallback_reason`、`mux_active_links` | 可选的 MUX 状态和展示信息。 |
| `mux_scheduler`、`mux_pool_policy`、`mux_turbo` | 当前原生序列化器的扩展字段；作为未知可选 v1 key 被兼容。 |
| `p2p_state`、`effective_path` | 序列化器从 `p2p_state` 推导 `effective_path`；它不是权威输入。 |
| `traffic`、`connected_monotonic_ms` | 可选的累计流量和 connected 时间区间数据。 |
| `last_error` | 可选的、由生产者填写的诊断载荷。 |

## 解析有效性与排序

解码负责校验字段形态和必填字段，不负责判断新旧。原生 publisher 和移动端 store 会在取得有效 snapshot 后应用排序：接受更大的 `generation`；同一 generation 仅接受严格更大的 `monotonic_ms`。较旧或重复的 snapshot 会被拒绝。

解析外部 JSON 的消费者，可以在解码失败但排序元数据有效时按顺序展示 `unknown`。没有有效排序元数据的坏 payload 不得覆盖更新的状态。原生 TUI adapter 接收已类型化的 snapshot，本身不解析此 JSON。

## 生命周期展示

正常生产者序列为：

```text
starting → preparing_host → connecting → handshaking → applying_policy → connected
```

`reconnecting` 表示恢复过程；停止时发布 `stopping`，完成后为 `idle` 或
`failed`。该序列描述正常生产者行为，不是严格的合法迁移表：生命周期代码校验 generation/停止所有权，而不会校验每一个 phase 到 phase 的边。

在五项 readiness 全部满足前，请求的 `connected` 会展示为
`applying_policy`。离开 `connected` 会清除 `connected_monotonic_ms`；随后重新连接将开始新的时间区间。

## Connected readiness 门槛

以下五项必须为真：

1. session 已建立；
2. adapter 已打开；
3. route 已应用，或明确不需要 route；
4. DNS 已配置且 session 活跃，或明确不需要 DNS；
5. policy 已协商。

当前 client 接线从 session 已建立推导 policy 事实。服务端模式中，一个活跃 listener 为五个 readiness bit 同时提供值；仅构造 server 对象不足以表示就绪。

## `last_error` 边界

`last_error.code` 当前是生产者特定的 `uint32_t` 数值，不保证是
`ppp::diagnostics::ErrorCode` 序号。生产者填写 severity、retryability、消息 key 和诊断详情；消费者不得从诊断错误码目录推断它们。

成功停止会清除 `last_error`；停止失败时携带 stop completion 提供的错误。即使数值 code 为零，只要诊断详情非空，payload 仍可能表示错误。

## TUI 命令安全性

Console UI 只识别 `openppp2` 命令命名空间，并在本地以帮助文本报告未知命令或子命令。未知 TUI 输入会被拒绝，不会转发给 shell 或系统命令执行器。

## 源码参考

- `ppp/app/runtime/RuntimeSnapshot.h` 和 `RuntimeSnapshotJson.h`
- `schemas/runtime-snapshot-v1.schema.json`
- `ppp/app/runtime/RuntimeLifecycle.h` 和 `RuntimeReadiness.h`
- `ppp/app/runtime/RuntimeError.h`
- `ppp/app/ConsoleUI.cpp`
