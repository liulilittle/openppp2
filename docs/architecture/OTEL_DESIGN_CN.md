# 可观测性
> Status: Active, optional at runtime
> Type: Architecture boundary
> Last verified: `ppp/diagnostics/Telemetry.*`, configuration, and shutdown sources, 2026-07-22
>
> **用途：**说明当前 telemetry 实现及其实际限制。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [Telemetry and Observability](OTEL_DESIGN.md)

## 已存在的能力

原生运行时有两个独立的诊断面：

| 状态面 | 当前职责 |
|---|---|
| `ErrorCode` / `ErrorHandler` | 来自 `ErrorCodes.def` 的类型化诊断；设置错误会更新本地/进程状态，并同步派发已注册 handler。 |
| `ppp::telemetry` | 通过树内 facade 提供运行时可配置的日志、计数器、gauge、histogram 和 span。 |

当运维需要生命周期状态时，二者都不能替代 `RuntimeLifecycle`。

## Telemetry 启用方式

在本树中 telemetry facade 始终被编译。尽管 CMake 暴露 `PPP_TELEMETRY` 选项，但 `Telemetry.h` 在缺失时把 `PPP_TELEMETRY` 定义为 `1`，实现中也没有 compile-out 的 no-op 分支。不能把该选项写成零二进制成本开关。

master telemetry、count 和 span 默认关闭。启动时 `PreparedArgumentEnvironment()` 应用 `telemetry.enabled`、级别、count/span、console、endpoint 与文件路径配置。配置路径即使在 master flag 关闭时仍会调用 `Configure()` 和 `SetLogFile()`，因此源码不支持“禁用 telemetry 永远不创建 backend 状态”的笼统说法。

## Backend 行为

backend 被创建后会持有一个 worker thread，以及 log、counter、span、gauge 和 histogram 的独立有界队列。普通队列上限为 4096 个事件，batch 最多 256；队列满时会丢弃对应事件类型。log level 在格式化/入队前和 backend 中各过滤一次。

该设计具有背压，但启用时并非 lock-free 或 allocation-free：队列和事件实现使用 mutex 与动态 string/vector 字段。唯一明确的 disabled-path 保证是在相关 atomic enable 检查后快速返回。

`SpanScope` 通过 thread-local 栈保持父子关系。同线程嵌套会被表示；该状态没有实现跨 Asio callback 或跨 thread 的自动 trace-context 传播。

## 导出与关闭限制

内置 OTLP 风格 exporter 使用原始 HTTP socket。对于 `https://` endpoint，若未安装外部 `HttpPostSink`，它不会发送；内置路径并未建立原生 TLS collector export。collector 兼容性与投递保证需要按部署验证。

`PppApplication::Dispose()` 调用 `Flush(3000)` 和 `Shutdown()`。这是 best-effort 关闭行为，不代表所有退出路径或负载下都无损投递。

## 安全文档边界

没有新证据前，避免宣称：

- compile-time 移除或零二进制成本；
- 启用后 hot path 为 lock-free/无分配；
- per-module 开关、sampling 或 rate limiting；
- 内置 HTTPS OTLP 投递；
- 稳定公共 OpenTelemetry SDK 或 collector 互操作保证。

错误码用于诊断，runtime snapshot 用于生命周期展示，telemetry 用于 opt-in 事件观测。
