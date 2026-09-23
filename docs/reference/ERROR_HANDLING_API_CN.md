# 错误处理 API

> Status: Current
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> English: [English version](ERROR_HANDLING_API.md)
> Related: [错误码](ERROR_CODES_CN.md) · [诊断错误系统](DIAGNOSTICS_ERROR_SYSTEM_CN.md)

本文说明 `ppp/diagnostics/Error.h`、`Error.cpp` 和 `ErrorHandler.*` 实现的
头文件可见 `ppp::diagnostics` C++ 接口。它是实现接口，不是独立支持的公共 SDK。

## 范围与 API 边界

`ErrorCode` 的定义、文本和严重级别均由
`ppp/diagnostics/ErrorCodes.def` 生成。`Error.h` 声明
`ppp::diagnostics` 自由函数；`ErrorHandler` 是其单例后端实现，不是对外声明的
对象 API 或兼容性边界。

当前源码**未提供**：

- `Error::ToString`
- `UnregisterErrorHandler`
- 自动重启、退出或 watchdog API

## 头文件可见函数

| 范畴 | 函数 | 含义 |
|---|---|---|
| 校验 | `IsValidErrorCode`、`IsValidErrorCodeValue` | 校验枚举或原始整数是否位于当前连续错误码范围内。 |
| 调用线程状态 | `GetLastErrorCode` | 返回调用线程最近设置的错误码。 |
| 进程级观测 | `GetLastErrorCodeSnapshot`、`GetLastErrorTimestamp` | 读取建议性的全局错误码和 tick 字段；两者不是一致记录。 |
| 发布 | `SetLastErrorCode` | 设置状态并返回传入的 `ErrorCode`；不校验该值的范围。 |
| 失败返回辅助函数 | `SetLastError` 重载/模板 | 设置错误码并返回 `false`、`-1`、`NULLPTR` 或调用方提供的值。 |
| 格式化和分级 | `FormatErrorString`、`FormatErrorTriplet`、`GetErrorSeverity`、`GetErrorSeverityName`、`IsErrorFatal` | 获取源码定义的展示和分类元数据。 |
| 通知 | `RegisterErrorHandler` | 添加、替换或删除带 key 的回调。 |

`FormatErrorTriplet(code)` 返回
`<numeric-id> <CodeName>: <message>` 格式的字符串。无效原始值使用实现中的
unknown 描述符回退。

## 状态与发布语义

`ErrorHandler` 使用函数内线程局部存储保存调用线程的最近错误码和 tick。
`SetLastErrorCode` 从 `Executors::GetTickCount()` 获取 tick，并以
`memory_order_relaxed` 写入一个进程级错误码原子变量和一个 tick 原子变量。

这两个全局字段分别存储、分别读取。不得把
`GetLastErrorCodeSnapshot()` 与 `GetLastErrorTimestamp()` 当作同一个原子
`(code, tick)` 事件记录；并发时它们可能来自不同发布。

同一失败路径应使用 `GetLastErrorCode()`。只有在尽力而为的跨线程观测即可满足需求
时，才使用全局 getter。

## 回调与注册

`SetLastErrorCode` 在设置者线程上同步调用已注册回调，并按注册表顺序执行。
每个回调抛出的异常都会被吞掉。线程局部递归保护会阻止回调内部嵌套调用
`SetLastErrorCode` 时再次分发回调；该嵌套调用仍会更新本地和全局错误状态。

注册操作刻意不做同步：

- 必须在多线程运行时开始前注册回调。
- 使用同一 key 会替换已有回调。
- 对已有 key 传入空 handler 会删除该项。
- 对不存在的 key 传入空 handler 不产生任何效果。
- 回调可能分发时，不得注册、替换或删除。

## 严重级别不是进程控制

`IsErrorFatal(code)` 只判断源码定义的严重级别是否为 `kFatal`。
该分类本身不会停止进程、安排重启或改变运行时生命周期；消费者可以自行决定升级策略。

## 源码参考

- `ppp/diagnostics/ErrorCodes.def` — 错误码目录来源
- `ppp/diagnostics/Error.h` — 声明与辅助函数
- `ppp/diagnostics/ErrorHandler.cpp` — 状态存储、发布、格式化与回调分发
