# 错误码参考

> Status: Current
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> English: [English version](ERROR_CODES.md)
> Related: [错误处理 API](ERROR_HANDLING_API_CN.md) · [诊断错误系统](DIAGNOSTICS_ERROR_SYSTEM_CN.md)

## 唯一事实来源

`ppp/diagnostics/ErrorCodes.def` 是当前
`ppp::diagnostics::ErrorCode` 目录的 X-macro 唯一事实来源。每一项形如：

```cpp
X(Name, "human-readable message", ErrorSeverity::kError)
```

该文件在 `Error.h` 中生成枚举和计数，并在 `ErrorHandler.cpp` 中生成名称、消息和
严重级别描述符表。完整的实时目录应直接查阅 `.def` 文件；本文不是手工维护的完整
枚举表。

## 当前目录

按本文核对的源码，目录共有 **628** 项。

| 严重级别 | 项数 |
|---|---:|
| `kInfo` | 9 |
| `kWarning` | 64 |
| `kError` | 531 |
| `kFatal` | 24 |
| **总计** | **628** |

`ErrorSeverity::kWarn` 是声明的枚举成员，`ErrorSeverity::kWarning` 是它的别名；
X-macro 目录使用后者的拼写。当前目录没有使用 `kTrace` 或 `kDebug` 的条目。

## 数值与校验

`ErrorCode` 是按定义顺序生成的 `uint32_t` 枚举。
按本文核对的修订，`kErrorCodeCount` 为 628，`kErrorCodeMax` 是其排他上界。应优先
使用具名枚举值；接收原始整数时，先用 `IsValidErrorCodeValue(int)` 校验，再转换为
`ErrorCode`。

可使用以下函数获得展示信息：

- `FormatErrorString(code)` — 消息文本
- `FormatErrorTriplet(code)` — `<numeric-id> <CodeName>: <message>`
- `GetErrorSeverity(code)` 和 `GetErrorSeverityName(severity)` — 源码定义的分类

数值顺序、计数和文本都是当前实现数据，不是线上格式、已发布的兼容性表，也不保证
外部消费者可以跨修订持久化这些数值。

## 严重级别边界

严重级别用于分类诊断错误。尤其是 `kFatal` 本身不会重启或退出进程；如需升级处理，
必须由消费者显式实现策略。

## 目录维护

错误码目录发生变化时，应把 `ErrorCodes.def` 作为唯一事实来源，并重新核对生成的
枚举/描述符行为和严重级别分布。保持本文与英文对应页和源码一致，不要保留会过时的
局部错误码表。

## 源码参考

- `ppp/diagnostics/ErrorCodes.def`
- `ppp/diagnostics/Error.h`
- `ppp/diagnostics/ErrorHandler.cpp`
