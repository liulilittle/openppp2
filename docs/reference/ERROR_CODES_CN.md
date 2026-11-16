# 错误码参考

> Status: Current
> Type: Reference
> Last verified: local workspace, 2026-10-07
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

按 2026-10-07 核对的本地工作区源码，目录共有 **632** 项。策略运行时改动计划纳入 v2.1.7，v2.1.6 不含；v2.1.7 是否已成功发布尚未确认，因此该计数不代表这两个版本。

| 严重级别 | 项数 |
|---|---:|
| `kInfo` | 9 |
| `kWarning` | 64 |
| `kError` | 534 |
| `kFatal` | 25 |
| **总计** | **632** |

`ErrorSeverity::kWarn` 是声明的枚举成员，`ErrorSeverity::kWarning` 是它的别名；
X-macro 目录使用后者的拼写。当前目录没有使用 `kTrace` 或 `kDebug` 的条目。

## 数值与校验

`ErrorCode` 是按定义顺序生成的 `uint32_t` 枚举。
按本地工作区修订，`kErrorCodeCount` 为 632，`kErrorCodeMax` 是其排他上界。应优先
使用具名枚举值；接收原始整数时，先用 `IsValidErrorCodeValue(int)` 校验，再转换为
`ErrorCode`。

可使用以下函数获得展示信息：

- `FormatErrorString(code)` — 消息文本
- `FormatErrorTriplet(code)` — `<numeric-id> <CodeName>: <message>`
- `GetErrorSeverity(code)` 和 `GetErrorSeverityName(severity)` — 源码定义的分类

数值顺序、计数和文本都是当前实现数据，不是线上格式、已发布的兼容性表，也不保证
外部消费者可以跨修订持久化这些数值。

## 工作区新增策略枚举

当前本地 `ErrorCodes.def` 新增以下三项：

| Code | 严重级别 | 含义 |
|---|---|---|
| `ConfigPolicyRuntimeUnavailable` | `kFatal` | v2 客户端策略运行时不可用或尚未准备。 |
| `ConfigPolicyTcpSniffUnsupported` | `kError` | 当前平台不支持 TUN TCP 域名嗅探。 |
| `ConfigPolicyUdpIdentityConflict` | `kError` | v2 客户端虚拟地址与内部 UDP identity 地址范围冲突。 |
| `ProxyInternetDisabled` | `kError` | 代理模式以 `--proxy-internet=no` 运行，只允许访问虚拟子网目标。 |

策略 CLI 和 source loader 还会生成 `E_POLICY_CONFIG`、`E_POLICY_JSON`、
`E_POLICY_SOURCE_CONFLICT`、`E_POLICY_SOURCE_UNAVAILABLE`、
`E_POLICY_CAPABILITY_UNSUPPORTED`、`E_POLICY_ARGUMENT`、`E_POLICY_STORAGE` 等诊断字符串。
这些是 JSON 报告码，不属于 `ppp::diagnostics::ErrorCode` 枚举，也没有 `ErrorCodes.def` 数值 ID。

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
