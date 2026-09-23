# 诊断错误系统

> Status: Current
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> English: [English version](DIAGNOSTICS_ERROR_SYSTEM.md)
> Related: [错误处理 API](ERROR_HANDLING_API_CN.md) · [错误码](ERROR_CODES_CN.md)

## 架构

诊断子系统是头文件可见、面向实现的 C++ 设施 `ppp::diagnostics`。它不是单独
版本化的 SDK，也不承诺 ABI 兼容性。

```text
ErrorCodes.def（X-macro 目录）
  ├─ Error.h：ErrorCode 枚举和计数
  └─ ErrorHandler.cpp：描述符表
       └─ SetLastErrorCode
            ├─ 每线程错误码和 tick 值
            ├─ 进程级错误码和 tick 值原子变量
            └─ 同步的带 key 回调
```

`ErrorCodes.def` 是错误码目录的唯一来源。按本文核对的源码，其 628 项分布为：9 个
`kInfo`、64 个 `kWarning`、531 个 `kError` 和 24 个 `kFatal`。

## 状态模型

每个线程均有函数内 `thread_local` 存储，保存最近错误码和 tick 值。
`GetLastErrorCode()` 读取调用线程自己的状态；线程局部 tick 没有对应的自由函数
getter。

`SetLastErrorCode()` 还会以 `memory_order_relaxed` 向两个独立的进程级原子变量
发布错误码和 tick 值。错误码先写入，tick 后写入，但二者既不打包也没有版本号。
getter 也分别读取，因此它们**不是**一致的错误记录：并发观测者可能得到来自不同
更新的错误码和 tick 值。

全局值只是尽力而为的最后写入观测，不是事件日志，也不是同步机制。连续 tick 值不
保证严格递增。

## 通知分发

状态更新后，`SetLastErrorCode()` 在调用者线程上遍历已注册的 handler 列表：

- 分发是同步的，并按当前列表顺序执行；
- 每个回调收到错误码的数值；
- 回调抛出的异常会被吞掉；
- 线程局部保护会阻止递归的回调再次分发；
- 嵌套 setter 在保护返回前仍会发布自己的错误状态。

handler 列表没有 mutex，分发时也不会复制。必须在并发运行前完成所有注册，并且回调
可能发生时不得修改注册。注册以 key 为单位：已有 key 会被替换，对已有 key 传入空
handler 会删除该项。不存在单独的 unregister 函数。

## 格式化与严重级别

描述符表为 `FormatErrorString`、`FormatErrorTriplet`、`GetErrorSeverity` 和
`GetErrorSeverityName` 提供错误码名称、消息和严重级别。setter 不会校验
`ErrorCode` 的取值范围；格式化或分类无效原始值时，会使用实现中的 unknown
描述符/分类回退。

`kFatal` 只是分类。诊断子系统不会自动停止、重启或监督进程，也没有 watchdog API。
需要升级处理的调用方必须自行拥有该策略。

## 实用方式

- 在失败路径中使用具名 `ErrorCode` 和 `SetLastError` 辅助函数。
- 在同一线程传播失败时读取 `GetLastErrorCode()`。
- 只有在跨线程展示可接受建议性结果时，才使用进程级快照。
- 回调在设置错误的路径中内联运行，应保持短小。
- 不要把目录数值、进程级快照或回调行为视为外部协议契约。

## 源码参考

- `ppp/diagnostics/ErrorCodes.def`
- `ppp/diagnostics/Error.h` 和 `Error.cpp`
- `ppp/diagnostics/ErrorHandler.h` 和 `ErrorHandler.cpp`
