# 并发模型
> Status: Active
> Type: Architecture
> Last verified: `ppp/threading/`, `ppp/coroutines/`, and runtime startup sources, 2026-07-22
>
> **用途：**说明当前源码实际提供的 executor 与协程机制。
> **适用对象：**修改异步代码的贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Concurrency Model](CONCURRENCY_MODEL.md)

## 范围与非目标

原生运行时是异步的并使用 Boost.Asio，但源码没有建立“每个会话一个线程”或“所有会话都有 strand”的通用模型。本文记录进程级机制及其边界；它不是 lock-free 报文处理、固定吞吐量或每核一个线程的承诺。

## Executor 拓扑

`ppp::threading::Executors` 持有由全局运行时设置初始化的进程级 executor 状态。

| Context | 创建与用途 |
|---|---|
| 默认 `io_context` | 由 `Executors::Run()` 附着并由调用线程驱动。application start callback 被 post 到这里。 |
| Worker context | 由 `SetMaxThreads()` 创建；每个有受管 worker 线程与缓存缓冲区。`GetExecutor()` 在它们之间轮转，缺失时回退到默认 context。 |
| Scheduler context | 由 `SetMaxSchedulers()` 一次性创建并由 scheduler 线程驱动。socket 迁移可将 socket 绑定到该 context 的 strand。 |
| Tick 线程 | 在 executor internal 仍存在时维护缓存时间和低层周期工作。它是 detached 的；源码没有证明一个 join 的 tick-thread shutdown 契约。 |

`AppConfiguration::concurrent` 默认是处理器数量，但启动代码没有施加源码级 CPU 数量上限。`concurrent - 1` 为正时会请求 scheduler 线程；非 client 启动路径还会请求 worker context。最终拓扑依赖配置。

默认与 worker context 使用 64 KiB 缓存缓冲区。当前实现没有把 scheduler context 记录为具有同样的缓存缓冲区注册。

## 异步与串行化

`YieldContext` 是项目自定义的有栈协程封装，构建于 Boost.Context 的 `make_fcontext` / `jump_fcontext`，默认栈大小为 128 KiB。VMUX 还有单独使用 `boost::asio::spawn` 的代码，不能把全部异步代码写成只使用一种协程机制。

只有调用方提供 strand 时，strand 才会串行化 handler。`Executors::Post` 与 `YieldContext::Spawn` 都接收可选 strand。`ShiftToScheduler()` 在将一个打开的 TCP socket 迁移至 scheduler context 时创建 strand，但这不能证明程序中所有对象、回调或会话都绑定了 strand。

## 生命周期含义

- executor 关闭会向已知 context post stop、join 受管 worker、尝试关闭 netstack，再停止 scheduler 和默认 context。
- `Executors::Awaitable` 是一个条件变量桥接，只有 `Processed()` 被调用才会解除阻塞；当前实现没有取消唤醒路径。
- `YieldContext` 在内部守护状态转换，但调用方仍须保持周边对象的所有权与 dispatch 要求。
- `nullof<T>()` 使用空地址引用约定。它存在于当前代码中，但本文不对该约定作可移植安全性声明，也不推荐新增使用。

## 修改时的实用规则

以下是由实现边界得出的 review 规则，不是运行时强制保证：

1. 不要用同步 I/O 或无界等待阻塞默认、worker 或 scheduler `io_context`。
2. 不要假设 post 之后的裸对象指针仍然有效；遵循本地 owner 已有的 `shared_ptr`/`weak_ptr` 模式。
3. 扩展已串行化路径时保留传入的 strand；不能默认为所有路径都存在 strand。
4. 除非本地实现已证明安全，否则不要让锁跨越可能 yield 或调用外部 callback 的操作。
5. 将 `Awaitable::Await()` 视为调用方能够安全阻塞时的桥接，而不是通用协程替代品。

## 相关边界

- [EDSM 状态机](EDSM_STATE_MACHINES_CN.md)说明运行时状态展示。
- [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)说明默认 executor 的所有权。
- [可观测性](OTEL_DESIGN_CN.md)说明可选后端；在本树中它既不是 lock-free，也不是 compile-out 保证。
- [工程概念](ENGINEERING_CONCEPTS_CN.md)记录共享的所有权词汇。
