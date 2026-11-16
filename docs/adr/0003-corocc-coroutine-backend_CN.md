# ADR 0003：可选 corocc L0 协程后端

> Status: Experimental
> Type: ADR
> Last verified: 2026-10-29, bfd5b881 + uncommitted corocc implementation

状态：实验性，默认关闭。[English](0003-corocc-coroutine-backend.md)。

## 决策

`ENABLE_COROCC=OFF` 保留 Boost fcontext。`ContextBackend.h` 在编译期选择
make/jump 后端；默认函数为 Boost 的编译期别名，类型仍是原 Boost 类型。Anchor、调度、YieldContext
公开方法及调用点不变。仅 corocc 构建在运行统计新增
`coroutine_backend: "corocc"`；默认构建不输出该字段，保留原始 JSON 字节。
这是对计划中双后端标签的有意例外，以满足更严格的默认行为兼容要求；
默认后端常量仍命名为 `boost-fcontext`，但不增加输出。

仅调用 corocc L0 上下文/栈函数；不使用 L1 token、L2 runtime 或 L3 scope。
继续链接 Boost.Context。上游静态库包含其他层，但链接器只需提取 L0 对象。
`tools/prepare_corocc.sh` 固定提交
`92502d92d136ea870a857d1578f13c33191b381f`，归档 SHA-256 为
`18042dd1ee9263eb40101e38aa7c72f46fb1502331d08619ab69092fb024f1b5`。

## Transfer 约定

`Jump(target, data)` 必须向目标交付 `{source, data}`；将来返回时，必须得到
**本次实际恢复者**提供的同类描述。corocc 的 `coro_ctx_swap(from, to)` 则把
保存帧写入稳定的 context 对象。因此适配层为每个协程持有一个稳定记录，
每个 OS 线程借用一个 root 记录；切换前写入 `target.incoming = {source, data}`，
入口与 swap 返回后读取该记录，不能沿用上一次 caller。

`Current()` 在不内联且带编译器屏障的访问器内计算 TLS 地址，不跨 swap 保存
TLS 引用。跨线程恢复后会重新设置当前线程记录。原生 `back` 和适配层
`incoming` 均由每次新恢复者在恢复执行前覆盖，支持嵌套及同一 io_context
不同 worker 间迁移；不会把协程移往另一个 io_context/shard。

YieldContext 独立保存初始 native context 的所有权，不依赖切换时置空的
`callee_`。结束使用 `Finish(caller, null)`，调用方看到空 data 后先销毁
native context，再回收栈。入口 trampoline 不得返回。现有 noexcept Handle
在切换边界之前捕获异常。

## 栈与 Sanitizer

普通栈继续由 BufferswapAllocator 分配，生产默认 128 KiB。固定版本 L0 没有
借用内存区间的初始化接口，适配层填写其 ABI 的 `coro_stack.lo/usable` 字段，
不转移分配所有权；升级 pin 时必须重新审计此依赖。
`PPP_COROCC_GUARD_STACK=ON` 改用 `coro_stack_alloc`，通过 shared_ptr deleter
回收映射；低地址端额外一页 guard，可用大小由 corocc 按页取整。
默认后端不会分配 guard 栈。

TSan 使用 corocc L0 的 fiber 钩子，仅在 corocc 下关闭 YieldContext 原有钩子，
避免重复切换。销毁协程 context 时回收其 fiber；线程 root 的 fiber 属于
sanitizer runtime，不能交给 corocc 销毁。TSan 保留已有诊断构建的大栈额度。
TSan 构建的后端接口显式传递 `COROCC_TSAN=1`，确保未插桩的使用方编译单元
也采用相同的原生上下文布局。

固定补丁强制内联两个 L0 TSan 切换辅助函数，涵盖全部优化等级。
若保留独立调用帧，函数在来源 fiber 进入、却在目标 fiber 退出，会破坏 TSan
的 shadow stack，并在首次进入 trampoline 时崩溃。Clang 19 的未优化构建
暴露了此问题，重点重测已覆盖修正。内存访问插桩保持开启。
函数级 thread-sanitizer 排除仍可能保留其他插桩，参见
[Clang TSan 文档](https://clang.llvm.org/docs/ThreadSanitizer.html)。

corocc 的 C 代码仍接受 ASan 插桩，但关闭其内部 fiber 钩子，由适配层统一
管理：来源记录保存自己的 fake-stack handle；到达时获取来源栈边界（含
本次 worker root）；结束切换用空保存指针释放 fake stack。上游把来源 handle
交给目标；适配层改为让 handle 始终归属原 fiber，跨线程迁移时也保持这一约定。
ASan/UBSan 与 TSan 始终使用独立构建。

## 平台与验收

初始白名单：Linux x86_64/aarch64、macOS x86_64/arm64、Android x86_64/arm64、
MSVC Windows x64。白名单仅表示允许配置，不代表已验证运行。其他平台警告
并关闭，除非 `COROCC_FORCE=ON`；iOS 始终警告并回退 Boost。无运行时回退。
手工维护的 `ppp.vcxproj` 暂不启用 corocc，Windows 可选构建使用 CMake。
TIB 恢复由上游汇编实现，仍需原生 SEH/栈边界验证。musl、Windows x86/ARM64
保持实验性；实测平台范围见验证报告。

正确性先于性能：transfer/嵌套/迁移/结束、Anchor 竞态与迟到唤醒、异常、
栈保持、worker 1/N、带 stack-use-after-return 的 ASan、TSan、可选 guard
故障与重复符号检查。任何正确性问题均否决。A/B 使用匹配的 release 二进制，
DL/UL P1/P16/P64，顺序 A1/B1/B2/A2。任一单元退化超过 3%，或波动大于差值，
均判无收益；默认始终关闭。参见[构建与验证](../development/COROCC_BACKEND_CN.md)。
