# M3 A 阶段剩余工作实施计划（Codex，workspace-write）

> Status: Implemented (A-stage) / plan snapshot
> Type: Plan
> Last verified: 2026-10-25

工作树：openppp2-m3，分支 `perf/m3-multicore`，基线 `b35d862b`（WIP 快照）。
权威设计：`M3_PLAN.md` §3.3–3.4、§5.1、§7.2–7.3、§8.A、§9；遵守 `AGENTS.md`、`.codex-brief-m3a.md`、`.codex-brief-m3a2.md`。

## 0. 全局约束（每步适用）
- 不联网/不 ssh/不运行 ppp/不改主机网络/不 push。
- 默认行为不变：所有新路径 opt-in；shards=1、未设环境变量、Windows/Android 行为与 `b35d862b` 完全一致。
- 每步一个 commit（Conventional Commit），不 push；commit message 不加任何 Co-Authored-By/attribution 行。
- 不改 vendor/xtcp 源码，不改其他 worktree，不改 `M3_PLAN.md` 与 brief。
- 新增 `.h/.cpp` 同步：`ppp.vcxproj`、`ppp.vcxproj.filters`（仅 ppp 目标编译的）、`tests/cpp/CMakeLists.txt`（测试）。
- 本地 C++ 编译可能不可用：先 `which g++ clang++ cmake`；有编译器则对 header-only 测试 `g++ -std=c++17 -fsyntax-only -I. tests/cpp/<t>.cpp`（缺 boost 头则跳过）；无则在 commit body 写 "not compiled locally"，并在最终报告列出未做检查。不伪造结果。
- 每个 commit 前离线检查：`git diff --check HEAD`；`bash tools/check_vcxproj_sources.sh`；`bash tools/check_include_boundaries.sh`；若存在则 `python tools/check_repository_layout.py`；相关 tooling 测试（`python -m pytest -q tests/tooling` 中 datapath/m3 相关）。

## 步骤 1：清理 + SpscHandoff::Abort 文档化
- `linux/ppp/tap/TapLinux.cpp`：仅删除行尾空白（`grep -nE '[ \t]+$'`），不动其他内容。
- `ppp/threading/SpscHandoff.h` `SpscHandoff::Abort()`（~107 行）：注释顺序语义——先 `closing_=true`(release) 再 `gate_=Closed`(acq_rel exchange)；观察到 Closed 的线程必见 closing_；仅见 closing_ 的生产者只会走 CommitWake 失败或 Closed 返回，不丢数据不重复调度。可选改为返回 bool（前状态非 Closed 返回 true），须先 rg `\.Abort()` 确认调用点兼容。`SerializedSpscHandoff::Abort()`（~176 行）同样注释。
- `tests/cpp/spsc_handoff_test.cpp` 新增 `AbortIsIdempotentAndObservable`：连续 Abort 两次后 `GetState()==Closed`、`Closing()==true`；PushBatch 返回 `HandoffPush::Closed`；Claim/ArmWait 返回 false；已入队元素可被析构，构造/析构计数相等。
- Commit：`chore(threading): document SpscHandoff abort ordering and strip TapLinux trailing whitespace`

## 步骤 2：TapOutputLane 选择与回退直接测试
- 新建 `ppp/tap/TapOutputLanePolicy.h`：`inline int SelectTapOutputLane(int slot, bool lanes_enabled) noexcept;`——`!lanes_enabled || slot<0 || slot>=kMaxTapOutputLanes` 返回 -1，否则 slot。
- `TapLinux::CurrentGsoOutputLane()`（~2446 行）改调用它，行为逐字等价：lane 已存在直接返回，否则 `CreateGsoOutputLane(index)`；创建失败（fail lambda）回退共享路径（nullptr），`Output`（~2755 行）走普通路径。
- 新建 `tests/cpp/tap_output_lane_test.cpp`（header-only，链接 Threads::Threads）：`DefaultSlotIsShared`；`ScopeNestsAndRestores`（Scope(3)→Scope(5)，恢复 -1）；`ThreadLocalIsolation`（两线程 lane 1/2，latch 同步）；`OutOfRangeFallsBack`（-5、16、INT_MAX→-1；0、15 原样）；`DisabledLanesFallBack`。
- 注册 CMake（靠近 spsc_handoff_test）；新 header 若被 ppp 目标引用，按 `TapOutputLane.h` 方式加入 vcxproj/filters。
- Commit：`test(tap): cover output lane selection and shared-path fallback`

## 步骤 3（计划 Step 5）：生产 direct-upload 数据交接改 SPSC handoff
现状：`XtcpRuntime.cpp` `OnReceive` direct 分支（~2810–2880）在 shard strand 调用 `direct->SendToPeer(data,len,credit)`，批处理期间 flush 推迟到 `deferred_peer_flushes`，否则立即 `FlushPeerSend()`。被调方 `VirtualEthernetTcpipConnection::SendDirectToPeer`（`ppp/app/protocol/VirtualEthernetTcpipConnection.cpp` ~1124）在 `direct_sync_` 下 push 到 `direct_upload_queue_`（deque），上限 `kDirectQueueMaxPackets=4096`/`kDirectQueueMaxBytes=32MiB`，低水位一半；`RunDirectUpload`（~1231）gather 写，低水位（~1402）唤醒 writable handler。相关：`StartDirectUploadWriterIfNeeded`（~1204）、`FlushDirectPeerSend`（~1220）、`CloseDirectSend`、`DirectSendCloseState` Open→Draining→SendShutdown→Disposed；`CloseFlow`（~3420–3455）的 `EraseDirectSecondLeg`/`direct_bridge`；`InitializeUploadBudget` 唤醒（~2404）；`OnDirectBridgeFallback`（~1835）。

目标：数据队列本体由 mutex+deque 换成 `SerializedSpscHandoff<...XtcpUploadChunk...>`；生产者 shard strand（strand 可跨线程迁移，故用 Serialized 适配器），消费者 `RunDirectUpload`。

设计要求：
1. 提取可测试的生产 helper `ppp/app/protocol/XtcpDirectUploadQueue.h`（类 `XtcpDirectUploadQueue`）：内含 handoff、原子字节/条目计数、高/低水位常量（数值不变）、backpressured 标志、关闭状态、遥测指针。API：`Push(data,len,Reservation&&)->DirectIoResult`（先查容量再拷贝再 publish；失败时 credit 由调用方保留或析构释放，绝不双释放）；`DrainGather(max_bytes,max_items,out)`；`Release(bytes,items)->bool resume_writable`（从高于低水位跨到以下时恰好一次 true）；`ArmWaitAndRecheck()`、`RequestClose()`、`Abort()`、`Snapshot()`。`VirtualEthernetTcpipConnection` 持有该 helper；生产代码与测试走同一个类（§3.4 硬要求）。
2. 控制锁保留：`direct_sync_` 仍保护 `direct_bridge_started_`、`direct_send_close_state_`、telemetry、download waiter；仅数据入/出队不持锁。关闭路径先在锁内改状态再 `RequestClose`。
3. 唤醒协议：Push 成功且 `CommitWake()` 为 true 时生产者负责启动 writer；`FlushDirectPeerSend` 仅在本批次至少一次 CommitWake 成功时 post writer（保持每批次一次 writer 启动+一次 gather write）；`RunDirectUpload` 排空后必须 `ArmWaitAndRecheck`，recheck 有数据则继续；任何时候不得有两个 writer。
4. Credit：chunk 持有 Reservation 直到写完成或丢弃；Close/Abort 时环中残留 chunk 在消费侧（或 Finalize 单线程）析构，`XtcpUploadBudget` 归零，旧 epoch credit 不释放到新 epoch。
5. 描述符内存上界与回退：环容量固定 4096 槽；分配失败时 `StartDirectBridge` 返回 false，走 `OnDirectBridgeFallback`，计数 `direct_handoff_alloc_fallback`+1。
6. Opt-in：环境变量 `OPENPPP2_XTCP_DIRECT_SPSC=1`，在 XtcpRuntime 构造时读取（参考 `OPENPPP2_XTCP_UNIX_BRIDGE` ~990 行），经 `StartDirectBridge` 参数或 setter 传给连接；未设置保留 deque 路径。旧路径也放入同一 helper（按 mode 分支），测试覆盖两种 mode。
7. XtcpRuntime 侧 ~2838–2880 语义不变（Accepted/Closed/Backpressured 计数、`receive_rejected`、`BeginResume`、`deferred_peer_flushes`）；`CloseFlow` 顺序不变；stale 回调由 `flow->generation`/`IsCurrent(generation)` 过滤。
8. 遥测：`RuntimeXtcpStats.h` 只增字段 `direct_spsc_enabled`、`direct_handoff_full`、`direct_handoff_wakes`、`direct_handoff_alloc_fallback`；同步序列化与 stats 测试（rg `direct_upload_queue_bytes`）。

测试 `tests/cpp/xtcp_direct_handoff_test.cpp`（直接用 `XtcpDirectUploadQueue` 与真实 `XtcpUploadBudget`；latch/barrier + 看门狗有界等待，禁止 sleep；每用例 deque 与 spsc 两种 mode）：
1. `FifoAndByteIntegrity`：10000 随机长度块，校验顺序、校验和、构造/析构计数。
2. `ItemAndByteCapBackpressure`：分别达 4096 条与 32MiB 上限返回 Backpressured，标志只置一次，credit 未消费；Release 跨低水位 resume_writable 恰一次 true。
3. `CreditReleaseOrdering`：Release 在 wait 注册前/后两种顺序，恢复不丢不重。
4. `WakeInterleavings`：生产者在 arm 前、arm 与 recheck 间、recheck 后、Scheduled 期间、drain 期间 publish（step hook 强制交错）；断言全部消费、单 writer owner、忙数据批次无多余唤醒。
5. `CloseWithFullRing`：满环 Close、消费者 park 时 Close、Abort 后 Push 返回 Closed；budget 归零。
6. `StaleEpochAfterRestart`：旧 epoch chunk 在新 epoch 开始后析构，新 epoch budget 不受影响。
7. `AllocationFailureFallsBack`：注入分配失败（测试钩子/allocator 模板参数），返回 fallback 且计数+1。
8. `TwoThreadStress`：生产/消费线程 1e6 条（供 TSan）。
另：扩展 `tests/cpp/xtcp_runtime_bridge_test.cpp` 增加 `OPENPPP2_XTCP_DIRECT_SPSC=1` 变体（测试 main 中 setenv），复用 DirectSecondLeg 用例；扩展 `xtcp_upload_budget_test` 断言所有路径结束计数归零；CMake 注册并确认现有 sanitizer 选项覆盖新目标。
helper 头部注释写明不变式：单写（Serialized）单读；每批次至多一次 writer 启动；credit 随 chunk；关闭后不再 publish；不出现两个 gather writer；低水位恢复恰一次；字节/条目最终归零。
Commits：`refactor(protocol): extract XtcpDirectUploadQueue from direct upload path`（纯提取，行为不变）；`feat(xtcp): opt-in SPSC handoff for direct upload data path`（含测试）。

## 步骤 4（计划 Step 7 Stage B）：opt-in 每 shard executor/lane 绑定 + 有界 read-envelope 交接
仅 `OPENPPP2_XTCP_AFFINITY=queues` 启用；`off` 默认与 Stage A `workers` 不受影响。

4a. 每 shard executor（XtcpRuntime.cpp）：
- `Shard` 增加 `std::shared_ptr<boost::asio::io_context> io`、work_guard、`std::thread worker`。
- 构造段（~997–1040）：queue 模式每 shard 自建 io_context，`s.strand` 绑 `s.io->get_executor()`；非 queue 模式保持共享 `own_context_`。
- 启动段（~1130–1180）：queue 模式每 shard 一线程 `s.io->run()`，按 `OPENPPP2_XTCP_IO_CPUS` 第 i 个 CPU 严格绑核；复用 `XtcpShardPolicy.h` 解析器并加 strict 规则（数量==N、无重复、在启动 affinity envelope 内）；`worker_runtime_` 记录 tid 与有效 CPU。
- `StartFlow` 中 Flow/connector socket、`SchedulePoll` timer、retry/resume timer、`InitializeUploadBudget` 唤醒 post 均绑定 `s.io`/`s.strand`（确认 weak context 为 per-shard）。
- SSMT 与 queue 模式同时开启：启动拒绝并给明确错误；shards==1 时 queue 模式记为 unsupported（stats），不得 silently 当作已绑核。
- 停止顺序（`Stop`/`DoStopShard`/`DoStopFinalize`/析构 ~774–807）：关 admission → 在 owner executor 上取消 timer/socket → 排空 handler → 释放 work guard → 非自身线程 join（保留"析构在自己 worker 上不 join 自己"）。部分启动失败只回滚已创建对象。
- 遥测只增：`affinity_mode`、`queue_mode_active`、`per_shard_worker_tid[]`。

4b. 启动绑定钩子：`XtcpRuntime.h` 增加 `struct XtcpLaneBinding { boost::asio::any_io_executor executor; std::weak_ptr<void> lifetime; };` 与 `bool GetLaneBinding(int lane, XtcpLaneBinding& out) const noexcept;`；`ClientConnectionOpener.cpp` 在流量开始/ready 前向 TapLinux 注册 provider（如 `SetOutputLaneExecutorProvider(std::function<bool(int, XtcpLaneBinding&)>)`）；`TapLinux::CreateGsoOutputLane`（~2465）若 provider 返回 executor 则用它构造 GsoOutputLane 的 descriptor 与 hold timer 并在其上启动 `LaneReadLoop`，否则沿用现有 context。不建新接口、不碰路由，lane 下标与内核 rx-N 分开记录；复用 `TapOutputLaneScope`、`gso_lanes_`、`DisableGsoOutputLanes`，不另写一套。

4c. 有界 read-envelope 交接：`LaneReadLoop`（~2533）在 queue 模式下读取后先拷贝/retain envelope 再 re-arm FD，推入有界 staging（每 lane 一个 SPSC + vnet 端轮询，或 Serialized 适配器，按 §3 组件选择）；全局上限 1024 条/8 MiB；消费端在原 vnet executor 上按 lane round-robin 取出并调用原 `OnInput`，策略检查顺序不变；满则丢弃并计数 `lane_envelope_full_drops`；credit 持有到 `OnInput` 返回。非 queue 模式路径不变。将交接逻辑提取到平台无关的纯 header `ppp/tap/TapLaneEnvelopeQueue.h`。

4d. 测试：
- `tests/cpp/xtcp_queue_mode_lifecycle_test.cpp`（仅 ENABLE_XTCP，链接方式同 `xtcp_runtime_adapter_test`）：`QueueModeStartStop`（N=2/4，线程全 join、io_context 析构、无残留 handler）；`PartialStartupUnwind`（注入第 k 个 shard 失败）；`StopFromOwnWorker`（无自 join 死锁）；`RestartStaleCallbacks`；`SsmtQueueModeRejected`；`Shards1QueueModeUnsupported`。
- `xtcp_shard_policy_test.cpp` 扩展 `OPENPPP2_XTCP_AFFINITY=queues` 与 `IO_CPUS` strict 解析：数量不匹配、重复、越界、格式错误、超出 envelope 均拒绝；非 strict 标记 degraded。
- `tests/cpp/tap_lane_envelope_handoff_test.cpp`：每 lane FIFO 与 round-robin 公平；1024 条/8 MiB 上限与丢弃计数；close 时残留释放且计数归零；多读者生产者+单消费者 TSan 压力。
- CMake/vcxproj/filters 同步（Windows 不编译 TapLinux，但共享 header 要列入）。
Commits：`feat(xtcp): opt-in per-shard executor queue mode with strict CPU binding`；`feat(tap): bind GSO output lanes to shard executors with bounded read-envelope handoff`。

## 步骤 5：收尾
- 全部离线检查；`git log --oneline b35d862b..HEAD` 确认每步独立 commit。
- `rg -n "OPENPPP2_XTCP_DIRECT_SPSC|OPENPPP2_XTCP_AFFINITY"` 确认默认关闭，并在 docs 中已有 XTCP 环境变量说明处（中英文配对文件都要）补一行。
- 最终报告：本地实际跑过的检查、未编译/未运行项、新增测试目标名、需要远端验证的点。

## 不在范围
B 阶段全部测量（吞吐、矩阵、cap32/48、NetEm、ABBA、`--throughput`）；运行 ppp/E2E；Windows MSBuild/Android；§5.2 内核 RPS/XPS/IRQ；§6 WS2 vendor patch；auto-policy 默认晋级；push/PR；修改 `M3_PLAN.md` 或 brief。
