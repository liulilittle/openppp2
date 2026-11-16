# TUN GSO PSH 触发 flush 的削减方案
> Status: Proposal
> Type: Design
> Last verified: 2026-11-01

> **用途：**设计如何减少 TUN GSO 写路径中由 PSH 触发的 writev，供实现前评审。
> **适用对象：**维护 `TapGsoCoalescer` / `TapLinux` / XTCP NDI 后端的开发者。
> **当前状态：**提案，未实现；不改变任何产品代码。
> **证据来源：**PR #134 诊断计数器与 [THROUGHPUT_OPTIMIZATION_PLAN_CN.md](THROUGHPUT_OPTIMIZATION_PLAN_CN.md) §2.4.5、§2.4.7。
> **核对范围：**`linux/ppp/tap/TapGsoCoalescer.h`、`linux/ppp/tap/TapLinux.cpp`、`ppp/app/client/xtcp/XtcpNdiBackend.cpp`。

## 1. 问题与现状

P1 DL 30 s：writev 平均 19.55 段 / 28 KB，最大 32 段 / 46 KB（即默认 `SegmentCap()=32`）；
非空 flush 的 99.88% 是 `FlushReason::Psh`。单流 DL 客户端线程饱和，内核 TUN/syscall I/O 约占客户端 CPU 33%。

代码事实：
- `TapGsoCoalescer.h` `PushInternal()` 末尾：`psh` 时先 `pending_psh_ = true`，再 `Flush(Psh)`；
  `BuildGso()` 仅当 `pending_psh_` 时把 PSH 写入聚合头。PSH 路径需 `OPENPPP2_TAP_GSO_PSH_BOUNDARY=1`
  （`TapLinux.cpp` `TapGsoPshBoundaryRequested()`），否则 PSH 走 `RejectionReason::Psh` 并按普通帧写出。
- `CanAppend()` 已要求同流、seq 连续、ack/window/选项一致，`ClassifyStrictV1()` 把 `flags & 0xE7`（FIN/SYN/RST/ECE/CWR/URG）
  判为 Control：先 `Flush(Control)` 再普通写，FIN 顺序天然保持。
- 已有 100 us 保持定时器：`TapLinux::ArmGsoHoldTimerLocked()`（`TapLinux.cpp` ~2253）与 `FlushExpired()`；
  `OPENPPP2_TAP_GSO_HOLD_US` 可调（10-1000 us）。Push 入口还会在 `now-started>=hold` 时先 `Flush(Timeout)`。
- 推送入口：`XtcpNdiBackend::Tx`（逐包）与 `TxBatch`（仅循环调用 Tx，无批末钩子）。
  §2.4.7 的调用栈显示 `FlushPendingSend → XtcpNdiBackend::Tx`，**尚未证实 DL 热路径经过 `TxBatch`**。

结论：PSH 位于 XTCP 一次 `FlushPendingSend` 突发的最后一段，因此 19.55 段/次基本等于“一次突发”。
削减 writev 的唯一办法是把相邻的多个突发合并，上限为 cap（32 或 48）。

## 2. 方案

### 方案 A：PSH 延迟到当前 Tx 批 / io turn 结束
- 代码点：`PushInternal()` 的 `if (psh)` 分支改为：新增成员 `defer_psh_`，开启时只记录 PSH 而不 `Flush`；
  `FlushReason` 增加 `BatchEnd`（同步扩展 `TunWriteDiagnostics::flushes[]` 与 `TapLinux.cpp` `FlushReasonName()`）。
  `TapLinux` 新增 `FlushGsoBatchEnd()`（持 `gso_mutex_`，调用 `Flush(BatchEnd)` 并 `CancelGsoHoldTimerLocked()`）。
  `XtcpNdiBackend::TxBatch()` 循环后调用新注册的 `batch_end_` 回调；若热路径实际走 `Tx`，则需在 xtcp 的
  `FlushPendingSend` 尾部（`third-party/xtcp/src/core/tcp_fsm.cpp`，本地补丁）增加批末通知。
- 预期：仅当同一 batch 内含多个突发才合并。若热路径本就一突发一批，则 writev 减少约 0%；理论上限同方案 B。
- 风险：依赖钩子正确覆盖所有退出路径（Tx 失败、stop、Ssmt、dispose）；漏调用时只能靠 100 us 定时器兜底。
- 优点：延迟上界 = 一个批，语义最干净；适合作为 B 的“安全版”。

### 方案 B：跨连续 PSH 段合并至 cap（仅靠 cap/ShortTail/定时器/不兼容 flush）
- 代码点：同 A 的 `PushInternal()` 分支，但无批末钩子；PSH 不再 flush，靠 `Cap`、`ShortTail`、`Incompatible`、
  `Control`、`Timeout`（`TapLinux` 定时器）出口。
- 头部正确性（混合 PSH）：聚合头取自首段，中间段 PSH 在内核 GSO 分段时被清除，仅末段保留头部 PSH。
  必须把 `pending_psh_` 改为“最后追加的段是否带 PSH”：`Start()` 置为首段 PSH，每次 `Append()` 覆盖为当前段 PSH，
  `BuildGso()` 里同时处理“首段带 PSH 而末段不带”的情形（需清除头部 PSH）。当前代码在首段 PSH 时必然立刻 flush，
  所以该情形今天不会出现；本方案必须显式清位，否则会在非末段保留 PSH 导致内核分段时每段都带 PSH。
  接收端语义变化：被合并掉的中间 PSH 仅是推送提示，Linux 接收端不依赖；但需要实验验证。
- 预期：平均段数从 19.55 向 32 靠拢（上界），writev 次数最多约 -39%（19.55/32）；现实预估 -15% 至 -30%。
- 风险：尾部延迟——一个突发的末段最长等待 hold（100 us 定时器，实际受 io_context 调度影响更大）；
  交互/小流量（单段突发）被放大延迟；ACK 驱动的发送变慢可能降低窗口增长（对 DL 单流为负反馈）。

### 方案 C：有界微延迟（hold 可调 + 仅对“满突发”延迟）
- 代码点：在方案 B 基础上加条件：只有当聚合已达 `defer_min_segs`（如 8）且 `hold_ns` 未到时才延迟 PSH flush，
  小聚合（< `defer_min_segs`）仍立即 `Flush(Psh)`；`OPENPPP2_TAP_GSO_HOLD_US` 默认 100 us 可降至 20-50 us。
- 预期：收益介于 A 与 B 之间；保护交互/短流（它们很少攒到 8 段）。
- 风险：参数多；hold 过小则收益趋零；定时器粒度（asio steady_timer）下 <50 us 不可靠。

## 3. 收益估算（Amdahl，p = 0.33）

假设 syscall 固定开销占 I/O 的 30%，其余随字节线性（拷贝/skb 构建不因合并而减少）：
可节省 CPU = 0.33 × 0.30 × (writev 次数减少比例)。
- writev -15%：节省 1.5%，加速约 **1.015×**；-30%：节省 3.0%，约 **1.03×**；理论上限 -39%：约 **1.04×**。
- 若固定开销占比高达 60%（唤醒/`sock_def_readable` 随调用次数增加），上限约 1.08×。
合并还会让 TCP 接收侧每次唤醒处理更多数据，可能带来对端少量额外收益，但不计入承诺。
该收益远小于 §2.4.7 所列 1.10-1.19× 的目标，需在文档中如实标注：此项是小幅优化，不是主要瓶颈解法。

## 4. 推荐

推荐 **方案 C 的保守形态，分两步**：
1. 第 0 步（无代码风险）：用 PR #134 计数器核实 `tx_calls` 与 `batch_calls`；若 DL 热路径不经 `TxBatch`，
   则放弃方案 A，直接做方案 C。同时对比 `OPENPPP2_TAP_GSO_SEGMENTS=48`（已有开关，零代码）作为基线，
   因为 cap 到 32 时多数 flush 将变为 Cap 而非 PSH，上界本就受 cap 限制。
2. 第 1 步：实现方案 C（含方案 B 的头部 PSH 修正），默认关闭。方案 A 仅在第 0 步证明批边界存在时追加，
   作为 C 的 `BatchEnd` 出口以收紧延迟。

理由：A 依赖尚未证实的批边界；B 无条件延迟，对短流/交互风险最大；C 复用现有定时器与 env 机制，改动最小（约 40-80 行）。

## 5. 门控

- 新增 `OPENPPP2_TAP_GSO_PSH_DEFER`：未设置或非 `1` 为关（默认关）；解析方式与 `TapGsoPshBoundaryRequested()` 一致。
  仅在 `OPENPPP2_TAP_GSO_PSH_BOUNDARY=1` 且合并开启时才生效，否则忽略。
- `OPENPPP2_TAP_GSO_PSH_DEFER_MIN_SEGS`（默认 8，范围 1-`SegmentCap()`）；hold 沿用 `OPENPPP2_TAP_GSO_HOLD_US`。
- 任何 `Control`、`Incompatible`、`Terminate`、`Ssmt`、写失败降级路径行为不变，仍先 flush 后处理。
- 不引入配置文件字段；验证通过后再议是否进入 `OPENPPP2_XTCP_DL_GSO_PERF_PROFILE`。
- 诊断：新增 `flushes[BatchEnd]`，并复用已有 writev 段数/字节计数；hold 直方图用于观察延迟。

## 6. A/B 与回归计划

全部通过 `tools/run_m3_isolated.sh`（外层 `unshare --net --mount`，`flock /tmp/ppp-m2-measure.lock`）在实验机运行，
不在本机编译/测试；每组交替顺序（ABBA）、至少 5 轮，报告中位数与离散度。
| 项 | 对照 / 实验 | 通过条件 |
|----|-------------|----------|
| P1 DL 30 s | 关 vs 开，另含 `SEGMENTS=48` | 吞吐不降；writev 次数、平均段数、客户端 CPU 达到预期；`FlushReason::Psh` 占比显著下降 |
| P16 DL 30 s | 同上 | 吞吐不降；多流下无聚合错配（`Incompatible` 不异常升高） |
| P1 UL / P16 UL | 同上（`run_datapath_p1_ul_matrix.sh`） | 回退 ≤ 噪声（沿用 PR #126 并发 UL A/B 判据）；UL 不应改变 |
| 短流时延 | 小请求/响应（1 段、数段）p50/p99/p99.9；含 ping 式 1 字节交互流 | p99 增量 ≤ hold（100 us）量级，p50 不变；超出则调低 hold 或抬高 `MIN_SEGS` |
| 半关闭 / FIN | 单向发送后 FIN、`shutdown(SHUT_WR)` 后对端继续发 | FIN 不早于其前数据；无数据丢失；`Control` flush 计数合理 |
| 重传 / 丢包 | 固定丢包（`datapath_fixed_loss.bpf.c`）下 DL | 吞吐与重传率不劣于关闭；无 seq 重排导致的假重传 |
| 头部正确性 | 抓包比对：关/开两路接收字节流 SHA 一致；检查聚合分段后 PSH 仅出现在末段 | 校验和无错误；`tcpdump` 无 bad csum |
| 守护 | 现有 `spinlock_test`、GSO coalescer 单测补充“混合 PSH”用例（头部位、中间 PSH 丢弃、首段 PSH 清位） | 全部通过 |
| 停止/降级 | 运行中 Ssmt、dispose、写失败降级 | 无泄漏、无重复发送（partial 写不重放保持不变） |

回滚：关闭环境变量即恢复现有行为；无数据格式或配置迁移。

## 7. 未验证项

- DL 热路径是否经过 `TxBatch`（决定方案 A 可行性）。
- 固定开销占比与 Amdahl 假设，需用 `perf` 对比 `tun_get_user` 与 `sock_def_readable` 的按调用/按字节成本。
- 接收端对“丢失中间 PSH”的行为，仅在 Linux 对端验证。
