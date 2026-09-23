# P2 治理决策记录
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 本文档记录 P2 级代码质量治理项的复核结论。
> P2 项通常为只读复核、文档约束补充，不涉及行为变更。
> 遵循原则：最佳兼容性、最小破坏性、最小侵入性。

---

## P2-13 Android ICMP 错误回送最小路径设计

| 字段 | 内容 |
|------|------|
| **编号** | P2-13-ICMP-ERR |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` B-2（§5.5 / §5.6 协议帧边界检查） |
| **设计文档** | `docs/ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md` |

### 问题描述

`VEthernetNetworkSwitcher::OnIcmpPacketInput()`（第 574 行）对所有非 `ICMP_ECHO`/`ICMP_ER` 类型的 ICMP 报文直接丢弃。这导致 Android 平台上：

- **traceroute 失效**：依赖 Time Exceeded（Type 11）响应
- **PMTUD 失效**：依赖 Destination Unreachable / Frag-Needed（Type 3, Code 4）
- **UDP 快速失败失效**：依赖 Port Unreachable（Type 3, Code 3）

旧实现曾将所有 ICMP 类型通过 `InternetControlMessageProtocol::Echo()` 的 Timer 路径转发，但该路径对非 Echo 类型存在 `EchoAsynchronousContext` 生命周期竞争导致的 use-after-free 崩溃风险，已在审计 B-2 中记录。

### 设计文档内容

`docs/ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md` 涵盖：

- 当前行为与功能影响分析（traceroute、PMTUD、Port Unreachable）
- 旧 Timer 路径崩溃根因分析（`EchoAsynchronousContext::Release()` vs `ReleaseAllPackets()` 并发竞争）
- 非 Echo ICMP 类型优先级矩阵（P0: DUR Code 3/4, TE Code 0; P1: DUR 其他 Code; P2: PP; 不处理: SQ/RD/Timestamp）
- 无 Timer 依赖的直注路径设计（`IcmpErrorPassthrough()` 方法，不创建 raw socket、不写入 `icmppackets_`）
- 速率限制方案（令牌桶 64/秒，使用 `Executors::GetTickCount()` 而非 `Timer`）
- 配置开关方案（`enable_icmp_error_passthrough`，默认 `false`）
- 安全边界分析（5 类威胁及缓解措施、5 层校验层次）
- 与现有 ECHO/ER 路径的隔离矩阵
- 实施步骤、前置条件、风险评估与回滚策略

### 暂不实施的原因

1. **无自动化测试基础设施**：项目零测试。新增的 `IcmpErrorPassthrough()` 路径涉及 TUN 写入，没有回归测试可能引入静默注入错误。
2. **需手动验证 Android TUN 行为**：需确认 `VpnService.establish()` 返回的 TUN fd 接受注入的非 Echo ICMP 错误报文。
3. **默认关闭零风险**：设计文档的配置开关默认 `false`，不实施不影响任何现有行为。
4. **与其它 P2 条目互不依赖**：设计文档已完成，实施时可独立进行。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该项的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持 ECHO/ER 现有路径完全不变（路径隔离矩阵见设计文档 §6.1）。
- 不得恢复旧 Timer 路径处理非 Echo ICMP 类型。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 配置系统支持新增可选 bool 字段 | JSON 解析器应忽略未知字段 | ✅ 已满足 |
| C-2 | `Output(IPFrame*)` 在非 Echo 路径下安全 | 无 Timer/Context 依赖 | ✅ 已满足 |
| C-3 | Android TUN 接受注入的 ICMP 错误 | `VpnService` 不过滤注入报文 | ⚠️ 需手动验证 |
| C-4 | 手动测试覆盖 | traceroute + PMTUD + port-unreachable | ❌ 无自动化测试 |

### 后续触发条件

| 触发条件 | 动作 |
|---|---|
| Android 用户报告 traceroute/PMTUD 不工作 | 评估实施优先级 |
| 引入基本集成测试框架 | 可开始实施 |
| 配置系统重构 | 确保 `enable_icmp_error_passthrough` 字段被纳入新配置模型 |
| IPv6 ICMPv6 错误支持需求 | 扩展设计文档，增加 ICMPv6 类型 |

---

## P2-12 Firewall RCU 规则快照优化设计文档

| 字段 | 内容 |
|------|------|
| **编号** | P2-12-RCU |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §4.6 |
| **设计文档** | `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` |

### 问题描述

P2-12 最小侵入优化（OPT-P2-12b/c）已实施，减少后缀拼接临时分配并移除冗余自拷贝。
剩余较大优化包括：

1. **RCU 规则快照**：使用 `std::atomic_load/store` free functions 实现 C++17 RCU 快照，消除域名表每次查询的 O(N) 深拷贝。
2. **反向 trie / `string_view` 后缀匹配**：替代线性 suffix walk。
3. **单趟 normalize**：替代 `LTrim(RTrim(ToLower(...)))` 三临时串链。

### 设计文档内容

`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` 涵盖：

- 当前问题分析（锁竞争、快照复制开销、后缀匹配线性扫描）
- C++17 RCU 快照方案详设（`FirewallRuleSnapshot` 结构体、读取路径不获取 `Firewall::syncobj_` / `shared_mutex`、写入路径 Copy-Modify-Publish）
- 读写线程安全模型（读取-写入并发安全、写入路径锁保留原因、`atomic_load/store` 行为）
- 为何不用 C++20 `std::atomic<std::shared_ptr<T>>`（项目基线 C++17、free functions vs atomic shared_ptr 对比、迁移路径）
- 语义保持矩阵（必须保持的行为、可接受的变化、不可接受的变化）
- 反向 trie 后缀匹配方案（独立于 RCU 的可选优化）
- 单趟 normalize 方案（独立于 RCU 的可选优化）
- 测试与基准计划（功能正确性、并发正确性、性能基准）
- 五阶段迁移步骤与回滚策略
- 风险评估与实施前置条件

### 暂不实施的原因

1. **无自动化测试基础设施**：项目零测试。RCU 快照修改所有读取路径的核心逻辑，没有回归测试，细微 bug 可能导致所有防火墙查询返回错误结果。
2. **无性能基准工具**：需要基准测试验证 RCU 快照的实际收益，当前项目无基准测试框架。
3. **`ppp::string` / `ppp::unordered_set` 的 move 语义需验证**：快照复制依赖容器的高效 move 构造，需确认不引入意外的深拷贝。
4. **与其它 P2 条目互不依赖**：设计文档已完成，实施时可独立进行。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该项的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持所有 public API 签名不变，保持匹配语义不变。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试存在 | 至少覆盖防火墙查询路径 | ❌ 无测试 |
| C-2 | 性能基准工具存在 | 验证 RCU 快照收益 | ❌ 无基准工具 |
| C-3 | `ppp::string` move 语义确认 | 快照复制依赖高效 move | ⚠️ 需验证 |

---

## P2-17 Android ProtectorNetwork JNI 上下文访问边界复核

| 字段 | 内容 |
|------|------|
| **编号** | P2-17 |
| **当前决策** | **已完成最小代码修复并通过只读复审** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联源码** | `linux/ppp/net/ProtectorNetwork.cpp`、`linux/ppp/net/ProtectorNetwork.h` |
| **关联提交** | `3a370d9`、`bf097fe` |

### 问题描述

Android `ProtectorNetwork` 通过 JNI 调用 Java/Kotlin 层 `VpnService.protect()` 保护 socket，避免连接递归进入 VPN 隧道。
该路径同时维护：

- `jni_`：`std::shared_ptr<boost::asio::io_context>`，由 `JoinJNI()` / `DetachJNI()` 设置或清空。
- `env_`：`JNIEnv*` 裸指针，由同一生命周期路径维护。

原实现存在两个边界问题：

1. `Protect()` Android 分支直接复制 `jni_`，与 `JoinJNI()` / `DetachJNI()` 的写入并发时可能触发 `shared_ptr` 成员 data race。
2. `ProtectJNI(context, ...)` 的 posted lambda 曾在持有 `syncobj_` 时调用 Java/JNI 外部逻辑，存在长持锁、可重入和潜在死锁风险。

### 修复内容

1. `Protect()` 中仅在 `syncobj_` 下 snapshot `jni_` 到局部 `shared_ptr`，随后锁外调用 `ProtectJNI(context, sockfd, y)`。
2. `ProtectJNI(context, ...)` 的 posted lambda 中仅在 `syncobj_` 下 snapshot `jni_` 和 `env_`，随后锁外调用 `ProtectorNetwork::ProtectJNI(env, sockfd)`。
3. `GetContext()` / `GetEnvironment()` 改为在 `syncobj_` 下读取成员。

### 复审结论

- `jni_` 的 `shared_ptr` 读写现在与 `JoinJNI()` / `DetachJNI()` 使用同一把锁保护，避免成员并发读写。
- Java/JNI 外部调用不再发生在 `syncobj_` 临界区内，降低长持锁和死锁风险。
- Android-only 代码仍位于 `_ANDROID` 条件编译范围内。
- `env_` 仍是裸 `JNIEnv*`，本次修复没有改变该既有设计；调用方仍需遵守 JNI 线程/生命周期约束。若后续要进一步增强，应考虑改为基于 `JavaVM*` 的按线程 attach/get-env 模式。
- 最新 6 个提交只读复审已通过，`git diff --check HEAD~6..HEAD` 通过。

### 后续触发条件

| 触发条件 | 动作 |
|---|---|
| `env_` 被跨线程长期缓存或在不同 JNI 线程复用 | 评估迁移到 `JavaVM*` attach/get-env 模式 |
| Java/Kotlin `protect()` 回调新增 native re-entry 路径 | 复核是否仍不存在锁内外部调用 |
| `JoinJNI()` / `DetachJNI()` 生命周期模型变化 | 重新审查 `jni_` / `env_` snapshot 边界 |

---

## P2-16 Dispose/Finalize 分级治理尾项复核

| 字段 | 内容 |
|------|------|
| **编号** | P2-16 |
| **当前决策** | **已完成只读复核：3 个类确认假设成立，仅记录治理约束，不改代码** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §15.2、§15.3 |
| **关联治理项** | P1-2（strand/thread-confined `disposed_` 分级复核） |

### 问题描述

P1-2 已完成 §15.2 中 4 个类的分级复核：
- 2 个类改为 `std::atomic_bool`（VEthernetLocalProxyConnection、VEthernetLocalProxySwitcher）
- 2 个类记录约束不改（InternetControlMessageProtocol、ITransmissionQoS）

§15.3 中 1 个类（Timer）记录为单线程生命周期，保持现状。

P2-16 对上述未修改的 3 个类进行二次只读代码复核，确认：
1. P1-2 记录的约束是否仍然成立
2. 是否存在隐式 atomic bool 读取风格问题（参考 P1-3 WebSocket 案例）
3. 是否需要补充治理约束和后续触发条件

### 复核结果

#### InternetControlMessageProtocol（strand-confined）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/net/asio/InternetControlMessageProtocol.h` / `.cpp` |
| **`disposed_` 类型** | `bool`（plain） |
| **复核结论** | **strand-confined 假设成立，不改** |

**线程模型验证：**

| 路径 | 操作 | 线程 | 验证 |
|------|------|------|------|
| `Echo()` line 364 | 读 `disposed_` | executor 线程 | `Echo()` 由 `VirtualEthernetExchanger::SendEchoToDestination()` 和 `StaticEchoEchoToDestination()` 调用，均在 exchanger 的 executor 线程上；ICMP 协议与 exchanger 共享同一 `io_context` |
| `Finalize()` line 327 | 写 `disposed_` | executor 线程 | `Dispose()` 通过 `boost::asio::post(*context, ...)` 投递 `Finalize()`；析构函数的 `Finalize()` 仅在所有 `EchoAsynchronousContext::owner_` 引用释放后运行 |
| `Dispose()` line 342 | 间接写（post） | 任意线程 → executor | `boost::asio::post` 保证 `Finalize()` 在 executor 线程执行 |

**风格检查：** `if (true == disposed_)` 是 plain bool 读取，非隐式 atomic 转换。无需修改。

#### ITransmissionQoS（mutex-protected）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/transmissions/ITransmissionQoS.h` / `.cpp` |
| **`disposed_` 类型** | `bool`（plain） |
| **复核结论** | **mutex-protected 假设成立，不改** |

**锁保护验证：**

| 方法 | `disposed_` 操作 | 锁保护 | 验证 |
|------|------------------|--------|------|
| `ReadBytes()` line 89 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |
| `EndRead()` line 128 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `else` 分支内 |
| `BeginRead()` line 146 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |
| `Finalize()` line 182 | 写 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |

**原子成员说明：** `bandwidth_`（`std::atomic<Int64>`）和 `traffic_`（`std::atomic<UInt64>`）用于无锁跨线程读取（`IsPeek()`、`GetBandwidth()`），与 `disposed_` 的锁保护模式不矛盾。

**风格检查：** 所有 `disposed_` 读写均在锁内，无隐式 atomic 转换问题。

#### Timer（single-thread）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/threading/Timer.h` / `.cpp` |
| **`_disposed_` 类型** | `bool`（plain） |
| **复核结论** | **单线程假设成立，不改** |

**线程模型验证：**

| 路径 | 操作 | 线程 | 验证 |
|------|------|------|------|
| `Start()` line 86 | 读 `_disposed_` | executor 线程 | `Start()` 由用户代码在 executor 线程调用 |
| `Next()` line 120 | 读 `_disposed_` | executor 线程 | `Next()` 由 async_wait 回调调用，运行在 executor 线程 |
| `Finalize()` line 53/59 | 写 `_disposed_` | executor 线程 | `Dispose()` 通过 `boost::asio::post` 投递；析构函数在所有 `shared_ptr` 释放后运行（async_wait 回调持有 `self` 引用） |

**`tick_event_guard_` 说明：** `tick_event_guard_`（`std::atomic<bool>`）是独立的回调许可开关。`OnTick()` 在执行用户回调前读取该 guard，`Finalize()` 清除该 guard 并释放回调表。跨线程 `Dispose()` 是允许路径，会通过 `boost::asio::post` 回到 executor 执行 `Finalize()`；若未来出现析构或直接 `Finalize()` 不再满足 executor 生命周期约束的路径，需要重新评估。该 guard 与 `_disposed_` 的 plain `bool` 设计不矛盾——`_disposed_` 的正常读写都在 executor 线程上，不需要 atomic。

**风格检查：** `_disposed_` 是 plain bool 读取，非隐式 atomic 转换。`tick_event_guard_` 已使用显式 `load(acquire)` / `store(release)` 风格。

### 治理文档补充

| 文件 | 修改 | 描述 |
|------|------|------|
| `docs/p2-governance-decisions-cn.md` | 新增治理记录 | 记录 `disposed_` 线程模型复核结果、后续触发条件和非阻断约束 |
| `docs/openppp2-deep-code-audit-cn.md` | 更新 §15 | 同步 P2-16 复核状态，不宣称全仓生命周期治理完全完成 |

### 未变更项

- **未改变任何 `disposed_` 类型**：3 个类的 `disposed_` 保持 plain `bool`。
- **未改变任何业务逻辑**：仅补充治理文档。
- **未改变 public API**：所有类的 public/protected 接口签名不变。
- **未改变 Finalize 调用顺序**：保持原有 cleanup 顺序。
- **未原子化**：确认无需原子化的类保持原样。

### 后续触发条件

| 触发条件 | 影响类 | 动作 |
|---|---|---|
| `InternetControlMessageProtocol::Echo()` 被从非 executor 线程调用 | InternetControlMessageProtocol | 升级 `disposed_` 为 `std::atomic_bool` |
| `ITransmissionQoS` 的 `disposed_` 出现锁外读写路径 | ITransmissionQoS | 升级 `disposed_` 为 `std::atomic_bool` 或将锁外路径纳入锁保护 |
| `Timer` 被跨线程直接调用 `Start()`/`Stop()`/mutating setter，或析构路径不再满足 executor 生命周期约束 | Timer | 重新评估并按需升级 `_disposed_` 为 `std::atomic_bool` |
| 新增使用 `disposed_` + `Finalize()` 模式的类 | 新类 | 按 §15.1–§15.3 分级评估 |

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 本文档仅作记录用途，不触发代码行为变更。
- 本文档和 `docs/openppp2-deep-code-audit-cn.md` §15 的修改与其他 P1/P2 条目互不依赖。

---

## P2-18 SSL_CTX 全局初始化锁缩小设计文档

| 字段 | 内容 |
|------|------|
| **编号** | P2-18-SSL-LOCK |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.4 P-2 |
| **设计文档** | `docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md` |

### 问题描述

审计 §14.4 P-2 指出客户端 `SSL_CTX` 创建被全局锁串行化，TLS/DoH/DoT 高并发可能退化。

### 设计文档内容

`docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md` 涵盖：

- **当前代码状态澄清**：P-2 核心修复（`std::mutex` → `std::once_flag`）已在当前代码中完成，审计文档示例代码需同步更新
- 当前锁保护范围分析（`CreateClientSslContext` 操作分解、`once_flag` 保护范围 vs 并发范围）
- X509_STORE lazy sort 并发安全性分析
- 退化风险分析（已消除 vs 仍存在的）
- Android BoringSSL / OpenSSL 差异与 CA fallback 不可退化约束
- SSL_CTX 复用优化方向（DoH/DoT 共享 context）
- 分阶段实施方案与前置条件
- 回滚策略与验证要求

### 暂不实施的原因

1. **P-2 核心修复已完成**：`once_flag` 已消除全局 mutex 串行化，CA 加载/配置已在锁外并发执行。
2. **剩余优化（SSL_CTX 复用）需基础设施支撑**：无集成测试、无并发压测、无性能基准，无法验证复用后行为不变。
3. **Android CA fallback 行为需专项验证**：复用场景下 CA 来源链和 fail-closed 语义必须端到端验证。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入 SSL_CTX 复用的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持 Android CA fallback 链、cipher 配置、verify_peer 语义完全不变。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试存在 | 至少覆盖 DoH/DoT handshake 路径 | ❌ 无测试 |
| C-2 | 并发压测存在 | 验证多线程 context 创建/handshake 安全 | ❌ 无测试 |
| C-3 | CA 热更新策略定义 | SSL_CTX 复用时 CA bundle 更新机制 | ❌ 未定义 |
| C-4 | 性能基准工具存在 | 验证 SSL_CTX 复用收益 | ❌ 无基准工具 |

---

## P2-19 Android DoH/DoT TLS Session Cache 设计分析

| 字段 | 内容 |
|------|------|
| **编号** | P2-19-TLS-CACHE |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.4 P-1 |
| **设计文档** | `docs/ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md` |

### 问题描述

审计 §14.4 P-1 声称 Android 上 `AcquireTlsSession` / `StoreTlsSession` 被 `#if defined(__ANDROID__)` 守卫禁用，导致每次 DoH/DoT 查询做完整 TLS 握手。

**代码考古结论：** 在当前可用 git 历史/refs 中未发现该守卫；`git log --all -S "__ANDROID__" -- ppp/dns/DnsResolver.cpp` 无匹配。TLS session cache 在当前可见历史中自引入之日起（commit `a35bb74`）即在所有平台生效。commit `ab00160` 对其实现进行了重大加固（LRU 驱逐、`CompletionState` 集中资源所有权、`SSL_SESSION_up_ref` 生命周期修正）。

### 设计文档内容

`docs/ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md` 涵盖：

- 审计文档 P-1 与实际代码状态的差异澄清（代码考古）
- 当前实现分析（数据结构、线程安全模型、引用计数生命周期、cache key 设计）
- 方案 A：加固现有实现（session TTL、telemetry 增强、cache key 协议隔离）
- 方案 B：连接复用 / 连接池（DoH keep-alive、DoT 连接复用）
- 方案 C：Telemetry-only 观测阶段
- 安全边界（SNI/host 绑定、证书验证不可跳过、cache key 隔离、过期策略、线程/strand 所有权）
- 验证矩阵（功能正确性、并发安全性、多 endpoint、失败回退、性能基线）
- 实施前置条件与推荐路径

### 暂不实施的原因

1. **审计文档 P-1 描述与实际代码不符**：需先澄清审计文档，避免基于错误前提实施改动。
2. **当前静态审查未发现明显实现错误**：线程安全、引用计数、LRU 驱逐模型看起来合理，但仍需 Android/BoringSSL 真机、sanitizer 与 telemetry 验证。
3. **无 Android 真机/模拟器测试环境**：无法验证 BoringSSL session cache 行为。
4. **无自动化测试基础设施**：项目零测试，无法回归验证。
5. **Telemetry 基线未收集**：缺乏 session reuse 实际数据支撑优化决策。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入 session cache 加固的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持 TLS 握手行为、证书验证语义、Android CA fallback 链完全不变。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | Android 真机测试环境 | arm64 设备，Android 10+ | ❌ 未配置 |
| C-2 | Android 模拟器环境 | x86_64 模拟器，API 29+ | ❌ 未配置 |
| C-3 | BoringSSL 版本确认 | 确认 NDK r20b 对应的 BoringSSL 版本及已知 session cache bug | ❌ 未确认 |
| C-4 | ASan / HWASan 构建 | Android 构建启用 AddressSanitizer | ❌ 未配置 |
| C-5 | Telemetry 基线 | 收集当前 session reuse 指标作为基线 | ❌ 未收集 |

---

## P2-20 CompletionState 类型安全化设计文档

| 字段 | 内容 |
|------|------|
| **编号** | P2-20-TYPE-SAFE |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-12 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.6 S-3（slot 类型擦除）、§14.9 A-2（CompletionState/StunCompletionState 重复）、§14.7 B-3（slot0 复用） |
| **设计文档** | `docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md` |

### 问题描述

`CompletionState` 使用 `std::shared_ptr<void> slot0..slot3` 作为通用槽位，类型语义完全依赖注释和调用约定。`std::static_pointer_cast<T>` 失去编译期类型校验，后续若调整槽位顺序会无声地把指针解释为错误类型（审计 S-3）。DoT 和 TCP 存在 `slot0` 复用（request → response），依赖异步链执行顺序的隐式契约（审计 B-3）。

### 设计文档内容

`docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md` 涵盖：

- 各协议（DoH、DoT、UDP、TCP、STUN）slot 使用模式逐行分析与汇总表
- 四类风险分析：类型安全缺失、slot0 复用隐式契约、结构体重复、生命周期/线程安全交互
- 方案 A：`std::variant` / 类型化 payload（编译期安全，中等变更量）
- 方案 B：继承式专用状态结构（`DohCompletionState` / `DotCompletionState`，编译期安全，大变更量）
- 方案 C：小步 helper accessor / 命名字段过渡（最小侵入，但仍需评审/复核）
- 三方案对比矩阵（类型安全、变更量、侵入性、lambda 捕获兼容性、前置条件）
- 生命周期、异步 lambda 捕获、strand/线程边界、slot0 复用的详细分析
- 实施路径建议（短期方案 C → 中期方案 A/B）与前置条件

### 暂不实施的原因

1. **无自动化测试基础设施**：项目零测试。方案 A/B 改变 CompletionState 结构和 lambda 捕获类型，没有回归测试可能引入静默生命周期错误。
2. **当前未发现直接运行时错误证据**：当前源码采用集中状态持有和 CAS 单次完成模型；但本文档仅为静态设计记录，不声明已完成 Android 真机回归验证。
3. **方案 C 可独立实施**：accessor 封装不改变运行时行为，但需要维护者纪律确保新增协议时使用 accessor。
4. **与其它 P2 条目互不依赖**：设计文档已完成，实施时可独立进行。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该重构的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持 `CompletionState::Complete()` 的 CAS 单次执行语义不变。
- 实施时必须保持 I/O 资源由 `CompletionState` 集中持有，并避免在 lambda 中分散捕获 socket/stream/timer/buffer 所有权。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试 | 至少覆盖 DoH/DoT/UDP/TCP/STUN 端到端路径 | ❌ 无测试 |
| C-2 | 逐调用点复核 | 确认所有 slot 赋值/读取点与设计文档分析一致 | ⚠️ 需实施前复核 |
| C-3 | 方案 C 可独立实施 | accessor 不改变运行时行为 | ✅ 可行（仍需谨慎） |

### 后续触发条件

| 触发条件 | 动作 |
|---|---|
| 引入基本集成测试框架 | 可开始评估方案 A 或 B 并回归验证 |
| 新增 DNS 协议（如 DoQ） | 必须更新 slot 使用模式文档，评估是否需要更多 slot |
| slot0 复用引发实际 bug | 立即实施方案 C 消除复用 |
| DnsResolver 文件拆分（审计 A-3） | 同步实施方案 B（继承） |
| 升级 C++20 | 方案 A 的 `std::visit` 更简洁 |

---

## P2-21 DoH/DoT 异步链 slot0 复用风险设计文档

| 字段 | 内容 |
|------|------|
| **编号** | P2-21-SLOT-REUSE |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-12 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.7 B-3、§14.6 S-3 |
| **关联治理项** | P2-20（CompletionState 类型安全化设计，slot0 复用为其子集问题） |
| **设计文档** | `docs/DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md` |

### 问题描述

`SendDot` 和 `SendTcp` 的异步链中，`CompletionState::slot0` 在查询生命周期内先持有 request buffer（供 `async_write` 引用），后在 write handler 的 read-length handler 中被覆盖为 response buffer。此复用依赖以下隐式假设：

1. `async_write` completion handler 在 write 完成后才被调用（Asio 保证）。
2. write handler 内部的 `async_read`（长度前缀）完成后才执行 slot0 覆盖（嵌套 handler 顺序）。
3. write 完成后 Asio 不再持有 request buffer 的引用（`boost::asio::buffer()` 是非拥有的）。

当前静态审查未发现已触发的 UAF 证据；slot0 复用依赖 Asio completion 语义与当前 handler 嵌套顺序，这些假设是**时序保证**而非**所有权保证**，仍需在实施、重构或 Asio 版本升级前复核。DoH 链不涉及此问题——它使用 `slot0`（http_req）、`slot1`（read_buf）、`slot2`（http_res）三个独立槽位。

### 设计文档内容

`docs/DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md` 涵盖：

- DoT/TCP 链 slot0 复用的完整代码位置分析（含行号对照表）
- DoH 链不涉及此问题的说明（使用 slot0/1/2 独立槽位）
- 隐式契约四要素分析（Asio write completion 语义、handler 嵌套顺序、buffer 非拥有视图、shared_ptr 延长生命周期）
- 四类风险分析（潜在 UAF 条件、handler 顺序变更、重构脆弱性、可读性/调试困难）
- 三种修复方案对比：
  - **方案 A（推荐）**：分离 `request_buf` / `response_buf` 命名字段
  - **方案 B**：write handler 后显式释放 request（收益不足）
  - **方案 C**：typed state 子类（与 S-3 / P2-20 合并实施）
- 推荐路径：当前仅记录设计；待测试/验证条件具备后，优先评估方案 A，后续与 CompletionState 类型安全化（S-3 / P2-20）合并升级为 typed fields
- 修复影响评估（行为/API/性能/兼容性/测试）
- 实施前置条件与后续触发条件

### 暂不实施的原因

1. **当前未发现已触发的 UAF 证据**：slot0 复用依赖 Asio completion 语义与当前 handler 嵌套顺序；这些依赖仍需在实施/重构前复核。
2. **无自动化测试基础设施**：项目零测试，DoT/TCP 异步链的手动验证成本高。
3. **与 P2-20（类型安全化）存在实施路径依赖**：方案 A 是 P2-20 的子集，合并实施效率更高。
4. **风险等级为"低"**：不构成 P0 阻断，不涉及安全漏洞或数据损坏。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该项的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 不得声称该问题已修复。
- 实施时必须保持 DoH/DoT/TCP/UDP 所有协议链的行为完全不变。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 理解所有 slot 使用点 | 确认各协议链的 slot 语义 | ✅ 已完成 |
| C-2 | 确认无外部代码依赖 slot 编号 | `CompletionState` 是内部 struct | ✅ 已确认 |
| C-3 | 手动测试覆盖 DoT/TCP 路径 | 验证修改后查询正常 | ❌ 无自动化测试 |
| C-4 | 与 P2-20 实施计划对齐 | 确保命名字段方案与长期 typed state 方向一致 | ⚠️ 需对齐 |

### 后续触发条件

| 触发条件 | 动作 |
|---|---|
| CompletionState 类型安全化设计启动（P2-20） | 将方案 A 作为子集纳入 |
| Boost.Asio 版本升级 | 复核 write completion 语义是否变更 |
| DoT/TCP 异步链重构 | 必须同时评估并优先纳入方案 A |
| 引入自动化测试框架 | 可开始评估方案 A 并回归验证 |
| 发现 write handler 在 write 完成前被调用的证据 | 立即升级为 P0 |

---

*创建时间：2026-05-11（初版） / 2026-05-12（追加 P2-20、P2-21）*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.6、§14.7、§14.9、§15*
