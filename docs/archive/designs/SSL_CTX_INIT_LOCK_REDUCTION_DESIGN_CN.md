# SSL_CTX 全局初始化锁缩小设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **状态：设计文档，暂不实施。**
> 本文档仅作设计分析和未来实施参考，不触发任何代码行为变更。

| 字段 | 内容 |
|------|------|
| **编号** | P2-18-SSL-LOCK |
| **关联审计项** | `docs/openppp2-deep-code-audit-cn.md` §14.4 P-2 |
| **关联源码** | `ppp/ssl/SSL.cpp`（`CreateClientSslContext`、`CreateServerSslContext`） |
| **创建日期** | 2026-05-11 |
| **当前决策** | **已完成设计文档，暂不实施** |

---

## 1. 背景与动机

### 1.1 问题来源

深度代码审计（§14.4 P-2）指出：客户端 SSL_CTX 创建被全局锁串行化，在 TLS/DoH/DoT 高并发场景下可能退化。

原始审计描述的代码模式：

```cpp
static std::mutex s_ssl_ctx_init_mutex;
std::lock_guard<std::mutex> guard(s_ssl_ctx_init_mutex);

std::shared_ptr<boost::asio::ssl::context> ssl_context =
    make_shared_object<boost::asio::ssl::context>(...);
// CA 加载 / verify mode / cipher suites / X509 sort 均在锁内
```

### 1.2 当前代码实际状态（关键澄清）

**审计描述的 `std::mutex` 模式已在之前的修复中被替换。** 当前代码（`SSL.cpp:224-230`）使用 `std::once_flag` + `std::call_once`：

```cpp
static std::once_flag s_ssl_ctx_init_once;
std::call_once(s_ssl_ctx_init_once, []() noexcept {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx != NULLPTR) {
        SSL_CTX_free(ctx);
    }
});
```

**这正是审计文档 §14.12.2 推荐的修复方案。** 即：

- ✅ 一次性全局 OpenSSL/BoringSSL 初始化已被 `once_flag` 保护
- ✅ CA 加载、cipher 配置、verify_peer 设置、X509_STORE 排序均已移出 openppp2 全局 mutex；其中 X509_STORE 并发排序仍需专项验证
- ✅ 不再存在 `std::mutex` 全局串行化

### 1.3 仍需分析的剩余问题

尽管 P-2 的核心修复（mutex → once_flag）已完成，以下问题仍值得设计文档记录：

1. **DoH/DoT 每次查询创建新 SSL_CTX**：每次 DNS-over-HTTPS / DNS-over-TLS 查询都调用 `CreateClientSslContext` 创建全新的 `SSL_CTX`，包括完整的 CA 加载和解析。高频 DNS 场景下这是可优化点。
2. **X509_STORE 排序的并发安全性**：`sk_X509_OBJECT_sort` 仅在首次查询触发 lazy sort，`once_flag` warmup 不覆盖此路径。
3. **审计文档与代码不一致**：§14.4 P-2 示例代码仍展示 `std::mutex` 模式，需更新为 `once_flag`。

---

## 2. 当前锁保护范围分析

### 2.1 `CreateClientSslContext` 操作分解

| 操作 | 行号 | 是否受锁保护 | 并发安全 | 说明 |
|------|------|-------------|---------|------|
| `once_flag` warmup（`SSL_CTX_new` + `SSL_CTX_free`） | 224-230 | ✅ `once_flag` 保护 | ✅ | 一次性全局初始化，所有线程阻塞直到完成 |
| `make_shared_object<ssl::context>(...)` | 232-234 | ❌ 无锁 | ✅ | `SSL_CTX_new` 内部有 BoringSSL/OpenSSL 内部锁 |
| `load_verify_file(cacert.pem)` | 248-252 | ❌ 无锁 | ✅ | 磁盘 I/O，各 context 独立 |
| `load_root_certificates()` | 267 | ❌ 无锁 | ✅ | 内存解析，各 context 独立 |
| `set_default_verify_paths()` | 285 | ❌ 无锁 | ⚠️ | OpenSSL 内部可能有全局状态初始化 |
| `set_verify_mode()` | 312 | ❌ 无锁 | ✅ | 仅设置 context 属性 |
| `SSL_CTX_set_ciphersuites()` | 318-321 | ❌ 无锁 | ✅ | 仅设置 context 属性 |
| `SSL_CTX_set_cipher_list()` | 323 | ❌ 无锁 | ⚠️ | OpenSSL 内部需解析 cipher string |
| `SSL_CTX_set_ecdh_auto()` | 326 | ❌ 无锁 | ✅ | 仅设置标志位 |
| `sk_X509_OBJECT_sort()` | 348-352 | ❌ 无锁 | ⚠️ | 见 §2.3 分析 |

### 2.2 `CreateServerSslContext` 操作分解

| 操作 | 行号 | 是否受锁保护 | 并发安全 | 说明 |
|------|------|-------------|---------|------|
| 证书/密钥加载 | 161-163 | ❌ 无锁 | ✅ | server 端启动时单次调用 |
| 密码回调设置 | 169-173 | ❌ 无锁 | ✅ | |
| `set_default_verify_paths()` | 185 | ❌ 无锁 | ✅ | 仅服务端，非热路径 |
| cipher 配置 | 192-199 | ❌ 无锁 | ✅ | |

**结论：** Server 端不需要锁缩小——`CreateServerSslContext` 仅在服务启动时调用一次，不在热路径上。

### 2.3 X509_STORE lazy sort 并发安全分析

`sk_X509_OBJECT_sort(objs)` 在 `CreateClientSslContext` 末尾调用（行 348-352），目的是预排序以避免并发 handshake 时的 race condition（详见源码注释）。

**安全性分析：**

- 每个 `SSL_CTX` 有独立的 `X509_STORE`，`objs` 是该 store 的私有对象栈。
- 预排序保证单个 context 返回给调用者前完成排序，避免后续多线程 handshake 首次 lookup 触发 lazy sort。
- 但不同线程并发创建 context 时，仍可能并发执行 `sk_X509_OBJECT_sort(objs)`；该路径与 BoringSSL/OpenSSL 全局 lazy 状态、qsort callback、`OPENSSL_sk_find` 的交互需要 Android 压测/TSan/崩溃复现验证。
- 因此当前只能认为预排序降低了“返回后 lazy sort”风险，不能把锁外并发排序表述为已完全证明安全。

**结论：** `sk_X509_OBJECT_sort` 在 `CreateClientSslContext` 内预排序是必要的低风险防护，但其高并发创建场景仍需专项验证；本文档不将该路径宣称为已完全证明安全。

---

## 3. 退化风险分析

### 3.1 当前已消除的退化

| 退化场景 | 原因 | 当前状态 |
|---------|------|---------|
| 全局 mutex 串行化所有 context 创建 | `std::mutex` 覆盖整个函数 | ✅ 已消除（`once_flag` 仅保护一次性初始化） |
| 锁内包含磁盘 I/O | `load_verify_file` / `load_root_certificates` 在锁内 | ✅ 已消除（均在锁外） |
| 锁内包含 cipher 配置 | `SSL_CTX_set_cipher_list` 在锁内 | ✅ 已消除 |

### 3.2 仍然存在的潜在退化

| 场景 | 严重程度 | 说明 |
|------|---------|------|
| DoH/DoT 每次查询创建新 SSL_CTX | 中 | 每次查询经历完整 CA 加载 + 解析 + store 排序开销。但此为"优化"而非"锁缩小"范畴 |
| `once_flag` 首次初始化阻塞 | 低 | 多线程同时首次调用时，非赢得锁的线程会阻塞直到 warmup 完成。仅发生一次 |
| `set_default_verify_paths()` 可能的内部全局初始化 | 低 | OpenSSL 3.x 有 lazy 全局状态初始化，但有内部锁保护 |

### 3.3 不可退化的关键行为

以下行为在任何锁缩小优化中**必须保持不变**：

1. **Android CA fallback 链**（行 248-286）：
   - 第一优先：`cacert.pem` 文件加载
   - 第二优先：`root_certificates.hpp` 内置 Mozilla CA
   - Android 跳过 `set_default_verify_paths()`
   - 全部失败时 fail-closed（handshake 拒绝，不降级）

2. **Cipher 配置**（行 318-324）：
   - BoringSSL：不设置 cipher list（使用内置默认）
   - OpenSSL：`"HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES"`
   - TLS 1.3 ciphersuites：按平台架构选择

3. **verify_peer 语义**（行 298-312）：
   - Android + verify_peer + 无 CA 来源 → 记录错误码 + fail-closed
   - verify_none → 不验证（用于非安全场景）

4. **X509_STORE 预排序**（行 348-352）：
   - 必须在 context 返回给调用者之前完成
   - 消除并发 handshake 时的 lazy sort race

---

## 4. Android BoringSSL / OpenSSL 差异

### 4.1 条件编译分支

| 宏 | 含义 | 影响 |
|---|---|---|
| `__ANDROID__` | Android 目标平台 | 跳过 `set_default_verify_paths()`；使用 CA fallback 链 |
| `OPENSSL_IS_BORINGSSL` | 使用 BoringSSL 密码库 | 跳过 `SSL_CTX_set_cipher_list()`（BoringSSL 不识别 `"DEFAULT"` 等 OpenSSL alias） |

### 4.2 Android CA 来源链（不可退化）

```
cacert.pem (文件系统)
    ↓ 不存在或加载失败
root_certificates.hpp (编译期内置 Mozilla CA)
    ↓ 解析失败
fail-closed: verify_peer 时 handshake 拒绝
             记录 ErrorCode::SslHandshakeFailed
```

**设计约束：** 任何未来的优化（如 SSL_CTX 复用、连接池化）必须确保 Android 上 CA 来源链的完整性和 fail-closed 语义不被破坏。

### 4.3 BoringSSL 全局初始化特殊性

BoringSSL 的 `SSL_CTX_new()` 会触发全局 lazy 初始化（ASN.1 对象表、错误字符串表等）。`once_flag` warmup 的作用就是让这次全局初始化在受控时机完成，避免并发 `SSL_CTX_new` 时的竞争。

**OpenSSL 3.x** 的全局初始化是线程安全的（有内部 `CRYPTO_ONCE`），但 warmup 仍然有价值——它确保首次 context 创建的延迟发生在启动时而非首次 DoH 查询时。

---

## 5. 可选未来优化方向（设计参考，不实施）

### 5.1 SSL_CTX 复用（连接池化）

**思路：** 对于 DoH/DoT，多个查询可共享同一个 `SSL_CTX`（CA 配置相同）。

**可行性分析：**

| 因素 | 评估 |
|------|------|
| SSL_CTX 线程安全 | ✅ `SSL_CTX` 本身是线程安全的（引用计数、内部锁） |
| CA 配置一致性 | ✅ DoH/DoT 查询使用相同 CA bundle 和 verify_peer 设置 |
| Cipher 一致性 | ✅ 同一 resolver 内 cipher 偏好不变 |
| 生命周期管理 | ⚠️ 需确保 SSL_CTX 在所有使用它的 SSL 连接关闭后才释放 |
| **收益** | 消除每次查询的 CA 加载 + 解析 + store 排序开销 |
| **风险** | 若 CA bundle 需热更新，复用的 context 不会自动刷新 |

**实施方案：**

```cpp
// 伪代码 — 不实施
class DnsResolver {
    // 在 resolver 生命周期内缓存 client SSL context
    std::shared_ptr<boost::asio::ssl::context> cached_client_ssl_ctx_;
    std::once_flag client_ssl_ctx_once_;

    std::shared_ptr<boost::asio::ssl::context> GetOrCreateClientSslContext() {
        std::call_once(client_ssl_ctx_once_, [this]() {
            cached_client_ssl_ctx_ = SSL::CreateClientSslContext(...);
        });
        return cached_client_ssl_ctx_;
    }
};
```

**不实施原因：**

1. 无自动化测试，无法验证复用后 handshake 行为不变
2. 需验证 SSL_CTX 引用计数在异常路径（超时、连接拒绝）下的正确性
3. CA bundle 热更新策略未定义
4. 收益需基准测试量化

### 5.2 合并 warmup 到 Server 端初始化

**思路：** 将 `once_flag` warmup 移到应用启动阶段（server context 创建时），而非延迟到首次 client context 创建。

**评估：** 收益极小（warmup 只执行一次，延迟约 1-5ms），不值得增加启动路径复杂度。

---

## 6. 分阶段实施方案（暂不实施）

### 阶段 0：审计文档同步（本文档）

| 项 | 状态 |
|---|---|
| 创建设计文档 | ✅ 本文档 |
| 更新审计文档 P-2 状态 | 待执行 |
| 更新 P2 治理决策索引 | 待执行 |

### 阶段 1：审计文档校正

**目标：** 使 §14.4 P-2 示例代码与实际代码一致。

**修改内容：**
- §14.4 P-2 代码示例从 `std::mutex` 更新为 `std::once_flag`
- 补充说明 P-2 核心修复已完成
- 保留剩余优化项（SSL_CTX 复用）作为后续方向

### 阶段 2：DoH/DoT SSL_CTX 复用（可选，未来）

**前置条件：**

| 序号 | 条件 | 当前状态 |
|------|------|---------|
| C-1 | 基本集成测试覆盖 DoH/DoT handshake 路径 | ❌ 无测试 |
| C-2 | 并发 handshake 压力测试 | ❌ 无测试 |
| C-3 | CA bundle 热更新策略定义 | ❌ 未定义 |
| C-4 | 性能基准验证 SSL_CTX 复用收益 | ❌ 无基准工具 |

**实施步骤（若条件满足）：**

1. 在 `DnsResolver` 中缓存 client SSL_CTX（`std::shared_ptr` + `std::call_once`）
2. 验证 Android CA fallback 链在复用场景下行为不变
3. 验证 cipher/verify_peer 配置在复用场景下行为不变
4. 验证 SSL_CTX 引用计数在连接超时/拒绝场景下正确
5. 性能基准对比（DoH/DoT QPS、context 创建延迟）

### 阶段 3：审计文档中 P-2 状态更新（阶段 2 完成后）

> **前置条件：阶段 2 代码实现完成且代码复审（code review）通过后，方可执行本阶段。**
> 在此之前，§14.4 P-2 的审计状态应保持为"设计完成 / 待实施"，不得标记为"已完成"。

#### 3.1 状态更新门禁检查项

在执行 §14.4 P-2 审计状态变更之前，必须逐项确认以下门禁条件：

| 序号 | 门禁条件 | 验证方式 | 当前状态 |
|------|---------|---------|---------|
| G-1 | 阶段 2 代码已合入主分支 | `git log` 确认相关 commit 已 merge | ❌ 阶段 2 未实施 |
| G-2 | 阶段 2 代码通过代码复审 | PR review 状态为 approved，无 unresolved comment | ❌ 阶段 2 未实施 |
| G-3 | §8.1 构建验证全部通过 | CI 日志确认 7 variant + Android + Windows + macOS 构建成功 | ❌ 阶段 2 未实施 |
| G-4 | §8.2 功能验证全部通过 | 手动或自动验证 DoH / DoT / TLS / Server SSL 全路径 | ❌ 阶段 2 未实施 |
| G-5 | §8.3 Android 专项验证全部通过 | Android arm64/arm 设备或模拟器验证 CA fallback + fail-closed | ❌ 阶段 2 未实施 |
| G-6 | §8.4 并发验证无 sanitizer 报告 | TSan / Helgrind 报告清洁 | ❌ 阶段 2 未实施 |
| G-7 | 回滚策略已验证可执行 | 确认 `git revert` 或代码回退可恢复到阶段 1 状态 | ❌ 阶段 2 未实施 |

**判定规则：所有 G-1 至 G-7 必须全部通过。任一项未通过则不得执行状态变更。**

#### 3.2 状态更新模板

当 §3.1 所有门禁条件均通过后，在 `docs/openppp2-deep-code-audit-cn.md` §14.4 P-2 中执行以下更新：

**（A）P-2 状态标记变更：**

```markdown
| 字段 | 变更前 | 变更后 |
|------|--------|--------|
| 状态 | 设计完成 / 待实施 | 核心修复已完成，复用优化已记录 |
| 代码状态 | mutex → once_flag 已完成 | + SSL_CTX 复用已完成 |
| 验证状态 | 未验证 | 全平台构建 + 功能 + Android + 并发验证通过 |
| 复审状态 | — | 代码复审已通过（PR #___ approved） |
```

**（B）§14.4 P-2 示例代码更新：**

将示例代码从 `std::mutex` 更新为当前实际代码（`std::once_flag` + SSL_CTX 复用模式），并附注变更说明。

**（C）变更日志条目：**

```markdown
### §14.4 P-2 状态变更日志

- **日期**：____-__-__
- **变更人**：________
- **前置确认**：
  - [ ] 阶段 2 代码已合入（commit: ________）
  - [ ] 代码复审已通过（PR: #________）
  - [ ] §8.1 构建验证：全部通过
  - [ ] §8.2 功能验证：全部通过
  - [ ] §8.3 Android 专项验证：全部通过
  - [ ] §8.4 并发验证：无 sanitizer 报告
  - [ ] 回滚策略已验证
- **变更内容**：§14.4 P-2 状态从"设计完成 / 待实施"更新为"核心修复已完成，复用优化已记录"
- **关联设计文档**：`docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`
```

#### 3.3 同步更新范围

状态变更后需同步更新以下位置：

| 文件 | 更新内容 |
|------|---------|
| `docs/openppp2-deep-code-audit-cn.md` §14.4 P-2 | 状态标记 + 示例代码 + 变更日志 |
| `docs/openppp2-deep-code-audit-cn.md` P2 治理决策索引 | P-2 行状态同步 |
| 本文档（`SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`）§6 阶段 3 行 | 状态从"待执行"更新为"✅ 已完成" |
| 本文档 §6 阶段 0 行"更新审计文档 P-2 状态" | 状态从"待执行"更新为"✅ 已完成" |

#### 3.4 当前状态声明

**阶段 3 当前状态：❌ 未执行（前置条件未满足）**

- 阶段 2（DoH/DoT SSL_CTX 复用）尚未实施
- 阶段 2 前置条件（C-1 至 C-4）均未满足（见 §6 阶段 2）
- 因此 §3.1 门禁条件 G-1 至 G-7 均不通过
- §14.4 P-2 审计状态应保持为"设计完成 / 待实施"

> **严禁在阶段 2 代码未完成或未通过复审的情况下，将 §14.4 P-2 标记为"已完成"。**

---

## 7. 回滚策略

### 7.1 阶段 1（审计文档校正）

- 回滚方式：`git revert` 文档修改
- 影响范围：仅文档，不影响运行代码
- 回滚成本：零

### 7.2 阶段 2（SSL_CTX 复用，若实施）

- **回滚方式：** 移除 `DnsResolver` 中的 context 缓存，恢复每次查询创建新 context
- **回滚触发条件：**
  - DoH/DoT handshake 失败率上升
  - Android 平台出现 CA 验证异常
  - SSL_CTX 引用计数泄漏（内存增长）
- **回滚验证：** 构建 + DoH/DoT/TLS 连接功能验证
- **回滚成本：** 低（代码改动量小，仅 DnsResolver 调用方式变化）

---

## 8. 验证要求（若实施）

### 8.1 构建验证

- [ ] Linux amd64 全部 7 个 variant 构建通过
- [ ] Android arm64/arm 构建通过（BoringSSL 路径）
- [ ] Windows x64 构建通过
- [ ] macOS 构建通过

### 8.2 功能验证

- [ ] DoH 查询：`https://dns.google/dns-query` 或 `https://cloudflare-dns.com/dns-query`
- [ ] DoT 查询：`tls://8.8.8.8:853`
- [ ] TLS 连接：标准 HTTPS 握手
- [ ] Server SSL context：服务端 TLS 接受连接

### 8.3 Android 专项验证

- [ ] `cacert.pem` 存在时 CA 加载成功
- [ ] `cacert.pem` 不存在时 fallback 到 `root_certificates.hpp`
- [ ] `verify_peer=true` + 无 CA 来源 → handshake fail-closed
- [ ] `verify_peer=false` → 正常连接（不验证证书）
- [ ] 无 SIGSEGV（X509_STORE sort / OPENSSL_sk_find）

### 8.4 并发验证

- [ ] 多线程同时调用 `CreateClientSslContext` 不崩溃
- [ ] DoH/DoT 并发查询不出现 handshake 异常
- [ ] 无线程 sanitizer 报告（TSan / Helgrind）

---

## 9. 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|-------|------|---------|
| 审计文档与代码不一致导致后续维护者误解 | 高 | 中 | 阶段 1 校正文档 |
| SSL_CTX 复用后 CA 更新不生效 | 中 | 高 | 阶段 2 前定义热更新策略 |
| SSL_CTX 复用后 Android 行为变化 | 低 | 高 | 阶段 2 Android 专项验证 |
| X509_STORE sort 优化引入新 race | 极低 | 高 | 保持当前预排序设计不变 |

---

## 10. 与其他治理项的关联

| 关联项 | 关系 |
|--------|------|
| P-1（TLS session cache） | 独立。session cache 禁用是不同问题（BoringSSL 并发 crash） |
| S-1（Android CA fallback） | 强关联。锁缩小不得破坏 CA fallback 链 |
| S-2（cipher list BoringSSL 兼容） | 弱关联。cipher 配置已在锁外，不受锁缩小影响 |
| P2-12（Firewall RCU） | 无关联。不同模块 |
| `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md` | 无关联。不涉及 shared_ptr atomic 操作 |

---

## 11. 结论

**P-2 核心修复（mutex → once_flag）已在当前代码中完成。** `CreateClientSslContext` 的 CA 加载、cipher 配置、verify_peer 设置均在锁外并发执行，仅一次性全局 OpenSSL/BoringSSL 初始化受 `once_flag` 保护。

剩余可选优化（SSL_CTX 复用）需在具备集成测试和性能基准后实施，且必须严格验证 Android CA fallback 行为不退化。

本文档不触发任何代码变更。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.4 P-2*
*状态：设计文档，暂不实施*
