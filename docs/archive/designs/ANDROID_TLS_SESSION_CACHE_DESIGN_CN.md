# Android DoH/DoT TLS Session Cache 设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 编号：P2-19-TLS-CACHE
> 状态：**设计文档，暂不实施**
> 决策日期：2026-05-11
> 关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.4 P-1
> 关联源码：`ppp/dns/DnsResolver.h`、`ppp/dns/DnsResolver.cpp`、`ppp/ssl/SSL.cpp`
> 语言标准：C++17

---

## 1. 文档性质声明

**本文档为设计分析与加固建议文档，暂不实施。**

本文档不声称已"恢复"TLS session cache——在当前可用 git 历史/refs 中，未发现审计文档 §14.4 P-1 描述的 `#if defined(__ANDROID__)` 禁用守卫；`git log --all -S "__ANDROID__" -- ppp/dns/DnsResolver.cpp` 无匹配。TLS session cache 在当前可见历史中自引入之日起（commit `a35bb74`）即在所有平台（含 Android）上生效。后续 commit `ab00160` 对其实现进行了重大加固（LRU 驱逐、`CompletionState` 集中资源所有权、`SSL_SESSION_up_ref` 生命周期修正）。

本文档的目的：
1. 澄清审计文档 P-1 与实际代码状态的差异
2. 分析当前实现的安全性与性能特征
3. 提供后续加固方案供实施时参考
4. 定义验证矩阵供真机/模拟器测试时使用

---

## 2. 审计文档 P-1 与实际代码状态

### 2.1 审计文档描述

审计 §14.4 P-1 声称 `AcquireTlsSession` / `StoreTlsSession` 包含如下守卫：

```cpp
// 审计文档描述的代码（当前可用 git 历史/refs 中未发现）
ssl_session_st* DnsResolver::AcquireTlsSession(const ppp::string& host_key) noexcept {
#if defined(__ANDROID__)
    (void)host_key;
    return NULLPTR;
#endif
    // ...
}
```

### 2.2 代码考古结论

| 检查项 | 结果 |
|--------|------|
| 当前 HEAD 是否包含 `__ANDROID__` 守卫 | **否** |
| commit `a35bb74`（首次引入 TLS cache）是否包含 | **否** |
| commit `ab00160~1`（加固前）是否包含 | **否** |
| `git log --all -S "__ANDROID__" -- ppp/dns/DnsResolver.cpp` | **无匹配** |
| 审计文档声称的行号（669-697）是否匹配 | **否**（实际为 674-736） |

**结论：** 审计文档 P-1 描述的 `__ANDROID__` 禁用守卫在当前可用 git 历史/refs 中未发现。TLS session cache 在当前可见历史中一直在 Android 上生效。

### 2.3 可能的解释

1. 审计文档可能基于一个未推送的本地分支或临时补丁编写
2. 审计文档可能基于外部参考（如其他 fork）而非本仓库
3. 审计文档的代码摘录可能为示意性伪代码，非实际代码

无论原因如何，本文档以**实际仓库代码**为分析基准。

---

## 3. 当前实现分析

### 3.1 数据结构

```cpp
// ppp/dns/DnsResolver.h:355-362
struct TlsSessionCacheEntry {
    ssl_session_st*                     session = NULLPTR;
    ppp::list<ppp::string>::iterator    lru;
};

mutable std::mutex                              tls_session_mutex_;
ppp::list<ppp::string>                          tls_session_lru_;
ppp::unordered_map<ppp::string, TlsSessionCacheEntry> tls_session_cache_;
```

| 属性 | 值 |
|------|-----|
| 缓存容量上限 | 32（`PPP_DNS_TLS_SESSION_CACHE_LIMIT`） |
| 驱逐策略 | LRU（`tls_session_lru_` 链表头部为最近使用） |
| 线程安全 | `std::mutex`（`tls_session_mutex_`） |
| Cache key | `"<SNI hostname>:<port>"` |
| 生命周期管理 | `SSL_SESSION_up_ref` / `SSL_SESSION_free` |

### 3.2 线程安全模型

| 操作 | 锁保护 | 说明 |
|------|--------|------|
| `AcquireTlsSession` | ✅ `std::lock_guard<std::mutex>` | 查找 + up-ref + LRU 提升 |
| `StoreTlsSession` | ✅ `std::lock_guard<std::mutex>` | 插入/替换 + LRU 驱逐 |
| 析构函数 | ✅ `std::lock_guard<std::mutex>` | 遍历释放所有 `SSL_SESSION*` |
| `SendDoh` / `SendDot` 中的 `SSL_set_session` | ❌ 无锁（正确） | 在锁外调用，`SSL_set_session` 内部 up-ref |
| `SendDoh` / `SendDot` 中的 `SSL_get1_session` | ❌ 无锁（正确） | 在锁外调用，返回 up-ref'd 指针后传入 `StoreTlsSession` |

**静态审查评估：** 线程安全模型未发现明显问题。`AcquireTlsSession` 返回 up-ref'd 指针后，调用方在锁外使用该指针应由 `SSL_SESSION` 引用计数保证生命周期；`StoreTlsSession` 接管调用方的引用。仍需 Android/BoringSSL 真机与 sanitizer 验证。

### 3.3 引用计数生命周期

```
AcquireTlsSession:
  mutex.lock()
  session = cache[key]          // cache 持有 ref
  SSL_SESSION_up_ref(session)   // refcount++
  mutex.unlock()
  return session                // 调用方持有 ref

调用方:
  SSL_set_session(ssl, session) // SSL 内部 up-ref
  SSL_SESSION_free(session)     // 释放调用方的 ref

StoreTlsSession:
  mutex.lock()
  old = cache[key]
  if old: SSL_SESSION_free(old) // 释放旧 ref
  cache[key] = new_session      // 接管新 ref
  mutex.unlock()
```

**静态审查评估：** 引用计数生命周期未发现明显 double-free 或泄漏风险；仍需 Android/BoringSSL 真机与 sanitizer 验证。

### 3.4 Cache Key 设计

```cpp
// SendDoh (line 1356-1358)
ppp::string host_key;
if (!sni_name.empty()) {
    host_key.append(sni_name).append(":").append(stl::to_string<ppp::string>(static_cast<int>(remote.port())));
}

// SendDot (line 1634-1636)
ppp::string host_key;
if (!entry.hostname.empty()) {
    host_key.append(entry.hostname).append(":").append(stl::to_string<ppp::string>(static_cast<int>(remote.port())));
}
```

| 属性 | 评估 |
|------|------|
| SNI 绑定 | ✅ 使用 `sni_name`（DoH）或 `entry.hostname`（DoT） |
| 端口隔离 | ✅ 包含端口号 |
| 协议隔离 | ⚠️ 不同协议（DoH/DoT）若使用相同 hostname:port，共享缓存条目 |
| IP 地址隔离 | ⚠️ 同一 hostname 多 IP 场景下，不同 IP 的连接共享缓存 |

### 3.5 证书验证与 Session Resume 的交互

**关键安全约束：** TLS session cache 不得改变 `verify_peer` 和 hostname verification 的配置，也不得允许 resume 绕过初始会话建立时的证书链与主机名校验。

TLS 1.2/1.3 session resumption / PSK 场景下，是否重新发送并完整验证证书链取决于协议版本、握手类型和库实现策略。因此本文档不声称“每次 resume 都会重新验证证书链”。后续实施或加固时必须通过 Android/BoringSSL 真机验证确认当前 `verify_peer`、SNI 和 hostname verification 前置条件在 resume 路径上不被绕过。

当前代码中，`SSL_CTX` 每次查询重新创建（`CreateClientSslContext`），verify 模式和 CA 来源在 context 创建时设置，与 session cache 无关。

---

## 4. 方案设计

### 方案 A：加固现有实现（推荐）

从静态代码审查看，当前实现未发现明显线程安全或引用计数问题；以下为可选加固项，仍需 Android/BoringSSL 真机、sanitizer 与 telemetry 验证：

#### A.1 Session 过期策略

当前实现无时间过期——仅靠 LRU 驱逐。建议增加 `SSL_SESSION` 超时检查：

```cpp
// 伪代码（不实施）
ssl_session_st* DnsResolver::AcquireTlsSession(const ppp::string& host_key) noexcept {
    // ... 现有逻辑 ...
    SSL_SESSION* session = reinterpret_cast<SSL_SESSION*>(it->second.session);

    // 检查 session 是否过期（例如 300 秒）
    if (SSL_SESSION_get_time(session) + PPP_DNS_TLS_SESSION_TTL_SECONDS < time(NULL)) {
        // 过期：移除并返回 nullptr
        SSL_SESSION_free(session);
        tls_session_lru_.erase(it->second.lru);
        tls_session_cache_.erase(it);
        return NULLPTR;
    }

    // ... 现有 up-ref 逻辑 ...
}
```

| 参数 | 建议值 | 说明 |
|------|--------|------|
| `PPP_DNS_TLS_SESSION_TTL_SECONDS` | 300（5 分钟） | 与典型 DNS TTL 对齐，避免使用过期 session |

**风险：** 低。仅在 `AcquireTlsSession` 中增加一次 `SSL_SESSION_get_time` 调用。

#### A.2 Telemetry 增强

当前已有基础 telemetry（`dns.tls.session_reuse_attempt`、`dns.tls.session_reused`）。建议增加：

| 指标 | 说明 |
|------|------|
| `dns.tls.session_cache_evict` | LRU 驱逐次数 |
| `dns.tls.session_expired` | 因 TTL 过期被丢弃次数 |
| `dns.tls.session_upref_fail` | `SSL_SESSION_up_ref` 失败次数 |
| `dns.tls.session_cache_size` | 当前缓存大小（定期采样） |

**风险：** 极低。仅增加 telemetry 计数器。

#### A.3 Cache Key 协议隔离（可选）

当前 DoH 和 DoT 共享同一 cache key 空间。对于使用相同 hostname:port 的场景（罕见但可能），可增加协议前缀：

```cpp
// 伪代码（不实施）
ppp::string host_key;
host_key.append(is_doh ? "doh:" : "dot:");
host_key.append(sni_name).append(":").append(port_str);
```

**风险：** 低。仅改变 cache key 格式，不影响 TLS 行为。

### 方案 B：连接复用 / 连接池

在 session cache 之上，进一步复用 TCP 连接（HTTP/1.1 keep-alive 或 HTTP/2 多路复用）。

#### B.1 DoH HTTP/1.1 Keep-Alive

当前实现每次 DoH 查询创建新的 TCP 连接 + TLS 握手。HTTP/1.1 支持 keep-alive，可在同一连接上发送多个请求。

```
当前：query → connect → TLS handshake → HTTP POST → response → close
优化：query → [复用已有连接] → HTTP POST → response → [保持连接]
```

| 属性 | 说明 |
|------|------|
| 连接池大小 | 每 upstream 1-2 个连接 |
| 空闲超时 | 30-60 秒 |
| 最大请求数 | 可选限制（如 100 请求/连接） |

**风险：** 中。需要修改 `SendDoh` 的异步链，引入连接池生命周期管理、空闲检测、连接健康检查。`CompletionState` 资源模型需要适配。

#### B.2 DoT 连接复用

DoT（DNS over TLS）使用 TCP 2-Byte 长度前缀协议，天然支持多查询复用同一连接。

```
当前：query → connect → TLS handshake → send → recv → close
优化：query → [复用已有连接] → send → recv → [保持连接]
```

**风险：** 中。同 B.1，需引入连接池。

#### B.3 方案 B 与方案 A 的关系

方案 B 是方案 A 的**超集**——连接复用自然减少了 TLS 握手次数，使得 session cache 的价值降低。但 session cache 仍有价值：
- 连接池中的连接可能因网络变化被断开
- 首次连接仍需 session cache 来加速握手
- 连接池有容量限制，溢出时仍需新建连接

### 方案 C：Telemetry-Only 观测阶段

在实施任何优化前，先通过 telemetry 收集实际数据。

#### C.1 观测指标

| 指标 | 说明 | 当前状态 |
|------|------|----------|
| `dns.tls.session_reuse_attempt` | 尝试复用 session 的次数 | ✅ 已有 |
| `dns.tls.session_reused` | 实际复用成功的次数 | ✅ 已有 |
| `dns.tls.session_reuse_attempt - dns.tls.session_reused` | 复用失败次数 | 可推导 |
| cache hit rate | `session_reuse_attempt / total_tls_handshakes` | 需新增分母 |
| 平均 TLS 握手耗时 | 需要端到端计时 | ❌ 未有 |
| session resume vs full handshake 耗时对比 | 需要分类计时 | ❌ 未有 |

#### C.2 Android 特定观测

| 观测项 | 说明 |
|--------|------|
| BoringSSL 版本 | 确认与 NDK 版本的对应关系 |
| TLS 1.3 ticket 生命周期 | BoringSSL 默认 ticket 超时 |
| `SSL_SESSION_get_time` 返回值分布 | 验证 session 是否在合理时间内被复用 |
| 并发 handshake 数量 | 评估锁竞争压力 |

**风险：** 极低。仅增加 telemetry，不改变任何行为。

---

## 5. 安全边界

### 5.1 SNI / Host 绑定

| 约束 | 当前状态 | 说明 |
|------|----------|------|
| Cache key 包含 SNI hostname | ✅ | `sni_name`（DoH）或 `entry.hostname`（DoT） |
| Cache key 包含端口 | ✅ | `remote.port()` |
| 空 hostname 时跳过缓存 | ✅ | `host_key.empty()` 检查 |

### 5.2 证书验证不可跳过

| 约束 | 当前状态 | 说明 |
|------|----------|------|
| `verify_peer` 设置独立于 session cache | ✅ | `SSL_CTX` 每次新建，verify 模式在 context 创建时设置 |
| `host_name_verification` 独立于 session cache | ✅ | 在 `SendDoh`/`SendDot` 中通过 `set_verify_callback` 设置 |
| Session cache 不改变 `verify_peer` / hostname verification 配置 | ✅ | 当前配置与 cache 逻辑独立；resume 行为仍需 Android/BoringSSL 真机验证 |

### 5.3 Cache Key 隔离

| 约束 | 当前状态 | 说明 |
|------|----------|------|
| 不同 hostname 隔离 | ✅ | hostname 是 key 的主要部分 |
| 不同端口隔离 | ✅ | 端口是 key 的一部分 |
| 不同协议隔离 | ⚠️ | DoH/DoT 共享 key 空间（方案 A.3 可修复） |
| 不同 IP 隔离 | ⚠️ | 同 hostname 多 IP 共享缓存（方案 A.1 的 TTL 可缓解） |

### 5.4 过期策略

| 约束 | 当前状态 | 说明 |
|------|----------|------|
| LRU 驱逐 | ✅ | 容量上限 32，超出时驱逐最久未用 |
| 时间过期 | ❌ | 无 TTL（方案 A.1 可修复） |
| BoringSSL 内部过期 | ✅ | BoringSSL 自身有 session ticket 超时 |

### 5.5 线程 / Strand 所有权

| 约束 | 当前状态 | 说明 |
|------|----------|------|
| Cache 读写受 mutex 保护 | ✅ | `tls_session_mutex_` |
| `SSL_SESSION` 引用计数 | ⚠️ | 静态审查未发现明显问题；需 sanitizer/真机验证 |
| 锁外 SSL 操作 | ⚠️ | `SSL_set_session` / `SSL_get1_session` 在锁外调用；需 Android/BoringSSL 行为验证 |
| `CompletionState` 资源所有权 | ✅ | 所有 async lambda 仅 capture `[state]`，资源在 `Complete()` 中集中管理 |

---

## 6. 验证矩阵

> **注意：以下矩阵仅供后续真机/模拟器验证时参考，本文档不实际执行任何验证。**

### 6.1 功能正确性

| 测试项 | 环境 | 预期结果 |
|--------|------|----------|
| DoH 查询 → session 缓存 → 第二次 DoH 查询复用 | Android 真机 | 第二次握手为 resume（`SSL_session_reused == 1`） |
| DoT 查询 → session 缓存 → 第二次 DoT 查询复用 | Android 真机 | 同上 |
| DoH 查询 → session 过期 → 第二次 DoH 查询 full handshake | Android 真机 + 人为延迟 | 第二次握手为 full（`SSL_session_reused == 0`） |
| 缓存容量溢出（>32 条目） | 模拟器 | LRU 驱逐生效，无内存泄漏 |
| `DnsResolver` 析构时缓存清理 | 模拟器 | 所有 `SSL_SESSION*` 被释放，无 ASan 报告 |

### 6.2 并发安全性

| 测试项 | 环境 | 预期结果 |
|--------|------|----------|
| 4 线程并发 DoH 查询（不同 upstream） | Android 真机 | 无 crash、无 ASan 报告 |
| 4 线程并发 DoH 查询（相同 upstream） | Android 真机 | 无 crash、session cache 命中率 > 0 |
| DoH + DoT 并发（相同 hostname） | Android 真机 | 无 crash |
| `DnsResolver` 析构期间有 in-flight 查询 | 模拟器 | 无 UAF、无 ASan 报告 |

### 6.3 多 Endpoint 测试

| 测试项 | 环境 | 预期结果 |
|--------|------|----------|
| 3+ DoH upstream（Cloudflare、Google、Quad9） | Android 真机 | 每个 upstream 独立缓存 |
| 3+ DoT upstream（Cloudflare、Google、Quad9） | Android 真机 | 同上 |
| 混合 DoH + DoT upstream | Android 真机 | 缓存互不干扰 |

### 6.4 失败回退

| 测试项 | 环境 | 预期结果 |
|--------|------|----------|
| TLS 握手失败（证书错误） | 模拟器 | session 不被缓存，回退到下一 upstream |
| Session resume 被服务端拒绝 | Android 真机 | 降级为 full handshake，新 session 被缓存 |
| 网络中断 → 重连 | Android 真机 | 旧 session 被丢弃，新连接 full handshake |
| BoringSSL `SSL_SESSION_up_ref` 失败 | 模拟器（mock） | 缓存条目被移除，返回 nullptr |

### 6.5 性能基线

| 测量项 | 环境 | 指标 |
|--------|------|------|
| Full handshake 耗时 | Android 真机 | P50 / P99 毫秒 |
| Session resume 耗时 | Android 真机 | P50 / P99 毫秒 |
| Resume vs full 握手加速比 | Android 真机 | 预期 30-50% |
| Cache hit rate（稳态） | Android 真机 | 预期 > 80%（连续查询场景） |
| `tls_session_mutex_` 争用率 | Android 真机 | 通过 telemetry 间接评估 |

---

## 7. 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | Android 真机测试环境 | arm64 设备，Android 10+ | ❌ 未配置 |
| C-2 | Android 模拟器环境 | x86_64 模拟器，API 29+ | ❌ 未配置 |
| C-3 | BoringSSL 版本确认 | 确认 NDK r20b 对应的 BoringSSL 版本及已知 session cache bug | ❌ 未确认 |
| C-4 | ASan / HWASan 构建 | Android 构建启用 AddressSanitizer | ❌ 未配置 |
| C-5 | Telemetry 基线 | 收集当前 session reuse 指标作为基线 | ❌ 未收集 |
| C-6 | 基本集成测试 | 至少覆盖 DoH/DoT 查询路径 | ❌ 无测试 |

---

## 8. 方案对比

| 维度 | 方案 A（加固现有） | 方案 B（连接复用） | 方案 C（Telemetry） |
|------|-------------------|-------------------|---------------------|
| 实施复杂度 | 低 | 中-高 | 极低 |
| 性能收益 | 中（减少握手 RTT） | 高（消除握手） | 无（仅观测） |
| 风险 | 低 | 中 | 极低 |
| 依赖条件 | C-3, C-4 | C-1, C-2, C-6 | 无 |
| Android 验证需求 | 需要 | 强烈需要 | 不需要 |
| 与现有代码兼容性 | 完全兼容 | 需重构 SendDoh/SendDot | 完全兼容 |

---

## 9. 推荐路径

1. **短期（无代码变更）：** 完成方案 C 的 telemetry 观测，收集 session reuse 基线数据
2. **中期（低风险代码变更）：** 实施方案 A 的 A.1（TTL）和 A.2（telemetry 增强）
3. **长期（中风险代码变更）：** 评估方案 B 的连接复用，需先完成 C-1/C-2/C-6

---

## 10. 当前约束

- 本文档为设计分析文档，不触发代码行为变更。
- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入 session cache 加固的代码改动。
- 实施时必须保持 TLS 握手行为、证书验证语义、Android CA fallback 链完全不变。
- 实施前必须完成 §7 中至少 C-3 和 C-4。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.4 P-1*
