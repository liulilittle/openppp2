# Firewall RCU 规则快照优化设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 编号：P2-12-RCU（主体）/ P3-3（阶段 3 写入路径迁移设计细化）
> 状态：**设计文档，暂不实施**；P3-3 细化状态：**设计细化完成，未实施**
> 决策日期：2026-05-11
> P3-3 细化日期：2026-05-12
> 关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §4.6
> 关联源码：`ppp/net/Firewall.h`、`ppp/net/Firewall.cpp`
> 语言标准：C++17

---

## 1. 当前问题

### 1.1 锁竞争模型

`Firewall` 类使用 `std::shared_mutex`（别名 `SynchronizedObject`）保护所有规则容器：

| 操作类型 | 锁模式 | 方法 |
|----------|--------|------|
| 写入（增删规则） | `std::unique_lock`（排他锁） | `DropNetworkPort`、`DropNetworkSegment`、`DropNetworkDomains`、`Clear`、`LoadWithRules` |
| 读取（匹配查询） | `std::shared_lock`（共享锁） | `IsDropNetworkPort`、`IsDropNetworkSegment`、`IsDropNetworkDomains` |

读取路径是热路径——每个 DNS 查询、每个连接建立、每个数据包路由都可能触发一次 `IsDropNetworkDomains()` 调用。写入路径是冷路径——仅在规则配置加载或动态更新时触发。

### 1.2 `IsDropNetworkDomains` 的快照复制开销

当前实现（`Firewall.cpp:355-367`）在每次域名查询时复制完整的 `network_domains_`（`ppp::unordered_set<ppp::string>`）：

```cpp
// 当前实现：每次查询复制整个域名表
NetworkDomainsTable domains_snapshot;
{
    SharedSynchronizedObjectScope scope(syncobj_);
    try
    {
        domains_snapshot = network_domains_;  // ← O(N) 深拷贝
    }
    catch (const std::bad_alloc&)
    {
        // fail-safe: 复制失败返回 false
        return false;
    }
}
// 然后对 domains_snapshot 执行后缀匹配
```

**性能影响：**

| 规则规模 | 每次查询复制成本 | 1000 QPS 下的开销 |
|----------|-----------------|-------------------|
| 100 条域名 | ~100 次 string 构造 + hash 节点分配 | 每秒 100,000 次堆分配 |
| 1,000 条域名 | ~1,000 次 string 构造 + hash 节点分配 | 每秒 1,000,000 次堆分配 |
| 10,000 条域名 | ~10,000 次 string 构造 + hash 节点分配 | 每秒 10,000,000 次堆分配 |

### 1.3 `IsDropNetworkPort` 和 `IsDropNetworkSegment` 的锁开销

这两个方法虽然不复制规则表，但仍需在每次调用时获取 `shared_lock`：

- **`IsDropNetworkPort`**（`Firewall.cpp:219`）：`SharedSynchronizedObjectScope scope(syncobj_)`
- **`IsDropNetworkSegment`**（`Firewall.cpp:287-288, 303-304`）：`SharedSynchronizedObjectScope scope(syncobj_)`

`std::shared_mutex` 的 `lock_shared()` 在高并发下存在原子计数器竞争，且写者会被所有读者阻塞（writer starvation 或读者侧 cache-line bouncing）。

### 1.4 后缀匹配的线性扫描开销

`IsSameNetworkDomains`（`Firewall.cpp:389-449`）对域名执行线性后缀遍历：

```
输入: "sub.evil.com"
标签: ["sub", "evil", "com"]
后缀候选:
  1. "sub.evil.com"        (精确匹配)
  2. "evil.com"            (从标签 1 开始)
  3. "com"                 (从标签 2 开始，但 label_size < 2 时跳过)
```

每个候选都需要字符串拼接（`next += '.'; next.append(label)`），然后执行 hash lookup。对于长域名（如 `a.b.c.d.e.example.com`），候选数量为 O(L)（L = 标签数）。

---

## 2. C++17 RCU 快照方案

### 2.1 核心思想

RCU（Read-Copy-Update）的核心是：

1. **读取者**：获取不可变快照的 `shared_ptr`，无需持锁即可执行匹配。
2. **写入者**：构建新规则表的副本，修改后通过原子操作发布新快照。
3. **内存回收**：旧快照通过 `shared_ptr` 引用计数自动回收（最后一个读取者释放时销毁）。

### 2.2 数据结构设计

```cpp
// Firewall.h — 新增

/**
 * @brief 包含所有防火墙规则的不可变快照。
 *
 * 通过 std::shared_ptr<const FirewallRuleSnapshot> 在读写线程之间共享。
 * 写入者创建新快照并原子发布；读取者获取快照的 shared_ptr 副本后即可
 * 不持有 Firewall 业务锁即可访问所有规则表。旧快照在最后一个读取者释放 shared_ptr 后自动销毁。
 */
struct FirewallRuleSnapshot
{
    /// 协议无关的端口黑名单
    ppp::unordered_set<int>                         ports;
    /// TCP 端口黑名单
    ppp::unordered_set<int>                         ports_tcp;
    /// UDP 端口黑名单
    ppp::unordered_set<int>                         ports_udp;
    /// 域名黑名单（精确 + 后缀匹配）
    ppp::unordered_set<ppp::string>                 network_domains;
    /// CIDR 网段黑名单
    ppp::unordered_map<Int128, int>                 network_segments;
};
```

### 2.3 成员变量变更

```cpp
class Firewall
{
public:
    // ... 保持现有 public API 不变 ...

private:
    // === 当前实现（将被替换）===
    // SynchronizedObject                           syncobj_;
    // ppp::unordered_set<int>                      ports_;
    // ppp::unordered_set<int>                      ports_tcp_;
    // ppp::unordered_set<int>                      ports_udp_;
    // NetworkDomainsTable                          network_domains_;
    // NetworkSegmentTable                          network_segments_;

    // === RCU 实现 ===
    /// @brief 当前规则快照，通过 std::atomic_load/store 保护。
    /// 初始值为 empty snapshot（所有容器为空）。
    std::shared_ptr<const FirewallRuleSnapshot>     snapshot_;
};
```

### 2.4 读取路径（不持 Firewall 业务锁）

```cpp
bool Firewall::IsDropNetworkPort(int port, bool tcp_or_udp) noexcept
{
    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
        return false;
    }

    // 获取不可变快照 — 不持 Firewall 业务锁；atomic_load 是否 lock-free 由标准库实现决定
    auto snap = std::atomic_load(&snapshot_);

    // 在不可变快照上执行查找
    if (snap->ports.count(port))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
        return true;
    }

    const auto& target_set = tcp_or_udp ? snap->ports_tcp : snap->ports_udp;
    if (target_set.count(port))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
        return true;
    }

    return false;
}
```

```cpp
bool Firewall::IsDropNetworkDomains(const ppp::string& host) noexcept
{
    // ... 前置校验和 IP 解析不变 ...

    // 获取不可变快照 — 不持 Firewall 业务锁
    auto snap = std::atomic_load(&snapshot_);

    // 直接在快照上执行匹配，无需复制
    auto contains = [&snap](const ppp::string& s) noexcept
    {
        return snap->network_domains.count(s) > 0;
    };

    bool blocked = IsSameNetworkDomains(host_lower, contains);
    if (blocked)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
    }
    return blocked;
}
```

```cpp
template <typename T>
static bool Firewall_IsDropNetworkSegment(
    const boost::asio::ip::address& ip,
    T __ip,
    int max_prefix,
    const Firewall::NetworkSegmentTable& network_segments) noexcept
{
    // ... 算法不变，仅参数类型从引用改为 const 引用 ...
}
```

### 2.5 写入路径（Copy-Modify-Publish）

```cpp
bool Firewall::DropNetworkPort(int port) noexcept
{
    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
        return false;
    }

    bool inserted = false;
    try
    {
        SynchronizedObjectScope scope(syncobj_);

        // 1. 获取当前快照
        auto old_snap = std::atomic_load(&snapshot_);

        // 2. 拷贝快照
        auto new_snap = std::make_shared<FirewallRuleSnapshot>();
        new_snap->ports             = old_snap->ports;
        new_snap->ports_tcp         = old_snap->ports_tcp;
        new_snap->ports_udp         = old_snap->ports_udp;
        new_snap->network_domains   = old_snap->network_domains;
        new_snap->network_segments  = old_snap->network_segments;

        // 3. 修改新快照
        inserted = new_snap->ports.emplace(port).second;

        // 4. 显式转换为 const 快照指针后原子发布，避免 C++17 atomic_store 模板推导冲突
        std::shared_ptr<const FirewallRuleSnapshot> published = std::move(new_snap);
        std::atomic_store(&snapshot_, std::move(published));
    }
    catch (const std::bad_alloc&)
    {
        return false;
    }

    ppp::diagnostics::SetLastErrorCode(
        inserted ? ppp::diagnostics::ErrorCode::Success
                 : ppp::diagnostics::ErrorCode::FirewallDropPortAlreadyExists);
    return inserted;
}
```

**关键点：** 写入路径仍然需要复制整个规则表，但写入是冷路径（仅在规则加载/更新时触发），一次复制的成本被所有后续读取的零拷贝收益摊销。

### 2.6 `Clear()` 实现

```cpp
void Firewall::Clear() noexcept
{
    try
    {
        SynchronizedObjectScope scope(syncobj_);
        // 发布一个全新的空快照
        auto empty_snap = std::make_shared<FirewallRuleSnapshot>();
        std::shared_ptr<const FirewallRuleSnapshot> published = std::move(empty_snap);
        std::atomic_store(&snapshot_, std::move(published));
    }
    catch (const std::bad_alloc&)
    {
        return;
    }
    // 旧快照在所有读者释放 shared_ptr 后自动销毁
}
```

### 2.7 构造函数初始化

```cpp
Firewall()
    : snapshot_(std::make_shared<FirewallRuleSnapshot>())
{}
```

> 设计注意：如果最终实现必须保持构造函数 `noexcept`，则初始化快照不能直接在初始化列表中调用可能抛出 `bad_alloc` 的 `make_shared`；应提供不抛出的 fallback 策略或移除 `noexcept`，避免异常逃逸触发 `std::terminate`。

---

## 3. 线程安全模型

### 3.1 读取-写入并发安全

| 场景 | 安全性保证 |
|------|-----------|
| 多个读取者并发读 | ✅ 安全：`shared_ptr` 的 control block 在 `atomic_load` 下是线程安全的；`const` 快照本身无竞争 |
| 一个写入者发布新快照 | ✅ 安全：`atomic_store` 是原子操作，读取者要么看到旧快照，要么看到新快照，不会看到撕裂状态 |
| 读取者与写入者并发 | ✅ 安全：读取者持有的 `shared_ptr` 副本指向旧快照，写入者不影响正在使用的快照 |
| 多个写入者并发 | ⚠️ 需要序列化：当前使用 `shared_mutex` 排他锁保护写入路径，确保 "read-modify-write" 快照更新是原子的 |

### 3.2 为何保留写入路径的锁

虽然读取路径不再需要锁，但写入路径仍然需要序列化，原因如下：

1. **Read-Modify-Write 原子性**：`DropNetworkPort` 需要读取当前快照 → 复制 → 修改 → 发布。如果两个写入者并发执行，可能发生 lost update：
   - 写入者 A 读取快照 V1，复制为 V2A
   - 写入者 B 读取快照 V1，复制为 V2B
   - 写入者 A 发布 V2A
   - 写入者 B 发布 V2B（覆盖了 A 的修改）

2. **解决方案**：保留 `std::shared_mutex`，但仅在写入路径使用 `unique_lock`。读取路径不获取 `Firewall::syncobj_`，仅通过 `std::atomic_load` 获取快照；该原子操作是否 lock-free 由标准库实现决定。

```cpp
class Firewall
{
private:
    SynchronizedObject                              syncobj_;      // 仅保护写入路径
    std::shared_ptr<const FirewallRuleSnapshot>     snapshot_;      // 读取路径使用 atomic_load
};
```

### 3.3 `std::atomic_load/store` free functions 行为

```cpp
// C++17 标准 §[util.smartptr.shared.atomic]
// 实现方式：主流实现使用全局 spinlock 表（hash table of mutexes）
// 性能特征：每次调用约 20-50ns（取决于平台和竞争程度）
// 相比之下：std::shared_mutex::lock_shared() 约 30-80ns + cache-line bouncing

// 使用方式：
auto snap = std::atomic_load(&snapshot_);          // 读取
std::atomic_store(&snapshot_, published_snapshot);  // 写入；类型需与 snapshot_ 完全一致
```

### 3.4 `shared_ptr` 控制块的线程安全性

`std::shared_ptr` 的引用计数操作（增加/减少）是原子的。`std::atomic_load/store` 保证对同一 `shared_ptr` 对象的并发读写不会导致 data race（控制块撕裂）。

**关键约束：** 不要混用普通 copy/move 与 `atomic_load/store` 操作同一个 `shared_ptr` 成员。如果一个成员在某些路径使用 `atomic_load/store`，则**所有**对它的读写都必须使用 `atomic_load/store`。

---

## 4. 为何不用 C++20 `std::atomic<std::shared_ptr<T>>`

### 4.1 项目基线限制

当前项目强制使用 C++17（`CMakeLists.txt` 中 `set(CMAKE_CXX_STANDARD 17)`）。`std::atomic<std::shared_ptr<T>>` 是 C++20 标准（§[util.smartptr.atomic]），在 C++17 下不可用。

### 4.2 C++17 free functions vs C++20 atomic shared_ptr

| 特性 | C++17 `atomic_load/store` free functions | C++20 `atomic<shared_ptr<T>>` |
|------|----------------------------------------|-------------------------------|
| 标准状态 | C++17 可用，C++20 起弃用，C++26 移除 | C++20 可用 |
| 接口风格 | 全局函数 `std::atomic_load(&ptr)` | 成员函数 `ptr.load()` / `ptr.store()` |
| CAS 操作 | 支持 `std::atomic_compare_exchange_weak/strong` free functions，但本设计不采用 | 支持成员函数 `compare_exchange_weak/strong` |
| `exchange()` | 不支持（需 load + store 两步，非原子交换） | 支持（原子交换） |
| 实现 | 全局 spinlock 表 | 实现自由（lock-free 或 spinlock） |
| 可移植性 | 主流编译器全部支持 | 需要编译器 + 标准库支持 |

### 4.3 迁移路径

当项目升级到 C++20 时：

```cpp
// C++17（当前）
std::shared_ptr<const FirewallRuleSnapshot> snapshot_;

auto snap = std::atomic_load(&snapshot_);
std::atomic_store(&snapshot_, published_snapshot);

// C++20（未来）
std::atomic<std::shared_ptr<const FirewallRuleSnapshot>> snapshot_;

auto snap = snapshot_.load();
snapshot_.store(new_snap);

// C++20 还支持 CAS，可用于不持业务锁的写入合并：
auto expected = snapshot_.load();
auto desired = make_modified_copy(expected);
while (!snapshot_.compare_exchange_weak(expected, desired)) {
    expected = snapshot_.load();
    desired = make_modified_copy(expected);
}
```

### 4.4 兼容性包装建议

建议在项目中引入兼容性包装（参考 `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4）：

```cpp
// ppp/net/AtomicSharedPtr.h（未来新增）

template<class T>
std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept
{
#if __cplusplus >= 202002L
    // C++20+: 使用 std::atomic<std::shared_ptr<T>> 的成员函数
    // 但此包装仍调用 free function 以保持接口一致
    // 迁移时直接删除此包装，改用 atomic<shared_ptr<T>>::load()
    return std::atomic_load(p);
#else
    return std::atomic_load(p);
#endif
}

template<class T>
void atomic_store_compat(std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    std::atomic_store(p, std::move(r));
}
```

---

## 5. 语义保持要求

### 5.1 必须保持的行为

| 行为 | 当前实现 | RCU 实现 | 是否变化 |
|------|----------|----------|----------|
| 端口精确匹配 | `ports_.find(port)` | `snap->ports.count(port)` | ❌ 不变 |
| TCP/UDP 协议匹配 | `ports_tcp_.find(port)` / `ports_udp_.find(port)` | `snap->ports_tcp.count(port)` / `snap->ports_udp.count(port)` | ❌ 不变 |
| 域名精确匹配 | `contains(host)` | `contains(host)` | ❌ 不变 |
| 域名后缀匹配 | 线性后缀遍历 + hash lookup | 相同算法 | ❌ 不变 |
| CIDR 段匹配 | 遍历 prefix + mask + hash lookup | 相同算法 | ❌ 不变 |
| IP 地址自动路由到段匹配 | `IsDropNetworkDomains` 中检测 IP 格式 | 相同逻辑 | ❌ 不变 |
| 错误码设置 | `SetLastErrorCode(...)` | 相同错误码 | ❌ 不变 |
| 重复插入返回 false | `emplace().second` | 相同逻辑 | ❌ 不变 |
| CIDR prefix 取较小值 | `if (prefix < now) { now = prefix; }` | 相同逻辑 | ❌ 不变 |
| `LoadWithFile` → `LoadWithRules` 委托 | 不变 | 不变 | ❌ 不变 |
| 规则文件解析（`drop ip/port/dns`） | 不变 | 不变 | ❌ 不变 |

### 5.2 行为变化（预期且可接受）

| 变化 | 描述 | 影响 |
|------|------|------|
| 快照版本 | 读取者看到的是发布时刻的规则快照，而非实时最新值 | 规则更新与查询之间存在极短窗口（纳秒级），可接受 |
| 写入路径不持有读取锁 | 写入不再阻塞读取 | ✅ 正面改进 |
| 内存占用 | 写入期间存在新旧两个快照副本 | 瞬态双倍内存，写入完成后旧快照自动释放 |

### 5.3 不可接受的行为变化

- ❌ 不得改变 `IsSameNetworkDomains` 的匹配语义（精确 + 后缀）
- ❌ 不得改变错误码体系
- ❌ 不得改变 public API 签名
- ❌ 不得改变 `LoadWithRules` 的解析逻辑
- ❌ 不得引入新的头文件依赖（除 `<memory>`，已在 `stdafx.h` 中包含）

---

## 6. 额外优化：反向 trie 后缀匹配（可选，独立于 RCU）

### 6.1 当前后缀匹配的问题

`IsSameNetworkDomains` 的后缀遍历是 O(L²)（L = 标签数）：

```
"a.b.c.d.example.com" → 标签: [a, b, c, d, example, com]
候选:
  i=1: "b.c.d.example.com"    → hash lookup
  i=2: "c.d.example.com"      → hash lookup
  i=3: "d.example.com"        → hash lookup
  i=4: "example.com"          → hash lookup
  i=5: "com"                  → hash lookup
```

每次候选都需要字符串拼接（O(domain_length)），总计 O(L × domain_length)。

### 6.2 反向 trie 方案

将域名标签反转后插入 trie：

```
规则: "evil.com"          → trie: com → evil → (terminal)
规则: "ads.tracker.net"   → trie: net → tracker → ads → (terminal)
规则: "malware.org"       → trie: org → malware → (terminal)

查询: "sub.evil.com"
标签: [sub, evil, com]
从 trie 根开始: com → evil → (命中！) → 返回 true
```

**优势：**
- 查询时间 O(L)（L = 标签数），无需字符串拼接
- 内存共享公共后缀（`com` 节点被所有 `.com` 规则共享）
- 天然支持 `string_view` 避免分配

**实现复杂度：**
- 需要实现 trie 节点结构
- 需要将 `unordered_set<string>` 替换为 trie
- 需要更新 `DropNetworkDomains` 和 `IsSameNetworkDomains`
- 侵入性中等，建议作为独立优化项

### 6.3 更简单的替代方案：`string_view` 后缀匹配

不改变数据结构，仅优化匹配过程：

```cpp
bool Firewall::IsSameNetworkDomains(
    std::string_view host,
    const std::function<bool(std::string_view)>& contains) noexcept
{
    // 精确匹配
    if (contains(host)) return true;

    // 后缀匹配：使用 string_view 避免分配
    auto dot_pos = host.find('.');
    while (dot_pos != std::string_view::npos)
    {
        std::string_view suffix = host.substr(dot_pos + 1);
        if (suffix.size() >= 2 && contains(suffix))  // 至少 "x.y"
        {
            return true;
        }
        dot_pos = host.find('.', dot_pos + 1);
    }
    return false;
}
```

**注意：** 此方案需要将 `NetworkDomainsTable` 的 key 类型从 `ppp::string` 改为支持 `string_view` 查找的容器（如 `std::unordered_set<std::string>` 配合透明 hash），或在查找时临时构造 `ppp::string`。侵入性较低，但需要验证 `ppp::string` 与 `std::string_view` 的互操作性。

---

## 7. 额外优化：单趟 normalize（可选，独立于 RCU）

### 7.1 当前 normalize 问题

`IsDropNetworkDomains` 和 `DropNetworkDomains` 中的 normalize 使用三步链式调用：

```cpp
ppp::string host_lower = LTrim(RTrim(ToLower(host)));
```

这会产生 3 个临时字符串（或至少 2 个，取决于实现是否有 RVO）。

### 7.2 单趟 normalize 方案

```cpp
ppp::string NormalizeHost(std::string_view input) noexcept
{
    // 找到第一个非空白字符
    auto start = input.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};

    // 找到最后一个非空白字符
    auto end = input.find_last_not_of(" \t\r\n");
    input = input.substr(start, end - start + 1);

    // 单趟转换为小写
    ppp::string result;
    result.reserve(input.size());
    for (char c : input)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}
```

**优势：** 从 3 次分配减少到 1 次（`reserve` 后 `push_back` 不会重新分配）。

---

## 8. 测试与基准计划

### 8.1 功能正确性测试

| 测试场景 | 验证内容 | 优先级 |
|----------|----------|--------|
| 空规则表查询 | 所有 `Is*` 方法返回 false | 高 |
| 单条端口规则 | `IsDropNetworkPort` 精确命中 | 高 |
| 协议分离规则 | TCP/UDP 独立命中 | 高 |
| 单条域名规则（精确） | `IsDropNetworkDomains` 精确命中 | 高 |
| 单条域名规则（后缀） | 子域名匹配 | 高 |
| 单条 CIDR 规则 | `IsDropNetworkSegment` 命中 | 高 |
| IPv6 CIDR 规则 | 128-bit 地址匹配 | 高 |
| 规则更新后查询 | 新规则立即可见（RCU 发布后） | 高 |
| `Clear()` 后查询 | 所有 `Is*` 方法返回 false | 高 |
| `LoadWithFile` 端到端 | 文件解析 → 规则匹配 | 中 |
| 注释行跳过 | `#` 开头行被忽略 | 中 |
| 无效输入 | 空字符串、超长域名、非法端口 | 中 |

### 8.2 并发正确性测试

| 测试场景 | 验证内容 | 优先级 |
|----------|----------|--------|
| 并发读取 | 多线程同时 `IsDropNetworkDomains` | 高 |
| 读写并发 | 一个线程 `DropNetworkPort`，多个线程 `IsDropNetworkPort` | 高 |
| 写写并发 | 两个线程同时 `DropNetworkPort`（不同端口） | 高 |
| 快照一致性 | 读取者看到的快照在查询期间不被修改 | 高 |
| 内存回收 | 旧快照在所有读者释放后正确销毁 | 中 |

### 8.3 性能基准

| 基准 | 指标 | 目标 |
|------|------|------|
| **RCU vs 当前实现：100 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.3 |
| **RCU vs 当前实现：1,000 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.1 |
| **RCU vs 当前实现：10,000 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.05 |
| **端口查询并发吞吐** | QPS（8 线程） | RCU ≥ 当前实现 × 2 |
| **CIDR 段查询并发吞吐** | QPS（8 线程） | RCU ≥ 当前实现 × 2 |
| **写入延迟** | 单次 `DropNetworkPort` 耗时 | ≤ 当前实现 × 1.5（可接受小幅增加） |
| **内存峰值** | 写入期间额外内存 | ≤ 规则表大小 × 2（瞬态） |

### 8.4 基准测试代码骨架

```cpp
// benchmark_firewall.cpp（未来新增）

static void BM_Firewall_IsDropNetworkDomains_100(benchmark::State& state)
{
    Firewall fw;
    for (int i = 0; i < 100; i++)
    {
        fw.DropNetworkDomains("rule" + std::to_string(i) + ".example.com");
    }
    for (auto _ : state)
    {
        benchmark::DoNotOptimize(fw.IsDropNetworkDomains("sub.rule50.example.com"));
    }
}
BENCHMARK(BM_Firewall_IsDropNetworkDomains_100);
```

---

## 9. 迁移步骤

### 阶段 1：准备（低风险）

1. **新增 `FirewallRuleSnapshot` 结构体**：在 `Firewall.h` 中定义，不影响现有代码。
2. **新增 `snapshot_` 成员**：与现有 `syncobj_` + 容器成员并存，通过编译期开关切换。
3. **新增兼容性包装**（可选）：`atomic_load_compat` / `atomic_store_compat`，便于未来 C++20 迁移。

### 阶段 2：读取路径迁移（中风险）

4. **迁移 `IsDropNetworkPort`**：从 `shared_lock` + 容器直接查找改为 `atomic_load(&snapshot_)` + 快照查找。
5. **迁移 `IsDropNetworkSegment`**：同上。
6. **迁移 `IsDropNetworkDomains`**：移除 `domains_snapshot = network_domains_` 复制，改为直接使用快照。
7. **验证所有 `Is*` 方法的语义不变**。

### 阶段 3：写入路径迁移（中风险）— P3-3 详细设计

> **P3-3 状态：设计细化完成，未实施。** 以下为每个写入方法的 Copy-Modify-Publish 步骤、
> 锁保护范围、lost update 防护机制及验收检查清单。所有代码片段仅为设计说明，非最终实现。

#### 9.3.0 总体写入路径不变式（Invariant）

所有写入方法必须遵守以下不变式：

| 不变量 | 说明 | 违反后果 |
|--------|------|----------|
| **INV-W1：锁内原子性** | `atomic_load → copy → modify → atomic_store` 四步必须在同一个 `SynchronizedObjectScope` 保护下完成 | Lost update：并发写入者互相覆盖规则 |
| **INV-W2：发布前不暴露中间状态** | 新快照必须在 `atomic_store` 之后才对读取者可见；`atomic_store` 前新快照仅写入者持有 | 读取者看到不完整的规则集 |
| **INV-W3：锁范围最小化** | 输入验证、normalize、地址解析等纯计算步骤必须在获取锁之前完成 | 不必要的锁持有时间增加读取者延迟 |
| **INV-W4：错误码在锁外设置** | `SetLastErrorCode` 在锁释放后调用 | 锁持有期间调用可能重入的诊断代码 |
| **INV-W5：异常安全** | `make_shared`、容器拷贝、`emplace`、批量规则应用都可能因分配失败抛异常；必须以同一 `try` 范围包住锁内 copy-modify-publish 全段并 fail-safe 返回 false | 在 `noexcept` 写入方法中异常逃逸会触发 `std::terminate`；旧快照不应被部分发布 |

```
┌─────────────────────────────────────────────────────────┐
│                  写入路径通用流程                          │
│                                                         │
│  ① 输入校验 / normalize / 地址解析  ← 无锁，可提前退出   │
│  ② SynchronizedObjectScope lock(syncobj_)  ← 获取排他锁  │
│  ③ old_snap = atomic_load(&snapshot_)                    │
│  ④ new_snap = make_shared<FirewallRuleSnapshot>()        │
│     拷贝 old_snap 的全部 5 个容器到 new_snap              │
│  ⑤ 修改 new_snap 的目标容器                              │
│  ⑥ atomic_store(&snapshot_, as_const(new_snap))          │
│  ⑦ lock 析构 → 释放排他锁                                │
│  ⑧ SetLastErrorCode(...)  ← 锁外，不阻塞读取者           │
│  ⑨ 返回结果                                             │
└─────────────────────────────────────────────────────────┘
```

---

#### 9.3.1 `DropNetworkPort(int port)` — 协议无关端口规则

**当前实现（`Firewall.cpp:49-62`）：**

```cpp
SynchronizedObjectScope scope(syncobj_);
bool inserted = ports_.emplace(port).second;
```

**RCU Copy-Modify-Publish 步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | `port` 范围校验 `[MinPort+1, MaxPort]` | 无锁 | 不合法则直接 `SetLastErrorCode(NetworkPortInvalid)` → `return false` |
| 2 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | 序列化所有写入者 |
| 3 | `old_snap = std::atomic_load(&snapshot_)` | 持锁 | 获取当前不可变快照的 `shared_ptr` 副本 |
| 4 | `new_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | 分配新快照；可能抛 `bad_alloc` → catch → `return false` |
| 5 | 拷贝 `old_snap->ports` → `new_snap->ports` | 持锁 | 5 个容器全部拷贝（ports, ports_tcp, ports_udp, network_domains, network_segments） |
| 6 | `inserted = new_snap->ports.emplace(port).second` | 持锁 | 修改新快照的 `ports` 集合 |
| 7 | `std::atomic_store(&snapshot_, std::shared_ptr<const FirewallRuleSnapshot>(std::move(new_snap)))` | 持锁 | 原子发布；读取者此后调用 `atomic_load` 将看到新快照 |
| 8 | `scope` 析构 | **释放排他锁** | RAII 自动释放 |
| 9 | `SetLastErrorCode(inserted ? Success : FirewallDropPortAlreadyExists)` | 无锁 | 错误码设置不影响快照一致性 |
| 10 | `return inserted` | 无锁 | |

**Lost Update 防护分析：**

```
时间线（无锁 → 有 lost update）：
  T1: Writer A → atomic_load → V1, copy → V1A, emplace(80)
  T2: Writer B → atomic_load → V1, copy → V1B, emplace(443)
  T3: Writer A → atomic_store V1A（含 port 80）
  T4: Writer B → atomic_store V1B（含 port 443，但不含 port 80）← port 80 丢失！

时间线（有 syncobj_ 排他锁 → 无 lost update）：
  T1: Writer A → lock → atomic_load → V1, copy → V1A, emplace(80), atomic_store V1A → unlock
  T2: Writer B → lock → atomic_load → V1A, copy → V1B, emplace(443), atomic_store V1B → unlock
  结果：V1B 含 port 80 和 port 443 ✓
```

---

#### 9.3.2 `DropNetworkPort(int port, bool tcp_or_udp)` — 协议特定端口规则

**当前实现（`Firewall.cpp:70-90`）：**

```cpp
SynchronizedObjectScope scope(syncobj_);
if (tcp_or_udp) inserted = ports_tcp_.emplace(port).second;
else             inserted = ports_udp_.emplace(port).second;
```

**RCU Copy-Modify-Publish 步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | `port` 范围校验 | 无锁 | 同 9.3.1 |
| 2 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | |
| 3 | `old_snap = std::atomic_load(&snapshot_)` | 持锁 | |
| 4 | `new_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | catch `bad_alloc` |
| 5 | 拷贝全部 5 个容器 | 持锁 | |
| 6 | `tcp_or_udp ? new_snap->ports_tcp.emplace(port) : new_snap->ports_udp.emplace(port)` | 持锁 | 根据协议选择目标集合 |
| 7 | `std::atomic_store(&snapshot_, as_const(new_snap))` | 持锁 | |
| 8 | `scope` 析构 | **释放排他锁** | |
| 9 | `SetLastErrorCode(inserted ? Success : FirewallDropPortProtocolAlreadyExists)` | 无锁 | |
| 10 | `return inserted` | 无锁 | |

**与 9.3.1 的差异：** 仅步骤 6 的目标集合不同（`ports_tcp` 或 `ports_udp` 而非 `ports`）。

---

#### 9.3.3 `DropNetworkSegment(const address& ip, int prefix)` — CIDR 网段规则

**当前实现（`Firewall.cpp:98-164`）：**

```cpp
// IPv4 路径：
SynchronizedObjectScope scope(syncobj_);
return set_network_segments(network_segments_, __networkIP, prefix);
```

**RCU Copy-Modify-Publish 步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | 地址族判断（`ip.is_v4()` / `ip.is_v6()`） | 无锁 | |
| 2 | prefix 范围钳位（IPv4: `[0,32]`, IPv6: `[0,128]`） | 无锁 | |
| 3 | 计算 `__mask` 和 `__networkIP` | 无锁 | 纯算术运算，无需锁保护 |
| 4 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | |
| 5 | `old_snap = std::atomic_load(&snapshot_)` | 持锁 | |
| 6 | `new_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | catch `bad_alloc` |
| 7 | 拷贝全部 5 个容器 | 持锁 | |
| 8 | 对 `new_snap->network_segments` 执行 `set_network_segments` lambda | 持锁 | RCU 版本不应将该 helper 标记为 `noexcept`，因为 `emplace` 可能分配内存并抛异常；异常由外层 copy-modify-publish try/catch 处理 |
| 9 | `std::atomic_store(&snapshot_, as_const(new_snap))` | 持锁 | |
| 10 | `scope` 析构 | **释放排他锁** | |
| 11 | `SetLastErrorCode(...)` | 无锁 | 错误码由 lambda 内部设置（`Success` 或 `FirewallDropSegmentAlreadyExists`） |
| 12 | `return result` | 无锁 | |

**`set_network_segments` lambda 语义保持：**

```cpp
// 当前 lambda（Firewall.cpp:104-126）直接修改 NetworkSegmentTable 引用
// RCU 版本：lambda 参数从引用改为对 new_snap->network_segments 的引用
// 逻辑完全不变：find → emplace 或 prefix 取较小值
auto set_network_segments = [](NetworkSegmentTable& m, Int128 k, int prefix) -> bool
{
    auto tail = m.find(k);
    if (tail == m.end())
    {
        return m.emplace(k, prefix).second;       // 新增
    }
    else
    {
        int& now = tail->second;
        if (prefix < now)
        {
            now = prefix;                           // 收紧
            return true;
        }
        else
        {
            SetLastErrorCode(FirewallDropSegmentAlreadyExists);
            return false;                           // 已有更严格规则
        }
    }
};
```

---

#### 9.3.4 `DropNetworkDomains(const ppp::string& host)` — 域名规则

**当前实现（`Firewall.cpp:171-192`）：**

```cpp
ppp::string host_lower = LTrim(RTrim(ToLower(host)));
SynchronizedObjectScope scope(syncobj_);
bool inserted = network_domains_.emplace(host_lower).second;
```

**RCU Copy-Modify-Publish 步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | `host.empty()` 校验 | 无锁 | 空字符串 → `DnsAddressInvalid` → `return false` |
| 2 | `host_lower = LTrim(RTrim(ToLower(host)))` | 无锁 | normalize 开销较大的步骤放在锁外 |
| 3 | `host_lower.empty()` 校验 | 无锁 | normalize 后为空 → `DnsAddressInvalid` → `return false` |
| 4 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | |
| 5 | `old_snap = std::atomic_load(&snapshot_)` | 持锁 | |
| 6 | `new_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | catch `bad_alloc` |
| 7 | 拷贝全部 5 个容器 | 持锁 | |
| 8 | `inserted = new_snap->network_domains.emplace(host_lower).second` | 持锁 | |
| 9 | `std::atomic_store(&snapshot_, as_const(new_snap))` | 持锁 | |
| 10 | `scope` 析构 | **释放排他锁** | |
| 11 | `SetLastErrorCode(inserted ? Success : FirewallDropDomainAlreadyExists)` | 无锁 | |
| 12 | `return inserted` | 无锁 | |

**设计注意：** `ToLower` / `LTrim` / `RTrim` 在锁外执行，避免在持锁期间进行字符串分配。这与当前实现的行为一致（当前代码也是先 normalize 再获取锁）。

---

#### 9.3.5 `Clear()` — 清空所有规则

**当前实现（`Firewall.cpp:195-203`）：**

```cpp
SynchronizedObjectScope scope(syncobj_);
ports_.clear(); ports_tcp_.clear(); ports_udp_.clear();
network_domains_.clear(); network_segments_.clear();
```

**RCU 实现步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | 防止与并发写入者交错 |
| 2 | `empty_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | 所有 5 个容器默认构造为空 |
| 3 | `std::atomic_store(&snapshot_, std::shared_ptr<const FirewallRuleSnapshot>(std::move(empty_snap)))` | 持锁 | 发布空快照 |
| 4 | `scope` 析构 | **释放排他锁** | |

**为何 `Clear()` 仍需排他锁：**

如果两个写入者并发执行 `Clear()` + `DropNetworkPort(80)`，无锁情况下：
- Writer A（Clear）：`atomic_load` → V1, 创建空快照 V_empty
- Writer B（Drop 80）：`atomic_load` → V1, 复制为 V2（含 port 80）
- Writer A：`atomic_store` V_empty
- Writer B：`atomic_store` V2（V2 基于 V1，不含 V1 中的其他规则，但含 port 80）
- 结果：V1 中的旧规则被正确清除（由 A），port 80 被正确添加（由 B）— 但 B 的 V2 是基于 V1 复制的，V1 中的旧规则又出现在 V2 中 → **Clear 语义被破坏**

排他锁确保 Clear 和 Drop 不会并发执行。

---

#### 9.3.6 `LoadWithRules(const ppp::string& configuration)` — 批量规则加载

**当前实现（`Firewall.cpp:628-723`）：** 逐行解析，每行调用对应的 `Drop*` 方法。

**RCU 迁移的两种策略：**

##### 策略 A：逐条调用 Drop*（简单，次优）

```
对每条规则行：
  解析 → 调用 DropNetworkPort / DropNetworkSegment / DropNetworkDomains
  每次调用独立执行 copy-modify-publish
```

| 维度 | 评估 |
|------|------|
| 拷贝次数 | N 次（N = 有效规则行数） |
| 总拷贝工作量 | O(N × \|snapshot\|) |
| 代码变更 | 最小：仅修改 Drop* 方法内部，LoadWithRules 无需改动 |
| 锁持有时间 | 每条规则一次 lock/unlock，N 次锁获取 |
| 适用场景 | 规则数量少（< 100），或作为初始迁移的过渡方案 |

##### 策略 B：批量 Copy-Modify-Publish（推荐）

```
LoadWithRules 内部流程：
  ① 解析所有规则行，分类为 port_rules / segment_rules / domain_rules
  ② 获取排他锁
  ③ atomic_load → old_snap
  ④ make_shared → new_snap，拷贝 old_snap 全部容器
  ⑤ 对 new_snap 批量应用所有解析好的规则
  ⑥ atomic_store new_snap
  ⑦ 释放锁
```

| 维度 | 评估 |
|------|------|
| 拷贝次数 | 1 次 |
| 总拷贝工作量 | O(\|snapshot\|) |
| 代码变更 | 中等：需要新增批量应用逻辑或内部 helper |
| 锁持有时间 | 1 次 lock/unlock，但单次持锁时间较长（包含所有规则的应用） |
| 适用场景 | 规则数量大（> 100），生产环境推荐 |

**策略 B 详细步骤：**

| 步骤 | 代码动作 | 锁状态 | 说明 |
|------|----------|--------|------|
| 1 | `rules.empty()` 校验 | 无锁 | 空输入 → `FirewallLoadRulesInputEmpty` → `return false` |
| 2 | `Tokenize(rules, lines, "\r\n")` | 无锁 | 分割为行 |
| 3 | 遍历 `lines`，解析每行的 `drop ip/port/dns <payload>` | 无锁 | 将解析结果存入临时 vector（`struct ParsedRule { enum Kind; ppp::string payload; }`） |
| 4 | 若无有效规则行 → `return false` | 无锁 | |
| 5 | `SynchronizedObjectScope scope(syncobj_)` | **获取排他锁** | |
| 6 | `old_snap = std::atomic_load(&snapshot_)` | 持锁 | |
| 7 | `new_snap = std::make_shared<FirewallRuleSnapshot>()` | 持锁 | catch `bad_alloc` → `return false` |
| 8 | 拷贝全部 5 个容器 | 持锁 | |
| 9 | 遍历 `parsed_rules`，对 `new_snap` 执行对应的容器操作 | 持锁 | port → `new_snap->ports.emplace`；segment → `set_network_segments(new_snap->network_segments, ...)`；domain → `new_snap->network_domains.emplace(normalize(payload))` |
| 10 | `std::atomic_store(&snapshot_, as_const(new_snap))` | 持锁 | |
| 11 | `scope` 析构 | **释放排他锁** | |
| 12 | `return any` | 无锁 | `any` = 至少一条规则成功应用 |

**策略 B 的 `LoadWithRules` 内部批量 helper 骨架（设计示意，非最终代码）：**

```cpp
bool Firewall::LoadWithRules(const ppp::string& configuration) noexcept
{
    // ... 解析逻辑不变（lines、drop_commands 等）...

    // 步骤 1-3：无锁解析所有规则
    struct ParsedRule
    {
        enum class Kind { Port, PortTcp, PortUdp, Segment, Domain } kind;
        int          port     = 0;
        Int128       network_key{};
        int          prefix   = 0;
        ppp::string  domain;           // 已 normalize
    };
    ppp::vector<ParsedRule> parsed;
    bool any = false;

    for (ppp::string& line : lines)
    {
        // ... 现有解析逻辑（去除注释、trim、匹配 drop header）...
        // 解析成功后 push_back 到 parsed，不调用 Drop* 方法
    }

    if (parsed.empty()) return false;

    // 步骤 5-10：单次 copy-modify-publish
    try
    {
        SynchronizedObjectScope scope(syncobj_);
        auto old_snap = std::atomic_load(&snapshot_);

        std::shared_ptr<FirewallRuleSnapshot> new_snap;
        new_snap = std::make_shared<FirewallRuleSnapshot>();

        new_snap->ports            = old_snap->ports;
        new_snap->ports_tcp        = old_snap->ports_tcp;
        new_snap->ports_udp        = old_snap->ports_udp;
        new_snap->network_domains  = old_snap->network_domains;
        new_snap->network_segments = old_snap->network_segments;

        for (const auto& rule : parsed)
        {
            switch (rule.kind)
            {
            case ParsedRule::Kind::Port:
                any |= new_snap->ports.emplace(rule.port).second;
                break;
            case ParsedRule::Kind::PortTcp:
                any |= new_snap->ports_tcp.emplace(rule.port).second;
                break;
            case ParsedRule::Kind::PortUdp:
                any |= new_snap->ports_udp.emplace(rule.port).second;
                break;
            case ParsedRule::Kind::Segment:
                // 复用 set_network_segments lambda 逻辑；helper 不能 noexcept。
                any |= apply_segment(new_snap->network_segments, rule.network_key, rule.prefix);
                break;
            case ParsedRule::Kind::Domain:
                any |= new_snap->network_domains.emplace(rule.domain).second;
                break;
            }
        }

        if (any)
        {
            std::shared_ptr<const FirewallRuleSnapshot> published = std::move(new_snap);
            std::atomic_store(&snapshot_, std::move(published));
        }
    }
    catch (const std::bad_alloc&)
    {
        return false;
    }
    return any;
}
```

**策略 B 语义约束：** 批量解析必须完整复刻当前 `LoadWithRulesDropIP` / `LoadWithRulesDropPort` / `LoadWithRulesDropDns` 的校验、normalize、prefix clamp 和 `SetLastErrorCode` 最终语义。若某批规则全部为重复项（`any == false`），应避免发布等价新快照，或者在实现说明中明确该发布只影响性能、不改变读取语义；推荐避免发布以降低噪声。

**策略选择建议：**

| 场景 | 推荐策略 | 理由 |
|------|----------|------|
| 初始迁移 / 低风险验证 | 策略 A | 最小代码变更，复用已验证的 Drop* 方法 |
| 生产环境 / 大规则集 | 策略 B | 单次拷贝，避免 O(N×R) 开销 |
| 混合方案 | 策略 A 作为 fallback，策略 B 通过编译期开关启用 | 渐进式迁移 |

---

#### 9.3.7 写入路径锁保护范围总结

| 方法 | 锁内操作 | 锁外操作 | 锁持有时间估算 |
|------|----------|----------|---------------|
| `DropNetworkPort(int)` | load + copy(5 容器) + emplace + store | port 校验、SetLastErrorCode | ~1-10 μs（取决于容器大小） |
| `DropNetworkPort(int, bool)` | 同上 | port 校验、SetLastErrorCode | ~1-10 μs |
| `DropNetworkSegment` | load + copy(5 容器) + set_network_segments + store | 地址解析、mask 计算、SetLastErrorCode | ~1-10 μs |
| `DropNetworkDomains` | load + copy(5 容器) + emplace + store | normalize（ToLower/LTrim/RTrim）、空值校验、SetLastErrorCode | ~1-10 μs |
| `Clear` | 创建空快照 + store | 无 | ~0.1-1 μs（仅分配 + store） |
| `LoadWithRules`（策略 A） | 每条规则独立 load+copy+modify+store | 解析、SetLastErrorCode | N × ~1-10 μs |
| `LoadWithRules`（策略 B） | load + copy(5 容器) + 批量修改 + store | 解析、SetLastErrorCode | ~1-10 μs（单次） |

---

#### 9.3.8 Lost Update 防护矩阵

| 并发场景 | 无锁（纯 CAS） | 有 `syncobj_` 排他锁 | 说明 |
|----------|----------------|----------------------|------|
| Drop(80) + Drop(443) | ⚠️ 可能丢失一个 | ✅ 两个都保留 | 排他锁序列化 load-modify-store |
| Drop(80) + Clear() | ⚠️ Clear 可能被覆盖 | ✅ Clear 语义正确 | 排他锁确保 Clear 和 Drop 不交错 |
| DropNetworkDomains("a.com") + DropNetworkDomains("b.com") | ⚠️ 可能丢失一个 | ✅ 两个都保留 | 同上 |
| LoadWithRules(1000 条) + Drop(80) | ⚠️ 大量 lost update | ✅ 完全正确 | 排他锁确保批量加载的原子性 |
| Clear() + Clear() | ✅ 幂等，无 lost update | ✅ 幂等 | 两个空快照等价 |
| Drop(80) + IsDropNetworkPort(80) | ✅ 读取者看到旧或新快照 | ✅ 同左 | 读取路径不持业务锁，无竞争 |

**为何不使用 CAS（compare-exchange）替代排他锁：**

C++17 针对 `std::shared_ptr` 的 atomic free functions 包含 `std::atomic_compare_exchange_weak/strong`。本设计仍不采用 CAS 循环，原因不是 API 缺失，而是复杂度和性能不可预测。典型 load-CAS-store 循环如下：

```cpp
// 伪代码 — 不使用，仅说明为何不采用
auto expected = std::atomic_load(&snapshot_);
auto desired = copy_and_modify(expected);
while (!std::atomic_compare_exchange_weak(&snapshot_, &expected, desired))
{
    expected = std::atomic_load(&snapshot_);
    desired = copy_and_modify(expected);  // 每次失败都要重新拷贝！
}
```

问题：
1. 每次 CAS 失败都需要重新 load、重新拷贝整个快照并重新应用修改 → 写入密集场景下性能退化
2. 对于 `LoadWithRules` 的批量操作，CAS 循环会放大重试成本，复杂度和持有临时快照的内存峰值都更难预测
3. 错误码、重复规则和批量解析的最终语义在 CAS 重试中更难保持清晰

**结论：排他锁是最简单、最可预测的 lost update 防护机制。**

---

#### 9.3.9 异常安全与 fail-safe 策略

| 异常点 | 位置 | 处理策略 | 后果 |
|--------|------|----------|------|
| `make_shared<FirewallRuleSnapshot>()` 抛 `bad_alloc` | 步骤 4/6/7（锁内） | 同一 `try` 包住锁内 copy-modify-publish 全段，`catch (const std::bad_alloc&) { return false; }` | 快照未更新，旧快照保持不变；规则未加载 |
| 容器拷贝/赋值抛异常 | 步骤 5/7（锁内） | 同上 catch | 同上 |
| `emplace` 抛异常 | 步骤 6/8（锁内） | 同上 catch | 同上 |
| `SetLastErrorCode` 抛异常 | 步骤 9/11（锁外） | 不捕获（诊断代码不应抛异常；若抛出则为 bug） | 程序可能终止 |

**关键约束：** 锁内的 catch 必须确保 `scope` 通过 RAII 自动释放。使用 `try-catch` 包裹锁内的 `make_shared` + 拷贝 + 修改 + store 操作，catch 块中 `return false` 触发 `scope` 析构 → 锁释放。

---

#### 9.3.10 `Firewall_IsDropNetworkSegment` 模板函数签名变更

**当前签名（`Firewall.cpp:248`）：**

```cpp
template <typename T>
static bool Firewall_IsDropNetworkSegment(
    const boost::asio::ip::address& ip, T __ip, int max_prefix,
    Firewall::NetworkSegmentTable& network_segments) noexcept
```

**RCU 版本签名变更：**

```cpp
template <typename T>
static bool Firewall_IsDropNetworkSegment(
    const boost::asio::ip::address& ip, T __ip, int max_prefix,
    const Firewall::NetworkSegmentTable& network_segments) noexcept
//  ^^^^^ 新增 const — 快照是不可变的
```

**影响范围：** 仅 `IsDropNetworkSegment` 的读取路径调用此模板，参数从 `&network_segments_`（可变引用）改为 `&snap->network_segments`（const 引用）。函数内部仅执行 `find` 和 `count`，不修改容器，因此 `const` 修饰无行为变化。

---

### 阶段 4：清理（低风险）

13. **移除旧的容器成员**：`ports_`、`ports_tcp_`、`ports_udp_`、`network_domains_`、`network_segments_`。
14. **保留 `syncobj_`**：仅保护写入路径的 read-modify-write 序列。
15. **更新文档和注释**。

### 阶段 5：可选优化（独立）

16. **反向 trie 后缀匹配**：替换 `unordered_set<string>` 为 trie 结构。
17. **`string_view` 后缀匹配**：不改变数据结构，仅优化匹配过程。
18. **单趟 normalize**：替换 `LTrim(RTrim(ToLower(...)))` 链。

### 回滚策略

每个阶段都是可独立回滚的。如果发现问题，可以：

1. 编译期开关：通过 `#define PPP_FIREWALL_RCU_SNAPSHOT 0` 回退到旧实现。
2. Git 回滚：每个阶段作为独立 commit，可精确回滚。

---

## 10. 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| `shared_ptr` control block 内存泄漏 | 低 | 高 | 确保所有路径都通过 `atomic_store` 发布，不保留裸 `shared_ptr` 引用 |
| 写入路径忘记发布快照 | 低 | 高 | 所有 `Drop*` 方法使用统一的 Copy-Modify-Publish helper |
| 写写并发 lost update | 中 | 中 | 保留 `syncobj_` 排他锁保护写入路径 |
| `atomic_load` 性能不如预期 | 低 | 低 | 全局 spinlock 表开销约 20-50ns，远低于当前 `shared_lock` + 全表复制 |
| 旧快照内存延迟回收 | 低 | 低 | 最后一个读者释放 `shared_ptr` 后自动回收，无内存泄漏 |
| C++17 free functions 在 C++26 被移除 | 高（远期） | 中 | 引入 `atomic_load_compat` 包装，升级时替换为 `atomic<shared_ptr<T>>` |

---

## 11. 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 无自动化测试 | 功能正确性需通过代码审查保证 | ❌ 无测试 |
| C-2 | `ppp::string` 类型确认 | 需确认 `ppp::string` 支持 move 语义和 `noexcept` 构造 | ⚠️ 需验证 |
| C-3 | `ppp::unordered_set` / `ppp::unordered_map` 支持 move | 快照复制需要高效 move | ⚠️ 需验证 |
| C-4 | 性能基准工具存在 | 需要基准测试验证收益 | ❌ 无基准工具 |
| C-5 | `shared_ptr<const T>` 确认可哈希容器支持 | `unordered_set/map` 的 `const` 版本需支持 move 构造 | ⚠️ 需验证 |

---

## 12. 时间线估计

| 阶段 | 工作量 | 依赖 |
|------|--------|------|
| 阶段 1（准备） | 0.5 天 | 无 |
| 阶段 2（读取路径） | 1 天 | 阶段 1 |
| 阶段 3（写入路径） | 1 天 | 阶段 2 |
| 阶段 4（清理） | 0.5 天 | 阶段 3 |
| 阶段 5（可选优化） | 2-3 天 | 阶段 4 |
| **总计** | **3-6 天** | — |

---

## 13. 总结

| 维度 | 当前实现 | RCU 实现 |
|------|----------|----------|
| 读取路径锁 | `shared_lock` 每次获取 | 不获取 `shared_mutex`，仅执行 `atomic_load`（是否 lock-free 由标准库实现决定） |
| 域名查询复制 | O(N) 深拷贝 | 零拷贝（`shared_ptr` 副本） |
| 写入路径 | `unique_lock` + 直接修改 | `unique_lock` + Copy-Modify-Publish |
| 并发读取吞吐 | 受 `shared_lock` 限制 | 近乎线性扩展 |
| 内存模型 | 单份规则表 + 查询时临时副本 | 新旧快照共存（瞬态双倍） |
| 代码复杂度 | 低 | 中 |
| C++ 标准要求 | C++17 | C++17（free functions） |
| C++20 迁移成本 | — | 低（替换为 `atomic<shared_ptr<T>>`） |

---

*创建时间：2026-05-11*
*P3-3 细化时间：2026-05-12*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §4.6*
*关联治理项：P2-12（Firewall 规则匹配热路径优化）/ P3-3（写入路径迁移设计细化）*

---

## 14. P3-3 验收检查清单

> **状态：设计细化完成，未实施。** 以下检查清单用于实施阶段的代码审查和验证。

### 14.1 写入路径正确性检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| W-01 | 每个 `Drop*` 方法的 load-copy-modify-store 四步在同一 `SynchronizedObjectScope` 内 | 代码审查：确认 `scope` 的生命周期覆盖四步 | **高** | ☐ 未验证 |
| W-02 | `atomic_store` 的参数类型为 `shared_ptr<const FirewallRuleSnapshot>` | 代码审查：确认显式转换为 const 指针 | **高** | ☐ 未验证 |
| W-03 | `make_shared` 的 `bad_alloc` 在锁内被捕获且不泄漏 | 代码审查：确认 catch 块在 `scope` 生命周期内 | **高** | ☐ 未验证 |
| W-04 | `SetLastErrorCode` 在锁释放后调用 | 代码审查：确认错误码设置在 `scope` 析构之后 | 中 | ☐ 未验证 |
| W-05 | `Clear()` 发布的空快照确实所有容器为空 | 代码审查：确认 `make_shared<FirewallRuleSnapshot>()` 默认构造 | **高** | ☐ 未验证 |
| W-06 | `DropNetworkSegment` 的 `set_network_segments` lambda 参数类型为 `NetworkSegmentTable&`（非 const） | 代码审查：确认 lambda 可修改 `new_snap->network_segments` | **高** | ☐ 未验证 |
| W-07 | `DropNetworkDomains` 的 normalize（ToLower/LTrim/RTrim）在锁外执行 | 代码审查：确认 `host_lower` 计算在 `SynchronizedObjectScope` 之前 | 中 | ☐ 未验证 |
| W-08 | `LoadWithRules`（策略 B）的解析步骤在锁外执行 | 代码审查：确认 `parsed` vector 构建在锁之前 | 中 | ☐ 未验证 |

### 14.2 并发安全检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| C-01 | 所有写入路径使用 `SynchronizedObjectScope`（`unique_lock`） | 代码审查：grep 所有 `atomic_store` 调用，确认每个都在 `scope` 生命周期内 | **高** | ☐ 未验证 |
| C-02 | 所有读取路径不获取 `syncobj_` 的任何锁 | 代码审查：grep `Is*` 方法，确认无 `SynchronizedObjectScope` 或 `SharedSynchronizedObjectScope` | **高** | ☐ 未验证 |
| C-03 | `snapshot_` 的所有访问都通过 `atomic_load/store` | 代码审查：grep `snapshot_`，确认无直接 copy/move/read | **高** | ☐ 未验证 |
| C-04 | 无 mixed access（部分路径用 `atomic_load`，部分路径直接读写 `snapshot_`） | 代码审查：同 C-03 | **高** | ☐ 未验证 |
| C-05 | `Clear()` 与 `Drop*` 不会并发发布不一致快照 | 代码审查：确认两者都持有 `syncobj_` 排他锁 | **高** | ☐ 未验证 |
| C-06 | `LoadWithRules`（策略 B）的批量修改是原子的（单次 store） | 代码审查：确认批量修改后仅调用一次 `atomic_store` | **高** | ☐ 未验证 |

### 14.3 语义保持检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| S-01 | `DropNetworkPort(port)` 返回值语义不变（`true` = 新插入，`false` = 已存在） | 对比当前实现 `emplace().second` | **高** | ☐ 未验证 |
| S-02 | `DropNetworkPort(port, tcp_or_udp)` 返回值语义不变 | 同上 | **高** | ☐ 未验证 |
| S-03 | `DropNetworkSegment` 的 prefix 取较小值逻辑不变 | 对比当前 lambda `if (prefix < now) { now = prefix; }` | **高** | ☐ 未验证 |
| S-04 | `DropNetworkDomains` 的 normalize 语义不变 | 对比 `LTrim(RTrim(ToLower(host)))` | **高** | ☐ 未验证 |
| S-05 | `Clear()` 后所有 `Is*` 方法返回 `false` | 功能测试 | **高** | ☐ 未验证 |
| S-06 | `LoadWithRules` 的解析逻辑不变（drop ip/port/dns 语法） | 对比当前解析代码 | **高** | ☐ 未验证 |
| S-07 | 错误码体系不变（`NetworkPortInvalid`、`FirewallDropPortAlreadyExists` 等） | 对比 `ErrorCodes.def` | 中 | ☐ 未验证 |
| S-08 | `IsSameNetworkDomains` 的匹配语义不变（精确 + 后缀） | 功能测试 | **高** | ☐ 未验证 |

### 14.4 编译与链接检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| B-01 | 新增 `FirewallRuleSnapshot` 结构体在 `Firewall.h` 中正确定义 | 编译 | **高** | ☐ 未验证 |
| B-02 | `snapshot_` 成员类型为 `std::shared_ptr<const FirewallRuleSnapshot>` | 编译 | **高** | ☐ 未验证 |
| B-03 | `std::atomic_load/store` 的模板参数推导无歧义 | 编译（确认显式 `const` 转换） | **高** | ☐ 未验证 |
| B-04 | 无新增头文件依赖（`<memory>` 已在 `stdafx.h` 中包含） | 编译 + 头文件审查 | 中 | ☐ 未验证 |
| B-05 | `Firewall_IsDropNetworkSegment` 模板的 `const` 参数兼容 | 编译 | **高** | ☐ 未验证 |
| B-06 | `LoadWithRules`（策略 B）的 `ParsedRule` 结构体定义无编译错误 | 编译 | 中 | ☐ 未验证 |
| B-07 | 编译无新增 warning（`-Wall -Wextra` 或项目默认警告级别） | 编译 | 中 | ☐ 未验证 |

### 14.5 回滚与兼容性检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| R-01 | 编译期开关 `PPP_FIREWALL_RCU_SNAPSHOT` 可禁用 RCU 路径 | 编译 + 运行 | **高** | ☐ 未验证 |
| R-02 | 禁用 RCU 后代码行为与当前实现完全一致 | 功能对比 | **高** | ☐ 未验证 |
| R-03 | 启用 RCU 后 public API 签名无变化 | 编译（所有调用方无需修改） | **高** | ☐ 未验证 |
| R-04 | `LoadWithFile` 委托 `LoadWithRules` 的路径不受影响 | 代码审查 | 中 | ☐ 未验证 |

### 14.6 性能回归检查

| 序号 | 检查项 | 验证方法 | 优先级 | 状态 |
|------|--------|----------|--------|------|
| P-01 | 读取路径延迟不增加（`atomic_load` vs `shared_lock`） | 基准测试 | **高** | ☐ 未验证 |
| P-02 | 写入路径延迟不超过当前实现的 1.5 倍 | 基准测试 | 中 | ☐ 未验证 |
| P-03 | `LoadWithRules`（策略 B）批量加载延迟不超过当前实现的 2 倍 | 基准测试 | 中 | ☐ 未验证 |
| P-04 | 写入期间瞬态内存峰值 ≤ 2 × 规则表大小 | 内存分析 | 中 | ☐ 未验证 |
| P-05 | 旧快照在所有读者释放后正确回收（无内存泄漏） | 内存分析 / valgrind | 中 | ☐ 未验证 |

---

## 15. P3-3 设计决策记录

### 15.1 决策：保留 `syncobj_` 排他锁保护写入路径

| 选项 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| **A. 保留排他锁** | 简单、可预测、无 lost update | 写入者之间仍然串行 | ✅ 采用 |
| B. CAS 循环 | 理论上无锁 | C++17 虽支持 `shared_ptr` CAS free functions，但每次失败需重新拷贝；批量操作成本和语义更难控制 | ❌ 不采用 |
| C. 写入者队列 | 写入可异步化 | 引入额外复杂度；规则加载需要同步等待结果 | ❌ 不采用 |

### 15.2 决策：`LoadWithRules` 策略选择

| 选项 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| **A. 逐条调用 Drop*** | 最小代码变更 | O(N×R) 拷贝 | 初始迁移采用 |
| **B. 批量 Copy-Modify-Publish** | O(R) 拷贝，单次锁获取 | 代码变更较大 | 生产环境推荐 |

### 15.3 决策：错误码设置位置

| 选项 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| **A. 锁外设置** | 锁持有时间最小化；避免锁内重入风险 | 错误码设置与快照发布之间有微小窗口 | ✅ 采用 |
| B. 锁内设置 | 错误码与快照发布原子 | 增加锁持有时间；诊断代码可能重入 | ❌ 不采用 |

---

*P3-3 设计细化完成。实施前需完成 14 节验收检查清单中的所有 **高** 优先级项目。*
