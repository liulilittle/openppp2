# `CompletionState` 类型安全化设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **文档状态：设计文档，暂不实施**
> **创建日期：2026-05-12**
> **关联审计条目：** `docs/openppp2-deep-code-audit-cn.md` §14.6 S-3（`CompletionState::slot0..slot3` 类型擦除）、§14.9 A-2（`CompletionState` / `StunCompletionState` 重复）
> **关联治理记录：** `docs/p2-governance-decisions-cn.md` P2-20

---

## 1. 文档性质声明

**本文档仅为设计分析和方案对比文档，不涉及任何运行代码的修改。**

- 当前 `CompletionState` 的集中持有 + CAS 单次完成模型与 `DnsResolver.cpp` 注释中的 Android arm64 SIGSEGV 修复背景一致；commit `ab00160` 在当前仓库可见，但本文档未独立核验该提交对应的真机崩溃修复验证结果。
- 本文档仅基于当前源码做静态设计分析，不声明现有实现已被完整运行时验证。
- 本文档的目的是记录类型擦除 slot 的使用模式、识别潜在误用风险、并提出改进方案供后续实施参考。
- 实施本文档中的任何方案前，必须具备基本集成测试基础设施。

---

## 2. 当前 `CompletionState` 结构

**位置：** `ppp/dns/DnsResolver.cpp:489-585`

```cpp
struct CompletionState final {
    std::atomic<bool>                           completed{ false };
    DnsResolver::ResolveCallback                callback;

    // 具名 I/O 资源（类型明确）
    std::shared_ptr<boost::asio::steady_timer>  timer;
    std::shared_ptr<boost::asio::ssl::context>  ssl_ctx;
    std::shared_ptr<boost::asio::ssl::stream<tcp::socket>> tls_stream;
    std::shared_ptr<tcp::socket>                tcp_socket;
    std::shared_ptr<udp::socket>                udp_socket;

    // 类型擦除的通用槽位
    std::shared_ptr<void>                       slot0;
    std::shared_ptr<void>                       slot1;
    std::shared_ptr<void>                       slot2;
    std::shared_ptr<void>                       slot3;
    // ...
};
```

**`StunCompletionState`**（`DnsResolver.cpp:603-645`）是独立的 STUN 专用结构体，使用相同的 CAS-guarded 单次完成模式，但回调签名不同（`ExitIpCallback` 而非 `ResolveCallback`）。

---

## 3. 各协议 Slot 使用模式分析

以下基于对 `DnsResolver.cpp` 当前代码的逐行审查。每个 `Send*` 方法独立创建自己的 `CompletionState` 实例，不存在跨协议共享。

### 3.1 DoH (`SendDoh`，第 1234-1538 行)

| Slot | 实际类型 | 写入时机 | 读取时机 | 生命周期说明 |
|------|----------|----------|----------|-------------|
| `slot0` | `shared_ptr<http_request_t>` | TLS 握手完成后（第 1457 行） | HTTP write 回调中通过 beast 引用 | 请求发出后由 beast 内部引用保活 |
| `slot1` | `shared_ptr<flat_buffer>` | 同上（第 1458 行） | HTTP read 回调中（第 1490 行） | beast `async_read` 按引用持有 |
| `slot2` | `shared_ptr<http_response_t>` | 同上（第 1459 行） | HTTP read 回调中（第 1491、1511 行） | 读取完成后提取 body |
| `slot3` | **未使用** | — | — | — |

**关键特征：**
- 三个 slot 的类型完全不同（`http_request_t`、`flat_buffer`、`http_response_t`）。
- 所有 slot 在 TLS 握手成功后一次性赋值，后续阶段只读。
- 每次 `static_pointer_cast` 必须匹配正确的 slot 编号和类型，无编译期保障。

### 3.2 DoT (`SendDot`，第 1544-1798 行)

| Slot | 实际类型 | 写入时机 | 读取时机 | 生命周期说明 |
|------|----------|----------|----------|-------------|
| `slot0` | `shared_ptr<vector<Byte>>` → **回收为** `shared_ptr<vector<Byte>>` | 初始化时为 request（第 1571 行）；长度前缀读取完成后被 response 覆盖（第 1766 行） | 写阶段（第 1708 行）；body 读阶段（第 1785 行） | **slot0 复用**：request → response |
| `slot1` | `shared_ptr<array<Byte, 2>>` | 初始化时（第 1572 行） | 长度前缀读回调中（第 1727、1744 行） | 整个读取阶段保持 |
| `slot2` | **未使用** | — | — | — |
| `slot3` | **未使用** | — | — | — |

**关键特征：**
- **`slot0` 存在复用**：初始存放 request buffer（`vector<Byte>`），在长度前缀接收完成后被替换为 response buffer（也是 `vector<Byte>`）。
- 复用的隐式前提：写操作已完成，boost::asio 不再引用旧 request buffer。这依赖于 `async_write` → `async_read` 的严格串行执行顺序。
- `slot0` 的两次类型相同（`vector<Byte>`），但语义完全不同（request vs response）。

### 3.3 UDP (`SendUdp`，第 1804-1908 行)

| Slot | 实际类型 | 写入时机 | 读取时机 | 生命周期说明 |
|------|----------|----------|----------|-------------|
| `slot0` | `shared_ptr<vector<Byte>>` | 初始化时（第 1831 行） | receive 回调中（第 1873、1891 行） | 接收缓冲区，接收完成后 resize 并返回 |
| `slot1` | `shared_ptr<udp::endpoint>` | 初始化时（第 1832 行） | receive 回调中（第 1874 行） | `async_receive_from` 的源端点 |
| `slot2` | **未使用** | — | — | — |
| `slot3` | **未使用** | — | — | — |

**关键特征：**
- 无 slot 复用，生命周期简单。
- `slot0`（recv buffer）和 `slot1`（endpoint）类型完全不同，无歧义。

### 3.4 TCP (`SendTcp`，第 1914-2075 行)

| Slot | 实际类型 | 写入时机 | 读取时机 | 生命周期说明 |
|------|----------|----------|----------|-------------|
| `slot0` | `shared_ptr<vector<Byte>>` → **回收为** `shared_ptr<vector<Byte>>` | 初始化时为 request（第 1941 行）；长度前缀读取完成后被 response 覆盖（第 2045 行） | 写阶段（第 1993 行）；body 读阶段（第 2063 行） | **slot0 复用**：request → response（与 DoT 相同模式） |
| `slot1` | `shared_ptr<array<Byte, 2>>` | 初始化时（第 1942 行） | 长度前缀读回调中（第 2010、2026 行） | 整个读取阶段保持 |
| `slot2` | **未使用** | — | — | — |
| `slot3` | **未使用** | — | — | — |

**关键特征：**
- 与 DoT 的 slot 使用模式完全镜像。
- 同样存在 `slot0` 复用（request → response）。

### 3.5 STUN (`TryStunCandidate`，第 2488-2668 行)

使用独立的 `StunCompletionState`（非 `CompletionState`）：

| Slot | 实际类型 | 写入时机 | 读取时机 | 生命周期说明 |
|------|----------|----------|----------|-------------|
| `slot0` | `shared_ptr<vector<Byte>>` | 初始化时（第 2523 行） | send 回调中按引用传给 `async_send_to`（第 2567 行） | STUN request packet |
| `slot1` | `shared_ptr<vector<Byte>>` | 初始化时（第 2524 行） | receive 回调中（第 2579、2599 行） | recv buffer |
| `slot2` | `shared_ptr<udp::endpoint>` | 初始化时（第 2525 行） | receive 回调中（第 2580 行） | recv endpoint |
| `slot3` | **未使用** | — | — | — |

**关键特征：**
- 独立结构体，不与 DNS `CompletionState` 共享。
- 三个 slot 类型各不相同（两个 `vector<Byte>` 语义不同 + 一个 `endpoint`），但两个 `vector<Byte>` slot 需要通过编号区分。

### 3.6 使用模式汇总

| 协议 | slot0 类型 | slot1 类型 | slot2 类型 | slot3 | slot 复用 |
|------|-----------|-----------|-----------|-------|-----------|
| DoH | `http_request_t` | `flat_buffer` | `http_response_t` | 未用 | 无 |
| DoT | `vector<Byte>` (req→resp) | `array<Byte,2>` | 未用 | 未用 | **slot0 复用** |
| TCP | `vector<Byte>` (req→resp) | `array<Byte,2>` | 未用 | 未用 | **slot0 复用** |
| UDP | `vector<Byte>` (recv) | `udp::endpoint` | 未用 | 未用 | 无 |
| STUN | `vector<Byte>` (req) | `vector<Byte>` (recv) | `udp::endpoint` | 未用 | 无 |

> **注意：** 上述分析基于当前可见代码的逐行审查。实施前应逐调用点复核，确认没有遗漏的中间赋值或条件赋值路径。

---

## 4. 风险分析

### 4.1 类型安全性缺失

**核心问题：** `shared_ptr<void>` 槽位的类型语义完全依赖注释和调用约定，编译器无法在 `static_pointer_cast` 时校验类型正确性。

**误用场景示例：**
- 将 DoH 的 `slot0`（`http_request_t`）误当作 `slot1`（`flat_buffer`）读取 → 运行时 UB。
- 将 STUN 的 `slot0`（request）和 `slot1`（recv buffer）互换 → 静默数据损坏。
- 新增协议时误用 slot 编号 → 无编译期警告。

**当前缓解因素：**
- 每个 `Send*` 方法独立创建 `CompletionState`，不存在跨协议的 slot 读取。
- 异步 lambda 在同一方法内闭合，slot 编号一致性由代码局部性保证。

### 4.2 `slot0` 复用的隐式契约

**DoT 和 TCP 的 `slot0` 复用**（request → response）依赖以下隐式前提：

1. `async_write` 完成回调执行时，boost::asio 已释放对 request buffer 的所有引用。
2. 在 `async_write` 完成回调中赋值 `slot0 = response` 之前，没有任何其他异步操作会读取 `slot0`。
3. `CompletionState` 的 `Complete()` 方法不读取 slot 内容（当前正确——`Complete()` 只关闭 socket/timer 并调用 callback）。

这些前提在当前代码中成立，但未被类型系统强制。未来修改异步链顺序可能破坏这些前提。

### 4.3 `StunCompletionState` 与 `CompletionState` 的重复

审计 §14.9 A-2 指出两个结构体存在约 60 行代码重复（`completed`、`callback`、`timer`、`IsCompleted()`、`Complete()` 模板逻辑）。

**当前状态：**
- 两个结构体的回调签名不同（`ResolveCallback` vs `ExitIpCallback`）。
- `StunCompletionState` 使用 `udp::socket` 而非 `tcp::socket`/`ssl::stream`。
- 合并为模板可能引入不必要的复杂度，当前分离状态可接受。

### 4.4 与生命周期/线程安全的关系

**CompletionState 的生命周期模型（来自代码注释）：**

1. 每个 `Send*` 方法在入口处创建 `shared_ptr<CompletionState>`。
2. socket/stream/timer/buffer/slot 等 I/O 相关资源由 `CompletionState` 持有，并通过捕获 `state` 保活；部分 lambda 仍会捕获 `weak_self`、`packet`、host/path/SNI/host_key 等元数据或输入数据。
3. `Complete()` 使用 CAS (`compare_exchange_strong`) 保证单次执行。
4. 资源释放依赖 lambda 自然析构时的 `shared_ptr` 引用计数归零。
5. **不在 `Complete()` 中 reset slot/stream/timer**——这与当前源码注释中的 Android SIGSEGV 修复背景一致；本文档不独立声明已完成真机回归验证。

**slot 与生命周期的交互：**
- slot 中的 `shared_ptr` 对象（如 `http_request_t`、`flat_buffer`）通过 `CompletionState` 的 `shared_ptr` 引用链间接保活。
- 当最后一个异步 lambda 析构并释放其 `[state]` 捕获时，`CompletionState` 析构，所有 slot 的 `shared_ptr` 成员随之析构。
- **strand/线程边界**：当前代码未在 `CompletionState` 周围显式展示 strand 绑定；若该 `io_context` 由单线程运行，则 handler 天然串行；若多线程运行，则不同异步完成 handler 可能并发调度。`Complete()` 的 CAS 可保证完成回调单次执行，但 slot/timer/socket 成员访问是否完全串行仍依赖上层 io_context/strand 运行模型，实施前必须复核。

---

## 5. 改进方案

### 方案 A：`std::variant` / 类型化 payload

**思路：** 将 `slot0..slot3` 替换为每个协议专用的 `std::variant` 类型。

```cpp
// 每个协议的 payload 类型
struct DohPayload {
    std::shared_ptr<http_request_t>  http_req;
    std::shared_ptr<flat_buffer>     read_buf;
    std::shared_ptr<http_response_t> http_res;
};

struct DotPayload {
    std::shared_ptr<vector<Byte>>     request;  // 不再复用
    std::shared_ptr<vector<Byte>>     response; // 独立槽
    std::shared_ptr<array<Byte, 2>>   length_buf;
};

struct UdpPayload {
    std::shared_ptr<vector<Byte>>   recv_buf;
    std::shared_ptr<udp::endpoint>  source_ep;
};

struct TcpPayload {
    std::shared_ptr<vector<Byte>>     request;
    std::shared_ptr<vector<Byte>>     response;
    std::shared_ptr<array<Byte, 2>>   length_buf;
};

struct StunPayload {
    std::shared_ptr<vector<Byte>>   request;
    std::shared_ptr<vector<Byte>>   recv_buf;
    std::shared_ptr<udp::endpoint>  recv_ep;
};

// CompletionState 使用 variant
struct CompletionState final {
    // ... 公共成员 ...
    using Payload = std::variant<
        std::monostate,  // 未初始化
        DohPayload,
        DotPayload,
        UdpPayload,
        TcpPayload
    >;
    Payload payload;
};
```

**优点：**
- 类型集合在编译期受限：`std::get<DohPayload>(state->payload)` 在 alternative 不匹配时会显式抛出 `bad_variant_access`，比 `shared_ptr<void>` 的错误 cast 更容易暴露问题。
- 消除 `static_pointer_cast` 和 slot 编号约定。
- `slot0` 复用问题自然消失（request 和 response 成为独立字段）。

**缺点：**
- `std::variant` 在 C++17 下的 `visit` 语法较繁琐。
- 每个协议的 payload 类型需要独立定义，增加文件组织复杂度。
- `CompletionState` 不再是协议无关的——variant 的每个 alternative 都引入了协议依赖。
- 需要同步修改 `StunCompletionState` 或将其合并到 variant 中。

**生命周期影响：** 无。payload 中的 `shared_ptr` 成员的生命周期模型与当前 slot 相同。

### 方案 B：继承式专用状态结构

**思路：** 将 `CompletionState` 拆分为基类 + 派生类。

```cpp
// 基类：公共的完成守卫和 I/O 资源
struct CompletionStateBase {
    std::atomic<bool>                           completed{ false };
    std::shared_ptr<boost::asio::steady_timer>  timer;

    bool IsCompleted() const noexcept {
        return completed.load(std::memory_order_acquire);
    }

    // Complete() 仅关闭 timer，不关闭 socket/stream
    // （因为派生类可能有不同的 I/O 资源）
    void CloseAndCancel() noexcept {
        boost::system::error_code ignored;
        if (timer) timer->cancel(ignored);
    }
};

// DoH 专用
struct DohCompletionState : CompletionStateBase {
    DnsResolver::ResolveCallback                callback;
    std::shared_ptr<boost::asio::ssl::context>  ssl_ctx;
    std::shared_ptr<boost::asio::ssl::stream<tcp::socket>> tls_stream;

    std::shared_ptr<http_request_t>  http_req;
    std::shared_ptr<flat_buffer>     read_buf;
    std::shared_ptr<http_response_t> http_res;

    void Complete(ppp::vector<Byte> response) noexcept {
        bool expected = false;
        if (!completed.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            return;
        }
        CloseAndCancel();
        if (tls_stream) tls_stream->lowest_layer().close(ignored);
        auto cb = std::move(callback);
        callback = NULLPTR;
        if (cb) cb(std::move(response));
    }
};

// DoT 专用
struct DotCompletionState : CompletionStateBase {
    DnsResolver::ResolveCallback                callback;
    std::shared_ptr<boost::asio::ssl::context>  ssl_ctx;
    std::shared_ptr<boost::asio::ssl::stream<tcp::socket>> tls_stream;

    std::shared_ptr<vector<Byte>>     request;   // 始终保留
    std::shared_ptr<vector<Byte>>     response;  // 独立槽
    std::shared_ptr<array<Byte, 2>>   length_buf;

    void Complete(ppp::vector<Byte> resp) noexcept { /* ... */ }
};

// UDP、TCP、STUN 类似...
```

**优点：**
- 每个派生类的字段类型完全明确，无 `static_pointer_cast`。
- 可以精确定义每个协议需要的 I/O 资源（如 DoH 不需要 `tcp_socket`，UDP 不需要 `ssl_ctx`）。
- `slot0` 复用自然消失。
- 基类的 `CompletionStateBase` 可被 `StunCompletionState` 共用，减少重复。

**缺点：**
- 异步 lambda 需要捕获具体派生类型的 `shared_ptr`，而非统一的 `shared_ptr<CompletionState>`。
- 基类的 `Complete()` 需要模板化或虚函数化（虚函数在 `final` 结构体中不适用，可能需要 CRTP）。
- 当前代码中 `CompletionState` 被声明为 `final`，改为继承需要调整设计。
- 增加类数量，每个协议一个文件可能更合适（与审计 A-3 拆分 DnsResolver 的建议一致）。

**生命周期影响：** 需要确保 `shared_ptr<DohCompletionState>` 在 lambda 捕获时的类型正确性。当前的 `shared_ptr<CompletionState>` 统一捕获模式变为每个协议独立类型。

### 方案 C：小步 helper accessor / 命名字段过渡方案

**思路：** 在不改变 `shared_ptr<void>` 底层存储的前提下，通过类型化的 accessor 方法和命名常量减少误用风险。

```cpp
struct CompletionState final {
    // ... 现有成员不变 ...

    // 协议专用 accessor（inline，零开销）
    // DoH accessors
    auto& doh_request() noexcept {
        return *std::static_pointer_cast<http_request_t>(slot0);
    }
    auto& doh_read_buf() noexcept {
        return *std::static_pointer_cast<flat_buffer>(slot1);
    }
    auto& doh_response() noexcept {
        return *std::static_pointer_cast<http_response_t>(slot2);
    }

    // DoT / TCP accessors（消除 slot0 复用）
    auto& tcp_request() noexcept {
        return *std::static_pointer_cast<vector<Byte>>(slot0);
    }
    auto& tcp_length_buf() noexcept {
        return *std::static_pointer_cast<array<Byte, 2>>(slot1);
    }
    // 新增 slot4 用于 response，消除 slot0 复用
    auto& tcp_response() noexcept {
        return *std::static_pointer_cast<vector<Byte>>(slot4);
    }

    // UDP accessors
    auto& udp_recv_buf() noexcept {
        return *std::static_pointer_cast<vector<Byte>>(slot0);
    }
    auto& udp_source_ep() noexcept {
        return *std::static_pointer_cast<udp::endpoint>(slot1);
    }

private:
    std::shared_ptr<void> slot4;  // 新增：TCP/DoT response 专用
};
```

**替代变体：** 使用命名字段而非编号 slot：

```cpp
struct CompletionState final {
    // ... 公共成员 ...

    // 命名字段（仍为 shared_ptr<void>，但语义明确）
    std::shared_ptr<void> payload_a;  // DoH: http_req | DoT/TCP: request | UDP: recv_buf
    std::shared_ptr<void> payload_b;  // DoH: flat_buf | DoT/TCP: length_buf | UDP: endpoint
    std::shared_ptr<void> payload_c;  // DoH: http_res | DoT/TCP: (unused) | UDP: (unused)
    std::shared_ptr<void> payload_d;  // DoT/TCP: response (新增，消除复用)
};
```

**优点：**
- 最小侵入：不改变底层 `shared_ptr<void>` 存储，不改变 `Complete()` 逻辑。
- accessor 提供了有意义的名称，减少注释依赖。
- 渐进式：可以逐协议添加 accessor，不需要一次性重构。
- 消除 `slot0` 复用只需新增一个 slot。

**缺点：**
- 仍然是 `static_pointer_cast`，只是封装了一层。如果 accessor 的 cast 类型错误，仍然是运行时 UB。
- accessor 方法名称与协议耦合，但 `CompletionState` 本身设计为协议无关。
- 需要维护者纪律：新增协议时必须添加对应 accessor，不能直接操作 slot。

**生命周期影响：** 无。只是对现有 slot 的封装。

---

## 6. 方案对比

| 维度 | A: variant | B: 继承 | C: accessor |
|------|-----------|---------|-------------|
| **类型安全收益** | ✅ 类型集合编译期受限，错误 alternative 运行时显式失败 | ✅ 字段类型编译期明确 | ❌ 仍是运行时 cast |
| **消除 slot 复用** | ✅ 自然 | ✅ 自然 | ✅ 新增 slot |
| **代码变更量** | 中等 | 大 | 最小 |
| **侵入性** | 中等 | 高 | 低 |
| **与现有 lambda 捕获兼容** | 需改 lambda 类型 | 需改 lambda 类型 | 无需改动 |
| **与 A-3（拆分文件）协同** | 良好 | 良好 | 无关联 |
| **C++17 兼容性** | ✅ | ✅ | ✅ |
| **实施前置条件** | 集成测试 | 集成测试 | 低侵入但仍需评审/复核 |

---

## 7. 重点问题详述

### 7.1 生命周期：slot 赋值与异步链的时序依赖

**当前模型：**

```
Send* 入口 → 创建 CompletionState → 赋值具名资源(timer/socket/stream)
    → 赋值 slot0..N → 启动异步链
    → 异步回调中读取 slot → 最终 Complete()
    → lambda 逐步析构 → CompletionState 析构 → slot 析构
```

**关键约束：**
- slot 赋值必须在启动第一个异步操作之前完成。
- 异步回调中读取 slot 时，必须确保 `!state->IsCompleted()`。
- `Complete()` 不读取 slot 内容（当前正确）。

### 7.2 异步 lambda 捕获模式

**当前模式（简化示意）：**
```cpp
// I/O 资源通过 state 保活；实际代码中的部分 lambda 还捕获 weak_self、packet、host/path/SNI/host_key 等元数据
timer->async_wait([state](const error_code& ec) noexcept { ... });
stream->async_handshake(..., [state](const error_code& ec) noexcept { ... });
```

**模式的优势：**
- 单一引用源，生命周期由 `CompletionState` 统一管理。
- lambda 析构时自动释放对 `CompletionState` 的引用。
- 不存在"哪个 lambda 负责释放哪个资源"的歧义。
- 该描述仅针对 socket/stream/timer/buffer 等 I/O 生命周期资源；不能笼统理解为所有 lambda 都只捕获 `[state]`。

**模式对类型安全方案的影响：**
- 方案 A（variant）：lambda 仍捕获 `[state]`，但在读取 payload 时需要 `std::get<PayloadType>(state->payload)`，增加了每次访问的类型检查（variant 的 index 检查）。
- 方案 B（继承）：lambda 需要捕获具体派生类型，如 `[state = std::static_pointer_cast<DohCompletionState>(state)]`，在 `TryProtocols` 的统一分发点需要类型转换。
- 方案 C（accessor）：lambda 捕获不变，读取时使用 `state->doh_request()` 等方法。

### 7.3 Strand / 线程边界

**当前线程模型：**
- 当前代码未在 `CompletionState` 周围显式展示 strand 绑定。
- 若上层 `io_context` 单线程运行，handler 天然串行；若多线程运行，则不同异步完成 handler 可能并发调度。
- `Complete()` 的 CAS 守卫保证完成回调单次执行，但不应把它扩大解释为所有成员访问都天然串行。

**对类型安全方案的影响：**
- 在确认单线程 io_context 或显式 strand 约束前，不应假设所有成员访问天然串行。
- 方案实施时需复核是否需要 strand 绑定或额外同步约束；accessor（方案 C）和 `std::get`（方案 A）本身不提供同步。

### 7.4 `slot0` 复用问题的根因与解决

**根因：** DoT 和 TCP 的异步链结构为：

```
connect → handshake → write(request) → read(length_prefix) → read(body)
                         ↑ slot0=request    ↑ slot0 被覆盖为 response
```

复用 `slot0` 是为了在 request 发出后释放其内存，将同一槽位用于 response。这在功能上正确，但违反了"字段语义不变"的直觉。

**方案 A/B 的解决：** request 和 response 成为独立字段，自然消除了复用。

**方案 C 的解决：** 新增 `slot4`（或 `payload_d`）专门用于 response，`slot0` 保留 request 直到 `CompletionState` 析构。代价是 request buffer 在 response 接收期间仍占用内存（通常为 DNS 查询大小，约 100-500 字节，可忽略）。

---

## 8. 实施建议

### 8.1 推荐路径

1. **低侵入候选方案：** 方案 C — 添加 accessor 方法和命名常量，消除 `slot0` 复用。虽然风险较低且不改变底层结构，但仍需按治理流程评审和复核，不应由本文档触发立即实施。
2. **中期（需测试基础设施）：** 方案 A 或 B — 在具备基本集成测试后，选择 variant 或继承方案实现编译期类型安全。
3. **与 A-3 协同：** 如果同时进行 DnsResolver 文件拆分（审计 A-3），方案 B（继承）可自然地将每个派生类放入独立文件。

### 8.2 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试 | 至少覆盖 DoH/DoT/UDP/TCP/STUN 的端到端解析路径 | ❌ 无测试 |
| C-2 | 逐调用点复核 | 确认所有 slot 赋值/读取点与本文档 §3 分析一致 | ⚠️ 需实施前复核 |
| C-3 | 方案 C 可独立评估 | accessor 不改变底层存储，但仍需评审/复核 | ⚠️ 候选方案 |

### 8.3 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该重构的代码改动。
- 本文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持 `CompletionState::Complete()` 的 CAS 单次执行语义不变。
- 实施时必须保持 I/O 资源由 `CompletionState` 集中持有，并避免在 lambda 中分散捕获 socket/stream/timer/buffer 所有权。
- 不得在 `Complete()` 中读取或重置 slot 内容。

---

## 9. 后续触发条件

| 触发条件 | 动作 |
|----------|------|
| 引入基本集成测试框架 | 可开始评估方案 A 或 B 并回归验证 |
| 新增 DNS 协议（如 DoQ / DNS-over-QUIC） | 必须同时更新 slot 使用模式文档，评估是否需要更多 slot |
| `slot0` 复用引发实际 bug（如 boost::asio 版本变更导致 write 引用语义变化） | 立即实施方案 C 消除复用 |
| DnsResolver 文件拆分（审计 A-3） | 同步实施方案 B（继承），将每个协议的 CompletionState 放入独立文件 |
| 升级 C++20 | 可使用 `std::variant` 的 `std::visit` with `constexpr` lambda，方案 A 更简洁 |
| `CompletionState` 出现新的跨协议共享模式 | 重新评估是否需要统一的 slot 语义 |

---

*创建时间：2026-05-12*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.6 S-3、§14.9 A-2、§14.7 B-3*
