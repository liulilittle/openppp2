# DoH 对照下的 DoT/TCP `slot0` 复用问题专项设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **文档类型：设计文档，暂不实施**
> **状态：只读记录，不触发代码行为变更**
> **创建日期：2026-05-12**
> **关联审计条目：`docs/openppp2-deep-code-audit-cn.md` §14.7 B-3、§14.6 S-3**
> **关联治理记录：`docs/p2-governance-decisions-cn.md` P2-21**

---

## 1. 问题概述

`ppp/dns/DnsResolver.cpp` 的 DoT（`SendDot`）和 TCP（`SendTcp`）异步链中，`CompletionState::slot0` 在查询生命周期内承担了两个不同的语义角色：

1. **阶段一（发送阶段）**：`slot0` 持有 request buffer（含 2 字节长度前缀 + DNS 查询报文），供 `boost::asio::async_write` 引用。
2. **阶段二（接收阶段）**：write handler 完成后，`slot0` 被覆盖为新分配的 response buffer，供后续 `boost::asio::async_read` 引用。

DoH 链不涉及此问题——它使用 `slot0`（http_req）、`slot1`（read_buf）、`slot2`（http_res）三个独立槽位，语义始终不变。

---

## 2. 受影响代码位置

### 2.1 DoT 链（`SendDot`）

| 行号 | 操作 | 说明 |
|------|------|------|
| 1571 | `state->slot0 = request;` | 初始赋值：request buffer（长度前缀 + DNS 查询） |
| 1715 | `async_write(*stream_inner, boost::asio::buffer(request_inner->data(), request_inner->size()), ...)` | write handler 启动时，Asio 通过 `boost::asio::buffer()` 持有 request data 的指针/大小视图 |
| 1766 | `state->slot0 = response;` | **复用点**：write handler 内部的 read-length handler 中，request buffer 被 response buffer 替换 |
| 1774 | `async_read(*stream_b, boost::asio::buffer(response->data(), response->size()), ...)` | response buffer 被用于读取响应体 |
| 1785 | `auto response_r = std::static_pointer_cast<ppp::vector<Byte>>(state->slot0);` | 读取 response buffer |

### 2.2 TCP 链（`SendTcp`）

| 行号 | 操作 | 说明 |
|------|------|------|
| 1941 | `state->slot0 = request;` | 初始赋值 |
| 1998 | `async_write(*socket_local, boost::asio::buffer(request_local->data(), request_local->size()), ...)` | 同 DoT |
| 2045 | `state->slot0 = response;` | **复用点** |
| 2052 | `async_read(*socket_b, boost::asio::buffer(response->data(), response->size()), ...)` | response buffer 被用于读取 |
| 2063 | `auto response_r = std::static_pointer_cast<ppp::vector<Byte>>(state->slot0);` | 读取 response buffer |

---

## 3. 隐式契约分析

### 3.1 当前依赖的假设

slot0 复用的安全性依赖以下**隐式假设链**：

1. **Asio write completion handler 在 write 完成后才被调用**：`boost::asio::async_write` 保证在所有数据写入底层 SSL stream 后才调用 completion handler。
2. **write handler 内部的 `async_read`（读取 2 字节长度前缀）完成后才执行 slot0 覆盖**：代码流程是线性的——write handler → read-length handler → slot0 覆盖 → read-body handler。
3. **write handler 执行时，Asio 不再持有 request buffer 的引用**：`boost::asio::buffer()` 创建的是非拥有的指针/大小视图，write 完成后视图失效。
4. **`shared_ptr<CompletionState>` 通过 lambda capture 保持所有资源存活**：即使 slot0 被覆盖，旧 request buffer 的 `shared_ptr` 引用计数归零后才被释放。

### 3.2 为什么这些假设当前成立

在 Boost.Asio 的 strand-per-connection 或单线程 io_context 模型下：

- `async_write` 是 composed operation，内部循环调用 `SSL_write` 直到所有字节写入。
- completion handler 在写入完成后由 io_context 调度。
- 同一连接上的 `async_read`（长度前缀）在 write handler 内启动，其 completion handler 在读取完成后调度。
- 因此 slot0 覆盖发生在 write 已完成 + 长度前缀已读取之后，write 不再引用旧 buffer。

---

## 4. 风险分析

### 4.1 风险等级：低（当前代码）

当前静态分析未证明存在已触发 UAF；风险主要来自未来重构、Asio 语义变化或 handler 顺序变化。需要关注以下隐患：

### 4.2 异步 write buffer 生命周期风险

| 场景 | 风险 | 可能性 | 严重性 |
|------|------|--------|--------|
| Asio 实现变更导致 write handler 在 write 完成前被调用 | 在违反 Asio write completion 语义的假设下，request buffer 可能被提前释放，形成生命周期不足风险 | 极低 | 高（潜在 UAF） |
| 反射型 SSL 实现中 write 操作需要重读数据（如 renegotiation） | request buffer 已被 response 替换 | 低 | 中 |
| 代码重构破坏 handler 嵌套顺序 | slot0 覆盖点前移到 write 未完成时 | 中（人为错误） | 高 |

### 4.3 Asio handler 触发顺序风险

Boost.Asio 文档保证 composed operation 的 completion handler 在操作完成后调用，但：

- **不保证同一连接上不同操作的 handler 交错顺序**（除非在同一 strand 上）。
- 当前代码依赖 write handler → read-length handler → slot0 覆盖的严格嵌套顺序。
- 如果未来重构将 read-length 提取为独立的顶层 async 操作（而非嵌套在 write handler 内），slot0 覆盖可能与 write 竞争。

### 4.4 shared_ptr 延长生命周期的隐式保护

当前代码中，DoT 的 connect handler lambda 捕获了 `[state]`，但 request buffer 本身仅通过 `state->slot0` 持有。当 slot0 被覆盖时：

```cpp
// 此前 slot0 = shared_ptr<vector<Byte>> (request)
// 覆盖后 slot0 = shared_ptr<vector<Byte>> (response)
// request 的 shared_ptr 引用计数 -1
// 如果 write handler 的 lambda 仍持有 state（它确实持有），request buffer 的生命周期
// 取决于是否有其他 shared_ptr 指向它
```

关键点：**DoT/Write handler lambda 捕获了 `[state]`，但没有单独捕获 request buffer**。request buffer 仅通过 `state->slot0` 持有。如果 slot0 被覆盖且没有其他引用，request buffer 的引用计数归零并被释放。此时如果 Asio 仍在使用 request buffer（违反假设 1），可能形成 request buffer 生命周期不足，进而存在 UAF 风险；当前代码未证明存在已触发的 UAF。

**当前静态审查结论**：未发现已触发的 UAF 证据；现有代码依赖 write handler 在 slot0 覆盖之前完成、Asio 不再引用 request buffer 这一时序假设。该假设是**时序保证**，不是**所有权保证**，仍需在实施、重构或 Asio 升级前复核。

### 4.5 可读性与可维护性风险

| 问题 | 说明 |
|------|------|
| 语义歧义 | `slot0` 在不同阶段表示不同类型的对象，阅读者需要追踪完整异步链才能理解 |
| `static_pointer_cast` 类型安全缺失 | 所有 slot 使用 `shared_ptr<void>`，`static_pointer_cast<T>(state->slot0)` 在编译期无法校验类型正确性 |
| 重构脆弱性 | 未来若改变 handler 嵌套顺序并提前覆盖 slot0，可能无声地引入 request buffer 生命周期不足风险 |
| 调试困难 | 核心 dump 中 slot0 的类型取决于执行到哪个阶段，增加诊断成本 |

---

## 5. 最小修复方案

### 5.1 方案 A：分离 request/response 命名字段（推荐）

将 `CompletionState` 的通用 `slot0..slot3` 替换为语义明确的命名字段：

```cpp
struct CompletionState final {
    // ... 现有成员 ...

    // 命名 buffer 槽——每个槽的语义在声明时固定
    std::shared_ptr<void> request_buf;   // DoT/TCP: request; DoH: http_req
    std::shared_ptr<void> response_buf;  // DoT/TCP: response body; DoH: http_res
    std::shared_ptr<void> aux_buf0;      // DoT/TCP: length_buffer; DoH: read_buf
    std::shared_ptr<void> aux_buf1;      // 保留
};
```

**DoT 链改动**：

```cpp
// 初始化
state->request_buf = request;      // 原 slot0 = request
state->aux_buf0 = length_buffer;   // 原 slot1 = length_buffer

// write handler 中
auto request_inner = std::static_pointer_cast<ppp::vector<Byte>>(state->request_buf);
// ... async_write ...

// read-length handler 中
// 不再覆盖 request_buf；使用独立的 response_buf
std::shared_ptr<ppp::vector<Byte>> response = make_shared_object<ppp::vector<Byte>>(response_size);
state->response_buf = response;    // 新增：独立槽

// read-body handler 中
auto response_r = std::static_pointer_cast<ppp::vector<Byte>>(state->response_buf);
```

**优势**：
- request buffer 生命周期与 response buffer 解耦，即使未来重构改变覆盖时机，也能降低 request buffer 生命周期不足的风险。
- 语义清晰，无需追踪异步链即可理解每个槽的用途。
- 与 DoH 链的 slot 使用方式自然对齐。

**代价**：
- 每次 DoT/TCP 查询多一次 `shared_ptr<vector<Byte>>` 分配（response buffer），但该分配在当前代码中已存在（`make_shared_object<ppp::vector<Byte>>(response_size)`），只是此前赋值给 slot0 而非新字段。
- `CompletionState` 结构体变更，所有 Send* 函数需要同步更新字段名。

### 5.2 方案 B：write handler 后显式释放 request

在 write handler 的 success 路径中，在启动 read-length 之前显式清空 request buffer：

```cpp
// write handler success path
state->slot0.reset();  // 显式释放 request buffer
// 然后在 read-length handler 中重新赋值
state->slot0 = response;
```

**优势**：最小改动（1 行）。
**劣势**：
- 仍然依赖"write 完成后 Asio 不再引用 buffer"的隐式假设。
- `slot0` 语义仍然不清晰。
- 与方案 A 相比，安全性增益有限。

### 5.3 方案 C：typed state 子类（长期方案）

为每种协议创建专用的 CompletionState 子类：

```cpp
struct DotCompletionState final {
    // 公共成员 ...
    std::shared_ptr<ppp::vector<Byte>> request;
    std::shared_ptr<std::array<Byte, 2>> length_buffer;
    std::shared_ptr<ppp::vector<Byte>> response;
};

struct DohCompletionState final {
    // 公共成员 ...
    std::shared_ptr<http_request_t> http_req;
    std::shared_ptr<boost::beast::flat_buffer> read_buf;
    std::shared_ptr<http_response_t> http_res;
};
```

**优势**：完全消除类型擦除，编译期类型安全。
**劣势**：改动较大，与 S-3（类型擦除治理）合并实施更合理。

### 5.4 推荐路径

1. **当前阶段**：仅记录设计，不触发代码行为变更。
2. **后续实施阶段（满足前置条件后）**：优先评估方案 A（命名字段），消除 slot 复用的隐式依赖。
3. **与 S-3 合并**：在 CompletionState 类型安全化设计中统一评估 typed state 方案。
4. **不优先做**：方案 B（收益不足）。

---

## 6. 为什么不应依赖隐式 slot0 复用

| 原则 | 说明 |
|------|------|
| **显式优于隐式** | slot0 复用依赖 handler 执行顺序的隐式保证，违反"代码应自文档化"原则 |
| **所有权应由结构保证** | request buffer 的"不再需要"应通过所有权转移（reset/覆盖到独立字段）显式表达，而非依赖"write handler 已完成"的时序假设 |
| **重构安全** | 显式分离可降低未来调整 handler 嵌套顺序时引入 request buffer 生命周期不足风险的概率 |
| **调试友好** | 核心 dump 中 request_buf 和 response_buf 的类型和值始终可确定 |
| **审计一致性** | 与审计 S-3（类型擦除）和 A-2（CompletionState 模板化）的治理方向一致 |

---

## 7. 与 CompletionState 类型安全化设计的关系

本文档聚焦于 slot0 复用的**具体风险和最小修复**。CompletionState 的整体类型安全化（S-3）是一个更广泛的治理项，涉及：

- `shared_ptr<void>` → typed fields 或 `std::variant`
- per-protocol 子类拆分（A-2）
- `StunCompletionState` 模板合并

本设计文档的方案 A（命名字段）可作为 S-3 实施时的低侵入子方案候选。后续与 CompletionState 类型安全化设计合并时，命名字段可自然升级为 typed fields。

> 本文档仅记录设计；即使采用方案 A，也必须在满足前置条件并完成评审后实施。

---

## 8. 修复影响评估

| 维度 | 影响 |
|------|------|
| **行为变更** | 无——slot 语义不变，仅将一个 slot 拆为两个命名字段 |
| **API 变更** | 无——`CompletionState` 是 `DnsResolver.cpp` 内部 struct，无 public API |
| **性能影响** | 中性——DoT/TCP 每次查询多一个 `shared_ptr` 控制块（约 32 字节），已有的 `make_shared_object` 分配不变 |
| **兼容性** | 完全向后兼容——不影响配置、协议、外部接口 |
| **测试需求** | 无自动化测试基础设施；需手动验证 DoT/TCP 查询正常工作 |

---

## 9. 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 理解所有 slot 使用点 | 确认 DoH/DoT/TCP/UDP 各链的 slot 语义 | ✅ 已完成（本文档 §2） |
| C-2 | 确认无外部代码依赖 slot 编号 | `CompletionState` 是内部 struct，无外部使用者 | ✅ 已确认 |
| C-3 | 手动测试覆盖 DoT/TCP 路径 | 验证修改后查询正常 | ❌ 无自动化测试 |
| C-4 | 与 S-3 实施计划对齐 | 确保命名字段方案与长期 typed state 方向一致 | ⚠️ 需对齐 |

---

## 10. 当前约束

- **不得将该项作为 P0 或当前 release 的阻断条件。**
- **不得在其他修复分支中混入该项的代码改动。**
- **本文档仅作记录用途，不触发代码行为变更。**
- **不得声称该问题已修复。**
- 实施时必须保持 DoH/DoT/TCP/UDP 所有协议链的行为完全不变。

---

## 11. 后续触发条件

| 触发条件 | 动作 |
|---|---|
| CompletionState 类型安全化设计启动（S-3） | 将本方案 A 作为子集纳入，升级为 typed fields |
| Boost.Asio 版本升级 | 复核 write completion 语义是否变更 |
| DoT/TCP 异步链重构 | 必须同时评估并优先纳入方案 A，消除隐式 slot 复用 |
| 引入自动化测试框架 | 可开始评估方案 A 并回归验证 |
| 发现 write handler 在 write 完成前被调用的证据 | 立即升级优先级并评估/实施方案 A |

---

*创建时间：2026-05-12*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.7 B-3、§14.6 S-3*
*关联治理记录：`docs/p2-governance-decisions-cn.md` P2-21*
