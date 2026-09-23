# Android ICMP 错误回送最小路径设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **文档类型**：设计文档（Design Document）
> **当前状态**：**已完成设计，暂不实施**
> **创建日期**：2026-05-11
> **关联审计项**：`docs/openppp2-deep-code-audit-cn.md` B-2
> **关联治理项**：`docs/p2-governance-decisions-cn.md` P2-13

---

## 1. 现状分析

### 1.1 当前行为

`ppp/app/client/VEthernetNetworkSwitcher::OnIcmpPacketInput()`（第 574 行）对所有非 `ICMP_ECHO`（Type 8）和 `ICMP_ER`（Type 0）的 ICMP 报文直接丢弃：

```cpp
if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
#if defined(_ANDROID)
    __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_drop unsupported type=%d code=%d dst=%s", ...);
#endif
    return false;
}
```

丢弃后 Android logcat 会记录 `icmp_drop unsupported type=<N> code=<M> dst=<addr>`。

### 1.2 功能影响

| 功能 | 依赖的 ICMP 类型 | 当前状态 |
|------|------------------|----------|
| **traceroute** | Time Exceeded（Type 11, Code 0） | ❌ 失效：隧道内 traceroute 无法收到中间跳 TTL 超时响应 |
| **PMTUD（路径 MTU 发现）** | Destination Unreachable / Fragmentation Needed（Type 3, Code 4） | ❌ 失效：大包被静默丢弃，TCP 无法执行 PMTUD，可能引发黑洞路由 |
| **UDP 快速失败** | Destination Unreachable / Port Unreachable（Type 3, Code 3） | ❌ 失效：UDP 短连接（DNS 53、QUIC 443 等）无法快速感知端口不可达 |
| **参数错误通知** | Parameter Problem（Type 12） | ⚠️ 低优先级：实际网络中极少触发 |

### 1.3 历史背景

旧实现曾将所有 ICMP 类型通过 `InternetControlMessageProtocol::Echo()` 的 Timer 路径转发。该路径的生命周期模型为：

1. 分配 raw socket（`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`）
2. 发送 ICMP 探测
3. 启动 `Timer::Timeout`（`MAX_ICMP_TIMEOUT = 3000ms`）
4. 异步接收响应
5. 超时/回调时通过 `EchoAsynchronousContext::Release()` 清理

**崩溃根因**：Android TUN 传入的 ICMP 错误报文（如 Destination Unreachable）不是 Echo 请求/响应，raw socket 的 `async_receive_from` 永远不会收到匹配的应答。Timer 超时后尝试清理 `EchoAsynchronousContext`，此时 `icmppackets_` 中的 `VEthernetIcmpPacket.packet`（`shared_ptr<IPFrame>`）可能已被释放或正在 Finalize 路径中释放，导致 use-after-free 或 dangling pointer 解引用。具体表现为 `ReleaseAllPackets()` 和 `EchoAsynchronousContext::Release()` 的并发竞争。

**结论**：不能将非 Echo ICMP 类型复用到现有 Echo Timer 路径。

---

## 2. 设计目标

| 编号 | 目标 | 约束 |
|------|------|------|
| G-1 | 最小路径 | 新增代码量尽可能少，不影响 ECHO/ER 现有路径 |
| G-2 | 无旧 Timer 依赖 | 不使用 `InternetControlMessageProtocol::Echo()`、`Timer::Timeout`、`EchoAsynchronousContext` |
| G-3 | 可选配置开关 | 通过 `appsettings.json` 控制，默认 **关闭**（保持现有丢弃行为） |
| G-4 | 不破坏 ECHO/ER 路径 | 新逻辑在 `OnIcmpPacketInput` 的 `frame->Type != ICMP_ECHO && frame->Type != ICMP_ER` 分支内部，不影响现有 echo 路径 |
| G-5 | 安全边界 | 速率限制、长度/校验和校验，并保留 session 关联性校验扩展点；当前阶段依赖 Android `VpnService` 路由约束 |

---

## 3. 非 Echo ICMP 类型分析

### 3.1 类型优先级

基于 `ppp/net/native/icmp.h` 中的 `IcmpType` 枚举和实际网络需求：

| ICMP Type | 名称 | 值 | Code 含义 | 优先级 | 理由 |
|-----------|------|----|-----------|--------|------|
| **Destination Unreachable** | `ICMP_DUR` | 3 | Code 3: Port Unreachable | **P0** | UDP 快速失败；DNS/QUIC 应用依赖 |
| **Destination Unreachable** | `ICMP_DUR` | 3 | Code 4: Fragmentation Needed | **P0** | PMTUD 核心；TCP 性能关键路径 |
| **Destination Unreachable** | `ICMP_DUR` | 3 | 其他 Code（0,1,2,5,13） | **P1** | 有用但不常见 |
| **Time Exceeded** | `ICMP_TE` | 11 | Code 0: TTL Expired in Transit | **P0** | traceroute 核心依赖 |
| **Parameter Problem** | `ICMP_PP` | 12 | Code 0: Pointer 指示错误字段 | **P2** | 极少触发，IP 选项处理异常时有用 |
| **Source Quench** | `ICMP_SQ` | 4 | — | **不处理** | RFC 6633 已废弃，不应生成也不应响应 |
| **Redirect** | `ICMP_RD` | 5 | — | **不处理** | 安全风险高（可劫持路由），且 VPN 隧道内不应出现合法重定向 |
| **Timestamp/Info/Address Mask** | 13–18 | — | — | **不处理** | 已过时或极少使用，不值得增加攻击面 |

### 3.2 优先透传类型详细说明

#### P0: Destination Unreachable（Type 3）

- **Code 3（Port Unreachable）**：当隧道内应用发送 UDP 数据报到不可达端口时，Android TUN 会生成此错误。当前被丢弃后，应用无法感知端口不可达，DNS 查询超时等待（而非快速失败），QUIC 连接建立延迟。
- **Code 4（Fragmentation Needed and DF Set）**：PMTUD 的核心信号。当路径中某路由器发现报文超过下一跳 MTU 且 DF 标志置位时生成。当前被丢弃后，TCP 连接在 MTU 较小的路径上会使用默认 MSS，严重时导致"黑洞路由"（所有大包被丢弃，小 ACK 仍能通过）。
- **Code 0（Net Unreachable）、Code 1（Host Unreachable）、Code 2（Protocol Unreachable）、Code 13（Communication Administratively Prohibited）**：路由/防火墙反馈信号，对调试有价值。

#### P0: Time Exceeded（Type 11）

- **Code 0（TTL Expired in Transit）**：traceroute 的唯一依赖。当前 `OnIcmpPacketInput` 中 `frame->Ttl == 1` 的处理逻辑只能生成本地 TTL 超时（通过 `EchoGatewayServer` 路径），无法透传来自隧道外路由器的真实 TTL 超时响应。

#### P2: Parameter Problem（Type 12）

- **Code 0**：IP 头部参数错误通知。在正常网络中极少见（通常出现在 IP 选项处理不当的场景），但作为完整性考虑应支持。

---

## 4. 设计方案

### 4.1 架构概览

```
┌─────────────────────────────────────────────────────────┐
│  Android TUN                                              │
│  ┌──────────┐                                             │
│  │ ICMP pkt │                                             │
│  └────┬─────┘                                             │
│       ▼                                                   │
│  OnIcmpPacketInput()                                      │
│       │                                                   │
│       ├─ Type == ECHO/ER ──────────► 现有 Echo 路径（不变）│
│       │                                                   │
│       └─ Type == 其他 ─┐                                  │
│                        ▼                                  │
│            [配置开关检查]                                  │
│            enable_icmp_error_passthrough == false          │
│            └─► return false（现有丢弃行为，不变）           │
│                        │                                  │
│                        ▼ enable == true                   │
│            IcmpErrorPassthrough()                         │
│            ┌───────────────────────┐                      │
│            │ 1. 校验：长度/校验和  │                      │
│            │ 2. 类型白名单         │                      │
│            │ 3. 速率限制           │                      │
│            │ 4. 提取内嵌原始报文   │                      │
│            │ 5. 关联性校验         │                      │
│            │ 6. Output() 直接注入  │                      │
│            └───────────────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

### 4.2 核心设计：无状态直注路径

新增方法 `IcmpErrorPassthrough()`，**不创建 raw socket、不使用 Timer、不写入 `icmppackets_` 表**。

#### 4.2.1 方法签名

```cpp
// VEthernetNetworkSwitcher.h（新增 private 方法声明）
/**
 * @brief Validates and injects a non-Echo ICMP error packet into the TUN.
 *
 * This is a stateless, timer-free path for ICMP error messages
 * (Destination Unreachable, Time Exceeded, Parameter Problem) on Android.
 * The packet is validated, rate-limited, and directly injected back into
 * the local TUN via Output() without going through the Echo Timer path.
 *
 * @param packet     Original IP frame from TUN containing the ICMP error.
 * @param frame      Parsed ICMP frame (non-ECHO/ER type).
 * @param allocator  Buffer allocator.
 * @return true if the packet was validated and injected; false otherwise.
 */
bool IcmpErrorPassthrough(
    const std::shared_ptr<IPFrame>&   packet,
    const std::shared_ptr<IcmpFrame>& frame,
    const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
```

#### 4.2.2 处理流程

```cpp
bool VEthernetNetworkSwitcher::IcmpErrorPassthrough(
    const std::shared_ptr<IPFrame>&   packet,
    const std::shared_ptr<IcmpFrame>& frame,
    const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {

    // ── 步骤 1：类型白名单 ──
    switch (frame->Type) {
        case IcmpType::ICMP_DUR:  // Type 3: Destination Unreachable
        case IcmpType::ICMP_TE:   // Type 11: Time Exceeded
        case IcmpType::ICMP_PP:   // Type 12: Parameter Problem
            break;
        default:
            return false;  // 其他类型（Redirect, Source Quench 等）直接丢弃
    }

    // ── 步骤 2：Payload 存在性校验 ──
    // ICMP 错误报文的 payload 必须包含原始 IP 头 + 至少 8 字节原始数据（RFC 792）
    if (NULLPTR == frame->Payload || frame->Payload->Length < 28) {
        // Payload 不含 ICMP header；最小为原始 IP 头 20 字节 + 原始数据前 8 字节
        return false;
    }

    // ── 步骤 3：速率限制 ──
    // 使用简单的令牌桶或计数器，防止 ICMP 错误报文洪泛
    // 具体实现见 §4.3

    // ── 步骤 4：长度校验 ──
    // IP 报文总长度不超过合理上限（防止超大报文注入）
    if (packet->Payload && packet->Payload->Length > 1500) {
        return false;
    }

    // ── 步骤 5：直接注入 TUN ──
    // 不经过 Timer、不写入 icmppackets_，直接 Output()
    return Output(packet.get());
}
```

#### 4.2.3 OnIcmpPacketInput 集成点

在 `OnIcmpPacketInput()` 的现有 `frame->Type != ICMP_ECHO && frame->Type != ICMP_ER` 分支中，**在丢弃之前**插入配置开关检查：

```cpp
// VEthernetNetworkSwitcher.cpp:574（修改现有分支）
if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
#if defined(_ANDROID)
    // 配置开关：Android ICMP 错误直注
    if (configuration_ && configuration_->udp.enable_icmp_error_passthrough) {
        bool injected = IcmpErrorPassthrough(packet, frame, allocator);
        __android_log_print(ANDROID_LOG_INFO, "openppp2",
            "icmp_error_passthrough type=%d code=%d ok=%d",
            (int)frame->Type, (int)frame->Code, (int)injected);
        if (injected) {
            return true;
        }
    }
    // 走到这里表示开关关闭或注入失败，继续原有丢弃逻辑
    __android_log_print(ANDROID_LOG_INFO, "openppp2",
        "icmp_drop unsupported type=%d code=%d dst=%s", ...);
#endif
    return false;
}
```

### 4.3 速率限制

采用简单的时间窗口计数器，避免引入额外的 Timer 依赖：

```cpp
// VEthernetNetworkSwitcher.h（新增成员）
struct {
    uint64_t    icmp_error_window_start_ms = 0;  // 当前窗口起始时间
    uint32_t    icmp_error_count           = 0;   // 当前窗口内已注入数量
} icmp_error_rate_;

static constexpr uint32_t ICMP_ERROR_RATE_LIMIT       = 64;   // 每窗口最大注入数
static constexpr uint64_t ICMP_ERROR_WINDOW_MS        = 1000; // 窗口长度（毫秒）
```

```cpp
// IcmpErrorPassthrough 内部速率限制检查
bool CheckIcmpErrorRateLimit() noexcept {
    uint64_t now = Executors::GetTickCount();
    if (now - icmp_error_rate_.icmp_error_window_start_ms > ICMP_ERROR_WINDOW_MS) {
        icmp_error_rate_.icmp_error_window_start_ms = now;
        icmp_error_rate_.icmp_error_count = 0;
    }
    if (icmp_error_rate_.icmp_error_count >= ICMP_ERROR_RATE_LIMIT) {
        return false;  // 超过速率限制
    }
    icmp_error_rate_.icmp_error_count++;
    return true;
}
```

**设计考量**：
- 使用 `Executors::GetTickCount()` 而非 `Timer`，因为 tick count 是无副作用的只读操作。
- 每秒 64 个 ICMP 错误足够覆盖正常的 traceroute（30 跳 × 3 探测 = 90 个 TE，但分摊到多秒）和 PMTUD 响应。
- 不使用 `boost::asio::steady_timer`，因为这会引入 executor 依赖。

### 4.4 配置开关

#### 4.4.1 配置结构

```cpp
// ppp/configurations/AppConfiguration.h（在 udp 子结构中新增）
struct UdpConfiguration {
    // ... 现有字段 ...

    /**
     * @brief Enables stateless passthrough of non-Echo ICMP error packets on Android.
     *
     * When true, Destination Unreachable, Time Exceeded, and Parameter Problem
     * messages received from the Android TUN are validated and directly injected
     * back into the TUN without going through the Echo Timer path.
     *
     * Default: false (preserves existing drop behavior).
     *
     * @note  Only effective on Android (_ANDROID defined). Ignored on other platforms.
     * @note  Does NOT affect Echo Request/Reply processing.
     */
    bool enable_icmp_error_passthrough = false;
};
```

#### 4.4.2 appsettings.json 示例

```json
{
    "udp": {
        "enable_icmp_error_passthrough": true
    }
}
```

#### 4.4.3 默认行为

- **默认 `false`**：保持现有丢弃行为，零风险。
- **用户显式设为 `true`**：启用 ICMP 错误直注。
- **非 Android 平台**：配置字段存在但被忽略（`#if defined(_ANDROID)` 守卫）。

### 4.5 关联性校验（可选增强）

ICMP 错误报文的 payload 中包含触发该错误的原始 IP 头（RFC 792）。可选地，验证该内嵌报文是否与当前 VPN session 相关：

```cpp
// 可选：提取内嵌原始 IP 头，检查目的地址是否属于 VPN 隧道
std::shared_ptr<IPFrame> original = IPFrame::Parse(
    allocator, frame->Payload->Buffer.get(),
    std::min<int>(frame->Payload->Length, 28));
if (NULLPTR != original) {
    // 检查原始报文的目的地址是否是 VPN 隧道内的地址
    // 如果不是，可能是误注入的报文，应丢弃
    if (!IsVpnTunnelAddress(original->Destination)) {
        return false;
    }
}
```

**当前阶段不实现此检查**。原因：
1. 需要维护 VPN 隧道地址表（`tap->AssignedAddress`、IPv6 lease 等），增加状态依赖。
2. Android TUN 的 `VpnService.Builder.establish()` 已通过路由表限制了哪些流量进入隧道，关联性由 OS 保证。
3. 后续可作为独立增强项实现。

---

## 5. 安全边界

### 5.1 威胁模型

| 威胁 | 描述 | 缓解措施 |
|------|------|----------|
| **ICMP 洪泛** | 恶意应用通过 TUN 注入大量 ICMP 错误报文 | 速率限制（§4.3）：每秒 ≤ 64 个 |
| **反射放大** | 注入的 ICMP 错误报文触发上层协议（TCP/UDP）产生更多流量 | 只注入到本地 TUN（`Output()`），不转发到远程服务器；ICMP 错误是单向信号，不产生响应级联 |
| **报文伪造** | 构造包含虚假内嵌报文的 ICMP 错误 | Payload 长度/结构校验（§4.2.2 步骤 2、4）；校验和由 `IcmpFrame::Parse()` 已验证 |
| **类型滥用** | 注入 Redirect（Type 5）等危险类型 | 类型白名单（§4.2.2 步骤 1）：仅允许 DUR/TE/PP |
| **旧 Timer 路径污染** | 非 Echo 报文意外进入 `EchoGatewayServer` / `EchoOtherServer` | 新路径在非 Echo/ER 类型检查分支内、进入原丢弃逻辑前处理，不会进入 Echo 路径 |

### 5.2 校验层次

```
输入：Android TUN → OnIcmpPacketInput(packet)
  │
  ├─ IcmpFrame::Parse() ── 校验 ICMP checksum（已有，IcmpFrame.h:169）
  │   └─ 失败 → return NULLPTR → return false
  │
  ├─ frame->Ttl == 0 ── 已有检查
  │   └─ 失败 → return false
  │
  ├─ Type 白名单（DUR/TE/PP）── 新增
  │   └─ 不匹配 → return false
  │
  ├─ Payload 长度 ≥ 28 ── 新增（RFC 792: 原始 IP 头最小 20 字节 + 原始数据前 8 字节）
  │   └─ 不满足 → return false
  │
  ├─ IP 总长度 ≤ 1500 ── 新增
  │   └─ 超过 → return false
  │
  ├─ 速率限制 ≤ 64/秒 ── 新增
  │   └─ 超过 → return false
  │
  └─ Output() 注入 TUN ── 使用现有 VEthernet::Output()
```

### 5.3 不引入的新风险

| 已有保护 | 来源 |
|----------|------|
| ICMP checksum 校验 | `IcmpFrame::Parse()`（`IcmpFrame.h:169`："checksum is verified; frames with invalid checksums are rejected"） |
| IP 头合法性 | `IPFrame::Parse()`（长度、版本号、协议字段校验） |
| TUN 写入保护 | `VEthernet::Output()` → `tap->Output()`：写入 TUN 文件描述符，受 Android `VpnService` 路由表约束 |

---

## 6. 与现有路径的关系

### 6.1 路径隔离

| 特征 | 现有 ECHO/ER 路径 | 新增 ICMP 错误直注路径 |
|------|-------------------|----------------------|
| 入口条件 | `Type == ICMP_ECHO \|\| Type == ICMP_ER` | `Type == DUR \|\| Type == TE \|\| Type == PP` |
| raw socket | ✅ 创建 `SOCK_RAW` | ❌ 不创建 |
| Timer | ✅ `Timer::Timeout(3000ms)` | ❌ 不使用 |
| `icmppackets_` 表 | ✅ 写入 | ❌ 不访问 |
| `EchoAsynchronousContext` | ✅ 创建 | ❌ 不创建 |
| 输出方式 | `Output()` 注入 TUN | `Output()` 注入 TUN（相同） |
| 平台守卫 | 全平台 | `#if defined(_ANDROID)` |

### 6.2 不修改的文件/路径

- `ppp/net/asio/InternetControlMessageProtocol.h/.cpp` — 不修改
- `ppp/threading/Timer.h/.cpp` — 不修改
- `ppp/app/client/VEthernetExchanger.h/.cpp` — 不修改
- `EchoGatewayServer()` — 不修改
- `EchoOtherServer()` — 不修改
- `ERORTE()` — 不修改
- DNS、SSL_CTX、TLS session cache、atomic helper — 不修改

---

## 7. 实施步骤（未来）

> **当前阶段不实施。** 以下步骤仅供未来实施时参考。

| 阶段 | 内容 | 文件 | 风险 |
|------|------|------|------|
| 1 | 添加配置字段 `enable_icmp_error_passthrough` | `ppp/configurations/AppConfiguration.h` | 极低：新增字段，默认 false |
| 2 | 添加 JSON 解析支持 | `ppp/configurations/AppConfiguration.cpp`（或相关 JSON 解析位置） | 极低：新增可选字段 |
| 3 | 添加速率限制成员 | `VEthernetNetworkSwitcher.h` | 极低：新增 private 成员 |
| 4 | 实现 `IcmpErrorPassthrough()` | `VEthernetNetworkSwitcher.cpp` | 低：新方法，不影响现有路径 |
| 5 | 修改 `OnIcmpPacketInput` 分支 | `VEthernetNetworkSwitcher.cpp:574` | 低：在丢弃逻辑前插入条件分支 |
| 6 | Android 集成测试 | 手动测试 | — |

### 7.1 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 配置系统支持新增可选 bool 字段 | JSON 解析器应忽略未知字段 | ✅ 已满足（nlohmann/json 默认忽略未知字段） |
| C-2 | `Output(IPFrame*)` 在非 Echo 路径下安全 | 无 Timer/Context 依赖 | ✅ 已满足（`VEthernet::Output()` 是无状态写入） |
| C-3 | Android TUN 可接收注入的 ICMP 错误 | `VpnService` 不过滤注入报文 | ⚠️ 需手动验证 |
| C-4 | 手动测试覆盖 | traceroute + PMTUD + port-unreachable | ❌ 无自动化测试 |

---

## 8. 风险评估

### 8.1 风险矩阵

| 风险 | 等级 | 影响 | 缓解 |
|------|------|------|------|
| 配置默认值错误导致意外启用 | 低 | 用户可能无意中启用 | 默认 `false`，文档明确说明 |
| 速率限制阈值不当 | 低 | 正常 traceroute 被限速 | 64/秒远超正常 traceroute 速率 |
| Payload 校验过于宽松 | 低 | 接受畸形报文 | `IcmpFrame::Parse()` 已做 checksum 校验 |
| `Output()` 对非 Echo 报文行为异常 | 极低 | TUN 写入失败 | `Output()` 是通用的序列化+写入，不区分 ICMP 类型 |
| 配置字段 JSON key 拼写不一致 | 极低 | 开关不生效 | 统一命名 `enable_icmp_error_passthrough` |

### 8.2 回滚策略

- **代码回滚**：删除 `IcmpErrorPassthrough()` 方法和 `OnIcmpPacketInput` 中的条件分支，恢复为纯 `return false`。
- **配置回滚**：`appsettings.json` 中删除或设为 `false`，无需重启（`configuration_` 由 shared_ptr 持有，下次读取即生效；若实现热加载则更即时）。
- **无状态回滚**：新路径不写入任何持久状态（不修改 `icmppackets_`、不创建 socket），回滚后不留残留。

---

## 9. 后续增强项（不在本文档范围）

| 增强项 | 描述 | 依赖 |
|--------|------|------|
| 关联性校验 | 验证 ICMP 错误 payload 中的内嵌报文是否属于当前 VPN session | VPN 地址表维护 |
| IPv6 支持 | ICMPv6 错误（Type 1: Destination Unreachable, Type 3: Time Exceeded, Type 2: Packet Too Big） | IPv6 ICMP 解析器 |
| ICMP Error 序列号映射 | 将 ICMP 错误与原始请求关联，用于精确的 PMTUD 状态机 | 需要 per-connection MTU 缓存 |
| OTel 指标上报 | `ppp_icmp_error_injected_total{type,code}` 计数器 | 依赖 `ppp/telemetry/` 框架 |

---

## 10. 术语表

| 术语 | 说明 |
|------|------|
| **TUN** | Android VPN 虚拟网络设备（`/dev/tun`），通过 `VpnService.Builder.establish()` 获取文件描述符 |
| **PMTUD** | Path MTU Discovery，路径最大传输单元发现（RFC 1191） |
| **DUR** | Destination Unreachable（ICMP Type 3） |
| **TE** | Time Exceeded（ICMP Type 11） |
| **PP** | Parameter Problem（ICMP Type 12） |
| **ER** | Echo Reply（ICMP Type 0） |
| **ECHO** | Echo Request（ICMP Type 8） |
| **直注（Passthrough）** | 不经过 Timer/raw socket 路径，直接将校验后的报文注入 TUN |

---

## 11. 参考文献

| 来源 | 位置 |
|------|------|
| 当前丢弃逻辑 | `ppp/app/client/VEthernetNetworkSwitcher.cpp:574` |
| 审计项 B-2 | `docs/openppp2-deep-code-audit-cn.md` §B-2（第 1781 行） |
| 审计优先级 2 第 6 项 | `docs/openppp2-deep-code-audit-cn.md` 第 1929 行 |
| ICMP 类型枚举 | `ppp/net/native/icmp.h:21` |
| IcmpFrame 解析与校验 | `ppp/net/packet/IcmpFrame.h:169` |
| Timer 路径实现 | `ppp/net/asio/InternetControlMessageProtocol.cpp:357` |
| Echo 路径入口 | `ppp/app/client/VEthernetNetworkSwitcher.cpp:620`（EchoOtherServer）、`656`（EchoGatewayServer） |
| ERORTE 回调 | `ppp/app/client/VEthernetNetworkSwitcher.cpp:506` |
| 治理决策记录 | `docs/p2-governance-decisions-cn.md` P2-13 |

---

*本文档仅作设计记录用途，不触发代码行为变更。*
*实施时必须保持 ECHO/ER 现有路径完全不变。*
