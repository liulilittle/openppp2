# 逐帧读取超时设计
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md) · **English：**[Per-Frame Read Timeout Design](PER_FRAME_READ_TIMEOUT_DESIGN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


[English Version](PER_FRAME_READ_TIMEOUT_DESIGN.md)

## 状态

| 字段 | 值 |
|------|-----|
| **优先级** | P1（慢读 DoS 加固） |
| **当前决策** | **暂不实施，仅记录设计** |
| **治理编号** | `p1-governance-decisions-cn.md` P1-1 |
| **审计引用** | `openppp2-deep-code-audit-cn.md` §5.1、§8 P1 第 10 项 |
| **日期** | 2026-05-11 |

---

## 1. 问题描述

传输读取管道中的每次 `async_read` 都会无限期阻塞调用方协程，直到对端发送所请求的字节数。慢速攻击者（slowloris）可以每隔几分钟发送一个字节来维持连接存活，从而长时间占用协程栈、socket fd、加密状态和 QoS 上下文。

需要保护的三条读取路径：

| 路径 | 入口 | 底层读取 |
|------|------|----------|
| **TCP** | `ITcpipTransmission::ReadBytes()` | `ppp::coroutines::asio::async_read(*socket, ...)` |
| **WebSocket** | `templates::WebSocket<IWebsocket>::ReadBytes()` | `IWebsocket::Read()` → `ppp::coroutines::asio::async_read(websocket_, ...)` |
| **ITransmission 帧层** | `ITransmission::Read()` → `ITransmissionBridge::Read()` → `DoReadBytes()` | 虚函数分派到上述路径之一 |

当前代码中一次帧读取是多步协程序列：

```
ITransmission::Read()
  └─ ITransmissionBridge::Read()
       ├─ [握手前] base94_decode_length()   ← ReadBytes(4 或 7 字节)
       │           base94_decode()          ← ReadBytes(payload_length 字节)
       └─ [握手后] Transmission_Packet_Read()
                     ├─ ReadBytes(3 字节)   ← 头部
                     └─ ReadBytes(N 字节)   ← 载荷
```

每次 `ReadBytes` 调用都可能独立阻塞。超时必须覆盖**整个帧读取**（头部 + 载荷），而非单个子读取，因为攻击者快速发送 3 字节头部后在载荷上阻塞同样危险。

---

## 2. 设计方案

### 2.1 架构：在 ITransmission 层设置定时器

```
                  ITransmission::Read(y, outlen)
                         │
          ┌──────────────┴──────────────┐
          │  启动逐帧定时器               │
          │  (steady_timer, T 秒)        │
          │                              │
          ▼                              │
   ITransmissionBridge::Read()           │
     ├─ ReadBytes(头部)  ◄─── 可能阻塞  │
     ├─ ReadBytes(载荷)  ◄───          │
     │                              │
     │  成功时：                    │
     │   取消定时器 ────────────────►│
     │   返回数据包                  │
     │                              │
     │  定时器到期时：               │
     │   取消 socket 读取 ───────────┘
     │   销毁传输连接
     │   返回 null + ErrorCode
```

定时器在帧读取开始前**启动一次**，在完整帧（头部 + 载荷）组装完成后**取消一次**。这限制了单次 `ITransmission::Read()` 调用的总时间。

### 2.2 为什么不使用子读取级别超时

子读取级别超时需要：
- 每帧多次定时器创建/取消（2-3 倍开销）。
- 头部和载荷读取使用不同超时值。
- 子读取成功但下一个阻塞时的复杂状态跟踪。

单次逐帧超时更简单、足够应对威胁模型，且与现有握手超时工作方式一致（单个定时器覆盖整个握手序列）。

### 2.3 定时器类型和所有权

```cpp
// ITransmission 中已有此类型定义：
typedef boost::asio::steady_timer  DeadlineTimer;
typedef std::shared_ptr<DeadlineTimer> DeadlineTimerPtr;
```

定时器在传输连接所属的同一 `io_context` 和 strand 上创建。作为 `ITransmission` 的成员（类似握手用的 `timeout_`），而非局部变量，原因：

1. **取消安全性**：定时器回调必须访问 `this->Dispose()`，要求传输对象仍然存活。成员变量确保生命周期延续到 `Finalize()` 取消它。
2. **单写入者模式**：协程模型保证同一时间只有一个帧读取在进行，因此单个定时器成员足够。

### 2.4 新成员和配置

```cpp
// ITransmission.h — 新私有成员
DeadlineTimerPtr    frame_read_timer_;        // 逐帧读取截止定时器
std::atomic_bool    frame_read_armed_{false}; // 防止重复启动

// AppConfiguration.h — 新字段（tcp.connect 下或新的 tcp.frame 节）
struct {
    int timeout;  // 逐帧读取超时（秒）；0 表示禁用
} frame_read;
```

默认值：`0`（禁用），直到验证通过。运维人员可通过 `appsettings.json` 启用：

```json
{
  "tcp": {
    "frame_read": {
      "timeout": 30
    }
  }
}
```

### 2.5 实现草图 (ITransmission::Read)

```cpp
std::shared_ptr<Byte> ITransmission::Read(YieldContext& y, int& outlen) noexcept {
    outlen = 0;
    if (disposed_.load(std::memory_order_acquire)) {
        return NULLPTR;
    }

    // ── 启动逐帧读取定时器 ──
    int frame_timeout_s = configuration_->tcp.frame_read.timeout;
    bool timer_armed = false;
    if (frame_timeout_s > 0 && context_ && strand_
        && handshaked_.load(std::memory_order_acquire)) {
        frame_read_timer_ = make_shared_object<DeadlineTimer>(*strand_);
        if (frame_read_timer_) {
            auto self = std::static_pointer_cast<ITransmission>(shared_from_this());
            frame_read_timer_->expires_after(
                std::chrono::seconds(frame_timeout_s));
            frame_read_timer_->async_wait(
                [self, frame_timeout_s](boost::system::error_code ec) noexcept {
                    if (ec == boost::system::errc::operation_canceled) {
                        return;  // 正常：帧读取按时完成
                    }
                    // 定时器到期 — 帧读取阻塞
                    ppp::telemetry::Count("transmission.frame_read_timeout", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "transmission",
                        "逐帧读取超时 %d 秒", frame_timeout_s);
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::TunnelReadTimeout);
                    self->Dispose();
                });
            frame_read_armed_.store(true, std::memory_order_release);
            timer_armed = true;
        }
    }

    // ── 实际帧读取（头部 + 载荷）──
    std::shared_ptr<Byte> result = ITransmissionBridge::Read(this, y, outlen);

    // ── 成功或失败时取消定时器 ──
    if (timer_armed) {
        frame_read_armed_.store(false, std::memory_order_release);
        DeadlineTimerPtr t = std::move(frame_read_timer_);
        if (t) {
            Socket::Cancel(*t);
        }
    }

    if (NULLPTR == result && ppp::diagnostics::ErrorCode::Success ==
            ppp::diagnostics::GetLastErrorCode()) {
        if (disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SessionDisposed);
        } else {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::TunnelReadFailed);
        }
    }

    return result;
}
```

### 2.6 定时器/取消生命周期

```
状态          操作                      执行者
────────────  ────────────────────────  ──────────────────────
空闲          创建 steady_timer         ITransmission::Read
              设置过期时间为 T 秒
              发布 async_wait 回调
已启动        帧读取进行中              协程（通过 DoReadBytes）
────────────  ────────────────────────  ──────────────────────
已完成        帧读取成功                协程
              取消定时器                ITransmission::Read
              定时器回调收到            (operation_canceled → 空操作)
              operation_canceled
────────────  ────────────────────────  ──────────────────────
已过期        定时器先触发              io_context 线程
              调用 Dispose()            定时器回调
              Socket 被取消            Finalize()
              协程读取恢复时返回        (ec != success → null)
              错误
────────────  ────────────────────────  ──────────────────────
已销毁        Finalize() 取消定时器     析构函数 / Dispose 路径
              (同已完成路径)            Socket::Cancel(*t)
```

关键不变量：
- 定时器总是在 `Finalize()` 运行前被取消，要么由读取完成路径取消，要么由 `Finalize()` 本身取消（它已经对 `timeout_` 调用 `Socket::Cancel(*t)`；`frame_read_timer_` 同理）。
- 定时器回调捕获 `shared_from_this()`，防止传输对象在回调排队期间被销毁。
- `frame_read_armed_` 防止在 `Read()` 重入时重复启动（协程模型下不应发生，但作为防御措施）。

### 2.7 与 QoS 层的交互

QoS 层（`ITransmissionQoS::ReadBytes`）可以通过挂起协程来**延迟**读取开始，直到带宽预算释放。此延迟计入逐帧超时。两个选项：

| 选项 | 行为 | 风险 |
|------|------|------|
| **A. 定时器在 QoS 前启动** | QoS 挂起时间计入超时 | 重节流下可能误报 |
| **B. 定时器在 QoS 后启动** | 仅限制实际 I/O 时间 | 攻击者可在 QoS 队列中阻塞 |

**推荐**：选项 A（定时器在 QoS 前启动）。理由：
- QoS 挂起有界（每秒在 `Update()` 中恢复）。
- 超时值应足够宽松以容忍 QoS 延迟。
- 选项 B 需要更改 QoS API 以发出"读取开始"信号，增加侵入性。

### 2.8 与握手超时的交互

握手期间，`ITransmission::HandshakeClient/Server` 已启动 `timeout_`（握手截止定时器）。逐帧定时器在握手读取期间**不应**启动，因为：
1. 握手超时已覆盖此场景。
2. `handshaked_` 为 false，`Read()` 仅从握手代码调用。

保护条件：当 `!handshaked_` 时跳过逐帧定时器。

---

## 3. 路径特定分析

### 3.1 ITcpipTransmission

```
ITcpipTransmission::ReadBytes(y, length)
  └─ ppp::coroutines::asio::async_read(*socket, buffer, y)
       └─ boost::asio::async_read(stream, buffers, yield[ec])
```

取消：`Socket::Cancel(socket)` 调用 `socket->cancel()` 取消所有挂起的异步操作。`async_read` 回调收到 `boost::asio::error::operation_aborted`。协程以 `len = -1`（失败）恢复。

**风险**：TCP `cancel()` 在所有支持的平台上均安全（Linux epoll、Windows IOCP、macOS kqueue）。内核已接收的缓冲数据被保留；仅挂起的 `recv()` 调用被取消。帧层正确处理部分读取，因为 `async_read` 返回错误（短读），调用方丢弃部分缓冲区。

**风险等级**：**低**。这与握手超时当前使用的机制相同。

### 3.2 WebSocket（明文）

```
templates::WebSocket<websocket>::ReadBytes(y, length)
  └─ socket->Read(buffer, 0, length, y)
       └─ ppp::coroutines::asio::async_read(websocket_, buffer, y)
            └─ boost::beast::websocket::stream::async_read(...)
```

取消：Beast websocket 流包装 TCP socket。取消底层 socket（`websocket_.next_layer().cancel()`）取消挂起的 Beast 操作。

**风险**：Boost.Beast 文档警告在操作进行中取消 websocket 流可能使其处于**不确定状态**。具体来说：
- 部分控制帧可能被缓冲。
- 流的内部读取缓冲区可能包含未处理的数据。
- 后续读取可能失败或产生损坏帧。

但在我们的代码中，逐帧超时会**销毁整个传输连接**，因此流在取消后不会被重用。这消除了"不确定状态"的担忧。

**风险等级**：**低-中**。因为超时后总是销毁，所以安全。如果试图在取消后重用流则为**高**。

### 3.3 WebSocket（TLS / WSS）

与 §3.2 相同，但有额外的 TLS 层：

```
templates::WebSocket<sslwebsocket>::ReadBytes(y, length)
  └─ socket->Read(buffer, 0, length, y)
       └─ ppp::coroutines::asio::async_read(ssl_websocket_, buffer, y)
```

取消底层 TCP socket 也会取消 TLS 读取。TLS 会话状态被破坏，但同样，超时时会销毁。

**风险等级**：**低-中**（与 §3.2 相同的推理）。

### 3.4 MUX 子通道

MUX 通道（`ppp/app/mux/`）从已解密的内存缓冲区读取，不从 socket 读取。逐帧读取超时不适用于 MUX 子通道，因为：
1. MUX 读取是非阻塞的（内存拷贝）。
2. MUX 有自己的空闲超时（`mux.inactive.timeout`）。

MUX 路径无需更改。

---

## 4. 新错误码

添加到 `ppp/diagnostics/ErrorCodes.def`（**拟新增/设计项，尚未收录于当前 ErrorCodes.def**）：

```cpp
X(TunnelReadTimeout,
    "Per-frame read timeout exceeded; connection disposed", ErrorSeverity::kWarning)
```

这将慢读超时与通用的 `TunnelReadFailed` 区分开来。

---

## 5. 遥测

定时器到期时发出：

```cpp
ppp::telemetry::Count("transmission.frame_read_timeout", 1);
ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "transmission",
    "逐帧读取超时 %d 秒 remote=%s:%u",
    frame_timeout_s,
    remoteEP_.address().to_string().c_str(),
    remoteEP_.port());
```

这使运维人员能够通过现有遥测管道（OpenTelemetry / 日志聚合）监控慢读攻击。

---

## 6. 测试要求

**本项目当前无自动化测试。** 以下测试计划为测试基础设施就绪后编写。在此之前，验证为手动方式。

### 6.1 单元测试（需要测试框架）

| ID | 测试 | 预期 |
|----|------|------|
| T-1 | 帧读取在超时内完成 | 定时器取消，不销毁连接 |
| T-2 | 帧读取超过超时 | 定时器触发，调用 `Dispose()`，返回 `TunnelReadTimeout` 错误 |
| T-3 | 成功读取后取消定时器 | 帧完成后无虚假销毁 |
| T-4 | `ITransmission::Dispose()` 时取消定时器 | 销毁后无悬挂定时器回调 |
| T-5 | 重复启动保护 | 第一个读取进行中的第二次 `Read()` 调用不创建第二个定时器 |
| T-6 | 握手读取跳过 | `handshaked_ == false` 时不启动定时器 |
| T-7 | QoS 延迟计入超时 | QoS 延迟 + I/O 时间 > 超时时帧超时 |

### 6.2 集成测试（需要对端进程）

| ID | 测试 | 预期 |
|----|------|------|
| I-1 | TCP：slowloris 攻击（1 字节/秒） | 超时后销毁会话 |
| I-2 | TCP：正常突发传输 | 100 Mbps 下无误报超时 |
| I-3 | WS：slowloris 攻击 | 超时后销毁会话 |
| I-4 | WSS：slowloris 攻击 | 超时后销毁会话 |
| I-5 | TCP：仅头部读取时超时 | 头部阻塞后销毁 |
| I-6 | TCP：仅载荷读取时超时 | 载荷阻塞后销毁 |
| I-7 | WS：仅载荷读取时超时 | 载荷阻塞后销毁 |
| I-8 | 定时器值为 0（禁用） | 无超时，保持现有行为 |

### 6.3 压力测试

| ID | 测试 | 预期 |
|----|------|------|
| S-1 | 1000 个并发连接，timeout=5s | 无 fd 泄漏，无定时器泄漏 |
| S-2 | 快速连接/断开循环 | 无陈旧定时器回调 |
| S-3 | QoS 节流期间定时器到期 | 优雅销毁，无崩溃 |

### 6.4 平台特定验证

| 平台 | 关注点 | 验证 |
|------|--------|------|
| Linux | `epoll` + `cancel()` 交互 | I-1、I-5、I-6 |
| macOS | `kqueue` + `cancel()` 交互 | I-1、I-5、I-6 |
| Windows | IOCP + `cancel()` 交互 | I-1、I-5、I-6 |
| Android | NDK 在较旧 API 级别上的 `cancel()` 行为 | API 21 上的 I-1 |

---

## 7. 配置模式

### 7.1 新字段

```json
{
  "tcp": {
    "frame_read": {
      "timeout": 30
    }
  }
}
```

| 字段 | 类型 | 默认值 | 范围 | 描述 |
|------|------|--------|------|------|
| `tcp.frame_read.timeout` | int | 0 | 0–300 | 逐帧读取超时（秒）。0 = 禁用。 |

### 7.2 向后兼容性

- 默认为 `0`（禁用），现有部署不受影响。
- 字段可选；缺少 `frame_read` 节表示禁用。
- 无需架构迁移。

### 7.3 推荐值

| 场景 | 推荐值 | 理由 |
|------|--------|------|
| 生产服务器 | 30s | 足够容忍 QoS 延迟，足够短以限制 slowloris |
| 高延迟链路 | 60s | 卫星/跨洲路径 |
| 开发/测试 | 0（禁用） | 避免调试期间的误报超时 |
| 高安全性 | 15s | 激进的 slowloris 缓解 |

---

## 8. 实施检查清单

获得实施批准后：

- [ ] 在 `AppConfiguration.h` 结构体中添加 `tcp.frame_read.timeout`
- [ ] 在 JSON 模式/配置加载器中添加 `frame_read.timeout`
- [ ] 在 `ErrorCodes.def` 中添加 `TunnelReadTimeout`
- [ ] 在 `ITransmission.h` 中添加 `frame_read_timer_` 和 `frame_read_armed_`
- [ ] 在 `ITransmission::Read()` 中实现定时器启动/取消
- [ ] 在 `ITransmission::Finalize()` 中取消 `frame_read_timer_`
- [ ] 添加遥测计数器和日志
- [ ] 手动测试：TCP slowloris (I-1)
- [ ] 手动测试：WS slowloris (I-3)
- [ ] 手动测试：WSS slowloris (I-4)
- [ ] 手动测试：正常流量 (I-2)
- [ ] 手动测试：timeout=0 保持现有行为 (I-8)
- [ ] 平台测试：Linux (I-1)
- [ ] 平台测试：macOS (I-1) — 如 CI runner 可用
- [ ] 平台测试：Windows (I-1) — 如 CI runner 可用
- [ ] 在 `CONFIGURATION.md` 和 `CONFIGURATION_CN.md` 中记录

---

## 9. 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 定时器泄漏（回调在销毁后触发） | 低 | 中 | `shared_from_this()` 捕获 + `Finalize()` 取消定时器 |
| 重 QoS 下误报超时 | 中 | 低 | 默认 0（禁用）；运维人员选择值 |
| 取消后 socket 状态损坏 | 极低 | 高 | 取消后总是销毁；永不重用流 |
| 协程重入 | 极低 | 中 | `frame_read_armed_` 原子保护 |
| 新字段配置解析错误 | 低 | 低 | 解析失败时默认 0 |

---

## 10. 为什么暂不实施

本功能暂不实施（仅设计，不改代码），原因如下：

1. **无自动化测试基础设施**：本项目零测试。逐帧读取超时修改了每个连接使用的核心读取路径。没有自动化回归测试，一个细微的 bug（如某条错误路径上定时器未取消）可能导致所有连接被虚假销毁。仅手动测试不足以应对如此核心的变更。

2. **Socket 取消的跨平台差异**：虽然 `socket::cancel()` 在 Linux/epoll、Windows/IOCP 和 macOS/kqueue 上定义明确，但与 Boost.Beast websocket 流的交互在本代码库中测试较少。本项目目前完全没有 WebSocket 传输测试。

3. **QoS 交互需要真实场景分析**：逐帧定时器必须根据实际 QoS 行为调优。设得太低会在带宽节流下产生误报；设得太高则无法提供保护。这需要类似生产的流量配置。

4. **配置表面区域**：添加 `tcp.frame_read.timeout` 更改配置模式。应与其他待定配置更改（如 §5.1 的多级帧限制）协调。

5. **现有握手超时提供部分缓解**：握手超时（`tcp.connect.timeout`）已限制攻击者在最脆弱阶段（加密建立前）维持连接的时间。握手后，保活机制（`PacketAction_KEEPALIVED`）提供次级活性检查，虽然工作间隔较长。

6. **需要功能标志方式**：鉴于风险配置，功能必须默认禁用（`timeout: 0`）发布，由运维人员显式启用。这意味着在验证完成前它不会提供任何保护，降低了在验证完成前发布的紧迫性。

### 何时实施

当**以下所有条件**满足时应实施此功能：

- [ ] 至少存在传输读取路径的基本集成测试
- [ ] Socket 取消已在目标平台上验证（至少 Linux）
- [ ] QoS 层在节流下的行为已被分析
- [ ] 配置模式更改已与其他待定工作协调
- [ ] 有候选版本可用于手动 slowloris 测试

---

## 11. 考虑过的替代方案

### 11.1 TCP SO_RCVTIMEO

设置 socket 级别的接收超时。否决原因：
- 平台特定（并非所有 Boost.Asio socket 类型都可用）。
- 适用于单个 `recv()` 调用，而非逻辑帧读取。
- 无法逐帧更改（需要在每次读取前后设置/取消设置）。

### 11.2 Boost.Beast WebSocket 流超时

Beast 为 websocket 流提供 `stream_base::timeout`。否决原因：
- 仅适用于 WebSocket 路径，不适用于 TCP 路径。
- 在 websocket 帧级别操作，而非 PPP 帧级别。
- 已在服务端握手代码中设置为"建议"默认值（见 `ppp/net/asio/templates/WebSocket.h:139-141`），但这些覆盖 Beast 级别的读/写，而非 PPP 帧级别。

### 11.3 协程级别截止

使用 `ppp::coroutines::asio::async_sleep` 作为与读取并行的竞态协程。否决原因：
- 每次读取需要生成第二个协程（栈分配开销）。
- 竞态条件：两个协程在同一 `YieldContext` 上恢复，该上下文不设计用于并发恢复。
- `steady_timer` 方案更简单且使用现有基础设施。

### 11.4 空闲连接清扫器（带外）

定期扫描所有连接并销毁超过 T 秒无流量的连接。作为主要机制被否决，因为：
- 需要遍历所有连接（每次扫描 O(n)）。
- 无法区分"空闲但合法"和帧读取期间的"slowloris 阻塞"。
- 作为**补充**机制更好（已通过保活超时部分实现）。

---

## 12. 相关工作

| 项目 | 状态 | 描述 |
|------|------|------|
| P0-4A 帧长度限制 | ✅ 已完成 | `PPP_BUFFER_SIZE`（65536）载荷解码后上限 |
| 握手超时 | ✅ 已完成 | `ITransmission::InternalHandshakeTimeoutSet/Cancel` |
| 保活机制 | ✅ 已完成 | `PacketAction_KEEPALIVED` 周期性心跳 |
| TCP 空闲超时 | ✅ 已完成 | `tcp.inactive.timeout` 配置 |
| 逐帧读取超时 | **本文档** | P1 暂缓 |
| 多级帧限制 | P1 暂缓 | 握手前/控制/数据最大长度 |
