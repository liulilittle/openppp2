# P1 治理决策记录
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 本文档记录 P1 级代码质量治理项中**暂不修改、仅记录在案**的条目。
> 每条包含：问题描述、当前决策、原因分析、后续可选方案、生效约束。
> 遵循原则：最佳兼容性、最小破坏性、最小侵入性。

---

## 1.8 治理 `system()` / `popen()` Shell 命令执行路径

| 字段 | 内容 |
|------|------|
| **编号** | P1-8 |
| **当前决策** | **暂不治理，只记录在案** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |

### 问题描述

项目中存在多处 `system()` / `popen()` / shell 命令执行路径，分散于跨平台核心代码和三个平台目录中。下表为早期治理清单草案；实施前必须使用 `rg '\b(system|popen)\s*\('` 重新生成并确认完整清单，不应将当前表格视为最终数量口径。主要用途：

`system()` 路径主要依赖命令返回码；`popen()` 路径还依赖 stdout 读取与解析，替换时必须保留输出读取语义，不能按纯返回码调用简单替换。

| 文件 | 行号 | 用途 | 平台 |
|------|------|------|------|
| `ppp/app/client/VEthernetNetworkSwitcher.cpp` | 1085, 1188 | 网络切换 shell 命令 | 跨平台 |
| `ppp/app/ConsoleUI.cpp` | 1795 | shell 命令输出读取（`popen()`） | 跨平台/Unix-like |
| `ppp/stdafx.cpp` | 1123, 1128 | `system("cls")` / `system("clear")` 清屏 | 跨平台 |
| `common/unix/UnixAfx.cpp` | 695, 717, 740 | Unix shell 命令输出读取（`popen()`） | Unix-like |
| `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` | 84, 352, 598；另有 `popen()` 查询路径 | IPv6 路由管理与状态查询 | Linux |
| `linux/ppp/tap/TapLinux.cpp` | 257, 684, 695；另有 `popen()` 查询路径 | TAP 接口配置与 NDP 查询 | Linux |
| `linux/ppp/diagnostics/UnixStackTrace.cpp` | 33, 100 | `addr2line` 调用与输出读取 | Linux |
| `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` | route 管理与 `popen()` 查询路径 | IPv6 路由管理与状态查询 | macOS |
| `darwin/ppp/tun/utun.cpp` | 143, 190, 223 | utun 接口配置 (`ifconfig`/`route`) | macOS |
| `windows/ppp/win32/Win32Native.cpp` | 777 | `system("pause")` | Windows |
| `windows/ppp/app/client/lsp/PaperAirplaneLspY.cpp` | 327 | `system("pause")` | Windows |

其中存在 shell 字符串拼接的高风险路径：

- **Linux/macOS IPv6 辅助模块**：将动态接口名、地址拼入 `ip` / `route` 命令字符串后传入 `system()`。
- **Linux TAP 模块**：`TapLinux.cpp` 注释已标明 `system()` 执行阻塞式 `fork()+exec()`，且命令中含动态参数。
- **VEthernetNetworkSwitcher**：网络切换逻辑中构造 shell 命令并执行。

### 暂不治理的原因

1. **跨平台命令执行改造侵入性较高**：替换 `system()` 需要为 Linux/macOS/Windows 分别实现进程管理器（如 `posix_spawn` / `CreateProcess` / `fork+exec`），涉及三个平台目录的同步修改。
2. **需要平台集成测试**：IPv6 路由管理、TAP 接口配置等命令的输出解析依赖 shell 行为，替换后必须在各平台实际验证。
3. **按最小破坏性原则暂缓**：当前主流程聚焦于 P0/P1 阻断问题修复，该项不属于阻断项。
4. **与 §2 文档任务及其他 P1 修复任务互不依赖**：治理该项不会影响其他并行任务。

### 后续可选治理方案

按侵入性从低到高排列：

| 方案 | 描述 | 侵入性 | 前置条件 |
|------|------|--------|----------|
| **A. 参数校验过渡** | 对拼接前的参数做白名单/正则校验，拦截注入风险，保留 `system()` 调用 | 低 | 无 |
| **B. 局部替换高风险路径** | 仅替换含动态参数拼接的 `system()` / `popen()` 路径，`popen()` 替换必须保留 stdout 读取/解析语义 | 中 | 平台集成测试 |
| **C. 统一 ProcessRunner** | 引入 `ppp/system/ProcessRunner` 抽象层，统一治理 shell 命令执行路径（含返回码与 stdout 两类语义） | 高 | 全平台测试 + API 设计评审 |

**推荐路径**：先实施方案 A 作为短期加固，再按平台逐步推进方案 B；方案 C 作为长期目标。

### 后续设计文档

**治理设计文档已完成（2026-05-12）**：`docs/SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md`

该文档覆盖：
- 全仓 `system()` / `popen()` 调用清单草案与风险分级；实施前需重新生成清单
- 治理原则（不直接 fail-closed、保持兼容、参数白名单、日志/telemetry、避免 shell 注入）
- **TapLinux 重点分析**：后续优先选择 cleaner withdrawal 边界（`DeleteRoute6`/`DeleteIPv6NeighborProxy`/`DisableIPv6NeighborProxy`/`DeleteIPv6Address`），而非 route-add 边界，因为 withdrawal 是 clean one-shot management operation，且可复用现有 add-path telemetry 模板；部分 withdrawal 函数已有 telemetry 基础
- 分阶段计划（Inventory → Telemetry 基线 → TapLinux pilot → 扩展 → 其他平台 → 清理）
- 回滚策略与风险评估

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他 P1 修复分支中混入该项的代码改动。
- 本文档仅作记录用途，不触发代码变更。

---

## 1.12 CodeQL / govulncheck / npm audit / OSV

| 字段 | 内容 |
|------|------|
| **编号** | P1-12 |
| **当前决策** | **暂不治理，只记录在案** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |

### 问题描述

CodeQL、govulncheck、npm audit、OSV-Scanner 等静态/依赖扫描工具可用于检测已知漏洞和代码安全问题。当前项目未启用任何此类扫描。

### 暂不治理的原因

1. **CI 噪音与误报**：在当前代码规模和依赖结构下，扫描工具会产生大量误报，增加维护负担。
2. **避免改变 release gate 行为**：引入扫描作为 CI 阻断条件会影响现有发布流程稳定性。
3. **项目现状限制**：该项目目前无自动化测试、无 linter，CI 仅检查编译通过。骤然加入扫描 gate 破坏性过大。
4. **与其它 P1 条目互不依赖**：治理该项不影响任何其它并行任务。

### 后续可选治理方案

按侵入性从低到高排列，各方案互不排斥：

| 方案 | 描述 | 侵入性 | 说明 |
|------|------|--------|------|
| **A. Report-only 扫描** | CI 中添加扫描步骤，仅生成报告 artifact，不阻断流水线 | 低 | 适合初期观察误报率 |
| **B. 分级 gate** | 对 C++ 核心（`ppp/`）和 Go 后端（`go/`）分别设定不同严重级别阈值，低级别仅 warn，高级别才 block | 中 | 需先积累误报基线 |
| **C. Nightly 或手动触发扫描** | 扫描放在独立 scheduled workflow（nightly cron 或 `workflow_dispatch`）中，与主构建流水线解耦 | 低 | 推荐首选方案 |

### 当前约束

- **不新增 CI workflow 或扫描 job。**
- **不修改任何现有 CI workflow 文件。**
- **不作为 P0 或当前 release 的阻断条件。**
- 本文档仅作记录用途，不触发代码或 CI 变更。

### 注意事项

- `common/` 下的 vendored 第三方库（lwIP、nlohmann/json、aesni 等）以及示例配置文件（`*.json`）若未来被扫描覆盖，需要配置 allowlist 排除。这些文件当前可以正常分发。
- `go/guardian/webui/` 下的 Svelte/Vite 前端依赖若未来启用 `npm audit`，需注意 devDependencies 与 production dependencies 的区分。
- Geo rules 相关数据文件若被 OSV-Scanner 或类似工具扫描，可能触发误报，同样需要 allowlist。

---

## P1-1 逐帧读取超时（慢读 DoS 加固）

| 字段 | 内容 |
|------|------|
| **编号** | P1-1 |
| **当前决策** | **暂不实施，已完成设计文档，仅记录在案** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §5.1、§8 P1 第 10 项 |
| **设计文档** | `docs/PER_FRAME_READ_TIMEOUT_DESIGN.md` / `docs/PER_FRAME_READ_TIMEOUT_DESIGN_CN.md` |

### 问题描述

传输读取管道中的每次 `async_read`（TCP 路径和 WebSocket 路径）无限期阻塞调用方协程，直到对端发送所请求的字节数。慢速攻击者（slowloris）可每隔几分钟发送一个字节来维持连接，长时间占用协程栈、socket fd、加密状态和 QoS 上下文。

受影响的读取路径：

| 路径 | 入口 | 底层读取 |
|------|------|----------|
| TCP | `ITcpipTransmission::ReadBytes()` | `ppp::coroutines::asio::async_read(*socket, ...)` |
| WebSocket | `templates::WebSocket<IWebsocket>::ReadBytes()` | `IWebsocket::Read()` → `ppp::coroutines::asio::async_read(websocket_, ...)` |
| 帧层 | `ITransmission::Read()` → `ITransmissionBridge::Read()` → `DoReadBytes()` | 虚函数分派到上述路径之一 |

当前 `PPP_BUFFER_SIZE`（65536 字节）帧长度上限（P0-4A ✅）防止了内存膨胀，但不防止慢读。握手超时（`tcp.connect.timeout`）仅覆盖握手阶段。保活机制（`PacketAction_KEEPALIVED`）间隔较长（秒级），不足以防御逐帧慢读。

### 暂不实施的原因

1. **无自动化测试基础设施**：本项目零测试。逐帧读取超时修改每个连接使用的核心读取路径。没有自动化回归测试，细微 bug 可能导致所有连接被虚假销毁。
2. **Socket 取消的跨平台差异**：`socket::cancel()` 与 Boost.Beast websocket 流的交互在本代码库中测试较少，无 WebSocket 传输测试。
3. **QoS 交互需要真实场景分析**：逐帧定时器必须根据 QoS 节流行为调优，需要类似生产的流量配置。
4. **配置表面区域**：添加 `tcp.frame_read.timeout` 更改配置模式，应与其他待定配置更改（多级帧限制）协调。
5. **现有机制提供部分缓解**：握手超时 + 保活机制 + TCP 空闲超时组合已覆盖多数场景，但慢读攻击窗口仍然存在。

### 设计概述

在 `ITransmission::Read()` 中，帧读取前启动一个 `boost::asio::steady_timer`，帧读取完成后取消。定时器到期时调用 `Dispose()` 销毁连接。

关键设计决策：

| 决策 | 选择 | 理由 |
|------|------|------|
| 超时粒度 | 逐帧（非逐子读取） | 简单；避免多次定时器创建/取消开销 |
| 定时器位置 | `ITransmission` 层（非 socket 层） | 覆盖所有路径；与握手超时模式一致 |
| QoS 交互 | 定时器在 QoS 前启动 | QoS 挂起有界；避免 API 侵入 |
| 默认值 | 0（禁用） | 零风险发布；运维人员显式启用 |
| 取消后行为 | 总是销毁传输连接 | 消除 Beast 流不确定状态风险 |

详细设计见 `docs/PER_FRAME_READ_TIMEOUT_DESIGN.md`。

### 后续可选方案

| 方案 | 描述 | 侵入性 | 前置条件 |
|------|------|--------|----------|
| **A. 仅 TCP 路径** | 仅在 `ITcpipTransmission::ReadBytes` 添加 socket 级超时 | 低 | 平台验证 |
| **B. 全路径 + 功能标志** | 完整实现，默认禁用（`timeout: 0`），运维人员按需启用 | 中 | 设计评审 + 至少 Linux 平台验证 |
| **C. 带外空闲清扫** | 定时扫描所有连接，销毁长时间无流量的连接 | 低 | 作为补充机制，非主要方案 |

**推荐路径**：方案 B。完整设计已就绪，待测试基础设施和平台验证后实施。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他 P1 修复分支中混入该项的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码变更。
- 实施时必须默认禁用（`timeout: 0`），由运维人员显式启用。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试存在 | 至少覆盖传输读取路径 | ❌ 无测试 |
| C-2 | Socket 取消在 Linux 上验证 | `epoll` + `cancel()` 与 async_read 交互 | ❌ 未验证 |
| C-3 | QoS 节流行为分析 | 确定合理默认超时值 | ❌ 未分析 |
| C-4 | 配置模式协调 | 与多级帧限制等其他配置变更协调 | ❌ 未协调 |

---

## P1-2 strand/thread-confined `disposed_` 分级复核

| 字段 | 内容 |
|------|------|
| **编号** | P1-2 |
| **当前决策** | **已完成分级复核：2 个类改为 atomic，2 个类记录约束不改** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §15.2 |

### 问题描述

审计文档 §15.2 列出四个候选类的 `disposed_` 标志可能存在跨线程读写的 data race（UB）。需要逐一复核每个类的 `disposed_` 生命周期、读写路径和线程模型，判断是否需要改为 `std::atomic_bool`。

### 分级复核结果

| 类名 | 分类 | 是否修改 | 理由 |
|------|------|----------|------|
| **VEthernetLocalProxyConnection** | **跨线程** | **是 → `std::atomic_bool`** | `IsPortAging()` 从 switcher 定时器线程读 `disposed_`；`Finalize()` 在连接 strand 上写 `disposed_`；析构函数可在任意线程直接调用 `Finalize()`。三者可并发。 |
| **VEthernetLocalProxySwitcher** | **跨线程** | **是 → `std::atomic_bool`** | accept 回调在 SocketAcceptor 的 io_context 线程用 `while (!disposed_)` 轮询；`Finalize()` 在 switcher 的 context 线程写；`Dispose()` 可从任意线程调用。acceptor 的平台实现（Unix/Win32）在独立的 accept 循环中触发回调，与 switcher context 线程不同。 |
| **InternetControlMessageProtocol** | **strand-confined** | **否** | `Dispose()` 通过 `boost::asio::post` 将 `Finalize()` 投递到 executor 线程；`Echo()` 按文档契约在 executor 线程调用；析构函数仅在所有 `shared_ptr` 引用释放后运行（`EchoAsynchronousContext` 持有 `owner_` 引用），此时无人可读 `disposed_`。生命周期语义保证无并发访问。 |
| **ITransmissionQoS** | **mutex-protected** | **否** | 所有 `disposed_` 读写均在 `SynchronizedObjectScope scope(syncobj_)` 锁内完成（`ReadBytes`、`EndRead`、`BeginRead`、`Finalize`）。互斥锁提供 happens-before 关系，无需原子化。 |

### 代码修改详情

#### VEthernetLocalProxyConnection

| 文件 | 修改 |
|------|------|
| `ppp/app/client/proxys/VEthernetLocalProxyConnection.h` | `bool disposed_` → `std::atomic_bool disposed_`；`IsDisposed()` 和 `IsPortAging()` 使用 `.load(acquire)` |
| `ppp/app/client/proxys/VEthernetLocalProxyConnection.cpp` | `Finalize()` 使用 `.store(true, release)`；`Run()` 和 `SendBufferToPeer()` 使用 `.load(acquire)` |

跨线程路径分析：
- **写端**：`Finalize()` 在连接的 strand/socket executor 上运行（通过 `Dispose()` 的 `boost::asio::post`）；析构函数可在任意线程直接调用 `Finalize()`。
- **读端**：`IsPortAging()` 在 `VEthernetLocalProxySwitcher::Update()` 的定时器回调中调用，运行在 switcher 的 context 线程上，与连接 strand 不同。
- **读端**：`IsDisposed()` 是 public 方法，可从任意线程调用。

#### VEthernetLocalProxySwitcher

| 文件 | 修改 |
|------|------|
| `ppp/app/client/proxys/VEthernetLocalProxySwitcher.h` | `bool disposed_` → `std::atomic_bool disposed_` |
| `ppp/app/client/proxys/VEthernetLocalProxySwitcher.cpp` | `Finalize()` 使用 `.store(true, release)`；`Open()`、`CreateAlwaysTimeout()` 和 accept 回调使用 `.load(acquire)` |

跨线程路径分析：
- **写端**：`Finalize()` 通常通过 `Dispose()` 的 `boost::asio::post(*context_, ...)` 在 switcher 的 context 线程运行；析构函数也会直接调用 `Finalize()`，因此写端也可能发生在最后释放对象的任意线程。
- **读端**：accept 回调（`while (!disposed_)`）在 `SocketAcceptor` 的平台 accept 循环线程运行（Unix: `UnixSocketAcceptor` 的 async_accept 回调；Windows: `Win32SocketAcceptor` 的 accept 回调），与 switcher context 线程不同。

### 未修改类的约束记录

#### InternetControlMessageProtocol（strand-confined）

**不改代码，记录约束：**

- 该类的 `disposed_` 所有读写路径在同一个 executor 线程上序列化。
- `Dispose()` 通过 `boost::asio::post(*context, ...)` 将 `Finalize()` 投递到 executor 线程。
- `Echo()` 按头文件文档契约必须在 executor 线程调用。
- 析构函数的 `Finalize()` 调用仅在所有 `shared_ptr` 引用释放后发生，此时 `Echo()` 不可能正在运行。
- **后续验证建议**：确认 `Echo()` 的调用方确实遵循 executor 线程契约；如有违反，需升级为 atomic。

#### ITransmissionQoS（mutex-protected）

**不改代码，记录约束：**

- 该类的 `disposed_` 所有读写均在 `syncobj_` 互斥锁保护下。
- `ReadBytes()`、`EndRead()`、`BeginRead()` 中的 `disposed_` 检查均在 `SynchronizedObjectScope` 内。
- `Finalize()` 中的 `disposed_ = true` 也在 `SynchronizedObjectScope` 内。
- `bandwidth_` 和 `traffic_` 已是 `std::atomic`，用于无锁跨线程读取，与 `disposed_` 的锁保护模式不冲突。
- **后续验证建议**：确认无路径在锁外读取 `disposed_`；当前代码审计未发现此类路径。

### 未变更项

- **未改变 public API**：所有类的 public/protected 接口签名不变。
- **未改变业务逻辑**：仅将 `bool` 升级为 `std::atomic_bool`，读写语义不变。
- **未改变 Finalize 调用顺序**：保持原有 cleanup 顺序，未引入 exchange 级别的 exactly-once 保护（现有析构+Dispose 双路径已是幂等安全的）。
- **未修改 `docs/openppp2-deep-code-audit-cn.md`**。

### 后续验证建议

| 序号 | 验证项 | 说明 | 优先级 |
|------|--------|------|--------|
| V-1 | ThreadSanitizer (TSan) 验证 | 对修改的两个类启用 TSan 构建运行，确认无 data race 报告 | 高 |
| V-2 | VEthernetLocalProxySwitcher Finalize 顺序 | 当前 `disposed_` 在 `acceptor->Dispose()` 之后设置；accept 回调在窗口期可能看到 `disposed_==false`。考虑将 `disposed_` 设置提前到 `acceptor->Dispose()` 之前 | 中 |
| V-3 | InternetControlMessageProtocol Echo 线程契约 | 确认所有 `Echo()` 调用方在 executor 线程上执行 | 低 |

---

## P1-4 Android TLS CA 加载路径复核

| 字段 | 内容 |
|------|------|
| **编号** | P1-4 |
| **当前决策** | **已完成最小治理：补充诊断 + root CA fallback 异常路径收敛 + 文档化** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.5 S-1 |

### 问题描述

审计文档 S-1 指出：Android 上 `set_default_verify_paths()` 被 `#if !defined(__ANDROID__)` 跳过，担心 `verify_peer=true` 时缺少 CA 来源，导致验证静默降级。

### 复核结论

**当前 Android CA 加载路径并非静默不安全。** 完整的 CA 来源顺序如下：

| 优先级 | CA 来源 | 平台 | 说明 |
|--------|---------|------|------|
| 1 | `cacert.pem` 文件 | 全平台 | 由 `chnroutes2_cacertpath_default()` 返回 `./cacert.pem`；仅当文件存在时尝试加载 |
| 2 | 内置根证书 (`root_certificates.hpp`) | 全平台 | 当 `cacert.pem` 加载失败时回退；包含 Mozilla 根 CA 集合（约 150+ 个根证书） |
| 3 | 系统默认 CA 路径 | 非 Android | `set_default_verify_paths()`；Android 跳过（Android 不通过标准 OpenSSL 文件系统路径暴露系统 CA 存储） |

**关键发现：**

1. **不会静默降级**：即使 `cacert.pem` 不存在，内置根证书作为 fallback 提供有效的 CA 数据。`verify_peer=true` 始终有 CA 来源可验证。
2. **fail-closed 行为**：如果所有 CA 加载路径均失败（概率极低——内置证书是硬编码 PEM 数据），信任存储为空，所有握手必然失败。这是正确的安全行为，不是静默跳过验证。
3. **存在 root CA fallback 异常路径风险**：原代码调用 `load_root_certificates(*ssl_context)` 的抛异常重载，在 `noexcept` 函数 `CreateClientSslContext` 中可能因 Boost/system_error 异常导致 `std::terminate`。**已收敛为使用带 `error_code` 的重载 `load_root_certificates(*ssl_context, ec)`，但该函数内仍可能受内存分配等非 Boost 异常路径影响；本次不声称彻底消除 `CreateClientSslContext` 内所有潜在 throw 点。**

### 治理措施（已完成）

| 修改 | 文件 | 描述 |
|------|------|------|
| **root CA fallback 异常路径收敛** | `ppp/ssl/SSL.cpp` | `load_root_certificates(*ssl_context)` → `load_root_certificates(*ssl_context, ec)`，避免该 fallback 路径通过 Boost/system_error 抛异常 |
| **Android 诊断** | `ppp/ssl/SSL.cpp` | 当 `verify_peer=true` 但所有 CA 加载失败时，通过 `SetLastErrorCode(SslHandshakeFailed)` 记录诊断 |
| **文档化注释** | `ppp/ssl/SSL.cpp` | 完善 client/server SSL context 中 Android 分支的 doxygen 注释，说明 CA 来源链、跳过原因和 fail-closed 语义 |

### 未变更项

- **未改变正常成功路径语义**：非 Android 仍会尝试系统默认 CA 路径；但 root CA fallback 的异常处理路径也从抛异常重载改为 `error_code` 重载，因此失败路径更温和。
- **未新增 Java/Kotlin bridge**：不引入 JNI CA 导出机制。
- **未修改构建系统**：不改 build.gradle 或 CMakeLists.txt。
- **未降级 verify_peer**：verify_peer 始终按调用者要求设置，不做任何静默跳过。
- **未修改 `docs/openppp2-deep-code-audit-cn.md`**。

### 剩余需真机/模拟器验证项

| 序号 | 验证项 | 说明 | 优先级 |
|------|--------|------|--------|
| V-1 | `cacert.pem` 在 Android APK 中的实际路径 | `chnroutes2_cacertpath_default()` 返回 `./cacert.pem`，需确认 Android NDK 进程的 CWD 是否指向 APK 可写目录 | 高 |
| V-2 | 内置根证书在 Android BoringSSL 下的解析兼容性 | `root_certificates.hpp` 使用 `add_certificate_authority()` 接口，需在 Android BoringSSL 上验证 PEM 解析无异常 | 高 |
| V-3 | BoringSSL `X509_STORE_get0_objects` / `sk_X509_OBJECT_sort` API 可用性 | 预排序逻辑已在代码中，需确认 Android BoringSSL 版本是否导出这两个符号 | 中 |
| V-4 | `verify_peer=true` 且 `cacert.pem` 缺失时握手行为 | 预期：使用内置根证书成功握手；需端到端验证 | 中 |
| V-5 | `verify_peer=true` 且所有 CA 路径失败时的诊断输出 | 预期：`SetLastErrorCode(SslHandshakeFailed)` 被设置；需确认日志可见 | 低 |

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 剩余验证项（V-1 至 V-5）需在 Android 真机或模拟器上进行，不在本次静态代码复核范围内。
- 本文档和 `ppp/ssl/SSL.cpp` 的修改与其他 P1 条目互不依赖。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md`*

---

## P1-5 启动安全诊断报告

| 字段 | 内容 |
|------|------|
| **编号** | P1-5 |
| **当前决策** | **已完成最小治理：添加 `EmitSecurityDiagnostics()` 启动安全诊断汇总** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §3.5（P0-2） |

### 问题描述

P0-2 已在 `AppConfiguration::Loaded()` 中实现了弱 key、短 key 和 plaintext 模式的检测，并通过 `SetLastErrorCode()` 设置 `kWarning` 级别错误码。然而存在以下局限：

1. **"Last writer wins" 问题**：`SetLastErrorCode()` 是 thread-local + 进程级快照机制，多次调用时只有最后一次设置的警告可见，之前的警告被静默覆盖。
2. **无可视化输出**：警告仅通过错误码系统记录，不输出到控制台或遥测日志，运维人员无法直接观察到安全风险。
3. **无汇总报告**：即使检测到多个安全问题，也缺少一个统一的诊断摘要。

### 治理措施（已完成）

| 修改 | 文件 | 描述 |
|------|------|------|
| **新增 `EmitSecurityDiagnostics()` 方法** | `ppp/configurations/AppConfiguration.h` | 声明公共方法，扫描配置并发射安全诊断报告 |
| **实现诊断扫描与输出** | `ppp/configurations/AppConfiguration.cpp` | 检查 protocol/transport key 默认值、短 key (< 8 字节)、plaintext 模式；每个发现通过 `telemetry::Log()` 和 `ConsoleFormat()` 各输出一次；末尾输出汇总行 |
| **启动集成调用** | `ppp/app/ApplicationConfig.cpp` | 在 `PreparedArgumentEnvironment()` 中 telemetry 配置完成后调用 `EmitSecurityDiagnostics()` |

### 设计约束

- **所有发现均为非阻断警告**：与 P0-2 一致，弱 key、示例 key、短 key、plaintext=true 永远不阻断启动。
- **原有 `SetLastErrorCode()` 检测保持不变**：`Loaded()` 中的原有检测代码保留，保持向后兼容。
- **`EmitSecurityDiagnostics()` 仅做诊断报告**：不修改配置、不改变默认值、不返回错误。
- **telemetry 和控制台双通道输出**：确保无论是否启用 telemetry，警告在控制台均可见。

### 输出格式示例

```
[security] WARN: protocol key uses well-known default — change for production
[security] WARN: plaintext mode enabled (key.plaintext=true) — not suitable for untrusted networks
[security] Startup security diagnostics: 2 warning(s) — startup continues (non-fatal)
```

当所有检查通过时，仅在 telemetry 中记录（不在控制台输出）：
```
[telemetry] security: Startup security diagnostics: all checks passed
```

### 未变更项

- **未改变 `Loaded()` 原有逻辑**：原有的 `SetLastErrorCode()` 调用保留不变。
- **未新增 ErrorCodes.def 条目**：复用已有的 `ConfigWeakKeyDefault`、`ConfigWeakKeyShort`、`ConfigPlaintextEnabled` 警告码。
- **未改变启动失败路径**：`PreparedArgumentEnvironment()` 的返回值不受影响。
- **未修改构建系统**：不改 CMakeLists.txt 或 build 脚本。

### 后续可选增强

| 序号 | 增强项 | 说明 | 优先级 |
|------|--------|------|--------|
| E-1 | 示例 key 字典扩展 | 增加对 `"password"`、`"123456"`、`"test"` 等常见弱口令的检测 | 中 |
| E-2 | TUI 集成 | 在 ConsoleUI 状态栏中显示安全警告数量 | 低 |
| E-3 | JSON 诊断报告 | 输出结构化 JSON 格式的诊断报告到文件，便于自动化工具消费 | 低 |

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- `EmitSecurityDiagnostics()` 的输出格式可能在后续版本中调整。
- 本文档和代码修改与其他 P1 条目互不依赖。
