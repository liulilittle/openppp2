# UDP 数据面解耦 P2-d 实施计划
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> **执行方式**：本会话内联 TDD 执行，步骤用 checkbox 跟踪。承接 P2-c（`ClientDatagramPortManager`
> 已抽出、exchanger 已 implements `IUdpRelayHost`），是 UDP 数据面**彻底离开 God-Object** 的收尾。

**Goal**：断掉 `VEthernetDatagramPort` 与 `VEthernetExchanger`/`VEthernetNetworkSwitcher` 的双向耦合——
port 通过注入的 `UdpRelayHostPorts` 回调访问能力，撤掉 4 处 `friend`，删除 `switcher_` 强引用，
热路径去除每收包一次的 `shared_ptr` 拷贝。**行为严格等价**。

**Architecture**：port 保留 `exchanger_` 的 `shared_ptr` **仅作生命周期锚**（前向声明、不经它调任何方法），
所有 exchanger/switcher 能力经 `ports_` 回调（裸 this，锚保证异步 Finalize 安全）。`switcher_` 强引用彻底删除。

**Tech Stack**：C++17 / Boost.Asio / `ppp::function` / 现有 `UdpRelayHostPorts` + `ClientDatagramPortManager`（P2-c）。

---

## Global Constraints（每个 Task 隐含遵守）

- **提交规范**（[[git-commit-standards]]）：author `HyacinthHaru <hyacinth@haru.ac>`、SSH 签名 `~/.ssh/id_ed25519`、
  **无任何 co-author**、标题一句正文 ≤ 2 句。分 3–4 个 commit 自定。
- **平台 guard**：Android 专有回调 `get_protector_network`（返回 `ProtectorNetworkPtr`，该类型仅 `_ANDROID` 存在）
  必须 `#if defined(_ANDROID)` 包字段；`is_bypass_ip`（`boost::asio::ip::address→bool`）跨平台可不 guard。
- **服务器验证法**：`cd /root/ppp-bench/openppp2 && g++ -std=c++17 -fsyntax-only -I. -Icommon/json/include
  -D__SIMD__ -DJEMALLOC -DFUNCTION <file>`。**必须用内置 jsoncpp `-Icommon/json/include`**（系统 libjsoncpp 假阳性）。
- **门禁**：`ppp.vcxproj` 同步新增 `.cpp`（parity）、include-boundary（`STDAFX_BASELINE`）、manager + port 单测、ASan。
- **停在 push/CI 前**（用户自行 push 触发 Boost 1.86 全平台 CI + 发上游 PR）。

---

## 核心设计决策

### D1 生命周期：shared exchanger 锚 + 裸 this ports 回调
坐实的 teardown：`exchanger.Finalize()`(VEthernetExchanger.cpp:256) 同步调 `datagram_manager_->Release()`(:293)，
Release 遍历 `port.Dispose()` → `post` **异步** `Finalize`。port 若不锚定 exchanger，该 post Finalize 可能在
exchanger 析构后才跑 → port 的裸 this 回调 UAF。

**决策**：port 保留 `std::shared_ptr<VEthernetExchanger> exchanger_` **仅作生命周期锚**（前向声明、**不经它调任何方法**），
保证 `exchanger 活 ⊇ port 活 ⊇ port 异步`。所有能力走 `ports_` 回调（裸 this，因锚而恒安全）。
与现有行为**等价**（现在 port 亦持 `exchanger_` shared_ptr）；净变化 = 删 `switcher_` 锚 + 能力改回调 + friend 全撤 + 热路径去拷贝。

**备选（不采用）**：① `weak_ptr` 锚 + 每次 `lock`——热路径 `SendTo→do_send_to` 每包一次原子操作，损性能；
② 无锚裸 this——需改 `switcher` teardown 等所有 port drain 后才 reset `exchanger_`，超出 P2-d 范围且引入风险。

### D2 `do_send_to` 真实签名
P2-c 占位 `bool(int in_protocol, src, dst, const Byte*, int)` → 真实
`bool(const ITransmissionPtr&, src, dst, Byte* packet, int len, ppp::coroutines::YieldContext&)`
（匹配 `VirtualEthernetLinklayer::DoSendTo`@VirtualEthernetLinklayer.h:167，**public**）。

### D3 friend 断除（4 处全撤，依据）
| friend 声明 | 为谁而设 | 撤除依据 |
|---|---|---|
| `port.h:71` friend `VEthernetExchanger` | exchanger 访问 port 私有 | exchanger 仅用 public 构造建 port + manager 经 public `OnMessage`/`MarkFinalize`/`Dispose`/`IsPortAging`/`SendTo` 驱动；不碰 port 私有 |
| `port.h:72` friend `VEthernetNetworkSwitcher` | switcher 访问 port 私有 | switcher 全仓不碰 port 实例私有 |
| `switcher.h:71` friend `VEthernetDatagramPort` | 让 port 调 switcher protected `DatagramOutput` | port 改走 `ports.datagram_output`（回调体在 exchanger，exchanger 是 switcher 的 friend@switcher.h:70） |
| `exchanger.h:98` friend `VEthernetDatagramPort` | 让 port 调 exchanger protected `ReleaseDatagramPort`/`NewDatagramPort` | port 改走 `ports.release_port`；`DoSendTo` 本就 public |

### D4 port 成员/接口变化
- **删** `switcher_`（`VEthernetNetworkSwitcherPtr`）成员 + port.cpp 的 `#include VEthernetNetworkSwitcher.h`。
- **保留** `exchanger_`（`shared_ptr`，锚，前向声明；注释 `lifecycle anchor only`）+ port.cpp 保留 `#include VEthernetExchanger.h`（锚析构）。
- **删** dead `GetExchanger()`（全仓无 `port->GetExchanger()` 调用点）。
- **加** `UdpRelayHostPorts ports_` 成员。
- **构造签名**：`(const VEthernetExchangerPtr& exchanger, UdpRelayHostPorts ports, const ITransmissionPtr& transmission, const endpoint& sourceEP)`
  ——`exchanger` 存锚，`ports` 存能力。`NewDatagramPort`(exchanger.cpp:1772) 改传 `(exchanger, BuildUdpRelayHostPorts(), transmission, sourceEP)`。
- **8 个用点改回调**：构造 `GetSwitcher`（删，不需要）/`GetConfiguration`→`ports.get_configuration`；`GetProtectorNetwork`→`ports.get_protector_network`；
  `ReleaseDatagramPort`→`ports.release_port`；`DoSendTo`×2→`ports.do_send_to`；`IsBypassIpAddress`→`ports.is_bypass_ip`；`DatagramOutput`→`ports.datagram_output`（传 `caching=true`，匹配现默认）。
  热路径 `OnMessage:258` 删 `shared_ptr<exchanger>` 拷贝。

---

## Tasks

### Task 1：扩展 `UdpRelayHostPorts` + manager 测试保绿
**Files**：`ppp/app/client/udp/UdpRelayHost.h`（改）；`tests/cpp/client_datagram_port_manager_test.cpp`、`tests/cpp/support/datagram_manager_stubs.*`（改）
**Interfaces produced**：`do_send_to` 新签名（D2）、`release_port`(`endpoint→void`)、`is_bypass_ip`(`address→bool`)、
`get_protector_network`(`()→ProtectorNetworkPtr`，Android guard)；前向声明 `ppp::coroutines::YieldContext` + `ppp::net::ProtectorNetwork`。

- [ ] 改 `UdpRelayHost.h`：`do_send_to` 签名 + 3 新字段（`get_protector_network` 用 `#if defined(_ANDROID)`）+ `IsValid`（保持只校验 manager 依赖的 8 项，新增 port 专有字段不入 IsValid）+ 前向声明。
- [ ] 更新 manager 测试 `MakeFilledPorts`：补 `do_send_to` 新签名的 non-null stub + `release_port`/`is_bypass_ip` stub；IsValid 用例对齐。
- [ ] 服务器编译 + 跑 manager 单测（15 例保持全绿）。**验收**：manager test green，UdpRelayHost.h 服务器 syntax 0 error。

### Task 2：exchanger `BuildUdpRelayHostPorts` 接线新字段
**Files**：`ppp/app/client/VEthernetExchanger.cpp:130`
- [ ] `do_send_to`→`[self](t,s,d,p,l,y){ return self->DoSendTo(t,s,d,p,l,y); }`；`release_port`→`[self](s){ self->ReleaseDatagramPort(s); }`；
  `is_bypass_ip`(Android)→`self->switcher_->IsBypassIpAddress`；`get_protector_network`(Android)→`self->switcher_->GetProtectorNetwork`。裸 this（范式一致）。
- [ ] 删除 P2-c 的 `do_send_to` 占位 lambda。
- [ ] 服务器 `-fsyntax-only` exchanger.cpp。**验收**：0 error。

### Task 3：port 改造持 ports + 断 friend/头依赖 + port 单测
**Files**：`VEthernetDatagramPort.h`/`.cpp`、`VEthernetExchanger.cpp:1772`、`VEthernetNetworkSwitcher.h:71`、`VEthernetExchanger.h:98`；
`tests/cpp/vethernet_datagram_port_test.cpp`（新）+ `tests/cpp/CMakeLists.txt` + `ppp.vcxproj`
- [ ] **RED**：写 port 单测——注入 spy `UdpRelayHostPorts`，断言 `SendTo`→`do_send_to`、`OnMessage`→`datagram_output`、`Finalize`→`release_port` + 终止 `do_send_to`。先跑证其失败/不编译。
- [ ] **GREEN**：port 构造持锚 + `ports_`；8 用点改回调（D4）；删 `switcher_`；撤 port.h 两 friend；撤 port.cpp `switcher.h` include；`NewDatagramPort` 传 `BuildUdpRelayHostPorts()`；撤 `switcher.h:71` + `exchanger.h:98` 两 friend。
- [ ] 跑 port 单测 green；服务器全量 syntax（port/exchanger/switcher）。**验收**：port test green，4 friend 全撤后 0 error。

### Task 4：生命周期审查 + 全量验证 + 签名提交
- [ ] 复核 D1 锚论证：port 所有 `ports_` 回调调用点（同步栈 + 异步 Finalize）在锚保护下裸 this 安全。
- [ ] 全量服务器 `-fsyntax-only`：exchanger / port / manager / switcher / friend 类（`ExchangerStaticEchoChannel`）。
- [ ] 门禁：`tools/check_vcxproj_sources.py`、`tools/check_include_boundaries.sh`、manager + port 单测、ASan（port 单测并发无 UAF）。
- [ ] 分 3–4 个 SSH 签名 commit。**停在 push/CI 前**。

---

## Self-Review
- **Spec 覆盖**：断双向耦合(D3/D4) + do_send_to 修正(D2) + 生命周期安全(D1) + 热路径去拷贝(D4) 均有 Task 承载。
- **类型一致**：`do_send_to` 新签名在 UdpRelayHost.h(T1)/exchanger(T2)/port(T3)/manager test(T1) 四处一致；`ProtectorNetworkPtr` 仅 Android。
- **雷区**：finalize 双向协议（port 自注销改 `ports.release_port`，语义等价）、两阶段 GC（manager 侧不动）、生命周期锚（D1 论证）。
- **无占位**：所有回调签名与调用形态已写死；机械改点给了 file:line。
