# P2-c: 抽取 ClientDatagramPortManager 实施计划
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> **For agentic workers:** 用 superpowers:subagent-driven-development 或 superpowers:executing-plans 逐任务实施。步骤用 `- [ ]` 复选框跟踪。

**Goal:** 把 `VEthernetExchanger` 里交织的 UDP 会话表(`datagrams_`/`datagram_handlers_`)与其管理逻辑抽成独立的 `ClientDatagramPortManager`,带**独立锁**,让 God-Object 卸下 UDP relay 这一职责簇。

**Architecture:** 照仓库既有 `DnsUdpRelay`+`DnsHostPorts`+`IDnsHost` / `route::RouteHostPorts`+`IRouteBackend` 范式。新组件自持会话表 + 独立 `syncobj_`,通过已就绪的 `udp::UdpRelayHostPorts`(注入回调)消费 exchanger/switcher 能力,无需 include 庞大的 exchanger 头。exchanger 保留薄转发壳(保 ABI),把状态与逻辑委托给 manager。协程/传输仍留在 `VEthernetDatagramPort` 内部(P2-d 处理),本阶段只迁"会话表管理"。

**Tech Stack:** C++17、Boost.Asio、`ppp::function`/`ppp::unordered_map`、tests/cpp 外科手术式单测 + ASan 护栏、GitHub Actions(Boost 1.86 完整编译)、服务器 `-fsyntax-only`(内置 jsoncpp)快验。

## Global Constraints

- 提交规范(硬性):author=`HyacinthHaru`(无空格)、email=`hyacinth@haru.ac`、SSH `~/.ssh/id_ed25519` 签名、**无任何 co-author**、标题一句/正文≤两句。
- 每 PR 过 `tools/check_include_boundaries.sh`(include-boundary)+ vcxproj-parity 门禁;新增 .cpp 必须同步进 `ppp.vcxproj` 且计数相等。
- 主库完整编译靠 CI;本地服务器 `cd /root/ppp-bench/openppp2 && g++ -std=c++17 -fsyntax-only -I. -Icommon/json/include -D__SIMD__ -DJEMALLOC -DFUNCTION <file>` 快验编译期(**必须内置 jsoncpp,系统 libjsoncpp 对 `Json::Value=ppp::string` 假阳性**)。
- **3 个正确性雷区原样保住**(详见每任务护栏):(1) DatagramPort 双向 finalize 协议;(2) NAT 超时两阶段 GC(锁内收集/摘除、锁外判定/Dispose、identity 校验防 ABA);(3) static-echo 状态/方法劈裂竞态。
- **独立锁**:manager 用自己的 `syncobj_`,不复用 exchanger 的 `syncobj_`(把 H1"去多余锁层"精神延伸到 UDP 会话表——当前每个 UDP 包都过 exchanger 那把与 FRP/定时器共享的锁)。
- 行为对等:迁移前后 `SendTo`/`ReceiveFromDestination`/GC 的可观察行为逐字保持;这是纯重构,不改数据面语义。

---

## File Structure

- **Create** `ppp/app/client/udp/ClientDatagramPortManager.h` — manager 类声明(自持会话表 + 独立锁 + 消费 `UdpRelayHostPorts`)。
- **Create** `ppp/app/client/udp/ClientDatagramPortManager.cpp` — manager 实现(迁自 exchanger 的会话表管理 + 两阶段 GC)。
- **Modify** `ppp/app/client/udp/UdpRelayHost.h` — 按真实调用链补齐 `UdpRelayHostPorts` 字段(见 Task 1)。
- **Modify** `ppp/app/client/VEthernetExchanger.h` — 加 `std::unique_ptr<udp::ClientDatagramPortManager> datagram_manager_`;会话表方法改为转发声明保留。
- **Modify** `ppp/app/client/VEthernetExchanger.cpp` — 会话表方法体委托给 manager;`Update()` 的 UDP GC 段委托 `manager->Tick(now)`(mapping GC 留原地);实现 `BuildUdpRelayHostPorts()`。
- **Modify** `ppp.vcxproj` — 加入新 .cpp(保 parity)。
- **Modify** `tools/check_include_boundaries.sh` — 若触及 stdafx 基线计数则同步。
- **Create** `tests/cpp/client_datagram_port_manager_test.cpp` — 会话表/数据面/finalize/GC 的外科手术式单测。
- **Create** `tests/cpp/support/datagram_manager_stubs.cpp` — 桩掉 `UdpRelayHostPorts` 回调与假 port,隔离测 manager。

---

## Task 1: 补齐 UdpRelayHostPorts 契约 + manager 骨架

**Files:**
- Modify: `ppp/app/client/udp/UdpRelayHost.h`
- Create: `ppp/app/client/udp/ClientDatagramPortManager.h`
- Create: `ppp/app/client/udp/ClientDatagramPortManager.cpp`
- Modify: `ppp.vcxproj`
- Test: `tests/cpp/client_datagram_port_manager_test.cpp`
- Test: `tests/cpp/support/datagram_manager_stubs.cpp`

**Interfaces:**
- Consumes: 现有 `udp::UdpRelayHostPorts`(已定义 `get_tap`/`get_configuration`/`datagram_output`/`rewrite_fakeip`/`do_send_to`/`emplace_timeout`)。
- Produces(后续任务依赖):
  - `UdpRelayHostPorts` 新增字段:`ppp::function<ITransmissionPtr()> get_transmission;`(SendTo 取 `transmission_`)、`ppp::function<VEthernetDatagramPortPtr(const ITransmissionPtr&, const udp::endpoint&)> create_port;`(封装 `NewDatagramPort`,port 本阶段仍持 exchanger)、`ppp::function<bool()> is_disposed;`。
  - `class ClientDatagramPortManager { public: explicit ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept; ~ClientDatagramPortManager() noexcept; bool IsValid() const noexcept; };` — 本任务只建骨架 + 独立 `SynchronizedObject syncobj_;` + 空 `datagrams_`/`datagram_handlers_` 表。

- [ ] **Step 1: 写失败测试**(manager 能构造且 `IsValid()` 校验 ports 完整)

```cpp
// tests/cpp/client_datagram_port_manager_test.cpp
#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include "support/catch_amalgamated.hpp"
using ppp::app::client::udp::ClientDatagramPortManager;
using ppp::app::client::udp::UdpRelayHostPorts;

TEST_CASE("manager rejects incomplete ports") {
    UdpRelayHostPorts ports;  // 全空回调
    ClientDatagramPortManager m(ports);
    REQUIRE_FALSE(m.IsValid());
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd tests/cpp && cmake -B build && cmake --build build --target client_datagram_port_manager_test && ./build/client_datagram_port_manager_test`
Expected: 链接失败(`ClientDatagramPortManager` 未定义)。

- [ ] **Step 3: 补 ports 字段 + 写 manager 骨架**

在 `UdpRelayHost.h` 的 `UdpRelayHostPorts` 里加上 Interfaces 所列三字段,并把它们纳入 `IsValid()`。新建 `ClientDatagramPortManager.h/.cpp`:构造存 `ports_`、初始化独立 `syncobj_` 与两张空表;`IsValid()` 返回 `ports_.IsValid()`。加入 `ppp.vcxproj`(紧邻 `UdpRelayHost` 相关条目,保 parity)。

- [ ] **Step 4: 跑测试确认通过**

Run: 同 Step 2。Expected: PASS。服务器 `-fsyntax-only` 编 `ClientDatagramPortManager.cpp` 得 0 error。

- [ ] **Step 5: 提交**

```bash
git add ppp/app/client/udp/UdpRelayHost.h ppp/app/client/udp/ClientDatagramPortManager.h ppp/app/client/udp/ClientDatagramPortManager.cpp ppp.vcxproj tests/cpp/client_datagram_port_manager_test.cpp tests/cpp/support/datagram_manager_stubs.cpp
git commit -m "feat(client): add ClientDatagramPortManager scaffold + UdpRelayHostPorts fields (P2-c)"
```

---

## Task 2: 迁会话表存储与 Add/Get/Release(独立锁)

**Files:**
- Modify: `ppp/app/client/udp/ClientDatagramPortManager.h` / `.cpp`
- Modify: `ppp/app/client/VEthernetExchanger.cpp:1840-1902`(AddNewDatagramPort/GetDatagramPort/ReleaseDatagramPort 改为转发)
- Modify: `ppp/app/client/VEthernetExchanger.h`(加 `datagram_manager_` 成员)
- Test: `tests/cpp/client_datagram_port_manager_test.cpp`

**Interfaces:**
- Produces: `Ptr AddNewDatagramPort(const ITransmissionPtr&, const udp::endpoint& src) noexcept;`、`Ptr GetDatagramPort(const udp::endpoint& src) noexcept;`、`Ptr ReleaseDatagramPort(const udp::endpoint& src) noexcept;`(`Ptr = std::shared_ptr<VEthernetDatagramPort>`)。语义与 exchanger 现版逐字一致(Get/Release 锁内 `Dictionary::FindObjectByKey`/`ReleaseObjectByKey`;Add 先 Get、未命中经 `ports_.create_port` 建、锁内 `emplace`、冲突则 `Dispose`)。

- [ ] **Step 1: 写失败测试**(Add 幂等去重 + Get/Release 往返;用 stub port 计数验独立锁不与 exchanger 共享)

```cpp
TEST_CASE("AddNewDatagramPort dedups by source endpoint") {
    auto m = MakeManagerWithFakePorts();      // stub: create_port 返回可计数假 port
    boost::asio::ip::udp::endpoint src(boost::asio::ip::make_address("10.0.0.1"), 5000);
    auto a = m->AddNewDatagramPort(FakeTransmission(), src);
    auto b = m->AddNewDatagramPort(FakeTransmission(), src);
    REQUIRE(a == b);                            // 同 key 复用
    REQUIRE(m->GetDatagramPort(src) == a);
    REQUIRE(m->ReleaseDatagramPort(src) == a);
    REQUIRE(m->GetDatagramPort(src) == nullptr);
}
```

- [ ] **Step 2: 跑测试确认失败** — Expected: 方法未定义/断言失败。

- [ ] **Step 3: 迁实现**

把 `VEthernetExchanger.cpp:1840-1902` 的三方法体迁入 manager,`syncobj_` 换成 manager 自己的,`NewDatagramPort` 换成 `ports_.create_port(transmission, src)`,`disposed_` 换成 `ports_.is_disposed()`。exchanger 里三方法改成一行转发:`return datagram_manager_->AddNewDatagramPort(transmission, sourceEP);` 等。`VEthernetExchanger.h` 加 `std::unique_ptr<udp::ClientDatagramPortManager> datagram_manager_;`,构造时经 `BuildUdpRelayHostPorts()`(Task 5 完善,先给最小可用版)注入。

- [ ] **Step 4: 跑测试确认通过** + 服务器 `-fsyntax-only` 编 manager 与 exchanger 均 0 error。

- [ ] **Step 5: 提交**

```bash
git commit -m "refactor(client): move UDP session table Add/Get/Release into ClientDatagramPortManager (P2-c)"
```

---

## Task 3: 迁数据面 SendTo/ReceiveFromDestination + 本地代理表(雷区 1 finalize)

**Files:**
- Modify: manager `.h`/`.cpp`
- Modify: `VEthernetExchanger.cpp`(SendTo:1656、ReceiveFromDestination:1627、OnSendTo:1621、TryHandleDatagram、RegisterDatagramHandler:1695、ReleaseDatagramHandler:1710 改转发)
- Test: manager test

**Interfaces:**
- Produces: `bool SendTo(src,dst,packet,size)`、`bool ReceiveFromDestination(src,dst,packet,len)`、`bool OnSendTo(transmission,src,dst,packet,len,YieldContext&)`、`bool TryHandleDatagram(src,dst,packet,len)`、`bool RegisterDatagramHandler(src,handler)`、`bool ReleaseDatagramHandler(src)`。`datagram_handlers_` 表迁入 manager(独立锁)。`ReceiveFromDestination` 的 `switcher_->DatagramOutput` 换 `ports_.datagram_output`。

- [ ] **Step 1: 写失败测试**(雷区 1:入站空包触发 `MarkFinalize()`+`Dispose()`;有 port 时 `OnMessage`;无 port 有效包走 `datagram_output`)

```cpp
TEST_CASE("ReceiveFromDestination finalize signal on empty packet") {
    auto m = MakeManagerWithFakePorts();
    udp::endpoint src(...), dst(...);
    auto p = m->AddNewDatagramPort(FakeTransmission(), src);
    m->ReceiveFromDestination(src, dst, nullptr, 0);       // 空包=UDP 关闭信令
    REQUIRE(FakePortOf(p).mark_finalize_called == 1);       // 雷区1
    REQUIRE(FakePortOf(p).dispose_called == 1);
}
TEST_CASE("ReceiveFromDestination reinjects to TUN when no port") {
    auto m = MakeManagerWithFakePorts();
    int reinjected = 0;                                     // datagram_output stub 计数
    m->ReceiveFromDestination(src, dst, buf, len);
    REQUIRE(reinjected == 1);
}
```

- [ ] **Step 2: 跑测试确认失败。**

- [ ] **Step 3: 迁实现** — 逐字搬 body,只替换能力调用为 `ports_.*`;`OnSendTo` 维持"仅转发 `ReceiveFromDestination`、不使用 `YieldContext`"的现状(协程留 port,P2-d)。exchanger 六方法改转发。

- [ ] **Step 4: 跑测试确认通过** + 服务器 syntax。

- [ ] **Step 5: 提交** `refactor(client): move UDP datagram data-plane into ClientDatagramPortManager (P2-c)`

---

## Task 4: 迁两阶段 GC 到 manager::Tick(雷区 2)

**Files:**
- Modify: manager `.h`/`.cpp`(加 `void Tick(UInt64 now) noexcept;`)
- Modify: `VEthernetExchanger.cpp:600-669`(datagram GC 段抽出 → `datagram_manager_->Tick(now)`;mapping GC 段**留原地**)
- Test: manager test(+ ASan 护栏)

**Interfaces:**
- Produces: `void Tick(UInt64 now) noexcept;` — 复刻四阶段:①锁内快照 `datagrams_`→candidates ②锁外 `IsPortAging(now)` 判定 ③锁内按 key+**identity 校验**(`tail->second==candidate.second`)erase→stale ④锁外 `IDisposable::Dispose(*port)`。**只处理 datagrams_,不碰 mappings_**。

- [ ] **Step 1: 写失败测试**(GC 摘除老化 port;identity 校验:GC 期间同 key 被替换则不误删新 port)

```cpp
TEST_CASE("Tick disposes aging ports and honors identity check") {
    auto m = MakeManagerWithFakePorts();
    auto oldp = m->AddNewDatagramPort(FakeTransmission(), src);
    FakePortOf(oldp).aging = true;
    m->Tick(now);
    REQUIRE(m->GetDatagramPort(src) == nullptr);           // 老化被摘
    REQUIRE(FakePortOf(oldp).dispose_called == 1);         // 锁外 Dispose
}
```

- [ ] **Step 2: 跑测试确认失败。**

- [ ] **Step 3: 迁实现** — 把 :600-669 的 datagram 相关四阶段搬进 `Tick`(用 manager `syncobj_`),`Update()` 原处只留 mapping GC + 调 `datagram_manager_->Tick(now)`。

- [ ] **Step 4: 跑测试 + ASan 并发护栏**(照 `bench/udp/allocator_stress.cpp` 思路:多线程 SendTo/Receive/Tick 交错,ASan 验无 UAF/无死锁——雷区 2 的锁外 Dispose 不得持锁重入)。

Run: `cmake -B build -DENABLE_ASAN=ON ... && ./build/client_datagram_port_manager_test`
Expected: PASS,ASan clean。

- [ ] **Step 5: 提交** `refactor(client): move UDP NAT-timeout GC into ClientDatagramPortManager::Tick (P2-c)`

---

## Task 5: 接线 BuildUdpRelayHostPorts + 撤 exchanger 会话表成员(雷区 3)

**Files:**
- Modify: `VEthernetExchanger.cpp`(实现 `udp::UdpRelayHostPorts VEthernetExchanger::BuildUdpRelayHostPorts() noexcept`,类实现 `IUdpRelayHost`)
- Modify: `VEthernetExchanger.h`(移除 `datagrams_`/`datagram_handlers_` 成员;`syncobj_` 若仅剩 FRP/定时器用则保留)
- Test: manager test + CI 完整编译

**Interfaces:**
- Consumes: 全部前序 manager 接口。
- Produces: `BuildUdpRelayHostPorts()` 把 `get_tap`→`switcher_->GetTap`、`get_configuration`→`GetConfiguration`、`datagram_output`→`switcher_->DatagramOutput`、`rewrite_fakeip`→`switcher_->RewriteFakeIpAddress`、`do_send_to`→`VirtualEthernetLinklayer::DoSendTo` 绑定、`get_transmission`→`transmission_`、`create_port`→`NewDatagramPort`、`emplace_timeout`→`NewDeadlineTimer`、`is_disposed`→`disposed_` 全部接上。

- [ ] **Step 1: 写失败测试**(端到端:经 exchanger 薄壳 `SendTo` → manager → fake port 收到;确认 exchanger 不再直接持 `datagrams_`——编译期即验,成员已移除)

```cpp
TEST_CASE("exchanger SendTo delegates through manager end to end") {
    auto ex = MakeFakeExchangerWithRealManager();
    REQUIRE(ex->SendTo(src, dst, buf, len) == true);
    REQUIRE(FakeSwitcher().datagram_output_or_send_seen == true);
}
```

- [ ] **Step 2: 跑测试确认失败。**

- [ ] **Step 3: 实现接线** — 补全 `BuildUdpRelayHostPorts()` 所有回调;exchanger 构造用它初始化 `datagram_manager_`。移除 `VEthernetExchanger.h` 的 `datagrams_`/`datagram_handlers_`。**雷区 3**:若 static-echo 读写 `datagrams_`,改为经 manager 提供的受锁访问器,保持 `static_echo_input_` + `switcher_->StaticMode()` 的读写时序不变(迁移前 grep `datagrams_`/`static_echo` 全量核对调用点)。

- [ ] **Step 4: 全量验证** — 服务器 `-fsyntax-only` 编 exchanger+manager 0 error;推 feat 触发 **CI 全平台**(Boost 1.86 完整编译 + 全 unit tests);include-boundary + vcxproj parity 门禁绿。

- [ ] **Step 5: 提交 + 开 PR** `refactor(client): wire ClientDatagramPortManager and drop exchanger session tables (P2-c)`

---

## 验证策略

- 每任务:tests/cpp 外科手术式单测(stub `UdpRelayHostPorts` 回调 + 假 port,隔离测 manager 纯逻辑)先 RED 后 GREEN;服务器 `-fsyntax-only`(内置 jsoncpp)快验编译期。
- Task 4 额外:ASan 多线程并发护栏(SendTo/Receive/Tick 交错),验雷区 2 无 UAF/无锁外 Dispose 重入死锁。
- Task 5:CI 全平台完整编译 + 全 unit tests(唯一能编 `VEthernetExchanger.cpp` 完整 TU 的途径),门禁绿方可开 PR。
- 行为对等基线:P2-c 全程不改数据面语义,任一单测若需改断言即说明动了行为——停下复查。

## Self-Review(已过)

- **Spec 覆盖**:设计文档 §3.3 的五方法迁移(SendTo/OnSendTo/ReceiveFromDestination/AddNewDatagramPort/GetDatagramPort)+ Update GC 段 → Task 2/3/4 全覆盖;§4 三雷区 → Task 3(雷区1)/Task 4(雷区2)/Task 5(雷区3)各有护栏。
- **独立锁**:manager 自持 `syncobj_`(Task 1),贯穿全程,兑现"UDP 会话表脱离 exchanger 共享锁"。
- **类型一致**:`Ptr=std::shared_ptr<VEthernetDatagramPort>` 全任务统一;`create_port`/`get_transmission` 签名在 Task 1 定义、Task 2/5 消费一致。
- **协程边界**:全程明确协程/传输留在 `VEthernetDatagramPort`(P2-d),P2-c 只迁会话表管理——与代码现状(OnSendTo 不使用 YieldContext)吻合。
- **YAGNI**:不提前做 P2-d(port 断双向引用)/服务端对称(P2-e);本计划止于客户端 UDP 会话表抽取。
