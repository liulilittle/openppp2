# UDP 数据面模块解耦（Phase 2）设计
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


- **日期**：2026-07-11
- **作者**：HyacinthHaru
- **前置**：Phase 0 基准闸门（`d60afe8`）、Phase 1 H4 加密加速（`035903f`/`66bb376`）、H1 分配器锁解耦（`3bd71d3`）均已落地。
- **本文范围**：UDP 数据面的模块解耦（原任务"各模块解耦、CPP 不职责紊乱"的另一半）。**这是多增量工程，逐 PR 推进。**

## 1. 问题

双端 `*EthernetExchanger` 是 God-Object（客户端 `VEthernetExchanger` 2184 行、服务端 `VirtualEthernetExchanger` 1959 行），一个类混了 ~13 个职责簇：连接状态机 + 传输创建 + **UDP relay** + ICMP + static-echo + MUX + FRP + 定时器 + 遥测 + 平台并发池。UDP relay（`SendTo`/`OnSendTo`/`ReceiveFromDestination`/`datagrams_` 会话表）与 mux/FRP/static-echo 逐行交织，是"CPP 职责紊乱"的核心。

另有 `checksum.cpp`（901 行）名不副实：校验和仅 ~14%，塞了 360 行 RIB/FIB 路由表 + File IO，任何 UDP 复用校验和都会拖入整块 L3/L4+File 依赖。

## 2. 目标范式（已在仓库验证有效）

照原作者 **DNS 线的成熟范式** `DnsUdpRelay` + `DnsHostPorts` + `IDnsHost`（`DnsUdpRelay.cpp` 里 7 处 `.callback()`、0 处 `owner_->`）：
- **`UdpRelayHostPorts`**（能力注入）：一组 `ppp::function<>` 回调（`datagram_output`/`get_tap`/`rewrite_fakeip`/`get_transmission`/`do_send_to`/`get_configuration`/`emplace_timeout`），消费方无需 include 庞大的 exchanger 头。
- **`ClientDatagramPortManager`**（自持会话表 + **独立锁**）：own `datagrams_`/`datagram_handlers_`，提供 `SendTo/Receive/TryHandle/Add/Get/Release/Tick(now)`。**独立锁 = 把 H1"去多余锁/拆锁"的精神延伸到 UDP 会话表**（当前 `datagrams_` 与 FRP/定时器共用一把 `syncobj_`，每个 UDP 包都过它）。
- **`IUdpRelayHost`**：exchanger/switcher 实现 `BuildUdpRelayHostPorts()`，与 `IDnsHost`/`IRouteBackend` 并列。

## 3. 增量步骤（逐 PR，各自可独立验证/提交）

1. **P2-a 拆 `checksum.cpp`**：RIB/FIB→`rib.cpp`、各 `*_hdr::Parse`→各自、eth→`eth.cpp`，只留校验和。缩小后续 UDP 重构的编译爆炸半径。（相对独立、不碰 God-Object，风险最低，宜先做。）
2. **P2-b `UdpRelayHostPorts` + `IUdpRelayHost` scaffold**：仅新增接口/端口结构，不改 exchanger 行为（照原作者 PR6a "add scaffold" 模式）。
3. **P2-c 抽 `ClientDatagramPortManager`**：自持 `datagrams_` + **独立锁**，把 `SendTo`(1656)/`OnSendTo`(1621)/`ReceiveFromDestination`(1627)/`AddNewDatagramPort`(1840)/`GetDatagramPort`(1893) 与 `Update()` 的 UDP GC 段(606-669)迁入。
4. **P2-d 迁移 `VEthernetDatagramPort`** 从"持 switcher_+exchanger_ 两个 shared_ptr"改为"持一个 `UdpRelayHostPorts`"，断双向 friend（**顺带减 shared_ptr 背引用**，与 H1 同精神）。
5. **P2-e 服务端对称**：`VirtualEthernetExchanger`/`VirtualEthernetDatagramPort` 照做，连带迁走后者寄生的 DNS 命名空间缓存。
6. **P2-f 收口**：撤 `friend` + 裸 `owner_`，移除对 exchanger 头的 include，兑现头解耦。

## 4. 正确性雷区（迁移时必须原样保住，来自源码审计）

1. **DatagramPort 双向 finalize 协议**：`exchanger.datagrams_ → port → exchanger_` 是引用环，靠 `Finalize/MarkFinalize/finalize_` 打破。抽取时保住三条路径：自注销 `Finalize→ReleaseDatagramPort`、finalize 的 UDP 关闭信令 `DoSendTo(...NULLPTR,0)`、`MarkFinalize` 防 GC 期重入。顺序错→UAF/漏口/双关。
2. **NAT 超时两阶段 GC**：`Update()` 用"锁内收集候选、锁外 Dispose"（避免持锁时 `Dispose→Finalize→ReleaseDatagramPort` 重入同锁）。新组件必须复刻这个两阶段结构，否则自死锁。
3. **static-echo 状态/方法劈裂竞态**：sockets 轮换与 `static_echo_input_` 由 exchanger 状态 + `switcher_->StaticMode()` 三方决定，回迁状态时须同步迁移读写时序。

## 5. 验证策略

- 每个增量用 **tests/cpp 外科手术式单测 + bench**（如 H1 的 ASan stress 护栏思路）验证正确性；主库完整编译靠 **CI**（GitHub Actions 编 Boost 1.86 完整 openppp2）。
- 迁移前后跑并发正确性护栏（UDP 会话表的 finalize/GC 无 UAF）。
- 每 PR 遵守 include-boundary + vcxproj parity 门禁。

## 6. 与已完成工作的衔接

- H1 已在 `BufferswapAllocator` 去掉多余锁层；P2-c/P2-d 把同精神用到 UDP 会话表（独立锁 + 减 shared_ptr 背引用），是"解耦即降延迟"的延续。
- 参照仓库既有 `DnsUdpRelay`/`DnsHostPorts`/`route::RouteHostPorts` 范式，与原作者的 Wave 系列一脉相承。
