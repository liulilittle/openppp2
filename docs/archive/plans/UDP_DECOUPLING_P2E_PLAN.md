# UDP 数据面解耦 P2-e 实施计划(服务端)
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> 承接客户端 P2-c/P2-d(已合并),对服务端 `VirtualEthernetExchanger`(1959 行)+ `VirtualEthernetDatagramPort`
> 做对称解耦。**关键前置发现已固化在下方**,新 context 实施时先读此文件 + 客户端 `UdpRelayHost.h`/`ClientDatagramPortManager` 范式。

**Goal**:把服务端 UDP relay 会话表 `datagrams_` 从 God-Object exchanger 抽出,并断掉 datagram port 的 `exchanger_` 背引用。行为严格等价。

**分支**:`feat/udp-decouple-p2e`(基于合并后 origin/main `4b833cc`)。

---

## 关键前置发现(一手代码坐实,决定设计)

1. **服务端 `datagrams_` 完全无锁**(单 io_context 线程模型):`GetDatagramPort`(:1409)/`ReleaseDatagramPort`(:1414)/emplace(:925)/GC `UpdateAllObjects`(:1266)/Finalize `ReleaseAllObjects`(:278)**全部不加锁**。`syncobj_` 实际只保护 `preferred_tun_fd_`(:245/251)和 `mappings_` FRP(:1675);成员注释"Guards datagrams_"**过时不实**。→ **服务端 manager 无锁**(纯搬移,比客户端 P2-c 简单:无 ASan 护栏、无两阶段 GC 锁内外分离)。
2. **三表功能独立**:`datagrams_`(UDP relay 会话)/`timeouts_`(DNS 重定向定时器)/`mappings_`(FRP 端口映射)共享 `syncobj_` 但功能无关。抽 `datagrams_` 走 manager,`timeouts_`/`mappings_`/`preferred_tun_fd_` 留 exchanger(`syncobj_` 继续护后二者)。
3. **服务端 port 有自己的 UDP socket**(`socket_`,跨平台):Open/Loopback/SendTo 经 socket_ 自包含,不经 exchanger。exchanger_ 仅用于:构造 config、Finalize 的 `DoSendTo`+`ReleaseDatagramPort`、Open 的 `GetSwitcher()->GetInterfaceIP()`、Loopback 的 `NamespaceQuery(GetSwitcher())`+`DoSendTo`。**无 switcher_ 成员**(客户端 port 有两个,服务端只一个 exchanger_)。
4. **数据面入口**:`OnSendTo`(:300 override linklayer)→ SendToDestination(:907-945):`GetDatagramPort`→有则 `SendTo`/fin 则 MarkFinalize+Dispose;无则 `NewDatagramPort`+`datagrams_.emplace`(:925)+`datagram->Open()`(开 socket)+`SendTo`。
5. **static datagram ports 暂缓**:`static_echo_datagram_ports_`(独立锁 `static_echo_syncobj_`、`VirtualEthernetDatagramPortStatic`)是服务端特有的第二类 port,耦合低,留 P2-f/后续。

---

## P2-e-1:抽 ServerDatagramPortManager(≈P2-c,但无锁)

**新建** `ppp/app/server/udp/`:`ServerUdpRelayHost.h`(`ServerUdpRelayHostPorts` + `IServerUdpRelayHost` + `MakeServerUdpRelayHostPorts`)、`ServerDatagramPortManager.h/.cpp`。

**ServerDatagramPortManager**(对照 `ClientDatagramPortManager`,去掉锁):持 `datagrams_`(`VirtualEthernetDatagramPortTable`),方法 `AddNewDatagramPort`(建 port→emplace→`Open()`→失败 erase)、`GetDatagramPort`、`ReleaseDatagramPort`、`SendToDestination`(数据面 :907-945 逻辑)、`Tick`(=UpdateAllObjects datagrams_)、`Release`(=ReleaseAllObjects+clear)。

**ServerUdpRelayHostPorts 字段**(manager 需要的 exchanger 能力):`get_configuration`、`create_port`(=NewDatagramPort)、`is_disposed`、`get_transmission`。(注:数据面 SendTo 走 port 自己 socket,manager 不需 do_send_to;do_send_to 是 **port** 用的,P2-e-2 加。)

**exchanger 改造**:implements `IServerUdpRelayHost`;构造注入 `datagram_manager_`;`datagrams_` 成员移除;`GetDatagramPort`/`ReleaseDatagramPort`/`NewDatagramPort`/数据面转发 manager;Finalize(:278-279)`datagrams_` 段→`manager->Release()`;GC(:1266)`UpdateAllObjects(datagrams_)`→`manager->Tick()`。**保留** `timeouts_`/`mappings_`/`preferred_tun_fd_` + `syncobj_`。

**验证**:manager 单测(对照 `client_datagram_port_manager_test`,stub port)+ 服务器 `-fsyntax-only` exchanger + friend 类 + 门禁(vcxproj +2 .cpp、include-boundary)。

## P2-e-2:断 port 的 exchanger_ 背引用(≈P2-d)

**ServerUdpRelayHostPorts 扩展**(port 用):`do_send_to`(真实 DoSendTo 协程签名)、`release_port`、`get_interface_ip`(→`switcher->GetInterfaceIP()`,开 socket 用)、`namespace_query`(→`NamespaceQuery(switcher,...)`,DNS 缓存;或 port 保留静态方法 + ports 提供 switcher 取用)。

**port 改造**:构造持 `ServerUdpRelayHostPorts ports_` + 保留 `exchanger_` **仅作生命周期锚**(前向声明、不 deref;服务端 Finalize 亦异步 post,同 D1 论证);6 用点改 ports 回调;删 dead `GetExchanger()`;断 friend(`port.h:57` + `exchanger.h:80`);port.cpp 撤 exchanger/switcher 头 include。`NamespaceQuery` 静态方法(:168 带 exchanger* 参数)按需保留参数式或走 ports。

**验证**:服务器 syntax + 回调接线逐行等价审查(**坐实 `exchanger->GetConfiguration()` 与 port 取用一致**、`GetInterfaceIP`/`NamespaceQuery` 语义) + 提交。

---

## Global Constraints
- 提交:[[git-commit-standards]](HyacinthHaru/hyacinth@haru.ac、SSH 签名、无 co-author、标题一句正文≤2句)。
- 服务器验证:`cd /root/ppp-bench/openppp2 && g++ -std=c++17 -fsyntax-only -I. -Icommon/json/include -D__SIMD__ -DJEMALLOC -DFUNCTION <file>`(内置 jsoncpp)。
- 停在 push/CI 前。static 暂缓(P2-f)。
