# 仅代理模式接入虚拟子网与 P2P 直连

> Status: In progress；内核接线已整合，Linux 默认 / 显式 XTCP=ON 与 Windows Release 编译通过，Linux 离线测试 181/181 通过；桌面 GUI 与实机验收未完成，详见 `build/subnet/INTEGRATION_REPORT.md`
> Type: Design / Plan
> Last reviewed: 2026-10-18，内核 WIP 整合到 origin/main 205d588b；运行时、P2P、多端及 macOS 验收尚未进行，不以源码接线证明连接可用
> Last verified: 2026-10-18，文档元数据与静态接线检查；运行时验收尚未进行
> **Purpose:** 让桌面端仅代理模式（`--mode=proxy` / `client.proxy-only`）不创建网卡，也能接入虚拟子网、访问其他客户端并复用 P2P v2 直连。
> **Audience:** 客户端运行时、P2P、平台适配与桌面 GUI 维护者。
> **Parent index:** [Design Documents](../README.md)

## 背景（整合前的行为）

P2P v2 直连在网卡（TUN）模式下已经接通，桌面端仅代理模式却完全用不上，而且问题不只在 P2P：

- 桌面仅代理模式使用 `TapStub`，它显示为已打开，但丢弃全部输出。客户端没有虚拟 IP，也不会产生虚拟子网 IP 包。
- 服务端只在 IP 包层面转发虚拟子网（`VirtualEthernetExchanger::OnNat` → `ForwardNatPacketToDestination`）。本地代理发出的是"连接到某地址"（`OnConnect`），服务端会用宿主机套接字去连虚拟 IP，而宿主机没有虚拟子网路由。**仅代理模式现在连经服务器中转访问对端都不行。**
- P2P 通道承载的是虚拟子网 IP 包。
- P2P 需要物理网卡信息来绑定套接字、生成候选地址；仅代理模式从不解析物理网卡，所以 P2P 能力判定为 `unavailable`。
- Android 的「仅代理模式」使用 VPN 框架提供的网卡，不在本计划范围内；本计划只针对桌面端（Windows、macOS、Linux）。

## 需求（2026-10-12 与需求方确认）

1. 仅代理模式**永远不创建网卡**，接入虚拟子网完全依靠进程内协议栈。
2. 两个独立开关组合出三种用法：

   | 用法 | `--proxy-subnet` | `--proxy-internet` |
   |---|---|---|
   | 组网 + 代理（默认） | `yes` | `yes` |
   | 只组网 | `yes` | `no` |
   | 只代理（原行为） | `no` | `yes` |

3. 进程内协议栈只承载访问对端虚拟 IP 的流量；上网流量仍按原方式（服务端代连或策略直连）。
4. 对端可以主动连入，但只转发**显式列出**的端口到本机。
5. 虚拟 IP：指定了 `--tun-ip` 就按手动地址登记、不申请地址池；没有指定就申请地址池，并把分到的地址用在进程内协议栈上。
6. 不改变仅代理模式的系统影响：不改路由、不接管 DNS、不需要管理员。

## 设计

### 进程内网卡 `TapUserspace`

代替 `TapStub`，"宿主"是进程内 lwIP 协议栈，而不是操作系统：

| 写入网卡的包 | 去向 |
|---|---|
| 本机虚拟 IP 发出的（lwIP 产生） | 作为网卡输入送回客户端路径 → `Nat()` → P2P 直连或中转 |
| 发往本机虚拟 IP 的 UDP | 按目的端口交给已绑定的 SOCKS UDP 关联；未绑定端口丢弃 |
| 发往本机虚拟 IP 的 TCP SYN（无 ACK） | 只有目的端口在入站转发表中才交给 lwIP，否则丢弃 |
| 发往本机虚拟 IP 的其他包 | 交给 lwIP |
| 其他 | 丢弃 |

分类逻辑在 `ppp/tap/TapUserspaceRoute.h`，有单元测试（`tap_userspace_route_test`）。

### 出站 TCP

- `common/libtcpip/netstack_outbound`：lwIP 主动连接，提供 connect / send / ack / close，全部在 `netstack::Executor` 上执行；只有调用过 `tcp_abort` 才返回 `ERR_ABRT`。
- `ppp/app/client/proxys/UserspaceSubnetBridge`：本地代理套接字与 `netstack_outbound` 之间的双向转发。连接带超时（`tcp.connect.timeout`）。数据写入本地套接字后才 `tcp_recved`；lwIP 接收上一块后才发起下一次本地读取。
- `VEthernetLocalProxyConnection`：策略和传统两条路径中，子网目标都改走桥接，不会落到宿主机套接字（否则会经物理网卡的默认路由泄漏出去）。

### 出站 UDP

`VEthernetSocksProxyConnection` 把子网 UDP 交给 `TapUserspace::SendDatagram`，从本机虚拟 IP 发出，回包按端口交回 UDP 关联。单个数据报负载上限 1372 字节，不做 IP 分片。

### 入站 TCP（端口转发）

- `--proxy-forward=22,8080:3000`：本机虚拟 IP 的 22 端口转发到 `127.0.0.1:22`，8080 端口转发到 `127.0.0.1:3000`。
- 允许的 SYN 进入 lwIP，经现有的 `before_accept` → `VNetstack::LwIpBeginAccept` → `BeginAcceptClient` 流程生成连接对象。
- `VEthernetNetworkTcpipConnection::ConnectToPeer` 在进程内协议栈模式下，按转发表把连接桥接到回环目标（`ResolveSubnetForward`），没有映射的一律拒绝。
- 回环目标不绑定物理网卡（`Rinetd` 中的 `loopback` 豁免）。
- 注意：这份 lwIP 定义了 `NETSTACK`，匹配监听者时忽略端口，所以不能为每个端口单独建监听 pcb，只能复用全局 `before_accept` 钩子。

### 只组网

`--proxy-internet=no` 时，本地代理只接受虚拟子网目标（TCP 和 SOCKS UDP），其余返回 `ProxyInternetDisabled`。桌面 GUI 此时不设置系统代理。

### 虚拟 IP

- 指定 `--tun-ip`：`ManualIPv4` 生效，按手动地址登记。
- 未指定：在客户端配置了 `server.ipv4-pool` 时申请地址池；收到分配后，`OnInformation` 更新 `TapUserspace` 的地址，并通过 `lwip::netstack::set_address` 改写 lwIP 接口地址。

### 物理网卡（仅读取）

进程内协议栈模式会读取物理网卡信息（`underlying_ni_`），供 P2P 绑定套接字、生成 host 候选；不调用 `FixUnderlyingNgw`，不改任何路由，解析失败只会让 P2P 不可用。

## 实现状态

- [x] `TapUserspace`、路由分类与单元测试
- [x] `netstack_outbound` 与 `UserspaceSubnetBridge`（出站 TCP）
- [x] 出站 SOCKS UDP
- [x] 入站 TCP 端口转发（`--proxy-forward`）
- [x] `--proxy-internet` 只组网模式与 `ProxyInternetDisabled` 错误码
- [x] `--tun-ip` 手动登记 / 地址池分配应用到进程内协议栈
- [x] 删除早期方案中的"子网网卡"（仅代理模式下创建只承载虚拟子网的网卡）
- [ ] 桌面 GUI：本分支未整合对应控件及系统代理行为；需另行集成与验证
- [x] 文档：代理模式指南、命令行参考、客户端架构、错误码（中英文）
- [ ] 入站 UDP 转发
- [ ] 运行时统计上报当前子网模式，连接页显示
- [x] Linux 默认 / 显式 XTCP=ON 与 Windows Release x64 编译验证（2026-10-18）
- [ ] macOS 编译验证
- [ ] 实机验收（暂缓，见下方验证计划）

## 验证计划

离线：本次分支的编译与测试结果以 `build/subnet/INTEGRATION_REPORT.md` 为准。旧版本的 Windows、前端与 Rust 测试记录不作为本分支的验证证据；本次不测试未整合的 GUI。

实机（**暂缓**，先不测；恢复时需要授权，并需要服务端开启 `server.subnet` 与 P2P、另一台客户端在线）：

| 场景 | 预期 |
|---|---|
| 组网 + 代理 | 经本地代理访问对端虚拟 IP（TCP、SOCKS UDP）成功；上网正常；P2P 能达到 Direct，断开后回退中转 |
| 只组网 | 访问对端成功；访问互联网被拒绝；系统代理未被设置 |
| 只代理 | 与旧版行为一致 |
| 入站转发 | 对端连接已列出端口成功并到达本机服务；未列出端口被拒绝 |
| 虚拟 IP | 指定 `--tun-ip` 时按手动地址；未指定且配置地址池时使用分配地址 |
| 全程 | `route print` 与 DNS 设置不变，没有新增网卡 |

## 相关修复（同一轮排查发现）

- 仅代理模式下，策略直连 TCP 要求绑定物理网卡，导致直连全部失败：已修复。
- 仅代理模式下，规则集更新走直连时因找不到网卡而断开会话：已修复（`DirectPolicySocketOptions::unbound`）。
- 内置 DNS 提供商条目错误：`doh.pub` 的 DoH 地址、百度 / 114 / TUNA 不存在的 DoH 主机名。已修正，并在 `policy check` 中拒绝没有 DoH/DoT 端点的提供商；传统配置迁移时替换为 doh.pub / cloudflare。
