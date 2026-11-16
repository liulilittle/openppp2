# 本地改动与文档更新范围

> Status: Active
> Type: Reference
> Last verified: 2026-10-07
> Parent index: [开发文档](README_CN.md)

发行记录：[v2.1.7](https://github.com/Miaocchi/openppp2/releases/tag/v2.1.7) 已公开，
标签源码为 `85220d2`，含 DNS 策略、P2P v2、平台兼容及 FakeClock 修复。
发行源码和后续发布流程修复 `9c3fbe5` 的十项 CI 均已通过，包括四 Android ABI、签名 APK、
Windows x64/ARM64、macOS、Linux 变体与交叉架构、普通单测和 TSan。
发行包含 32 个安装包及校验、来源记录，共 35 个资产；摘要与 `SHA256SUMS.txt` 一致。
TSan 本地连续 50 次验证也通过（修复前第 9 次复现）。自动发布令牌曾收到 403，
本次经授权凭据完成公开，并补充已发布资产的重复执行核验。
CI 与发行成功不表示完整 VPN runtime 或全平台运行验收通过。

历史说明：2026-10-07 首轮文档整理时，远端 main 和文档站为 `99892a8`，当时的发布范围
仅含文档，P2P 提交尚未推送。之后用户授权代码推送及 CI 全绿后发布 v2.1.7，代码与测试
随后按上述提交公开。本清单中的起始清点数字仍描述 2026-10-07 的工作区快照，不代表当前差异。

## 1. 清点边界

2026-10-07 开始整理时：44 个已跟踪文件修改，91 个新增代码、测试、基准和 Markdown
文档文件。当时这些是尚未整理为 Git 提交的候选实现范围。其中新增生产文件 37 个、
测试与样本 42 个、基准 3 个、文档 9 个；这些是当时的候选范围，计数不代表当前 Git 差异，
本清单与后续文档更新不计入该起始数量。

另有 178,157 个未跟踪文件属于临时树、历史构建、artifacts、perf.data 或补丁残留。
保留这些文件，不删除、不移动、不发布，亦不把它们纳入代码清单或站点。
这些目录可能包含私有运行材料，不能仅依据名称判断可删除或公开。

## 2. 按功能划分

以下范围按实现职责划分，文件可能同时包含多个功能的变更。尤其是移动端接入与
UDP provider 文件，不能按整个文件盲目归入单一重构提交。

| 范围 | 已修改文件 | 新增模块或文件 | 应更新文档 |
|---|---|---|---|
| P0 行为基线 | tests/cpp/CMakeLists.txt | routing_policy_baseline_test.cpp、support/policy_baseline.h、tests/contracts/routing-policy/v1/ | 旧优先级、离线样本、平台证据与总方案 |
| P1 配置/解析/编译 | AppConfiguration.cpp/.h、GeoDataReader.cpp/.h、geo_data_reader_test.cpp | policy/PolicyModel.h、PolicySourceLoader.cpp/.h、PolicyCompiler.cpp/.h、PolicyEvaluator.h、v2 样本 | 配置参考、分组规则、DNS/规则集字段与错误定位 |
| P2 执行入口 | VEthernetNetworkSwitcher.cpp/.h、VEthernetNetworkTcpipConnection.cpp/.h、VEthernetNetworkTcpipStack.cpp、ClientPacketDispatchHandler.cpp、VEthernetExchanger.cpp/.h | policy/PolicyRuntime.cpp/.h、PolicyTcpFlow.h | TUN TCP/UDP、策略快照、流固定、IPv6 边界 |
| P2 本地代理/UDP | VEthernetLocalProxyConnection.cpp、VEthernetSocksProxyConnection.cpp、ClientDatagramPortManager.cpp/.h、UdpRelayHost.h、UdpRoutingSelector.cpp/.h | LocalProxyPolicyDestination.h、DirectDatagramFlow.h、UdpFlowPolicy.h | HTTP/SOCKS 原域名、保护出口、UDP 来源验证、回复端点方向 |
| P3 DNS/Fake-IP | DnsController.cpp/.h、DnsInterceptor.cpp/.h、DnsFakeIpResponse.cpp/.h、DnsSessionContext.h、IDnsPolicy.h、IDnsTunnelTransport.h、DnsResolver.cpp/.h、AssignedAddressManager.cpp | DurableFakeIpStore.cpp/.h、PolicyFakeIpAsync.cpp/.h、PolicyResolverService.cpp/.h、PolicyTunnelDnsStream.cpp/.h、PolicyTelemetry.h | DNS 架构、隔离缓存/合并、上游 transport、持久化与冲突保护 |
| P4 更新 | VEthernetNetworkSwitcher.cpp/.h | policy/DurablePolicyBundle.cpp/.h、PolicyUpdateFetcher.cpp/.h、PolicyUpdateService.cpp/.h、PolicyTunnelUpdateConnector.cpp/.h、PolicyStatusFile.cpp/.h | 自动更新、durable CURRENT/PREVIOUS、失败保留、状态租约与下载出口 |
| P5 CLI/兼容 | main.cpp、ApplicationClientBootstrap.cpp、android/libopenppp2.cpp、ios/OpenPPP2PacketTunnelBridge.cpp | ApplicationPolicyCommand.cpp/.h、policy/LegacyPolicyAdapter.cpp/.h、LegacyPolicyMigration.cpp/.h | 七个 policy 命令、旧来源优先级、迁移 draft、导出边界 |
| 移动端 provider | ios/App/OpenPPP2PacketTunnel/ProviderOwnedP2PDatagramTransport.swift | 无 | 每端点队列上限、串行化、晚到回调隔离；仅源码证据，无 iOS 构建运行验收 |
| 构建/诊断 | ppp.vcxproj、ppp.vcxproj.filters、tests/cpp/CMakeLists.txt、ErrorCodes.def | 测试链接 stub 与离线入口 | 新源码登记、独立测试构建、保留 CRLF、错误码说明 |
| 验证/性能 | client_datagram_port_manager_test.cpp、dns_fake_ip_response_test.cpp、geo_data_reader_test.cpp、support/dns_host_wiring_switcher_stub.cpp | policy_*、durable_fake_ip_store、local_proxy、udp_direct_flow 测试及 benchmarks/policy/ | 测试层级、Linux 实机矩阵、sanitizer 限制与离线性能 |

两个 P2P 父提交的补充范围：`ppp/p2p/` 的 v2 编解码、channel、offer、limiter、
coordinator 和 STUN；客户端/服务端 `VEthernetP2PV2.cpp`、INFO 注册与协调；
Noise/authenticated carrier；P2P v2 isolation/recovery 脚本及对应 C++/tooling 测试；
根 CMake、Android/测试 CI、Windows 登记。文档对应 protocol、state-machine、
v2-implementation-plan 和双语 TESTING。此范围与上表共享文件必须按差异分别核对。

上表未写完整前缀的客户端模块位于 `ppp/app/client/` 下相应目录，配置模块位于
`ppp/configurations/`，命令入口位于 `ppp/app/`，测试位于 `tests/cpp/`。

## 3. 文档实施分工

主代理先界定本清单和发布边界，Luna 根据源码与调用点修改以下互不重叠的范围：

1. 用户入口：中英文路由/DNS、纯代理指南；归一化 Policy CLI 指南到 `guides/`；
   用户示例采用测试域名和文档地址，旧入口保留兼容链接。
2. 参考手册：中英文配置与 CLI；记录 v2 字段、七个命令、迁移退出码和旧/新版选择。
3. 架构与运维：中英文 DNS 架构、平台能力和运维；区分源码接线、离线测试和实机证据。
4. 实施记录与导航：P0–P5 元数据和状态、Linux 实机报告、测试说明、首页与各级索引。
   将仍适用的旧说明保留在明确的 legacy 范围中，不把历史缺口当作当前事实。
5. P2P 提交记录：协议、状态机与实施方案，区分隔离测试、生产能力门禁和真实
   NAT/平台验收；DNS 实机结果不能推断 P2P 直连已经验收。

首轮文档阶段仅发布审核过的文档文件；之后代码与测试已按授权推送。平台兼容与 TSan
修复、发行源码 CI 验证及 v2.1.7 tag/release 已完成，参见本文顶部发行记录。
临时产物和真实配置不进入文档站发布范围。

## 4. 证据与限制

- 离线：169 项测试合计通过；9 项 socket 测试先受沙箱 EPERM 限制，放行后重跑通过。
  本地验证包括相关 ASan/UBSan 与 Linux native 编译链接；全套普通单测与 TSan、
  P2P 及生命周期 ASan/UBSan 已在发行源码 CI 中通过。
- 实机：HTTP/CONNECT80、SOCKS UDP direct/proxy/DOMAIN、四种 DNS 上游、Fake-IP
  重启稳定性、有效更新和坏候选保留已有真实成功证据。
- 未完成：HTTPS 与部分 proxy TCP 路径，非 DNS 的通用 TUN UDP、同出口上游故障注入、
  IPv6 全入口拒绝、流更新固定策略、长期故障恢复和实际吞吐的完整验收。
- 构建：Android 四 ABI、签名 APK、Debian 10、Windows x64/ARM64、macOS 和 Linux
  变体及交叉架构均通过发行源码 CI；iOS 模拟器单测与 Swift 类型检查通过。
  这些是构建与隔离测试证据，各平台设备上的完整 VPN runtime 验收仍未完成。
- 并发：TSan 锁序与 FakeClock lost wakeup 已修复；普通 target 通过，无 suppression 的 TSan
  连续 50 次通过，修复前第 9 次复现。最终同 SHA 全套 CI 待验证，尚不能宣称 CI 全绿。
- 原服务已经恢复，配置、系统 DNS、IPv4 路由和规则保持基线；IPv6 差异为动态
  RA expires 与重建 TAP 的本地地址变化。详细依据见
  [Linux 实机验证](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)。

GitNexus 索引未更新，采用源码、调用点、差异与聚焦测试核对范围。
本轮“整理”指清点、分类和文档同步，不删除他人文件或合并不相关代码。
