# DNS 与分流 P0 现状基线

> Status: Historical baseline
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

基于 `99892a8cf1dda90f8da475fb044016e7ae33d195`，记录日期 2026-10-05。
对应[重构方案](DNS_ROUTING_POLICY_REFACTOR_CN.md)的 P0；本文记录旧行为，
不表示 `client.policy.version=2` 已实现。生产代码未因本批测试修改。

## 1. 证据边界

“离线调用”指测试直接调用生产解析器或纯决策函数，静态预期由源码和已有测试
逐项审查后手写。“源码检查”只证明当前调用结构或平台条件，不证明设备运行结果。
所有域名和 IP 样本为测试值；provider 名称仅查询内置目录，不发起 DNS 请求。

测试程序 `tests/cpp/routing_policy_baseline_test.cpp` 与静态合同
`tests/contracts/routing-policy/v1/cases.json`（schema `1`）是代码发布候选的一部分；目标版本为 v2.1.7，
仍待代码推送和 CI 全绿，不能标为已发布。
配置输出仅选择路由相关字段，并排除 Linux 专有的 `nic` 序列化字段；
不比较整个配置，不把环境默认值或机器路径固定成策略语义。
隔离链接复用配置测试的网络/coroutine/Executors stub；没有执行客户端启动、socket
解析、DNS 上游传输、路由安装或系统 DNS 接管。

## 2. 已冻结的优先级

| 范围 | 当前行为 | 证据 |
|---|---|---|
| 配置来源 | `client.routing` 是对象时为 canonical；嵌套 `ip/dns` 优先于短别名；空对象可覆盖旧路由 | 离线 `configuration_*` |
| 模式 | `client.proxy-only` 独立控制模式，nested `mode` 不控制它 | 离线 `configuration_nested_wins/aliases` |
| 配置投影 | canonical 普通/peer 路由镜像到旧成员，序列化不重复写旧键；无 canonical 时旧成员投影为 canonical JSON | 离线 `configuration_*`，包括 Normalize 和再加载 |
| 双入口 | 顶层 `routing.rules/tcp-domain-sniff` 与 `client.routing` 并存 | 离线 `configuration_nested_wins` |
| 来源分类 | 已存在路径是 file；缺失 `file://` 去掉 scheme 后仍为 inline；文本去首尾空白 | 离线 `source_*` |
| Human 域名 | 显式来源先于 Geo；同来源 Exact → Regexp → 最长 Suffix/Subdomain；等长 Subdomain 优先 | 离线 `human_priority/geo_explicit_precedence_and_skips`；既有规则测试 |
| Human IPv4 | 显式先于 Geo，同来源最长前缀 | 离线同上 |
| Human 状态 | 区分 invalid、有效 unmatched、matched；有效 unmatched 用 default，invalid 返回 auto | 离线 `human_priority` |
| 重复条件 | 同动作去重，异动作加载失败并给两处行号 | 离线 `human_dedup/conflict` |
| Geo | 声明需要 GeoIP/GeoSite 来源；IPv6 和 Plain 跳过；坏文本行单独计数 | 离线 `geo_*`；既有 Human/Geo 测试覆盖 dat 格式及失效处理 |
| 旧 DNS | slash 格式；full → regexp → suffix；输入大小写归一；非法行跳过，IP 字面量不匹配 | 离线 `legacy_dns_priority` |
| 旧 DNS 重复 | 相同 key 后续加载覆盖；bare IP/provider 可形成 wildcard | 离线 `legacy_dns_overwrite/bare_*` |
| 旧 DNS regex | 存储于 unordered_map，重叠正则不能承诺文件顺序 | 源码 `Rule::GetWithRegExp`；故意不固定重叠正则结果 |
| `Rule::Nic` | IP 条目表示 NIC/TUN；provider 条目表示 domestic/ECS，不能等同实际 DNS 出口 | 离线字段样本加 `Rule`、resolver 调用源码检查 |
| DNS 计划 | strict human 动作先于旧规则，strict AAAA 阻断；缺 provider/resolver 有 drop；gateway 不无条件越过规则；同目标 relay 可 defer | 离线 `plan_*` |
| Fake-IP | 显式开关决定启动模式；strict A 关闭时解析真实地址；开启但不合格、分配/响应失败时拒绝；sniff 不改变 DNS 决策 | 离线 `dns_*` |
| TCP 选择 | 未解析 Fake-IP 拒绝；不支持 direct 时强制 direct 拒绝；proxy 强制代理，auto 保留旧选择 | 离线 `tcp_*` |
| UDP 选择 | Android 支持强制 direct；其余 UnsupportedDirect 拒绝；auto 仅 Android legacy bypass 直连 | 离线 `udp_*`，模拟能力输入 |

## 3. 平台与入口能力

以下为源码检查，未执行平台构建或设备/真实 VPN 流量验证。

| 入口/平台 | 当前路径和限制 | 源码位置 |
|---|---|---|
| TUN TCP：桌面/Android | selector 支持 direct；具体 socket 建立仍可能失败，不能由选择结果推断连通 | `VEthernetNetworkTcpipStack.cpp`、`VEthernetNetworkTcpipConnection.cpp` |
| TUN TCP：iOS | accept 调用点将 `direct_supported=false`；域名 sniff 候选排除 iOS | `VEthernetNetworkTcpipStack.cpp` |
| TUN UDP：Android | 使用 Android selector 与 legacy bypass 状态，实际 socket 需保护和回复处理 | `VEthernetDatagramPort.cpp` |
| TUN UDP：其他平台 | 使用默认 UnsupportedDirect；不能宣称已实现跨平台 UDP direct | 同上 |
| HTTP/SOCKS TCP | 本地代理在解析 IP 后尝试旧 bypass，没有统一调用 Human 域名匹配 | `proxys/VEthernetLocalProxyConnection.cpp` |
| SOCKS UDP DOMAIN | 解析后只保留 endpoint，再调用无显式动作的 `SendTo` | `proxys/VEthernetSocksProxyConnection.cpp` |
| proxy-only DNS | `DnsInterceptor::Configure` 保存规则/Fake-IP 池但不创建 resolver | `dns/DnsInterceptor.cpp` |
| DNS 拦截 | 分派入口只针对 UDP/53；resolver 的 UDP/TCP/DoH/DoT 能力不等于通用 TCP/加密 DNS 拦截 | `ClientPacketDispatchHandler.cpp`、`DnsResolver.cpp` |
| DNS 缓存 | 旧全局业务缓存主要按域名，不是新版按出口、resolver 和策略隔离的缓存 | `ppp/net/asio/vdns.cpp`、`dns/DnsResponseHandler.cpp` |
| Geo bootstrap | 桌面与 Android 调用生成器；iOS 当前未调用，平台加载链不完全相同 | `ApplicationClientBootstrap.cpp`、`android/libopenppp2.cpp`、`ios/OpenPPP2PacketTunnelBridge.cpp` |

`ppp/app/client/` 是上表未写目录的文件前缀，`DnsResolver.cpp` 位于 `ppp/dns/`。
测试中的 Android/iOS 能力是纯函数输入模拟，并非编译了这些平台的接入代码。

## 4. 差分合同与复现

fixture 为 `{ "schema": 1, "cases": [{ "id", "kind", "input", "expected" }] }`；
report 为 `{ "schema": 1, "results": [{ "id", "output" }] }`。
案例 ID 必须非空且唯一，输入和输出是对象，比较器严格检查案例/字段缺失、额外项
与递归叶子变化，数组顺序有意义，报告案例顺序无意义。浮点数未用于本批样本。
整数按精确值比较，不区分 JsonCpp 的内部 signed/unsigned 存储；整数与浮点表示仍区分。

未来 evaluator 应独立实现并输出同一 report；不得复用旧优先级算法来证明新旧一致。
新增 v2 语义时记录有意差异，不能为使比较通过而自动替换 v1 静态预期。
`--dump` 输出实际报告，不修改 fixture；`--compare` 只读候选报告并对照静态预期。
任一差异或合同错误均返回非零退出码。`--self-test` 验证比较器自身会拒绝坏报告。
`invalid-duplicate.json` 与 `invalid-trailing.json` 是故意非法的读取器反例，
只供自测使用，不是行为样本或可用配置。

从仓库根目录执行：

```sh
cmake -S tests/cpp -B build/private/dns-policy-p0 -G Ninja
cmake --build build/private/dns-policy-p0 --parallel 2 --target \
  routing_policy_baseline_test human_routing_rules_test tcp_routing_selector_test \
  udp_routing_selector_test human_dns_query_policy_test dns_redirect_plan_test
ctest --test-dir build/private/dns-policy-p0 \
  -R 'routing_policy_baseline|human_routing_rules|tcp_routing_selector|udp_routing_selector|human_dns_query_policy|dns_redirect_plan' \
  --output-on-failure
build/private/dns-policy-p0/routing_policy_baseline_test --dump
build/private/dns-policy-p0/routing_policy_baseline_test --compare candidate-report.json
```

所需环境为 C++17、CMake/Ninja、Boost（含 regex/filesystem）、OpenSSL。
本批不验证 DNS 实际出口、完整 VPN、Windows/macOS/Android/iOS 运行、并发在线更新
或性能收益。GitNexus 索引落后 HEAD，当前影响范围依靠源码、调用点与聚焦测试确认。

## 5. 本批验证结果

2026-10-05，在 Linux 主机以 GCC 14.2.0、OpenSSL 3.5.6 完成以上隔离配置和构建：

- `routing_policy_baseline_test`：50 个静态案例全部通过。
- `routing_policy_baseline_harness_test`：变化、缺失/额外案例与字段、重复 ID、坏 schema、
  非对象输出、空报告、非法 JSON、整数表示、嵌套数组/类型变化自测通过。
- 既有 `human_routing_rules_test`、TCP/UDP selector、Human DNS policy、DNS redirect plan
  五个目标通过；本批合计 7/7 CTest 目标通过。
- CLI 导出的 JSON 可重新读取并用 `--compare` 通过；修改一个布尔叶子时返回 1 并给出
  对应 case/field 路径；未知选项返回用法错误。
- include 边界、相对文档链接、P0 文件空白/冲突标记检查和 `git diff --check` 通过。
- Visual Studio 源清单检查未通过：并行 P2P 改动有 7 个 `.cpp` 未登记，涉及
  `VirtualEthernetP2PV2`、`P2PIngressLimiter`、`P2PProbeCoordinator`、`P2PRelayOfferV2`、
  `P2PV2Channel`、`P2PV2ControlCodec`、`P2PV2DataCodec`；本批未修改这些文件或项目清单。

未运行完整独立测试集、sanitizer、完整内核或移动/Windows/macOS 构建。
所有验证均未启动 PPP、更改网络状态或提交 Git。以上结果完成 P0 的离线基础门槛，
不代替 P2/P3 的实际出口及平台运行验收。
