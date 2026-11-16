# P5：旧适配、CLI 与发布实施约束

> Status: Implemented; migration remains draft; v2.1.7 release pending
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

当前状态：P5 的 CLI 与兼容适配已实现并完成记录中的离线验收；迁移仍可能为 draft/exit5。
代码推送已获授权，v2.1.7 仍待推送和 CI 全绿；Linux 实机限制见 [实机报告](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)。
依据 [总方案](DNS_ROUTING_POLICY_REFACTOR_CN.md)，首期范围为内核与 CLI，不扩展 GUI。

## 1. 旧配置适配

新增 LegacyPolicyAdapter，把旧入口解析集中为含兼容标记的中间模型：源顺序、来源类别、
匹配规则、默认 auto/native fallback、provider/NIC/ECS、AAAA/Fake-IP/fallback、平台
投影和普通/peer 路由。适配器接收配置及显式 CLI sources，不修改用户配置或生成线上文件。
生产旧 bootstrap 与 DNS/routing 加载通过此模型获取来源；不得只为 migrate 命令造
适配器而宣称运行时已统一。v2 不允许残留 legacy 冲突字段，旧配置继续保持原入口行为。
可采用兼容模型内保留原生 HumanRoutingRules/旧 DNS Rule 索引，而不能把语义直接
强行翻译成 v2 的 Direct/Proxy/Reject 丢失 Auto/NIC。保持独立 legacy evaluator 的
明确分支，集中兼容判断，避免各业务调用点重复读取旧字段。
canonical 对象（包括空对象）优先；嵌套 ip/dns 优先别名；proxy-only 独立；顶层
routing.rules 与 canonical 来源并存，CLI bypass/dns-rules 按原 bootstrap 优先级。
复用 ParseClientRoutingSource，缺失 file:// 保持 inline，并在迁移时给出差异警告。
Geo 使用 checked materialized sources，不启动 Geo 生成器去写用户文件；必要副作用
记录为 legacy 标记。实际旧连接仍可走现有平台路由投影，不能无授权改系统行为。
通过 P0 fixtures 比较新 adapter 的相同输出；旧 regex unordered 重叠的不可确定性
是明确差异，不能用排序掩盖。平台数据只按可验证能力声明。

## 2. CLI 分派与参数

所有 policy 子命令继续在 main 的普通初始化前 Dispatch，禁止启动监听/TAP/PPP。
ApplicationPolicyCommand 支持 init/check/explain/migrate/export/update/status，同一
诊断报告 schema，严格拒绝重复参数/未知参数/缺值。人类输出来自同一报告，不能所有
命令一律显示 Offline plan；update 明确只准备 durable 包，status 只读已有状态。
0 成功，2 配置/规则/参数错误，3 源或存储不可用，4 能力不支持，5 有未解决迁移差异。
保持现有 check/explain 参数兼容，target 仅 explain 有效。check/explain/export 默认
离线，禁止触发 remote fetch 或写缓存/Fake-IP目录；缓存可读取且必须验证完整性。
explain 无 IP 明确 needs_ip/provisional，不能调用真实 DNS，报告版本与规则/DNS出口。

init --out DIR --template proxy-all|direct-all|split-cn --runtime tun|http|socks：
生成 policy.json（client.policy 片段）与 routing.rules，仅写尚不存在目标。
tun 模板 auto/Fake-IP，包含相对 storage 与稳定 identity；http/socks 明确 real 模式。
split-cn 要求 --geoip/--geosite 明确已有本地路径或声明 URL；不内置下载站点。
输出不得伪造可运行节点配置。overwrite 默认拒绝，失败不能留下看似成功的部分文件。

export --config FILE --out FILE [--json]：输出仅有效 client.policy、物化规则/规则集
指纹和明确默认值，不输出整个 AppConfiguration::ToJson，不带节点/代理凭据。
相对资源路径保持可解释的 base，或导出为显式 bundle；不能输出移到别处就失效而不提示。
不导出运行时 Fake-IP 映射；拒绝 legacy export 的伪 v2 输出，先 migrate。

update --config FILE [--json]：显式授权获取声明来源，通过 P4 完整事务验证/persist。
CLI 无法向正在运行进程提交内存对象；应明确 prepared-for-next-start，不伪称 active。
独占 store 锁冲突报告源不可用，不抢锁；后台在线更新只由活动进程的 P4 service 发布。
离线测试必须注入 fetch，真实命令不在本次验收运行真实网络下载。
独立 update 可接受显式 --interface 指定 direct 底层出口，或 --proxy-endpoint 指定
loopback 数值地址的本地 SOCKS5 控制代理。它们只用于更新下载，不改变业务/系统代理。
direct hostname 来源还需要 --bootstrap 数值 IPv4 UDP resolver URI（或配置内
updates.bootstrap）；没有它不能隐式调用系统解析器。
SOCKS5 CONNECT 保留上游 hostname，TLS 仍在本命令内验证原主机；不将凭据写入参数、
报告或 URL。没有所需出口能力时返回4，不自动切换到另一出口，也不启动普通 PPP。
运行中自动 proxy 更新使用自身控制隧道；独立 CLI 与活动进程的内存发布能力有明确边界。

status --config FILE [--json]：只读状态，schema 包含 pid、进程启动身份、更新时间、
session generation、active version、bundle digest、更新状态/失败诊断和 prepared version。
状态文件 atomic replace，路径用配置 identity 隔离；不包含节点、DNS查询/域名映射和URL凭据。
校验 pid + 启动身份及 freshness（默认120秒，运行时至少每30秒刷新）；pid 复用、
身份不可验证、旧时间、未来异常时间、损坏文件均显示 offline/stale，不伪造在线。
Linux 可验证 /proc 启动 ticks，Windows creation time，Apple 可支持 pid identity 或
诚实显示 unverified/offline；不新增管理 HTTP 服务，也不发信号给进程。
运行时退出标记 offline；无法写状态需诊断但不改变业务策略。读状态不执行远程控制。

## 3. 迁移证据与输出

migrate --config OLD --out DIR [--bypass SOURCE] [--dns-rules SOURCE]
 [--runtime tun|http|socks] [--platform PLATFORM] [--json]：
用真实 AppConfiguration 加载和 LegacyPolicyAdapter，分析旧来源、产生 v2 草案和报告。
只写新目录、不覆盖输入或已有文件；原配置 hash 前后不变，失败整体回滚本次临时输出。
报告按 source/line 显示旧行为、新行为、差异原因、需要用户选择的调整及验证证据。
有 Auto/native、NIC/provider/ECS、gateway、跨出口 fallback、regex优先级、文件缺失inline、
Geo生成文件副作用、路由投影、旧fake/AAAA/IPv6差异时返回5并标 draft，不称无损。
确实等价的简单样本必须经旧 evaluator 与新 compiler/evaluator对照；默认全部判差异
不能代替迁移实现。不能只有几个探测 domain 就证明无限输入行为等价：只对受支持的
可证明规则子集给 equivalent，其余保守 draft。保留明确 real 模式可消除默认Fake-IP变化，
但不能因此忽略旧全局缓存/出口/IPv6的差别。输出不得复刻节点秘密。
导出的草案必须能够离线 check，若需占位资源则标 incomplete 并列出具体依赖。

### 3.1 等价声明的边界

报告分别给出 host-routing equivalence 与 whole-policy equivalence，不能把前者提升为
完整迁移成功。可证明 host 子集仅含显式 direct/proxy 默认动作、Exact/Suffix/Subdomain
和 IPv4 CIDR；拒绝 Auto、正则、Geo、旧 bypass/路由投影及未物化来源。证明需核对两侧
规则集合、来源层级和每种匹配类型优先级；同动作去重不影响决策。域名相交/包含关系和
CIDR 包含关系可形成有限决策分区，但只取若干 probe 地址不足以替代这个结构条件。
不满足证明条件时即使所有 probe 相同，也必须标 unverified/draft。

whole-policy 还需明确平台/runtime、IPv6、AAAA、DNS 上游与实际出口、缓存、Fake-IP、
ECS 等语义。旧 provider/Nic 信息不能证明出口；缺少运行时事实时给出具体阻碍和 exit5。
确实完整等价的可支持子集应列出完整前提，不能永久 unconditional complete=false。
初始化模板和迁移输出分别测试；成功生成可检查草案不等于证明等价。

实施审查确认旧缓存可关闭且启用时使用全局域名键，而v2当前始终启用语义隔离缓存。
因此仅关闭旧缓存、选择相同provider、明确runtime/platform仍不足以证明whole-policy。
本批实现应由这个已知差异阻断whole等价并给出诊断，继续输出已证明的host-routing结果。
不为满足成功样本而伪造缓存开关或把差异隐去；若未来提供完整等价模式，再增加对应
whole-success验收。迁移CLI的exit5在存在这个已知差异时是正确结果，不代表未执行迁移。

## 4. 验收与发布

生产 CLI 调用测试涵盖七命令、严格参数、JSON/human一致、exit2/3/4/5、无普通启动、
模板与split-cn来源、no-overwrite/部分写失败、policy-only导出秘密排除、status身份/
过期/损坏/未来时间、update prepared与active区别、迁移等价/差异、原文件不变。
Legacy adapter 跑 P0 手工样本；增加 canonical/alias/CLI混合、old regex/auto/NIC/ECS
和缺失file来源测试。旧回归不可只改期待值迎合新行为。验证P3身份、P4失败保留。
运行全部可用standalone C++ tests、include/source-layout、完整Linux kernel compile/link、
适用ASan/UBSan；TSan可用则做聚焦并发测试，不与ASan混用。
Windows/Android/iOS/macOS没有工具链时，记录未构建；源码检查不能标为平台验收通过。
不安装SDK/驱动，不启动PPP，不改路由DNS，不跑特权network E2E，不提交Git。
更新使用文档、格式示例、迁移说明、运行资料位置和平台能力矩阵，并按真实验收结果
回填总方案状态。不能把待验证VPN实际出口或恢复故障写成已验证。

### 4.1 离线性能与可观察性

提供独立离线 benchmark，使用固定种子生成小型/100000/1000000条测试域名与CIDR，
真实 loader/compiler/evaluator/runtime，输出JSON记录规模、种子、编译耗时、峰值RSS及
命中/未命中p50/p95/p99。规则分布、正则数量、采样次数必须出现在报告；正则增长用
独立小规模场景，避免百万级正则导致无界测量。更新期间用reader线程采样，保持候选
编译发布与读取并发；不能计入联网或系统路由操作。基准不加入普通CTest，也不设依赖
机器速度的通过阈值。结果存放build/private，报告区分Debug/Release及运行环境。
缓存场景只使用假transport和可控时钟，至少记录命中/未命中调用数和时延；不能把mock
微基准当成真实网络延迟。真实直连/bypass吞吐仍需授权运行会话，作为发布限制记录。
状态与既有遥测接口应报告已能获得的版本/来源/错误信息，尚无计数器的指标必须列出，
不得以状态文件存在就宣称所有动作/DNS/Fake-IP遥测已完成。

遥测实现按会话/服务所有权保存聚合计数，不使用全局跨配置累加，不保存目标域名。
至少提供DNS cache hit/miss/coalesced、timeout/upstream failure/cancel、Fake-IP映射数量/
耗尽/持久化错误/等待数量，以及策略direct/proxy/reject决策次数。明确计数单位：
DNS请求/上游尝试/策略决策不能混写为连接成功次数。read snapshot不触发I/O，计数器
采用已有锁或原子值；关闭读数安全。运行时状态sink从真实服务读数，CLI status读取
该聚合记录。增加值守恒与失败分支的离线测试，不把源码字段存在当作已接入。

## 5. 完成记录

实机审查补充约束（2026-10-07）：`export --out` 的父目录不存在时应创建所需目录；
仅跟踪本次创建的目录用于失败回滚，不删除既存目录或文件。输出继续遵守不覆盖与
完整事务原则；创建目录不能弱化输入文件/节点秘密排除检查。

2026-10-07：内核与 CLI 的 P0–P5 实现及 Linux 离线验收完成。
`check/explain/init/migrate/export/update/status` 七个命令在普通启动之前分派。
新建 TUN 模板默认持久化 Fake-IP，HTTP/SOCKS 模板保留原域名并使用 real DNS。
导出物化完整策略来源，仅输出策略内容，不导出节点秘密或实际 Fake-IP 映射。
更新区分准备包与运行时活动版本；自定义 `--store` 若不匹配配置派生目录，报告
`prepared_in_custom_store`，须经 export 后安装，不能宣称下次启动会自动读取它。

桌面、Android、iOS 旧来源入口已使用 `LegacyPolicyAdapter`，保持 canonical、CLI、
Geo 和路由的来源优先级。迁移分别报告 host-routing 与 whole-policy 证据；前者有
结构证明支持的子集，后者因缓存/实际 DNS 出口/IPv6 等差异继续产生 draft 和 exit5。
这不是无损迁移成功，也不能用有限 probes 代替规则集合证明。
使用指南见 [Policy CLI](../guides/POLICY_CLI_CN.md)。

### 5.1 验证结果

- 全部 standalone C++ 目标构建成功；最终 CTest 169/169 通过，使用隔离单元测试及
  loopback 模拟服务器，没有启动 PPP。新增启动刷新样本也通过聚焦 ASan/UBSan。
- Linux native 使用 Clang 19 完整编译链接成功，258 个生产 C++ 源文件与 Windows
  工程登记对齐。产物在 `build/private/dns-policy-p2-native-audit/bin/ppp`，未执行。
- 本轮 10 个 P3–P5 聚焦目标的 ASan/UBSan 通过，最新配置/CLI/更新变更再验六项。
  LeakSanitizer 因环境限制关闭，部分链接测试沿用 vptr 检查豁免，不能称全部 sanitizer
  类型均通过。持久化 Fake-IP store 的 17 个案例通过独立 GCC TSan；未全量跑 TSan。
- include 边界、vcxproj 源清单检查通过；tracked 新增行和本任务新增文件通过保留
  CRLF 的空白检查。GitNexus 索引未更新，采用源码、调用点、diff 与测试审查。

### 5.2 离线性能

可选基准入口 `benchmarks/policy/README.md` 与复现命令属于代码发布候选；目标版本为 v2.1.7，发布状态待 CI。
GNU 14 Release、固定种子下，小型/十万/百万规模和缓存报告保存在
`build/private/dns-policy-p5-benchmarks/`，不加入普通 CTest 或按机器速度设门槛。
百万规则编译 4108.9ms，峰值 RSS 1,193,705,472 bytes，域名命中 p99 4451ns，
并发编译发布期间 reader p99 4694ns。峰值包含生成数据、候选和 reader 测量，不能
视为单份活动索引常驻内存；这仍是大规模使用时需要关注的资源成本。
缓存基准使用假 transport，5000 个冷 miss 后分别立即 warm hit，容量 4096、
working set 1；hit p50 29984ns、miss p50 74448ns，不代表网络 DNS 时延。

### 5.3 剩余发布限制

Windows/macOS/Android/iOS 未在适用工具链构建或运行；移动端 host 语法尝试因缺少
SDK 头文件停止。Windows 文件/目录 durability 仍需平台验证。
真实 VPN TCP/UDP、DNS 实际出口、IPv6 阻断、路由/DNS 退出恢复、外网数据源更新、
设备故障恢复及 direct/bypass 吞吐均未验证。GUI 改造仍在本期范围之外。
截至 2026-10-07 本轮检查时，未改变系统网络状态、未安装驱动、未提交 Git；保留并行工作区改动。

### 5.4 后续 Linux 实机验证

2026-10-07 按用户授权复用现有节点配置完成临时实例测试，修复 export 父目录和
SOCKS UDP 三处运行问题。HTTP、UDP direct/proxy/DOMAIN、DNS TCP/DoH/DoT 上游、
Fake-IP 重启稳定性、在线版本更新及坏候选保留活动版本已有真实成功证据。
原安装与配置保留，主动恢复原服务，核对配置、DNS、路由与实际 HTTP 回复。
HTTPS/proxy TCP 等仍有未通过项，不能称完整发布验收通过。详细结果、恢复差异与
剩余测试范围见 [Linux 实机验证记录](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)。
