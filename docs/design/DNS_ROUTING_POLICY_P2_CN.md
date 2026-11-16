# DNS 与分流策略 P2：执行路径接入

> Status: Implemented; offline acceptance complete, Linux live acceptance partial; v2.1.7 pending
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

当前状态：P2–P5 离线验收已完成，Linux 实机仍有 HTTPS/proxy TCP 等未通过项，跨平台尚未验收。
代码推送已获授权，v2.1.7 仍待推送和 CI 全绿；下文“留待 P3”“仍未交付”是 P2 当时记录。

本文记录 [重构方案](DNS_ROUTING_POLICY_REFACTOR_CN.md) 的 P2 实施。
P1 的加载器与离线语义见 [P1 记录](DNS_ROUTING_POLICY_P1_CN.md)。
本文保留 P2 当时的验证范围；后续缓存/Fake-IP/bootstrap 与更新/迁移的完成状态见
[P3](DNS_ROUTING_POLICY_P3_CN.md)、[P4](DNS_ROUTING_POLICY_P4_CN.md)、
[P5 联合验收](DNS_ROUTING_POLICY_P5_CN.md#5-完成记录)。

## 实施范围

仅显式 `client.policy.version=2` 进入新版执行路径。旧配置保留兼容入口。
主配置文件记录资源基准路径，候选策略在打开 TAP 和进入网络初始化之前准备。
策略来源或编译失败不能继续使用旧字段代替新版策略。

`PolicyRuntime` 独立于 DNS 持有不可变快照，准备与发布分开。失败候选、过期候选、
其他运行时的候选，以及被替换快照的候选均不能覆盖当前版本。查询读取完整快照；
正在建立的连接保留所用版本，完成决策后释放规则索引。

HTTP/SOCKS 与 TUN TCP 使用同一 evaluator。HTTP/SOCKS 原始域名、Fake-IP 身份
和可选嗅探域名分别保留，解析地址不覆盖域名证据。强制 direct 失败不回退代理，
强制 proxy 不进入旧 bypass，reject 在连接或数据报发送之前拒绝。
HTTP/SOCKS TCP 即使命中 proxy 域名规则，也先通过策略 DNS 取得真实地址；MUX 与
隧道 CONNECT 使用该数值地址，原目标域名和 HTTP/TLS 内容保留，不交给旧服务端 DNS
代替客户端的 resolver/via 计划。
IPv6 和非法 IP 在已匹配域名时仍拒绝。
可通过 `client.policy.tcp-domain-sniff: true` 显式开启 TUN TCP 嗅探，默认关闭；
iOS 仍不支持此路径。

SOCKS UDP 的 DOMAIN 目标传递域名身份、快照和动作。共享 UDP direct 出口具有
独立缓冲区与 socket/provider 生命周期，不要求隧道 transmission 分配缓冲区。
每流队列最多 32 包、64 KiB；接收端点校验、空闲超时和关闭取消归流对象管理。
不同域名不能因为解析到相同 IP 而共用策略身份。
实机补充约束（2026-10-07）：内存池是可选配置，SOCKS UDP ASSOCIATE 必须在未配置
pool 时使用已有 Copy/Spawn 系统分配回退。不能把空 allocator 当作运行环境损坏；
context、缓存 buffer 与 socket 的实际缺失仍须拒绝，缓存分配失败不能误报为策略拒绝。
SOCKS 的 IPv4 loopback UDP 监听须保持 IPv4 socket/端点族，不得借通用 invalid-address
处理变成 IPv6-any 后把 mapped IPv6 source 送入 IPv4 流管理器。此约束只针对本地 relay
绑定，不放宽新版 IPv6 目标限制，也不改变通用 socket 的现有地址检查。
已有 UDP 流固定实际端点与出口，空闲释放后新流才采用更新版本。隧道数据报每流
使用独立、会话内不复用的内部 source 身份，校验回复来源后恢复原始目标。
内部身份使用 `198.19.0.0/16`，只存在于已有 SENDTO 元数据，不安装系统地址或路由；
新版客户端虚拟源地址与该保留范围冲突时必须明确拒绝。

## DNS 出口

`PolicyResolverService` 在同一捕获快照内选 resolver 与 via。备用上游只能来自
该 resolver 的同一出口，拒绝规则返回 REFUSED，失败返回 SERVFAIL，AAAA 返回
受限制的应答。会话关闭后的回调唤醒本地等待者但不向客户端发送应答。
新版解析不读写旧的按域名共享全局缓存；独立缓存及合并留待 P3。
P2 的 `dns.mode: auto` 暂时返回真实地址；默认 Fake-IP 要等 P3 完成持久化身份后启用。
`default reject` 同时会拒绝未命中的 DNS。需要先解析域名再按 IP 放行的策略，应
配置显式 DNS 例外组允许相应查询；等待解析不会越过 DNS 自身的拒绝决策。

UDP proxy 使用隧道数据报通道和查询/回复关联。TCP proxy 复用既有 CONNECT
协议，将解析器的 socket 字节传输连接到隧道桥；DoT/DoH 保留原 hostname、SNI
及证书校验。适配器只在 loopback 接受精确匹配的内部对端，并有单次完成与超时关闭。
direct 使用平台显式 socket 保护或绑定；缺失保护能力时拒绝发送。

节点控制连接的 bootstrap 保持独立。自定义上游 hostname 没有可用 bootstrap
地址时不会隐式调用系统 DNS；内置 provider 使用自己的预配置地址。
当前 resolver schema 没有自定义 bootstrap 字段，因此自定义 hostname URI 会失败或
尝试同出口下一上游；可以使用数字 endpoint URI 或内置 provider。

## 平台能力

以下是已接入源码路径的能力，不代表对应平台的运行验证：

| 路径 | IPv4 TCP direct | IPv4 UDP direct | DNS direct |
|---|---|---|---|
| Linux/Windows/macOS TUN | 受保护 socket | 共享受保护出口 | 绑定底层接口 |
| Android TUN | 受保护 socket | 共享受保护出口 | Android 保护回调 |
| iOS TUN | 拒绝 | 需要已安装的 Packet Tunnel datagram provider | 普通 socket 路径拒绝 |
| HTTP 本地代理 | iOS 以外支持 | 无 UDP 入口 | 无 TUN 时使用 OS socket |
| SOCKS 本地代理 | iOS 以外支持 | 共享出口；iOS 需要 provider | 无 TUN 时使用 OS socket |

共享 native 流和 iOS provider 均限制收发在途包数与字节数；Swift 层额度在异步
写入完成后释放，关闭后的读写回调按 session 实例隔离。该 Swift 修改未在本机编译。

隧道 DNS 支持 UDP、TCP、DoT、DoH 的出口适配，不宣称应用 TCP/加密 DNS 流量被
通用拦截。iOS 的能力限制通过 CLI 诊断和实际执行拒绝表达。
DNS 字节流适配器 30 秒只保证查询完成期限；尚在建立的底层 child transmission
释放依赖已有连接/握手超时，不能宣称该阶段立即取消全部底层资源。

## 验证与边界

本批只允许隔离构建与离线测试。未启动 PPP、改变系统路由/DNS、安装驱动或提交 Git。
2026-10-05：真实 Linux 内核的 249 个生产 C++ 源文件在隔离目录完成 Clang 19
编译与链接，产物位于 `build/private/dns-policy-p2-native-audit/bin/ppp`，未执行该产物。
34 个聚焦 CTest 目标通过，包括 P0/P1、八个新增 P2 目标和旧 DNS/UDP/启动回归。
测试值使用 `.test` 域名和文档地址，不自动生成正确结果。

ASan/UBSan 验证覆盖七个相关目标：先运行六个策略/解析/流目标，再增量运行
端口管理器与 UDP 流两个目标。未发现地址或未定义行为错误；LeakSanitizer 因
环境 ptrace 限制关闭，DNS 部分链接测试按已有方式关闭 `vptr` 检查。
测试中的网络入口为 mock 或遇调用即失败的 stub，不能推断真实 TLS、网络或协程路径通过。

include 边界、Visual Studio 源码清单和 XML 检查通过，249 个 C++ 源文件一致；
空白检查保留已有 SOCKS 文件 CRLF 格式。Swift 仅通过现有源码接线检查，缺少工具链；
Windows/macOS/Android/iOS 未编译或运行验证，TSan 和完整测试集未执行。

下面的辅助程序只有策略命令入口，不启动客户端。P2 共享 UDP 出口接入后，示例
Linux 和 Android `check` 均成功；iOS 条件能力仍由诊断明确表达。

```sh
cmake -S tests/cpp -B build/private/dns-policy-p2 -G Ninja
cmake --build build/private/dns-policy-p2 --parallel 3 --target policy_offline_cli
build/private/dns-policy-p2/policy_offline_cli policy check \
  --config tests/contracts/routing-policy/v2/example.json --runtime tun --platform linux --json
build/private/dns-policy-p2/policy_offline_cli policy explain \
  --config tests/contracts/routing-policy/v2/example.json --runtime tun --platform linux \
  --domain local.example.test --network tcp --port 443 --json
```

辅助程序拒绝普通客户端参数，返回 4。`check/explain` 始终是离线计划，报告中的
`runtime_installed: false` 表示命令没有安装运行时，不表示客户端执行路径仍未接入。

运行时接线和离线决策一致性不等于真实 VPN、DNS 出口或跨平台运行验收。
P3 的独立缓存、解析合并与持久化 Fake-IP，P4 的自动更新和 P5 的迁移已在后续阶段实现；
迁移仍可能产生 draft/exit5。P2 实机未通过项见 [Linux 实机报告](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)。
GitNexus 索引未更新，本批使用源码、调用链、差异及聚焦测试分析影响。

### Linux 实机 UDP 回复修复约束（2026-10-07）

Datagram handler 的端点契约为 `(client_relay, remote)`；SOCKS UDP 回复编码函数
接收 `(remote, client_relay)`，前者写入 SOCKS 回复头，后者作为实际发送目的地。
direct 与 tunnel 回复必须遵守同一契约。实机发现回调未交换这两个端点，导致
握手成功后回复发往远端。修复限定在 SOCKS 回调，保留 socket 地址族、保护器、
来源验证及分流行为；增加方向回归检查，并以真实数值地址和 DOMAIN 请求复测。
仅策略计数增加、握手 REP0 或无回复均不能作为 UDP 数据路径验收通过证据。
