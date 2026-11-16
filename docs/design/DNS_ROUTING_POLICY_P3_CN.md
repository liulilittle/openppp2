# P3：DNS 与 Fake-IP 实施约束

> Status: Implemented; offline acceptance complete, Linux live acceptance partial; v2.1.7 pending
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

当前状态：P3 已实现并完成记录中的离线验收。代码推送已获授权，v2.1.7 仍待推送和 CI 全绿；
HTTPS 等 Linux 实机项未通过，Windows/macOS/Android/iOS 未验收。
本文件细化 [总方案](DNS_ROUTING_POLICY_REFACTOR_CN.md) 的 P3；不得将设计项标为已验证。

## 1. 边界与调用链

生产入口为 DnsInterceptor、PolicyResolverService，以及使用 FakeIpPool 查询身份的
TUN TCP/UDP、本地代理。P2 的 PolicyEvaluator::PlanDns 仍决定 resolver 与实际出口。
不得改变 default reject、同出口备用、AAAA 空成功和真实端点解析语义。
旧配置继续使用现有缓存和 Fake-IP 行为。新版服务不访问 vdns 全局业务缓存。
不重复实现 P2 已有 TCP 等待及 UDP 32 包/64 KiB 队列；检查失败和超时释放即可。
GitNexus 当前索引未验证有效，实施前使用 rg、调用点和聚焦测试评估影响。

## 2. 配置与能力

dns.mode 接受 auto、real、fake-ip。auto 在 TUN 使用 Fake-IP，本地代理使用真实地址。
仅拦截 TUN UDP/53 的 A 查询合成 Fake-IP；代理连接的真实解析不能进入合成路径。
增加 dns.fake-ip 对象：range 默认 198.18.0.0/16，storage 为持久化目录，identity 为
显式稳定配置标识。路径相对配置文件解析；启用 Fake-IP 时缺失稳定存储必须拒绝启动。
身份不能包含节点凭据。可用配置绝对路径的 SHA256 作默认身份，移动配置需明确迁移说明。
池不得重叠 P2 内部 UDP relay 198.19.0.0/16 或实际 TUN 源地址。
prepare 在 TAP 初始化前验证池、目录和恢复结果；准备失败不得修改网络状态。
平台不能提供持久目录时报告能力限制，不退回临时内存池。

上游 hostname 的 endpoint/bootstrap 细化为结构化 server 条目：uri、addresses、bootstrap。
保留现有 string server。addresses 为 IPv4 字面量，TLS 仍校验原 hostname；bootstrap
是数值 IPv4 UDP resolver URI 数组（udp://192.0.2.53:53），固定 direct 并使用 protect。
两个数组均可缺省，hostname URI 至少需要非空 addresses 或 bootstrap；数值 URI不用它们。
优先 addresses；没有 addresses 时，异步对原 hostname 发 A 查询到显式 bootstrap 数值
resolver，得到服务器地址后执行原来的出口计划，不经过业务 evaluator/Fake-IP/系统 DNS。
bootstrap 与实际查询共享5秒总时限、取消和代际检查，单次1秒，同类bootstrap按声明顺序。
bootstrap 只能数值 endpoint，不接受 hostname、provider或resolver引用，从结构上避免环。
两者都没有的自定义 hostname 明确诊断，不能静默调用系统 DNS。
ServerEntry.bootstrap_ips 表示得到的服务器 IP，不能把 bootstrap resolver 本身 IP
错误填入该字段，否则会把业务DNS请求发送给bootstrap而非原上游。

## 3. 独立缓存

键包含标准化小写域名、QTYPE/QCLASS、resolver 完整配置指纹、有序备用列表、实际出口、
ECS 和 RD/CD/DO 等影响应答的标志。事务 ID 不进入键；复杂/不支持 EDNS 可以绕过缓存。
不同 resolver/出口不能共用；不同策略版本仅键中语义完全相同时可命中。
解析并验证 response ID、question、QR、RCODE、记录边界后才写入。
正缓存取所有相关 answer/CNAME TTL 最小值，TTL=0 不缓存；返回时扣除已经过秒数。
负缓存仅 NXDOMAIN 或 NODATA 且有可验证 SOA，取 SOA TTL/MINIMUM 最小值，上限 300 秒。
SERVFAIL/REFUSED、截断及非法应答不缓存。上限 4096 项和 16 MiB，可淘汰缓存，不能淘汰身份。
时钟使用 monotonic，可注入测试时钟；不得靠真实 sleep 检验 TTL。
命中时重写事务 ID并保持合法 question；大小写不一致应正确返回或安全绕过。

## 4. 合并、取消与生命周期

同键只发起一份上游查询；每等待者保留原始 query、session、snapshot 和取消状态。
公开可取消 request handle，旧 Resolve 调用可忽略返回值，不能靠 handle 析构取消兼容调用。
单等待者取消不影响其他等待者；最后等待者取消关闭子 transport 和计时器。
关闭服务原子禁止新查询，所有存量等待者至多完成一次；回调不在持锁区域执行。
session 失效后的结果不能发送或写入缓存。策略快照已 pin 的有效旧流允许旧语义完成，
但结果只能进入匹配的完整语义 namespace，不能进入新配置的缓存空间。
补齐 direct resolver / tunnel stream cancellation，覆盖连接建立和握手中取消；
晚到回调不能重新打开 socket、发送数据或再次完成用户回调。
pending keys 上限 1024，每 key 等待者上限 256，总包内存有上限，超限 SERVFAIL。

TUN 合成入口必须支持常见合法 EDNS OPT 查询（含 DO/UDP size），不能因有 additional
记录就把 auto/fake-ip A 查询默默改为真实应答。v2 合成用结构化 decode/encode，
正确重建 question，保留适用 CD/OPT，AD=0；不能复制可能引用被丢弃区段的压缩指针。
不支持的复杂 EDNS、畸形或多问题请求不得分配身份或回退真实解析，明确受限错误应答。
旧配置的合成器保持独立，不能用本阶段顺便改变 legacy DNS 报文语义。

## 5. 持久身份与崩溃恢复

新版身份只存 domain <-> IPv4，不保存 action/real endpoint；新连接重新用当前 snapshot 决策。
复用 legacy FakeIpPool 的 lookup 接口时，也不能读取旧 sticky action 作为新版决策。
采用独立 versioned snapshot + append journal；包含 schema、配置 identity、CIDR、序号和校验。
恢复验证 schema、identity、pool、域名唯一、地址唯一及边界；完整记录校验失败拒绝启动。
允许忽略仅末尾未完成记录，但必须保证该记录从未被应答；校验完整却无效的记录不能忽略。
文件写入、flush/fsync(Windows FlushFileBuffers) 成功之后才公开分配结果和发 DNS 应答。
目录及原子 rename 的持久化要求按平台实现；写失败 SERVFAIL，已保留地址不能复用给其他域名。
第一版允许同步逐条 durable 写入，批处理只能 <=10ms，禁止网络 IO strand 长时间磁盘阻塞。
独占文件锁避免两个进程同时分配相同池；锁冲突拒绝启动，不删除别人的锁/数据。
池耗尽 SERVFAIL；未分配但落在池内的地址不能作为真实端点发送。
池改变/identity 改变/清空映射只能重启并提示清理客户端 DNS 缓存，不提供在线 clear。
持久化文件是本地运行资料，不导出节点秘密，不提交实际映射。

## 6. 离线验收

实现测试必须调用生产服务，注入 exchange/clock/storage 故障，不启动 PPP 或联网。
覆盖缓存命中与 TTL 递减、TTL=0、SOA 负缓存、不同出口/resolver/ECS/flags 隔离、
相同语义跨版本共享、不同语义不共享、畸形响应不缓存、每等待者事务 ID、独立取消、
关闭与晚到回调、容量限制及可重入回调。
Fake-IP 覆盖首次写盘先于应答、重启恢复不换身份、规则更新重新决策、池耗尽、
write/fsync/rename/磁盘满注入、文件锁冲突、完整损坏拒绝、尾部 torn write、pool 变更拒绝。
验证 DNS 合成与真实解析不同路径；TCP/UDP 不把未知 Fake-IP 发往网络。
新增源文件加入 CMake 和 vcxproj/filter。运行 P0/P1/P2 回归、布局检查、native Linux
编译以及适用 sanitizer。平台构建缺失和真实 VPN 出口未验证必须单独记录。

## 7. 完成记录

2026-10-07：DNS 服务与持久化 Fake-IP 的实现和离线专项验收已完成。
`PolicyResolverService` 提供按 resolver/出口/ECS/查询语义隔离的缓存、TTL 与 SOA
负缓存、解析合并及独立取消；上游 hostname 使用显式 bootstrap。Fake-IP 合成
覆盖 EDNS、保留 CD 并清除 AD。`DurableFakeIpStore` 提供独占锁、校验日志、
尾部未完成写入恢复和压缩恢复；后台有界写盘在 durable 成功之后才完成应答。
DNS/TCP/UDP 决策接入会话聚合计数，状态读取不包含目标域名。

持久化 store 的 17 个案例通过 GCC TSan；store、异步分配、DNS 传输与应答的
聚焦 ASan/UBSan 检查通过。故障测试使用注入存储与可控回调，不能代替真实断电、
磁盘满、设备恢复或 DNS 实际出口测试。Windows 的文件刷新与原子替换已有路径，
但目录持久化没有 POSIX fsync 等价保证，且未在 Windows 工具链或设备上验证。

完整构建与阶段联合验收结果见 [P5 完成记录](DNS_ROUTING_POLICY_P5_CN.md#5-完成记录)。
未启动 PPP、改变系统路由/DNS、安装驱动或提交 Git。
