# P4：完整数据包更新实施约束

> Status: Implemented; offline acceptance complete, Linux live acceptance partial; v2.1.7 pending
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

当前状态：P4 已实现并完成记录中的离线验收。代码推送已获授权，v2.1.7 仍待推送和 CI 全绿。
Linux 实机已有受控更新成功与坏候选保留证据，完整平台及故障恢复验收仍未完成。
依据 [总方案](DNS_ROUTING_POLICY_REFACTOR_CN.md)，保持 P2/P3 执行语义。

## 1. 更新边界

PolicyRuntime 的 Prepare/Commit 是唯一内存发布入口。更新器不得直接修改 snapshot 或
逐项替换规则索引。只可更新规则文本和已声明 rule-set 的物化字节；resolver、Fake-IP
identity/storage/range、DNS mode、sniff、ipv6、监听/拓扑等不可在线改变。
每次候选比较不可变配置指纹，改变则报告需要重连，不提交。业务路径仅获取 snapshot。
Luna 可先实现独立模块；根 agent 验收 P3 后再集成共享入口，先读最新 API 和调用点。

## 2. 接口和所有权

新增 PolicyUpdateService（名称可按代码惯例调整）：持有 runtime、已声明配置、durable
store、fetch adapter 和更新状态。RunOnce/Start/Close 的操作串行，在后台 context 执行。
fetch 接口接收 source、出口、条件头、deadline、size limit、cancel，返回 status/body/
etag/last-modified/diagnostics；store 接口可注入磁盘失败。离线测试禁止实际 fetch。
下载线程不持 publication/traffic mutex。多次触发合并为最多一次后续更新，关闭取消全部。
每轮 pin 当前完整数据包，变更全部收齐后一次编译；无字节变化返回 unchanged，不增版本。
需要更新规则主文件时，从原声明路径读完整文件，不能依赖只读到一半的直接覆盖。
规则来源可保持本地路径；远程 rule-set 保留 source.url，不能伪装为本地来源失去出处。

## 3. Durable bundle

使用配置 identity 隔离的存储目录，单写者文件锁。bundle schema=1，记录完整配置指纹、
每源名称/format/tag/SHA256/长度/校验时间、条件头以及完整主规则和所有 rule-set 字节。
内容文件用 digest 命名且不可覆盖；manifest 不包含连接凭据。URL 日志和状态只保留
scheme/host/脱敏路径或指纹，隐藏 username/password/query/fragment。
恢复严格检查 manifest/schema/引用/hash/大小/格式/必需 tag，并重新编译，不信任旧索引。
已配置固定 sha256 必须始终验证，更新不自动改用户 pin；新版本不匹配即失败保留旧版。
至少保留 current 和 previous 两份完整可恢复包，不能先删旧版以腾空间再试写新版。
所有文件 durable 写入后，提交候选 manifest，随后原子切换 durable CURRENT 指针，再
调用 runtime Commit。更新器必须独占此运行时的更新提交，Prepare 的 stale/foreign
校验保留；预期 Commit 失败时恢复指针并记录错误，不能宣称在线版本更新成功。
启动恢复读取 CURRENT，失败可回退上一完整版本并显式诊断；不能复用损坏来源的零字节。
crash 在指针切换之后、内存发布之前：下次启动使用完整新包。进程存活时 status 以内存
已提交版本为准，磁盘准备版本另外显示。这个边界必须有测试，不宣称双介质同时原子。
磁盘满、fsync/rename 失败、标签消失、非法 regex、任一必要源缺失均不改变运行时。

### 3.1 指针事务和失败边界

发布前保留原 current/previous 指针状态；runtime Commit 拒绝时恢复该状态，不能用
再次 Commit(old_bundle) 代替回滚并把失败候选留下为 previous。首次发布失败需能恢复
无 current 的原状态。优先把 current/previous 合并为一个原子指针记录，避免两个文件
替换之间的崩溃窗口；采用独立指针文件时必须记录可恢复的完整事务状态。
rename 成功后目录 fsync 失败意味着持久状态不确定，不等于指针没有改变。此时保持
旧内存策略、尝试恢复原指针并报告结果；回滚失败必须显式报告，不宣称旧磁盘版保持。
恢复 previous 应保留至少一个已验证的完整备用包，不能静默把损坏 current 当成备用。
测试分别覆盖 persist 返回失败、发布拒绝、首包拒绝和替换后 flush 失败。

## 4. 来源和网络约束

正常解析入口继续默认离线；新增显式 load-declarations/load-materialized 模式以接收
已验证的缓存字节，禁止将 E_POLICY_SOURCE_UNAVAILABLE 简单抹去而忽略其他诊断。
每源 body <=64 MiB，aggregate <=256 MiB，30 秒总请求时限，包括握手和重定向。
默认 HTTPS 证书/hostname 校验；不允许 HTTPS -> HTTP downgrade、file URL 或用户信息。
优先 HTTPS，明文 HTTP 需显式配置允许，并有明确诊断，不靠静默降级。
重定向最多 5 次，同样遵守出口、size/deadline、credential stripping 与证书检查。
304 只在有已验证相同 URL/来源缓存时接受；无缓存的 304 为失败。
etag 和 last-modified 控制条件请求，但最终是否更新以完整 bytes digest 为准。
via direct 使用 protected socket；via proxy 必须走控制隧道连接，不能靠系统路由猜出口。
独立 CLI 可使用显式绑定底层 interface 的 direct connector，或显式 loopback SOCKS5
控制代理 connector；没有相应能力必须失败，不能隐式直连或初始化普通客户端。
下载 hostname 的 direct bootstrap 单独配置为 updates.bootstrap 数值 IPv4 UDP resolver
URI 数组；独立命令可显式提供 --bootstrap。它不经过业务规则和 Fake-IP，使用同一
protected 底层出口及30秒请求总时限。缺少 bootstrap 时只可下载数值host来源，
hostname 明确不可用。proxy SOCKS5 connector 保留 hostname 由控制代理解析；运行时
隧道 connector 使用明确控制 bootstrap，不能让规则下载依赖尚未完成的业务策略。
可复用 P3 transport 的真实取消/握手保护。现有 HttpClient 接口不能表达所需条件头/流式
限额/出口时不能直接调用后宣称已满足；需完整 adapter，mock 只验证事务不证明线上出口。
下载服务禁止访问生产配置的真实节点，测试使用假 fetch 和保留测试地址。

## 5. 首次启动与调度

有完整缓存：TAP 前恢复/编译/验证；业务允许启动，后台按配置间隔更新。
无缓存的远程规则：配置声明、DNS/Fake-IP、能力先检查；在业务 gate 关闭状态建立必要
控制连接，拉取/编译/persist/commit 后才开放业务。若控制连接依赖未完成策略，使用
独立明确节点 bootstrap，不能向空业务策略透传。失败终止连接事务并执行正常回滚。
desktop、Android、iOS bootstrap 必须接同一生命周期接口；平台不能支持时明确拒绝，
不得让 remote-only source 绕过 P2 pre-TAP prepare 检查后带空 snapshot 运行。
业务 gate 覆盖 TUN/HTTP/SOCKS 的 TCP、UDP、DNS，不只 UI 的 connected 标志。
CLI update 在 P5 暴露，P4 先提供真正可调用的独立准备包 API；不启动 PPP 去测试此 API。
调度 interval 默认 24h，失败指数退避 1min 至1h；注入时钟/定时器验证。时间换算需
checked arithmetic，防止 duration 溢出。服务关闭后计时器不得再启动下载。
当前 TCP 连接和活跃 UDP 流继续 pin 原决策，只有新流看到新版本。

## 6. 离线验收

注入 fake fetch/storage/clock，真实 compiler/runtime，覆盖全成功、304/相同 bytes 不编译、
任一失败全轮不提交、tag 丢失、regex 坏、SHA 错、64MiB 上限、aggregate 上限、
半写/fsync/rename/磁盘满、恢复 current/previous、crash 边界、配置变化要求重连。
覆盖串行触发、关闭与晚回调、退避上限、溢出、下载不阻塞 snapshot reader、
旧连接 pin 与新流决策变化。覆盖 direct/proxy fetch adapter 出口、TLS 校验设置、
不降级/重定向限额/取消与 URL 脱敏；禁止用源码字符串测试替代所有生产事务测试。
首启无缓存覆盖 gate 关闭、成功开放、失败回滚；移动端只能源码审查时诚实记录。
运行所有 P0-P3 相关 CTest、布局、native Linux build 和适用 sanitizer。

## 7. 完成记录

2026-10-07：完整包持久化、候选编译/发布、失败保留与运行时生命周期已实现。
`FileDurablePolicyBundleStore` 保存校验 blob/manifest 与 CURRENT/PREVIOUS，失败回滚
恢复原指针；回滚失败单独报告，不能把状态不确定写成成功。`PolicyUpdateService`
串行更新、合并触发，提供 24h 默认周期、1min–1h 失败退避和关闭取消。
启动时先恢复完整缓存，再刷新本地主规则及本地规则集；没有下载器时仅复用验证过的
远端缓存。内存配置与文件配置分开重载，关闭自动更新不妨碍重启时读取本地变更。
首启无缓存的远端来源保持业务 gate 关闭，下载验证成功之后才开放业务。

测试覆盖规则/blob/manifest/CURRENT/PREVIOUS 的 write、flush、rename、目录刷新
失败组合及重启读取，服务测试覆盖回滚失败、调度、取消、旧流决策保持和缓存恢复后
本地刷新。direct/SOCKS/HTTP/TLS fetcher 使用动态 loopback 模拟服务器验证；隧道
connector 的完成/晚回调/取消使用注入 hooks，不能推断真实 PPP 隧道更新已验证。
Windows 文件刷新权限已按 API 契约修正，但未在 Windows 构建；目录刷新没有 POSIX
fsync 等价保证。注入失败不代替真实断电或磁盘满测试。

完整构建和联合验收见 [P5 完成记录](DNS_ROUTING_POLICY_P5_CN.md#5-完成记录)。
