# DNS 与分流策略 P1：离线编译和诊断

> Status: Implemented; offline acceptance complete; v2.1.7 release pending
> Type: Design
> Last verified: 2026-10-07
> Parent index: [设计文档](README.md)

当前状态：P1 已实现并通过记录中的离线验收。用户已授权推送代码，并在 CI 全绿后发布 v2.1.7；
该版本目前不能标为已发布。
本文件的“后续阶段”文字保留 P1 当时的时间边界，不表示 P2–P5 当前仍未实施。

本文记录 [重构方案](DNS_ROUTING_POLICY_REFACTOR_CN.md) 中 P1 的实现边界。
旧行为基线见 [P0 文档](DNS_ROUTING_POLICY_BASELINE_CN.md)。
本文中的启动保护与平台能力描述记录 P1 完成时的状态；后续变更见
[P2 执行路径接入](DNS_ROUTING_POLICY_P2_CN.md)。

## 实现边界

P1 提供 v2 配置加载、规则编译、不可变快照、纯路由与 DNS 决策，以及
`policy check` 和 `policy explain` 离线命令。命令在客户端初始化前分派，
不会建立 PPP 连接、下载规则集、解析测试域名或操作路由与 DNS。

这里的决策是计划，不证明相应平台已经接入新版运行时。
JSON 报告明确输出 `plan_only: true` 和 `runtime_installed: false`。
普通启动路径遇到显式 `client.policy` 时拒绝启动，避免忽略 v2 配置后按旧语义运行。
P2 才接入连接与 DNS 运行路径；自动更新、Fake-IP 生命周期和旧配置迁移仍在后续阶段。

## 配置与来源

入口为 `client.policy.version = 2`，规则路径相对主配置所在目录解析。
缺失文件是错误，不转换为内联文本。与旧客户端路由或 DNS 策略字段同时出现时
返回 `E_POLICY_SOURCE_CONFLICT`。独立的运行模式与网络拓扑字段不成为规则条件。

JSON 定义命名 resolver、规则集及更新参数。P1 读取本地源；只声明 URL 的源
返回来源不可用，离线命令不会访问网络。更新参数被校验，但不启动更新器。
resolver 的 `via` 为 `direct` 或 `proxy`，provider 名称仅表示上游列表。
DNS 端点支持现有 provider 名称及显式 UDP、TCP、DoH、DoT 端点。
显式写法为 `udp://IPv4[:port]`、`tcp://IPv4[:port]`、`tls://hostname[:port]`、
`https://hostname[:port]/path`；P1 不支持 endpoint 的 IPv6、userinfo、fragment 或原始非 ASCII。
配置和本地来源单文件上限为 64 MiB；只校验计划，不进行网络 bootstrap。

规则集格式：

| 格式 | 内容 |
|---|---|
| `geoip-dat` | GeoIP protobuf 数据，必填 `tag` |
| `geosite-dat` | GeoSite protobuf 数据，必填 `tag` |
| `geoip-text` | 本次明确提供的文本扩展：逐行 IPv4/IPv6 CIDR |
| `geosite-text` | 本次明确提供的文本扩展：域名及 `full:`、`domain:`、`plain:`、`regexp:` 条目 |

可选 `sha256` 检查源文件完整字节，包括二进制中的零字节。
加载器保留已校验字节，编译器从该内存副本解析，避免文件在校验后变化影响编译。
Geo 中 IPv6 CIDR 跳过并计数；显式 IPv6 规则报错。
Geo Plain 条目作为关键词参与新版匹配，不继承旧编译器跳过 Plain 的行为。

## 语法与索引

分组为 `[direct]`、`[proxy]`、`[reject]`、`[dns:name]`。
支持裸域名后缀、`=domain` 精确、`*.domain` 仅子域名、`regexp:`、IPv4/CIDR、
`lan` 和 `set:name`。额外明确提供 `full:` 精确域名及 `keyword:` 关键词写法。
注释与空行保留在来源文本中；P1 不提供导出或递归 include。
域名使用 ASCII/Punycode，匹配规范化大小写与尾点，后缀遵守标签边界。

`default direct|proxy|reject` 设置默认动作，省略时为 proxy；不接受 auto。
`dns direct name`、`dns proxy name` 绑定命名 resolver。
当前编译器要求两条 DNS 绑定都存在；单出口配置也需声明两者。
DNS 分组禁止 IPv4 条件和 IP 规则集，避免先解析才能决定解析上游的循环。

LAN v1 固定展开为 `0.0.0.0/8`、`10.0.0.0/8`、`127.0.0.0/8`、
`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、`224.0.0.0/4`、
`255.255.255.255/32`。这是一组匹配条件，不会生成系统绕行路由。

手写条件优先于规则集。域名层依次为精确、最长后缀、关键词、声明顺序正则；
同长度后缀中仅子域名优先。规则集同等条件按引用顺序。
IP 层在各来源优先级内取最长前缀。有效域名命中后不再被 IP 覆盖；
域名未命中且没有 IP 时，返回 `needs_ip_resolution`，默认动作只是待解析的计划。

精确域名使用哈希索引，后缀使用反向树，IPv4 使用前缀树，关键词共享匹配索引，
正则在编译时一次性构建。热路径不读取文件、不下载数据、不编译正则。
相同手写条件与相同动作去重并告警，不同动作报错且包含两处位置。
规则集重叠条件有诊断，任意正则重叠不宣称能够完整分析。

## API 与 DNS 计划

`PolicySourceLoader::LoadFile` / `Load` 生成带路径和原始字节的来源模型。
`PolicyCompiler::Compile` 成功后返回 `shared_ptr<const PolicySnapshot>`；失败时不产生
候选快照。调用者可保留上一快照，P1 没有安装在线热更新器。
快照持有自己的规则、resolver 与索引，外部修改来源对象不改变已编译结果。

`PolicyEvaluator::Evaluate` 返回动作、命中与原因、规则 ID、来源位置、版本和
是否需要 IP 解析。`PlanDns` 先判断已命中的业务 reject，再判断 DNS 例外，否则使用
业务域名动作或默认动作对应的 resolver，并返回名称与 `via`。
未命中业务域名时，DNS 例外可以覆盖默认 reject；已命中的业务 reject 不能被覆盖。
IP 条件不会影响该 DNS 计划。计划没有发送查询或实现备用上游重试。

## CLI 与能力限制

```bash
ppp policy check --config ./config.json --runtime tun --platform android --json
ppp policy explain --config ./config.json --runtime tun --platform android \
  --domain example.test --ip 192.0.2.7 --network tcp --port 443 --json
```

`--config`、`--runtime` 必填；runtime 为 tun/http/socks，platform 为
linux/windows/macos/android/ios，省略 platform 时取编译宿主。
`explain` 至少指定 domain 或 IP，默认 network 为 tcp；network/port 是能力与解释
输入，不是新增规则谓词。仅有域名且未匹配时不会伪造最终 IP 结果。
输出包含路由动作、DNS resolver/via、规则 ID、来源位置、版本与诊断。
IP-only explain 的 DNS 计划标记为不适用。

能力检查根据当前源码调用路径判断，未做跨平台运行测试：

| 路径 | 强制 direct TCP | 强制 direct UDP |
|---|---|---|
| TUN Android | 源码支持 | 源码支持 |
| TUN Linux/Windows/macOS | 源码支持 | 不支持 |
| TUN iOS | 不支持 | 不支持 |
| 本地 HTTP | TCP 路径可计划 | 没有 UDP 传输 |
| 本地 SOCKS | TCP 路径可计划 | 新版强制 direct 未接入 |

`check` 检查完整策略可能使用的动作，包含 direct 时会检查 TCP/UDP；
因此某个 TCP explain 可通过，完整策略 check 仍可能报 UDP 能力限制。
`ipv6: block` 是待运行时执行的配置，P1 不据此声称已经阻断 IPv6。
exit code：0 成功、2 配置/规则错误、3 来源不可用、4 能力不支持；
迁移相关的 5 由后续阶段实现。

## 验证口径

`policy_acceptance_test` 从 JSON 来源加载到编译和 evaluator 执行独立手工预期案例：
手写覆盖规则集、后缀先于正则、域名先于 IP、DNS 例外出口差异与 reject 优先、
缺失/远程/冲突来源、有效二进制 Geo 与哈希、加载后覆盖或删除文件仍使用已校验字节。
其 protobuf 样本按 Geo 线格式独立编码，不以 evaluator 输出生成预期。

2026-10-05 集成验证：隔离 CMake/Ninja 构建成功，19/19 相关 CTest 目标通过，
包含 P0 基线、Geo、原配置/transport-auth、P1 十个新增测试目标。
性质测试包含独立 seeded IP 区间与关键词 oracle，发现并修正规则集内部条目的顺序平局；
比较结果没有用生产 evaluator 自动生成静态预期。
独立 Clang ASan/UBSan 稳健性测试通过；因环境 ptrace 限制关闭了 LeakSanitizer，
泄漏检查未验证。完整独立测试集、TSan、完整内核及 Windows/macOS/Android/iOS 构建未执行。

从仓库根目录可用完全离线的辅助程序复现。该程序只有策略命令入口，拒绝普通客户端参数：

```sh
cmake -S tests/cpp -B build/private/dns-policy-p0 -G Ninja
cmake --build build/private/dns-policy-p0 --parallel 3 --target policy_offline_cli
build/private/dns-policy-p0/policy_offline_cli policy check \
  --config tests/contracts/routing-policy/v2/example.json --runtime tun --platform android --json
build/private/dns-policy-p0/policy_offline_cli policy explain \
  --config tests/contracts/routing-policy/v2/example.json --runtime tun --platform linux \
  --domain local.example.test --network tcp --port 443 --json
```

`tests/contracts/routing-policy/v2/example.json` 只含测试值，属于代码发布候选；目标版本为 v2.1.7，
仍待代码推送和 CI 全绿，不能标为已发布；
切换 check 平台到 Linux 时，该 split 策略返回 4，说明当前 UDP direct 能力不足。
原内核构建中的 `ppp policy ...` 使用同一命令模块，但本批没有构建或启动完整内核。

离线验收不等同于真实 DNS 出口、VPN 会话、驱动、系统路由或跨平台运行验证。
