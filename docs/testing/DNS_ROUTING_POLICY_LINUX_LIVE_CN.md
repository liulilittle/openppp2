# DNS 与分流策略 Linux 实机验证

> Status: Partial acceptance
> Type: Test report
> Last verified: 2026-10-07
> Parent index: [设计文档](../design/README.md) · [开发文档](../development/README_CN.md)

日期：2026-10-07。关联：[总方案](../design/DNS_ROUTING_POLICY_REFACTOR_CN.md)、
[P2](../design/DNS_ROUTING_POLICY_P2_CN.md)、[P5](../design/DNS_ROUTING_POLICY_P5_CN.md)。
候选内核来自本地构建。代码推送已获授权，v2.1.7 仍待推送完成和 CI 全绿；本报告不表示该版本已发布。

用户授权在现有 Linux x86_64 客户端主机复用节点配置进行实机测试。
候选二进制与派生配置放在 root 私有测试目录，未替换原安装或修改原配置。
暂时停止原服务，使用临时 TAP、loopback HTTP/SOCKS 监听器，独立 timer 保护恢复。
原节点地址、凭据、配置与日志不进入本报告或 Git。

## 1. 真实流量结果

| 检查 | 结果与证据 | 限制 |
|---|---|---|
| CLI 七个命令 | check、explain、init、export、status 正常；update 下载后报告 prepared_for_next_start；migrate 为 draft/exit5 | whole-policy 迁移不等价，exit5 符合当前合同 |
| export 新建嵌套父目录 | 修复后远端成功 | 保留 no-overwrite 与策略专用导出 |
| HTTP forward direct | example.com HTTP 200 | 不据此推断所有 TCP 出口通过 |
| HTTP CONNECT direct | example.org:80 握手 200，连接内 GET 收到 HTTP 200 | 在更新后该域名属于 direct；不是 proxy TCP 证据 |
| SOCKS TCP DOMAIN direct | HTTP 200 | HTTPS 另见下文 |
| SOCKS UDP 数值 direct | 有答案，来源、事务 ID 与 question 验证通过 | 目标为公开 DNS，载荷是测试查询 |
| SOCKS UDP 数值 proxy | 同上 | 已有真实隧道数据回包 |
| SOCKS UDP DOMAIN | one.one.one.one 与 dns.google 都收到有效答案 | 前者解析后由 IPv4 规则选 direct，后者选 proxy |
| SOCKS UDP reject | 无回复；最终拒绝样本集合使 reject 计数增加 | 单独无回复不证明策略拒绝；计数按会话汇总 |
| real DNS | TUN UDP/53 查询收到真实 A 答案，缓存 hit/miss 增加 | DNS 拦截仍只覆盖 UDP/53 |
| DNS TCP 上游 | 配置 direct TCP 上游后，TUN UDP 查询收到答案 | 不是客户端 TCP/53 拦截支持 |
| DNS DoH/DoT 上游 | 指定服务器地址与主机名后，两者都收到答案 | 初始 2 秒探针失败，增加到 8 秒后通过；不代表所有公共上游可达 |
| Fake-IP | A 返回池内地址；AAAA 无答案；拒绝域名 REFUSED | IPv6 全路径拒绝尚未完整验收 |
| Fake-IP 持久化 | 重启候选后同域名仍对应同一地址，mappings=1 | 未做设备断电/文件系统故障测试 |
| Fake-IP TUN TCP | 映射地址 HTTP 200；未知池地址请求失败，最终 reject 计数增加 | tun-host=no 下额外添加测试池路由后，普通未绑定接口请求才经过 TUN；未验收自动池路由 |
| TUN DNS 流量 | 为测试 DNS 地址临时添加 TUN 路由后查询均有答案 | 端口 53 会经过 DNS 拦截，不能据此宣称通用 TUN UDP 吞吐已通过 |
| 在线规则集更新 | 活动版本从 1 升至 2，新增域名 direct HTTP 200 | 专用受控 HTTP 上游，非生产订阅服务验收 |
| 无效更新保留版本 | 非法 regexp 导致 complete compiler validation 失败，活动版本仍为 2 | 未覆盖所有崩溃/断电窗口 |

HTTPS CONNECT、SOCKS HTTPS、proxy TCP 和 TUN HTTPS 在本轮既有探针中仍有超时，
没有标为通过。物理网卡绑定的 example.com HTTPS 同样超时，而普通未绑定 HTTPS
成功；原安装恢复后 TUN HTTPS 也仍超时。这是环境对照，尚不足以定位具体原因。
Cloudflare DoH 的成功不代表 example.com:443 的路径已通过。保护器和出口没有因失败
而被弱化或隐式回退。

同出口备用上游的故障注入、活跃连接更新前后固定策略、通用 TUN UDP 非 DNS 载荷、
IPv6 全入口拒绝、长期稳定性、P2P 数据路径和实际 direct/bypass 吞吐尚未完整实机验收。
Windows/macOS/Android/iOS 本轮未构建或运行。不能称所有功能或完整发布验收通过。

## 2. 实机发现及修复

实现仍由 Luna 按先补充设计约束、再实现的顺序完成。

1. export 缺少父目录时失败：创建本次缺失目录，失败时仅清理本次创建且仍为空的目录。
2. SOCKS UDP ASSOCIATE 拒绝可选 null allocator：沿用系统分配回退。
3. SOCKS accept 所用 scheduler context 未登记缓存 buffer：cache miss 使用 allocator
   MakeByteArray 回退，没有扩大 Executors 的全局上下文行为。
4. UDP 回复回调端点颠倒：handler 接收 `(client_relay, remote)`，编码发送需要
   `(remote, client_relay)`。修复后 direct/proxy/DOMAIN 的实际回复全部通过验证。

端点修复保留 socket 地址族、来源验证和保护器。只读审查确认 IPv4 loopback 不会被
OpenSocket 改成 IPv6 any，没有依据该错误假设更改绑定行为。

## 3. 编译与回归

- 最新候选完成 Linux native 编译链接。已有 stdafx char 比较告警，不是本轮新增。
- 完整 CTest 首次运行 160/169 通过，9 项因沙箱 socket EPERM 失败；获准创建本地
  socket 后这 9 项全部重跑通过。不是一次不受限制的全量测试通过记录。
- 随后的端点方向改动重建并通过 local_proxy_policy_test；CLI 父目录合同测试通过。
- 最新 local_proxy_policy_test 与 policy_cli_contract_test 的 ASan/UBSan 通过，
  LeakSanitizer 按环境限制关闭。本轮未重跑全部 sanitizer 或 TSan。
- include 边界、258 个 C++ 源文件的 vcxproj 登记与保留 CRLF 的空白检查通过。
  GitNexus 索引未更新，使用源码、协议方向、调用点、diff 与聚焦测试分析。

## 4. 恢复核验

主动停止临时实例，启动原服务。原服务 active/running、NRestarts=0，遥测
connected/relay；原 TUN HTTP 200，HTTPS 仍与先前一样超时。
原配置 SHA256、resolv.conf、IPv4 路由、IPv4/IPv6 rules 与基线一致。
IPv6 routes 的差异检查为另一接口 RA expires 倒计时，以及原 TAP 重建后本地
链路地址变化；原路由目的与其他字段保持一致，未强改动态地址或 RA 有效期。
临时 TAP 不存在，原 TAP 存在。临时目标路由已删除，自动恢复 timer 已取消，
本地受控规则上游已停止。保留私有证据与备份，没有提交 Git 或清理并行工作区。
