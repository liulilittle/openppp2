# DNS 模块设计
> Status: Active
> Type: Architecture
> Last verified: client DNS controller/interceptor and `ppp/dns/` sources, 2026-07-22
>
> **用途：**说明原生 client DNS 拦截与 resolver 的边界。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [DNS Module Design](DNS_MODULE_DESIGN.md)

## 范围

client 拦截入口只针对 UDP/53。`ClientPacketDispatchHandler` 识别目标端口为 53 的 UDP 包，并委托给 `DnsController`。这不会使 client TCP DNS、DoH 或 DoT 流量成为通用拦截能力。UDP、TCP、DoH 与 DoT 描述的是 resolver 的**上游**协议。

## Owner 与生命周期模型

```text
client UDP/53 包
  -> DnsController
  -> DnsInterceptor / DnsRedirectPlan
  -> cache、legacy relay、provider resolver、tunnel fallback 或 drop
  -> datagram output 或 session tunnel send
```

`DnsController` 持有 policy wrapper、当前 session context、query context 和 close 顺序。`OpenSession()` 安装由弱 tunnel transport 支持的 session context。`Close()` 使 session 失效、清除 context、取消已提供 timer 并关闭 policy，因此后续异步工作不能通过该 transport 延长 exchanger 生命周期。

`DnsInterceptor` 持有 DNS rule、`DnsResolver` 与 fake-IP 状态。它完成 DNS decode、IPv6 不允许时的 AAAA 抑制、cache lookup、routing-plan 选择、fake A response 生成与 dispatch。

## Resolver 路径

routing plan 主要区分以下路径：

| 输入/结果 | 当前 dispatch 边界 |
|---|---|
| Cached response | 通过 datagram-output callback 注入响应 |
| 含 IP 的 legacy rule | `DnsUdpRelay` |
| 含 provider 的 rule | `DnsResolver::ResolveAsync()` |
| Unmatched/gateway resolver 路径 | 显式 foreign entry、显式 domestic entry，或 foreign → domestic → cloudflare fallback |
| Defer/drop/blocked AAAA | 按 plan 返回响应或不转发 |

rule 是 plan 选择的输入；不能将 gateway 处理写成无条件高于所有 rule 的优先级。成功的 legacy UDP relay 通过它的 relay callback 注入响应；resolver response 与 fallback 使用 response handler 路径。

`DnsResolver` 当前实现 UDP、TCP、DoH 和 DoT upstream sender。没有 DoQ 或 DoH3 的 protocol enum/实现。provider entry 顺序提供 fallback 顺序；部署行为仍取决于已配置 endpoint 的可达性。

## Fake IP 与 DNS reachability

fake-IP 设施仅支持 IPv4/A record。它可合成 A response、在后台解析真实 A answer，并在 UDP 与 TCP 路径上改写已知 fake destination。desktop route planning 可以包含 fake-IP pool route。

DNS reachability 有意分为两路：tunnel DNS route 可以经 tunnel gateway，underlying DNS route 可以经 underlying gateway。provider endpoint IP 和 legacy rule IP 按其路由语义收集；这不是“所有 DNS 都走物理 NIC”的通用规则。

## Server DNS 是独立的

server UDP/53 处理在启用时使用 `VirtualEthernetNamespaceCache`。cache miss 时仅当配置 `udp.dns.redirect` 才重定向；否则继续普通 UDP forwarding。只有 DNS cache 已启用且 TTL 为正时才会创建 namespace cache。

## 必须保留的边界

- 上游 TLS 校验、endpoint 可达性和 resolver 互操作性都依赖部署；不能只因配置存在就承诺解析成功。
- Fake IP 不提供 IPv6/AAAA synthesis。
- DNS controller/session cleanup 的目标是阻止关闭 session 后继续发送，不保证每个未完成的 upstream 操作都完成。
- 配置字段和安全运维示例应以[参考](../reference/README_CN.md)与 routing/DNS guide 为准，不应由本文架构概览重复定义。

## 源码锚点

- `ppp/app/client/ClientPacketDispatchHandler.cpp`
- `ppp/app/client/dns/DnsController.cpp`
- `ppp/app/client/dns/DnsInterceptor.cpp`
- `ppp/app/client/dns/DnsRedirectPlan.cpp`
- `ppp/dns/DnsResolver.h/.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
