# IPv6 中继平面

> **状态：**当前 Linux 服务端实现边界
> **类型：**指南
> **最后核对：**IPv6 配置规范化、服务端启动、switcher 与 Linux 平台源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[IPv6 Transit Plane](IPV6_TRANSIT_PLANE.md)

## 范围

服务端 IPv6 中继数据平面只在 Linux（排除 Android）实现。不支持的服务端平台会在配置规范化时拒绝 NAT66/GUA；不能把它文档化为无害空操作或可移植服务端功能。

实现有两种模式：

| 模式 | 已按源码核对的行为 |
|---|---|
| `nat66` | Linux 宿主机准备使用 NAT66 路径和基于 `ip6tables` 的规则。空 CIDR 可以规范为项目 ULA 回退值。 |
| `gua` | 使用有效全球单播 CIDR、服务端 IPv6 路由以及每客户端 NDP 代理支持。 |

两种模式都不保证公网可达。它依赖宿主机能力、TUN 可用性、IPv6 路由、上游策略和运维维护的防火墙/NAT 环境。

## 当前配置表面

只使用已解析的 `server.ipv6` 字段：

| 字段 | 角色 |
|---|---|
| `mode` | `nat66` 或 `gua` |
| `cidr` | IPv6 网络/地址池输入 |
| `gateway` | IPv6 网关输入 |
| `dns1`、`dns2` | 适用时写入协商客户端信息的 IPv6 DNS 输入 |
| `lease-time` | 动态地址分配生命周期 |
| `static-addresses` | 客户端 GUID 到地址的映射 |

当前没有 `server.ipv6.enabled`、`prefix`、`uplink`、`transit_tap`、`forwarding`、`nat66_masq` 配置契约。不要依赖这些被忽略的名称。

## 运行时生命周期

1. 服务端启动会在打开 switcher 前准备 Linux IPv6 宿主机环境。
2. switcher 创建专用中继 TAP 并配置中继路径。
3. 客户端地址激活时，服务端为每个客户端安装/替换 `/128` IPv6 路由；它不会为所有客户端安装单一的池前缀路由。
4. GUA 模式还会为活跃客户端地址使用 NDP 代理路径。
5. 服务端清理会按生命周期顺序释放关联路由/代理/隧道状态。

这是重要的宿主机变更。应在受控环境测试，并保留由其他系统管理的路由或防火墙规则。

## SSMT 边界

中继 SSMT 是 opt-in。它需要已配置的 TUN SSMT 和多队列路径；它不是自动的“每 CPU 一个 worker”机制，也不能文档化为保证的线程生命周期。

## 运维检查清单

1. 在受支持 Linux（非 Android）上以所需网络管理能力运行服务端。
2. 预期 Linux NAT66 宿主机条件时选择 `nat66`；只有具备有效全球单播 CIDR 和上游 IPv6 设计时才选择 `gua`。
3. 上线前验证 `/dev/net/tun`、IPv6 路由；对于 NAT66 还应验证所需 `ip6tables` 路径。
4. GUA 模式应按[IPv6 NDP 代理](IPV6_NDP_PROXY_CN.md)验证默认路由和 NDP 行为。
5. 添加测试客户端后检查宿主机路由和应用诊断；当前没有已文档化的 `/api/v1/server/ipv6/state` 端点。
6. 防火墙、路由持久化和外部前缀委托仍由运维负责。

## 相关页面

- [IPv6 租约管理](IPV6_LEASE_MANAGEMENT_CN.md)
- [IPv6 NDP 代理](IPV6_NDP_PROXY_CN.md)
- [IPv6 客户端地址分配](IPV6_CLIENT_ASSIGNMENT_CN.md)
- [部署模型](../operations/DEPLOYMENT_CN.md)