# IPv6 NDP 代理

> **状态：**当前 Linux GUA 服务端实现边界
> **类型：**指南
> **最后核对：**服务端 switcher 与 Linux TAP/NDP 源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[IPv6 NDP Proxy](IPV6_NDP_PROXY.md)

## 范围

NDP 代理使单独分配给客户端的 GUA 地址能够经 Linux 服务端的上行链路可达。它属于 Linux GUA 服务端路径；NAT66 不使用它，它也不是 Windows/macOS/移动服务端的可移植功能。

实现通过 procfs 读取/启用 Linux `proxy_ndp` 设置，并通过 rtnetlink 创建/删除每地址的代理邻居条目。核心实现路径不会通过 shell 执行 `ip neigh add`/`del`。

## 它在数据平面中的位置

对于活跃 GUA 客户端地址，服务端同时需要：

1. 将该客户端地址的数据包送入中继路径的服务端 IPv6 路由；
2. 上行接口上的 NDP 代理条目，以便相邻 IPv6 网络把该地址解析到服务端。

第一部分见[IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)。NDP 只解决邻居发现，不能证明上游路由、宿主机转发、防火墙策略或客户端可达性正确。

## 前提

启用 GUA 模式前，应在应用外核对以下事项：

- 服务端是 Linux（非 Android），且拥有所需网络管理能力；
- `server.ipv6.mode` 为 `gua`，并且 CIDR 是有效全球单播前缀；
- 选定宿主路径有可用 IPv6 默认路由和可达上游网络；
- 宿主机允许所需的 procfs 与 rtnetlink 操作；
- 上游路由器/防火墙策略允许预期流量。

代码不能代替运维确认委托前缀所有权、上游路由器策略或 Internet 可达性。

## 观察，而非猜测

客户端活跃后，可使用只读宿主机检查查看代理条目：

```bash
ip -6 neigh show proxy dev <uplink-interface>
```

条目缺失可能表示服务端没有建立 GUA 路径或宿主机前提失败。条目存在仍不证明外部可达；应从相关网络测试，并检查服务端/客户端诊断。

## 生命周期边界

- switcher 只在 GUA 模式启用 NDP 代理路径。
- IPv6 exchanger 进入活跃状态时会尝试添加每客户端条目，并在关联服务端生命周期清理时移除。
- 既有宿主机配置和失败条件很重要。应把清理视为实现管理的状态，但不要依赖它修复无关的手工 NDP 条目。
- 当前没有已文档化的 NDP 条目或运行状态管理 REST 端点。

## 运维检查清单

1. 先确认 Linux-only GUA 模式和中继设置，再检查 NDP。
2. 在满足 TUN、路由、procfs、邻居操作的前提下使用最小权限。
3. 将运维拥有的 sysctl/防火墙/前缀路由变更纳入配置管理。
4. 测试客户端收到地址后，检查代理条目和宿主机路由表。
5. 若可达性失败，应区分 NDP 解析、服务端路由、客户端分配和上游策略，避免一次性修改所有宿主机设置。

## 相关页面

- [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)
- [IPv6 租约管理](IPV6_LEASE_MANAGEMENT_CN.md)
- [平台集成](PLATFORMS_CN.md)
- [安全模型](../operations/SECURITY_CN.md)