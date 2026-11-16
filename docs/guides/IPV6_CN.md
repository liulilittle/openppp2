# IPv6

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `AppConfiguration.cpp`、`ppp/app/server/VirtualEthernetSwitcher.cpp`、`ppp/app/client/AssignedAddressManager.cpp`）
>
> **用途：** 让服务端给客户端分配 IPv6 并经服务端访问 IPv6 网络。
> **读者：** 部署服务端的运维人员。
> **上级索引：** [指南](README_CN.md) · **English:** [IPv6](IPV6.md)

## 1. 支持范围

| 端 | 支持情况 |
|---|---|
| 服务端 | **仅 Linux（不含 Android）**。其他平台写了 `server.ipv6.mode` 时配置加载失败。 |
| 客户端 | Windows / Linux / macOS 会把服务端分配的地址、路由和 DNS 自动应用到虚拟网卡，断开时恢复。Android / iOS 由各自的系统 VPN 框架处理，行为不同。 |

## 2. 选择模式

| 模式 | 适用场景 | 前提 |
|---|---|---|
| `nat66` | 服务器只有一个公网 IPv6，或没有可分配的前缀。客户端拿到私有（ULA）地址，由服务端做 NAT66 出网。 | 服务端可用 `ip6tables`；`cidr` 可不填，默认使用 `fd42:4242:4242::/64`。 |
| `gua` | 你拥有一段可路由的全球单播前缀，希望每个客户端拿到公网 IPv6。 | `cidr` 必须是全球单播前缀；服务器有可用的 IPv6 默认路由；上游会把该前缀路由到服务器，或通过 NDP 代理解析（见第 5 节）。 |

两种模式都不保证一定能访问公网，这取决于主机路由、上游策略和防火墙。

## 3. 服务端配置

```json
"server": {
  "ipv6": {
    "mode": "nat66",
    "cidr": "fd42:4242:4242::/64",
    "gateway": "fd42:4242:4242::1",
    "dns1": "2606:4700:4700::1111",
    "dns2": "2001:4860:4860::8888",
    "lease-time": 300,
    "static-addresses": {
      "{F4569208-BB45-4DEB-B115-0FEA1D91B85B}": "fd42:4242:4242::100"
    }
  }
}
```

| 字段 | 说明 |
|---|---|
| `mode` | **必填**，`nat66` 或 `gua`。只写 `cidr` 不会启用 IPv6。 |
| `cidr` | 地址池前缀。前缀长度不合法（如 `/128`）或 `gua` 下不是全球单播地址时，IPv6 被关闭。 |
| `gateway` | 服务端网关地址；不填或不在前缀内时使用前缀内第一个地址。 |
| `dns1` / `dns2` | 下发给客户端的 IPv6 DNS。 |
| `lease-time` | 动态地址租期（秒），默认 300；`0` 表示不过期。 |
| `static-addresses` | 按客户端 GUID 固定地址；不在前缀内、与网关相同或重复的条目被丢弃。 |

其他名字（`enabled`、`prefix`、`uplink`、`lease_duration` 等）都不会被读取。

服务端需要 root（或 `CAP_NET_ADMIN`）和可用的 `/dev/net/tun`。启动时程序会创建专用的转发网卡，并为每个在线客户端添加一条 `/128` 路由。

## 4. 地址如何分配

1. 客户端 GUID 在 `static-addresses` 里有条目时，优先使用该地址（不过期）。
2. 客户端可以用 `--tun-ipv6=<地址>` 请求指定地址，但这只是提示，服务端可以拒绝或换成别的地址。
3. 否则由会话 ID 计算出一个确定的候选地址，冲突时做有限次调整。
4. 地址与会话绑定；动态地址在租期到期后可被回收。同一进程内重连时，客户端会优先请求上一次拿到的地址。

想让某台客户端长期使用同一个地址，请用 `static-addresses`，并保持该客户端 `client.guid` 不变。

## 5. GUA 模式与 NDP 代理

`gua` 模式下，服务端会为每个在线客户端地址在上行网卡上添加 NDP 代理条目（通过 procfs 开启 `proxy_ndp`、通过 rtnetlink 增删条目），让上游路由器能解析到这些地址。`nat66` 不使用 NDP 代理。

客户端上线后可以只读检查：

```bash
ip -6 neigh show proxy dev <上行网卡>
ip -6 route | grep <客户端地址>
```

有条目不代表外网一定可达；没有条目说明 GUA 路径未建立或主机前提不满足。

## 6. 上线检查

1. 服务端是 Linux 且以 root 运行；`nat66` 时确认 `ip6tables` 可用。
2. 客户端连接后，在客户端执行 `openppp2 info`，确认拿到了 IPv6 地址。
3. 在客户端测试 IPv6 访问（如 `ping -6 2606:4700:4700::1111`）。
4. `gua` 模式下按第 5 节检查 NDP 代理条目和路由。
5. 断开客户端后确认它添加的地址和路由已被移除，且没有误删你手动配置的 IPv6 设置。

## 7. 常见现象

| 现象 | 说明 |
|---|---|
| 启动报 IPv6 不可用 / 平台不支持 | 服务端不是 Linux，或在 Android 上运行。 |
| 配置了 `cidr` 但客户端没有 IPv6 | 缺少 `mode`，或前缀不合法被自动关闭。 |
| 分配的地址和 `--tun-ipv6` 不一样 | 正常，分配由服务端决定。 |
| IPv4 正常、IPv6 不通 | 检查客户端平台、服务端 `ip6tables`（nat66）或上游路由 / NDP（gua）。 |
| Android / iOS 行为不同 | 预期行为，移动端由系统 VPN 框架处理地址。 |

## 相关文档

- [配置文件参考 · server](../reference/CONFIGURATION_CN.md)
- [平台说明](PLATFORMS_CN.md) · [部署](../operations/DEPLOYMENT_CN.md) · [安全](../operations/SECURITY_CN.md)
