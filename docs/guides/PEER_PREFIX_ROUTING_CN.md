# 对端前缀路由（站点互联）

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `ppp/app/server/PeerRouteAnnouncePolicy.h`、`VirtualEthernetSwitcher.cpp`、`ppp/app/client/PeerPrefixRouteManager.cpp`、`VEthernetExchanger.cpp`）
>
> **用途：** 让其他客户端经某台“网关客户端”访问它背后的整个局域网。
> **读者：** 需要把多个站点的内网互联起来的运维人员。
> **上级索引：** [指南](README_CN.md) · **English:** [Peer prefix routing](PEER_PREFIX_ROUTING.md)

## 1. 场景

```text
客户端 B (10.1.0.3) ──► 服务端 ──► 网关客户端 A (10.1.0.2) ──► A 所在局域网 10.0.0.0/24
```

默认情况下（`server.subnet: true`），客户端之间只能按虚拟 IP 互通。对端前缀路由增加了“前缀 → 网关客户端”的转发：B 访问 `10.0.0.5` 时，服务端按最长前缀匹配把包交给 A，A 再转发进它的局域网。

- 只支持 IPv4。
- 路由的建立在桌面端（Windows / Linux / macOS）完整支持；Android / iOS 支持有限。
- 和 P2P 直连互不冲突：前缀路由决定“交给哪个客户端”，P2P 只优化“怎么到达那个客户端”。

## 2. 三个角色要做的事

| 角色 | 必须配置 |
|---|---|
| 服务端 | `server.subnet: true`；`server.peer-routing.enabled: true`；在 `allowed-routes` 里**白名单**每个网关能宣告的前缀 |
| 网关客户端 A | `client.peer-route-announce` 宣告前缀；`client.peer-gateway-forward: true`；主机开启 IP 转发；局域网有回程路由 |
| 访问客户端 B | 什么都不用配（服务端会下发路由表）；或用 `client.routing.ip.peer-routes` 写静态路由 |

## 3. 服务端

```json
"server": {
  "subnet": true,
  "ipv4-pool": { "network": "10.1.0.0", "mask": "255.255.255.0" },
  "peer-routing": {
    "enabled": true,
    "distribute": true,
    "allowed-routes": [
      { "network": "10.0.0.0", "prefix": 24, "guid": "{11111111-1111-1111-1111-111111111111}" }
    ]
  }
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `peer-routing.enabled` | `false` | 启用前缀转发。 |
| `peer-routing.distribute` | `true` | 有网关上线 / 下线时，把最新路由表推送给所有客户端。 |
| `peer-routing.allowed-routes[]` | 空 | 宣告白名单。每条为 `{network, prefix, guid}`：只有 `client.guid` 等于 `guid`（不区分大小写、忽略花括号）且前缀**完全相同**的宣告才会被接受。**列表为空时所有宣告都会被拒绝。** |

无论白名单怎么写，以下前缀一律拒绝：默认路由、`0.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`224.0.0.0/4`、`240.0.0.0/4`。

## 4. 网关客户端 A

```json
"client": {
  "guid": "{11111111-1111-1111-1111-111111111111}",
  "server": "ppp://vpn.example.com:20000/",
  "peer-route-announce": [
    { "network": "10.0.0.0", "prefix": 24 }
  ],
  "peer-gateway-forward": true
}
```

| 字段 | 说明 |
|---|---|
| `peer-route-announce[]` | 本机背后可达的前缀 `{network, prefix}`，不写 `via`。连接时随握手发给服务端；服务端只回显被接受的前缀。 |
| `peer-gateway-forward` | 必须为 `true`。否则 A 会丢弃所有目标不是自己虚拟 IP 的数据包。 |

主机设置（Linux 示例）：

```bash
sysctl -w net.ipv4.ip_forward=1
# 局域网设备不知道 10.1.0.0/24 时，做 SNAT 或在局域网路由器上添加回程路由：
iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
```

A 的虚拟 IP 需要固定，访问端的静态路由才有意义：启动时加 `--tun-ip=10.1.0.2 --tun-gw=10.1.0.1 --tun-mask=24`。

## 5. 访问客户端 B

**动态（推荐）：** 服务端 `distribute: true` 时，B 连接后自动收到 `10.0.0.0/24 via 10.1.0.2` 并安装，不需要额外配置。

**静态：** 拓扑固定、或服务端关闭了 `distribute` 时：

```json
"client": {
  "routing": {
    "ip": {
      "peer-routes": [
        { "network": "10.0.0.0", "prefix": 24, "via": "10.1.0.2" }
      ]
    }
  }
}
```

`network`、`prefix`、`via`（网关的虚拟 IP）都必填；`via` 等于本机虚拟 IP 的条目被忽略。没写 `client.routing` 时也可以用旧位置 `client.peer-routes`。静态与动态路由可以同时存在。

代理模式下这些路由只在程序内部生效，不写入系统路由表。

## 6. 服务端转发顺序

1. 目标地址正好是某个客户端的虚拟 IP → 交给该客户端；
2. 否则在已接受的宣告中做最长前缀匹配 → 交给对应网关客户端；
3. 都不匹配 → 不转发。

网关断开时，其前缀从路由表移除，并（`distribute: true` 时）推送给其他客户端。

## 7. 上线检查

1. 服务端：`subnet`、`peer-routing.enabled` 为 `true`，`allowed-routes` 包含网关 GUID 和完全相同的前缀。
2. 网关：`peer-gateway-forward: true`、IP 转发已开、局域网回程路由或 SNAT 已配置。
3. 访问端：`ip route | grep 10.0.0.0`（Windows 用 `route print`）能看到经网关虚拟 IP 的路由。
4. 从访问端 `ping 10.0.0.x`。

## 8. 排查

| 现象 | 原因 |
|---|---|
| 访问端没有路由 | 宣告被拒（`allowed-routes` 为空、GUID 或前缀不一致、前缀属于被禁止的范围）；或 `distribute: false` 且没写静态路由 |
| 有路由但不通 | 网关不在线，或静态路由的 `via` 写错 |
| 包到了网关但进不了局域网 | `peer-gateway-forward` 没开，或主机未开启 IP 转发 |
| 局域网设备不回包 | 局域网没有到 `10.1.0.0/24` 的回程路由，需要 SNAT 或静态路由 |
| 服务端不转发 | `server.subnet` 或 `peer-routing.enabled` 为 `false` |

## 相关文档

- [配置文件参考 · server / client](../reference/CONFIGURATION_CN.md) · [路由与 DNS](ROUTING_AND_DNS_CN.md)
