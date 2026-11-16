# 路由与 DNS（分流）

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `AppConfiguration.cpp`、`ppp/app/client/policy/LegacyPolicyAdapter.cpp`、`ClientRoutingSources.h`、`ClientBypassRouteLoader.cpp`、`ppp/net/native/rib.cpp`、`ppp/app/client/dns/Rule.cpp`、`GeoRuleGenerator.cpp`、`ApplicationNetwork.cpp`、`ApplicationMainLoop.cpp`）
>
> **用途：** 用 `client.routing` 决定哪些流量直连、哪些走隧道，以及每个域名用哪个 DNS 解析。
> **读者：** 需要分流的客户端用户。
> **上级索引：** [指南](README_CN.md) · **English:** [Routing and DNS](ROUTING_AND_DNS.md)

本页讲旧版（也是默认）的分流方式 `client.routing`。需要直连 / 代理 / 拒绝三种动作、关键字和正则匹配、规则集自动更新时，请改用 [策略 v2](POLICY_CLI_CN.md)。两者不能写在同一份配置里。

## 1. 流量如何判定

| 流量 | 判定方式 | 结果 |
|---|---|---|
| IP 数据 | 目标地址是否命中**直连列表**或**路由文件** | 命中：经物理网卡（或路由文件指定的网关）直接发出；未命中：走隧道（TUN 模式）或经隧道转发（代理模式） |
| DNS 查询 | 域名是否命中 **DNS 规则** | 命中：用规则指定的上游服务器，经本地网卡或隧道查询；未命中：按 `dns.intercept-unmatched` 处理（第 5 节） |

TUN 模式和代理模式使用同一套规则，区别只在于 TUN 模式会把规则写进系统路由表和 DNS 设置，代理模式不写。

## 2. 配置写法

```json
"client": {
  "routing": {
    "ip": {
      "bypass": ["./ip.txt", "10.0.0.0/8"],
      "routes": [],
      "peer-routes": []
    },
    "dns": {
      "rules": ["./dns-rules.txt"]
    }
  }
}
```

| 字段 | 作用 |
|---|---|
| `ip.bypass` | 直连列表来源（第 3 节）。 |
| `ip.routes` | 按文件指定网关的路由（第 4 节），常用于多运营商出口。 |
| `ip.peer-routes` | 经某个客户端转发的前缀，见 [对端前缀路由](PEER_PREFIX_ROUTING_CN.md)。 |
| `dns.rules` | DNS 规则来源（第 5 节）。 |

**来源字符串：** `bypass` 和 `rules` 的每个元素先去掉可选的 `file://` 前缀；对应文件存在就读文件，**否则整串当作内联规则**。所以 `"10.0.0.0/8"` 直接就是一条规则，而写错的文件路径会悄悄变成一条无效规则——启动后请确认规则已生效。直连列表**不支持 URL**；需要从网络下载请用 `--virr` 或 `ip.routes[].vbgp`（第 6 节）。

**与命令行的优先级：**

| 配置中 | 使用的来源 |
|---|---|
| 写了 `client.routing` | 只用 `client.routing` 里的来源；`--bypass`、`--dns-rules` 被忽略。 |
| 没写 `client.routing` | `--bypass`（默认 `./ip.txt`）+ `--dns-rules`（默认 `./dns-rules.txt`）+ `client.routes` / `client.peer-routes`。 |

`routing.bypass`、`routing.routes`、`routing.peer-routes`、`routing.dns-rules` 是兼容写法，和嵌套写法同时存在时以嵌套写法为准。

## 3. 直连列表

每行一个 IPv4 地址或 CIDR；`#` 之后为注释；同一行可用逗号、分号或空白分隔多条。只支持 IPv4。

```text
# ip.txt
1.0.1.0/24
1.0.2.0/23
192.168.0.0/16, 172.16.0.0/12
```

生成中国大陆列表：

```bash
./ppp --pull-iplist=ip.txt/CN
```

## 4. 路由文件（多出口）

`ip.routes` 让某个列表里的地址经指定网关发出，而不是默认网关：

```json
"routes": [
  { "path": "./cmcc.txt", "ngw": "192.168.1.1", "nic": "eth1", "vbgp": "https://example.com/cmcc.txt" }
]
```

| 字段 | 说明 |
|---|---|
| `path` | 必填，列表文件（格式同第 3 节）。 |
| `ngw` | 必填，IPv4 网关。 |
| `nic` | 仅 Linux，出口网卡。 |
| `vbgp` | 可选，远程列表 URL，按 `vbgp.update-interval` 定期下载到 `path`（第 6 节）。 |

`path` 或 `ngw` 不合法的条目会被忽略。

## 5. DNS 规则

### 5.1 规则行格式

```text
# 后缀匹配：域名本身及其子域名
example.com/1.1.1.1
# 精确匹配
full:www.example.com/8.8.8.8
# 正则匹配（不区分大小写）
regexp:.*\.example\.net$/cloudflare
# 第三段以 t / v / f / c 开头 = 经隧道查询（如 tun、vpn）；省略或其他 = 经本地网卡
example.org/223.5.5.5/tun
# 只写一个 IP 或提供方名 = 所有域名的默认上游
cloudflare
```

- `#` 之后为注释；`,`、`;`、制表符等同换行。
- 第二段可以是 IP 地址，也可以是内置提供方名称：`doh.pub`、`alidns`、`baidu`、`360`、`114`、`tuna`、`cloudflare`、`google`、`quad9`、`adguard`、`nextdns`、`mullvad`。写提供方名时由内置解析器查询（支持 DoH / DoT），写 IP 时按普通 UDP 转发。
- 对提供方规则，第三段同时表示“国内 / 国外”语义：经本地网卡 = 国内（可附带 ECS），经隧道 = 国外。

社区维护的中国大陆域名规则：[liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt)。

### 5.2 未命中规则的查询与上游设置

| 字段 | 默认 | 说明 |
|---|---|---|
| `dns.intercept-unmatched` | `true` | 未命中的查询依次用 `foreign → domestic → cloudflare` 解析；`false` 时按原目标转发。 |
| `dns.servers.domestic` | `doh.pub` | 国内上游：提供方名、`IP[:端口]`、`{protocol, url, hostname, address, bootstrap}` 对象或它们的数组。 |
| `dns.servers.foreign` | `cloudflare` | 国外上游，格式同上。 |
| `dns.ecs.enabled` / `override-ip` | `false` / 空 | EDNS Client Subnet。 |
| `dns.tls.verify-peer` | `true` | DoH / DoT 证书校验。 |
| `dns.fake-ip.enabled` / `range` | `false` / `198.18.0.1/16` | Fake-IP：立即返回假地址，后台做真实解析。 |
| `udp.dns.ttl` / `udp.dns.cache` | `60` / `true` | 客户端缓存：TTL = `min(响应 TTL, ttl)`；`ttl=0` 或 `cache=false` 关闭缓存。 |

TUN 模式推送给系统的 DNS 地址也由 `dns.servers` 推导（先 foreign 后 domestic），`--dns` 可直接指定。TUN 模式下，程序会为规则中经本地网卡查询的 DNS 服务器添加直连路由，保证默认路由切到隧道后仍能访问它们。

## 6. 自动更新列表（VIRR / vBGP）

| 方式 | 启用 | 行为 |
|---|---|---|
| VIRR | 启动参数 `--virr=ip.txt/CN` | 每隔 `virr.update-interval`（默认 86400 秒）从 APNIC 下载国家 IP 列表；失败后按 `virr.retry-interval`（默认 300 秒）重试。 |
| vBGP | `ip.routes[].vbgp` 写了 URL（`--vbgp` 默认开启） | 每隔 `vbgp.update-interval`（默认 3600 秒）下载该 URL 到对应 `path`。 |

两者都只在列表内容**真的变化**时才写入文件，并且会**重启整个进程**让新列表生效，期间连接会短暂中断。

## 7. 从 GeoIP / GeoSite 生成规则（`geo-rules`）

`geo-rules.enabled: true` 时，客户端启动时从 GeoIP / GeoSite 数据生成直连列表和 DNS 规则文件，再与其他来源一起加载。

```json
"geo-rules": {
  "enabled": true,
  "country": "cn",
  "geoip-dat": "./GeoIP.dat",
  "geosite-dat": "./GeoSite.dat",
  "geoip-download-url": "https://example.com/geoip.dat",
  "geosite-download-url": "https://example.com/geosite.dat",
  "geoip": ["./geoip-extra.txt"],
  "geosite": ["./geosite-extra.txt"],
  "dns-provider-domestic": "doh.pub",
  "output-bypass": "./generated/bypass-cn.txt",
  "output-dns-rules": "./generated/dns-rules-cn.txt",
  "append-bypass": ["10.0.0.0/8"],
  "append-dns-rules": ["internal.example.cn", "rules://./my-dns-rules.txt"]
}
```

| 字段 | 说明 |
|---|---|
| `country` | 提取的国家 / 分类标签，默认 `cn`。 |
| `geoip-dat` / `geosite-dat` | `.dat` 文件路径（默认 `GeoIP.dat` / `GeoSite.dat`）；配置了对应的 `*-download-url` 时启动时下载到这里。 |
| `geoip` / `geosite` | 额外的**本地文本**来源：geoip 每行一个 CIDR；geosite 每行一个域名，支持 `.qq.com`、`domain:`、`suffix:`、`full:`、`regexp:` 前缀。 |
| `dns-provider-domestic` | 生成的 DNS 规则使用的提供方（形如 `域名/<提供方>/nic`）；未设置时取 `dns.servers.domestic`，再退回 `doh.pub`。 |
| `dns-provider-foreign` | 当前生成器不使用（保留）。 |
| `output-bypass` / `output-dns-rules` | 生成文件路径，默认 `./generated/bypass-cn.txt`、`./generated/dns-rules-cn.txt`。 |
| `append-bypass` | 追加在生成结果后的 CIDR 或本地文件。 |
| `append-dns-rules` | 追加的完整规则、纯域名（按国内提供方规范化），或 `rules://路径` 引用的本地文件。**`rules://` 只在这里有效。** |

生成结果先于 `client.routing` 中的显式来源加载。桌面端和 Android 在 TUN 与代理模式下都会运行生成器；iOS 目前不运行生成器。

## 8. 服务端的 DNS 处理

客户端经隧道发出的 DNS 查询到达服务端后：

- 配置了 `udp.dns.redirect`（`IP:端口` 或 `域名:端口`）时，转发到该上游；
- 服务端维护域名缓存（同样受 `udp.dns.ttl` / `udp.dns.cache` 控制），命中时直接应答；
- 否则按原目标转发。

## 9. 排查

| 现象 | 先查 |
|---|---|
| 该直连的地址仍走了隧道 | 规则来源是否真的是文件（路径错会被当成内联文本）；是否同时写了 `client.routing` 导致 `--bypass` 被忽略；列表是 IPv4 格式吗 |
| 国内网站解析到了国外地址 | DNS 规则是否命中；该规则第三段是不是写成了 `tun` |
| 连接时不时断开一下 | 是否启用了 `--virr` / vBGP，列表更新会重启进程 |
| 改了 `geo-rules` 没效果 | 查看 `output-bypass` / `output-dns-rules` 是否被重新生成；iOS 不支持 |

## 相关文档

- [配置文件参考 · client.routing](../reference/CONFIGURATION_CN.md) · [策略 v2](POLICY_CLI_CN.md) · [代理模式](PROXY_MODE_CN.md)
- 实现细节：[客户端架构](../architecture/CLIENT_ARCHITECTURE_CN.md) · [DNS 模块设计](../architecture/DNS_MODULE_DESIGN_CN.md)
