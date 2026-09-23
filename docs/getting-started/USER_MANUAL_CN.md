# 用户手册
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **用途：**说明本主题的当前行为、配置或实现边界。
> **适用对象：**OPENPPP2 用户、运维人员与开发者。
> **当前状态：**当前有效。
> **最后核对依据：**当前仓库结构、实现路径与文档链接，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md) · **English：**[User Manual](USER_MANUAL.md)


[English Version](USER_MANUAL.md)

## 定位

本文是面向使用者的 OPENPPP2 运行手册，涵盖 OPENPPP2 是什么、如何运行、如何为常见场景配置，以及预期宿主变化。

---

## OPENPPP2 是什么

OPENPPP2 是一个单二进制、多角色、跨平台的虚拟网络运行时。它能以 client、proxy-only 客户端或 server 运行，并可叠加路由、DNS steering、反向映射、静态数据路径、MUX、平台集成以及可选管理后端。

```mermaid
flowchart TD
    A[OPENPPP2] --> B[客户端模式]
    A --> C[服务端模式]
    B --> D[虚拟 NIC + 隧道]
    B --> E[分流或全隧道路由]
    B --> F[DNS steering]
    B --> G[MUX / Static UDP]
    C --> H[会话路由]
    C --> I[TCP + UDP 转发]
    C --> J[IPv6 transit]
    C --> K[可选 Go backend]
```

---

## 先决定什么

在写配置和运行命令之前，先决定：

| 决策 | 选项 | 说明 |
|------|------|------|
| 节点角色 | `client`、`proxy-only` 客户端或 `server` | 在有公网 IP 的机器上运行**服务端**；在需要经服务端转发流量的机器上运行**客户端**；只想要本地 HTTP/SOCKS 代理而不修改系统路由时，选 **proxy-only**。 |
| 宿主平台 | Linux、Windows、macOS、Android、iOS | 决定下载哪个二进制及所需权限 |
| 隧道模式 | 全隧道或分流 | **全隧道**：所有流量走服务端。**分流**：只有指定 IP（如境外 IP）走隧道，其余直连。 |

---

## 基本运行模型

| 场景 | 命令 |
|------|------|
| 以服务端启动（默认） | `./ppp` |
| 以服务端启动并指定配置 | `./ppp --config=/etc/openppp2/appsettings.json` |
| 以客户端启动 | `./ppp --mode=client` |
| 以客户端启动并指定配置 | `./ppp --mode=client --config=./appsettings.json` |
| 以 proxy-only 客户端启动 | `./ppp --mode=proxy --config=./appsettings.json` |

要求：
- Windows 上的全隧道客户端/服务端宿主集成需要管理员权限；Linux/macOS 需要 root/CAP_NET_ADMIN。
- 桌面 proxy-only 使用 `TapStub`，不安装宿主路由，通常不需要接管网络的 root 权限；Android/iOS 仍需要平台 VPN 授权/entitlement 流程。
- 配置文件在可访问的路径上。

---

## 宿主会被改什么

根据平台、角色和路由模式，OPENPPP2 可能修改：

| 宿主元素 | 客户端（TUN） | 客户端（proxy-only） | 服务端 |
|---------|--------------|---------------------|--------|
| 虚拟 NIC | 会创建 | 桌面使用 `TapStub`；移动端使用系统框架接口 | 不创建 |
| OS 路由表 | 可能添加/保护 TUN 和策略路由 | 桌面不安装宿主路由；移动端只保留最小 interface/subnet 路由 | 不修改 |
| DNS 配置 | 可能配置隧道/系统 DNS | native DNS rules 仍生效，但不接管系统 DNS | 不修改 |
| 系统 HTTP 代理 | 仅在平台/辅助路径明确配置时设置 | 不自动发布；需手动配置本地 HTTP/SOCKS listener | 不设置 |
| IPv6 设置 | 如果启用 TUN IPv6 | 不接管宿主 IPv6 或系统 DNS | 如果启用 `server.ipv6` |
| 防火墙规则 | 不修改 | 不修改 | 可能设置规则 |

路由模式改变的是宿主集成，而不是 native client policy。两种模式下都会加载 `client.routing` 的 bypass、普通路由、peer-prefix 路由和 DNS 规则；proxy-only 只是不接管桌面宿主路由和系统 DNS。

**Android 和 iOS（proxy-only 模式）的特殊说明：**

- VPN 框架只保留最小 interface/subnet 路由。
- 不自动发布默认路由、系统 DNS 或本地 HTTP 代理。
- native bypass 和 DNS policy 仍会加载。
- Android 不能将本地 HTTP 代理发布为 VPN 系统代理——原生 listener 只能在 VPN 建立后才能保留端口，提前发布可能被其他本地应用截获代理流量。请使用全隧道模式，或将可信客户端手动指向本地 HTTP/SOCKS 地址。

---

## 推荐阅读顺序

1. [`ARCHITECTURE_CN.md`](../architecture/ARCHITECTURE_CN.md) — 系统整体设计
2. [`STARTUP_AND_LIFECYCLE_CN.md`](../architecture/STARTUP_AND_LIFECYCLE_CN.md) — 进程如何启动和停止
3. [`CONFIGURATION_CN.md`](../reference/CONFIGURATION_CN.md) — 配置文件参考
4. [`CLI_REFERENCE_CN.md`](../reference/CLI_REFERENCE_CN.md) — 命令行参数
5. [`PLATFORMS_CN.md`](../guides/PLATFORMS_CN.md) — 平台特定说明
6. [`DEPLOYMENT_CN.md`](../operations/DEPLOYMENT_CN.md) — 部署检查清单
7. [`OPERATIONS_CN.md`](../operations/OPERATIONS_CN.md) — 故障排查

---

## 快速开始

### 服务端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 获取发布包 | `openppp2-linux-amd64-simd.zip` |
| 2 | 解压并进入目录 | `mkdir -p openppp2 && cd openppp2` |
| 3 | 编辑服务端配置 | 设置 `tcp.listen.port`、`key.*` 字段 |
| 4 | 启动运行时 | `sudo ./ppp` |

最简服务端配置：

> **⚠ 安全提示：** 部署前必须替换示例中的 `protocol-key` 和 `transport-key`，下方的值仅为占位符，不得用于生产环境。

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true
  }
}
```

### 客户端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 创建安装目录 | `mkdir -p /opt/openppp2` |
| 2 | 解压发布包 | `unzip openppp2-linux-amd64.zip -d /opt/openppp2` |
| 3 | 编辑客户端配置 | 设置 `client.guid`、`client.server`、`key.*`（需与服务端匹配） |
| 4 | 以 root 启动 | `sudo ./ppp --mode=client` |

最简客户端配置：

> **⚠ 安全提示：** 使用与服务端相同的 `protocol-key` 和 `transport-key`，并自行生成唯一密钥。

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "client": {
    "guid": "{F4519CF1-7A8A-4B00-89C8-9172A87B96DB}",
    "server": "ppp://192.168.0.1:20000/"
  }
}
```

---

## 隧道模式选择

```mermaid
flowchart TD
    A[选择运行模式] --> B{--mode=proxy 或 client.proxy-only？}
    B -->|是| C[Proxy-only 模式]
    B -->|否| D[TUN 客户端模式]
    C --> E[本地 HTTP/SOCKS + native policy\n不接管宿主路由/DNS]
    D --> F{所有流量经隧道？}
    F -->|是| G[全隧道模式]
    F -->|否| H[分流 / DNS steering]
    G --> I[配置 canonical IP/DNS policy]
    H --> I
```

| 模式 | 说明 | 关键配置 |
|------|------|---------|
| 全隧道 | 所有流量经 TUN policy | `--mode=client`，且不配置 bypass 项 |
| 分流 | 指定 IP 绕过隧道，同时 native route policy 仍生效 | `--mode=client`；`client.routing.ip.bypass`、`ip.routes` 或 `ip.peer-routes` |
| DNS steering | 在 native DNS policy 中按域名选择 resolver | `client.routing.dns.rules` |
| Proxy-only | 本地 HTTP/SOCKS 入口使用 native bypass/route/DNS policy；不接管宿主路由或系统 DNS | `--mode=proxy` 或 `client.proxy-only: true` |
| 服务发布 | 服务端通过 FRP 发布本地服务 | `server.mappings` |
| IPv6 服务 | 服务端提供 IPv6 transit | `server.ipv6` |

---

## 配置参考重点

### 核心字段

| 参数 | 类型 | 示例 | 说明 | 适用范围 |
|------|------|------|------|---------|
| `concurrent` | int | `4` | IO 线程并发数 | 两者 |
| `key.kf` | int | `154543927` | 协议密钥因子 | 两者 |
| `key.protocol` | string | `"aes-128-cfb"` | 加密算法 | 两者 |
| `key.transport` | string | `"aes-256-cfb"` | 传输加密算法 | 两者 |

### 客户端字段

| 参数 | 类型 | 示例 | 说明 |
|------|------|------|------|
| `client.guid` | string | `"{F4519CF1-...}"` | 客户端唯一标识符 |
| `client.server` | string | `"ppp://192.168.0.1:20000/"` | 服务端连接地址 |
| `client.server-proxy` | string | `"http://user:pass@proxy:8080/"` | 连接服务端的代理 |
| `client.bandwidth` | int | `10000` | 带宽限制，Kbp/s |
| `client.proxy-only` | bool | `false` | 独立运行标志；抑制宿主接管但不关闭 native policy；`--mode=proxy` 选择相同行为 |
| `client.routing` | object | `{ "ip": ..., "dns": ... }` | 只承载 canonical IP/DNS policy；旧的嵌套 mode 字段会被忽略且不序列化 |
| `client.routing.ip.bypass` | array | `["file:///etc/bypass.txt"]` | native bypass policy 来源，两种模式都生效 |
| `client.routing.ip.routes` | array | `[]` | native 普通 route 来源；桌面宿主投影另行处理 |
| `client.routing.ip.peer-routes` | array | `[]` | native peer-prefix route 来源 |
| `client.routing.dns.rules` | array | `["file:///etc/dns.txt"]` | native DNS policy 来源，两种模式都生效 |

### 服务端字段

| 参数 | 类型 | 示例 | 说明 |
|------|------|------|------|
| `server.node` | int | `1` | 服务端节点 ID |
| `tcp.listen.port` | int | `20000` | TCP 隧道监听端口 |
| `websocket.listen.ws` | int | `20080` | WebSocket 监听端口（0 = 禁用） |
| `websocket.listen.wss` | int | `20443` | TLS WebSocket 监听端口（0 = 禁用） |
| `server.backend` | string | `"ws://backend:80/ppp/webhook"` | 可选管理后端 |
| `server.ipv4-pool.network` | string | `"10.0.0.0"` | IPv4 地址池（客户端分配用） |
| `server.ipv4-pool.mask` | string | `"255.255.255.0"` | IPv4 地址池子网掩码 |

---

## DNS 规则

| 项目 | 说明 | 链接 |
|------|------|------|
| 主 DNS rules list | 定期更新的中国大陆域名直连规则 | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

DNS 规则文件格式——支持两种写法：

**传统 IP 目标格式**（将域名直接路由到指定 DNS 服务器 IP）：
```
# 将指定域名路由到某个 DNS IP
.example.com 192.168.1.1
.google.com 8.8.8.8
```

**推荐 Provider 格式**（将域名路由到命名 provider，支持 DoH/DoT）：
```
# 通过内置 cloudflare provider 解析
.google.com /cloudflare/tun
# 通过 doh.pub 解析
.cn /doh.pub/tun
```

推荐使用 provider 格式。Provider 名称在 `dns` 块中配置。详见 [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)。

---

## HTTPS 证书配置

| 项目 | 说明 | 位置 |
|------|------|------|
| 运行时根证书 | 将 `cacert.pem` 放入运行目录 | `ppp` 旁边的 `cacert.pem` |
| 镜像仓库 | 证书备用来源 | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | 官方 CA 提取页 | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

---

## 常见场景

### 场景 1：Linux 全隧道客户端

```bash
# 1. 安装
mkdir -p /opt/openppp2
cd /opt/openppp2
unzip openppp2-linux-amd64-simd.zip

# 2. 编辑 appsettings.json — 设置 client.server 和 key 字段

# 3. 运行
sudo ./ppp --mode=client
```

预期效果：所有流量经服务端转发。

### 场景 2：带中国大陆分流的客户端

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://server-ip:20000/",
    "proxy-only": false,
    "routing": {
      "ip": {
        "bypass": ["file:///opt/openppp2/rules/china-cidr.txt"],
        "routes": [],
        "peer-routes": []
      },
      "dns": { "rules": [] }
    }
  }
}
```

预期效果：中国大陆 IP 直连，其余流量走隧道。
启用 `--mode=proxy` 或 `client.proxy-only` 后，纯代理模式仍使用相同的 native bypass/route/DNS policy，
但桌面不接管宿主路由和系统 DNS；请将可信任客户端配置为使用本地 HTTP/SOCKS listener。

### 场景 3：带管理 Backend 的服务端

```json
{
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true,
    "backend": "ws://192.168.0.100/ppp/webhook"
  }
}
```

预期效果：客户端会话由 Go backend 认证并计费。

### 场景 4：Nginx 反向代理的 WebSocket 服务端

```json
{
  "websocket": {
    "host": "your-domain.com",
    "path": "/tun",
    "listen": {
      "ws": 8080
    }
  }
}
```

然后配置 Nginx 将 WebSocket 代理到 8080 端口。

客户端连接字符串：

```
ppp://ws/192.168.0.1:443/
```

---

## 连接 URL 格式

| 格式 | 协议 | 示例 |
|------|------|------|
| `ppp://host:port/` | 原始 TCP | `ppp://1.2.3.4:20000/` |
| `ppp://ws/host:port/` | WebSocket | `ppp://ws/1.2.3.4:443/` |
| `ppp://wss/host:port/` | TLS WebSocket | `ppp://wss/1.2.3.4:443/` |

---

## 附录 1：UDP 静态聚合器

UDP 静态聚合器将多条 UDP 链路绑定为单条隧道，提升吞吐量和冗余度。

| 参数 | 类型 | 示例值 | 说明 | 适用范围 |
|------|------|--------|------|---------|
| `udp.static.aggligator` | int | `4` | 聚合链路数 | `client` |
| `udp.static.servers` | array | `["1.0.0.1:20000"]` | 聚合或转发服务器列表 | `client` |

| 条件 | 含义 |
|------|------|
| `udp.static.aggligator > 0` | 启用聚合器模式，必须配置 `servers` |
| `udp.static.aggligator <= 0` | 启用静态隧道模式 |

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

---

## 附录 2：Linux 路由转发

### 开启 IPv4 和 IPv6 转发

向 `/etc/sysctl.conf` 添加：

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
```

应用：

```bash
sysctl -p
```

### 双网卡路由示例

```bash
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### 分流绕过示例（SNAT）

```bash
iptables -A FORWARD -s 192.168.0.0/24 -d 0.0.0.0/0 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -d 192.168.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to 192.168.0.20
```

---

## 附录 3：Windows 软路由转发

| 项目 | 示例 |
|------|------|
| 虚拟网关工具 | VGW |
| 下载地址 | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

VGW 示例参数：

| 参数 | 类型 | 示例值 | 说明 |
|------|------|--------|------|
| `--ip` | string | `192.168.0.40` | 虚拟网关 IP |
| `--ngw` | string | `192.168.0.1` | 主路由网关 |
| `--mask` | string | `255.255.255.0` | 子网掩码 |
| `--mac` | string | `30:fc:68:88:b4:a9` | 自定义虚拟 MAC |

---

## 附录 4：Android 部署

Android 部署使用 VPNService API。OPENPPP2 以原生库形式嵌入：

```mermaid
flowchart TD
    A[Android App] --> B[VPNService]
    B --> C[JNI 桥接]
    C --> D[OPENPPP2 C++ 运行时]
    D --> E[连接到服务端的隧道]
```

关键点：
- 需要在 `AndroidManifest.xml` 中声明 `BIND_VPN_SERVICE` 和 `INTERNET` 权限。
- JNI 函数：`run(config_json)`、`stop()`、`release()`。
- 不需要 root；使用 Android VPNService 框架。
- 错误码以整数返回，映射到 `ppp::diagnostics::ErrorCode`。

---

## 附录 5：IPv6 Transit（服务端 IPv6 中转）

在服务端启用 IPv6 transit：

```json
{
  "server": {
    "ipv6": {
      "cidr": "fdec:1234::/64"
    }
  }
}
```

这允许客户端获得 IPv6 地址，并通过服务端访问 IPv6 目标。

详见 [`IPV6_TRANSIT_PLANE_CN.md`](../guides/IPV6_TRANSIT_PLANE_CN.md)。

---

## 附录 6：FRP 反向映射（服务发布）

通过服务端发布本地服务：

```json
{
  "server": {
    "mappings": [
      {
        "local-ip": "127.0.0.1",
        "local-port": 22,
        "remote-port": 10022,
        "protocol": "tcp"
      }
    ]
  }
}
```

这会将 `localhost:22` 发布为服务端的 `server-ip:10022`。

---

## 故障排查速查

| 症状 | 最可能原因 | 解决方式 |
|------|---------|---------|
| 进程立即退出 | 权限缺失 | 以 root/管理员运行 |
| "configuration not found" | 配置路径错误 | 使用 `--config=/绝对路径` |
| 无法连接服务端 | 网络或防火墙 | 先用 `nc` 或 `telnet` 测试 |
| 隧道内 DNS 不工作 | DNS 路由缺失 | 检查 bypass 列表是否覆盖 DNS 服务器 |
| 会话频繁断开 | 保活失败 | 检查 `keepalive.*` 配置值 |
| 退出后路由未恢复 | 强制杀进程 | 使用 SIGTERM 优雅关闭 |

---

## 相关文档

- [`CONFIGURATION_CN.md`](../reference/CONFIGURATION_CN.md)
- [`CLI_REFERENCE_CN.md`](../reference/CLI_REFERENCE_CN.md)
- [`DEPLOYMENT_CN.md`](../operations/DEPLOYMENT_CN.md)
- [`OPERATIONS_CN.md`](../operations/OPERATIONS_CN.md)
- [`PLATFORMS_CN.md`](../guides/PLATFORMS_CN.md)
- [`ROUTING_AND_DNS_CN.md`](../guides/ROUTING_AND_DNS_CN.md)
- [`SECURITY_CN.md`](../operations/SECURITY_CN.md)
- [`MANAGEMENT_BACKEND_CN.md`](../guides/MANAGEMENT_BACKEND_CN.md)
