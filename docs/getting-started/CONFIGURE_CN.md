# 编写配置文件

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `ppp/configurations/AppConfiguration.cpp`、`ppp/auxiliary/UriAuxiliary.cpp`）
>
> **用途：** 从零写出一对能互通的服务端 / 客户端配置，并知道下一步该改哪个字段。
> **读者：** 第一次部署 OPENPPP2 的用户。
> **上级索引：** [快速开始](README_CN.md) · **English:** [Writing the configuration file](CONFIGURE.md)

本页只讲“怎么写”。每个字段的完整行为见 [配置文件参考](../reference/CONFIGURATION_CN.md)，命令行参数见 [命令行参考](../reference/CLI_REFERENCE_CN.md)。

## 1. 先弄清四件事

| 问题 | 答案 |
|---|---|
| 配置文件放哪？ | 用 `--config=<路径>` 显式指定。没指定时依次找 `./config.json`、`./appsettings.json`。 |
| 服务端还是客户端？ | 由命令行 `--mode=server` / `client` / `proxy` 决定，**不写 `--mode` 就是服务端**。建议分成 `server.json` 和 `client.json` 两个文件。 |
| 必须写全部字段吗？ | 不用，没写的字段有默认值。但**很多字段省略时是 0 / false**，不一定是你以为的默认值，所以下面最小配置里的字段请全部保留。 |
| 仓库里的 `appsettings.json` 能直接用吗？ | 不能。它是“几乎所有字段”的示例，里面的地址、密钥、证书都是假的。 |

## 2. 第一步：服务端最小配置

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "替换为你自己的随机字符串-1",
    "transport": "aes-256-cfb",
    "transport-key": "替换为你自己的随机字符串-2",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "tcp": { "listen": { "port": 20000 } },
  "server": {
    "node": 1,
    "ipv4-pool": { "network": "10.0.0.0", "mask": "255.255.255.0" }
  }
}
```

启动：

```bash
sudo ./ppp --mode=server --config=./server.json
```

要点：

- `tcp.listen.port` 是客户端连接的端口，防火墙 / 安全组要放行该 TCP 端口。
- `server.ipv4-pool` 让服务端给每个客户端分配一个独立的虚拟 IPv4（Windows / Linux / macOS 客户端会自动应用）。
- **一定要写 `"plaintext": false`。** `key.plaintext` 省略时是 `true`，等于不加密。
- 密钥建议 16 位以上随机字符串；等于 `"ppp"` 或短于 8 字节时启动会打印 `[security] WARN`。

## 3. 第二步：客户端最小配置

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "替换为你自己的随机字符串-1",
    "transport": "aes-256-cfb",
    "transport-key": "替换为你自己的随机字符串-2",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "client": {
    "guid": "{为每台客户端生成一个新的 GUID}",
    "server": "ppp://服务器IP:20000/"
  }
}
```

启动（TUN 模式需要管理员 / root 权限，会修改本机路由和 DNS）：

```bash
sudo ./ppp --mode=client --config=./client.json
```

要点：

- `key` 块直接从服务端复制，**一个字符都不能差**。
- `client.guid` 每台客户端必须不同。生成方法：Linux / macOS 用 `uuidgen`，Windows PowerShell 用 `[guid]::NewGuid()`，外面加上 `{}`。省略时所有客户端共用同一个占位 GUID。
- 只想要本地 HTTP / SOCKS 代理、不接管系统路由：`./ppp --mode=proxy --config=./client.json`，默认在 `127.0.0.1:8080`（HTTP）和 `127.0.0.1:1080`（SOCKS5）监听，见 [代理模式](../guides/PROXY_MODE_CN.md)。

## 4. 两端必须对上的字段

客户端连不上时，最先逐项核对这张表：

| 字段 | 要求 |
|---|---|
| `key.kf` `kx` `kl` `kh` `sb` | 两端完全相同 |
| `key.protocol` / `protocol-key` | 两端完全相同 |
| `key.transport` / `transport-key` | 两端完全相同 |
| `key.masked` `plaintext` `delta-encode` `shuffle-data` | 两端完全相同 |
| 客户端 `client.server` | 承载和端口要对应服务端实际开启的监听（见下表） |

| 客户端 `client.server` 写法 | 服务端需要 |
|---|---|
| `ppp://IP或域名:端口/`（或 `tcp://`） | `tcp.listen.port` = 该端口 |
| `ws://域名[:端口]/路径`（默认端口 80） | `websocket.listen.ws` = 该端口，`websocket.host` 为域名，`websocket.path` = 该路径 |
| `wss://域名[:端口]/路径`（默认端口 443） | `websocket.listen.wss` = 该端口，同上，并配置有效证书 |

## 5. 第三步：按需求加字段

一次只加一项，确认能连通后再加下一项。

### 5.1 改用 WebSocket / WSS（例如放在 Nginx 或 CDN 后面）

服务端增加：

```json
"websocket": {
  "host": "vpn.example.com",
  "path": "/tun",
  "listen": { "ws": 20080, "wss": 20443 },
  "ssl": {
    "certificate-file": "/etc/ppp/vpn.example.com.pem",
    "certificate-chain-file": "/etc/ppp/vpn.example.com.pem",
    "certificate-key-file": "/etc/ppp/vpn.example.com.key"
  }
}
```

客户端改为：

```json
"server": "wss://vpn.example.com:20443/tun"
```

- `websocket.host` **必须是域名**，写 IP 会导致 WS 和 WSS 监听都被关闭。
- 只要 WS（比如由 Nginx 终结 TLS）就不写 `wss` 和 `ssl`。
- 需要指定连接 IP（CDN 优选 IP 等）时写成 `wss://vpn.example.com[203.0.113.10]:443/tun`。

### 5.2 其他常见需求

| 我想要…… | 加 / 改什么 | 详细说明 |
|---|---|---|
| 国内直连、其余走隧道（分流） | 客户端 `client.routing.ip.bypass`、`client.routing.dns.rules` | [配置参考 · client.routing](../reference/CONFIGURATION_CN.md) · [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md) |
| 用规则文件的新版策略（v2） | 客户端 `client.policy`（不能和 `client.routing` 同时写） | [Policy CLI 指南](../guides/POLICY_CLI_CN.md) |
| 在 TUN 模式下顺便开本地代理 | `client.http-proxy.port` / `client.socks-proxy.port`，`bind` 写 `127.0.0.1`（留空会监听所有网卡） | [配置参考 · client](../reference/CONFIGURATION_CN.md) |
| 经过 HTTP / SOCKS 代理连服务器 | `client.server-proxy`：`http://用户:密码@主机:端口/` 或 `socks://主机:端口/` | 同上 |
| 客户端限速 | `client.bandwidth`（单位 Kbps，0 = 不限） | 同上 |
| 把客户端内网服务发布到服务器端口 | `client.mappings`（服务端需 `server.mapping: true`） | 同上 |
| 给客户端分配 IPv6 | 服务端 `server.ipv6` | [IPv6 客户端分配](../guides/IPV6_CN.md) |
| 接入管理后台 | 服务端 `server.backend`、`server.backend-key` | [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) |
| 多链路加速 | 客户端命令行 `--tun-mux=4`；调度模式 `mux.mode` | [配置参考 · mux](../reference/CONFIGURATION_CN.md) |
| 额外的连接认证 | 两端 `transport-auth` + `server/client.transport-auth.enabled` | [配置参考 · transport-auth](../reference/CONFIGURATION_CN.md) |

## 6. 常见错误

| 现象 | 先查 |
|---|---|
| 客户端一直重连 | 第 4 节两张表；服务器端口是否放行；`client.server` 的 IP / 端口 / 前缀 |
| 加了 WebSocket 却连不上 | `websocket.host` 是不是 IP（必须是域名）；`path` 是否以 `/` 开头且与客户端 URL 一致；WSS 证书路径是否可读 |
| 写了 `ppp://ws/...` | 这是旧文档的错误写法，应写 `ws://...` / `wss://...` |
| 启动打印 `plaintext mode enabled` | `key` 里缺少 `"plaintext": false` |
| 多台客户端互相顶掉 | `client.guid` 重复或没写 |
| `--bypass` / `--dns-rules` 不生效 | 配置里写了 `client.routing`，此时命令行这两个参数被忽略 |
| 写了 `client.policy` 后启动失败 | 同时存在 `client.routing`、顶层 `dns`、`udp.dns` 等冲突键 |
| JSON 解析失败 | 去掉注释和末尾多余逗号；文件保存为 UTF-8 |

更多排障见 [运维与排障](../operations/OPERATIONS_CN.md) 和 [错误码](../reference/ERROR_CODES_CN.md)。
