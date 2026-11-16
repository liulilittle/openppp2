# 配置文件参考

> Status: Active
> Type: Reference
> Last verified: 2026-10-11（对照 `ppp/configurations/AppConfiguration.cpp` 的 `Clear()` / `Load()` / `Loaded()`）
>
> **用途：** `appsettings.json` 每个字段的类型、省略时的实际值、作用端和校验规则。
> **读者：** 需要查某个字段确切行为的用户和运维。
> **上级索引：** [参考](README_CN.md) · **English:** [Configuration reference](CONFIGURATION.md)

第一次写配置请先看 [编写配置文件](../getting-started/CONFIGURE_CN.md)；本页是逐字段查阅用的。命令行参数见 [CLI 参考](CLI_REFERENCE_CN.md)。

## 1. 加载过程

1. 定位文件：`--config=<路径>`（别名 `-c`、`--c`、`-config`）指向的可读文件；否则依次尝试 `./config.json`、`./appsettings.json`。某个候选解析失败时会继续尝试下一个。
2. `Clear()` 写入内置初值。
3. `Load()` 读取 JSON。**注意：** 很多字段是“无条件读取”的——JSON 里没有这个键时读到的是 `0` / `false` / 空字符串，会覆盖内置初值，再由下一步修正。所以下表“省略时”一列写的是**省略后最终生效的值**，不是 `Clear()` 里的初值。
4. `Loaded()` 规范化：裁剪空白、把越界端口归零、非法值回退、关闭条件不满足的监听等。规范化**不会因为值不合法而报错退出**，而是静默修正；只有 `client.policy` 冲突、`transport-auth` 非法和平台不支持的服务端 IPv6 模式会让这份配置加载失败。
5. 命令行参数覆盖一部分运行时行为（`--mux-mode`、`--mode=proxy`、`--proxy-*-port` 等）。

JSON 必须是标准 JSON（不能有注释、不能有尾逗号）。

## XTCP 运行时调优

客户端在启用 XTCP 的构建中选择 `--tcp-stack=xtcp` 后，Linux、Windows x64
和 Android 的 XTCP 每连接 `snd_buf` 配额默认为 1 MiB。它是配额，不会为每条连接
预先分配内存。macOS 和 iOS 当前不支持 XTCP 构建。此项不是
`appsettings.json` 字段；启动 `ppp` 前设置进程环境变量：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `OPENPPP2_XTCP_SNDBUF_BYTES` | 1 MiB | 以字节为单位显式设置发送缓冲配额（小于 1024 的值会忽略）。优先于默认值和吞吐 profile。 |
| `OPENPPP2_XTCP_DL_GSO_PERF_PROFILE` | 未设置 | 精确值为 `1` 且 `OPENPPP2_XTCP_SNDBUF_BYTES` 未设置或无效时，选择 2 MiB 配额。 |

该 1 MiB 默认值沿用 #109 在 Linux 上引入的调优，并应用于当前支持 XTCP
的所有平台。吞吐 profile 仍需显式启用。

## 2. 作用端速查

| 块 | 服务端 | 客户端 | 说明 |
|---|:-:|:-:|---|
| `key` | ✔ | ✔ | 两端必须完全一致 |
| `concurrent` `tcp` `udp` `mux` `vmem` `telemetry` | ✔ | ✔ | 各自本地生效 |
| `websocket` | ✔ | — | 只用于服务端监听；客户端的 WS 路径写在 `client.server` URL 里 |
| `ip` `cdn` `server` | ✔ | 部分 | 客户端配置里写 `server.ipv4-pool` 表示主动请求地址分配 |
| `client` `dns` `routing` `geo-rules` `virr` `vbgp` | — | ✔ | |
| `p2p` | ✔ | ✔ | |
| `transport-auth` | ✔ | ✔ | 开关分别是 `server.transport-auth.enabled` / `client.transport-auth.enabled` |

## 3. 顶层字段

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `concurrent` | int | CPU 核数 | 工作线程数，`< 1` 时取 CPU 核数。服务端额外创建 `concurrent-1` 个 I/O 线程；客户端只影响调度器数量。 |
| `cdn` | int[2] | `[0, 0]` | 服务端额外的两个 TCP 监听端口（CDN / SNI 转发入口）。`0` = 关闭，越界归零。 |

## 4. `key` —— 加密与混淆（两端必须一致）

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `kf` | int | `0` | 头部混淆参数。**省略时是 0，不是 154543927**；两端一致即可，建议显式写出。 |
| `kx` | int | `0` | 混淆参数，`< 0` 归零。 |
| `kl` | int | `0` | 混淆参数，限制在 `0..16`。 |
| `kh` | int | `0` | 混淆参数，限制在 `0..16`。 |
| `sb` | int | `0` | 混洗块大小，限制在 `0..5536`。 |
| `protocol` | string | `aes-128-cfb` | 协议层（握手/控制）加密算法，OpenSSL 算法名。不支持的名字回退为 `aes-128-cfb`。 |
| `protocol-key` | string | `"ppp"` | 协议层密钥。空串回退为 `"ppp"`。 |
| `transport` | string | `aes-256-cfb` | 传输层（数据）加密算法，不支持时回退为 `aes-256-cfb`。 |
| `transport-key` | string | `"ppp"` | 传输层密钥。空串回退为 `"ppp"`。 |
| `plaintext` | bool | **`true`** | `true` 表示**不加密**。省略即明文，务必显式写 `false`。 |
| `masked` | bool | `true` | 载荷掩码。 |
| `delta-encode` | bool | `true` | 差分编码。 |
| `shuffle-data` | bool | `true` | 字节混洗。 |
| `simd-auto` | bool | `true` | 自动选择 SIMD 加速实现，仅本地生效，不需要两端一致。 |

启动时打印 `[security] WARN` 的情况（只警告、不阻止启动）：

- 任一密钥等于默认值 `"ppp"`，或短于 8 字节；
- `plaintext` 为 `true`；
- 算法属于 RC4 / DES / Blowfish / CAST5 / SEED / IDEA，或密钥长度低于 128 位。

## 5. `transport-auth` —— 传输层预共享密钥认证（可选）

在 `key` 之外，再用 32 字节预共享密钥对连接做认证。默认关闭。

```json
"transport-auth": {
  "handshake-timeout-ms": 5000,
  "keys": [
    { "id": "k2026a", "state": "active", "secret-file": "/etc/ppp/k2026a.hex" }
  ]
},
"server": { "transport-auth": { "enabled": true } }
```

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `transport-auth.handshake-timeout-ms` | int | `5000` | 限制在 `1000..30000`。 |
| `transport-auth.keys[]` | array | 空 | 最多 8 个；`keys` 不是数组或元素不是对象时加载失败。 |
| `keys[].id` | string | — | 1–63 个字符，小写字母或数字开头，只能包含 `a-z 0-9 . _ -`，不得重复。 |
| `keys[].state` | string | — | `active`、`verify-only` 或 `revoked`。启用时必须**恰好一个** `active`；`verify-only` 最多 2 个（用于轮换）。 |
| `keys[].secret-file` | path | — | `active` / `verify-only` 必填。内容必须恰好是 64 个小写十六进制字符（无换行）；必须是普通文件、属于当前用户、组和其他用户无任何权限（`chmod 600`）。**Windows 不支持读取 secret-file。** |
| `server.transport-auth.enabled` / `client.transport-auth.enabled` | bool | `false` | 分别在服务端 / 客户端启用。 |

## 6. `tcp`

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `listen.port` | int | `0` | 服务端 TCP 隧道端口，对应客户端 `ppp://` / `tcp://` 地址。`0` 或越界 = 不监听。 |
| `backlog` | int | `511` | 监听队列长度，`< 1` 时取 511。 |
| `connect.timeout` | int（秒） | `5` | 出站 TCP 连接超时，`< 1` 时取 5。 |
| `connect.nexcept` | int | `4` | 连接重试计数，`< 0` 时取 4。 |
| `inactive.timeout` | int（秒） | `300` | TCP 中继空闲超时，`< 1` 时取 300。 |
| `turbo` | bool | `false` | 设置 `TCP_NODELAY`。 |
| `fast-open` | bool | `false` | 启用 TCP Fast Open（平台支持时）。 |
| `cwnd` / `rwnd` | int | `0` | 套接字发送 / 接收缓冲区大小，`0` = 系统默认。 |

## 7. `udp`

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `listen.port` | int | `0` | 服务端 UDP 端口（静态 UDP 隧道 `--tun-static` 使用）。 |
| `inactive.timeout` | int（秒） | `72` | UDP 中继空闲超时，`< 1` 时取 72。 |
| `dns.timeout` | int（秒） | `4` | 经隧道转发的 DNS 查询超时，`< 1` 时取 4。 |
| `dns.ttl` | int（秒） | `60` | DNS 缓存 TTL 上限，实际 TTL = `min(响应 TTL, ttl)`；`0` 关闭缓存写入。 |
| `dns.cache` | bool | `true` | DNS 缓存开关，仍需 `ttl > 0`。 |
| `dns.turbo` | bool | `false` | 启用内置 vdns 快速解析。 |
| `dns.redirect` | string | 空 | 服务端把客户端 DNS 查询重定向到该 `IP:端口` 或 `域名:端口`；格式非法时清空。 |
| `static.keep-alived` | int[2]（秒） | `[0, 0]` | 静态 UDP 保活间隔范围，负数归零。 |
| `static.dns` / `static.quic` / `static.icmp` | bool | `true` | 静态模式下是否承载 DNS / QUIC / ICMP。 |
| `static.aggligator` | int | `0` | 静态 UDP 聚合链路数，负数归零。 |
| `static.servers` | string[] | 空 | 静态 UDP 服务器 `IP:端口` 列表（兼容旧键 `static.server`）。 |
| `cwnd` / `rwnd` | int | `0` | 套接字缓冲区大小。 |

## 8. `mux` —— 多路复用

MUX 是否启用、开几条连接由客户端命令行 `--tun-mux=<连接数>` 决定（默认 0 = 关闭），JSON 里没有连接数字段。

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `mode` | string | `compat` | 调度模式：`compat`（默认，原始行为）、`flow`（低延迟）、`balance`（按流有序的负载均衡）、`stripe`（实验性）。别名：`legacy`/`default`→compat，`flow-v1`/`primary`/`primary-link`→flow，`balanced`/`lb`/`load-balance`→balance，`striped`/`striping`→stripe。无法识别时回退 `compat` 并打印警告。可被 `--mux-mode` 覆盖。 |
| `turbo` | bool | `false` | 仅在 `flow` 下有意义：首包选最佳链路 + 预热链路。可被 `--mux-mode-turbo` 覆盖。 |
| `connect.timeout` | int（秒） | `20` | 子连接建立超时。 |
| `inactive.timeout` | int（秒） | `60` | 子连接空闲超时。 |
| `keep-alived` | int[2]（秒） | `[0, 0]` | 保活间隔范围，负数归零。 |
| `congestions` | int（字节） | `134217728` | 拥塞窗口预算；`0` 表示不限制，小于 1 MiB 的正数或负数回退为默认值。 |
| `flow.reorder.bytes` | int | `8388608` | 每连接重排缓冲软上限：超过后暂停读取送来该帧的链路（反压），超过 2 倍才重置该连接。 |
| `flow.reorder.timeout` | int（毫秒） | `400` | 缺口等待超时（flow_v2 按连接，compat 按会话），从最近一次按序交付开始计时。 |
| `flow.session_reorder.bytes` | int | `33554432` | 会话级重排缓冲软上限：超过后暂停读取送来该帧的链路；超过 2 倍才重置连接（flow_v2）或重建会话（compat）。 |
| `flow.max_open` | int | `4096` | 最大逻辑流数。 |
| `flow.unknown_cid.max` | int | `64` | 未知流 ID 容忍数。 |
| `tx.queue.max` | int（帧） | `4096` | 发送队列高水位，达到后对读取限流。 |
| `tx.queue.stall` | int（毫秒） | `8000` | 发送队列持续积压超过该时间则重建会话。 |
| `tx.ctrl.budget_frames` | int | `32` | 每轮优先发送的控制帧数。 |
| `reliability.enabled` | bool | `true` | 协商可靠传输（重传）。 |
| `reliability.rtx.bytes` | int | `33554432` | 会话级重传发送窗口（未确认字节）；满时帧留在队列中等待，超过 2 倍才重建会话。吞吐上限约为 窗口 / RTT。 |
| `reliability.rtx.flow_bytes` | int | `8388608` | flow_v2 下的单流发送窗口（不超过 `reliability.rtx.bytes`）；单条连接上限约为 该值 / RTT。 |
| `reliability.rtx.max_attempts` | int | `8` | 单帧最大重传次数。 |
| `reliability.rtx.pto` | bool | `false` | 超时（PTO）重传。默认关闭：承载链路是可靠字节流，PTO 多数只是把还排在慢链路后面的帧重发一遍。链路断开时，其上未确认的帧总会在剩余链路上补发。 |
| `reliability.rtx.fast` | bool | `false` | dup-ACK 快速重传。默认关闭：跨链路乱序不等于丢包。 |
| `reliability.ack.delay` | int（毫秒） | `10` | 延迟 ACK 上限。 |
| `reliability.gap.timeout` | int（毫秒） | `3000` | 启用可靠传输时的缺口超时。 |
| `fec.enabled` | bool | `false` | XOR 前向纠错。 |
| `fec.group` | int | `8` | 每组数据帧数。 |
| `fec.flush` | int（毫秒） | `20` | 未满分组的最长等待时间。 |
| `debug.key` | string | 空 | 调试用共享密钥；两端相同且非空时可用 `--mux-mode-set` 远程切换调度模式。可被 `--debug-key` 覆盖。 |

除 `keep-alived` 和 `congestions` 外，上表数值字段 `<= 0` 时都回退为表中的值。

## 9. `websocket` —— 服务端 WS / WSS 监听

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `host` | string | 空 | **必须是域名**（不能是 IP）。为空或不是域名时 WS 和 WSS 都被关闭。 |
| `path` | string | 空 | 必须以 `/` 开头，例如 `/tun`。不满足时 WS 和 WSS 都被关闭。 |
| `listen.ws` | int | `0` | 明文 WebSocket 端口，对应客户端 `ws://`。 |
| `listen.wss` | int | `0` | TLS WebSocket 端口，对应客户端 `wss://`。证书校验失败时被关闭。 |
| `ssl.certificate-file` | path | 空 | 证书文件。 |
| `ssl.certificate-key-file` | path | 空 | 私钥文件。 |
| `ssl.certificate-chain-file` | path | 空 | 证书链文件。 |
| `ssl.certificate-key-password` | string | 空 | 私钥密码。 |
| `ssl.ciphersuites` | string | 内置 TLS 1.3 套件 | 为空时使用内置值。 |
| `ssl.verify-peer` | bool | `true` | 兼容旧位置 `websocket.verify-peer`。 |
| `http.error` | string | 空 | 非 WebSocket 请求返回的错误文本。 |
| `http.request` / `http.response` | object | 空 | 自定义 HTTP 头（键值对）。 |

`listen.ws` 为 0 时，`host`、`path`、`http.*` 会被清空；`listen.wss` 为 0 时，证书字段会被清空。

## 10. `ip`（服务端）

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `interface` | string | 空 | 监听绑定的本机地址；空 = 所有地址。不是合法 IP 时清空。 |
| `public` | string | 空 | 服务器公网 IP，用于 CDN 转发防回环判断和状态显示。 |

## 11. `server`

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `node` | int | `0` | 节点编号，负数归零。 |
| `log` | path | 空 | 会话日志文件，转换为绝对路径；空 = 不写。 |
| `subnet` | bool | `true` | 允许客户端之间通过虚拟子网互通。 |
| `mapping` | bool | `true` | 允许客户端端口映射（`client.mappings`）。 |
| `backend` | string | 空 | 管理后端 WebSocket 地址，见 [管理后端](../guides/MANAGEMENT_BACKEND_CN.md)。 |
| `backend-key` | string | 空 | 管理后端密钥。 |
| `ipv4-pool.network` / `ipv4-pool.mask` | string | 未配置 | 写了 `ipv4-pool` 对象就启用：服务端从该网段给每个会话分配虚拟 IPv4（Windows / Linux / macOS 客户端会把它应用到虚拟网卡）。网段或掩码非法时只记录日志、不分配。 |
| `ipv6.mode` | string | 关闭 | `nat66` 或 `gua`，其他值 = 关闭。当前平台不支持服务端 IPv6 数据面时**加载失败**。 |
| `ipv6.cidr` | string | 空 | 前缀，如 `fd42:4242:4242::/64`。`nat66` 未填时使用内置 ULA /64；`gua` 必须是全球单播前缀。前缀非法时关闭 IPv6。 |
| `ipv6.gateway` | string | 前缀内第一个地址 | 不在前缀内时忽略。 |
| `ipv6.dns1` / `ipv6.dns2` | string | 空 | 下发给客户端的 IPv6 DNS。 |
| `ipv6.lease-time` | int（秒） | `300` | 租约时间，负数归零。 |
| `ipv6.static-addresses` | object | 空 | `{ "<客户端GUID>": "<IPv6地址>" }`；不在前缀内或重复的条目被丢弃。 |
| `peer-routing.enabled` | bool | `false` | 客户端前缀路由，见 [对端前缀路由](../guides/PEER_PREFIX_ROUTING_CN.md)。 |
| `peer-routing.distribute` | bool | `true` | 向客户端分发路由表。 |
| `peer-routing.allowed-routes[]` | array | 空 | 宣告白名单，元素为 `{network, prefix, guid}`：只接受 GUID 与前缀完全一致的宣告。**为空时所有宣告都被拒绝。** |
| `session_resume.enabled` | bool | `false` | 允许断线会话在宽限期内恢复。 |
| `session_resume.grace_ms` | int（毫秒） | `60000` | 宽限期，限制在 `1000..3600000`。 |
| `transport-auth.enabled` | bool | `false` | 见第 5 节。 |

IPv6 详见 [IPv6 客户端分配](../guides/IPV6_CN.md)。

## 12. `client`

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `guid` | string | 全 F 的哨兵 GUID | 客户端身份，形如 `{F4569208-BB45-4DEB-B115-0FEA1D91B85B}`。**每台客户端必须不同**；省略时所有客户端共用同一个哨兵值。 |
| `server` | string | 空 | 服务器地址，格式见第 17 节。 |
| `server-proxy` | string | 空 | 经代理连接服务器，只接受 `http://[用户:密码@]主机:端口/` 或 `socks://[用户:密码@]主机:端口/`。 |
| `bandwidth` | int（Kbps） | `0` | 限速，`0` = 不限，负数归零。 |
| `proxy-only` | bool | `false` | 与 `--mode=proxy` 等效：只开本地 HTTP / SOCKS 代理，不接管系统路由和 DNS。 |
| `http-proxy.bind` / `http-proxy.port` | string / int | 空 / `0` | 本地 HTTP 代理，见下方规则。 |
| `socks-proxy.bind` / `socks-proxy.port` | string / int | 空 / `0` | 本地 SOCKS5 代理（支持 CONNECT 和 UDP ASSOCIATE）。 |
| `socks-proxy.username` / `socks-proxy.password` | string | 空 | SOCKS5 认证。 |
| `reconnections.timeout` | int（秒） | `5` | 重连基础间隔，`< 1` 时取 5。 |
| `reconnections.max_delay` | int（秒） | `15` | 最大退避间隔，不小于 `timeout`。 |
| `reconnections.jitter_percent` | int | `20` | 退避抖动百分比，限制在 `0..100`。 |
| `session_resume.enabled` | bool | `false` | 请求会话恢复（需服务端也启用）。 |
| `transport-auth.enabled` | bool | `false` | 见第 5 节。 |
| `mappings[]` | array | 空 | 把本地服务发布到服务器端口，见下方。 |
| `routing` | object | 未配置 | 分流规则（旧版策略的规范入口），见第 13 节。 |
| `routes[]` / `peer-routes[]` | array | 空 | 未写 `client.routing` 时的旧位置。 |
| `peer-route-announce[]` | array | 空 | 向服务端宣告本端可达前缀 `{network, prefix, via, guid}`。 |
| `peer-gateway-forward` | bool | `false` | 作为对端前缀的网关转发流量。 |
| `policy` | object | 未配置 | 新版策略（v2），见第 14 节。 |
| `paper-airplane.tcp` | bool | `true` | 仅 Windows：纸飞机 TCP 加速（LSP）。 |

**本地代理的生效规则：**

- `--mode=proxy` 或 `proxy-only: true`：HTTP 和 SOCKS 监听地址**强制为 `127.0.0.1`**（配置里的 `bind` 被忽略），端口未配置时分别取 `8080` / `1080`，可用 `--proxy-http-port` / `--proxy-socks-port` 覆盖。只绑定回环地址，绑定失败即报错，不会退回到所有地址。
- 普通 TUN 客户端：只有配置了端口才启动对应代理；`bind` 为空时监听**所有地址**（局域网可访问），只想本机使用请写 `127.0.0.1`。

**`mappings[]` 元素：**

| 字段 | 说明 |
|---|---|
| `protocol` | `tcp`（默认）或 `udp` |
| `local-ip` / `local-port` | 客户端这边被发布的服务地址 |
| `remote-ip` / `remote-port` | 服务器上对外开放的地址；`remote-ip` 写 `::` 表示所有地址 |

端口必须在 1–65535，地址必须是合法 IP 且不能是组播；不合法的条目被丢弃，`protocol + remote` 相同的条目去重。服务端需 `server.mapping: true`。

## 13. `client.routing` —— 分流规则（旧版策略）

```json
"client": {
  "routing": {
    "ip":  { "bypass": ["./ip.txt"], "routes": [], "peer-routes": [] },
    "dns": { "rules": ["./dns-rules.txt"] }
  }
}
```

| 字段 | 说明 |
|---|---|
| `ip.bypass` | 直连（不走隧道）的 IP 列表来源，字符串或字符串数组。 |
| `dns.rules` | DNS 分流规则来源，字符串或字符串数组。 |
| `ip.routes[]` | 按文件导入的路由：`{ "path": "./cmcc.txt", "ngw": "192.168.1.1", "vbgp": "https://...", "nic": "eth1" }`。`path` 和 IPv4 `ngw` 必填；`vbgp` 为可选的远程更新 URL；`nic` 仅 Linux。 |
| `ip.peer-routes[]` | 对端前缀路由 `{network, prefix, via, guid}`。 |

兼容写法：`routing.bypass`、`routing.routes`、`routing.peer-routes`、`routing.dns-rules`（嵌套位置优先）。

**来源字符串的解释：** 每个字符串先去掉可选的 `file://` 前缀；对应文件存在就按文件读取，**否则整串当作内联规则文本**。路径写错不会报错，只会变成一条无效的内联规则。

**与命令行的关系：** 写了 `client.routing` 时，`--bypass` 和 `--dns-rules` 命令行参数**被忽略**。没写时使用旧来源：`--bypass`（默认 `./ip.txt`）、`--dns-rules`（默认 `./dns-rules.txt`），以及 `client.routes` / `client.peer-routes`。

**DNS 规则行格式**（`#` 后为注释；`,`、`;`、制表符等同换行）：

```text
example.com/1.1.1.1            # 后缀匹配，用指定 DNS 服务器
full:www.example.com/8.8.8.8   # 精确匹配
regexp:.*\.cn$/doh.pub         # 正则匹配；可写内置 DNS 提供方名称
example.org/223.5.5.5/tun      # 第三段以 t/v/f/c 开头 = 经隧道查询；省略 = 经本地网卡
cloudflare                     # 只写一个 IP 或提供方名 = 所有域名的默认上游
```

内置 DNS 提供方名称：`doh.pub`、`alidns`、`baidu`、`360`、`114`、`tuna`、`cloudflare`、`google`、`quad9`、`adguard`、`nextdns`、`mullvad`。

更完整的路由 / DNS 行为见 [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)。

## 14. `client.policy` —— 新版策略（v2）

```json
"client": { "policy": { "version": 2, "rules": { "path": "./policy.rules" }, "dns": { "resolvers": { } } } }
```

- `version` 必须是整数 `2`。
- 写了 `client.policy` 时**不能同时存在**以下任何键，否则加载失败：`client.routing`、`client.bypass`、`client.dns-rules`，以及顶层 `routing`、`geo-rules`、`dns`、`bypass`、`dns-rules`、`udp.dns`。
- 字段、规则语法和 `ppp policy` 子命令见 [Policy CLI 指南](../guides/POLICY_CLI_CN.md)。

## 15. 旧版客户端 DNS 与规则字段（`dns` / `routing` / `geo-rules`）

这些顶层块只在**没有** `client.policy` 时生效。

| 字段 | 省略时 | 说明 |
|---|---|---|
| `dns.servers.domestic` | `doh.pub` | 国内上游。可写提供方名、`IP[:端口]`、结构化对象 `{protocol, url, hostname, address, bootstrap}`（`protocol` 为 `udp`/`tcp`/`doh`/`dot`，`doq` 视为 `dot`），或它们的数组。 |
| `dns.servers.foreign` | `cloudflare` | 国外上游，格式同上。TUN 模式推送给系统的 DNS 地址也由这两项推导（先 foreign 后 domestic），`--dns` 可覆盖。 |
| `dns.intercept-unmatched` | `true` | 未命中规则的查询按 `foreign → domestic → cloudflare` 解析。 |
| `dns.ecs.enabled` / `dns.ecs.override-ip` | `false` / 空 | EDNS Client Subnet；`override-ip` 非法时清空。 |
| `dns.tls.verify-peer` | `true` | DoH / DoT 证书校验。 |
| `dns.stun.candidates` | 空 | `主机:端口` 列表。 |
| `dns.fake-ip.enabled` / `dns.fake-ip.range` | `false` / `198.18.0.1/16` | Fake-IP。 |
| `routing.rules` | 空 | 人类可读规则文件路径。 |
| `routing.tcp-domain-sniff` | `false` | TCP 域名嗅探。 |
| `geo-rules.*` | `enabled: false` | 从 GeoIP / GeoSite 生成直连列表和 DNS 规则：`country`（默认 `cn`）、`geoip-dat`、`geosite-dat`、`geoip-download-url`、`geosite-download-url`、`geoip`、`geosite`、`dns-provider-domestic`、`dns-provider-foreign`、`output-bypass`、`output-dns-rules`、`append-bypass`、`append-dns-rules`。 |

## 16. 其他块

| 字段 | 省略时 | 说明 |
|---|---|---|
| `p2p.enabled` | `true` | 客户端间直连通道；`false` 时强制 `relay`。 |
| `p2p.mode` | Linux / Android：`direct-preferred`；Windows / macOS：`relay` | 只接受 `direct-preferred`，其他值一律视为 `relay`（经服务器中继）。 |
| `p2p.punch-timeout` / `p2p.keep-alived` | `5` / `15`（秒） | 最小 1。 |
| `p2p.stun.servers` / `p2p.stun.request-profile` | 空 / `standard` | profile 只接受 `standard` 或 `tailnode`。 |
| `p2p.max-probes` | `2` | 限制 `1..10`。 |
| `p2p.probe-timeout-ms` | `2000` | 限制 `500..10000`。 |
| `p2p.heartbeat-interval-ms` / `p2p.heartbeat-miss-max` | `1000` / `2` | 分别限制 `500..5000`、`1..10`。 |
| `p2p.suspect-timeout-ms` / `p2p.migration-grace-ms` | `2000` / `5000` | 分别限制 `500..10000`、`1000..30000`。 |
| `p2p.buffer-pool-count` | `64` | 限制 `8..256`。 |
| `vmem.path` / `vmem.size` | 空 / `0` | 用文件作为缓冲区内存池。`size` 单位 **MB**，实际至少 32 MB；任一为空 / 0 则关闭（Windows 只看 `size`）。 |
| `virr.update-interval` / `virr.retry-interval` | `86400` / `300`（秒） | 配合 `--virr` 自动更新 IP 列表的间隔，最小 1。 |
| `vbgp.update-interval` | `3600`（秒） | `ip.routes[].vbgp` 的更新间隔，最小 1。 |
| `telemetry.enabled` / `level` / `count` / `span` | `false` / `0` / `false` / `false` | 遥测开关与级别。 |
| `telemetry.endpoint` / `log-file` | 空 | OTLP 地址、日志文件。 |
| `telemetry.console-log` / `console-metric` / `console-span` | `true` | 控制台输出。 |

## 17. 服务器地址（`client.server`）格式

URL 会先转为小写再解析。

| 写法 | 承载 | 默认端口 | 对应服务端字段 |
|---|---|---|---|
| `ppp://主机:端口/` 或 `tcp://主机:端口/` | 原生 TCP | 必须写端口 | `tcp.listen.port` |
| `ws://主机[:端口]/路径` | WebSocket | 80 | `websocket.listen.ws` + `websocket.path` |
| `wss://主机[:端口]/路径` | TLS WebSocket | 443 | `websocket.listen.wss` + `websocket.path` |

- `主机` 可以是域名或 IP；IPv6 字面量写成 `[2001:db8::1]`。
- `域名[IP]:端口` 写法：用方括号里的 IP 建立连接，同时把前面的域名作为主机名（适合 CDN 或自定义解析），例如 `wss://vpn.example.com[203.0.113.10]:443/tun`。
- WS / WSS 的路径必须和服务端 `websocket.path` 一致。

## 18. 完整示例

仓库根目录的 [`appsettings.json`](../../appsettings.json) 列出了大部分字段的示例值（其中的地址、密钥都是示例，不能直接使用）；[`appsettings-server-minimal.json`](../../appsettings-server-minimal.json) 是服务端最小示例。

## 相关文档

- [编写配置文件](../getting-started/CONFIGURE_CN.md)
- [CLI 参考](CLI_REFERENCE_CN.md)
- [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md) · [代理模式](../guides/PROXY_MODE_CN.md) · [Policy CLI](../guides/POLICY_CLI_CN.md)
- [错误码](ERROR_CODES_CN.md)
