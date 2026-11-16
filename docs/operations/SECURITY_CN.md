# 安全

> Status: Active
> Type: Operations
> Last verified: 2026-10-11（对照 `AppConfiguration.cpp` 安全诊断、`ppp/diagnostics/ErrorCodes.def`、`TransportAuthConfiguration.cpp`、`ApplicationMode.cpp`、`VEthernetLocalProxySwitcher.cpp`、`go/ppp/Admin.go`、`go/guardian/config.go`）
>
> **用途：** 部署时需要保护的资产、必须避免的配置，以及加固清单。
> **读者：** 部署和维护 OPENPPP2 的运维人员。
> **上级索引：** [运维](README_CN.md) · **English:** [Security](SECURITY.md)

本页是运维加固说明，不是正式的安全评估，也不声称提供前向保密、防泄漏开关或自动防火墙管理。

## 1. 需要保护的资产

| 资产 | 位置 | 泄露后果 |
|---|---|---|
| 隧道密钥 | 配置文件 `key.protocol-key` / `transport-key` | 可伪造客户端接入服务器、解密流量 |
| `transport-auth` 密钥文件 | `keys[].secret-file` | 可通过连接认证 |
| 管理端密钥与 Token | 管理端 `key`、`admin.token`；C++ `server.backend-key` | 可冒充节点或控制管理端 |
| 订阅链接与文档 | `/sub/{token}` | 文档包含节点地址和密钥 |
| 管理端数据 | `manager-data.json` | 用户、节点、订阅全部信息 |
| Guardian 配置 | `guardian.json`（`auth.jwtSecret` 即登录密码） | 可控制本机 `ppp` 进程和配置 |
| 策略存储、状态文件、日志 | `.ppp-policy`、`dns-fake-ip`、`server.log`、遥测日志 | 访问记录、内部地址 |

以上文件只允许服务账户读取（如 `chmod 600`），不要提交到代码仓库、贴到工单或截图里。

## 2. 加密配置

启动时会对以下情况打印 `[security] WARN`（只警告，**不会阻止启动**）：

| 告警 | 触发条件 | 处理 |
|---|---|---|
| `ConfigPlaintextEnabled` | `key.plaintext` 为 `true`——**省略该字段时就是 `true`** | 显式写 `"plaintext": false` |
| `ConfigWeakKeyDefault` | 密钥等于内置默认值 `"ppp"`（密钥为空时也会回退到它） | 为每个部署生成独立随机密钥 |
| `ConfigWeakKeyShort` | 密钥短于 8 字节 | 使用 16 位以上随机字符串 |
| `ConfigLegacyCipherAlgorithm` / `ShortKey` | RC4、DES、Blowfish、CAST5、SEED、IDEA，或密钥长度低于 128 位 | 使用默认的 `aes-128-cfb` / `aes-256-cfb` |
| `ConfigLegacyKdfMd5` | 每次都会出现：密钥派生内部使用 `EVP_BytesToKey`（MD5） | 已知的历史设计；用足够长的随机密钥弥补 |

补充说明：

- 算法名写错会**静默回退**为默认算法，而不是报错；两端都写错同一个名字时仍能连通，但实际算法不是你以为的那个。
- 默认的 CFB 模式本身不提供完整性校验。需要在密钥之外再做连接认证时启用 `transport-auth`；穿越不可信网络时可以叠加 WSS（TLS）承载。
- 生成随机密钥示例：`openssl rand -base64 24`。不要使用文档或仓库示例里的密钥。

## 3. `transport-auth`（可选的连接认证）

- 使用 32 字节预共享密钥文件（64 个小写十六进制字符），文件必须属于运行用户且权限为 `600`，否则加载失败。生成：`openssl rand -hex 32 | tr -d '\n' > k.hex && chmod 600 k.hex`。
- 启用时必须恰好一个 `active` 密钥；轮换时先把新密钥以 `verify-only` 加到所有节点，再切换为 `active`，最后把旧密钥改为 `revoked`。
- Windows 无法读取 secret-file。字段说明见 [配置文件参考 · transport-auth](../reference/CONFIGURATION_CN.md)。

## 4. 监听面与暴露范围

| 监听 | 默认 | 建议 |
|---|---|---|
| 服务端隧道端口（`tcp` / `websocket` / `udp` / `cdn`） | 所有地址 | 只开放实际使用的端口；需要时用 `ip.interface` 绑定到指定网卡 |
| 客户端本地代理（代理模式） | 强制 `127.0.0.1` | 无需处理 |
| 客户端本地代理（TUN 模式） | `bind` 为空时监听**所有地址** | 只给本机用时写 `127.0.0.1`；对局域网开放时为 SOCKS5 设置用户名密码 |
| 管理端（`go/`） | `:10000`（所有地址），**不带 TLS** | 绑定到内网 / 回环；对外通过 TLS 反向代理；设置固定 `admin.token`（否则每次启动生成临时 Token） |
| Guardian | `127.0.0.1:18080` | 保持仅本机；远程用 SSH 隧道或 TLS 反向代理 |

## 5. 主机网络也是安全边界

TUN 客户端会修改路由和 DNS，服务端可能修改 IPv6、NDP、NAT 规则。

- 上线前审查分流列表和 DNS 规则：错误的规则会让流量或 DNS 查询走出隧道。
- 客户端异常退出可能留下残余路由；默认路由保护不是“断网保护开关”，不能保证零泄漏。
- 主机防火墙、路由持久化、DNS 服务策略应由运维自己掌控，程序不会自动管理防火墙。
- Linux 服务端的 GUA / NAT66 / NDP 属于特权主机操作，需要单独评估上游和防火墙。

## 6. 订阅与管理面

- 订阅链接即凭证，token 不会过期。用户离开或链接泄露时，在管理端轮换 token 或停用订阅。
- 订阅只通过 HTTPS 发布（`admin.public-base-url` 只改变生成的链接，不会给监听加 TLS）。
- 管理端 `key` 与 C++ `server.backend-key` 必须一致且保密；不同环境使用不同的值。

## 7. 加固清单

1. 配置、密钥文件、管理数据、日志只允许服务账户读取。
2. `key` 块写全，`"plaintext": false`，每个环境使用不同的随机密钥；启动输出中没有 `[security] WARN`（MD5 KDF 一条除外）。
3. 每台客户端使用独立的 `client.guid`。
4. 只开放用到的端口；管理端、Guardian 不直接暴露到公网。
5. 对外的管理 / 订阅入口使用 HTTPS，并监控访问日志。
6. 发布订阅前检查内容，确认没有多余节点或测试密钥。
7. 升级或拓扑变更后，重新验证路由、DNS、IPv6 和对端前缀策略。
8. 怀疑泄露时：更换受影响的密钥 / Token，收紧监听，重新下发配置，并确认旧凭证已无法使用。

## 相关文档

- [部署](DEPLOYMENT_CN.md) · [运维与排障](OPERATIONS_CN.md)
- [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) · [远程订阅](../guides/REMOTE_SUBSCRIPTION_CN.md) · [配置文件参考](../reference/CONFIGURATION_CN.md)
