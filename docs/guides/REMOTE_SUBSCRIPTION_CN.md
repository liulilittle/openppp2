# 远程订阅

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `go/ppp/Subscription.go` 及 Android / 桌面客户端的订阅解析）
>
> **用途：** 订阅链接的格式、客户端如何使用、以及发布时的安全注意事项。
> **读者：** 发布订阅的运维人员和使用订阅的用户。
> **上级索引：** [指南](README_CN.md) · **English:** [Remote subscription](REMOTE_SUBSCRIPTION.md)

## 1. 概览

[管理端](MANAGEMENT_BACKEND_CN.md) 在 `GET /sub/{token}` 发布订阅文档。客户端（Android、iOS、桌面客户端）导入这个链接后，会把文档里的每个节点变成一个可连接的配置档。

链接里的 token 就是访问凭证：任何拿到链接的人都能读取文档，而文档包含节点密钥。请像对待密码一样对待订阅链接。

## 2. 文档格式（v1）

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "示例订阅",
  "profilePrefix": "示例",
  "updatedAt": "2026-10-11T00:00:00Z",
  "nodes": [
    {
      "id": "server-1",
      "name": "示例节点",
      "subtitle": "vpn.example.invalid:20000",
      "server": "ppp://vpn.example.invalid:20000/",
      "key": {
        "protocol": "aes-128-cfb",
        "protocol-key": "<协议层密钥>",
        "transport": "aes-256-cfb",
        "transport-key": "<传输层密钥>"
      },
      "client": { "guid": "<分配给该用户的 GUID>" },
      "options": {}
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `type` / `version` | 固定为 `openppp2-subscription` / `1`。 |
| `name` / `profilePrefix` | 订阅名称和节点显示名前缀。 |
| `updatedAt` | 生成时间。 |
| `nodes[].id` | 节点的稳定标识，客户端据此更新已有配置档。 |
| `nodes[].server` / `key` / `client.guid` | 对应客户端配置的同名字段，格式见 [配置文件参考](../reference/CONFIGURATION_CN.md)。 |
| `nodes[].options` | 管理端原样复制订阅记录里的任意 JSON；各客户端只读取自己支持的选项。 |

客户端还兼容一些额外写法（如节点里直接带完整 `config`），但那不是跨平台的约定，发布时请只用上面的结构。文档请控制在远小于 2 MiB（客户端的上限）。

## 3. 客户端行为

| 方面 | 行为 |
|---|---|
| 支持的链接 | Android / iOS 只接受 HTTPS（本机回环地址的 HTTP 仅用于开发），并限制重定向次数；桌面客户端（实验性）同时接受 HTTP 和 HTTPS。 |
| 更新 | Android / iOS 按“订阅链接 + 节点 `id`”更新配置档；桌面客户端有自己的缓存逻辑。不同客户端对“节点被删除”的处理不保证一致。 |
| 缓存 | 管理端返回 `ETag` 和 `Cache-Control: private, max-age=60`，支持 `If-None-Match`；现有客户端不发条件请求，每次刷新都会完整下载。 |

## 4. 发布与安全

- **始终通过 HTTPS 发布**：管理端本身不做 TLS，请在前面放 TLS 终结代理，并设置 `admin.public-base-url` 为外部 HTTPS 地址。
- 不要把订阅链接或文档贴到日志、工单、截图或公开仓库。
- token 不会过期。用户离开或链接泄露时，在管理后台轮换 token（`rotate-token`）或停用订阅。
- 管理 API 的 Bearer Token 与订阅 token 是两个不同的凭证。

## 相关文档

- [管理后端](MANAGEMENT_BACKEND_CN.md) · [安全](../operations/SECURITY_CN.md)
