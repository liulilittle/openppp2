# OPENPPP2 远程订阅格式

> **状态：**当前发布端契约；客户端处理因平台而异
> **类型：**指南
> **最后核对：**原生管理器发布端以及随附 Android/iOS/桌面消费端源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Remote Subscription Format](REMOTE_SUBSCRIPTION.md)

## 范围

原生 Go 管理器可以在 `GET /sub/{token}` 下发 `openppp2-subscription` v1 JSON 文档。URL token 是未认证 capability：持有该 URL 即可读取文档。因此 URL 和响应都应按含凭据材料处理。

本文描述发布端稳定的 v1 形态。各客户端还接受一些兼容字段，但它们不是可跨平台依赖的订阅 schema。

## 已发布的 v1 形态

发布端输出以下顶层字段：

| 字段 | 含义 |
|---|---|
| `type` | 固定为 `openppp2-subscription` |
| `version` | 当前为 `1` |
| `name` | 订阅显示名称 |
| `profilePrefix` | 可选显示名称前缀 |
| `updatedAt` | 发布端时间戳 |
| `nodes` | 节点数组 |

生成的紧凑节点包含 `id`、`name`、`subtitle`、`server`、`key`、`client.guid`、`options`。`id` 由管理器 server 记录生成；对按 ID 更新 profile 的客户端而言，它是稳定身份。

示例只使用占位符，绝不能填写生产密钥：

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "Example subscription",
  "profilePrefix": "Example",
  "updatedAt": "2026-07-22T00:00:00Z",
  "nodes": [
    {
      "id": "server-1",
      "name": "Example node",
      "subtitle": "vpn.example.invalid:20000",
      "server": "ppp://vpn.example.invalid:20000/",
      "key": {
        "protocol": "aes-128-cfb",
        "protocol-key": "<provisioned-protocol-key>",
        "transport": "aes-256-cfb",
        "transport-key": "<provisioned-transport-key>"
      },
      "client": {
        "guid": "<assigned-client-guid>"
      },
      "options": {}
    }
  ]
}
```

## 发布端与客户端边界

| 主题 | 当前行为 |
|---|---|
| `options` | 管理器从订阅记录复制任意 JSON map；各客户端只消费自身代码支持的选项。不要假设统一 `options` schema。 |
| 额外节点形态 | 随附客户端支持紧凑节点、完整 `config` 对象/JSON 字符串等兼容路径。跨平台发布时不要依赖未文档化的额外字段。 |
| 大小 | 已检查的随附客户端把文档限制为 2 MiB；应远小于该上限。 |
| 刷新身份 | Android/iOS 使用订阅 URL 加 node ID 更新节点；桌面客户端维护自己的订阅缓存行为。不要由单一客户端推断删除语义。 |
| ETag | 管理器会输出 ETag/cache 头，但已检查客户端不会发条件请求。应将 ETag 视为发布端支持，而不是刷新保证。 |

## URL 与传输策略

- Android 和 iOS 接受 HTTPS 订阅 URL，并只对 loopback HTTP 开发 URL 放宽；它们还限制重定向。
- 实验性桌面客户端当前接受 HTTP 和 HTTPS URL。
- 因此运维仍应使用 HTTPS 发布，不能把“客户端强制 HTTPS”描述为通用事实。

## 安全与生命周期

- 下发文档可能包含 protocol/transport key。不要把它写入日志、问题跟踪、截图或公开仓库。
- 已检查发布端没有公开 token 的到期机制。需要终止访问时，应轮换 token、禁用/删除订阅或限制网络暴露。
- 原生管理器 admin bearer token 与公开订阅 token 是不同凭据。
- 直接 Go 服务不会自行终止 TLS；在不可信网络发布前，应部署由运维管理的 TLS 端点。

## 相关页面

- [管理后端](MANAGEMENT_BACKEND_CN.md)
- [安全模型](../operations/SECURITY_CN.md)
- [配置参考](../reference/CONFIGURATION_CN.md)