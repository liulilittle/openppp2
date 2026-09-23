# 管理后端

> **状态：**当前实现边界
> **类型：**指南
> **最后核对：**原生 Go 管理器、C++ 托管链路、管理 API 与订阅源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Management Backend](MANAGEMENT_BACKEND.md)

## 选择正确的 Go 表面

本树包含两个独立的 Go 程序：

| 表面 | 角色 | 是否兼容 C++ `server.backend`？ |
|---|---|---|
| `go/` 下的原生管理器 | 订阅下发、管理 API、可选的 C++ 托管控制链路 | 是，但仅限 managed 模式 |
| `go/guardian/` 下的 Guardian | 独立进程/Profile 管理器 | 否；它不是原生 C++ 后端端点 |

不要混用它们的参数或配置结构。特别地，原生管理器通过第一个位置参数选择配置；Guardian 的 `--config` 仅属于 Guardian。

## 原生管理器模式

原生管理器有两个不同模式：

- **独立订阅管理器：**没有完整外部数据库/Redis 配置时使用。它持久化本地数据（默认 `manager-data.json`），并提供管理/订阅表面，但会拒绝原生 C++ 节点控制 WebSocket 链路。
- **Managed 模式：**使用已配置的 database/Redis 结构，并接受原生 C++ 托管链路。这是 `server.backend` 所需的模式。

默认监听/路径是 `:10000` 和 `/ppp/webhook`。不需要公网访问时，应绑定明确的 loopback 或管理网地址。

## C++ 托管链路前提

只有同时满足以下条件，才应期待 C++ 服务端使用原生管理器：

| 条件 | 原因 |
|---|---|
| `server.node >= 1` | 节点值小于一时，C++ 服务端不会打开托管链路。 |
| 非空 `server.backend` | 提供原生管理器 WebSocket URL。 |
| `server.backend-key` 与 Go 顶层 `key` 匹配 | CONNECT 会直接比较两者。 |
| 管理器内有对应的 server/node 记录 | 控制链路标识具体节点。 |
| 原生管理器运行在 managed 模式 | 独立模式会拒绝节点控制链路。 |

C++ 配置片段可安全使用占位符：

```json
{
  "server": {
    "node": 1,
    "backend": "ws://127.0.0.1:10000/ppp/webhook",
    "backend-key": "<shared-manager-key>"
  }
}
```

Go 管理器必须使用相同 path/key，并在依赖托管认证前启动。不要把独立模式配置当作 C++ 链路已激活的证据。

## 控制链路内容

原生协议以如下方式帧化 JSON：

```text
[8 个十六进制长度字符][JSON]
```

包字段为 `Id`、`Node`、`Guid`、`Cmd`、`Data`。已实现命令为 ECHO (1000)、CONNECT (1001)、AUTHENTICATION (1002)、TRAFFIC (1003)。

CONNECT 在用户认证前建立 C++ 节点到管理器的链路。TRAFFIC 是批量上报；该协议没有 `SessionEnd` 命令，也不承诺每 tick 直接写 SQL。

## 管理与订阅表面

管理器实现 bearer-token 保护的 `/api/v1/` 状态和 users/servers/subscriptions CRUD 路由，以及 token 轮换/预览。`GET /sub/{token}` 通过未认证的 capability URL 下发订阅文档。

以下内容均应视为秘密或敏感控制材料：

- 管理 bearer token；
- 原生管理器 `key` / C++ `server.backend-key`；
- 使用独立模式时的 `manager-data.json`；
- 公开订阅 URL 与其下发文档，因为节点可能包含隧道密钥材料。

直接 Go HTTP 服务不会自行提供 TLS。把管理或订阅表面公开前，应使用可信网络绑定或由运维部署 TLS 终止。

## 运行边界

原生管理器从 `go/` 使用其 Go module 构建，例如：

```bash
cd go
go build -o ppp-go .
./ppp-go ./manager.json
```

位置参数可省略；省略后管理器会查找 `appsettings.json`，再使用默认值。在连接 C++ 服务端前，应确认该配置实际选择的是独立模式还是 managed 模式。

## 相关页面

- [远程订阅格式](REMOTE_SUBSCRIPTION_CN.md)
- [部署模型](../operations/DEPLOYMENT_CN.md)
- [安全模型](../operations/SECURITY_CN.md)
- [配置参考](../reference/CONFIGURATION_CN.md)