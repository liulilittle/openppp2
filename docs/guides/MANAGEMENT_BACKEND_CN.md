# 管理后端

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `go/ppp/Configuration.go`、`go/ppp/ManagedServer.go`、`go/ppp/Admin.go`、`ppp/app/server/VirtualEthernetSwitcher.cpp`）
>
> **用途：** 部署 Go 管理端，用来发布订阅、管理用户和节点，并让 C++ 服务端接入认证与流量统计。
> **读者：** 运营多台节点或需要订阅分发的运维人员。
> **上级索引：** [指南](README_CN.md) · **English:** [Management backend](MANAGEMENT_BACKEND.md)

## 1. 先分清两个 Go 程序

| 程序 | 目录 | 作用 | 能否作为 C++ `server.backend`？ |
|---|---|---|---|
| **管理端** | `go/` | 订阅发布、管理后台、用户 / 节点管理、可选的 C++ 节点接入 | 能（仅托管模式） |
| Guardian | `go/guardian/` | 本机 `ppp` 进程和配置档的守护管理工具 | 不能 |

本页只讲管理端。两者的配置文件和参数互不通用。

## 2. 两种运行模式

| 模式 | 条件 | 能力 |
|---|---|---|
| **独立模式** | 配置里没有 `database` 和 `redis` | 数据保存在本地 JSON 文件（默认 `manager-data.json`），提供管理后台和订阅发布；**拒绝 C++ 节点接入**。 |
| **托管模式** | 同时配置完整的 `database.master`（MySQL）和 `redis`（Sentinel：`addresses` + `master`） | 在独立模式能力之上，接受 C++ 服务端的控制连接，负责用户认证和流量统计。只配了其中一项时启动失败。 |

## 3. 构建与启动

```bash
cd go
go build -o ppp-go .
./ppp-go ./manager.json
```

第一个参数是配置文件路径；省略或文件不存在时读取当前目录的 `appsettings.json`，再没有就使用内置默认值。仓库提供两个示例：`go/appsettings.json`（独立模式）和 `go/appsettings.managed.json`（托管模式，其中的密码和密钥都是占位值）。

## 4. 配置字段

| 字段 | 默认 | 说明 |
|---|---|---|
| `prefixes` | `:10000` | HTTP 监听地址。不想对外开放时写成 `127.0.0.1:10000`。 |
| `path` | `/ppp/webhook` | C++ 节点连接的 WebSocket 路径。 |
| `key` | 空 | 与 C++ `server.backend-key` 比对的共享密钥（托管模式）。 |
| `admin.token` | 空 | 管理 API 的 Bearer Token。为空时启动生成一个临时 Token 并打印到日志；也可用环境变量 `OPENPPP2_ADMIN_TOKEN` 设置。 |
| `admin.path` | `/admin/` | 网页管理后台路径。 |
| `admin.public-base-url` | 空 | 生成订阅链接时使用的外部访问地址，例如 `https://manager.example.com`。 |
| `admin.data` | `manager-data.json` | 独立模式的数据文件。 |
| `database` / `redis` | 无 | 托管模式所需，格式见 `go/appsettings.managed.json`。 |
| `interfaces` / `concurrency-control` | 内置值 | 托管模式的内部接口路径与超时，一般不需要改。 |

## 5. 让 C++ 服务端接入（托管模式）

C++ 服务端配置：

```json
"server": {
  "node": 1,
  "backend": "ws://127.0.0.1:10000/ppp/webhook",
  "backend-key": "<与管理端 key 相同>"
}
```

以下条件**全部满足**才会建立连接：

| 条件 | 原因 |
|---|---|
| `server.node >= 1` | 节点号小于 1 时 C++ 不会连接管理端。 |
| `server.backend` 非空 | 管理端 WebSocket 地址（`ws://` 或 `wss://`）。 |
| `server.backend-key` 与管理端 `key` 完全相同 | 连接时直接比对。 |
| 管理端里存在对应节点记录 | 控制连接按节点号识别。 |
| 管理端运行在托管模式 | 独立模式会拒绝节点连接。 |

连接建立后，用户认证和流量上报由管理端处理。控制协议为 `[8 位十六进制长度][JSON]` 帧，命令包括 ECHO（1000）、CONNECT（1001）、AUTHENTICATION（1002）、TRAFFIC（1003，批量上报）。

## 6. 管理后台与 API

- 网页后台：`http://<管理端>/admin/`。
- 管理 API：`/api/v1/` 下的 `status`、`users`、`servers`、`subscriptions` 增删改查，以及订阅的 `preview` 和 `rotate-token`；请求需带 `Authorization: Bearer <admin.token>`。
- 订阅发布：`GET /sub/{token}`，格式见 [远程订阅](REMOTE_SUBSCRIPTION_CN.md)。

## 7. 安全

- 以下都是敏感信息：管理 Token、`key` / `server.backend-key`、`manager-data.json`、订阅链接及其内容（里面包含节点密钥）。
- 共享 `key` 以常量时间比较，可用 `?key=`（兼容旧方式）或 `Authorization: Bearer <key>` 传递。建议使用请求头：查询字符串会被反向代理和访问日志记录，`?key=` 的值可能因此泄露。
- 节点连接与握手时给出的节点编号绑定；认证或流量包中携带不同 `Node` 会被丢弃并记录日志。流量上报的计数值超过 1 TiB（2^40）或不是非负整数时会被忽略。
- API 错误只返回通用信息；数据库/Redis 的详细错误仅写入服务端日志。
- 管理端本身不提供 TLS。对公网开放前请放在 Nginx 等 TLS 终结代理后面，或只监听内网 / 回环地址。
- 订阅 Token 没有过期机制；需要收回访问权时，轮换 Token（`rotate-token`）或停用该订阅。

## 相关文档

- [远程订阅](REMOTE_SUBSCRIPTION_CN.md) · [配置文件参考 · server](../reference/CONFIGURATION_CN.md)
- [部署](../operations/DEPLOYMENT_CN.md) · [安全](../operations/SECURITY_CN.md)
