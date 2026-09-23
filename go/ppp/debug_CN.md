# Go 核心控制面实现索引

> [Go 概览](../debug_CN.md) · [English](debug.md) · [基础设施](../io/debug_CN.md)

**Status:** 实验性内部实现

**Type:** 根 Go 服务与管理面源码索引

**Last verified:** 2026-07-22

`go/ppp/` 负责根 Go 服务的管理面行为。它与本树中的配置、存储、websocket 协议和嵌入式管理 UI 耦合，不是支持外部导入的 API。

## 入口与生命周期

`go/main.go` 创建 `ppp.NewManagedServer()`，挂接信号处理后调用 `ListenAndServe()`。

`ManagedServer` 由 `ManagedServerConfiguration` 构建，持有：

- 配置的 websocket/HTTP 服务器；
- 受管模式下的 Redis、MySQL，或独立模式下的 `LocalStore`；
- 内存中的服务器、节点、用户和脏状态映射；
- 嵌入式管理/订阅 HTTP 处理器。

受管模式启动时，`ListenAndServe()` 加载服务器和用户、启动服务器周期任务，然后开始监听。释放时它关闭 HTTP/websocket 服务器和节点；仅受管模式会尝试最终归档用户数据。

## 配置模式

`Configuration.go` 明确区分三种状态：

| 配置状态 | 结果 |
|---|---|
| 完整的数据库 master 与 Redis Sentinel 配置 | 受管模式，使用数据库/缓存处理服务器和节点。 |
| 同时没有数据库和 Redis | 使用独立 `LocalStore` 的订阅/管理模式；节点 websocket 会被拒绝。 |
| 部分数据库/Redis 配置 | 启动配置错误。 |

第一个位置参数选择配置文件；否则加载器尝试 `appsettings.json`。数据库、Redis、密钥和管理令牌字段都应视为机密。

## 请求与协议归属

`ManagedServer.request()` 按以下顺序分发：

1. 嵌入式管理 API/UI 和公共订阅路径；
2. 受管模式下旧的/配置的 consumer、server HTTP 接口；
3. 其他请求返回 `404`。

`Admin.go` 注册当前 `/api/v1/` 管理组（状态、用户、服务器、订阅）和公共 `/sub/{token}`。本页不固定内部 payload 字段，也不把这些处理器升级为外部 API 契约。

`ManagedServer.accept()` 读取首个 websocket 包，只接收符合条件的连接命令和有效节点标识。随后 `run()` 把 echo、认证和流量包交由本目录处理器。`Packet.go`、`Node.go`、`User.go`、`Server.go` 和 `Traffic.go` 分别承载编码、节点、用户/缓存、服务器和流量相关工作。

## 存储与同步

- `User.go`、`Traffic.go` 参与配额/流量和缓存同步。
- `Server.go` 加载并缓存服务器记录。
- `LocalStore.go` 支持独立的管理/订阅路径，不替代受管数据库/Redis 路径。
- `../io/DB.go` 使用 GORM/MySQL；`../io/RedisClient.go` 使用 Redis failover/Sentinel 设置。

排查节点或鉴权问题时先确定运行模式。独立本地存储服务不能接收受管节点；受管服务则可能因数据库、Redis、缓存或配置状态在协议处理器前失败。

## 运维注意事项

- 默认监听设置不是安全边界。`../io/WebSocket.go` 中的 upgrader 接受所有 Origin，且此服务层没有 TLS。
- 管理处理器为 `/api/v1/` 操作检查 Bearer 令牌。应配置 `admin.token` 或 `OPENPPP2_ADMIN_TOKEN`，避免依赖输出到日志的自动生成令牌。
- `/sub/{token}` 是刻意公开的订阅路径，需要单独审查暴露策略。
- 不要把源码中的处理器名或包结构当成稳定 SDK 契约。

启动/安全上下文见 [Go 概览](../debug_CN.md)；连接器行为见[基础设施索引](../io/debug_CN.md)。
