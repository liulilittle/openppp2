# Go 基础设施实现索引

> [Go 概览](../debug_CN.md) · [English](debug.md) · [核心服务](../ppp/debug_CN.md)

**Status:** 实验性内部实现

**Type:** 存储、Redis、WebSocket 和文件工具源码索引

**Last verified:** 2026-07-22

`go/io/` 包含根 Go 控制面所使用的工具。它不是稳定库包，也不应被视为通用的数据库或 WebSocket 抽象。

## 当前组件

| 文件 | 当前职责 |
|---|---|
| `DB.go` | 通过 GORM 打开 MySQL，暴露底层 GORM 句柄，配置 SQL 连接池，并识别重复键错误。 |
| `RedisClient.go` | 根据 Sentinel/master 设置创建 Redis failover 客户端，并包装部分缓存、集合、哈希和锁操作。 |
| `WebSocket.go` | 承载根 HTTP 服务，在配置的 websocket 路径升级请求、跟踪连接，并提供 HTTP 辅助函数。 |
| `File.go` | 供根服务配置加载使用的文件/路径辅助函数。 |

## 关键行为

### MySQL/GORM

`ConnectDB` 从配置组装 MySQL DSN、打开 GORM，并设置最大打开/空闲连接和连接生命周期。主从选择由核心服务决定；本包不提供独立的迁移或配置策略。

### Redis Sentinel

`NewRedisClient` 使用 `master`、`addresses`、`password` 和 `db` 构造 Redis failover 客户端。缓存和锁的语义属于核心服务实现细节。连接失败或缓存不一致可能在上层表现为用户、节点或流量问题。

### HTTP 与 WebSocket

`NewWebSocketServer` 绑定配置的监听前缀，把非 websocket 请求交给调用方 HTTP 处理器，并通过 Gorilla WebSocket 升级匹配 websocket 路径的请求。

当前 Gorilla upgrader 的 `CheckOrigin` 返回 true。这是重要安全限制：不要假设 `go/io` 提供 Origin 检查、TLS 或认证 HTTP 暴露。绑定地址、TLS 终止、认证和防火墙策略属于调用方/部署边界。

## 排查顺序

1. 先确认根服务处于独立本地存储还是受管 MySQL/Redis 模式。
2. 在修改处理器逻辑前，确认配置和网络连通性。
3. MySQL 问题应从调用方的连接/连接池和 GORM 错误入手。
4. Redis 问题应检查 Sentinel/master 可达性及 `go/ppp` 使用的缓存状态。
5. websocket 问题先区分 HTTP 路由不匹配与升级/连接失败。

除非先定义支持的接口和安全契约，否则不要新增外部调用方。业务归属见[核心服务索引](../ppp/debug_CN.md)。
