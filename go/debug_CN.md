# OpenPPP2 Go 控制面表面

> [English](debug.md) · [核心服务](ppp/debug_CN.md) · [基础设施](io/debug_CN.md) · [本地守护层](daemon/README_CN.md) · [Guardian](guardian/ARCHITECTURE_CN.md)

**Status:** 实验性、内部实现

**Type:** Go 控制面、本地运维和进程管理表面

**Last verified:** 2026-07-22

`go/` 包含多个彼此独立的 Go 程序和包，用于管理/控制面工作；它们不实现 VPN 数据转发，也不是稳定的 Go SDK。

## 表面概览

| 表面 | 用途 | 当前边界 |
|---|---|---|
| 根模块（`main.go`、`ppp/`、`io/`） | 节点控制面、受管用户/服务器、订阅/管理 HTTP 路由和 websocket 节点通信。 | 实验性内部服务。 |
| `daemon/` | 管理一个本地 `ppp` 子进程，并提供小型 HTTP UI/API。 | 无认证的本地运维工具；不得直接暴露到网络。 |
| `guardian/` | 多实例进程、配置文件和二进制管理器，包含 REST、SSE、嵌入式 Web UI 和独立 TUI。 | 实验性运维表面，默认仅监听回环并启用令牌认证。 |

根 `go.mod` 使用 Go 1.22，并声明 GORM/MySQL、Redis Sentinel、Gorilla WebSocket 和 UUID 等外部依赖；它不是纯标准库实现。

## 根控制面的两种模式

`ppp.NewManagedServer()` 把第一个位置参数当作配置文件；没有参数时会尝试 `appsettings.json`，再在加载器允许时使用默认值。

### 受管模式

只有同时具备以下内容时才会启用：

- 完整的 `database.master`；以及
- Redis Sentinel 地址和 master 名称。

该模式初始化基于数据库/Redis 的用户和服务器，接收节点 websocket 连接，并运行服务器周期任务。

### 独立本地存储模式

若同时没有数据库和 Redis 配置，服务会使用 `admin.data`（默认 `manager-data.json`）打开本地订阅管理器。这不是数据库节点服务的降级版本：独立模式会关闭节点 websocket 连接，只适合本地服务器/订阅管理。

部分数据库/Redis 配置会导致启动配置错误，而不会回退到独立模式。

## 本地检查与启动

在 `go/` 中先运行不启动实例的检查：

```sh
go test ./...
```

需要时把配置文件作为第一个位置参数传给根服务：

```sh
go run . ./path/to/control-plane.json
```

启动可能会连接已配置的 Redis/MySQL，或创建/读取本地管理数据。开发时请使用可替换配置，绝不要提交密码、数据库凭据、管理令牌或真实订阅链接。

## 安全边界

此文档不把根服务描述为已完成生产加固：

- 默认监听前缀为 `:10000`；在本地以外启动前必须审查绑定地址。
- 当前 Gorilla WebSocket upgrader 接受所有 Origin，且该层没有配置 TLS。
- `/api/v1/*` 管理操作使用 Bearer 令牌。应明确设置 `admin.token` 或 `OPENPPP2_ADMIN_TOKEN`；需要自动生成令牌时，服务会把它写入日志。
- 公共订阅路由刻意与认证的管理路由分开。
- 数据库、Redis、配置和缓存状态都会影响鉴权/流量现象。

任何非本地部署都应自行配置经过审查的网络边界、TLS、认证策略和密钥管理。这不属于本内部文档的保证范围。

## 按职责阅读

- [核心服务](ppp/debug_CN.md)：配置模式、websocket 生命周期、管理/订阅处理边界和源码入口。
- [基础设施](io/debug_CN.md)：MySQL/GORM、Redis Sentinel、WebSocket 和文件工具。
- [单实例守护层](daemon/README_CN.md)：不带认证的本地进程包装器。
- [Guardian](guardian/ARCHITECTURE_CN.md)：独立配置的多实例管理器，带认证、Web UI 和 TUI。

这里的路径和接口仅是实现索引，不是兼容性承诺。
