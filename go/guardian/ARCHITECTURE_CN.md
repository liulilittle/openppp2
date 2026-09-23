# OpenPPP2 Guardian 架构

> [Go 概览](../debug_CN.md) · [English](ARCHITECTURE.md)

**Status:** 实验性运维表面

**Type:** 本地/远程进程、配置文件和二进制管理器

**Last verified:** 2026-07-22

Guardian 是 `go/guardian` 下独立的 Go 1.22 模块。它监督配置的 `ppp` 子进程，并提供 REST、Server-Sent Events（SSE）、嵌入式 Web UI 和独立终端 UI 客户端。它不修改 C++ 运行时，也不是稳定的公开管理 API。

## 启动与持久化状态

`main.go` 接受 `-config`（默认 `guardian.json`），把它解析为绝对路径，加载配置，创建管理器/API 服务器，启动启用的实例，并在 interrupt/SIGTERM 时关闭。

首次运行且配置不存在时使用 `DefaultConfig()`：

- 监听 `127.0.0.1:18080`；
- 默认启用认证；
- 令牌有效期默认 24 小时，缺失 JWT secret 时生成一个；
- profile、二进制记录和备份目录默认相对于配置文件位置；
- 默认保留 2,000 行日志。

生成的 secret 会保存到 `guardian.json`；`SaveConfigFile` 以 `0600` 写入配置。应把该文件、profile 文件和实例环境映射视为敏感运维数据。已有配置中的相对路径会相对于配置文件目录解析。

## 组件关系

| 组件 | 职责 |
|---|---|
| `guardian.go`、`config.go` | 协调配置以及实例/profile/二进制管理器。 |
| `instance/` | 子进程生命周期、输出/日志缓冲、可选自动重启和健康检查、事件/日志订阅及平台进程行为。 |
| `profile/` | profile 校验、持久化、备份、恢复和保留。 |
| `binary/` | 已登记二进制和尽力而为的自动发现。 |
| `api/` | HTTP 路由、认证、REST 处理器、SSE、静态 Web UI 和 Linux systemd 入口。 |
| `webui/` | Svelte/Vite Web UI 源码；`webui.go` 嵌入编译后的 `webui/dist/*`。 |
| `cmd/tui/` | 独立 Go 模块，经 Guardian API 调用并消费 SSE。 |

`NewGuardian` 还会在多个工作目录/系统位置尝试自动发现。发现结果取决于主机；应明确登记并验证实例所需的二进制。

## API 与流边界

路由包含以下组：

- 登录、令牌刷新和密码修改；
- 实例及实例日志；
- profile、校验、备份和恢复；
- 已登记/发现的二进制；
- Guardian 配置和状态；
- Linux systemd 服务状态、安装和卸载；
- 实例日志和全局事件 SSE 流。

认证默认启用。普通受保护 `/api/` 端点要求有效的、内存中已签发的 Bearer 令牌；`/api/v1/status` 刻意公开。SSE 在认证启用时自行校验令牌/JWT，允许 query `token` 或 Bearer header，因此中间件对 SSE 的豁免不代表 SSE 无认证。

当前 CORS 允许 `*`，Guardian 未配置 TLS。除非前方有经过审查的 TLS、认证、授权和暴露控制边界，否则应保持默认回环绑定。

## Web UI 与 TUI 构建边界

`webui.go` 在 Go 编译时要求 `webui/dist/*` 已存在。本检出包含 Svelte/Vite 源码和 lock 文件，但不提交 `dist`。构建/测试 Guardian 前先生成它：

```sh
cd go/guardian/webui
npm ci
npm run build

cd ..
go test ./...
go run . -config ./guardian.json
```

`cmd/tui/` 是独立 Go 模块。应在自己的目录中构建/测试，并按需传入 Guardian API 地址和令牌；不要假设它会嵌入或启动 Guardian 实例。

## 平台与运维限制

- 启用的实例会在 Guardian 启动时自动启动；启用自动启动前应先验证 profile 和二进制。
- 实例停止/重启/profile 写入可能影响运行中的子进程和配置；应使用备份与维护窗口。
- systemd 安装仅在 Linux 上实现且需要 root；其他平台会报告不支持。
- Guardian 的日志/状态用于运维辅助，不替代协议级可观测性，也不是稳定 SDK 遥测契约。
- 本文不保证多主机安全、生产级服务管理或安全的远程暴露。

根 Go 控制面是另一套服务与配置模型，见 [Go 概览](../debug_CN.md)。
