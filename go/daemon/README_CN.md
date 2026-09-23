# OpenPPP2 本地单实例守护层

> [Go 概览](../debug_CN.md) · [English](README.md)

**Status:** 实验性；仅限本地使用

**Type:** 单子进程 HTTP 管理包装器

**Last verified:** 2026-07-22

`go/daemon` 负责启动、停止和观察一个配置好的本地 `ppp` 子进程。它还提供一个极简浏览器页面、JSON 接口，并可反向代理指定的管理 API。它不是带认证的管理服务，不能直接暴露到不受信任或远程网络。

## 管理对象

守护层配置有四个部分：

| 部分 | 相关行为 |
|---|---|
| `listen` | HTTP 绑定地址；默认 `:18080`。本地开发请明确使用回环地址。 |
| `instance` | 一个子进程二进制、工作目录、配置路径、参数、环境、停止策略和内存日志上限。 |
| `managedApi` | 可选反向代理目标；转发前会去掉 `/api/managed/` 前缀。 |
| `ui` | 仅控制浏览器页面标题。 |

默认值指向 `./openppp2`，并使用 client mode 和 `./appsettings.json`，但真实部署必须提供有效的路径和配置。相对的 `instance.configPath` 会相对于 `instance.workDir` 解析。

## 使用显式配置启动

在 `go/` 中先运行不会启动实例的检查：

```sh
go test ./daemon
```

守护层需要可读取的 JSON 配置文件。使用源码支持的参数启动：

```sh
go run ./daemon --configuration=./path/to/daemon.json
```

安全的开发配置应使用回环 `listen` 和可替换工作目录下的相对路径。不要在提交的示例中放入生产凭据、令牌或私有端点。

## HTTP 表面

处理器注册以下路径：

| 路径 | 行为 |
|---|---|
| `/` | 极简本地 HTML 控制页。 |
| `/api/status` | 当前子进程/配置/日志缓冲状态。 |
| `/api/config` | `GET` 读取配置；`PUT` 或 `POST` 写入 JSON/纯文本配置。 |
| `/api/start` | 未运行时启动配置的子进程。 |
| `/api/stop` | 请求子进程停止。 |
| `/api/restart` | 先停止，再启动子进程。 |
| `/api/logs` | 返回内存中的 stdout/stderr 日志缓冲。 |
| `/api/managed/…` | 配置后反向代理到 `managedApi.baseUrl`。 |

该实现**没有认证或授权中间件**。默认 `:18080` 在不同主机上可能监听到回环以外；应显式绑定回环，或在前方放置经过审查的认证/TLS/反向代理边界。本代码不提供这些功能。

## 进程与文件影响

- 子进程使用配置的工作目录和环境运行，stdout/stderr 写入有上限的内存缓冲。
- 停止时先发送配置的 interrupt/TERM 信号，等待 `stopWaitMs`，仍存活则 kill。
- 配置写入会校验 JSON 语法，但直接以 `0644` 覆盖配置文件；它不是访问控制或机密存储机制。
- `/api/managed/` 仅转发请求，不会为下游服务增加认证层。

根控制面的安全/配置边界见 [Go 概览](../debug_CN.md)。本守护层刻意更窄，不应被描述为 Guardian 的替代品或多实例监督器。
