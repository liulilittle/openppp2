# OpenPPP2 Sub / Client 方案设计
> Status: Active
> Type: Design
> Last verified: 8c8a888

> **用途：**记录 Sub 管理器和桌面 Client 管理器的状态绑定方案边界。
> **适用对象：**Sub、桌面 Client 和原生管理链路的维护者。
> **当前状态：**设计基线；Client 管理器 MVP 位于 `desktop/client/`（Tauri + Svelte），Sub 以现有 `go/ppp` 为准；不是稳定接口或发布承诺。
> **最后核对依据：**`go/ppp`、`desktop/client/`、`ppp/app/server/VirtualEthernetManagedServer.cpp` 与相关 manifest，2026-07-22。
> **上一层索引：**[Design Documents](README.md)

> **核对提示：**本文档限定 Sub 和桌面 Client 的设计范围，不声明它们是本仓库仅有的产品表面。实现、传输和部署结论必须以当前代码、配置和测试为准。

> 日期：2026-07-22
> 范围：服务端 Sub 管理器、Windows/macOS Client 管理器
> 相关：`CLIENT_UIUX_DESIGN_CN.md`、`CLIENT_MANUAL_PROFILES_DESIGN_CN.md`、`docs/reference/PROJECT_INTERFACE_MAP.md`

## 1. 目标与约束

本文档只定义两个产品表面；这不是本仓库仅有两个产品表面的声明：

- **Sub 管理器**：集中管理用户、服务器节点、权限、订阅和现有 C++ ppp-server 管理链路。
- **Client 管理器**：Windows/macOS 桌面客户端，消费订阅并管理本机 ppp 客户端。

当前只适配仓库已有能力：不新增 C++ 原生命令、不新造节点通信协议、不把 Guardian 作为新产品依赖。进入实现阶段时必须重新检查代码、协议和部署环境；允许自行收敛或调整边界。

## 2. 总体架构

```text
管理员 -> Sub 管理器 -> 现有 WebSocket 管理链路 -> 多台 C++ ppp-server
                         ECHO / CONNECT / AUTHENTICATION / TRAFFIC

普通用户 -> Client 管理器 -> HTTPS（生产要求；当前也接受 HTTP）/sub/{token} -> Sub 管理器
                         Client 管理器 -> 本机现有 ppp 客户端
```

Sub 管理器是集中控制面；每台 ppp-server 通过 `VirtualEthernetManagedServer` WebSocket 接入。Client 管理器不接入服务端管理 WebSocket，只消费订阅并运行本地 ppp。

## 3. Sub 管理器

以当前 `go/ppp` 为基础，不引入 Guardian HTTP 作为中间层。

### 用户模块

管理用户 GUID、入站/出站额度、过期时间、QoS 和启用状态，适配 `/api/v1/users`、`/api/v1/users/{guid}`。

### 节点模块

管理 `tb_server` 节点记录、地址、协议、传输、密钥、在线状态及订阅关联，适配 `/api/v1/servers`、`/api/v1/servers/{id}`。

### 订阅模块

管理订阅名称、用户 GUID、节点列表、Token、选项和更新时间，适配：

```text
/api/v1/subscriptions
/api/v1/subscriptions/{id}/rotate-token
/api/v1/subscriptions/{id}/preview
/sub/{token}
```

下发继续使用现有 `openppp2-subscription` v1 JSON，不改变字段语义。

### 原生节点管理模块

复用现有 8 位十六进制长度前缀 + JSON 协议：

| 命令 | 编号 | 作用 |
|---|---:|---|
| ECHO | 1000 | 心跳和保活 |
| CONNECT | 1001 | 节点接入握手 |
| AUTHENTICATION | 1002 | 客户端会话认证、额度和过期校验 |
| TRAFFIC | 1003 | 流量上报和额度同步 |

当前不增加启动、停止、重载、配置推送或远程日志命令。

### 存储模式

- 独立模式：复用 `manager-data.json`，不依赖 MySQL/Redis。
- 托管模式：复用 MySQL + Redis，用于多节点、集中额度和持久化流量。

两种模式共享 HTTP API 和订阅格式。只有托管模式维护 C++ 原生 WebSocket 管理链路；独立模式会拒绝该 WebSocket 连接。

## 4. Client 管理器

技术路线：**Tauri 2 + Svelte 4**，代码在 `desktop/client/`（前端 `src/`，原生壳 `src-tauri/`）。

### 普通模式（已实现）

粘贴订阅 URL，拉取并校验文档，缓存最近一次成功订阅，展示节点并选择连接，生成现有 ppp 配置并启动本地 ppp，显示连接状态、速度、流量和错误。支持手动节点增删改、全局启动参数、TCP 延迟探测、托盘与收藏。

### 高级模式（部分实现）

配置页提供启动参数表单与原始 appsettings JSON；日志页消费进程输出。多配置、备份恢复、完整服务端模式编辑仍属后续范围。高级模式只管理本机配置，不访问 Sub 的用户数据库。

### 生命周期

v1 不新增 `ppp-agent` 协议。Client 管理器直接管理现有 ppp 进程：关闭窗口默认隐藏到托盘，退出托盘程序时按设置断开或保留连接。`autostart` 目前只写入 `preferences.json`，尚未接 OS 开机启动 API。Windows/macOS 提权启动 ppp 仍需平台验收。只有真实验证表明服务化和权限隔离不足时，才另行设计 agent。

## 5. 认证与失败行为

设计上三种凭据必须分离：管理员 Bearer Token 保护 `/api/v1/*`；`backend-key` 仅用于 C++ 原生 WebSocket；订阅 Token 仅用于 `/sub/{token}`。当前静态 `/admin/` 资源不经过 `adminAuthorized` 检查，因此不能把它描述为已由管理员 Token 保护。

生产部署应使用 HTTPS/WSS。当前桌面 Client 仍接受 `http` 订阅 URL；服务端会发出 ETag，但桌面 Client 尚不保存或发送 `If-None-Match`。缓存、Token 轮换和输入校验的具体边界必须以当前实现为准。

- Sub 暂时不可用：已有 ppp 会话按现有行为继续，新的托管认证可能失败，C++ 继续重连。
- 订阅暂时不可用：Client 使用最近一次成功缓存并显示同步时间。
- 节点离线：Sub 标记节点状态，管理员可禁用，Client 刷新订阅时感知变化。
- ppp 异常退出：Client 显示退出码和日志并提供重新连接，不新增 C++ 重启命令。

## 6. Guardian 处理

Guardian 暂时保持独立，不进入 Sub/Client 运行链路：不让 Client 依赖 Guardian HTTP/WebUI，不让 Sub 通过 Guardian 管理 C++ 节点，保留 Guardian 作为现有多实例运维工具。后续若需复用其进程管理逻辑，再抽公共 Go 包。

## 7. 实施与验证顺序

1. ~~重新核对 `VirtualEthernetManagedServer`、Go `ManagedServer`、`Packet.go`、`Handler.go` 和订阅 API。~~（设计基线已对齐现有协议）
2. 以现有 `go/ppp` 收敛 Sub 管理器边界，保持协议不变。
3. ~~实现 Client MVP：订阅导入、缓存、节点选择、配置生成、ppp 启停和托盘状态。~~（`desktop/client/`）
4. ~~手动节点与启动参数。~~（见 `CLIENT_MANUAL_PROFILES_DESIGN_CN.md`）
5. Client 高级配置、日志与诊断的剩余缺口；Windows/macOS 安装、提权、开机启动与断线验收。

Sub 端验证：`cd go && go test ./... && go build ./...`。Client 验证：`cd desktop/client && npm test && npm run build`；原生壳 `cargo test` / `cargo run` 于 `desktop/client/src-tauri`。

## 8. 明确不做

- 新增 C++ 原生命令或第二套节点控制协议。
- 新增 gRPC、IPC 或 Guardian 中间层。
- 把 Guardian 嵌入 Client。
- 远程启动/停止/重载 ppp-server。
- 在 Sub 与 Client 之间共享管理员凭据。
