# 运维与故障排查

> **状态：**当前有效
> **类型：**运维指南
> **最后核对：**运行时生命周期、CLI 帮助、统计、Console UI 与诊断源码，2026-07-22
> **上一层索引：**[部署与运维](README_CN.md) · **English：**[Operations and Troubleshooting](OPERATIONS.md)

## 从可观测状态开始

先使用选定进程模式和明确配置路径：

```bash
./ppp --mode=server --config=./server.json
./ppp --mode=client --config=./client.json
./ppp --mode=proxy  --config=./client.json
```

运行时快照的 phase 名称为：

```text
idle → starting → preparing_host → connecting → handshaking →
applying_policy → connected → reconnecting → stopping → idle|failed
```

phase 是有用证据，但不能证明每项宿主网络操作或应用流均正常。

## 内置本地可观测性

| 表面 | 用途 | 边界 |
|---|---|---|
| `--stats-json=<path|stdout>` | 写出本地 NDJSON 运行时统计。 | 它是本地输出选项，不是网络 metrics 端点。 |
| 运行时快照 | 包含角色、phase、端点/传输信息、流量、能力和最后错误状态。 | 访问方式受宿主/UI 路径约束；不表示存在公开 REST API。 |
| Console UI | UI 可用时可使用本地交互命令 `openppp2 help`、`restart`、`reload`、`exit`、`info`。 | 不能把它当作远程管理。 |
| 诊断 | 检查进程输出和当前错误状态；嵌入运行时的代码可以使用错误格式化 API。 | 代码级诊断 API 不是运维 HTTP API。 |

重启控制仅属于 CLI：

| 标志 | 含义 |
|---|---|
| `--auto-restart=<seconds>` | 自动重启间隔；`0` 禁用。 |
| `--link-restart=<count>` | 触发链路重启的重连尝试阈值；`0` 禁用。 |

## 按 phase 排障

| 现象 | 首先检查 |
|---|---|
| `starting` 前失败或立即退出 | 模式/配置路径、进程权限、单实例条件、配置解析错误。 |
| 停在 `connecting` | 服务端 URI、网络可达性、本地路由策略、使用时的上游代理配置。 |
| 停在 `handshaking` | 匹配的端点/传输/密钥配置，以及所选 WebSocket/TLS 路径。 |
| 停在 `applying_policy` | 虚拟接口可用性、路由/DNS 权限、平台宿主机状态。 |
| 到达 `connected` 但没有预期流量 | 宿主机路由、bypass/DNS 输入、解析行为、远端服务端策略、应用测试路径。 |
| 托管认证失败 | `server.node`、`server.backend`、C++/Go 共享 key、管理器模式、node 记录。 |
| 服务端 IPv6 失败 | Linux-only 服务端边界、IPv6 模式/CIDR、宿主机能力、TUN、路由/NDP/NAT66 前提。 |

## 安全的运维顺序

1. 记录准确命令、选定配置路径和初始输出。
2. 核对与模式对应的宿主机副作用：服务端/proxy 的监听绑定，或普通客户端的虚拟接口/路由。
3. 更改配置前记录 phase 和最后错误。
4. 每次只修改一个变量；路由/DNS 和防火墙修改会相互掩盖问题。
5. 对宿主机管理的设置使用明确维护/回滚流程，而不是假设应用能恢复无关状态。

## 不要假设

- `connected` 快照不等于端到端流量测试；
- `--stats-json` 不是 Prometheus 或远程可观测服务；
- Console UI 命令不是经过认证的远程管理协议；
- 运行时没有承诺未文档化的 `/metrics`、租约或 IPv6 状态 REST 端点；
- 默认路由保护不是通用 kill switch。

## 相关页面

- [部署模型](DEPLOYMENT_CN.md)
- [安全模型](SECURITY_CN.md)
- [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)
- [管理后端](../guides/MANAGEMENT_BACKEND_CN.md)
- [错误码](../reference/ERROR_CODES_CN.md)