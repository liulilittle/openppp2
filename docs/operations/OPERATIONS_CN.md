# 运维与排障

> Status: Active
> Type: Operations
> Last verified: 2026-10-11（对照 `ppp/facade/ApplicationBootstrap.cpp`、`ApplicationInitialize.cpp`、`ApplicationMainLoop.cpp`、`ppp/app/runtime/RuntimePhase.h`、`RuntimeStatsJson.*`、`ConsoleUI.cpp`）
>
> **用途：** 判断 OPENPPP2 是否在正常工作，出问题时按顺序定位。
> **读者：** 运行服务端或客户端的运维人员和用户。
> **上级索引：** [运维](README_CN.md) · **English:** [Operations and troubleshooting](OPERATIONS.md)

## 1. 可以看到什么

| 手段 | 怎么用 | 能看到 |
|---|---|---|
| 启动失败输出 | 进程退出时 stderr 打印一行 `[级别] 编号 名称: 说明` | 失败原因，按名称在 [错误码](../reference/ERROR_CODES_CN.md) 中查 |
| 控制台界面 | 前台终端运行时自动显示（Guardian 托管时同样可用） | 状态栏：连接状态、吞吐、最近错误；输入 `openppp2 info` 看完整运行环境 |
| 启动诊断 | 启动时打印的 `[security]`、`[mux]` 行 | 弱密钥 / 明文 / 旧算法警告；当前 MUX 调度模式 |
| `--stats-json=<文件\|stdout>` | 启动参数 | 每行一个 JSON（`type: "ppp-stats"`）：收发字节、链路质量、TCP 栈，以及平台相关计数 |
| `server.log` | 服务端配置 | 会话日志文件 |
| `telemetry.*` | 配置 | 遥测日志 / 指标 / Span，可输出到文件或 OTLP |
| `openppp2 peer status` | 控制台命令 | P2P 对端状态 |

没有内置的 HTTP 指标或管理接口；`--stats-json` 只是写本地文件。

## 2. 运行阶段

客户端运行时按以下阶段推进，控制台和运行快照里可以看到当前阶段：

```text
idle → starting → preparing_host → connecting → handshaking → applying_policy → connected
                                                       ↘ reconnecting ↗          ↘ stopping → idle / failed
```

`connected` 只说明隧道握手完成，不代表流量一定按预期转发，仍需实际测试访问。

## 3. 按阶段排查

| 卡在 / 现象 | 先查 |
|---|---|
| 启动即退出 | stderr 的错误名称。常见：`AppPrivilegeRequired`（非代理模式需要管理员 / root，**服务端也需要**）、`AppAlreadyRunning`（同一模式、同一配置文件已有实例在运行）、`ConfigFileNotFound` / `ConfigLoadFailed`（路径或 JSON 错误）、IPv6 平台不支持 |
| `preparing_host` | 虚拟网卡驱动（Windows Wintun / TAP，Linux `/dev/net/tun`）；网卡名是否冲突 |
| `connecting` | `client.server` 地址、端口和前缀；服务器防火墙；`client.server-proxy`；本机能否访问服务器（`nc -vz 服务器 端口`） |
| `handshaking` | 两端 `key` 是否完全一致；WS / WSS 的域名、路径、证书；`transport-auth` 是否两端都配置 |
| `applying_policy` | 路由 / DNS 权限；分流规则文件；`client.policy` 是否通过 `ppp policy check` |
| `connected` 但不通 | 分流规则是否把目标放到了直连；DNS 是否可达；服务端出口网络；在客户端 `openppp2 info` 看分配到的地址 |
| 反复 `reconnecting` | 网络抖动、服务端重启、两端 `client.guid` 冲突；`--link-restart` 设置是否过小 |
| 周期性短暂断开 | `--auto-restart`、`--virr`、vBGP 列表更新都会重启进程 |
| 托管认证失败 | `server.node >= 1`、`server.backend` / `backend-key` 与管理端一致、管理端为托管模式、节点记录存在（见 [管理后端](../guides/MANAGEMENT_BACKEND_CN.md)） |

## 4. 自动重启

| 方式 | 说明 |
|---|---|
| `--auto-restart=<秒>` | 运行满该时间后进程自行重启 |
| `--link-restart=<次数>` | 客户端重连次数达到该值后重启 |
| `openppp2 restart` / `reload` | 手动重启（重新读取配置） |
| systemd `Restart=always` / Guardian `autoRestart` | 进程异常退出后由外部拉起，见 [部署](DEPLOYMENT_CN.md) |

## 5. 安全的操作顺序

1. 记下完整启动命令、配置文件路径和首屏输出。
2. 改配置前先记录当前阶段和最近错误。
3. 一次只改一处。路由、DNS 和防火墙的改动容易互相掩盖。
4. 修改前备份配置；涉及路由、DNS、防火墙的主机设置，准备好手动回滚步骤。
5. 客户端用 `Ctrl+C` / `openppp2 exit` 正常退出，以恢复路由和 DNS。

## 6. 策略 v2 的排查

| 现象 | 查看 |
|---|---|
| 某个域名走向不对 | `ppp policy explain --config F --runtime tun --domain <域名>` |
| 规则检查不过 | `ppp policy check --config F --runtime tun --json` 的诊断项 |
| 更新后没有生效 | `ppp policy status`：`ppp policy update` 下载的版本要到下次启动才生效（`prepared_version`）；自定义 `--store` 需要 `export` |
| Fake-IP 地址在重启后变化或不可用 | `dns.fake-ip.storage` 目录是否被删除、是否被另一个进程占用；不要把删除存储目录当作第一步恢复手段 |
| 状态文件缺失或过期 | 是否有另一个进程持有状态写入锁；状态文件只是观测信息，不影响路由决策 |

## 7. 提交问题时

只提供脱敏后的信息：错误行、运行阶段、平台和版本、去掉了地址和密钥的配置片段。不要贴出完整配置、节点地址、订阅链接或密钥。

## 相关文档

- [部署](DEPLOYMENT_CN.md) · [安全](SECURITY_CN.md) · [错误码](../reference/ERROR_CODES_CN.md)
- [编写配置文件 · 常见错误](../getting-started/CONFIGURE_CN.md) · [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)
