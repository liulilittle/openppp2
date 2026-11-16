# 部署

> Status: Active
> Type: Operations
> Last verified: 2026-10-11（对照 `ppp/app/ApplicationInitialize.cpp`、`PppApplication.cpp`、`go/guardian/config.go`、`go/guardian/service/systemd.go`、`go/guardian/instance/manager.go`、`.github/workflows/release.yml`）
>
> **用途：** 把 OPENPPP2 长期运行为系统服务，以及升级、回滚和多实例的做法。
> **读者：** 部署服务端或常驻客户端的运维人员。
> **上级索引：** [运维](README_CN.md) · **English:** [Deployment](DEPLOYMENT.md)

先用前台方式跑通（见 [用户手册](../getting-started/USER_MANUAL_CN.md)），再按本页改成服务。

## 1. 部署前检查

| 项目 | 要求 |
|---|---|
| 权限 | 服务端和 TUN 客户端必须以管理员 / root 运行（代理模式除外），否则启动报 `AppPrivilegeRequired`。 |
| 配置 | 用 `--config=<绝对路径>` 显式指定；`key` 块写全且 `"plaintext": false`；每台客户端 `client.guid` 不同。 |
| 端口 | 服务器防火墙 / 安全组放行 `tcp.listen.port`，以及启用了的 `websocket.listen.ws/wss`、`udp.listen.port`、`cdn`。 |
| 驱动 | Linux 有 `/dev/net/tun`；Windows 保留发行包中的 `Driver\` 目录。 |
| 证书 | WSS 的证书和私钥文件对运行用户可读。 |
| 时间 | 服务器时间准确（TLS 证书校验依赖系统时间）。 |

## 2. 目录布局（Linux 示例）

```text
/opt/openppp2/
├── ppp                 # 可执行文件
├── server.json         # 或 client.json
├── ip.txt              # 分流列表（客户端，可选）
├── dns-rules.txt       # DNS 规则（客户端，可选）
└── cacert.pem          # 自定义 CA（可选）
```

```bash
chmod 700 /opt/openppp2
chmod 600 /opt/openppp2/*.json    # 配置里有密钥
```

## 3. Linux：systemd

仓库不附带 `ppp` 的 unit 文件，以下为示例，按需修改路径：

```ini
# /etc/systemd/system/openppp2-server.service
[Unit]
Description=OPENPPP2 server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/openppp2
ExecStart=/opt/openppp2/ppp --mode=server --config=/opt/openppp2/server.json
Restart=always
RestartSec=10
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now openppp2-server
journalctl -u openppp2-server -f
```

- 客户端把 `--mode=server` 换成 `--mode=client`（或 `--mode=proxy`），配置换成 `client.json`。
- `systemctl stop` 发送 SIGTERM，`ppp` 会正常退出并恢复路由和 DNS。
- 平滑重启（重新读取配置）：`kill -64 <pid>`，或在控制台执行 `openppp2 restart`。
- 以 systemd 运行时没有交互式控制台，用 `journalctl` 看输出，需要统计时加 `--stats-json=/var/log/openppp2/stats.ndjson`。

## 4. 用 Guardian 托管

Guardian（`go/guardian/`，发行包 `guardian-<平台>.tar.gz` / `.zip`）是本机的 `ppp` 进程守护和配置管理工具：自动重启、日志查看、配置备份 / 回滚，并带网页管理界面。它和 [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) 是两个不同的程序。

```bash
./guardian -config guardian.json
```

`guardian.json` 示例：

```json
{
  "listen": "127.0.0.1:18080",
  "auth": { "enabled": true, "jwtSecret": "", "tokenExpiryHours": 24 },
  "profilesDir": "./profiles",
  "binariesDir": "./binaries",
  "backup": { "enabled": true, "maxBackups": 10, "dir": "./backups" },
  "instances": [
    {
      "name": "server",
      "enabled": true,
      "binary": "/opt/openppp2/ppp",
      "workDir": "/opt/openppp2",
      "configPath": "/opt/openppp2/server.json",
      "args": ["--mode=server", "--config=/opt/openppp2/server.json"],
      "autoRestart": { "enabled": true, "maxRetries": 0, "retryDelayMs": 3000 }
    }
  ]
}
```

- `autoRestart.maxRetries` 为 `0` 表示不限次数；`retryDelayMs` 是每次重启前的等待时间。
- **启动 `ppp` 时只使用 `args`**，`configPath` 仅用于管理和显示；`--mode` 和 `--config` 必须写在 `args` 里。
- 网页界面在 `listen` 地址上（默认只监听本机）。登录密码就是 `auth.jwtSecret`；首次启动时为空则自动生成并写回配置文件。这个文件要当作密钥保护，不要打印或提交。
- 管理 API 前缀为 `/api/v1`。需要远程访问时请走 SSH 隧道或 TLS 反向代理，不要直接对公网开放。
- 在 Linux 上可以从网页界面（或 `POST /api/v1/service/install`）把 Guardian 自身安装为 systemd 服务 `openppp2-guardian`。
- Guardian 用伪终端运行 `ppp`，控制台界面和日志都能在网页里查看。

## 5. Windows

- 以管理员身份运行；`ppp.exe` 旁边保留 `Driver\` 目录（Wintun / TAP 驱动）。
- 开机自启可用“任务计划程序”：触发器选“系统启动时”，勾选“使用最高权限运行”，操作为 `ppp.exe --mode=client --config=C:\openppp2\client.json`，起始位置设为程序目录。
- 停止时优先用控制台 `openppp2 exit` 或 `Ctrl+C`，以便恢复路由和 DNS。

## 6. macOS：launchd

```xml
<!-- /Library/LaunchDaemons/org.openppp2.client.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.openppp2.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/openppp2/ppp</string>
    <string>--mode=client</string>
    <string>--config=/opt/openppp2/client.json</string>
  </array>
  <key>WorkingDirectory</key><string>/opt/openppp2</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

```bash
sudo launchctl load -w /Library/LaunchDaemons/org.openppp2.client.plist
```

## 7. 同一台机器运行多个实例

同一模式下，**同一个配置文件**只能运行一个实例（第二个会报 `AppAlreadyRunning`）。使用不同的配置文件即可同时运行多个，但要注意：

- 服务端实例的监听端口不能冲突；
- 多个 TUN 客户端需要不同的虚拟网卡名（`--tun=`）和不重叠的路由。

## 8. 升级与回滚

1. 备份当前的 `ppp` 和配置文件。
2. 新版本放到新目录，先用 `./ppp --help` 确认能运行，客户端可先用代理模式试连。
3. 停止服务 → 替换可执行文件 → 启动；查看启动输出中有无 `[security] WARN` 或配置相关警告。
4. 有问题时换回旧的可执行文件和配置并重启。

升级前请阅读发行说明。v2.1.7 起新增 `client.policy` 与 `ppp policy`；`client.policy` 与旧版分流字段不能混用（见 [策略 v2](../guides/POLICY_CLI_CN.md)）。

## 9. 常见拓扑

| 拓扑 | 参考 |
|---|---|
| 单服务端 + 客户端（原生 TCP） | [编写配置文件](../getting-started/CONFIGURE_CN.md) |
| 服务端在 Nginx / CDN 后面（WS / WSS） | [用户手册 · 放在 Nginx 后面](../getting-started/USER_MANUAL_CN.md) |
| 多节点 + 集中认证计费 | [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) |
| 站点互联 | [对端前缀路由](../guides/PEER_PREFIX_ROUTING_CN.md) |

## 相关文档

- [运维与排障](OPERATIONS_CN.md) · [安全](SECURITY_CN.md) · [平台说明](../guides/PLATFORMS_CN.md)
