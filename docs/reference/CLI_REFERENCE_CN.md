# 命令行参考

> Status: Active
> Type: Reference
> Last verified: 2026-10-11（对照 `ppp/app/ApplicationHelp.cpp`、`ApplicationConfig.cpp`、`ApplicationInitialize.cpp`、`ApplicationPolicyCommand.cpp`、`ConsoleUI.cpp`）
>
> **用途：** `ppp` 可执行文件全部命令行参数、子命令和运行时控制台命令。
> **读者：** 启动、调试和部署 OPENPPP2 的用户。
> **上级索引：** [参考](README_CN.md) · **English:** [CLI reference](CLI_REFERENCE.md)

JSON 配置字段见 [配置文件参考](CONFIGURATION_CN.md)。`ppp --help` 打印的是当前构建实际支持的参数列表（平台相关参数只在对应平台显示）。

## 1. 语法

```bash
ppp [--参数=值 ...]
ppp policy <子命令> [选项]
```

- 参数写成 `--name=value`；布尔参数接受 `yes`/`no`（也接受 `y`、`true`、`1` 等）。值含空格时加引号。
- `-h`、`--h`、`-help`、`--help` 打印帮助并退出。
- 大部分客户端参数只影响本次运行，不写回配置文件。

## 2. 通用参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--mode=client\|server\|proxy` | `server` | 运行角色。别名 `--m`、`-mode`、`-m`。以 `c` 开头即为 client；`proxy` 必须完整拼写；其他值和不写都是 server。 |
| `--config=<路径>` | 见右 | 配置文件。别名 `-c`、`--c`、`-config`。未指定或不可读时依次尝试 `./config.json`、`./appsettings.json`。 |
| `--rt=yes\|no` | `yes` | 实时（高优先级）调度。 |
| `--dns=<IP列表>` | 由 `dns.servers` 推导 | TUN 模式推送给系统的 DNS，逗号分隔。未指定时由 `dns.servers.foreign` / `domestic` 推导，都推导不出时为 `8.8.8.8`（Windows 客户端补 `8.8.4.4`）。 |
| `--tun-flash=yes\|no` | `no` | 为套接字设置高优先级 TOS（QoS）。 |
| `--block-quic=yes\|no` | `no` | 阻断 QUIC 流量，迫使应用回落到 TCP。 |
| `--auto-restart=<秒>` | `0` | 进程运行满该时间后自动重启；0 = 关闭。 |
| `--link-restart=<次数>` | `0` | 客户端重连次数达到该值后重启进程；0 = 关闭。 |
| `--stats-json=<路径\|stdout>` | 关闭 | 以 NDJSON 写出本地运行统计；路径不可写时忽略。 |

## 3. 服务端参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--firewall-rules=<文件>` | `./firewall-rules.txt` | 防火墙规则文件。 |

服务端的监听端口、地址池、IPv6 等都在配置文件里，见 [配置文件参考](CONFIGURATION_CN.md)。

## 4. 客户端参数

### 网卡与地址

| 参数 | 默认 | 说明 |
|---|---|---|
| `--tun=<名称>` | 平台默认 | 虚拟网卡名称。 |
| `--tun-ip=<IP>` | `10.0.0.2` | 虚拟网卡 IPv4。显式指定时，若服务端启用了地址池，则作为“指定地址”请求。 |
| `--tun-gw=<IP>` | `10.0.0.1` | 虚拟网卡网关。 |
| `--tun-mask=<位数>` | `30` | 前缀长度，限制在 16–32。 |
| `--tun-ipv6=<IP>` | 服务端分配 | 请求指定的 IPv6 地址。 |
| `--tun-vnet=yes\|no` | `yes` | 子网转发（客户端之间互通）。 |
| `--proxy-subnet=yes\|no` | `yes` | 仅代理模式：经进程内协议栈接入虚拟子网（不建网卡）。见[代理模式](../guides/PROXY_MODE_CN.md)。 |
| `--proxy-internet=yes\|no` | `yes` | 仅代理模式：同时代理上网；`no` 时只组网。 |
| `--proxy-forward=<端口>[:<本机端口>][,...]` | （无） | 接入虚拟子网的代理模式：对端可连接的虚拟 IP TCP 端口，转发到 `127.0.0.1`。 |
| `--tun-host=yes\|no` | `yes` | 把默认路由指向隧道（全局）。 |
| `--tun-static=yes\|no` | `no` | 静态 UDP 隧道模式（使用服务端 `udp.listen.port`）。proxy 模式下无效：不进行 `STATIC`/`STATICACK` 交换；`--proxy-subnet=yes` 时仍接受显式指定的 `--tun-ip`。 |
| `--nic=<网卡>` | 自动 | 指定物理出口网卡。 |
| `--ngw=<IP>` | 自动 | 指定物理网关。 |

### 协议栈与多路复用

| 参数 | 默认 | 说明 |
|---|---|---|
| `--tcp-stack=native\|lwip\|xtcp` | `native`（Windows 非 Wintun 驱动时为 `lwip`） | TCP 协议栈。`xtcp` 只有构建时启用才能用，否则启动失败。XTCP 每连接默认使用 1 MiB 发送缓冲配额，见[配置参考](CONFIGURATION_CN.md#xtcp-运行时调优)。 |
| `--lwip=yes\|no` | 同上 | 旧的协议栈开关，等价于 `--tcp-stack=lwip`。 |
| `--tun-mux=<连接数>` | `0` | MUX 并行连接数，0 = 不启用 MUX。 |
| `--tun-mux-acceleration=<0-3>` | `0` | MUX 加速模式，超过 3 视为 0。 |
| `--mux-mode=compat\|flow\|balance\|stripe` | `compat` | 覆盖 `mux.mode`。 |
| `--mux-mode-turbo=yes\|no` | `no` | 覆盖 `mux.turbo`（仅 `flow` 下有意义）。 |
| `--debug-key=<密钥>` | 关闭 | 覆盖 `mux.debug.key`。 |
| `--mux-mode-set=<模式>` | 关闭 | 会话建立后请求对端切换调度模式，需双方 `debug.key` 相同。仅本次运行，不写入配置。 |

### 平台相关

| 参数 | 平台 | 默认 | 说明 |
|---|---|---|---|
| `--tun-promisc=yes\|no` | Linux、macOS | `yes` | 网卡混杂模式。 |
| `--tun-ssmt=<N>[/mq]` | Linux | `0` | 包处理线程数；带 `mq` 时每个线程打开一个 TUN 队列。 |
| `--tun-ssmt=<N>` | macOS | `0` | 包处理线程数。 |
| `--tun-route=yes\|no` | Linux | `no` | 路由兼容模式。 |
| `--tun-protect=yes\|no` | Linux | `yes` | 保护隧道自身连接不被路由进隧道。 |
| `--bypass-nic=<网卡>` | Linux | 自动 | 直连列表使用的出口网卡。 |
| `--tun-lease-time-in-seconds=<秒>` | Windows | `7200` | 虚拟网卡 DHCP 租期。 |
| `--set-http-proxy=yes\|no` | Windows | `no` | 把系统 HTTP 代理设置为客户端本地 HTTP 代理（proxy 模式下不生效）。 |

### 分流

| 参数 | 默认 | 说明 |
|---|---|---|
| `--bypass=<文件1\|文件2>` | `./ip.txt` | 直连 IP 列表，多个文件用 `\|` 分隔。**配置里写了 `client.routing` 时被忽略。** |
| `--bypass-ngw=<IP>` | 自动 | 直连列表使用的网关。 |
| `--dns-rules=<文件>` | `./dns-rules.txt` | DNS 规则文件。**配置里写了 `client.routing` 时被忽略。** |
| `--virr=[文件/国家]` | 不启用 | 定期从 APNIC 下载国家 IP 列表并重新应用，例如 `--virr=ip.txt/CN`。间隔由 `virr.*` 配置。参数格式同 `--pull-iplist`。 |
| `--vbgp=yes\|no` | `yes` | 启用 `ip.routes[].vbgp` 远程路由更新。 |

### 代理模式

| 参数 | 默认 | 说明 |
|---|---|---|
| `--proxy-http-port=<端口>` | `8080` | 覆盖 `client.http-proxy.port`。必须是 1..65535 的整数，非法值会中止启动。 |
| `--proxy-socks-port=<端口>` | `1080` | 覆盖 `client.socks-proxy.port`。必须是 1..65535 的整数，非法值会中止启动。 |

`--mode=proxy` 的完整行为见 [代理模式](../guides/PROXY_MODE_CN.md)。

## 5. 工具命令（执行后退出）

| 命令 | 平台 | 说明 |
|---|---|---|
| `--pull-iplist [文件/国家]` | 全部 | 从 APNIC 下载国家 IP 列表，文件默认 `./ip.txt`。见下方格式说明。 |
| `--system-network-reset` | Windows | 重置 Windows 网络栈。 |
| `--system-network-optimization` | Windows | 应用网络性能优化。 |
| `--system-network-preferred-ipv4` / `--system-network-preferred-ipv6` | Windows | 设置 IPv4 / IPv6 优先。 |
| `--no-lsp <程序>` | Windows | 让指定程序绕过 LSP。 |

**`文件/国家` 的格式：** 程序在**第一个** `<`（没有 `<` 时为第一个 `/`）处拆分文件和国家代码。因此文件名本身含 `/` 时必须用 `<` 分隔：

```bash
./ppp --pull-iplist=ip.txt/CN                    # 当前目录下的 ip.txt
./ppp --pull-iplist="/opt/openppp2/ip.txt<CN"    # 带路径时用 <，并加引号
```

`./ip.txt/CN` 这种写法会在 `./` 处被拆开，**不要使用**（`ppp --help` 中显示的默认值写法同样受此影响）。

## 6. `ppp policy` 子命令

用于检查、解释、初始化、迁移和更新 `client.policy`（v2）配置，不启动隧道。

| 命令 | 用途 |
|---|---|
| `ppp policy check --config FILE --runtime tun\|http\|socks [--platform P] [--json]` | 校验并编译策略。 |
| `ppp policy explain --config FILE --runtime R (--domain HOST\|--ip ADDR) [--network tcp\|udp] [--port N] [--json]` | 解释某个目标会走哪条路由、用哪个 DNS。 |
| `ppp policy init --out DIR --template proxy-all\|direct-all\|split-cn --runtime R [--geoip SRC --geosite SRC] [--json]` | 生成初始策略包。 |
| `ppp policy migrate --config LEGACY --out DIR [--bypass F] [--dns-rules F] [--runtime R] [--platform P] [--json]` | 把旧配置迁移为 v2 草稿。 |
| `ppp policy export --config FILE --out FILE [--store DIR] [--json]` | 导出策略数据。 |
| `ppp policy status --config FILE [--store DIR] [--json]` | 查看更新状态。 |
| `ppp policy update --config FILE [--store DIR] (--interface IF [--bootstrap udp://IP:PORT] \| --proxy-endpoint 127.0.0.1:PORT) [--json]` | 下载并校验远程规则集。 |

`--platform` 取 `linux`、`windows`、`macos`、`android`、`ios`。退出码：`0` 成功，`2` 参数 / 配置 / 编译错误，`3` 来源不可用或存储失败，`4` 能力不支持，`5` 迁移草稿需要人工复核。详细用法见 [Policy CLI 指南](../guides/POLICY_CLI_CN.md)。

## 7. 运行时控制台命令

在终端前台运行时，底部输入行接受以下命令（必须带 `openppp2` 前缀，其他输入会作为系统 shell 命令执行）：

| 命令 | 说明 |
|---|---|
| `openppp2 help` | 列出命令。 |
| `openppp2 info` | 打印完整运行环境快照。 |
| `openppp2 restart` / `openppp2 reload` | 重启进程（重新加载配置）。 |
| `openppp2 exit` | 退出。 |
| `openppp2 clear` | 清空命令输出区。 |
| `openppp2 peer status` | 打印 P2P 对端状态。 |
| `openppp2 peer set <uuid> ipv4-first\|ipv6-first\|relay-first` | 设置某个对端的 P2P 优先级。 |
| `openppp2 telemetry [status\|help]` | 查看遥测控制台过滤状态。 |
| `openppp2 telemetry log\|metric\|span on\|off\|toggle` | 切换控制台输出过滤（不改配置文件）。 |
| `openppp2 telemetry level 0-3` | 控制台详细级别（0=Info … 3=Trace）。 |
| `openppp2 telemetry all\|quiet\|clear` | 全开 / 全关 / 清空遥测缓冲。 |

按键：`↑`/`↓` 历史，`PageUp`/`PageDown` 滚动命令输出，`Home`/`End` 滚动状态区，`Ctrl+A`/`Ctrl+E` 行首 / 行尾。

## 8. 示例

```bash
# 服务端
sudo ./ppp --mode=server --config=/etc/ppp/server.json

# 全局 TUN 客户端，4 条 MUX 连接
sudo ./ppp --mode=client --config=./client.json --tun-mux=4

# 只开本地代理（127.0.0.1:1080 / 8080），不改系统路由
./ppp --mode=proxy --config=./client.json --proxy-socks-port=1080

# 下载中国 IP 列表到 ./ip.txt
./ppp --pull-iplist=ip.txt/CN
```

## 相关文档

- [编写配置文件](../getting-started/CONFIGURE_CN.md) · [配置文件参考](CONFIGURATION_CN.md)
- [代理模式](../guides/PROXY_MODE_CN.md) · [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md) · [平台说明](../guides/PLATFORMS_CN.md)
