# 用户手册

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照当前源码与 `.github/workflows/release.yml` 发行包清单）
>
> **用途：** 从下载到跑通隧道，再到常见场景的运行手册。
> **读者：** 部署和使用 OPENPPP2 的用户。
> **上级索引：** [快速开始](README_CN.md) · **English:** [User manual](USER_MANUAL.md)

## 1. OPENPPP2 是什么

OPENPPP2 是一个单文件、跨平台的虚拟网络程序 `ppp`。同一个可执行文件按启动参数扮演三种角色：

| 角色 | 启动方式 | 作用 |
|---|---|---|
| 服务端 | `ppp --mode=server`（默认） | 运行在有公网地址的机器上，接受客户端连接并转发流量。 |
| TUN 客户端 | `ppp --mode=client` | 创建虚拟网卡，按全局或分流规则把本机流量送进隧道。 |
| 代理客户端 | `ppp --mode=proxy` | 只在本机开 HTTP / SOCKS5 代理，不改系统路由和 DNS。 |

## 2. 选择安装包

发行页每个版本提供以下二进制包（解压后得到 `ppp` 或 `ppp.exe`）：

| 平台 | 包名 | 说明 |
|---|---|---|
| Linux x86_64 | `openppp2-linux-amd64.zip` | 通用版本 |
| | `openppp2-linux-amd64-simd.zip` | 启用 SIMD，较新 CPU 推荐 |
| | `…-io-uring…`、`…-tc…` 组合 | io_uring / 其他构建变体 |
| | `openppp2-linux-amd64-debian10.zip` | 面向较旧的 glibc |
| Linux 其他架构 | `openppp2-linux-{aarch64,armv7l,riscv64,ppc64el,s390x,mipsel}-cross.zip` | 交叉编译 |
| Windows | `openppp2-windows-x64-Release.zip`、`openppp2-windows-ARM64-Release.zip` | |
| macOS | `openppp2-darwin-arm64.zip`、`openppp2-darwin-x86_64.zip` | |
| Android | `openppp2-android-{arm64-v8a,armeabi-v7a,x86,x86_64}.zip` | 原生库，供 App 集成 |

文件名带 `-asan` 的是调试构建，不要用于生产。自行编译见 [开发](../development/README_CN.md)。

## 3. 权限与对系统的改动

| 系统项 | TUN 客户端 | 代理客户端 | 服务端 |
|---|---|---|---|
| 所需权限 | 管理员 / root（Linux 需 `CAP_NET_ADMIN`） | 桌面一般不需要；移动端走系统 VPN 授权 | 管理员 / root（启动时强制检查） |
| 虚拟网卡 | 创建 | 桌面不创建 | 不创建（启用 IPv6 等功能时视平台而定） |
| 系统路由 | 添加隧道和分流路由，退出时恢复 | 不修改 | 不修改 |
| 系统 DNS | 设置为隧道 DNS（`--dns` 或由 `dns.servers` 推导） | 不修改 | 不修改 |
| 系统 HTTP 代理 | 仅 Windows 且加 `--set-http-proxy=yes` 时设置 | 不修改 | — |

分流规则（`client.routing` / `client.policy`）在两种客户端模式下都生效；代理模式只是不接管系统路由和 DNS。

请用 `Ctrl+C`、`openppp2 exit` 或系统服务的正常停止命令退出客户端，以便恢复路由和 DNS。强制杀进程可能留下残余路由。

## 4. 快速开始

1. **下载并解压**对应平台的包，例如 Linux：

   ```bash
   mkdir -p /opt/openppp2 && cd /opt/openppp2
   unzip openppp2-linux-amd64-simd.zip
   chmod +x ppp
   ```

2. **编写配置**：按 [编写配置文件](CONFIGURE_CN.md) 写出 `server.json` 和 `client.json`。两边的 `key` 块必须完全相同，`"plaintext": false` 不能省。

3. **启动服务端**（在服务器上）：

   ```bash
   sudo ./ppp --mode=server --config=./server.json
   ```

   放行 `tcp.listen.port` 对应的端口。

4. **启动客户端**：

   ```bash
   sudo ./ppp --mode=client --config=./client.json
   ```

   Windows 上以管理员身份打开终端运行 `ppp.exe --mode=client --config=client.json`。

5. **确认已连通**：客户端界面底部状态栏显示连接已建立；在输入行执行 `openppp2 info` 查看虚拟地址、DNS 和统计；再访问一个外部网站确认出口地址已变为服务器地址。进程在运行或打印了启动日志，并不代表隧道可用。

查看全部参数：`./ppp --help`。

## 5. 常见场景

### 5.1 全局隧道

上面的最小配置即为全局模式：所有流量经服务器转出。不想让某些网段走隧道时，见 5.2。

### 5.2 分流：中国大陆直连，其余走隧道

```bash
./ppp --pull-iplist=ip.txt/CN     # 下载中国大陆 IP 列表到 ./ip.txt
```

客户端配置增加：

```json
"client": {
  "guid": "{...}",
  "server": "ppp://服务器IP:20000/",
  "routing": {
    "ip":  { "bypass": ["./ip.txt"] },
    "dns": { "rules": ["./dns-rules.txt"] }
  }
}
```

`dns-rules.txt` 示例（格式见 [配置参考 · DNS 规则](../reference/CONFIGURATION_CN.md)）：

```text
cn/doh.pub
baidu.com/doh.pub
google.com/cloudflare/tun
```

要让列表自动更新，启动时加 `--virr=ip.txt/CN`。写了 `client.routing` 后，命令行的 `--bypass` / `--dns-rules` 不再生效。规则更复杂时可改用 v2 策略：`ppp policy init --template split-cn ...`，见 [Policy CLI 指南](../guides/POLICY_CLI_CN.md)。

### 5.3 只要本地代理

```bash
./ppp --mode=proxy --config=./client.json
```

在 `127.0.0.1:8080`（HTTP）和 `127.0.0.1:1080`（SOCKS5）监听，把浏览器或应用的代理指向这里即可。端口可用 `--proxy-http-port` / `--proxy-socks-port` 修改。详见 [代理模式](../guides/PROXY_MODE_CN.md)。

### 5.4 放在 Nginx 后面（WebSocket）

服务端：

```json
"websocket": { "host": "vpn.example.com", "path": "/tun", "listen": { "ws": 20080 } }
```

Nginx（由它终结 TLS）：

```nginx
location /tun {
    proxy_pass http://127.0.0.1:20080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

客户端：

```json
"server": "wss://vpn.example.com/tun"
```

`websocket.host` 必须是域名；客户端 URL 的路径必须与 `websocket.path` 一致。

### 5.5 把客户端内网服务发布到服务器

客户端配置：

```json
"mappings": [
  { "protocol": "tcp", "local-ip": "127.0.0.1", "local-port": 22, "remote-ip": "::", "remote-port": 10022 }
]
```

（写在 `client` 块内。）连接建立后，访问 `服务器IP:10022` 即到达客户端的 22 端口。服务端需保持 `server.mapping: true`（默认）。

### 5.6 给客户端分配 IPv6（服务端）

```json
"server": {
  "ipv6": { "mode": "nat66", "cidr": "fd42:4242:4242::/64" }
}
```

`mode` 必填（`nat66` 或 `gua`），只写 `cidr` 不会启用。平台不支持时配置会加载失败。详见 [IPv6 客户端分配](../guides/IPV6_CN.md)。

### 5.7 接入管理后端

```json
"server": { "node": 1, "backend": "ws://127.0.0.1/ppp/webhook", "backend-key": "替换为后端密钥" }
```

由后端负责认证与计费，见 [管理后端](../guides/MANAGEMENT_BACKEND_CN.md)。

### 5.8 多链路加速

```bash
sudo ./ppp --mode=client --config=./client.json --tun-mux=4
```

`--tun-mux` 指定并行连接数；调度方式由 `mux.mode`（`compat` / `flow` / `balance`）决定，见 [配置参考 · mux](../reference/CONFIGURATION_CN.md)。

## 6. 作为局域网网关

### Linux

开启转发（写入 `/etc/sysctl.conf` 后执行 `sysctl -p`）：

```conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
```

对局域网做 NAT（按实际网段和出口调整）：

```bash
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### Windows

可配合虚拟网关工具 [VGW](https://github.com/liulilittle/vgw-release)，参数示例：`--ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0`。

## 7. 证书

DoH / DoT 和 WSS 等 TLS 连接优先加载程序目录下的 `cacert.pem`（存在时），否则使用内置根证书和系统证书库。需要自定义信任链时，把 PEM 格式的 CA 包命名为 `cacert.pem` 放在 `ppp` 旁边即可（例如 [curl 提供的 CA 包](https://curl.se/docs/caextract.html)）。

## 8. 故障速查

| 现象 | 先查 |
|---|---|
| 启动即退出 | 是否以管理员 / root 运行；配置文件路径；控制台输出的错误码（见 [错误码](../reference/ERROR_CODES_CN.md)） |
| 一直重连 | [编写配置文件 · 两端必须对上的字段](CONFIGURE_CN.md)；服务器端口是否可达（`nc -vz 服务器IP 端口`） |
| 打印 `[security] WARN` | 密钥为默认值 / 过短，或 `plaintext` 为 `true` |
| 连上了但打不开网页 | DNS：`--dns` 指定的服务器是否可达；分流规则是否把 DNS 服务器放到了直连 |
| 退出后无法上网 | 进程被强制结束，路由未恢复；重启网络或重新运行再正常退出 |

更完整的排障流程见 [运维与排障](../operations/OPERATIONS_CN.md)。

## 相关文档

- [编写配置文件](CONFIGURE_CN.md) · [配置文件参考](../reference/CONFIGURATION_CN.md) · [命令行参考](../reference/CLI_REFERENCE_CN.md)
- [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md) · [代理模式](../guides/PROXY_MODE_CN.md) · [平台说明](../guides/PLATFORMS_CN.md)
- [部署](../operations/DEPLOYMENT_CN.md) · [安全](../operations/SECURITY_CN.md)
