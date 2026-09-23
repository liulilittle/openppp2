# 纯代理模式
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **用途：**说明本主题的当前行为、配置或实现边界。
> **适用对象：**OPENPPP2 用户、运维人员与开发者。
> **当前状态：**当前有效。
> **最后核对依据：**当前仓库结构、实现路径与文档链接，2026-07-31。
> **上一层索引：**[返回索引](README_CN.md) · **English：**[Proxy-only mode](PROXY_MODE.md)


纯代理模式连接 OPENPPP2 服务端，并提供**本地 HTTP 与 SOCKS5 转发代理**，不安装宿主系统路由条目或系统 DNS 设置，但仍会把 canonical 路由策略加载到 native client。桌面端使用 `TapStub`；移动端只保留运行时所需的最小 tunnel 接口。不安装宿主规则不等于对应的 native policy 失效。

## 快速开始

```bash
./ppp --mode=proxy --config=./appsettings.json
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## 配置

推荐使用 canonical 对象 `client.routing` 保存 IP/DNS policy。它存在时只对这些 policy source 具有权威性；运行模式保持独立：

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://your-server:20000/",
    "proxy-only": true,
    "routing": {
      "ip": {
        "bypass": [],
        "routes": [],
        "peer-routes": []
      },
      "dns": {
        "rules": []
      }
    },
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

`client.proxy-only` 是独立的顶层运行标志，即使存在 `client.routing` 也会读取。旧的 `client.routes` 和 `client.peer-routes` 仅在 canonical 对象缺失时作为兼容输入；旧 routing 对象中的 mode 字段会被忽略且不会序列化。命令行使用 `--mode=client` 或 `--mode=proxy` 选择运行模式；`--mode=proxy` 等价于启用纯代理行为。

省略监听端口或绑定地址时使用以下默认值：

| 监听器 | 默认绑定地址 | 默认端口 |
|--------|--------------|----------|
| HTTP | 127.0.0.1 | 8080 |
| SOCKS5 | 127.0.0.1 | 1080 |

## 平台行为

| 平台 | proxy-only 下的变化 | 仍然生效的内容 |
|------|---------------------|----------------|
| Linux / macOS / Windows | 不安装 OS 路由；不覆写系统 DNS；使用 `TapStub` 代替真实 TUN | native bypass、路由、peer 路由和 DNS rules 仍加载。本地 HTTP/SOCKS 代理可用。无需 root。 |
| Android | `VpnService.Builder` 只安装 VPN 接口子网路由；不捕获 IPv6；不设置隧道 DNS | native bypass、路由、peer 路由和 DNS policy 仍加载。需要 VpnService 权限。 |
| iOS | `PacketTunnelProvider` 只安装 tunnel 子网 included route；不设置 bypass 排除路由；不配置 `NEDNSSettings` | native 路由和 DNS policy 仍加载。需要 Network Extension 授权。 |

TUN 和 proxy-only 都会把 `routing.ip.bypass`、`routing.ip.routes`、`routing.ip.peer-routes` 和 `routing.dns.rules` 加载到 native policy，区别仅在于是否将状态投影到宿主 OS。

**Android：** 在应用的 **仅代理模式** 选项中启用（`vpnOptions.proxyOnly=true`）。仍会创建最小 TUN 以支持 `protect()` 调用。

**iOS：** extension 从准备好的 JSON 读取 `client.proxy-only`，并据此调整 `NEPacketTunnelNetworkSettings`。

## 静态传输边界

纯代理模式启动时强制关闭静态传输（static transport）。这意味着：

- 不会发起 `STATIC`/`STATICACK` 交换。
- 即使 `--tun-ip` 通常会启用静态传输，在此模式下也会被覆盖。
- IPv4 地址分配使用自动模式，而不是提交本地 TUN 地址。

## CLI 选项

| 选项 | 说明 |
|------|------|
| `--mode=proxy` | 选择纯代理运行时 |
| `--proxy-http-port=N` | 覆盖 HTTP 监听端口 |
| `--proxy-socks-port=N` | 覆盖 SOCKS 监听端口 |

完整说明见 [CLI_REFERENCE_CN.md](../reference/CLI_REFERENCE_CN.md) 和 [CONFIGURATION_CN.md](../reference/CONFIGURATION_CN.md)。

## 相关文档

- [路由与 DNS](ROUTING_AND_DNS_CN.md) — 归一化路由策略与 DNS 行为
- [平台集成](PLATFORMS_CN.md) — 桌面端、Android 与 iOS 边界
- [CLI 参考](../reference/CLI_REFERENCE_CN.md) — 所有命令行选项
- [配置参考](../reference/CONFIGURATION_CN.md) — 所有配置字段
