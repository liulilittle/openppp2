# 策略 v2 与 `ppp policy`

> Status: Active
> Type: Guide
> Last verified: 2026-10-11（对照 `ppp/app/client/policy/PolicySourceLoader.cpp`、`PolicyCompiler.cpp`、`PolicyModel.h`、`ppp/app/ApplicationPolicyCommand.cpp`）
>
> **用途：** 用规则文件描述分流和 DNS 策略（`client.policy`），并用 `ppp policy` 检查、解释、迁移和更新。
> **读者：** 需要比 `client.routing` 更精确分流控制的客户端用户。
> **上级索引：** [指南](README_CN.md) · **English:** [Policy v2 and `ppp policy`](POLICY_CLI.md)

v2.1.7 起提供；v2.1.6 及更早版本没有 `client.policy` 和 `ppp policy`。

## 1. 和 `client.routing` 的关系

| | `client.routing`（旧版） | `client.policy`（v2） |
|---|---|---|
| 写法 | IP 列表 + DNS 规则文件 | 一个规则文件：域名 / IP → direct / proxy / reject，加 DNS 解析器绑定 |
| 能力 | 直连 / 隧道二选一 | 直连、代理、拒绝；精确 / 后缀 / 关键字 / 正则匹配；规则集；Fake-IP；自动更新 |
| 检查工具 | 无 | `ppp policy check` / `explain` |

**二者不能同时使用。** 写了 `client.policy` 时，下列键任何一个存在都会让配置加载失败：`client.routing`、`client.bypass`、`client.dns-rules`、顶层 `routing`、`geo-rules`、`dns`、`bypass`、`dns-rules`、`udp.dns`。旧配置可以用 `ppp policy migrate` 生成 v2 草稿（第 7 节）。

## 2. 快速开始

```bash
# 1. 生成初始策略（split-cn 需要 GeoIP / GeoSite 来源：本地文件或 HTTP(S) URL）
ppp policy init --out ./policy --template split-cn --runtime tun \
  --geoip ./geoip.txt --geosite ./geosite.txt

# 2. 把生成的 client.policy 合并到客户端配置后检查
ppp policy check --config ./client.json --runtime tun

# 3. 看某个目标会怎么走
ppp policy explain --config ./client.json --runtime tun --domain www.example.com --network tcp --port 443

# 4. 正常启动客户端
sudo ./ppp --mode=client --config=./client.json
```

模板：`proxy-all`（全部走代理）、`direct-all`（全部直连）、`split-cn`（中国大陆直连、其余代理）。`init` 不会覆盖已有文件；本地来源文件不能超过 64 MiB；URL 来源只记录、不下载。

`--runtime` 取 `tun`、`http`、`socks`（对应 TUN 客户端和代理模式的两个监听）；`--platform` 可选，取 `linux`、`windows`、`macos`、`android`、`ios`，默认当前平台。

## 3. 配置字段

最小示例（地址为文档保留地址）：

```json
"client": {
  "policy": {
    "version": 2,
    "rules": { "path": "./policy/rules.txt" },
    "dns": {
      "mode": "auto",
      "resolvers": {
        "direct": { "via": "direct", "servers": ["udp://192.0.2.53:53"] },
        "proxy":  { "via": "proxy",  "servers": ["udp://192.0.2.53:53"] }
      }
    }
  }
}
```

v2 配置**拒绝未知键**，拼错字段名会报错。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `version` | int | 必填 | 必须是整数 `2`。 |
| `rules.path` | string | 必填 | 规则文件路径，相对路径以配置文件所在目录为准；本地来源上限 64 MiB。 |
| `ipv6` | string | `block` | 目前只支持 `block`。 |
| `tcp-domain-sniff` | bool | `false` | TUN 模式下从 TCP 流量嗅探域名；iOS TUN 不支持，对本地 HTTP / SOCKS 无意义。 |
| `dns.mode` | string | `auto` | `auto`、`real` 或 `fake-ip`。`auto` 在 TUN 下使用 Fake-IP，在 HTTP / SOCKS 下使用真实解析并保留原始域名。显式 `fake-ip` 需要 TUN DNS 拦截。 |
| `dns.resolvers` | object | 必填 | 非空；每个解析器有 `via`（`direct` 或 `proxy`，决定上游连接从哪里出去）和非空、有序的 `servers`。服务器可写提供方名、数字 IPv4 端点字符串（如 `udp://IP:53`、TCP / DoT / DoH URI），或 `{uri, addresses?, bootstrap?}` 对象；主机名形式的端点需要显式数字地址或直连 UDP bootstrap。 |
| `dns.fake-ip.range` | IPv4 CIDR | `198.18.0.0/16` | Fake-IP 地址池。 |
| `dns.fake-ip.storage` | path | `./dns-fake-ip` | 映射持久化目录，相对配置文件；`fake-ip` 模式必需。 |
| `dns.fake-ip.identity` | string | 由配置路径派生 | 1–128 个字符，字母、数字、`.`、`_`、`-`、`:`。 |
| `rule-sets.<名称>.format` | string | 必填 | `geoip-text`、`geosite-text`、`geoip-dat`、`geosite-dat`。 |
| `rule-sets.<名称>.source` | object | 必填 | `path`（本地）和 `url`（HTTP(S)）二选一。 |
| `rule-sets.<名称>.tag` | string | `.dat` 必填 | 选择数据集标签，如 `cn`。 |
| `rule-sets.<名称>.sha256` | hex | 无 | 可选，64 位十六进制，校验来源原始字节。 |
| `updates.enabled` | bool | `false` | 运行时按周期更新远程规则集。 |
| `updates.interval` | string | `24h` | 正整数加 `s` / `m` / `h` / `d`。 |
| `updates.via` | string | `proxy` | 更新走 `direct` 还是 `proxy`；必须和 `ppp policy update` 选择的出口一致。 |
| `updates.bootstrap` | string[] | 空 | 直连更新时解析主机名用的 `udp://IPv4:端口`；不会隐式解析主机名。 |
| `updates.allow-http` | bool | `false` | 允许 HTTP 来源；默认只允许 HTTPS。 |

## 4. 规则文件语法

```text
default proxy              # 必须且只能有一条：default direct | proxy | reject
dns direct direct          # 必须：直连流量用哪个解析器（名称来自 dns.resolvers）
dns proxy proxy            # 必须：代理流量用哪个解析器

[direct]
=router.lan                # 精确域名
example.cn                 # 后缀：域名本身及子域名
*.corp.example             # 仅子域名
keyword:intranet
regexp:^api[0-9]+\.example\.com$
192.168.0.0/16             # IPv4 CIDR
set:geosite-cn             # 引用 rule-sets 中声明的规则集
set:geoip-cn

[proxy]
example.com

[reject]
ads.example

[dns:direct]               # 某些域名例外使用指定解析器
special.example
```

**匹配优先级：**

1. 显式写出的规则优先于 `set:` 展开的规则。
2. 域名条件：精确 > 后缀 / 子域名 > 关键字 > 正则。
3. 后缀取最长匹配；后缀长度相同时 `*.example` 优先于 `example`。
4. IPv4 CIDR 取最长前缀。
5. 同优先级按声明顺序。

规则集示例：

```json
"rule-sets": {
  "geoip-cn":   { "format": "geoip-dat",   "tag": "cn", "source": { "path": "./GeoIP.dat" } },
  "geosite-cn": { "format": "geosite-dat", "tag": "cn", "source": { "url": "https://rules.example.test/geosite.dat" } }
}
```

只声明了 URL 的规则集在离线检查时无法通过，需要先 `ppp policy update` 下载。

## 5. DNS 与 Fake-IP

- 解析器 `servers` 的协议（UDP / TCP / DoT / DoH）只决定**策略引擎向上游**的连接方式；TUN 拦截的只是发往 UDP 53 端口的查询，不会拦截应用自己的 TCP/53 或 DoH / DoT。
- Fake-IP 映射保存在 `dns.fake-ip.storage`。客户端可能缓存着池里的地址时不要删除该目录；修改地址池、identity 或清空映射后，需要重启并清理各设备的 DNS 缓存。没有在线清除功能。

## 6. 检查与解释

| 命令 | 作用 |
|---|---|
| `ppp policy check --config F --runtime R [--platform P] [--json]` | 校验配置、规则语法、本地规则集和所选平台能力。不启动隧道、不下载。 |
| `ppp policy explain --config F --runtime R (--domain H \| --ip A) [--network tcp\|udp] [--port N] [--json]` | 说明目标命中哪条规则、走哪个出口、用哪个解析器。不做 DNS 查询；不支持 IPv6 目标。 |

`check` 的能力判断基于代码路径，通过检查不代表隧道一定可用。

## 7. 迁移旧配置

```bash
ppp policy migrate --config ./old-client.json --out ./policy-draft \
  --bypass ./ip.txt --dns-rules ./dns-rules.txt --runtime tun
```

- 写出 v2 草稿和报告，不修改原配置。
- 退出码 `5` 表示草稿存在需要人工确认的差异（文件仍已写出）。DNS 上游出口、缓存范围、Fake-IP、ECS、IPv6 / AAAA、Geo 生成、平台路由等不一定能自动等价转换。

## 8. 导出、更新与状态

| 命令 | 作用 |
|---|---|
| `ppp policy export --config F --out FILE [--store DIR]` | 把检查过的本地规则或持久化策略包导出为仅含策略的文件；不导出整份应用配置和 Fake-IP 映射，不下载。 |
| `ppp policy update --config F [--store DIR] --interface IF [--bootstrap udp://IP:PORT]` | 经指定网卡直连下载远程规则集。只有来源 URL 用主机名时才需要 `--bootstrap`。 |
| `ppp policy update --config F [--store DIR] --proxy-endpoint 127.0.0.1:PORT` | 经本地 SOCKS5 代理下载；此方式不接受 `--bootstrap`。 |
| `ppp policy status --config F [--store DIR]` | 查看更新状态和当前 / 待生效版本。 |

- `update` 是唯一会下载的命令。下载并校验成功后存为待生效版本（报告显示 `prepared_for_next_start`），**不会**切换正在运行的进程，下次启动生效。默认存储目录是配置文件旁的 `.ppp-policy`；使用自定义 `--store` 时运行时不会读取它，需要再 `export`。
- 运行时自动更新是另一回事：`updates.enabled: true` 时，正在运行的客户端按 `interval` 下载并在本会话内生效。

## 9. 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 成功 |
| `2` | 参数、配置或规则错误 |
| `3` | 来源不可用、存储失败或状态租约被占用 |
| `4` | 所选平台 / 运行方式不支持该能力 |
| `5` | 迁移草稿需要人工复核 |

`--json` 输出 schema 1 的机器可读报告。

## 10. 验证范围

Linux 实机测试覆盖了 HTTP、80 端口上的 CONNECT、SOCKS UDP、DNS、Fake-IP 和受控的策略更新；HTTPS CONNECT、SOCKS HTTPS、代理 TCP 和 TUN HTTPS 的探测当时未通过。Windows、macOS、Android、iOS 未做该项实机验证。详见 [Linux 实机报告](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)。

## 相关文档

- [路由与 DNS](ROUTING_AND_DNS_CN.md) · [配置文件参考 · client.policy](../reference/CONFIGURATION_CN.md) · [命令行参考](../reference/CLI_REFERENCE_CN.md)
