# IPv6 租约管理

> **状态：**当前 Linux 服务端实现边界
> **类型：**指南
> **最后核对：**服务端配置与 IPv6 exchanger/租约源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[IPv6 Lease Management](IPV6_LEASE_MANAGEMENT.md)

## 范围

服务端会跟踪会话对应的已分配 IPv6 地址，并用这些记录完成数据包投递和过期动态分配回收。该服务端数据平面支持 Linux（排除 Android）；它不是跨平台 IPv6 租约服务。

当前没有已实现的 `/api/v1/leases` 端点。不要围绕这个未文档化路径构建监控或自动化。

## 已解析的服务端配置

当前 `server.ipv6` 配置表面只有以下字段：

| 字段 | 用途 |
|---|---|
| `mode` | 服务端模式 `nat66` 或 `gua` |
| `cidr` | 地址池/网络输入 |
| `gateway` | 服务端路径使用的 IPv6 网关输入 |
| `dns1`、`dns2` | 适用时返回给客户端的 IPv6 DNS 输入 |
| `lease-time` | 动态租约生命周期（秒），默认 300 |
| `static-addresses` | 客户端 GUID 到静态 IPv6 地址的映射 |

`enabled`、`prefix`、`lease_duration`、`max_leases`、`static_bindings` 等字段不是当前解析接口。

## 分配行为

地址分配由服务端拥有：

1. 配置了静态客户端 GUID 映射时，静态地址优先。
2. 客户端可通过 `--tun-ipv6` 请求地址，但该值只是提示。
3. 动态候选地址由会话身份确定性导出；发生冲突时使用有限重试掩码。
4. 租约与会话关联，并与活跃 IPv6 exchanger 映射共同使用。

除非实际的 `static-addresses` 映射提供该属性，否则不要把分配描述成随机、永久粘性或已被外部保留。

`lease-time` 为零和静态映射都会使用实现中的不自动过期租约语义。应审慎选择：它会改变回收预期，但不能取代运维清理。

## 模式与前提

- `nat66` 使用 Linux 服务端 NAT66 路径；空 CIDR 可以规范为项目 ULA 回退值。
- `gua` 需要有效全球单播 CIDR，并依赖宿主机 IPv6 路由/NDP 环境。
- 不支持的服务端平台会在配置规范化期间拒绝这些 IPv6 模式。

启用任一模式前，请阅读 [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)。

## 运维检查清单

1. 使用 `static-addresses` 时保持客户端 GUID 稳定。
2. 根据部署决定动态过期还是不自动过期的租约语义。
3. 确认客户端能接受服务端选择的地址，而不是假设请求提示一定成功。
4. 通过可用日志、宿主机状态和受支持管理接口监控运行中服务端；不要抓取不存在的租约 REST API。
5. 在依赖长期地址计划前，于维护环境测试清理和重连行为。

## 相关页面

- [IPv6 客户端地址分配](IPV6_CLIENT_ASSIGNMENT_CN.md)
- [IPv6 NDP 代理](IPV6_NDP_PROXY_CN.md)
- [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)
- [安全模型](../operations/SECURITY_CN.md)