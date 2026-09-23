# IPv6 客户端地址分配

> **状态：**当前桌面实现边界
> **类型：**指南
> **最后核对：**已分配地址管理器、客户端 exchanger 与移动平台源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[IPv6 Client Assignment](IPV6_CLIENT_ASSIGNMENT.md)

## 范围

服务端可以在客户端/服务端信息交换中返回 IPv6 分配。桌面 Windows、Linux、macOS 的原生客户端会通过 `AssignedAddressManager` 应用和清理该分配。

Android 和 iPhone 构建不使用这条原生协商地址的应用/恢复路径。它们的 VPN/network-extension 行为由平台拥有，不能视为与桌面托管 IPv6 等价。

## 请求地址只是提示

客户端可通过 CLI 请求 IPv6 地址：

```bash
./ppp --mode=client --config=./client.json --tun-ipv6=2001:db8::42
```

`--tun-ipv6` 是请求提示，不是本地地址分配，也不是服务端 IPv6 启用开关。服务端可根据配置和活跃租约拒绝或替换该值。

桌面端原生应用成功后，当前 switcher 可以在后续重连时复用上一次成功地址作为进程内请求。该值不是持久用户配置，也不是保留租约。

## 原生桌面生命周期

当服务端提供受支持的分配时，桌面管理器会：

1. 为当前客户端路径校验分配和模式；
2. 捕获足以撤销自己修改的宿主机状态；
3. 通过平台 helper 应用已分配 IPv6 地址及相关路由/DNS；
4. 记录成功应用的状态；
5. 在断开/清理期间恢复自己拥有的状态。

该生命周期是尽力而为的宿主机集成。隧道握手成功并不能单独证明宿主机已接受每一项 IPv6 地址、路由或 DNS 操作。

## 运维检查清单

1. 确认服务端配置了支持的 IPv6 模式；参阅 [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)。
2. 依赖原生协商应用时，使用 Windows、Linux 或 macOS 桌面客户端。
3. 只有在服务端策略允许时才使用 `--tun-ipv6` 请求地址。
4. 连接后检查宿主机接口/地址/路由状态，并测试预期 IPv6 路径。
5. 断开后确认运维自行配置的 IPv6 状态没有与 VPN 客户端添加的状态混淆。

## 常见边界

| 现象 | 含义 |
|---|---|
| 已分配地址与 `--tun-ipv6` 不同 | 正常：服务端拥有分配权。 |
| IPv4 正常但协商 IPv6 未应用 | 检查客户端平台支持、服务端模式和宿主机权限/状态。 |
| Android/iPhone 的 IPv6 行为不同 | 预期行为：它们使用平台 VPN 处理，而不是本原生生命周期。 |
| 地址/路由操作失败 | 应按宿主机集成失败处理，不能假设流量会自动 fail-closed。 |

## 相关页面

- [IPv6 租约管理](IPV6_LEASE_MANAGEMENT_CN.md)
- [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)
- [平台集成](PLATFORMS_CN.md)
- [运维与故障排查](../operations/OPERATIONS_CN.md)