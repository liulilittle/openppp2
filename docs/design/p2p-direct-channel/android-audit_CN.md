# Android P2P v2 审计

> Status: Audit record
> Type: Platform audit
> Last verified: 2026-10-30

## 路由与保护

原 Android host 候选通过 Socket::GetBestInterfaceIP 获取，其临时 UDP
socket 未 protect，VPN 路由生效时可能选中 TUN 地址。现在通过受保护的
临时 socket 进行 UDP connect 选路，不发包，支持 IPv4/IPv6，保护失败关闭。
数据 socket 也改为 bind 前保护；IPv6 仍为可选、v6-only，数据 socket
不绑定探测出的 host 地址。

## 配置与诊断

Android CMake production 默认 ON；Service.instance 在 onCreate 中、native
启动前赋值，onDestroy 清除。JNI 使用加载时缓存的全局类引用，只为桥调用
附加线程，仅当本次附加时才分离；不在每个数据包上调用。

调试面板新增 Gate 行，来自 p2p_gate_reason：

Android 原生 OnTick 原先只同步 MUX，未向 runtime lifecycle 同步 P2P，
会使面板状态陈旧；现同时发布 P2P 状态、peer 和 gate reason。

- authenticated-exporter-unavailable：TCP/普通 WS 需要双方配置匹配的
  transport-auth keyring 并协商 noise-psk-v1（默认关闭），或使用提供认证
  exporter 的兼容 TLS/WSS；不能绕过安全门。
- socket-protection-unavailable：检查服务/桥就绪状态。
- relay-only：检查两端 mode；Windows/macOS 默认 relay。
- eligible：仅表示通过能力门，不代表 NAT 穿透成功。

STUN 默认列表为空，跨 NAT 请在 p2p.stun.servers 配置可达的数字 IP:port。
当前 gatherer 解析地址字面量，不执行域名解析，STUN 与探测/数据共用已保护
socket。空 STUN 列表加不可路由 host 地址无法穿透不同 NAT；不擅自加入公共服务。

P2PChannel 的 Linux 专用 include 不承担 Android 接口枚举；Android 使用
选路探测。服务端 v2 offer 检查双方 v2 能力及认证 exporter，不按 Android
平台名拒绝。Windows 对端需明确启用 direct-preferred。

## 验证边界

隔离回环测试覆盖保护先于 bind/connect、失败关闭、同 socket STUN 及 JSON
往返。真机还需确认候选不是 TUN 地址、STUN 生成 srflx、双方启用直连且实际
数据路径到达 direct。logcat 查看 openppp2 的 protect result 以及
OpenPPP2VpnProtect 的 JNI 错误。IPv6-only、NAT64、切网及严格 NAT 仍需真机验收。
