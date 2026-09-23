# ADR 0002：以经认证的会话导出器为 P2P 直连通道设门

> **用途：**记录 P2P 直连通道的持久安全边界。
> **适用对象：**协议、安全和平台维护者。
> **当前状态：**当前架构决策。
> **最后核对依据：**Exchanger/Switcher 接线和生产能力门，2026-07-22。
> **上一层索引：**[架构决策记录](README_CN.md) · **English：**[ADR 0002](0002-p2p-direct-channel-security.md)

> Status: Accepted
> Type: ADR
> Last verified: 8c8a888

## 背景

P2P 直连通道类型（offer 会话、控制数据报、直连数据路径和重放辅助工具）已集成到 `VEthernetExchanger` 和 `VirtualEthernetSwitcher`，但生产经认证控制仍保持**失败关闭**：`P2PCapabilityGate.h` 中的 `ProductionAuthenticatedControlV1Ready = false`。`ITransmission` 现在定义了经认证会话导出器边界，经过认证的 TLS WebSocket 会在应用握手后通过标准 TLS exporter 实现它。这并不会启用 P2P 直连：最终生产控制门仍为 false。原始 TCP、明文 WebSocket 和没有可用 exporter 的传输仍不具备资格。

若以配置密钥、未经认证的控制消息或原始 TCP 会话派生直连 UDP 路径的密钥，就会创建一个未加密绑定到经认证 relay 会话的第二通道。

## 决策

P2P 能力默认关闭。实验性直连尝试只有在最终经认证控制门被显式启用，且其传输通过显式、传输无关的接口提供按会话认证的 exporter 时才具备资格。exporter 只能在 relay 握手成功后可用，并且必须绑定经认证的对端、relay 会话标识、协商的协议版本和新的连接 epoch。

两个客户端不共享 TLS exporter。两个 relay 会话都具备资格后，服务端生成新的随机 pair seed。它从每个客户端的会话 exporter 派生不同的封装密钥，并在各自独立认证和加密的 relay offer 中向每个客户端发送同一个 pair seed。直连通道密钥由 pair seed 派生，而非直接由任一 TLS exporter 派生。pair seed 绑定两个对端身份、两个 relay 会话标识、offer、版本和连接 epoch；它绝不以明文发送，也不会在多个 offer 间复用。

经过认证的 TLS WebSocket 会在证书和应用认证完成后用标准 TLS exporter 实现此接口。原始 TCP、明文 WebSocket、未暴露 exporter 的 TLS 实现和任何 exporter 故障都只能走 relay。offer-v1 路径不得读取或假定能访问 TLS master secret。一个已编译的旧 P2P helper 仍有 `tls_master_secret` 输入；它不属于 offer-v1，不能用于满足本决策。

服务端可以协调候选项并发出有界 offer，但不能绕过 exporter 资格。两个对端都必须认证受保护的 UDP probe 及其确认，之后任一方才能报告或转发 `direct`。探测、suspect 恢复和回退均保留 relay 数据路径。

线格式和生命周期要求见[协议](../design/p2p-direct-channel/protocol.md)、[状态机](../design/p2p-direct-channel/state-machine.md)和[威胁模型](../design/p2p-direct-channel/threat-model.md)。

## 备选方案

- 从配置的协议或传输密钥派生：拒绝，因为这些密钥是部署范围的，不能把直连通道绑定到一个经认证的 relay 会话。
- 把 TLS master secret 传入 P2P：拒绝，因为原始 TCP 没有此值，暴露它会扩展信任边界，而标准 exporter 才是正确的 TLS 接口。
- 仅用服务端 Token 启用直连模式：拒绝，因为 bearer token 不能证明两个端点都持有会话绑定的密钥材料。
- 永久禁用 P2P：安全，但会阻止未来的经认证直连路径。exporter 门在保持 relay 安全的同时允许增量工作。

## 后果

- 既有部署和线格式保持兼容且仅走 relay。
- 当前 P2P scaffold 不是生产证据，必须保持不可达，直到 coordinator、经认证控制能力和平台门均完成。
- 已存在经过认证的 TLS WebSocket exporter 支持，但它本身并不能满足这些门。支持原始 TCP 需要另行接受的经认证密钥协商；不属于本决策。
- 失败、超时、降级、重启或不支持的对端绝不会拆除基础 VPN 会话。
