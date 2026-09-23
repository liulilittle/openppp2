# 隧道设计
> Status: Active
> Type: Architecture
> Last verified: client/server exchanger and link-layer sources, 2026-07-22
>
> **用途：**映射 `ITransmission` 之上当前隧道运行时的所有权。
> **适用对象：**贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Tunnel Design](TUNNEL_DESIGN.md)

## 分层与 owner 地图

```text
carrier -> ITransmission -> VirtualEthernetLinklayer -> exchanger -> 宿主/中继工作

client: VEthernetNetworkSwitcher -> VEthernetExchanger
server: VirtualEthernetSwitcher -> VirtualEthernetExchanger（每个主会话）
```

`ITransmission` 将 carrier 字节转换为已成帧 payload。`VirtualEthernetLinklayer` 将每个已解码 payload 解释为动作 opcode。具体 exchanger 实现 client 或 server 的动作 handler；链路层本身不是顶层运行时 owner。

## Client 与 server 职责

| 一侧 | 顶层 owner | 会话 owner | 主要边界 |
|---|---|---|---|
| Client | `VEthernetNetworkSwitcher` | `VEthernetExchanger` | 宿主设备/虚拟协议栈、路由、DNS 策略、代理及 client 侧动作 |
| Server | `VirtualEthernetSwitcher` | `VirtualEthernetExchanger` | 监听器、按会话注册、转发、中继设施及共享策略 |

exchanger 有主 transmission 路径，但 client TCP/代理和 VMUX 路径可以创建子 carrier transmission。因此 carrier 类不能等同于“整个隧道会话”。

## 会话建立边界

carrier 必须先完成 `ITransmission` 握手，隧道动作才能流动。当前握手交换携带 NOP 包、`session_id`、`ivv` 和 `nmux`；方法级顺序及角色名注意事项见[握手序列](HANDSHAKE_SEQUENCE_CN.md)。

成帧后，`VirtualEthernetLinklayer::Run()` 将动作 payload 送入 `PacketInput()`。首字节选择 information、keepalive、LAN、原始 NAT/IP 转发、TCP relay、UDP relay、echo、static mapping、FRP 或 MUX 等动作。方向和可接受性由具体 handler 定义，而不是统一 opcode 方向规则。

## 数据流形态

```text
client 宿主或虚拟协议栈事件
  -> client exchanger Do* 动作
  -> ITransmission write
  -> carrier
  -> server ITransmission read
  -> server exchanger On* handler
  -> relay、forwarding 或 server 设施
```

响应沿相反的 owner 链返回。准确的宿主数据包路径会随协议和平台变化；[数据包生命周期](PACKET_LIFECYCLE_CN.md)专门记录这些分支，而不是宣称存在单一 TAP/lwIP 路径。

## MUX、子链路与 P2P

握手 `nmux` 位是 carrier/session-path 信号，不是完整 VMUX 生命周期。当前 VMUX setup 从链路层 `MUX` 交换开始，打开最多为配置数量的子 carrier transmission，并在这些子链路上使用 `MUXON`。初始 server 侧 `MUX` 处理回复的是 `MUX`；`MUXON` 是子链路附着交换。

直连 P2P 实现代码虽然存在，但 production authenticated-control capability gate 为 false。正常执行应记录为 relay-only，而不是活跃直连投递。

## 相关页面

- [传输与受保护会话层](TRANSMISSION_CN.md)
- [数据包生命周期](PACKET_LIFECYCLE_CN.md)
- [客户端架构](CLIENT_ARCHITECTURE_CN.md)
- [服务端架构](SERVER_ARCHITECTURE_CN.md)
