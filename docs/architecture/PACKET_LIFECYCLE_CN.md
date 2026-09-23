# 数据包生命周期
> Status: Active
> Type: Architecture
> Last verified: `ppp/tap/`, `ppp/ethernet/`, client/server exchanger, and transport sources, 2026-07-22
>
> **用途：**展示主要数据包路径分支，而不虚构通用线上或宿主路径。
> **适用对象：**排查转发行为的贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Packet Lifecycle](PACKET_LIFECYCLE.md)

## 关键修正

当前运行时不能被准确描述成单一、无条件的“Ethernet/TAP → lwIP → 加密 tunnel → Ethernet/TAP”图。它主要处理 IP 包，具有直接 NAT 路径、按协议拆分的 TCP/UDP/ICMP 路径、代理 socket 路径以及平台专属设备适配器。配置的 plaintext 行为也意味着“加密”不是通用表述。

## 原生 client 入站

```text
选中的 ITap 实现
  -> VEthernet::Open() 安装的 callback
  -> IPv4 解析 / packet dispatch
  -> 直接 NAT 分支、虚拟协议栈 TCP，或 UDP/ICMP 分支
  -> VEthernetExchanger Do* 动作
  -> ITransmission write
```

`ITap::AsynchronousReadPacketLoops()` 调用已安装设备 callback。`VEthernet::Open()` 在分发前解析 IPv4 输入；原始 `OnPacketInput(Byte*, ...)` hook 并不是每个包无条件的第一步。

满足条件的虚拟网络原始 IPv4/IPv6 流量可以直接到达 `VEthernetExchanger::Nat()` 与 `DoNat()`。TCP 进入虚拟协议栈连接路径。UDP 可以进入 DNS、static-echo 或普通 `SendTo()` 中继；ICMP 有独立路径。这些选择取决于包类型和当前配置。

## Tunnel 与 server 处理

`ITransmission` 对链路层 payload 成帧/变换，并通过 TCP、WS 或 WSS 传递。接收后，`VirtualEthernetLinklayer::PacketInput()` 将首个已解码字节作为动作 opcode，并调用具体 handler。

server 侧 `VirtualEthernetExchanger` 随后在其 switcher/session 上下文中完成动作的会话工作，例如 TCP/UDP relay、原始 NAT/IP、ICMP、FRP、static echo 或 MUX。本文刻意不重复 opcode 与线上格式参考材料。

## 回程

响应遵循互惠分支，而不是固定路线：

```text
server relay / forwarding 结果
  -> server Do* 动作 -> server ITransmission write
  -> carrier -> client ITransmission read
  -> client On* 动作 / 虚拟协议栈 / datagram manager
  -> VEthernet::Output() -> 选中的 ITap output
```

`TapStub` 接受 output 调用，但会按设计丢弃字节。其他平台适配器通过原生设备或嵌入边界注入。

## MUX 与子 carrier

VMUX 不是“许多逻辑流精确共享一个 `ITransmission`”。当前 setup 可以打开子 carrier transmission，并通过后续 `MUX`/`MUXON` 交换附着它们。初始会话与子链路是不同的 carrier 对象，但共享更高层会话所有权。

## 排查数据包时的限制

- 链路层在 opcode 后解析动作专属字段；它没有通用 opcode 加 16 位 length 的记录格式。
- 基础 dispatcher 中 `KEEPALIVED` 会更新活动时间；那里没有定义通用 ACK 行为。
- 动作方向拒绝依赖具体 handler，而不是对全部动作全局保证。
- 原始 NAT 承载转发 payload 字节，不只是穿透元数据。
- 分片、QoS 和平台行为还有额外分支；发布运维结论前应按当前实现核对。

## 源码地图

- `ppp/tap/ITap.cpp` 及平台 `Tap*` 实现
- `ppp/ethernet/VEthernet.cpp` 与 `VNetstack.cpp`
- `ppp/app/client/ClientPacketDispatchHandler.cpp`
- `ppp/app/client/VEthernetExchanger.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp`
- [传输与受保护会话层](TRANSMISSION_CN.md)
