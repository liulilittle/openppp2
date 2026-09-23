# 链路层协议（内部）

> Status: 内部 — 与实现耦合
> Type: 基于源码的隧道实现说明
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer documents: [English](LINKLAYER_PROTOCOL.md) · [包格式](PACKET_FORMATS_CN.md) · [传输握手与会话 ID](TRANSMISSION_PACK_SESSIONID_CN.md)

> **边界：**本文描述当前隧道 C++ 实现及其线上行为。它不是公共 SDK、协议 API
> 或正式兼容性规范。

## 分帧边界

`ITransmission` 负责隧道分帧，并有条件地使用加密和 base94 封装。
`VirtualEthernetLinklayer` 取得一条已经解码的 transmission payload 后再进行分发。

链路层消息以一个字节的 action opcode 开始，后面直接跟该 action 的 payload。此层**没有
通用的 `uint16_t` 长度字段**；每种 action 使用自己的解析器，消息边界由外层
`ITransmission` 帧提供。

## 已知 action code

下表是 `VirtualEthernetLinklayer.h` 中当前的 `PacketAction` 值，也是实现中
known-action 检查接受的值。已知 opcode 不代表其 payload 有效，也不建立稳定的方向或
兼容性契约。

| 代码 | Action | 当前用途 |
|---|---|---|
| `0x20`–`0x25` | `FRP_ENTRY`、`FRP_CONNECT`、`FRP_CONNECTOK`、`FRP_PUSH`、`FRP_DISCONNECT`、`FRP_SENDTO` | FRP 映射与中继动作 |
| `0x28` | `LAN` | LAN 地址/掩码通告 |
| `0x29` | `NAT` | 原始 IP/NAT payload 转发 |
| `0x2A`–`0x2D` | `SYN`、`SYNOK`、`PSH`、`FIN` | TCP 中继动作 |
| `0x2E` | `SENDTO` | UDP 中继动作 |
| `0x2F`、`0x30` | `ECHO`、`ECHOACK` | Echo 请求与确认 |
| `0x31`、`0x32` | `STATIC`、`STATICACK` | Static 查询与确认 |
| `0x35`、`0x36` | `MUX`、`MUXON` | MUX 建立与确认 |
| `0x7E` | `INFO` | 信息信封 |
| `0x7F` | `KEEPALIVED` | 活动保活 |

dispatcher 落入末尾时，结构无效的已知 action 记录 `ProtocolFrameInvalid`；未知 opcode
记录 `ProtocolPacketActionInvalid`。具体 handler 仍可能发布更具体的诊断错误。

## 关键行为

- **`KEEPALIVED`：**接收后只更新链路层活动时间并返回成功，不会生成确认帧。
- **`NAT`：**opcode 后的非空字节以原始 payload 传给 `OnNat`；空 NAT payload 成功返回，但不会调用 `OnNat`。
- **`INFO`：**当前客户端和服务端路径都使用它。源码中的发送入口是 `DoInformation(...)`。

当 `INFO` payload 至少有 28 字节时，decoder 读取按网络字节序排列的 packed
`VirtualEthernetInformation` base，剩余字节作为扩展文本。空 INFO payload 会成功返回，
但不会调用 information handler；非空但短于 base 的 payload 会作为无效已知 action
落入末尾。实现会尝试解析扩展，但仅扩展解析失败本身不会拒绝完整 INFO 消息。

| Base 字段 | 源码类型 | 字节数 | 含义 |
|---|---:|---:|---|
| `BandwidthQoS` | `Int64` | 8 | 带宽 QoS 值 |
| `IncomingTraffic` | `UInt64` | 8 | 剩余入站额度 |
| `OutgoingTraffic` | `UInt64` | 8 | 剩余出站额度 |
| `ExpiredTime` | `UInt32` | 4 | 过期时间 |
| **合计** |  | **28** | Packed base payload |

当前 extension parser 识别 IPv6 模式 `None`、`Nat66` 和 `Gua`。其 JSON 字段是实现数据，
不是公共 schema 保证。

## 验证边界

当前 `tests/cpp/CMakeLists.txt` 没有以 `VirtualEthernetLinklayer.cpp` 为源的 target；CI
测试工作流会对该 manifest 运行 `ctest`。本 action 表和 parser 说明基于源码，不是完整
帧样本或互操作性验证。

## 源码定位

- `ppp/transmissions/ITransmission.{h,cpp}` — transmission 分帧边界
- `ppp/app/protocol/VirtualEthernetLinklayer.{h,cpp}` — opcode enum、分发、诊断与 `DoInformation`
- `ppp/app/protocol/VirtualEthernetInformation.{h,cpp}` — packed 信息 base、扩展和 IPv6 模式
- `tests/cpp/CMakeLists.txt` 与 `.github/workflows/test.yml` — 当前测试 manifest 证据

修改时应以源码为准；action 的方向和 payload 细节属于运行时实现行为，不是稳定的外部
契约。
