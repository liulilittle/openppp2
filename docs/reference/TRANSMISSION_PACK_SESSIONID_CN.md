# 传输握手与会话 ID（内部）

> Status: 内部 — 与实现耦合
> Type: 基于源码的握手实现说明
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer documents: [English](TRANSMISSION_PACK_SESSIONID.md) · [链路层协议](LINKLAYER_PROTOCOL_CN.md) · [包格式](PACKET_FORMATS_CN.md)

> **边界：**本文描述当前 `ITransmission` C++ 握手及相关隧道 payload 行为。
> 它不是公共 SDK、协议 API 或正式兼容性规范。

## 职责归属

`ITransmission` 负责传输分帧、握手前的会话 ID 交换、握手顺序和密码生命周期。只有
`ITransmission` 返回已解码 payload 后，链路层才会运行。

## 握手顺序

实现按角色使用以下本地步骤：

| 端 | 顺序 |
|---|---|
| 客户端 | `NOPs` → 接收 session ID → 发送 `ivv` → 接收 `nmux` → 有条件地重建 cipher → 标记握手完成 |
| 服务端 | `NOPs` → 发送 session ID → 发送 `nmux` → 接收 `ivv` → 有条件地重建 cipher → 标记握手完成 |

`NOPs` 是伪会话 ID 消息。其数量受配置和随机数影响（当前 helper 使用
`key.kl` / `key.kh`），会话 ID decoder 会跳过标记为伪消息的帧。真实会话 ID helper
消息也包含随机字节和可选 padding；不要从中推导固定数据包样本。

当前 `nmux` 的低位用于选择服务端的 MUX 结果，高 64 位携带分帧配置 canary。仅在
canary 的 magic 存在时，客户端才会比较它；不匹配时发布
`ObfuscationFlagsMismatch`。没有该 magic 并不表示协商出了版本或兼容性契约。

只有当前 protocol 和 transport cipher 对象都存在，且配置中 protocol/transport 名称和
密钥均非空时，才会在设置 `handshaked_` 前重建 cipher。替换密钥会附加当前 `ivv`
表示。这些细节（包括有条件的 canary 检查）属于实现行为，而非线上保证。

## `INFO` 控制 payload

`INFO` 是由 `ITransmission` 分帧的链路层 action，不是第二套传输分帧方案。当前
client 和 server 路径均通过 `VirtualEthernetLinklayer::DoInformation(...)` 发送它。

它的 payload 先是按网络字节序排列、长度为 28 字节的 packed
`VirtualEthernetInformation` base，随后可选地附加扩展文本。

| 字段 | 源码类型 | 含义 |
|---|---|---|
| `BandwidthQoS` | `Int64` | 带宽 QoS 值 |
| `IncomingTraffic` | `UInt64` | 剩余入站额度 |
| `OutgoingTraffic` | `UInt64` | 剩余出站额度 |
| `ExpiredTime` | `UInt32` | 过期时间 |

存在扩展字节时，链路层实现将其保留为 `ExtendedJson`，并调用
`VirtualEthernetInformationExtensions::FromJson`。扩展解析失败本身不会拒绝
`INFO` action；handler 仍会收到 base 和原始扩展文本。该扩展 parser 当前识别的 IPv6
模式为 `None`、`Nat66` 和 `Gua`。扩展字段及其 JSON 拼写均不是外部协议契约。

## 验证边界

当前 `tests/cpp/CMakeLists.txt` 包含一个以 `VirtualEthernetInformation.cpp` 为源的 JSON
单元测试，但没有以 `ITransmission.cpp` 为源的 target。CI 测试工作流会构建该 manifest
并运行 `ctest`；这不是握手或互操作性证据。

## 源码定位

- `ppp/transmissions/ITransmission.{h,cpp}` — 分帧归属、会话 ID helper、顺序、canary 和 cipher 重建
- `ppp/configurations/AppConfiguration.{h,cpp}` — 当前 `key.*` 输入名与已配置 cipher 判定
- `ppp/app/protocol/VirtualEthernetLinklayer.{h,cpp}` — `INFO` 分发和 `DoInformation`
- `ppp/app/protocol/VirtualEthernetInformation.{h,cpp}` — packed base 字段、扩展和 IPv6 模式
- `tests/cpp/CMakeLists.txt` 与 `.github/workflows/test.yml` — 当前测试 manifest 证据

受支持的用法应配置并启动 `ppp` 进程，不应将这些 C++ 或线上细节视为 API。
