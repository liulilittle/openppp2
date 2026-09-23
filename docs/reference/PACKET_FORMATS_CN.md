# 包格式（内部）

> Status: 内部 — 与实现耦合
> Type: 基于源码的线上格式实现说明
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer documents: [English](PACKET_FORMATS.md) · [链路层协议](LINKLAYER_PROTOCOL_CN.md) · [传输握手与会话 ID](TRANSMISSION_PACK_SESSIONID_CN.md)

> **边界：**这些内容是当前 C++ 实现细节，不是公共 SDK 或正式兼容性规范。
> 本文刻意不提供原始数据包样本。

## 常规隧道帧

`ITransmission` 负责常规隧道分帧。它先完成分帧和解密，
`VirtualEthernetLinklayer` 才会看到 opcode。

| 条件 | 当前形式 |
|---|---|
| 握手前，或启用 `key.plaintext` 时 | 先生成二进制 transmission packet，再套入 base94；解码时按相反顺序处理。选择 base94 本身并不能说明当前二进制 cipher 对象是否存在。 |
| 初始 base94 发送 / 接收 | 发送端输出 7 字节头（4 字节 simple 区加 3 字节验证区）；接收端在验证该形式前也期待该形式。 |
| 后续 base94 发送 / 接收 | 每个方向各自在状态改变后使用 4 字节 simple 头。这是有状态的实现行为，不是协商出的头版本。 |
| 握手完成且禁用 `key.plaintext` 时 | 使用带 3 字节长度头的直接二进制路径。payload 是否使用 cipher 仍取决于当前两个 cipher 对象是否都存在。 |

base94 头中随机生成的 key 和 filler 值位于可打印 ASCII 范围 `0x20`–`0x7e`。二进制
packet 路径还可能应用受配置控制的变换。两者均不构成安全性或互操作性保证。

## Static-echo UDP 编解码器

`VirtualEthernetPacket.cpp` 中的 `PACKET_HEADER` 由当前 static-echo UDP 调用方使用，
包括 client static-echo channel 与 server static-echo 路径。它**不是**常规
`ITransmission` 隧道流量的分帧格式。

该 packed struct 是变换前的表示，而非固定的最终线上布局：可选的 protocol-header
加密会在 shuffle、masking 和最终 delta encoding 前重建从 `checksum` 开始的部分。

| 字段 | 源码类型 | 当前职责 |
|---|---|---|
| `mask_id` | `uint32_t` | 非零的包级混淆输入 |
| `header_length` | `uint8_t` | 混淆后的头长度值 |
| `session_id` | `int32_t` | 有符号的会话/包族选择值 |
| `checksum` | `uint16_t` | 在变换前的 header 和 payload 上计算的 Internet checksum |
| `posedo` endpoint | packed IPv4/port 字段 | UDP/IP 端点元数据 |

`mask_id` 是 `uint32_t`，不是字节。`checksum` 由 `ppp::net::native::inet_chksum`
计算；它是完整性/错误检查，**不是密码学认证**。

恢复后的 `session_id` 为负时选择 IP 路径，为正时选择 UDP 处理。解码后的
`VirtualEthernetPacket` 使用 `Protocol` 记录该结果，不存在 `VirtualEthernetPacket.udp`
字段。

## 职责分界

- 常规隧道分帧和链路层 payload 交付应以 `ITransmission` 行为为准。
- 仅在当前 static-echo UDP 编解码器路径中使用 `VirtualEthernetPacket::Pack` / `Unpack`。
- 所有变换顺序、尺寸和字段行为都与实现耦合；不要据此建立外部线上兼容性契约。

## 验证边界

当前 `tests/cpp/CMakeLists.txt` 没有以 `VirtualEthernetPacket.cpp` 为源的 target；CI
测试工作流会对该 manifest 运行 `ctest`。这份基于源码的说明不是数据包样本或
互操作性验证。

## 源码定位

- `ppp/transmissions/ITransmission.cpp` — 二进制/base94 帧选择及 7/4/3 字节头行为
- `ppp/app/protocol/VirtualEthernetPacket.{h,cpp}` — `PACKET_HEADER`、变换、checksum 和 `Protocol`
- `ppp/app/client/ExchangerStaticEchoChannel.cpp`、`ppp/app/server/VirtualEthernetDatagramPortStatic.cpp` 与 `ppp/app/server/VirtualEthernetSwitcher.cpp` — 当前 static-echo UDP 使用路径
- `tests/cpp/CMakeLists.txt` 与 `.github/workflows/test.yml` — 当前测试 manifest 证据
