# 传输与受保护会话层
> Status: Active
> Type: Architecture
> Last verified: `ppp/transmissions/`, carrier adapters, and handshake sources, 2026-07-22
>
> **用途：**定义承载适配器、`ITransmission` 与隧道动作之间的边界。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [Transport and Protected Transmission](TRANSMISSION.md)

## 分层边界

```text
TCP / WS / WSS 承载
  -> 承载适配器
  -> ITransmission：握手、成帧、已配置的变换/密码
  -> VirtualEthernetLinklayer：动作 opcode payload
```

`ITransmission` 是通用的受保护会话/成帧层，不定义隧道动作。`VirtualEthernetLinklayer` 接收完整的已解码 payload，将首字节作为动作 opcode，并把其余字段交给具体 `On*` handler。

## 承载适配器

| 承载 | 适配器 | Server 配置 |
|---|---|---|
| 原始 TCP | `ITcpipTransmission` | `tcp.listen.port` |
| WebSocket | `IWebsocketTransmission` | `websocket.listen.ws` |
| TLS WebSocket | `ISslWebsocketTransmission` | `websocket.listen.wss` |

普通 WS 与 WSS 在 `IWebsocketTransmission.h` 中是兄弟类；二者都继承 WebSocket template，而不是其中一个继承另一个。WebSocket adapter 会先完成包装握手，再委托 OpenPPP2 的 `ITransmission` 握手。WSS 在 WebSocket upgrade 前添加 TLS，但不替代 `ITransmission` 层。

上表字段名是当前准确名称。`websocket.listen.ws.port` 与 `websocket.listen.wss.port` 不是当前配置路径。

## 握手边界

方法级交换为：

```text
NOP 前奏 -> session_id -> ivv -> nmux -> 可选的 cipher 重建 -> handshaked_
```

`InternalHandshakeClient()` 发送 NOP、接收 session id、生成/发送 `ivv`、接收 `nmux`，按配置重建 cipher 后设置 `handshaked_`。`InternalHandshakeServer()` 发送 NOP 和 session id、发送 `nmux`、接收 `ivv`，按配置重建 cipher 后设置 `handshaked_`。

不能把这些方法名直接等同于 application 目录角色：当前 client exchanger 为主 carrier 调用 `HandshakeServer` 路径，而 server accept 路径调用 `HandshakeClient`。

当前 `nmux` 有两项职责：

- 低位携带协商的 MUX 标记；
- 高半部分在当前实现中承载 obfuscation-flag canary，以便理解该 canary 的 peer 拒绝不匹配的 transform flag。

它不是工作 cipher key string 的组成部分。启用 cipher 时，双方用配置基础 key 加 base-32 `ivv` 字符串重建 protocol 与 transport cipher：

```text
protocol key  = key.protocol_key  + ivv_str
transport key = key.transport_key + ivv_str
```

`session_id` 与 `nmux` 都不会拼接进工作 key string。NOP 包通过前缀高位标记为 dummy，接收方会忽略它们；当配置 bounds 不同时，它们的数量不是必然确定的。

这是实现说明，不是形式化认证或前向保密协议的声明。cipher 与 plaintext 行为仍依赖配置。

## 成帧与动作边界

carrier 代码读写字节流。`ITransmission` 根据当前握手/成帧状态以及 plaintext、masking、delta encoding、shuffling 等配置标志处理数据。链路层自身没有通用的 `[opcode][length][payload]` 记录格式：底层成帧先确定消息长度，然后链路层在 opcode 后解析动作专属字段。

接收到 `KEEPALIVED` 时会更新链路活动；基础 dispatcher 没有定义通用的 keepalive-ack 交换。动作方向约束同样依赖具体 handler，不是 parser 的通用规则。

## MUX 与 P2P 限制

握手 MUX 位本身不构成完整 VMUX setup。当前 VMUX 需要后续 `MUX`/`MUXON` 动作，并可能创建子承载 transmission。直连 P2P 仍由共享 capability gate 禁用于生产运行时。

## 复核源码

- `ppp/transmissions/ITransmission.cpp`
- `ppp/transmissions/IWebsocketTransmission.h/.cpp`
- `ppp/transmissions/templates/WebSocket.h`
- `ppp/app/protocol/VirtualEthernetLinklayer.h/.cpp`
- [握手序列](HANDSHAKE_SEQUENCE_CN.md)
