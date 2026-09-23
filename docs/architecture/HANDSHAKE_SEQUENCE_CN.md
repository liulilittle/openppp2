# 握手序列与会话建立
> Status: Active
> Type: Architecture
> Last verified: `ppp/transmissions/ITransmission.cpp`, 2026-07-22
>
> **用途：**记录当前 `ITransmission` 握手序列，避免把实现细节写成安全性保证。
> **适用对象：**排查承载/会话建立的贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Handshake Sequence and Session Establishment](HANDSHAKE_SEQUENCE.md)

## 范围

这是位于链路动作协议之下的握手。它在原始 TCP、WS 或 WSS 承载建立后开始，并在 `VirtualEthernetLinklayer` 接收已解码动作 payload 前完成。

## 方法级顺序

```text
InternalHandshakeClient:
  NOP -> 接收 session_id -> 生成/发送 ivv -> 接收 nmux
      -> 重建已配置 cipher -> handshaked_

InternalHandshakeServer:
  NOP -> 发送 session_id -> 构造/发送 nmux -> 接收 ivv
      -> 重建已配置 cipher -> handshaked_
```

这些名称是协议方法名，不是 application 角色标签。当前原生调用接线相对常规图是反向的：client exchanger 为主 carrier 调用 `HandshakeServer` 路径，server accept 路径调用 `HandshakeClient`。诊断时应查看 call site，不要仅按方法名推断角色。

## 在线值与当前含义

| 值 | 当前含义 |
|---|---|
| NOP | dummy 的 session-id 风格包。前缀高位标记 dummy，接收方会跳过。 |
| `session_id` | 由 `InternalHandshakeServer` 路径发送的非零会话值。 |
| `ivv` | 新生成的 client `Int128` 值，用于工作 cipher 重建。 |
| `nmux` | 低位携带 MUX 决策；高位携带当前的 obfuscation-flag canary。 |

NOP 数量从配置 bounds 导出，但当这些 bounds 不同可以随机化。不能将它写成固定、确定性的流量模式。

## Cipher 重建边界

启用 ciphertext 时，构造函数先按配置基础 key 创建 cipher 对象。交换后，两条方法路径都用 base-32 `ivv_str` 重建 protocol 和 transport cipher：

```text
key.protocol_key  + ivv_str
key.transport_key + ivv_str
```

`session_id` 与 `nmux` 不会追加到这些字符串。特别是，当前重建代码不把 `nmux` 作为 key-derivation 熵输入；其高半部分 canary 仅用于理解它的 peer 校验兼容 flag。

`handshaked_` 在重建路径之后设置。若配置的 ciphertext 不可用或选择 plaintext 行为，也不能把所有握手后帧写成“已加密”。

## 失败与兼容边界

公开握手包装层会在内部交换前后设置和清除 timeout。读写失败、校验失败、分配失败、timeout 或 disposal 都可能使握手失败。精确的线上成帧和兼容变换属于实现细节；修改互操作行为时应以当前源码为准。

该代码使用变换后的握手包族以及配置的 cipher/transform。本文不能将它表示为已证明的双向认证、PFS 或形式化抗流量分析协议。

## 一起阅读

- [传输与受保护会话层](TRANSMISSION_CN.md)
- [隧道设计](TUNNEL_DESIGN_CN.md)
- `ppp/transmissions/ITransmission.cpp`
