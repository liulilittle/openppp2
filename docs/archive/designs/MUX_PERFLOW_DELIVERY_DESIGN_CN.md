# MUX 按流交付设计说明（mux-perflow-delivery / flow v2）

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期、Git 历史及 main 最新验证记录，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。

> Status: Implemented
> Type: Design
> Last verified: 2566750

首版接收端 per-flow 定序能力已经落地。本文件是仓库内的设计参考，配合 spec
`.kiro/specs/mux-perflow-delivery/`（design / requirements / tasks）。技术术语保留英文。

## 定位

本特性是 GitHub issue #5（`--mux-mode` 调度策略）的"真正多链路聚合"阶段，即 **flow v2**：在已实现的发送侧调度器（`compat`/`flow`/`balance`/`stripe`）之上，新增**接收端按连接（per-flow）定序**这一可协商能力，消除接收端队头阻塞（HOL blocking）。当前启用场景是 `balance`、`stripe`，以及 `flow` 开启 `mux.turbo` 时。

## 为什么需要它（根因）

当前 VMUX 线协议用**单一全局序号窗口**：

```cpp
// ppp/app/mux/vmux_net.h —— 9 字节 packed
typedef struct { uint32_t seq; uint8_t cmd; uint32_t connection_id; } vmux_hdr;
// status_.tx_seq_  发送端单调递增（每帧 ++，不分连接）
// status_.rx_ack_  接收端严格按全局 seq 交付，乱序帧进全局 rx_queue_
```

后果：`balance`/`stripe` 把不同连接的帧发往不同链路后，接收端仍按单一全局 `rx_ack_` 串行交付。`flow+turbo` 还会动态预热额外承载，进一步提高跨链路乱序概率。慢链路上某个 seq 未到，全局 `rx_ack_` 停步，所有连接被一起扣押。**瓶颈在接收端的全局定序，不在发送侧分发。** 所以 `balance` 与 `flow+turbo` 只有在 flow v2 之上才真正有用。

## 核心设计

### 1. 可协商的接收定序模式（安全闸门）

新增 `receiver_ordering_mode { ordering_compat=0, ordering_flow_v2=1 }`。**只有双方都声明支持，才启用 flow v2，否则回退 compat。** compat 对端绝不能被静默当作 flow-v2 接收端（否则误交付乱序数据）。

协商三态：

| Client 声明 | Server 声明/支持 | 结果 |
|---|---|---|
| FLOW_V2 | FLOW_V2 | FLOW_V2 |
| FLOW_V2 | COMPAT / 旧版（字段缺失） | COMPAT |
| COMPAT / 旧版 | FLOW_V2 | COMPAT |
| COMPAT | COMPAT | COMPAT |

安全不变式：`agreed==FLOW_V2 ⟺ 双方 bit0 都为 1`。降级永远安全（fail-safe），绝不静默升级。

### 2. 协商承载：MUX 帧追加 1 字节能力位（实现细节，偏离原设计）

> **与 spec design.md 的偏离**：design.md 设想把协商结果放在 `MUXON` 帧的 `ordering_mode` 字节。实测代码里 **MUXON 是 per-linklayer 的 seq/ack 握手**，而**会话级**的 mux 能力协商走的是 **MUX 帧的客户端→服务端发送 + 服务端回显 MUX**（`VEthernetExchanger`/`VirtualEthernetExchanger::OnMux`）。因此实现把能力位放在 **MUX 帧尾部**（双向都发 MUX，天然双向协商），未改动 MUXON。三态判定与安全性与原设计完全一致。

```cpp
// VirtualEthernetLinklayer.cpp（packed），尾部追加可选字节
typedef struct {
    Byte il; uint16_t vlan; uint16_t max_connections; Byte acceleration;
    Byte ordering_caps;   // bit0 = FLOW_V2；旧端不发送该字节
} VirtualEthernetLinklayer_MUX_IL;
```

向后兼容：解析所需长度仍只覆盖**原有**字段（`sizeof(struct) - 1 - sizeof(Byte)`），`ordering_caps` 按"可选尾部"读取——旧端不发就当 0（=COMPAT）。客户端在 MUX 里声明 `bit0 = mode_requires_flow_v2(mux.mode, mux.turbo)`；服务端 `OnMux` 计算 `agreed = peer_bit0 && mode_requires_flow_v2(local_mode, local_turbo)`，把 `agreed` 回显在它发回的 MUX 帧里；两端在建链前调用 `vmux_net::set_ordering_mode(agreed)`。

### 3. 序号方案：复用 `vmux_hdr.seq`，零线格式扩容

FLOW_V2 下，对 per-flow 数据帧（`cmd_push`/`cmd_fin`），`seq` 解释为该 `connection_id` 的 **per-flow DSN**：

- 发送端为每连接维护 `tx_flow_seq_[connection_id]`（DSN 从 1 起，0 保留给控制帧占位）。
- 接收端按 `connection_id` 用独立 `flow_rx_next_` 定序，独立 reorder 缓冲。
- 控制帧（除 `cmd_fin`）以 `seq=0` 占位，不消耗 DSN，接收端忽略其 DSN。

**诚实的权衡**：`seq` 字段二义（全局 vs per-flow），但换来零 header 扩容、零跨版本对齐风险；安全性完全由能力协商保证（compat 端永不进入 per-flow 解释路径）。若未来要链路质量可观测或 striping 的 per-link seq，再用新的能力位演进到"扩展 header"。

### 4. 接收端 per-flow 交付

每个 `connection_id` 一个 `flow_rx_context`：

```cpp
struct flow_rx_context {
    uint32_t          flow_rx_next_         = 0;     // 期望的下一个 DSN
    rx_packet_ssqueue flow_reorder_;                // map<DSN, 帧>，packet_less 处理回绕
    uint64_t          oldest_buffered_tick_ = 0;     // 最老缓冲帧入队 tick（超时基准）
    size_t            buffered_bytes_       = 0;     // 当前缓冲字节（内存上界）
    bool              primed_               = false; // 已将 flow_rx_next_ 初始化为协议起始值 1
    bool              fin_seen_             = false; // 已交付 FIN
};
```

`packet_input_flow()`：控制帧旁路（不进 DSN 闸门）；新流从协议固定起始 DSN `1` 开始定序，首个观测帧若为未来 DSN 也必须等待缺口；命中 `flow_rx_next_` 立即交付并连续回放；未来帧入有界 reorder 缓冲；过期/重复帧丢弃。一条慢链路只卡它自己那个连接，不影响其它连接。

### 5. 有界内存 + 缺口失败语义（活性）

`flows_`（以及发送侧 `tx_flow_seq_`）按 **`connection_id`（逻辑流）** 索引，**不是**按 carrier / `max_connections`（承载链路数）索引。把“最坏内存”写成 `max_connections × reorder.bytes` 是错误的。

**当前代码（待 P0-A 修正）：** 超限/`flow_evict_expired` 仍可能通过 `flow_force_advance` 跳过缺口并继续交付后续帧；`flow_evict_expired` **只推进** `flow_rx_next_`，**不会**释放 `flows_` 表项。这会造成静默字节空洞，目标语义禁止。

**目标语义（P0-A / P0-B）：**

- 每逻辑流 reorder：`buffered_bytes_ <= mux.flow.reorder.bytes`。
- 会话级 reorder 硬上界：`mux.flow.session_reorder.bytes`（P0-B）。
- 逻辑流 + pre-open 数量硬上界：`mux.flow.max_open`（P0-B）。
- 未知 `connection_id` 预算：`mux.flow.unknown_cid.max`（P0-A/B）。
- 缺口不可恢复（超时、reorder 溢出、单帧超限）时：**reset/close 该逻辑流**（flow_v2）或 **session rebuild**（compat 全局 gap），**禁止** `force_advance` 后静默交付后续帧。
- 遥测：流重置计为 `mux.rx.flow.reset`（或等价名）；`mux.rx.flow.evict` **不得**再表示“跳过字节并已交付”。
- 第一版仍**无 mux 层重传**；丢失/重置由上层 TCP（或会话重建）处理，而不是在 mux 层造空洞。

**最坏 reorder 内存模型：**

```text
per_flow_reorder_bytes   = mux.flow.reorder.bytes
max_open_flows           = mux.flow.max_open          // 逻辑连接 + pre-open（P0-B）
session_reorder_bytes    = mux.flow.session_reorder.bytes  // P0-B
unknown_cid_budget       = mux.flow.unknown_cid.max   // P0-A/B

worst_case_reorder ≈ min(
  session_reorder_bytes,
  max_open_flows × per_flow_reorder_bytes
)
```

### 6. 发送侧不绑定，接收状态不回退

当前 `balance` 发送侧保持竞争法，不做 per-connection link binding；`stripe` 才是实验性逐包轮询。承载链路掉线或 runtime shrink 时，发送侧后续帧继续由剩余可用链路竞争发送。接收侧 `flow_rx_context` 保留、`flow_rx_next_` 不回退；在途丢帧表现为该连接自己的 DSN 缺口，超时后 **fail 该流**（不再 skip 后继续交付）。

## 配置项

| 键 | 类型 | 默认 | 作用 |
|---|---|---|---|
| `mux.flow.reorder.bytes` | int (>0) | 1048576 | 每逻辑流 reorder 缓冲字节上界（已实现） |
| `mux.flow.reorder.timeout` | int (>0, ms) | 400 | 缺口等待超时；超时后应 **fail flow/session**，不是 skip（P0-A） |
| `mux.flow.session_reorder.bytes` | int (>0) | （P0-B 计划） | 会话级 reorder 字节硬上界 |
| `mux.flow.max_open` | int (>0) | （P0-B 计划） | 逻辑流 + pre-open 数量硬上界 |
| `mux.flow.unknown_cid.max` | int (>0) | （P0-A/B 计划） | 未知 cid 缓冲/记账预算，禁止 `flows_` 无界增长 |

不再有独立 `mux.flow-v2` 配置项；所有非 `compat` 模式（`flow` / `balance` / `stripe`）都会声明 flow v2，`compat` 不声明。双方都支持能力字节时启用 flow v2；`balance` / `stripe` 遇到旧 peer 会回退到 `compat`，而 `flow` 保持其调度模式并使用兼容接收顺序。

## 第一版明确不保证

- 不在 mux 层重传（靠上层 TCP 或 session rebuild）。
- 无拥塞控制 / 无 per-flow ACK 反馈。
- `seq` 字段二义，无独立链路质量序号。
- 内存有界，但上界按**逻辑流**计：`worst_case_reorder ≈ min(session_reorder.bytes, max_open × reorder.bytes)`，**不是** `max_connections × reorder.bytes`（`max_connections` 是 carrier 数）。
- `stripe` 仍实验性；本特性只为其提供接收端定序基础。
- 协商是会话级一次性，建链后不热切换。
- 多链路不宣称 HA：单 carrier 丢失在途帧时，P0 以明确 fail（流/会话）为准，不做无 ACK 的无损迁移。

## 接收失败语义（仅三种结局）

对任一逻辑流的数据路径，只允许：

1. **交付**按序、连续的 DSN 数据；
2. **丢弃**重复/过期帧（不推进交付游标以外的副作用）；
3. **失败**——flow_v2 下 reset/close 该流，compat 下全局 gap 超时则 session rebuild——**禁止**静默制造字节空洞后继续交付。

## 验证与默认值门槛

`compat` 保持生产默认值，`stripe` 保持实验性。当前代码和测试已经覆盖协商状态、
旧 peer 回退、每 flow 字节与条目数双上限、in-flight retire，以及 100-cycle
drain-state 单元回归；真实 `vmux_net` grow/shrink sanitizer 测试仍待补齐。benchmark harness 也已落地，但仓库中尚无真实 Linux + mobile
性能 baseline。吞吐、p99、sanitizer 与双平台证据要求见稳定参考
[`VMUX_VALIDATION_CN.md`](../../reference/VMUX_VALIDATION_CN.md)。只有独立 PR 附上完整
benchmark artifacts 与 compatibility results 并满足该参考，才允许讨论修改默认值。

## 代码触点

- `ppp/app/mux/vmux_net.h` / `.cpp`：`receiver_ordering_mode`、`flow_rx_context`、`packet_input_flow`、`deliver_one`、`flow_force_advance`（P0-A 起改为 fail_flow，禁止 skip-and-deliver）、`flow_evict_expired`、`maybe_release_flow` / `fail_flow`、`set_ordering_mode`、`post_internal` 的 DSN 分支、`forwarding` 分流。
- `ppp/app/protocol/VirtualEthernetLinklayer.h` / `.cpp`：MUX_IL 追加 `ordering_caps`，`DoMux`/`OnMux` 增参与长度容忍解析。
- `ppp/app/server/VirtualEthernetExchanger.cpp` / `ppp/app/client/VEthernetExchanger.cpp`：协商 `agreed` 并 `set_ordering_mode`。
- `ppp/configurations/AppConfiguration.h` / `.cpp`：`mux.mode` / `mux.flow.reorder.*`。

详见 spec：`.kiro/specs/mux-perflow-delivery/{design,requirements,tasks}.md`。
