# MUX Turbo 动态承载池设计与实现说明
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 状态：已实现首版（flow 模式 turbo 的运行时动态承载池 + per-flow DSN 协商）。本文件记录当前实现和仍需关注的风险。技术术语保留英文。

## 需求

- `--tun-mux` 重新定位为**最初首包的 per-connection 连接池基数**（base）。
- turbo 开启时，按链路质量**运行时动态增减**承载链路数：
  - 池大小 = `ceil(需求数 / (有效空闲 + 带载倍数)) × factor`，`factor ∈ [1..3]`；
  - **质量越差，池越大**（多开链路扩竞争池）。
- 会话存活期间随质量变化加/减链路，不重建 mux 会话。
- turbo 仍保持发送侧竞争法，不做 per-connection binding；额外叠加“最优链路首包”和 flow-v2 per-flow DSN，避免扩池后某条连接的缺口全局阻塞其它连接。

## 当前实现的不变量拆分

`max_connections`（= `--tun-mux`）仍是建链基数和会话身份，不在运行时修改。turbo 动态池通过拆分状态避免触发整会话重建：

- `max_connections`：base pool，保持不变；非 turbo 时也是硬上限。
- `pool_hard_max`：运行时承载链路硬上限；turbo flow 模式下提升到 `base * PPP_MUX_TURBO_FACTOR_MAX`。
- `pool_current`：turbo controller 的当前目标池大小，范围 `[max_connections, pool_hard_max]`。
- `opened_connections`：只用于初始 base pool handshake 计数，以触发 established；runtime carrier id 改由 `allocate_linklayer_id()` 在 `[1, pool_hard_max]` 空闲槽中分配/复用。

server 端在 flow-capable mux 会话中提前抬高 `pool_hard_max`，允许 client turbo runtime grow 的新链路接入；非 turbo client 不会发送这些额外链路。

flow+turbo 会通过 MUX `ordering_caps` 协商 flow-v2。协商成功后，数据帧的 `vmux_hdr.seq` 改按 `connection_id` 解释为 per-flow DSN；协商失败或旧端则安全回退全局定序。

## 已落地的实现点

### C-B1 调用方：不新增 resize 控制帧
- 当前实现没有新增 `cmd_pool_resize`。
- grow 由本端 `turbo_controller_tick()` 产生 `turbo_pending_grow_`，client `VEthernetExchanger::MuxGrowLinklayers()` 消费该请求并新建一条 carrier TCP。
- 新链路仍走现有 MUX / MUXON 建链握手；server 通过已提升的 `pool_hard_max` 接纳它。
- 好处：不扩张控制帧，不改变 `max_connections`，不引入额外双端 resize 协议。

### C-B2 会话不变量：base / hard / current
- `max_connections` 继续表示 base，不作为 runtime 目标变化。
- `add_linklayer` 配额使用 `pool_hard_max`。
- established 判据仍以 base 完成建链为准；established 后的 `add_linklayer` 进入 runtime 单链路加入路径。
- server `OnMux` 仍用 base 判断是否是同一 mux 会话，避免 runtime grow 被误判为会话重建。

### C-B3 运行时增链路：复用 `add_linklayer`，按 established 分支区分
- 未 established：保持原始批量建链语义，base 全部到齐后 spawn forwarding。
- 已 established：runtime 单链路语义，只 attach 当前这一条链路，只 spawn 一个 forwarding 协程。
- pending runtime link 在握手完成前保留于 `rx_links_` 计入 hard quota，但不进入 `tx_links_`，不给发送 credit。
- handshake 成功后再加入 `tx_links_` 并驱动 `process_tx_all_packets()`。
- runtime grow 失败是 best-effort：只移除/Dispose 新链路，不拆掉已 established 的 base mux。

### C-B4 运行时减链路：retiring + inflight drain
- `retire_linklayer_runtime()` 标记一条额外 link 为 `retiring_`。
- retiring link 不再接收新发送；已有 async write 通过 per-link `inflight_` 计数等待完成。
- `reap_retired_linklayers()` 只在 `inflight_ == 0` 后从 `rx_links_` / `tx_links_` / `primary_linklayer_` / `affinity_links_` 移除并 Dispose。
- 不会退到 base 以下。

### C-B5 质量度量与池大小控制器
- 当前质量 proxy 使用 `tx_queue_` backlog 相对 high-water 的比例：队列越深，目标 factor 越高。
- `factor ∈ [1, PPP_MUX_TURBO_FACTOR_MAX]`，目标池大小 clamp 到 `[base, pool_hard_max]`。
- 控制器每个 cooldown 窗口最多 grow 或 shrink 一步，避免抖动。
- grow 通过 `turbo_pending_grow_` 交给 exchanger；shrink 本地 retire 一条额外 link。

## 仍需关注的风险

- runtime carrier id 已不再通过 `opened_connections` 单调递增分配，避免长时间 grow/shrink 后 `uint16_t` wrap 到 0；仍需在压力测试中覆盖 id 复用路径。
- controller 使用 backlog 作为滞后质量信号，能反映压力但不是 RTT/丢包测量；可能需要后续引入更细粒度的 per-link 质量指标。
- teardown 生命周期仍是 VMUX 的高风险区；当前通过 `retiring_` + `inflight_` 降低 runtime shrink 风险，但全链路 C2/C3 生命周期模型仍需继续推进。
