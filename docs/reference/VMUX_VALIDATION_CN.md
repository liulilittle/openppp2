# VMUX 验证与发布门槛

> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer link: [English](VMUX_VALIDATION.md)
> Related: [UI Runtime 契约](UI_RUNTIME_CONTRACT_CN.md)

`compat` 是当前 VMUX 默认值。`stripe` 仍为实验性功能。本文说明已实现的协商/展示行为，以及修改默认值所需的证据；并不表示性能门槛已经通过。

## 运行时状态契约

`ppp::app::mux::MuxRuntimeState` 报告以下事实：

| 字段 | 含义 |
|---|---|
| `requested_mode` | 配置/请求的预设：`compat`、`flow`、`balance` 或 `stripe`。 |
| `effective_mode` | 经能力处理后的协商预设。 |
| `receiver_ordering` | 独立协商的 `compat` 或 `flow_v2` 接收排序。 |
| `scheduler` | 推导的展示字段：`stripe` 为 `round_robin`，其他为 `competition`。 |
| `pool_policy` | 推导的展示字段：仅有效 `flow` 且启用 turbo 时为 `adaptive`，其他为 `fixed`。 |
| `turbo` | 生效的 flow-turbo 标志；它是选项，不是第五种模式。 |
| `reliability` | 协商成功的可靠性子协议（ACK + 断链补发；PTO 与快速重传需显式开启）；与排序正交，compat 下也可启用。 |
| `fec` | 协商成功的 XOR 奇偶 FEC（蕴含 `reliability`）。 |
| `active_links` | 已完成握手且未 retire 的链路数，展示时会被钳制。 |
| `fallback_reason` | 能力回退或会话未激活的机器可读原因。 |

`receiver_ordering` 不是 `effective_mode` 的同义词；消费者必须单独使用该排序事实。

## 排序协商（FLOW_V2 请求）

`ordering_caps` 的 bit0（`FLOW_V2`）是实现能力，客户端总会宣告。bit3（`FLOW_V2_REQUEST`）只由
自身预设需要按流排序的客户端发送（`flow` + turbo、`balance`、`stripe`）。只要两端都宣告了 `FLOW_V2`，
服务端在**自身预设需要或客户端请求**时就同意 `flow_v2`。服务端保留自己的调度预设，只改变两端共享的接收排序。
旧服务端会忽略 bit3，行为不变。

## 接收反压

重排上限（`mux.flow.reorder.bytes`、`mux.flow.session_reorder.bytes`）是软上限，默认值不小于对应的发送窗口（单流 8 MiB、会话 32 MiB）：乱序到达的帧会被选择性 ACK，缺口存在期间发送端仍会继续发送，接收预算小于发送窗口就会重置流。缓存一个乱序帧会超过上限时，
接收端照样缓存，但暂停读取送来该帧的链路，由这条链路自身的 TCP 流控去限制发送端，直到落后的帧到达。
缓冲回落到上限的一半时恢复读取。接收端不会把所有存活链路都暂停；单次暂停最长 `PPP_MUX_RX_PAUSE_MAX_MS`（200 ms），
到时链路会重新读取，因为缺的那一帧可能排在任意一条链路上，包括被暂停的那条。
只有超过 2 倍上限（`PPP_MUX_REORDER_HARD_FACTOR`）才重置流（flow_v2）或重建会话（compat）。
缺口超时在每次按序交付后重新计时，持续乱序但一直在推进时不会超时。
遥测：`mux.rx.backpressure.pause` / `resume` / `release_all` / `lease_expired`。

## 发送调度

只要在途字节低于 `PPP_MUX_LINK_BYTE_HIGH_WATER`（256 KiB），链路就一直留在调度列表里，同一条链路上可以有多帧在途，
链路的写队列会把它们合并成一次 socket 写；之前每条链路每次写完成往返只能发一帧。每一帧发给在途字节最少的链路（相同时选 SRTT 更低的），
因为 socket 缓冲膨胀的链路报告本地写完成的速度和正常链路一样快。compat 下全局序号在帧交给链路时才分配，而不是入队时：
DRR 出队顺序与投递顺序不同，入队时编号会让单条链路上也出现乱序。DRR 会持续轮转，直到某条流的队首帧放得进它的额度
（帧最大 64 KiB，配额 16 KiB），而不是返回去等一个无关事件。读满缓冲一半以上的 push 直接从读缓冲发送、不再拷贝；
更小的读拷进刚好大小的帧，使帧占用的内存接近发送窗口所计的长度。

## 单流发送队列与 XON/XOFF 顺序

开启加速时，push 在写出之前就已完成，流的读泵可能跑在链路前面。以下任一情况下读泵会重新挂到写完成上：会话队列达到
`mux.tx.queue.max`、所在流被发送窗口停放、或该流自身队列达到上限（`PPP_MUX_TX_FLOW_MAX_FRAMES` /
`PPP_MUX_TX_FLOW_MAX_BYTES`）的一半。若仍有帧撞上上限，也不会静默丢弃：flow_v2 只重置该流；compat 的全局序号已经分配，
因此立即重建会话，而不是等缺口超时（`mux.tx.flow_overflow`）。

`cmd_acceleration`（XON/XOFF）携带 `[开关][4 字节版本号]`。flow_v2 下控制帧无序，可能跨链路互相超车，
接收端会忽略版本号不比上次已应用版本新的 XON/XOFF。旧版 peer 只发送、只读取第 1 个字节，仍可正常工作。
接收端在某条流的积压达到 `mux.congestions` 时让对端暂停，降到一半时恢复（之前要等清零才恢复，每个周期都会把管道排空）。

## 可靠性子协议（ACK + 断链补发 + FEC）

MUX 握手 `ordering_caps` 字节新增 bit1（`RELIABILITY`）与 bit2（`FEC`）：客户端按
`mux.reliability.enabled`（默认 true）/ `mux.fec.enabled`（默认 false）宣告，服务端取交集并权威回显。
可靠性在 compat 与 flow_v2 下均可运行：接收侧按序号空间（compat 全局 / flow_v2 per-flow DSN）累积报告已收区间，
发送侧把未确认帧保留在重传缓冲中，其上限（默认 32 MiB）作为发送窗口使用（见下节）。承载链路是可靠字节流，所以默认只在链路断开时补发：
最后写到该链路上的所有未确认帧，以**原序号**在剩余链路上重新注入（`mux.rtx.reinject`）。
一条链路只退出一次：退出时即标记为 retiring，其上仍在途的写完成后不会再把它挂回发送列表；同一链路的第二次退出上报（先写失败、再转发循环结束）直接忽略。
dup-ACK 距离 ≥3 的快速重传（`mux.reliability.rtx.fast`）与 PTO 200ms–3s（`mux.reliability.rtx.pto`）需显式开启：
在可靠链路上它们多数只是把还排在慢链路后面的帧重发一遍。单帧重传次数耗尽或缓冲超过硬上限后退化为既有 `fail_flow` / 会话重建。`cmd_ack`/`cmd_fec` 是无序控制帧，
只在协商成功后发送（旧端遇未知 cmd 会断会话）。FEC 为 XOR 奇偶组（默认 8 帧一组），单组单丢失即时恢复，
缺两帧及以上交给重传。协议细节见 [VMUX 可靠性子协议设计](../design/MUX_RELIABILITY_FEC_DESIGN_CN.md)。

## 发送反压（重传窗口）

在途未确认字节约等于 BDP 加上各链路的内核发送缓冲，高吞吐、高 RTT 的链路在途字节超过重传上限是正常现象。
因此重传上限是帧离开 DRR 队列前检查的发送窗口，而不是终止条件：会话窗口为 `mux.reliability.rtx.bytes`（32 MiB），
flow_v2 下每条流另有 `mux.reliability.rtx.flow_bytes`（8 MiB）。吞吐上限约为 窗口 / RTT
（此前 8 MiB / 2 MiB 时实测单流约 165 Mbps、8 流约 516 Mbps）。再发一帧会越过任一窗口时，该帧留在队列中，
所在流从 DRR 轮转中停放，其他流照常发送（`mux.tx.rtx_window.hold` / `hold_flow`）。被停放的流同时把
socket 读泵重新挂到发送完成上，因此会等待而不是撑爆单流发送队列。释放字节的 ACK 会恢复停放的流并重新驱动调度
（`mux.tx.rtx_window.resume`）；流被重置释放的字节没有 ACK，由可靠性定时器兜底重试。窗口为空时总允许发出一帧，
超大帧不会卡死发送端。只有绕过窗口的帧（turbo SYN）会让缓冲超过窗口，且只有超过 2 倍窗口
（`PPP_MUX_RTX_HARD_FACTOR`）才会失败该流（flow_v2）或重建会话（compat），日志为 `rtx hard cap exceeded` /
`rtx flow hard cap exceeded`。compat 下 `cmd_ack`/`cmd_fec` 同样走优先控制队列，ACK 不会排在被停放的数据之后。

## 回退行为

实现会区分以下情况：

| 请求/条件 | 实际结果 |
|---|---|
| 未知请求模式 | `compat`、`receiver_ordering=compat`、`turbo=false`，并给出 `unsupported_requested_mode`。 |
| `balance` 或 `stripe` 缺少本地或 peer FLOW_V2 | `compat` 和 compat 排序，并给出 `local_missing_flow_v2` 或 `peer_missing_flow_v2`。 |
| 普通 `flow` | 保持有效 `flow`；排序可能为 `compat`。 |
| `flow` 启用 turbo 但缺少所需 FLOW_V2 | 保持有效 `flow`，使用 compat 排序，并报告缺少 FLOW_V2 的原因。 |
| 客户端发送 `FLOW_V2_REQUEST`，服务端预设不需要 flow_v2 | 服务端保留自身预设；两端都宣告 `FLOW_V2` 时同意 `flow_v2` 排序。 |
| client VMUX session 未激活 | 有效模式/排序均为 `compat`；非 compat 配置请求会报告 `mux_inactive`。 |

权威 peer 握手回复会提供协商后的排序，因此 UI 和运维必须同时检查
`effective_mode` 与 `receiver_ordering`。

## 修改默认值所需的发布证据

`benchmarks/vmux/` 中的 harness 和 parser 定义了发布门槛。合格结果至少需要：

- 物理 Linux x86-64（非 WSL）和物理 Android 或 iOS client 的证据；
- endpoint manifest 证明、原始结果 JSON、匹配的环境指纹和时长，以及与 runner 一致的 Linux client commit；
- 每个 client 均有配对的 `off-one-flow` 和 `flow-one-flow` 结果；
- `flow-one-flow` 平均吞吐至少为 mux-off 的 95%；
- `flow-one-flow` 平均 p99 延迟至多为 mux-off 的 110%；
- 零断线，且 buffered-byte/reorder-entry 数值不超过提交的配置上限。

对完整结果包运行验证器：

```bash
python3 benchmarks/vmux/parse_results.py --rollout-gate <results...>
```

当前 benchmark 矩阵覆盖 `off`、`compat`、`flow` 和 `balance` 场景；没有
`stripe` 晋级场景。

## Harness 能证明的内容

默认 `run.sh` 调用是 dry-run：它校验计划，但不会改变网络状态，也不会写结果。真实运行需要 `--execute`、外部 `iperf3` server、可执行的 preparation hook、endpoint manifest，以及本次运行采集的 telemetry。parser 校验提交工件和阈值；它本身不证明物理设备测量或 tunnel 配置确实发生。

仓库源码提供了 harness、parser 和正确性/tooling 测试，但没有合格的 Linux + mobile 吞吐/p99 证据包。提交 `ded25d6` 仍作为已记录的兼容性/正确性基线；它不是合格的发布性能证据包，也不表示默认值修改门槛已经通过。因此本文不声称性能已通过，也不把任何历史 raw commit 或 sanitizer 运行结果作为发布证据。

## 默认值变更规则

在合格证据满足发布门槛前，保持 `compat` 为默认值。除非有单独定义并提供证据的晋级决策，否则将 `stripe` 视为实验性功能。

## 源码参考

- `ppp/configurations/AppConfiguration.cpp`
- `ppp/app/mux/MuxRuntimeState.h`
- `ppp/app/mux/MuxRxBackpressure.h`
- `ppp/app/mux/MuxTxBackpressure.h`
- `ppp/app/client/VEthernetExchanger.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
- `benchmarks/vmux/README.md`、`run.sh` 和 `parse_results.py`
