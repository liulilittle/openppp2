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
| `reliability` | 协商成功的可靠性子协议（ACK + 快速重传 + PTO）；与排序正交，compat 下也可启用。 |
| `fec` | 协商成功的 XOR 奇偶 FEC（蕴含 `reliability`）。 |
| `active_links` | 已完成握手且未 retire 的链路数，展示时会被钳制。 |
| `fallback_reason` | 能力回退或会话未激活的机器可读原因。 |

`receiver_ordering` 不是 `effective_mode` 的同义词；消费者必须单独使用该排序事实。

## 可靠性子协议（ACK + 快速重传 + FEC）

MUX 握手 `ordering_caps` 字节新增 bit1（`RELIABILITY`）与 bit2（`FEC`）：客户端按
`mux.reliability.enabled`（默认 true）/ `mux.fec.enabled`（默认 false）宣告，服务端取交集并权威回显。
可靠性在 compat 与 flow_v2 下均可运行：接收侧按序号空间（compat 全局 / flow_v2 per-flow DSN）累积报告已收区间，
发送侧在重传缓冲（默认 8 MiB 上限）内以**原序号**跨链路补发丢失帧（dup-ACK 距离 ≥3 快速重传，PTO 200ms–3s 兜底）；
单帧重传次数或缓冲超限后退化为既有 `fail_flow` / 会话重建。`cmd_ack`/`cmd_fec` 是无序控制帧，
只在协商成功后发送（旧端遇未知 cmd 会断会话）。FEC 为 XOR 奇偶组（默认 8 帧一组），单组单丢失即时恢复，
缺两帧及以上交给重传。协议细节见 [VMUX 可靠性子协议设计](../design/MUX_RELIABILITY_FEC_DESIGN_CN.md)。

## 回退行为

实现会区分以下情况：

| 请求/条件 | 实际结果 |
|---|---|
| 未知请求模式 | `compat`、`receiver_ordering=compat`、`turbo=false`，并给出 `unsupported_requested_mode`。 |
| `balance` 或 `stripe` 缺少本地或 peer FLOW_V2 | `compat` 和 compat 排序，并给出 `local_missing_flow_v2` 或 `peer_missing_flow_v2`。 |
| 普通 `flow` | 保持有效 `flow`；排序可能为 `compat`。 |
| `flow` 启用 turbo 但缺少所需 FLOW_V2 | 保持有效 `flow`，使用 compat 排序，并报告缺少 FLOW_V2 的原因。 |
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
- `ppp/app/client/VEthernetExchanger.cpp`
- `benchmarks/vmux/README.md`、`run.sh` 和 `parse_results.py`
