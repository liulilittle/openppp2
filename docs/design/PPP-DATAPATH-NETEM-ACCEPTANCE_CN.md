# PPP-DATAPATH-NETEM-ACCEPTANCE — 严格 datapath 网络损伤验收设计

> Status: Draft / one strict v3 pilot sealed with 36/36 valid cells; performance assessed_fail; campaign not launched
> Type: Design
> Last verified: working tree

## 1. 目的与状态边界

本文定义 datapath 严格网络损伤验收的 v3 配置、证据链和后续性能验收边界。16 个 profile 的有界 root namespace preflight 已通过；它只证明配置、挂载位置、有限 UDP 流量和 BPF 计数器语义可被检查，**不是**已经发起或完成的性能验收结果。

一次 profile-bound pilot 在 pre-iperf 阶段因错误地要求 server `POINTOPOINT` TUN 而停止：正常 compat server 没有 host `POINTOPOINT` TUN。该 pilot 的结论为 `not_assessed`，不重跑；它不产生性能通过结论。

2026-09-08 的新 pilot 已完成并封存于 `artifacts/g6-v3b-0908/`：`rtt-75-j20-iid-loss-0p5`、seed 73，36/36 cell 证据有效，18 个对比对为 **3 pass / 15 assessed_fail / 0 not_assessed**，无全局证据错误。总体为 `assessed_fail`，不是性能验收通过；完整 campaign 仍未启动。修复及结果见第 9 节。

v2 验收格式、语义和兼容性保持不变；v3 仅以附加的网络 profile、损伤证据和 source inventory 输入扩展 v2，不替换 v2。

## 2. 封闭 profile 集合

v3 共有 16 个 profile：

| 类别 | Profile |
| --- | --- |
| 固定 RTT | `rtt-35-fixed`、`rtt-55-fixed`、`rtt-75-fixed`、`rtt-90-fixed`、`rtt-100-fixed` |
| 对应的 j20 | `rtt-35-j20`、`rtt-55-j20`、`rtt-75-j20`、`rtt-90-j20`、`rtt-100-j20` |
| 75 ms j20 周期丢失 | `rtt-75-j20-periodic-loss-0p1`（N=1000）、`rtt-75-j20-periodic-loss-0p5`（N=200）、`rtt-75-j20-periodic-loss-1p0`（N=100） |
| 75 ms j20 IID 丢失 | `rtt-75-j20-iid-loss-0p1`（1000 ppm）、`rtt-75-j20-iid-loss-0p5`（5000 ppm）、`rtt-75-j20-iid-loss-1p0`（10000 ppm） |

目标 RTT 的单向基础延迟为 RTT 的一半。j20 在两个方向各自施加独立的均匀 ±10 ms jitter，因此观测 RTT 大致在目标值 ±20 ms 的范围内变化；两个独立均匀变量之和并不使 RTT 本身服从均匀分布。每个 netem qdisc 的队列上限固定为 32,768 个包。

IID profile 使用 netem 的独立随机丢包，概率分别为 1000、5000、10000 ppm。周期 profile 不把随机丢包加入 netem，而是在 carrier SKB 上按 `PERIODIC_EVERY_N` 丢弃：每处理一个 SKB 增加 `seen`，且仅当 `seen % PERIODIC_EVERY_N == 0` 时丢弃并增加 `dropped`。因此周期计数必须满足对应观察窗口的 floor-division 增量语义，而不是按短时间样本估计概率。

## 3. 强制方向与拓扑位置

损伤只能放在 tunnel namespace 的 server-facing/client-facing carrier veth 上：

- client → server：`dt…b`，即 tunnel server-facing 接口；
- server → client：`dt…a`，即 tunnel client-facing 接口。

preflight 同时验证这两个接口均为 `br0` 的 veth slave，并用定向 UDP echo 的 TX 计数证明上述方向实际到达相应接口。正式 v3 执行中，client namespace 必须发现唯一的 `POINTOPOINT` overlay sentinel，并用它保留 formal target 的 route proof；正常 compat server 不创建 host `POINTOPOINT` TUN，因此 server 侧 sentinel 固定为 target service 所在 server namespace 的 loopback `lo`（`server_target_loopback`），不等待或发现 server overlay。控制链路、client overlay sentinel、server target-service loopback sentinel 和其他非目标接口的 `pre`、`immediate`、`post` qdisc 快照必须不含 netem。不得把损伤迁移到控制路径、overlay 路径、target-service loopback 或只凭接口名称推断方向。

## 4. 输入与证据链

j20 的均匀分布输入为 `tools/uniform.dist`。它复制到本次运行私有的 `TC_LIB_DIR` 后才供 `tc netem distribution uniform` 使用；源文件和副本都必须满足固定的 4096 个有符号十进制样本序列（`-32768` 至 `32752`，步长 16）。

周期 carrier-SKB 丢失程序源为 `tools/datapath_fixed_loss.bpf.c`。它复制为本地证据源 `periodic-bpf/source.c`，并且只生成、保留和挂载一个带 BTF 的 runtime object `periodic-bpf/datapath_fixed_loss.bpf.c`：

```bash
clang -O2 -g -target bpf -DPERIODIC_EVERY_N=<N> \
  -c periodic-bpf/source.c -o periodic-bpf/datapath_fixed_loss.bpf.c
```

该对象以保留的精确 apply argv 挂载：`tc filter replace dev <IFACE> egress protocol all chain 0 bpf da obj periodic-bpf/datapath_fixed_loss.bpf.c sec carrier_egress`。因此 `egress` 和 `sec carrier_egress` 是命令证据的一部分。实际 `tc -j -s -d filter show dev <IFACE> egress` readback 可以包含一条 terse companion 和一条 detailed record，也可以只有 detailed record；readback 通常没有 JSON `egress` 字段和 `options.section`。验证改为要求所有记录均为 `protocol=all`、`chain=0`、相同的正 `pref` 和 BPF，detailed record 还必须是 direct-action、具有 canonical `bpf_name` `datapath_fixed_loss.bpf.c:[carrier_egress]`、无额外 tc actions，以及正的嵌套 `options.prog.id`，而不虚构 readback 不提供的字段。

周期 BPF 的 nested qdisc 证据保留原始 JSON：安装前的 `pre` 是包含 root netem 的完整快照，且不得含 `clsact` 或 BPF；安装后 `immediate` 和 `post` 通过 `clsact` selector 单独采集，且各自必须恰好为一条 canonical `clsact` record。安装后的完整 netem 快照独立保留，用于配置与计数器检查，不能把它误当作 clsact selector 输出。

有界 UDP echo 前后，root netem 的 bytes/packets 必须增加，drops 必须非递减，所有 profile 的 `overlimits` 必须为零；无丢失 profile 的 drops 仍必须为零。周期 profile 中，kernel 可能将 direct-action `TC_ACT_SHOT` 计入 root-netem drops，故其丢失的权威证据是通过 ctypes/libbpf API 读取实际 `counters` map（不是 `bpftool` 或推测的发送包数）：`seen_delta >= N`、`dropped_delta > 0`，且 `dropped_delta == post_seen // N - immediate_seen // N`。map 还必须是唯一的 `counters` 单元素 array map，使用 4-byte key 与 16-byte value。

IID 的短 UDP 运行只需验证配置和 readback；它不要求在有限样本中观察到一次随机丢包。

## 5. 有界 preflight

具备 root、network namespace、`tc` direct-action BPF、clang BPF target 和 libbpf map API 能力的 Linux 主机可运行：

```bash
bash tests/integration/linux/datapath_netem_contract_preflight.sh
```

该脚本创建三个一次性 namespace，建立 client/tunnel/server bridge 拓扑，逐项应用 16 个 profile，并在退出时清理 namespace、root-side veth、子进程及私有临时状态目录。它不启动 PPP、不使用 candidate binary、不采集性能指标，也不构成 benchmark；成功输出仅表示“bounded datapath netem/BPF contract preflight completed; no performance campaign was run”。因此该 root preflight 不加入常规 CI。

## 6. 尚未发起的完整 campaign

完整 campaign 尚未启动。计划矩阵为 16 个 profile × 36 个固定 workload cell，共 576 个 cell；在可审计的隔离环境中完成、封存并评估之前，不得把 preflight、单对象 BPF 证据或任意单个运行描述为全部性能验收通过。已完成的新 pilot 仅覆盖一个 profile，其性能结论仍为失败。

后续把 v3 接入正式 runner 时，`run --network-profile <profile> --netem-seed <seed>` 必须将两项作为一个成对选择：v3 运行必须同时提供两项，单独提供任一项必须失败；两项均未提供时仅保留历史 v2 语义。这是后续接口约束，不代表当前已经以该命令启动任何 campaign。

接受阈值保持不变：每个已评估的 paired workload ratio 必须达到 `>=1.20`。v3 的网络损伤扩展不降低该阈值，也不将未评估 cell 转换为通过。

## 7. NDI TSO 边界

NDI TSO 仍为 default-off 的实验能力。即使显式启用，也必须遵守保守的 single-flight recovery gate：当 retransmission queue 非空或 recovery 处于 active 状态时不得发送 TSO。不得为了本设计的网络损伤 profile 或吞吐结果移除该 gate；当前 preflight 也不验证或宣称 NDI TSO 性能结论。

## 8. 结论

本文记录的是 v3 输入、部署位置、证据要求和待执行的验收计划。当前没有 576-cell campaign 完成的声明，也没有性能通过声明。

## 9. 2026-09-08 OOO 候选与真实 pilot 验证

`glm-5.3-flash` 独立执行验证，主代理核对原始结果。OOO 候选只改变上游接收重叠段的清理/裁剪，未改变 NDI TSO、recovery、single-flight 或性能阈值。两侧都已包含先前 NDI 控制块精简和 VNET 指针偏移优化。

- 原版二进制 SHA256：`86793664eef6818770a0e7206cdd26ee4c78ba43de1b80c1a0ff261ca23c193c`。
- 候选二进制 SHA256：`c17f1d320b9f8f398a09cf5163e9a5bb0b5602ac5bb28e487c88d7de1e177fbe`。
- 正确性验证：28 个定向重叠/FIN/回绕场景原版失败、候选通过；候选 C++ 137/137、历史 fault suite 20/20 通过。

无损伤历史同等 P1 UL 对照（10s + 2s omit、CPU8、GSO-on、direct bridge，三轮交错原版/候选，各自配 native）位于 `artifacts/gpt6fix-ooo-historical-ab-20260908-r2/`。12/12 cell qualification 通过，三轮 XTCP goodput（Mbps）如下：

| Round | 原版 | OOO 候选 | 候选/原版 | 候选/native |
| --- | ---: | ---: | ---: | ---: |
| 1 | 908.75 | 903.10 | 0.9938 | 1.2447 |
| 2 | 822.42 | 892.68 | 1.0854 | 1.2529 |
| 3 | 836.03 | 836.86 | 1.0010 | 1.1640 |

配对候选/原版中位数为 1.000987，native 归一化增益中位数为 1.003991；没有稳定吞吐提升证据。两侧本轮均无重传、direct upload reject 或 resume，未复现历史低速事件，不能宣称其端到端根因已完全消除。不能用两组独立吞吐中位数之比替代配对提升结论。

真实 v3 pilot 暴露并修复了两处采集问题：

1. 系统 `tc -j -s -d qdisc show` 的 `fq` 统计输出重复 `throttled` 键。无 netem sentinel 改用配置快照 `tc -j -d`；目标 netem 仍采集 `-s` 统计，严格 JSON、非目标无 netem、计数递增等校验保持不变。
2. link pre 原先采在安装 netem 前，post 中预期的 `qdisc=noqueue→netem` 被误判为流量期间漂移。link pre 移到 netem/BPF 配置完成之后、流量开始之前；qdisc pre 仍在配置前，配置一致性验证器未放宽。

另一次长路径尝试中，128 字符的 distribution 文件路径被本机 `tc` 截断为 `uniform.dis`；文件实际存在。本次改用短 artifact 根，不改变分布文件、profile 或 seed。各次失败目录均保留，没有覆盖或转换为通过。

最终 `artifacts/g6-v3b-0908/acceptance-report.json` 的三轮 XTCP/native 比值：

| 并发 | UL（R1 / R2 / R3） | DL（R1 / R2 / R3） |
| --- | --- | --- |
| P1 | 0.6433 / 0.5787 / 0.7351 | 0.9792 / 1.0777 / 1.1961 |
| P4 | 0.7485 / 1.1071 / 0.6398 | 1.4077 / 1.0697 / 0.9108 |
| P16 | 1.4439 / 1.1582 / 1.5541 | 1.1073 / 0.9304 / 1.1910 |

六个 workload 均未实现三轮全部 `>=1.20`。pilot 已证明修正后的 server `lo` sentinel、双向损伤及完整证据链可以走通；未证明 Route 1/2/3 性能目标完成。

后续优先单独验证 DL 短批次 pacing 额度回收：隔离虚拟时间实验中，100MB/s pacing 的 16KiB 批次原先被预收 64KiB quantum 的 655µs，候选按实际用量回收后为 164µs；pacing gate/integrity、pacing update、persist 三项回归通过。这不是端到端吞吐结果，该候选未混入上述 OOO 二进制。诊断应锁定实际数据 flow，并分别记录本地 XTCP 与 carrier TCP 的窗口/RTT/ACK/pacing；不能把 carrier 的 75ms RTT 直接代入本地 XTCP，也不能在禁止 PERF_JSON 的正式 pilot 中开启诊断变量。
