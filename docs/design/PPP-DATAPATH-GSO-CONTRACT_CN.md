# PPP-DATAPATH-GSO-CONTRACT — Linux TapLinux 边缘 GSO 合并设计

> Status: Implemented, opt-in (default-off)
> Type: Design
> Last verified: 2026-09-23 (contract text and implementation paths reviewed; performance evidence is dated inline)

状态：**v1 已实现，默认关闭**。实现位于 `linux/ppp/tap/TapGsoCoalescer.h` 与
`TapLinux`；只有 `OPENPPP2_TAP_GSO_MERGE=1` 才会尝试协商，
`OPENPPP2_TAP_GSO_MERGE_DISABLE=1` 具有最高优先级并强制关闭。

## 0. 证据链（为什么值得做）

| 步骤 | 结论 |
| --- | --- |
| K1/U1 归因 | c1 单核 ~0.3Gbps = TUN(27%) + carrier(23.5%) + crypto(13.4%) + syscall/libc 等多域叠加；TUN 是最大单一域 |
| K2-TUN | 隔离 write(TUN) ≈ 6.86µs CPU/写，是固有 on-CPU 成本 |
| GSO 功能契约 | 双 TUN 探针 2/4/8/16 MSS 全部通过（分段/序号/payload/checksum 逐字节验证） |
| G2-5 B0/B1 | N=4/8/16：writer CPU ns/B 提升 1.64×/2.01×/2.44×；CPU A system-wide 1.80×/2.23×/2.75×；**B1≈B0（边缘组包成本可忽略）**；CPU A softirq 增量 0 |
| MERGEABILITY | 真实 P1 UL：**93.2%** data bytes 位于 run≥4；cap4 写次 **−54.3%**；cap8 **−63.0%**；4 段成形 p95 ≈ 100-200µs；B1 加权端到端预测 **+13.5%** |

## 1. 目标与非目标

目标：在 `TapLinux::Output()` 出口将**实际相邻输出**的 strict-v1 兼容 TCP data 段合并为单个
`virtio_net_hdr + GSO superpacket` 写入，降低每有效字段的 TUN 域 CPU 成本；预期端到端单核 ≥10%。

非目标（明确不做）：

- 不改 wire protocol、`ITap::Mtu`、`IPFrame::Subpackages`、MSS clamp、`IPFrame` 分片语义；
- 不做跨流重排、不做 per-flow 队列（mergeability 实测 flow 交错不是主要限制，ACK 插入才是）；
- 不在 SSMT 多线程路径启用（v1 单 writer 前提）；
- 不引入 per-packet 堆分配；
- 默认关闭的裸 TUN 路径保持原有同步写入返回语义；启用合并后，`Output` 对延迟包在固定存储复制并接管所有权后返回，不表示物理 write 已完成。普通 VNET 写与触发 flush 的回退仍同步报告其直接 write 结果。

## 2. 能力协商（open 时，default-off）

- 不新增 AppConfiguration 字段；`OPENPPP2_TAP_GSO_MERGE=1` 为唯一 opt-in，
  `OPENPPP2_TAP_GSO_MERGE_DISABLE=1` 为最高优先级 kill-switch；
- 仅 Linux；SSMT 启用前会 flush 并永久关闭本实例的合并器，后续写仍使用正确的 VNET 普通帧格式；
- open 时对 TUN fd 执行（顺序固定，任一失败即整体关闭特性并回落现状）：
  1. `TUNGETFEATURES` 判定 `IFF_VNET_HDR`；
  2. `TUNSETIFF` 追加 `IFF_VNET_HDR`；
  3. `TUNSETVNETHDRSZ(sizeof(virtio_net_hdr))` 并 `TUNGETVNETHDRSZ` 回读验证；协商结果必须恰为标准 `virtio_net_hdr`，读缓冲容量按该**实际协商值**计算，不能硬编码 `+10`；
  4. `TUNSETOFFLOAD(TUN_F_CSUM | TUN_F_TSO4)`——实际能力以此 ioctl 结果为准
     （`TUNGETFEATURES` 只是 device flags，不能判定 offload）。
- 任一步失败均关闭该 fd 并以裸 `IFF_TUN|IFF_NO_PI` 格式重新打开；禁用属于正常降级。
- VNET 会改变双向 framing：普通 `GSO_NONE` 入站帧在回调前剥离 virtio 头；合法的
  `GSO_NONE + NEEDS_CSUM` IPv4/TCP 帧会按已验证的 `csum_start/csum_offset` 完成 TCP 校验和；
  合法 TCPv4 GSO 入站帧会软件分段并重算 IPv4/TCP 校验和。非 TCP checksum-partial、未支持的
  GSO 类型或任一 header/offset/长度/flags 异常均 fail-closed：记录日志、设为 `TunnelReadFailed`
  并关闭适配器。该内核帧不会被伪装成交给上层的 IP 包；这是显式硬输入失败，而非“无丢包”保证。

## 3. strict-v1 资格规则（与 MERGEABILITY 分析器逐条对齐）

仅 IPv4 + TCP + 有 payload 的裸 IP 包可入 run：

- IPv4 version/IHL 合法、`total_length <= packet_size`、非分片（MF=0 且 offset=0）、proto=TCP；
- TCP data offset 合法、payload > 0；
- 无 SYN/FIN/RST/URG/ECE/CWR（掩码 0xE7）；
- 与 run 当前状态相比：五元组一致、seq 严格连续（`seq == next_seq`，int32 语义判 gap/rewind）、
  ACK/window/urgent pointer 一致、TOS/TTL/DF 一致、IP options 字节一致、TCP options 字节一致。

中断原因与 MERGEABILITY 相同的互斥枚举（flow_change/seq_gap/seq_rewind/payload_size_change/
ack_change/window_change/urg_change/ip_header_change/ip_options_change/tcp_options_change/
psh/control_flags/…），逐项计数用于线上可解释性。

**PSH 策略（v1）**：任何 PSH 段都中断 run，PSH 段本身走逐包写。
`psh_last_candidate`（仅 run 末段带 PSH 可追加）留作 v2 候选，启用前提是先通过独立的
“内核 GSO 对 PSH 标志传播到最终 segment”的契约验证，v1 不赌该行为。

**IP ID 语义（需评审签字的决策点）**：MERGEABILITY 实测 499,957/499,958 包 IP ID 严格递增
且 DF=100%。GSO 分段后内核自生成各 segment 的 IP ID，**不逐字节复现原输入段的 ID**。
本 contract 采用“TCP/IP 语义等价”而非“host-facing 逐字节等价”：DF 已置位、路径 MTU 内不分片，
IP ID 不承担重组语义。若评审要求逐字节等价，则边缘 GSO 不成立（这是二选一）。

**payload/gso_size 规则**：run 首段 payload 定候选 `gso_size`；中间段必须 == `gso_size`；
短段只能收尾（追加后立即 flush）；大于 `gso_size`、gap、rewind 均中断。

## 4. 状态机

合并器状态、定时器和 VNET 写 fd 由专用 feature mutex 串行化；该锁只进入 VNET/GSO 分支，默认裸 TUN `Output` 路径不加锁、也不访问合并状态。合并器继续使用固定存储，不存 borrowed pointer。

```text
state: idle | open(short_allowed=false)
open run: flow key + normalized header snapshot + next_seq + gso_size
          + segment list(长度/偏移) + start_ns + segments_count + bytes
```

flush 条件（任一触发即完成当前 superpacket 写出，然后按新包语义继续）：

```text
不兼容包（v1 资格/连续性任一失败）
segments == 4（v1 固定上限）
每段长度超过 `ITap::Mtu`（直接普通写）
首段入队后 100µs（`steady_timer` flush）
write 失败/短写
runtime stop / 接口关闭
```

写出内容 = `virtio_net_hdr` + 合并后的 IPv4/TCP 帧：

- `flags=VIRTIO_NET_HDR_F_NEEDS_CSUM`、`gso_type=VIRTIO_NET_HDR_GSO_TCPV4`、
  `hdr_len=IP header + TCP header`、`gso_size=<run gso_size>`、
  `csum_start=IP header length`、`csum_offset=16`；
- TCP checksum 字段 = 伪首部 partial seed（非最终校验和）；
- **IPv4 header checksum 必须在字段清零后计算**（首个原型在此踩坑：
  旧值参与求和会得到 0x0000）；
- 载荷按序拼接；写长度 = `10 + IP total length`。

**短段（short tail）**：追加后立即 flush，允许作为 superpacket 最后一段
（GSO 语义允许末段 < gso_size；探针已验证内核正确处理）。

## 5. 失败与回退

- 特性未启用、协商失败或 SSMT → 裸 TUN 逐包写；已启用 VNET 而合并停止时 → 立即写入带零化 virtio 头的普通 VNET 帧；
- 物理写只有 `written == frame_size` 才是成功。GSO write **负返回**表示未提交，才允许按原顺序同步回退 retained originals；
- `0 <= written < frame_size` 是提交状态未知的 positive short write：**绝不重放 originals**，立即清空 pending state、禁用合并、将适配器置 `TunnelWriteFailed` 并 fail-closed，防止重复交付；普通 VNET 和裸 TUN 的 positive short write 同样失败并关闭适配器；
- 有效且已被延迟接受的 `Output` 包始终由固定存储持有，直至完整 GSO 写、或已尝试有序的 negative-error fallback。定时器触发时没有可回溯的 `Output` 返回值，因此失败必须关闭适配器而不是静默吞掉。

## 6. 遥测

除既有 direct-write 和可选 MERGEABILITY 外，`OPENPPP2_DATAPATH_GSO_LEDGER=1` 启用只读
`tun_gso_ledger`：eligible/merged bytes、普通/GSO full writes、segments、negative fallback、partial-unknown、
flush/rejection reason 与 hold histogram。它的 framing domain 固定标注为
`vnet_gso_coalescer_only_not_global`；与 TUN、VNet、frame、crypto、carrier stage ledger 的 packet framing
不同，**不得跨域相加或声称全局 closure**。

## 7. 聚焦验证与最近 c1/native D0/P1 UL 配对 A/B

1. 已构建 `ppp`；`tun_gso_coalescer_test`、`tun_gso_mergeability_test`、`tun_gso_ledger_test`、`tap_vnet_codec_test` 四个 focused CTest 均通过。它们覆盖 cap=4、100µs `FlushExpired` seam、short tail、严格资格规则、negative fallback 的字节序、positive short 无重放、ordinary partial 失败，以及 VNET checksum-only/GSO decode 边界；
2. `tun_gso_output_probe --self-test --execute` 通过：直接 2/4/8/16 MSS 和 production builder 的 cap=4、short tail、PSH/ACK-only 插入均经私有 netns 的真实 TUN/内核路径验证长度、序号、payload 与 checksum；
3. `TapLinux` 使用真实 `boost::asio::steady_timer` 在首段 pending 后独立 arm 100µs；callback 在 feature mutex 下调用 `FlushExpired()`，故后续没有 `Output()` 也会写出。focused test 当前覆盖 coalescer 的到期 flush seam；仍缺少直接驱动 `TapLinux` timer/lifecycle 的独立特权或集成测试，不能把该代码审计替代为已完成的运行时门禁；
4. 最近一对 30s、`--perf-stat --gso-ledger --loaded-echo-latency` 运行的 baseline/GSO goodput 为 **298.700/822.385 Mbps**（**2.753×，+175.3%**），retrans 均为 0。该窗口的 ledger 均来自实际二进制和同一 runner，但运行在共享宿主，不能作为严格单核结论；
5. 此对账本说明吞吐变化不是仅有最后一次 edge write：TUN reads 从 **33.36k/s** 降至 **4.42k/s**，frame encode/carrier send 从 **7.49k/s** 降至 **1.77k/s**，而 VNet input/output 变为 **73.31k/s**。GSO ledger 有 **16.00k/s** full GSO writes、**63.55k/s** GSO segments（约 3.97 segment/GSO write）、**4.77k/s** ordinary full writes；无 negative fallback 或 partial unknown。故端到端提升包含 VNET/GSO 双向 framing/batching 的影响，不能全部归因于 edge coalescer；
6. 同一 GSO 窗口中 95.3MB/s merged payload 由 96.2MB/s eligible payload 构成；cap flush 15.57k/s，PSH flush 1.04k/s，timeout 0.37/s。hold 绝大多数落在 5–25µs，仅 11 次超过 100µs；这只描述该 bulk workload；
7. loaded latency 是 bulk iperf 期间**独立 TCP control flow**上的 100Hz persistent in-band echo，不是 TCP RTT。baseline/GSO 的 3000/3000 samples 均成功，p50/p95/p99 为 **6434.601/8152.077/9416.451µs** 与 **1701.189/2389.997/3574.343µs**；
8. 15s idle echo（无 bulk）各 1500/1500 成功。baseline/GSO p50/p95/p99 为 **350.352/475.436/758.523µs** 与 **367.863/506.703/1253.270µs**。该小样本的 idle p99 变差，故不能声称 GSO 无 idle tail-latency 回归；还需要单个 strict-eligible packet、随后没有 `Output()` 的真实 timer flush 测试；
9. 先前的三组 30s P1 UL 中位结果（253.725→842.028 Mbps，3.319×）可作为现象重复性证据，但与本节的最近配对不是同一统计总体；
10. 最近以 `cmake --build build/test -j"$(nproc)" && ctest --test-dir build/test --output-on-failure` 跑完整 C++ suite：130 个中 129 个通过；唯一 `spinlock_test` 在 120s 超时。随后从 `build/test` 单独执行 `timeout 300s ./spinlock_test` 仍超时（exit 124、无输出）。因此全量 suite **尚未全绿**；该项不是可忽略的短暂 flake；
11. XTCP 功能门禁：独立 `ENABLE_XTCP=ON` 构建成功；现有 XTCP dependency/runtime adapter/runtime bridge CTest **5/5** 通过；固定上游 revision `e79db8fd10a1ee39be2dc3a9361727fcad79d04c` 的 fault/stress suite **20/20** 通过。使用独立 XTCP `ppp` 二进制的最小 TAP netns E2E 在强制 GSO-off 与显式 GSO-on 下均通过（echo、half-close、peer-close drain、RST、churn×16、1% loss/25% reorder/10ms netem、MTU 1280、3s soak、rollback）。新 `tools/run_datapath_linux_matrix.sh` 已完成 GSO-off、3 round、P1/P4/P16 × UL/DL × native/XTCP 的 **36/36** cell，全部 XTCP stats NDJSON 验证通过，最终窗口无 zero-rate flow。这证明 XTCP 接入、最小故障路径与 GSO-off 性能矩阵已运行；**不**等价于 XTCP+GSO 性能或延迟矩阵已验证。

## 8. 实测收益、边界与风险

- 隔离 B1 曲线 × mergeability 的原预测约 +13.5%；近期端到端配对为 +175.3%，此前三组中位为 +231.9%。这不是矛盾：前者仅估算 strict-v1 edge output，后者包含 Linux TUN VNET/GSO 双向行为；现阶段只完成 stage-rate 解释，尚未量化每个域的因果份额；
- `max_hold_us=100µs` 是上限而非承诺的实际延迟增量。loaded control-flow latency 改善不能覆盖 idle、建连、反向流量、短流、真实远端或尾延迟；当前 idle p99 结果要求继续验证；
- CPU 口径：共享宿主上指定 CPU 集合被其他负载占满，且 NET_RX 可发生于集合外。当前不能证明没有 softirq/ksoftirqd 或其他核心迁移，也不满足严格 system-wide 单核收益声明；
- 内核/NIC/TUN 配置和真实远端路径仍需独立 A/B。`tools/run_datapath_linux_matrix.sh` 已完成 GSO-off、3 round、native + XTCP、P1/P4/P16、UL/DL paired matrix；该共享宿主结果不能作为严格单核或 CI 基线。首次 XTCP+GSO 三轮矩阵在 **34/36** cell 后停于 round-3 XTCP P16 DL：所有 16 条流在约 43s 后变为零速，iperf server 报 `select failed: Bad file descriptor`，外层运行超时前未生成该 cell result 或矩阵 summary。随后为 runner 增加每 cell `timeout` watchdog（默认 `duration + omit + 30` 秒）；单独重跑相同 XTCP P16 DL GSO-on cell 在 42s watchdog 下通过（312.805Mbps、零零速流），故故障目前定性为**未解释的间歇性 stall**，不构成矩阵通过证据。XTCP+GSO 性能/延迟矩阵仍不完整，能力协商失败只保证自动关闭该 feature，不保证跨环境收益；
- `XTCP-GSO-STALL-001` 随后固定为 XTCP/GSO-on/P16/DL、`duration=10`、`omit=2`、42s watchdog 的专场。round-1 通过，round-2 再现：吞吐从 4–5s 的 26.2Mbps 降至 **5–6s 起 16/16 流同时为零**，并持续到 watchdog；42s 时 runner 在 SIGINT 前冻结现场（`build/c1-gso-production-candidate-20260901/xtcp-gso-stall-001-r30/round-2/xtcp-p16-dl/timeout-diagnostics/`）。稳定 XTCP stats 显示 `flows_active=17`、`flows_closed=0`、ingress 无 drop、队列为 0，`timer_polls` 仍约 55k/s 增长，但 `output_packets/output_bytes`、connector read/write 已冻结；因此问题已缩至 XTCP 输出/发送许可、ACK clock 或其前置状态，而**不能**据此归因为 GSO、KCC 或生命周期。target 的 16 条 iperf socket 均 ESTAB，server Send-Q 约 5–9MiB、`rwnd_limited≈99.5%`，且 pre-signal fd 快照未见 data fd 消失；本次没有 `EBADF`，旧 `Bad file descriptor` 降为次要症状。GSO ledger 已确实渲染，但仅记录 40,692 次 ordinary write（其中 40,657 次因 PSH 拒绝），0 次 GSO full write/segment，故该失败样本不能提供 GSO 合并器内的正向或反向因果证据；
- IP ID 语义仍需评审接受“TCP/IP 语义等价”而非 host-facing 逐字节等价；
- v1 保持 **default-off**。在 timer/lifecycle 集成门禁、隔离 CPU system-wide accounting、跨环境与 XTCP 性能回归，以及全量 C++ suite 均通过前，不得改为默认开启。

## 9. 评审决策点与剩余门禁

1. IP ID 语义等价 vs 逐字节等价（**必须二选一**，v1 假设前者）；
2. PSH v1 全拒绝是否接受（psh-last-candidate 留作 v2）；
3. max_segments 固定为 4；提高到 8 必须重新验证 A/B、延迟与 system CPU；
4. 100µs hold 是否接受，且必须先补 singleton pending 的实际 timer flush 与 stop/close race 测试；
5. 特性保持环境变量 opt-in + kill-switch，还是在所有 gate 后增加稳定配置面；
6. default-on 前必须完成：隔离 CPU 的 system-wide softirq/ksoftirqd accounting、真实远端/不同内核、native + XTCP P1/P4/P16 × UL/DL、MTU/PMTU/loss/reorder/short-flow/FIN-stop 故障矩阵，以及全量 C++ 和相关 E2E 回归。
