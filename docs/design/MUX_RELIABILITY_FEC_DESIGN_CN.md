# VMUX 可靠性子协议设计(ACK + 快速重传 + FEC)
> Status: Active
> Type: Design
> Last verified: 13e2785

> **用途:**记录 vmux QUIC 风格可靠性子协议(ACK 反馈、快速重传、PTO、XOR 奇偶 FEC)的协议格式、状态机、限界与回落规则。
> **适用对象:**vmux 维护者、协议评审者、基准验证执行者。
> **当前状态:**已实现,与 `ppp/app/mux/` 代码一致;可靠性默认开启(协商失败自动回落),FEC 默认关闭。
> **最后核对依据:**`ppp/app/mux/vmux_net.{h,cpp}`、`MuxAckTracker.h`、`MuxRetransmitBuffer.h`、`MuxFecCodec.h`、`MuxRuntimeState.h`,2026-07-22。
> **上一层索引:**[Design Documents](README.md)

## 1. 动机

vmux 多链路此前是"吞吐/时延优化,不是 HA":死链上的在途帧直接丢失,恢复手段只有
flow_v2 的 400ms 缺口超时 `fail_flow`(杀单条逻辑流)或 compat 的整会话重建
(`vmux_net.h` `on_link_exit` 注释)。本子协议把恢复粒度从"杀流/杀会话"降到"补一帧":

- **ACK 反馈**(仿 QUIC ACK frame):接收侧报告已收到的帧序号区间;
- **快速重传**:发送侧保留重传缓冲,丢帧以**原序号**在另一条活链路上重发;
- **PTO 兜底**:无 ACK 推进时按探测超时重传;
- **FEC 向前纠错**:每 K 个数据帧一个 XOR 奇偶帧,单组单丢失即时恢复,不等重传。

## 2. 协商

复用 MUX 握手的 `ordering_caps` 字节(旧端不发送该字节,按 0 处理):

| bit | 名称 | 含义 |
| --- | --- | --- |
| 0 | `FLOW_V2` | per-flow DSN 接收排序(既有) |
| 1 | `RELIABILITY` | ACK + 重传子协议 |
| 2 | `FEC` | XOR 奇偶组(蕴含 RELIABILITY) |

- 客户端按本地配置(`mux.reliability.enabled` 默认 true、`mux.fec.enabled` 默认 false)宣告;
  服务端取双方交集并**权威回显**(`VirtualEthernetExchanger::OnMux`);
  客户端按回显应用(`VEthernetExchanger::OnMux` → `apply_agreed_ordering`)。
- 可靠性与调度模式/接收排序**正交**:compat 与 flow_v2 下均可启用,排序回落不影响可靠性协商。
- **未协商成功绝不发送 `cmd_ack`/`cmd_fec`**:旧实现对未知 cmd 直接断会话
  (`vmux_net.cpp` `packet_input` 的 else 分支),协商是唯一的兼容闸门。
- 协商纯函数:`NegotiateMuxRuntimeState` / `ApplyAgreedMuxRuntimeState`(`MuxRuntimeState.h`),
  结果落在 `MuxRuntimeState.reliability` / `.fec`。

## 3. 线格式

帧头仍为 9 字节 `vmux_hdr{seq(4), cmd(1), connection_id(4)}`,新增两个命令字:

- `cmd_ack`:`block_count(1) | per block { connection_id(4), largest(4), range_count(1), {start(4), end(4)}* }`,
  全大端,区间闭区间。`connection_id=0` 表示 compat 全局序号空间。
  单帧上限 8 块 × 24 区间(`PPP_MUX_ACK_MAX_BLOCKS` / `PPP_MUX_ACK_MAX_RANGES`)。
- `cmd_fec`:`count(1) | { connection_id(4), sequence(4) }*count | parity_len(2) | parity`。
  parity = 组内各帧 `[len(2 大端)] [frame bytes]` 按最长块零填充后的逐字节 XOR;
  覆盖帧**显式列举**,与跨链路乱序、两种排序模式均兼容。

`cmd_ack`/`cmd_fec` 是**无序控制帧**:seq=0,两种模式下接收侧都在定序逻辑之前内联处理,
自身不被 ACK、不重传、不进 FEC 组(不存在 ack-of-ack)。

## 4. 序号空间与寻址

- compat:全局 `tx_seq_`,ACK/重传以 `(0, seq)` 寻址;所有非可靠性控制帧都可被 ACK/重传
  (compat 全局定序下任何帧丢失都会阻塞后续投递,必须全覆盖)。
- flow_v2:per-flow DSN,以 `(connection_id, dsn)` 寻址;仅 `cmd_push`/`cmd_fin` 参与。
  控制帧(syn/syn_ok/acceleration/keepalive)seq=0 不入 DSN 空间,丢失由既有机制容忍
  (连接超时重试、周期心跳)。

## 5. 发送侧状态机

`underlyin_sent` 成功入队后 `track_sent_frame` 把帧(shared_ptr,零拷贝)登记进
`MuxRetransmitBuffer`(会话级字节上限 `mux.reliability.rtx.bytes`,默认 8 MiB)。

- **ACK 处理**(`packet_input_ack`):释放被覆盖的表项;首个未被重传过的表项给出 RTT 样本
  (Karn 规则),`srtt = 7/8·srtt + 1/8·sample`。
- **快速重传**:某表项序号比 ACK 的 largest 小 ≥3(`PPP_MUX_FAST_RETX_THRESHOLD`,
  即"其上至少 3 帧被确认"的 dup-ACK 近似)且本轮 largest 未标记过 → 立即重发。
- **PTO**:`update` 之外的独立 10ms 维护定时器(`reliability_tick`,挂在 vmux strand 的
  `steady_timer` 上)扫描 `now - last_sent ≥ PTO` 的表项;
  `PTO = clamp(2·srtt, 200ms, 3000ms)`,无样本时 500ms。
- 重发经既有 `underlyin_sent`(走 drain ticket / 链路字节 credit),保留**原序号**,
  不附带完成回调(原回调已在首发时按既有语义触发)。
- **降级**:单帧重传次数超过 `mux.reliability.rtx.max_attempts`(默认 8)或重传缓冲超限 →
  与既有缺口策略一致:flow_v2 `fail_flow`,compat `close_exec` 重建会话。

## 6. 接收侧状态机

- 每个序号空间一个 `MuxAckTracker`(区间合并,24 区间硬顶,溢出丢最旧区间由 PTO 兜底);
  序号回绕启发式:回跳超过半空间即重置跟踪器。
- ACK 触发:每 2 个可靠帧立即发,或最老未确认帧滞留超过 `mux.reliability.ack.delay`
  (默认 10ms,由维护定时器检查)。ACK 内容是**累积**的(跟踪器不随发送清空),
  ACK 帧自身丢失由下一帧自然覆盖。
- **去重**(重传能工作的前提):compat 路径此前把重复帧当致命错误
  (已交付序号 → `ProtocolFrameInvalid`;重组队列重复 → `MappingEntryConflict`,均杀会话),
  协商可靠性后一律静默丢弃;flow_v2 的 `MuxFlowReorderBuffer` 本就拒绝重复 DSN,无需改动。
- **gap 超时放宽**:可靠性生效时 flow_v2 的 400ms 与 compat 的全局缺口超时改用
  `mux.reliability.gap.timeout`(默认 3000ms),让重传先填洞;超时仍是最终兜底。
- **FEC 恢复**:接收侧按组缓存(`PPP_MUX_FEC_WINDOW_GROUPS=64` 组上限)+
  最近数据帧缓存(`PPP_MUX_FEC_CACHE_BYTES=4 MiB` 字节上限,FIFO 驱逐);
  组内恰好缺 1 帧且其余齐 → XOR 恢复、校验头 (cmd/cid/seq) 后按正常路径注入投递;
  缺 ≥2 帧放弃该组,交给 ACK/重传。

## 7. 配置与限界汇总

| 配置 | 默认 | 含义 |
| --- | --- | --- |
| `mux.reliability.enabled` | true | 可靠性子协议开关(仍需对端协商) |
| `mux.reliability.rtx.bytes` | 8 MiB | 会话级重传缓冲字节上限 |
| `mux.reliability.rtx.max_attempts` | 8 | 单帧重传次数上限 |
| `mux.reliability.ack.delay` | 10 ms | 延迟 ACK 等待 |
| `mux.reliability.gap.timeout` | 3000 ms | 可靠性生效时的缺口兜底超时 |
| `mux.fec.enabled` | false | XOR 奇偶 FEC 开关(带宽开销 1/K) |
| `mux.fec.group` | 8 | 每组数据帧数 K |
| `mux.fec.flush` | 20 ms | 未满组补发滞留 |

硬编码限界(`ppp/stdafx.h`):ACK 8 块×24 区间、快速重传阈值 3、PTO [200,3000]ms、
重传突发 32 帧/轮、维护 tick 10ms、FEC 组 64、FEC 缓存 4 MiB、FEC 单帧上限 60000
(超大帧只做重传,保证奇偶帧不超过单帧载荷上限)。

## 8. 与既有机制的关系

- gap 超时、`fail_flow`、D11 积压看门狗、turbo 动态池全部保留,语义不变;
  可靠性层只是让大多数丢失在触发它们之前被补上。
- 早期 ACK(acceleration 快路径)语义不变;重传缓冲留存的是线上帧的 shared_ptr,
  不引入新的拷贝(组帧/重组/投递的既有 memcpy 不变)。
- 重传帧不再进 FEC 组(首发已覆盖),也不再重复登记重传缓冲。

## 9. 验证

- `tests/cpp/`:`vmux_ack_tracker_test`(区间合并/上限/回绕/编解码/畸形拒绝)、
  `vmux_retransmit_buffer_test`(登记/释放/快速重传候选/PTO 扫描/字节上限)、
  `vmux_fec_codec_test`(成组/单丢失恢复字节级一致/双丢失拒绝/畸形拒绝)、
  `vmux_reliability_negotiation_test`(协商矩阵与回落)。
- `benchmarks/vmux/`:`reliability-loss-{0.5,2,5}` 与 `fec-loss-2` 场景对照
  `carrier-loss` 基线(0.5%/2%/5% 丢包)。
- 遥测:`mux.ack.{send,recv,malformed,unexpected}`、`mux.rtx.{send,fast,pto,exhausted,cap}`、
  `mux.fec.{send,recv,recovered,recover_failed,recover_invalid,malformed,unexpected,group.evict}`。
