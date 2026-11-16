# OpenPPP2 吞吐优化计划

当前 pin：c9dd56013842（2026-10-31），33 个本地补丁。上游 #3-#8 已完整
吸收 0037-0040、0048；0042/0043/0045/0046 仅保留本地集成残余。
下文旧 pin 与测量记录保持历史含义，不作为本次升级的性能验收。

> Status: Draft / plan
> Type: Plan
> Last verified: 2026-10-26（§2.4 历史矩阵 d4fcdb6f；新基线与诊断 add77894）
> Tracking: Miaocchi/openppp2#91

本文把已有的性能证据整理成一份可执行的优化计划。度量口径沿用
[XTCP 集成说明](XTCP_INTEGRATION_CN.md) §11.4 的三榜框架；Linux TUN 边缘
合并沿用 [GSO 合并设计](PPP-DATAPATH-GSO-CONTRACT_CN.md)；损伤验收沿用
[NetEm 验收设计](PPP-DATAPATH-NETEM-ACCEPTANCE_CN.md)。所有性能结论必须标明属于
哪一榜（A 严格单核产品 / B 实际产品 / C 逐层归因）以及哪个冻结 revision。

## 1. 目标

| 编号 | 目标 | 榜 | 现状 |
| --- | --- | --- | --- |
| G1 | Linux native D0 P1 单核吞吐翻倍以上 | A | 基线约 0.3 Gbps；GSO-on UL 实测 822 Mbps（default-off） |
| G2 | XTCP 在 A 榜全矩阵（P1/P4/P16 × UL/DL）稳定达到 native 的 1.2 倍 | A | 2026-10-26 当前 main 三轮复测未达成：六组均未每轮达到 1.2×；UL P4/P16 为 0.945–0.991× / 0.913–0.923×（§2.4.2） |
| G3 | 多核场景按核数扩展，单连接不因跨线程唤醒退化 | B | shard 默认 1；跨线程逐段唤醒 |
| G4 | Windows、Android 有可复现的真机基线，并找到各自的主要瓶颈 | A/B | 只有回环组件基准；没有真机矩阵 |
| G5 | 每项优化都不降低正确性：xtcp 上游测试全过，Route3 qualification 全过 | — | 本地补丁栈让 13–15 个 xtcp 测试失败 |

非目标：本计划不改动加密协议、不改 carrier 线格式、不追求和内核回环比绝对数值
（见 §2.3）。

## 2. 现状与证据

### 2.1 产品数据面（Linux，A 榜）

- 单核约 0.3 Gbps 时的成本归因：TUN 27%、carrier 23.5%、加解密 13.4%，其余是
  系统调用、libc 等（GSO 合并设计 §0）。没有哪一域超过三成，单点优化收益有限。
- TUN 边缘 GSO 合并（default-off）：P1 UL 298.7 → 822.4 Mbps（2.75×），重传为 0。
- XTCP：P1 direct GRO 12KiB 约 975–1039 Mbps；13–15KiB 严重退化；
  DL 16KiB chunk 约 596 Mbps；NDI TSO 中位 527 Mbps，负收益，保持 default-off。
- 已知问题：`XTCP-GSO-STALL-001`（P16/DL GSO-on 全流归零）、P64 DL server wedge、
  direct 路径间歇退化（同配置三轮出现 30 Mbps 低值）。

### 2.2 组件基准（`xtcp_runtime_bridge_test --throughput`，C 榜补充）

单连接、32 KiB 窗口、合成对端：

| 平台 | 路径 | Mbps |
| --- | --- | --- |
| Windows | Winsock 回环参考 | 约 1000 |
| Windows | XTCP TCP 桥 / 直连桥 | 约 1130 / 约 1245 |
| Linux (WSL2) | 内核回环参考 | 7186–9561 |
| Linux (WSL2) | XTCP TCP 桥 / 直连桥（批量唤醒） | 1305–1389 / 1878–1987 |

剖析结论：runtime I/O 线程跑满，剩余成本是逐段（1360 B）的固定开销和每批次的跨线程
唤醒；`getenv` 热路径（占 I/O 线程约 36%）已修复。

### 2.3 口径说明

内核回环在组件基准里约 9 Gbps，是内核内存拷贝的速度，不是 OpenPPP2 能达到的上限，
不作为目标值。产品目标以 A/B 榜的 native 同机配对为准。

### 2.4 M2 矩阵与瓶颈（A 榜定向）

以下先保留 2026-10-25 的历史矩阵；当前 main 的复测与上行诊断见 §2.4.2。

冻结二进制：`d4fcdb6f`（clean，SHA-256 `7767443b…`），远端共享 VM（Xeon E5-2680 v4），
隔离 netns，客户端单核绑定。参数：gather 65536 / wait 1 ms、memory bridge on、
`--tap-gso-segments 32`、kcc、aes-256-cfb、shards 1。3 轮交错（GSO on/off 顺序轮换），
每 cell 45 s；72 cell 全部 pass，无零速流，netns 清理与二进制冻结校验均通过。测量在
同机 M3 编译结束、负载降至 4 以下后才开始。

| GSO | 方向 | P | native Mbps | XTCP Mbps | XTCP/native（3 轮） |
| --- | --- | --- | --- | --- | --- |
| on | UL | 1 | 1119 | 1301 | 1.17 / 1.17 / 1.12 |
| on | UL | 4 | 1123 | 1177 | 1.04 / 1.05 / 1.05 |
| on | UL | 16 | 1107 | 1070 | 0.94 / 0.96 / 0.97 |
| on | DL | 1 | 1842 | **414** | **0.23 / 0.22 / 0.22** |
| on | DL | 4 | 1745 | 1269 | 0.72 / 0.72 / 0.73 |
| on | DL | 16 | 1735 | 1528 | 0.92 / 0.88 / 0.87 |
| off | UL | 1 | 244 | 547 | 2.25 / 2.23 / 2.18 |
| off | UL | 4 | 240 | 514 | 2.14 / 2.21 / 2.09 |
| off | UL | 16 | 222 | 485 | 2.18 / 2.18 / 2.13 |
| off | DL | 1 | 623 | 364 | 0.57 / 0.58 / 0.59 |
| off | DL | 4 | 618 | 771 | 1.26 / 1.23 / 1.24 |
| off | DL | 16 | 608 | 813 | 1.36 / 1.34 / 1.33 |

（native/XTCP 列为 3 轮中位数。）

结论：

- G2（全矩阵每轮 ≥ 1.2×）**未达成**。GSO-on 下 12 个 cell 中没有一个满足；GSO-off 下
  只有 UL 全部与 DL P4/P16 满足，但这是因为 native 在 GSO-off 时本身很低。
- 最大缺口是**单连接下行**：GSO-on 时 XTCP 固定在约 414 Mbps（native 1842），三轮
  几乎无方差，说明是结构性上限而不是间歇抖动；随并发数升高差距缩小（P4 0.72×、
  P16 0.9×），符合"每连接存在固定上限"的特征，与 2.5（直连桥下行 16 KiB、单在途）
  的描述一致。列为新工作项 1.6。
- 此前只测 UL 的定向结果（P1 UL 1.12–1.20×）在本矩阵中得到复现。
- 这仍是共享 VM 上的定向结论；严格 A 榜验收需隔离单核环境。

#### 2.4.1 单连接下行上限的根因：XTCP snd_buf（2026-10-25/26）

- 诊断（GSO-on DL P1，perf + 计数器）：客户端进程只用 0.33 核，不是 CPU 瓶颈；
  直连桥下行块 16→32 KiB 只从 413 提到 424 Mbps，也不是块大小。生产默认不设
  `OPENPPP2_XTCP_SNDBUF_BYTES`，xtcp 每连接 snd_buf 取上游默认 64 KiB，在途数据被
  限制，约 410 Mbps 正好对应 64 KiB / ~1.2 ms。
- snd_buf A/B（旧 xtcp 77d45585，3 轮，XTCP/native）：

| snd_buf | DL P1 | DL P4 | DL P16 | DL P64 | UL P1 / P4 / P16 |
| --- | --- | --- | --- | --- | --- |
| 64 KiB | 0.22 | 0.72 | 0.9 | — | 1.12–1.17 / 1.04 / 0.95 |
| 256 KiB | 0.56–0.65 | 1.09–1.23 | 1.08–1.20 | 1.36–1.46 | 1.14–1.22 / 1.05–1.15 / 0.95–1.03 |
| 1 MiB | 0.92–0.99 | 1.15–1.18 | 1.06–1.15 | 3 轮中 1 轮卡死 | 1.00–1.15 / 0.96–1.05 / 0.96–0.99 |

- xtcp 更新到上游 f71548f（#102）后，KCC v2 的 cwnd 目标缺少 Linux `bbr_set_cwnd`
  的 ack-aggregation 与 quantization 余量，大 snd_buf 下多流 DL 减半；#106（补丁 0038）
  已修复，P4/P16 DL 回到旧版水平。
- 大 snd_buf × 多流的卡死根因：xtcp 全局固定缓冲池（约 36 MiB，修复前无堆兜底）被发送缓冲
  占满后，入向 ACK 因申请不到缓冲被丢弃，snd_buf 无法释放，形成死锁。默认 64 KiB 在
  数百条满载流时同样可能触发。#108 的 0039/0040 已用 TX 余量与有界 heap overflow
  修复（集成说明 §11.188），#109 已把 Linux 默认 snd_buf 调为 1 MiB。
  当前 1 MiB 默认已扩展到所有支持 XTCP 的平台（Linux、Windows、Android）；macOS/iOS
  当前不支持 XTCP 构建。
- 结论：调大 snd_buf 默认值是 G1/G2 下行缺口的主要手段，1.7 的前置修复已经合入。上行
  P4/P16 在各档 snd_buf 下都只有约 1.0×，不受 snd_buf 影响，需要单独工作项。

#### 2.4.2 当前 main 复测与上行多流归因（2026-10-26）

冻结产品源码 `add778946e268ad765a284b682dda02a5cba1b85`；新构建二进制 SHA-256
为 `6c6b7e327b7d64a06ab7e5edd0159cc6a72d52f824645fdb10f916bbf1965363`。
使用固定上游 f71548f、0038/0039/0040、Linux snd_buf 1 MiB；M3 开关全部保持关闭，
shards=1、客户端与 iperf 同绑 CPU 49、GSO on、cap32、KCC、AES-256-CFB、
direct memory bridge、gather=65536、wait=1 ms。构建与测量均持共享锁；测量经过
空闲检查，外层独立 network/mount namespace，内层三端 netns。

远端本次证据根目录记为 `W=/home/ppp-m2/m2b-20261026`。`m2b-source.tgz`、
`binary.sha256`、`frozen-source.json` 与每组的 `provenance.json` 保存冻结证据。
产品源码未改；测量工具先修复同文件系统 bind mount 被 `os.path.ismount()` 误拒绝的问题，
改读 `/proc/self/mountinfo`，继续核对 backing 目录身份。初次启动前拒绝记录保留在
`W/runs/`、`W/runs-isolated/`；实际测量位于 `W/runs-v3/`。
包装器在 Popen 时调整方向和 snd_buf，`provenance.args` 保留 measure 的原始模板；
实际参数以 `matrix/ordered-runs.json` 和 `matrix-metadata.txt` 为准。
早期诊断沿用已有 `ordered-runner.py` 的公共 perf 缓存配置
`/home/ppp-m2/source/build/private/m2/perf-cache`，存在新目录以外的缓存写入可能，
这是本次执行偏差。AES-128 对照及后续报告改用本次专用 `W/ordered-runner.py` 与
`W/perf.config`，公共缓存没有清理。

**新基线：30 秒正式区间、omit=2 秒、三轮交错。** 每轮依次测 UL P1/P4/P16、
DL P1/P4/P16、DL P64；第一、三轮 native 在前，第二轮 XTCP 在前。结果根目录为
`W/runs-v3/baseline/pass-{1,2,3}/`，分组名为 `ul-p1-4-16`、`dl-p1-4-16`、
`dl-p64`，每格保存 `matrix/round-1/{stack}-gso-on-p{P}-{direction}/result.json`。
吞吐列是各栈三轮的中位数（Mbps），比值列是当轮 XTCP/native，不是两个中位数之比。

| 方向 / P | native 中位数 | XTCP 中位数 | 第 1 轮比值 | 第 2 轮比值 | 第 3 轮比值 | 每轮 ≥1.2× |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| UL / 1 | 1124.60 | 1230.94 | 1.095 | 1.072 | 1.090 | 否 |
| UL / 4 | 1083.59 | 1070.41 | 0.991 | 0.991 | 0.945 | 否 |
| UL / 16 | 1099.58 | 1012.98 | 0.921 | 0.923 | 0.913 | 否 |
| DL / 1 | 1811.82 | 1715.20 | 0.954 | 0.953 | 0.917 | 否 |
| DL / 4 | 1744.60 | 2138.17 | 1.134 | 1.226 | 1.246 | 否 |
| DL / 16 | 1739.22 | 1837.05 | 1.067 | 1.050 | 1.051 | 否 |
| DL / 64 | 944.60 | 1249.25 | 1.019 | 1.323 | 1.384 | 否 |

`W/summary.json` 保留逐轮原值，`W/audit.json` 核验 42 格 result/qualification 全部
pass、零速流为 0、9 组冻结/监测/清理通过，并核对实际 argv 与 M3 关闭状态。
另有 20 格定向诊断通过，放宽 watchdog 仍失败的 `p64-long` 现场单独保留。
G2 **未达成**：必选六组均未每轮达到 1.2×；DL P4 仅第二、三轮达标，补充项 DL P64
也仅第二、三轮达标。DL P1 已不再受历史 64 KiB snd_buf 的约 350 Mbps 上限限制，
但比值仍低于 1。DL P64 的 native 三轮为 1522.65 / 944.60 / 891.68 Mbps，存在明显
波动；三轮未重现 pool 耗尽或零速流，不代表长期稳定性验收。共享 VM 即使使用测量锁
和空闲检查也不能完全消除宿主调度影响；本轮提供方向性证据，不替代独占机器的 A 榜验收。

**20 秒定向诊断。** `W/runs-v3/diagnostic/base/matrix/round-1/` 中 native/XTCP
P4/P16 四格均 pass、零速流为 0：

| P | native Mbps | XTCP Mbps | XTCP/native | XTCP PPP 核数 | 同核 iperf 核数 | 所选核心忙碌率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 1090.40 | 1027.19 | 0.942 | 0.848 | 0.108 | 97.9% |
| 16 | 1078.26 | 988.59 | 0.917 | 0.866 | 0.107 | 98.5% |

- 核心容量基本用尽，不能把 PPP 未独占 1.0 核误判成窗口瓶颈：iperf 与 PPP 本来就共用
  一核。`cpu-process-perf.csv`、`cpu-iperf-perf.csv`、`cpu-*-proc-stat.txt`、
  `result.json` 给出上述数值。`client-ss-tin-samples.txt` 保存 TCP_INFO 独立采样。
- `stats.ndjson` 中两格 upload budget reject、direct upload backpressure、ingress drop
  均为 0，预算上限仍为 32 MiB；这组没有触发 #100 的预算限制。direct accepted
  bytes/chunks 的全程平均块长约 9 KiB，逐块分配、校验和与 ACK 等固定成本仍存在。
- `cpu-process-perf.data` 的 49 Hz CPU 样本中，AES-256-CFB 加密占 XTCP P4/P16
  的 33.80%/33.66%，native 为 33.90%/34.20%；它是共同的大头，不能单独解释
  XTCP/native 的缺口。XTCP 的 checksum 类符号约 4%，另有协议栈、分配、引用计数与
  mutex 成本。原始报告为 `W/perf-{native,xtcp}-gso-on-p{4,16}-ul.txt`；样本量仅
  约 800/格，百分比是定向证据，不能据此宣称精确的 C4/C5/C6 保留率。

**单变量 A/B（每方案 20 秒、单轮，单位 Mbps）。** 路径为
`W/runs-v3/diagnostic/{base,gather-off,wait-off,aes128}/matrix/round-1/`；16 格均
result/qualification pass、零速流为 0，冻结与清理通过。

| 方案 | native P4 | XTCP P4 | 比值 | native P16 | XTCP P16 | 比值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 默认 gather / wait / AES-256 | 1090.40 | 1027.19 | 0.942 | 1078.26 | 988.59 | 0.917 |
| gather=1（不聚合） | 1077.99 | 762.53 | 0.707 | 1066.47 | 791.50 | 0.742 |
| gather=65536，wait=0 | 1097.18 | 927.46 | 0.845 | 1075.46 | 956.32 | 0.889 |
| 仅改为 AES-128-CFB | 1218.73 | 1155.53 | 0.948 | 1178.19 | 1051.76 | 0.893 |

- 关闭 gather 后 XTCP P4/P16 吞吐下降 25.8%/19.9%，关闭等待下降 9.7%/3.3%。
  `datapath-client.jsonl` 中全程 carrier bytes/send_calls 显示，默认平均写入约
  42,969/33,072 B，wait=0 降到 23,818/22,927 B，不聚合降到约 9 KiB。
  对照 native 默认约 43,658/43,580 B。多流时逐流聚合变小，放大 carrier、分配与唤醒
  的固定成本；目前 gather 和 1 ms 等待确实有收益，不应关闭。
- AES-128 使 XTCP P4/P16 增加 12.5%/6.4%，native 同时增加 11.8%/9.3%；比值没有
  接近 1.2。加密是共同的 CPU 大头，更换密码套件不是 G2 修复。
- 默认诊断的 PPP CPU 成本：native P4/P16 为 6.50/6.83 ns/B，XTCP 为 6.66/7.19
  ns/B；同核 iperf 占用也更高。P4 的聚合大小已接近 native，仍有差距，不能把全部
  差距归因于 gather。已确定上限在单核 CPU 容量，尚未把剩余差距收敛为一个可修复的
  函数。下一步是按每字节成本拆分协议栈/校验和/分配和 carrier，加密考虑跨流批量；
  C4/C5/C6 完整分层与长期/损伤验收仍待做。

以上为单轮筛选，不是新默认值的稳定性验收；本次不修改产品 C++、密码套件或 M3 默认值。

#### 2.4.3a 2026-10 重测（main 027b398d 之后）

英文配对记录：[October remeasurement](THROUGHPUT_OPTIMIZATION_PLAN.md)。

2026-10-30 在同一共享实验 VM 重测，main 为
`18b02f8cab224d214998ef2286c5c29ff1ecf61d`，晚于 `027b398d`，包含 #116、
#117、#118、#121。Release、`ENABLE_XTCP=ON`、SIMD on，固定 XTCP
`c1fc9d6b6ead239043d7a7608eaea7e0cb143fe6`，由 `tools/prepare_xtcp.sh`
准备并应用当前补丁。产品构建 335/335 成功，二进制 SHA-256：
`e2060fc3016f4db0c7b963110f3eb0a2e29f5c8203a2ffe051cc6ea1c0857d2d`。
所有编译和测量均在测试机新目录 `/home/ppp-m2/m2-remeasure`，本机没有编译或测试。
开始时根分区可用 48GB；编译使用指定共享 flock、CPU 0-15、nice 10、12 jobs。

通过 GitHub API 核对 `c232f892` 的原始变更（本机 Git worktree 的 Windows 路径
无法由当前 Linux Git 解析，Windows Git 互操作也失败，未用其他 gitdir 绕过）。
复用 #107 的单核 CPU49、native/XTCP、UL/DL × P1/P4/P16、45秒正式区间、
omit=2秒、AES-256-CFB、KCC、单 shard、memory bridge、GRO=12288、
gather=65536 / wait=1ms、GSO cap32。snd_buf 显式取当前默认 1MiB，而不是
#107 的 64KiB。外层私有 net/mount namespace，内层三端 netns；steering on
只操作私有虚拟设备的 RPS/XPS，禁止物理 IRQ 写入。客户端 PPP 与 iperf 固定
CPU49。只通过未改动的 `/home/ppp-m2/measure.py` 的 guard/run 调用，保留
共享构建/测量锁、负载≤4及无其他编译/测量进程检查、磁盘检查和冻结清单。

**一小时目标下采用优先范围，不是完整 #107 矩阵。** 本次 GSO-on 两轮，
第一轮 native→XTCP，第二轮 XTCP→native；每轮主矩阵之后补 P64 DL。
未跑 GSO-off，未跑第三轮，因此没有复现原来的 on/off、off/on、on/off 顺序。
不能据此判断 GSO-off 或完整 G2 门禁已通过。

单位 Mbps；native/XTCP 列为本次两轮算术均值，变化为本次 XTCP 均值相对
#107 三轮中位数。统计口径与样本量不同，这是描述性比较，不是显著性检验。

| 方向 / P | native 均值 | XTCP 均值 | 第1 / 第2轮 XTCP/native | #107 XTCP | XTCP 变化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| UL / 1 | 1114.418 | 1227.308 | 1.111 / 1.092 | 1301 | -5.66% |
| UL / 4 | 1110.741 | 1091.139 | 0.988 / 0.977 | 1177 | -7.29% |
| UL / 16 | 1084.898 | 997.018 | 0.922 / 0.916 | 1070 | -6.82% |
| DL / 1 | 1836.234 | 1817.772 | 0.975 / 1.006 | 414 | +339.08% |
| DL / 4 | 1726.207 | 2120.729 | 1.214 / 1.244 | 1269 | +67.12% |
| DL / 16 | 1680.812 | 1742.771 | 1.061 / 1.014 | 1528 | +14.06% |
| DL / 64（补充） | 1332.289 | 1311.644 | 0.944 / 1.038 | — | — |

P64 DL 逐轮 native=1519.588/1144.990、XTCP=1434.484/1188.804 Mbps；
两轮两栈零速流均为 0，XTCP 最慢流为 8.250/6.002 Mbps。未复现零速流或
watchdog，但吞吐有明显轮间波动，不能据两轮排除长期饥饿。#107 主表没有
P64，因此不提供伪造的 P64 同口径历史百分比。

总计 **28/28 result/strict qualification pass、零速流 0**。四组退出状态均为 0，
runtime_faults 均为空，namespace cleanup 与监控完整性全部通过，前后二进制
SHA-256 一致。最终根分区可用 47GB。证据统计不包含前面的失败/中断尝试。

主矩阵 24/24 result/strict qualification pass。下行单流差距由约 0.22× 缩小到
0.975/1.006×，但不是稳定 ≥1.2×；只有 DL P4 两轮均超过 1.2×。
**观察到 >3% 的退化信号：UL P1/P4/P16 分别 -5.66%/-7.29%/-6.82%。**
不能宣称无退化；共享 VM、非同期基线及 snd_buf 变化也不允许将这些差异归因于
某个单独补丁。相较 §2.4.2 的较新历史 XTCP 中位数，上述 UL 均值变化约
-0.30%/+1.94%/-1.58%；这不撤销相对 #107 的退化记录。

完整证据保存在测试机 `W=/home/ppp-m2/m2-remeasure`：
`main.tar.gz`、`frozen-source.json`、构建日志、`campaign-priority.py`、
`ordered-runner.py`、`summary.json` 以及 `runs-priority/` 下的逐格 result、
qualification、实际 argv、provenance、completed 和 contention 记录。
初次 steering-off 的资格失败及为切换优先范围而中断的尝试分别保留在
`runs/`、`runs-qualified/`，不混入结果表。没有更改产品源码、宿主网络设置，
也没有验证 Windows、移动端或真实节点网络。

#### UL 同期 A/B（2026-10-30）

**结论：按预设判据判噪声，未确认约 -6% 的真实提交退化；停止二分。**
A=`c232f892`，B=`18b02f8c`，同期两组 ABBA，共4A+4B，每次仅测
XTCP UL P1/P16。总体 B/A：P1 **-0.43%**，P16 **+0.28%**；两组均未
出现 B 低于 A 超过3%，因此不满足“低 >3% 且超过组内波动”的联合判据。
不能据此归因 #116/#117/#118/#121，也不需要进入 ECN/snd_buf 开关细分。

全部构建和测试仅在测试机新目录 `W=/home/ppp-m2/ul-regress` 完成，
本机未编译或测试。根分区开始/结束均可用47GB。两版分别用原版本
`tools/prepare_xtcp.sh` 准备依赖及补丁，Release、XTCP/SIMD on、GCC14.2、
同一依赖目录；构建命令前缀均为
`flock /tmp/ppp-m2-build.lock taskset -c 0-15 nice -n 10`，12 jobs，
两版均335/335成功。二进制 SHA-256：

- A：`06408863be37e5255f2ec02e89876cc83b036fc91bbd9adab8fde7044714fd6a`
- B：`6416a143a7cefec222bdb7a71f1f77b7198d52e603656d748104ee6802e4ab00`

只调用未改动的 `/home/ppp-m2/measure.py` guard/run；沿用 #124 的 CPU49
客户端单核、45秒正式区间、omit2秒、KCC、AES-256-CFB、单shard、memory
bridge、GRO12288、gather65536/wait1ms、GSO cap32、私有设备 steering on。
**A/B 均显式固定 snd_buf=1MiB**，避免默认值差异混入代码对照；不是重放
#107 的64KiB配置。每次运行前由 guard 等待负载≤4且无外来构建/测量进程。
保持外层私有 net/mount namespace、内层三端 netns，不修改宿主网络设置。

单位 Mbps，按实际执行顺序；每格一轮45秒，不以历史数据补样：

| 组 | 顺序 | 版本 | UL P1 | UL P16 |
| --- | ---: | --- | ---: | ---: |
| 1 | 1 | A | 1243.698 | 1000.313 |
| 1 | 2 | B | 1209.219 | 1010.726 |
| 1 | 3 | B | 1227.335 | 1002.656 |
| 1 | 4 | A | 1245.252 | 1014.579 |
| 2 | 1 | A | 1189.057 | 999.603 |
| 2 | 2 | B | 1224.145 | 1002.611 |
| 2 | 3 | B | 1226.816 | 1015.952 |
| 2 | 4 | A | 1230.488 | 1006.114 |

| 范围 / P | A均值 | B均值 | B/A变化 | A / B波动 |
| --- | ---: | ---: | ---: | ---: |
| 组1 / 1 | 1244.475 | 1218.277 | -2.11% | 0.12% / 1.49% |
| 组1 / 16 | 1007.446 | 1006.691 | -0.07% | 1.42% / 0.80% |
| 组2 / 1 | 1209.772 | 1225.481 | +1.30% | 3.42% / 0.22% |
| 组2 / 16 | 1002.858 | 1009.281 | +0.64% | 0.65% / 1.32% |
| 总体 / 1 | 1227.124 | 1221.879 | -0.43% | 4.58% / 1.48% |
| 总体 / 16 | 1005.152 | 1007.986 | +0.28% | 1.49% / 1.32% |

波动定义为各范围内同版本 `(最大值-最小值)/算术均值`。P1 的组间方向反转，
A自身总体极差4.58%，说明非同期基线不适合归因。组1 P1差异虽超过该组
同版本极差，但仅2.11%，仍未达到3%阈值；本记录不是统计等效性证明。

16/16 result及严格qualification pass，零速流0；8次运行退出0，
runtime_faults为空，cleanup_ok/monitoring_complete均true，前后二进制哈希一致。
竞争监控未检测到外来构建/测量进程，但这不排除共享VM的其他竞争。
初次A运行因旧版 `os.path.ismount` 不识别同文件系统bind mount而退出1，
无有效样本，证据保留在 `runs/group-1/slot-1-A`。外部 `isolated.sh` 仅在
私有mount namespace中将隔离目录挂tmpfs，使两版原有检查都通过；产品源码
未改动，失败尝试不混入表格。

证据：`W/{A,B}/src`、`build`、`bin/ppp`、`frozen.json`，
`prepare-{A,B}.log`、`build-{A,B}.log`、`campaign-qualified.py/.log`、
`isolated.sh`、`ordered-runner.py`、`summary.py/.json`、`runs/qualified/`。
后者包含实际argv、逐格result/qualification、provenance、completed及contention。
Git工作树元数据不可解析；归档只读使用获准的备用gitdir，未向其提交。

建议：当前不回滚或修改任何嫌疑补丁；后续性能变更继续保留同期ABBA门禁。
若需排除小幅退化，使用独占CPU/主机扩大样本，并另做64KiB/1MiB配置对照。
本结论不覆盖P4、GSO-off、其他配置/平台，也不证明历史差异完全由哪一种噪声造成。

#### 2.4.3 P64 UL watchdog：iperf 周期统计阻塞结束计时（2026-10-26）

旧现场根目录 `/home/ppp-m2/runs/poolfix/new-p64-64k-ul-a/` 的
`matrix/round-1/xtcp-gso-on-p64-ul/timeout-diagnostics/` 中 iperf 主线程为 D，
连接仍为 ESTAB，接收端超时前仍有流量；19 个正式区间跨约 48.66 秒，不能因为清理后
`flows_closed=65` 就归因为 FIN 收尾。

新 native 对照 `W/runs-v3/diagnostic/p64-long/` 把 watchdog 从 52 秒放宽到 150 秒，
仍在约 59 秒后以控制消息 Broken pipe 失败。独立采样的
`iperf-kernel-stacks.ndjson` 多次捕获主线程
`getsockopt(TCP_INFO) → tcp_get_info → __lock_sock`。iperf 3.18 的
`iperf_stats_callback` 遍历所有流同步查询 TCP_INFO；client 主循环先运行这些 timer
callback 再检查结束条件。同核 64 个发送线程下，统计的 socket 锁等待拖延结束计时。
源码证据为 ESnet iperf 3.18 的
[iperf_api.c](https://github.com/esnet/iperf/blob/3.18/src/iperf_api.c)、
[iperf_client_api.c](https://github.com/esnet/iperf/blob/3.18/src/iperf_client_api.c)，以及 Linux
v6.12 [tcp.c](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp.c)，本次下载副本保存在 W 中。

单变量对照 `W/runs-v3/diagnostic/p64-i0/` 仅给 client 加 `--interval 0`：20 秒正式
区间、原 52 秒 watchdog，native 970.24 Mbps、XTCP 878.07 Mbps，两格均 pass、
64 条流全部非零，清理与冻结校验通过。该失败的直接机制是 harness 使用 iperf 周期
统计的方式；没有证据把这一次超时归为产品 FIN/close 缺陷，也不能据此消除所有历史
P64 产品问题。

runner 因而只对 `client-single-core × UL × P>=64` 使用 `--interval 0`，在 dry-run、
metadata 与 result JSON 记录 `iperf_report_interval`。其他格继续每秒统计，最终逐流
统计仍保留；该组合不再有 iperf 每秒区间，诊断时沿用 stats/ss 独立采样。

正式修改复测位于 `W/runs-v3/diagnostic/p64-fixed/`：同一产品二进制，20 秒、52 秒
watchdog，native 982.57 Mbps、XTCP 889.89 Mbps，两格 result/qualification 均 pass，
64 条流全部非零，实际正式区间 20.10/19.85 秒，metadata/result 的 interval 均为 0；
冻结与 netns 清理通过。工具源码及指纹为 `W/src-fixed/`、`W/frozen-source-fixed.json`、
`W/harness-fixed.diff`。本地 planner/CPU 合同、冻结清单测试、bind mount 回归通过，
远端 bind mount 隔离冒烟与拒绝未隔离运行的回归通过；没有修改产品 C++ 默认行为。

#### 2.4.4 M3 B 段测量（2026-10-26）

环境：远端共享宿主（56 vCPU，2 NUMA），`origin/main` add77894 + 本分支 runner 改动，
binary sha256 `a8568046…`；所有命令都经 `tools/run_m3_isolated.sh`；GSO on cap32、memory
bridge on、AES-256-CFB、KCC、snd_buf 用产品默认（Linux 1 MiB）、GRO 12288、gather
65536/1 ms。多核用 `client-cpuset` 5 个 CPU（36,39,40,46,50），IO_CPUS 取后 4 个
（2 shard 取 39,40）；单核用 CPU 36。配对 native，30 s，2 轮 ABBA 交错。数据在远端
`/home/ppp-m2/m3b-20261026/`（`gates/`、`runs/m3b/`、`summarize.py`）。

**正确性门禁**：`xtcp_tap_netns_e2e.sh`（echo、半关闭、RST、churn×512、netem、60 s soak、
回滚）在 baseline、s4+SPSC+DIRECT_SPSC、s4+SPSC+workers、s4+SPSC+queues+DIRECT_SPSC 四组
全部通过，stats-json 确认 shard/worker/亲和/direct_spsc 生效值。stall 压力（queues+direct
P16 DL 10×10 s、P64 DL 5×、UL P16 5×；workers P16 DL 5×）共 25 格全部 PASS，无 watchdog、
无零速流、netns 清理干净；qualification 仅因该门禁未开 `--process-perf-stat` 缺进程核数而记
fail，与功能无关。

**A/B（XTCP Mbps，两轮均值；括号内为相对 baseline）**：

| 配置 | DL P1 | DL P4 | DL P16 | DL P64 | UL P1 | UL P4 | UL P16 | 进程核数 DL P16 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline（全关，1 shard） | 1801 | 1583 | 1740 | 1818* | 1453 | 1389 | 918 | 0.99 |
| s2+SPSC | 1516 (0.84) | 2176 (1.37) | 2187 (1.26) | 2143 (1.18) | 1475 (1.02) | 1521 (1.09) | 1458 (1.59) | 1.90 |
| s4+SPSC | 1356 (0.75) | 2195 (1.39) | 2193 (1.26) | 2132 (1.17) | 1444 (0.99) | 1509 (1.09) | 1376 (1.50) | 2.36 |
| s4+SPSC+workers | 1349 (0.75) | 2215 (1.40) | 2201 (1.26) | 2135 (1.17) | 1460 (1.00) | 1509 (1.09) | 1241 (1.35) | 2.36 |
| s4+SPSC+queues | 1671 (0.93) | 2190 (1.38) | 2185 (1.26) | 2140 (1.18) | 1127 (0.78) | 1346 (0.97) | 1057 (1.15) | 1.67 |
| s4+SPSC+queues+DIRECT_SPSC | 1659 (0.92) | 2167 (1.37) | 2196 (1.26) | 2119 (1.17) | 1258 (0.87) | 1441 (1.04) | 1068 (1.16) | 1.68 |
| s2+SPSC+queues+DIRECT_SPSC | 1664 (0.92) | 2155 (1.36) | 2177 (1.25) | 2144 (1.18) | 1250 (0.86) | 1480 (1.07) | 1137 (1.24) | 1.58 |

\* baseline DL P64 两轮分别有 7、8 条零速流（p10 0 Mbps），qualification fail；所有多 shard
配置 P64 无零速流（p10 约 33 Mbps）。native 同期为 DL 1690/1694/1534/1351、UL 1310/1294/1126。

单核（client-single-core，P1）：baseline DL 1788 / UL 1234；s4+SPSC DL 1081（0.60）/ UL 1089
（0.88）；s4+SPSC+DIRECT_SPSC DL 1072（0.60）/ UL 1108（0.90）。

**结论**：
- 多流 DL 在 2 shard 时提升 1.18–1.40×，4 shard 与 2 shard 持平（约 2.2 Gbps 平台，进程只用
  1.6–2.4 核，瓶颈不在客户端核数），B 榜"随核数扩展"只到 2 核，未达到 4 核 2× 目标。
  多 shard 消除了 baseline P64 DL 的零速流饿死。
- 单连接 DL 无改善且回退：非 queues 模式 P1 DL −16%~−25%，queues 模式 −7%~−8%，单核下
  −40%。M3"单连接 DL 提升可复现"未达成。
- workers 亲和与无亲和差别在噪声内；queues 模式降低 CPU（DL P16 6.3 vs 8.8 ns/B）且减轻
  P1 DL 回退，但 UL 回退 13%–22%。DIRECT_SPSC 无可测收益，仅在 queues 下略缓解 UL。
- 建议：Linux 默认不变（shards 不设=1、其余开关关闭）。多流服务场景若接受 P1 DL 回退，
  可显式开 `OPENPPP2_XTCP_SHARDS=2` + `SPSC_INGRESS=1`；queues/workers/DIRECT_SPSC 保持
  opt-in。M3 记为 WS3 完成、验收未达成；baseline P64 零速流需单独排查。

#### 2.4.5 单连接 DL 热点诊断（2026-11-01）

**结论：客户端单线程已饱和；不是“服务端 AES 样本最多，所以先优化服务端 AES”。**
本次只做分析，没有修改产品代码。冻结本 worktree HEAD
`2b4d720e16f9534e76c444c9c6e04fef868c0156`（与同时进行的 M3 eval 相同）；
本地 `main` 引用实际停在 `cb29bed9`，未将其冒充当前 main，也未联网更新引用。
远端归档副本另建 Git snapshot 仅满足 runner provenance，不能把 snapshot commit 当上游 revision。

**方法与运行边界**：实验主机新目录独立 Release 构建，335/335 完成；
`flock /tmp/ppp-m2-build.lock taskset -c 0-15 nice -n 10`，最多 `-j16`。
二进制 SHA-256：`bccef28776c6792d6d6b4ee4a13540fdec7ff4b896466248344e9adb236d256c`。
没有本机编译或测试。测量同时取得共享 measure/build 锁，运行前 `pgrep -af`
检查 measure.py、run_m3_isolated、PPP benchmark 和 iperf；确认 idle 后才启动。
只通过 `tools/run_m3_isolated.sh` 包裹现有 matrix runner，kernel steering off，
不修改宿主 IRQ、路由、DNS。根分区构建前后均可用 42 GB。

沿用 §2.4.4：XTCP、DL P1、30 s + omit 2 s、KCC、AES-256-CFB、memory bridge on、
GSO on cap32、gather 65536/1 ms；显式 shards=1、SPSC ingress/direct SPSC=0，
client-cpuset=36,39,40,46,50，其余产品默认。单格 result/qualification 均 PASS，
**1708.73 Mbps**，零零速流。没有同期 native 配对、没有无 profiler 对照，不能判定
相对历史 1801 Mbps 的回归，更不能据此重新验收 1.2×。

客户端/服务端同时 `perf record -e cpu-clock -F 99 --call-graph dwarf,8192 -p PID`，
并 `perf stat -x, -e task-clock,context-switches,cpu-migrations,cycles,instructions -p PID`。
采样窗口约 24 s，覆盖正式流量主体而非完整 30 s；以 SIGINT 结束 perf，返回 -2，
数据正常落盘。正式 30.087 s 的 runner 客户端 task-clock=30.001 s（按正式墙钟为
0.997 核；perf 自身报告 0.988 核，计时边界不同）。
采样窗口客户端 task-clock=23.910 s（0.999 核），服务端=17.257 s（0.721 核）。
`/proc/PID/task/TID/stat` 同窗口差值：最热 client TID 577998 **99.74% 单核**，
server TID 577988 **71.95%**；tick 线程分别 0.25%/0.17%，其余观测线程为 0。
因此即使允许 5 CPU，P1 实际仍卡在一个客户端执行线程；不能靠增加 shard 假定单流可分摊。

**互斥叶子样本排名**（各端自身 CPU 时间份额，不是端到端耗时比例；父子调用不重复计数）：

| 类别 | client（2227 样本） | server（1632 样本） |
| --- | ---: | ---: |
| syscalls/TUN I/O 与内核网络（不含下面复制、锁） | 33.27% | 19.12% |
| locking（含内核自旋锁） | 12.84% | 2.39% |
| XTCP 段处理（不含复制/校验融合） | 11.99% | 0.00% |
| crypto | 9.16% | 67.40% |
| copies（含 CopyAndChecksumAvx2 的融合成本） | 7.95% | 5.82% |
| 其他：分配、调度、协议、未解析 | 24.79% | 5.27% |

client 最大明确叶子：AES decrypt 9.03%、`_raw_spin_unlock_irqrestore` 5.93%、
`do_syscall_64` 5.84%、`rep_movs_alternative` 5.30%、`_raw_spin_unlock_irq` 4.49%、
`clear_page_orig` 2.92%、`TcpConn::FlushPendingSend` 2.11%、
`CopyAndChecksumAvx2` 1.80%、`pthread_mutex_lock` 1.35%。libc 未解析叶子占 10.51%，
保留在“其他”，没有假定都是 memcpy；复制排名因而是可识别部分而非完整复制成本。
锁类主要是内核网络唤醒路径；解锁指令采样不证明阻塞或争用，不能宣称应用 mutex 是主瓶颈。

**前三类可行动成本的源码归因与建议**（仅提案；收益均为条件估算，非测量结果）：

| 优先级 / 成本与调用链 | 具体变化提案 | 条件性吞吐收益 / 风险 / 规模 |
| --- | --- | --- |
| 1：客户端内核 I/O 与锁合计 46.11%（锁部分不全是内核）。`FlushPendingSend → XtcpNdiBackend::Tx → TunGsoCoalescer::PushInternal/Flush → TapLinux::WriteGsoIov → writev → tun_get_user → TCP → sock_def_readable`；见 `ppp/app/client/xtcp/XtcpNdiBackend.cpp`、`linux/ppp/tap/TapGsoCoalescer.h`、`linux/ppp/tap/TapLinux.cpp` | 先量化每次 writev 的字节/段数及 FlushReason；在 ACK 驱动短批次上减少过早 flush，保留已有 retained-writev；仅在受控批次结束统一 flush，并保留定时器/PSH/关闭边界。不是重新实现已有 GSO 或 retained-writev | 若此组 CPU 减少 20%–35%，Amdahl 约 **1.10–1.19×**；风险高：ACK 延迟、尾延迟、短流/关闭语义、UL 回退；M，约 150–300 行、3–5 天含门禁 |
| 2：客户端 XTCP 段处理 11.99%，另有融合 copy/checksum 1.80%。`OnSegment/OnAckReceived → FlushPendingSend → EmitOrRetry`；`third-party/xtcp/src/core/tcp_fsm.cpp`、`src/core/stack.cpp`，PPP 接入在 `ppp/app/client/xtcp/XtcpRuntime.cpp` | 先观察 ACK 到发送的批次大小；减少每 MSS 的 BufRef/回调/计时开销，沿用现有大段/GSO 能力，在 FlushPendingSend 中按可用窗口聚合发出；重传和 partial ACK 保留 MSS 语义，不能只加 snd_buf 或 shard | 若这 13.79% 减少 25%–40%，约 **1.04–1.06×**；风险高：拥塞控制、重传、包所有权、池耗尽；M，约 200–400 行及 XTCP 补丁、4–7 天 |
| 3：客户端 crypto 9.16%；服务端 67.40%。`Transmission_Packet_Read/Encrypt → EVP::DecryptInPlace/EncryptTo → aesni::AES::ProcessTo → aes256_cfb_decrypt/encrypt`；`ppp/transmissions/ITransmission.cpp`、`ppp/cryptography/EVP.cpp`、`common/aesni/impl/simd_aes_256_cfb.cpp` | 客户端已有 4-block 并行 CFB 解密，可比较 8-block 交错及更大帧的尾部摊销；不要重复推荐已实现的原地解密、EncryptTo、密钥调度缓存。CFB 加密块间串行，服务端若研究跨独立帧流水线，必须保持帧序与各帧重置语义；不把更换密码套件当兼容性无损优化 | 客户端 crypto 减少 20%–40% 仅 **1.02–1.04×**；全部消除也仅约 1.10×。风险中：原地重叠、尾块、CPU feature dispatch；S，约 80–150 行、1–2 天。仅优化服务端不能保证当前 P1 增益 |

1.2× 需要饱和客户端每字节 CPU 至少减少 16.7%；不能把上表重叠路径收益直接相加。
优先做 #1 的批次/flush 计数，再同输入开关 A/B；#2 配合才能更可能跨过目标。
若客户端提高 20%，按线性外推服务端线程约 86% 单核，仍有余量，但这不是容量保证。
下一步两项：① 无采样 native/XTCP 交错复测 P1，确定 profiler 开销；② 增加
writev/flush 诊断再做单因素批次实验，同时跑半关闭、重传、短流及 UL 回归门禁。

**证据与限制**：本地私有目录 `build/private/dl-single-flow/` 保存二进制、构建日志、
`profile.py`/`analyze.py`、perf.data、调用图文本、分类 JSON、线程快照、matrix 结果及失败日志；
不提交原始数据或配置。首次归档缺 Git 元数据，runner 在 PPP 启动前报 Git exit 129，
不计入有效运行。解析时禁用 inline addr2line 后成功；旧 perf 不支持
`perf script --no-call-graph`，改用 `-G`，空分类中间结果不作为证据。
client perf report 报 41 lost samples，分类是保留样本估计；硬件 cycles/instructions 不支持，
没有 IPC、cache miss 或 off-CPU 锁等待结论。共享虚机、单轮、部分 libc 符号缺失，
CPU 边界另提示 other-CPU NET_RX/NET_TX，内核成本不是整个系统网络 CPU 总量。
未验证实网、Windows/mobile、1.2× 收益或任何产品优化效果。远端本次专用构建目录在证据取回后清理。

#### 2.4.6 M3 Linux 默认值复评（2026-11-01）

**决定：保持默认关闭。** 当前 main `2b4d720e16f9534e76c444c9c6e04fef868c0156`，
XTCP `c9dd5601384201b396b1b6599c6c868097da5dcf` 加当前补丁栈。未修改产品代码或默认值。
远端独立目录 `/home/ppp-m2/m3-default-20261101`，Release 构建 335/335 成功；二进制 SHA-256
`c3295492703eda17a086cb3c11ff9d58177ee08be41bb60f6f0c605c0f556f23`。
无本地编译、测试或 PPP 启动。构建经共享 flock、CPU 0–15、nice 10、最多 -j16，
根分区空闲始终至少 42 GB。等待另一 UL 控制器退出后才测量；排队使总耗时超过原定约一小时。

方法沿用 §2.4.4：client-cpuset `36,39,40,46,50`，queues IO CPUs `39,40`；
GSO on/cap32、memory bridge on、AES-256-CFB、KCC、默认 snd_buf、GRO 12288、
gather 65536/1 ms；30 s、omit 2 s，DL/UL × P1/P16/P64。
两轮配置顺序为 baseline→s2→queues、queues→s2→baseline；每格 native/XTCP，第二轮反序，
即与历史相同的两轮配对 ABBA，而非每配置额外跑四次。
每个单元启动前 pgrep 排除其他 measure.py、run_m3_isolated、iperf 和 PPP，
再经 measure.py 的共享测量/构建锁及负载门禁；实际命令全部在本仓库 run_m3_isolated.sh 内。
kernel-steering off，没有修改宿主网络设置。

XTCP 两轮算术均值 Mbps（括号为相对 baseline）；native 列依次为 DL P1/P16/P64、UL P1/P16/P64：

| 配置 | DL P1 | DL P16 | DL P64 | UL P1 | UL P16 | UL P64 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 1735.8 | 1754.9 | 1814.7 | 1445.8 | 940.2 | 568.6 |
| s2+SPSC | 1532.3 (-11.7%) | 2195.2 (+25.1%) | 2169.9 (+19.6%) | 1485.8 (+2.8%) | 1399.1 (+48.8%) | 911.4 (+60.3%) |
| s2+SPSC+queues+DIRECT_SPSC | 1631.8 (-6.0%) | 2187.9 (+24.7%) | 2132.9 (+17.5%) | 1278.9 (-11.5%) | 1193.7 (+27.0%) | 1525.7 (+168.3%) |

- baseline 配对 native：1680.7 / 1535.4 / 1295.3；1320.7 / 1118.0 / 899.3。
- s2 配对 native：1696.9 / 1540.2 / 1314.6；1310.0 / 1121.0 / 937.9。
- queues 配对 native：1687.1 / 1540.4 / 1279.9；1299.7 / 1138.9 / 959.4。

P1 DL 原始两轮：baseline 1756.051/1715.471，s2 1533.441/1531.237，
queues 1618.303/1645.357 Mbps。两轮方向一致，候选均未通过“无 P1 回退”门禁；
native P1 DL 基本稳定，不能用宿主漂移解释全部差距。queues 仍伴随 P1 UL 回退。

**P64 DL 零速流未复现**：baseline 两轮均为 0，吞吐 1820.490/1808.852 Mbps，
最慢流 0.175/1.223 Mbps；s2 最慢流 34.009/33.520，queues 33.205/33.205 Mbps。
多 shard 公平性明显更好，但两次 30 s 不能证明旧故障已永久修复，也不能将变化归因于
c9dd560 某个补丁。全部 36 个配对单元（72 个 stack 结果）exit 0、status pass、无零速流，
cleanup_ok=true、无 runtime_faults，binary hash 不变。stats 确认 queues 模式 shard_count=2、
queue_mode_active=true、direct_spsc_enabled=1。本次未重跑历史正确性/soak/单核门禁，
没有新增条件策略，因此也没有策略 A/B。

**代码归因与窄方案**：`XtcpRuntime.cpp` 的 Start 路径在 shards>1 时创建专属
io_context/worker；默认单 shard 复用外部 IO context。
`OnSecondLegPayload` 对每个 DL 接收数据块做 mutex/预算预留，再 post 到拥有该流的
shard strand。P1 没有可分摊的并行流，却增加线程交接、唤醒与缓存一致性成本；这是
源码支持、与结果一致的主要机制解释，不是本次 perf 因果分解。不是每个 TCP segment 都
唤醒：ingress `PublishIngress`/`DrainSpscIngress` 会批量并合并唤醒（64 包/256 KiB 上限）。
DIRECT_SPSC 控制 `XtcpDirectUploadQueue`，不能直接消除上述 DL post。
queues 将 GSO lane 绑定 shard executor，缩短输出交接，但未消除 P1 回退。

“active flows>1 才开 shard”不宜热切换：四元组决定 stack 所有者，flow_generation 高位编码
shard，还关联 ACK/重传 timer、budget、关闭回调与 TAP lane；第二流到来或退出时迁移会引入
乱序、双消费者和生命周期风险。可研究会话启动时显式选择单流/多流模式，或新流固定分配到
IO-thread shard、既有流不迁移；前者需要外部工作负载提示，后者需混合 executor 拓扑、
同步/预算与回归测试，且首流可能长期成为热点。均非明确安全的约 50 行修复，本次不实现。

证据：远端 `runs-retry/`、`retry.log`、`wrapper.py`、`summarize.py`、`summary.json`、
`build.log`；本地私有归档 `build/private/m3-default-20261101/`。首批 `runs/` 是归档源码
缺 Git HEAD 导致 metadata 检查 exit 1 的失败尝试，无吞吐；补齐真实 bundle 后另开
`runs-retry/`，未覆盖失败记录。结束后清理本任务远端源码/编译目录，保留证据。

#### 2.4.7 Linux TUN GSO writev/flush 诊断（2026-11-01）

本次仅添加诊断计数，不修改合并、PSH、定时器、失败回退或发送顺序。
`WriteGsoIov` 对每次实际 writev 尝试（含重试、失败）累计请求字节、逻辑段数及
各自最大值；字节包含 VNET 头，段数由 VNET `gso_size/hdr_len` 推导，不能简单用
iovec 数量代替。`TunGsoCoalescer::Flush` 按原因累计非空 flush，包含 singleton，
不等同于 writev 次数。所有计数使用 relaxed 原子，进程生命周期累计、跨 TUN/lane
汇总，快照不是事务一致的。通过现有 stats-json 的 `tap_linux.writev_calls`、
`writev_bytes`、`writev_segments`、`writev_max_bytes`、`writev_max_segments`、
`gso_flushes.{explicit,cap,timeout,incompatible,short_tail,psh,control,ssmt,terminate}` 暴露。

**方法与验证**：候选基于 HEAD `b76d3ba7971820643ff8e7bdb606778585a187f3`；
独立实验目录 `/home/ppp-m2/tunctr-20261101`。所有构建/测试在实验机以
`flock /tmp/ppp-m2-build.lock taskset -c 0-15 nice -n 10` 执行，最多 j16。
Release 构建成功，`CPP_TEST_JOBS=16 bash scripts/run-cpp-tests.sh` **195/195 通过**。
新增 sum/max、非空 flush 和 JSON 64 位字段测试。没有本机编译或测试，没有提交/推送。
测量沿用 §2.4.5：XTCP、DL P1、30 s + omit 2 s、KCC、AES-256-CFB、memory bridge on、
GSO on cap32、gather 65536/1 ms、shards=1、SPSC ingress/direct SPSC=0、
client-cpuset `36,39,40,46,50`。每格取得共享 build/measure 锁，并在锁内用 pgrep
检查其他 measure.py、run_m3_isolated、PPP/iperf；空闲后只经 `tools/run_m3_isolated.sh`
运行，kernel steering off。等待了其他任务的构建/测量，没有干预其进程或宿主网络。
根分区观测最低 26 GB；提前归档并清理本任务中间构建产物后恢复余量。

**单次诊断**：`runs-qualified/00-modified`，1721.656 Mbps，result/qualification
均 PASS。39 条客户端 stats，首条计数为零；下表取末条，包含启动、omit 和收尾流量，
不是正式 30 s 窗口的精确差分。选择 sum+max，未采集直方图或分位数。

| 指标 | 观测值 |
|---|---:|
| writev 次数 | 235,906 |
| 请求字节总和 / 每次均值 / 最大值 | 6,688,806,419 / 28,353.69 / 46,386 |
| 逻辑段总和 / 每次均值 / 最大值 | 4,611,225 / 19.5469 / 32 |
| 非空 flush 总数 | 236,109 |
| PSH | 235,823（99.8789%） |
| cap / timeout / incompatible / short_tail | 212 / 16 / 2 / 56 |
| explicit / control / ssmt / terminate | 全部 0 |

**同源码开销对照**：本地 literal main 为 `cb29bed9`，其 XTCP pin 为 `77d45585`，
不同于候选的 `c9dd5601`，不能隔离计数器开销。因此另构建同 HEAD 的无计数版本 A，
候选为 B；构建参数/依赖相同。追加两轮 ABBA，8 格全部 result/qualification PASS，
无零速流、清理成功、二进制哈希未变。单位 Mbps：

| 轮次 | A | B | B | A | B/A 均值差 |
|---|---:|---:|---:|---:|---:|
| 1 | 1706.733 | 1738.927 | 1708.203 | 1753.291 | -0.373% |
| 2 | 1729.311 | 1687.231 | 1753.220 | 1737.560 | -0.762% |

A/B 总均值 1731.724/1721.895 Mbps，**-0.568%**；样本标准差分别为
19.404/29.779 Mbps（1.12%/1.73%）。客户端 task-clock ns/载荷字节均值
4.6053/4.6370（+0.69%）。差异小于本次样本波动，可作为诊断开销处于观测噪声范围的
初步证据，**不能证明严格等效或排除亚百分比开销**，也未验证延迟、UL 或其他平台。

literal main 另做两轮 ABBA 尝试，合格第一轮为
1552.311 / 1723.055 / 1722.041 / 1580.727 Mbps（末 A 重试后通过）；
第二轮为 1577.339 / 1706.593 / 1728.787 / 1442.000，末 A qualification 失败，
最后重试 1380.870 仍失败，**不能声明 literal main 的第二轮完整合格**。
其他被排除的 main 样本 1498.610、1444.238 Mbps，同样仅因 `process_cores_ok`
未达门槛（不是流量或清理失败）。没有降低门槛；失败数据全部保留，跨版本差异不作
计数器开销或回归结论。另一次准备失败为冻结清单缺必填字段，流量前 exit 1；补齐后
换目录运行。等待阶段控制器退出 143/255 不作为 benchmark 样本。

**二进制 SHA-256**：B `caede4294c98489b65987850c77ca1c7144c7c0e4776c75bafca0004a3d35be5`；
A `fd79783f5c33f794646c1465a11005273a870387432dd31f217d5497930c8ae4`；
literal main `b70ce160d4426eecfe74f7ac925606a81a25bf4cc02f258775d51546bc7ef5b1`。
证据在本地私有目录 `build/private/tunctr-20261101/`：原始运行、冻结源码/二进制指纹、
构建及 CTest 日志、`summary*.json`、补丁/修改副本及回滚验证。runner 源码指纹与
`binary_source_revision` 分列，未把 runner 的 HEAD 冒充旧 main 二进制源码。

结论：当前每次 writev 已承载约 19.5 个逻辑段，PSH 而非 explicit/cap 主导 flush。
后续批量写实验应保留帧边界和 PSH/超时/关闭语义，不应仅凭此表延迟 PSH 或调大 cap。
本次不改变 batching 行为；源码补丁可重建修改副本，独立回滚副本哈希与原始源码一致。

#### 2.4.8 无 profiler 单连接 DL 配对复测（2026-11-01）

**结论：未发现相对 native 的 P1 DL 明显回归；不能把历史差距全部认定为 profiler 开销。**
联网核对当前 main 为 `b76d3ba7971820643ff8e7bdb606778585a187f3`，以该提交归档
在实验主机新目录独立 Release 构建（335/335）；二进制 SHA-256
`d4b19da55977c47e3ad62d0d838c05f60cc49fa9269488eaa3f785cecbafaad7`。
XTCP pin 仍为 c9dd560 + 仓库补丁。仅修改测量记录，没有产品代码、默认值变更。

**方法**：30 s、omit 2 s，DL P1，shards=1、SPSC ingress/direct SPSC=0、
client-cpuset `36,39,40,46,50`、KCC、AES-256-CFB、GSO on/cap32、memory bridge on、
GRO 12288、gather 65536/1 ms、snd_buf 产品默认。三轮次序 N→X、X→N、N→X。
每个 stack 单独经过 `/home/ppp-m2/measure.py` 共享 measure/build 锁、负载门禁和
`pgrep -af`（measure.py、run_m3_isolated、PPP、iperf）空闲检查；实际命令全部经
`tools/run_m3_isolated.sh`，kernel-steering off。显式移除驱动自动追加的
`--process-perf-stat`，没有 perf record/stat 或其他 profiler。
所有构建仅在实验主机新目录，以共享 build flock、CPU 0–15、nice 10、最多 -j16 执行；
没有本地编译或测试，没有修改宿主网络设置。共享主机多次构建/测试排队导致配对间隔较长，
不能将其视为紧邻的同一瞬时负载；每格均重新检查空闲。

| P1 DL / Mbps | native | XTCP | XTCP/native |
| --- | ---: | ---: | ---: |
| 第 1 轮 | 1652.24 | 1771.05 | 1.072 |
| 第 2 轮 | 1625.19 | 1738.57 | 1.070 |
| 第 3 轮 | 1684.33 | 1763.46 | 1.047 |
| 算术均值（比值为均值之比） | 1653.92 | 1757.69 | 1.063 |

相对 §2.4.4 的 native 1690、XTCP 1801 Mbps，当前分别约 -2.1%、-2.4%；
比值从约 1.066 到 1.063，仅约 -0.3%，且落在三轮波动内。
因此未触发“比值明显下降后构建 add77894 做 ABBA”的条件，本次未构建旧提交。
无采样 XTCP 均值比 §2.4.5 的 1708.73 Mbps 高约 2.9%，但仍比历史 1801 低约 2.4%；
native 同向降低，说明不能用绝对值直接宣布产品回归。
结果与 profiler/共享宿主条件造成差距相容，但 §2.4.5 没有同期 native，且提交与时间不同，
本次没有同一二进制 profiler on/off 实验，**无法分离或定量证明 profiler 的独立开销**。
本次不重新验收 1.2×，不提供 CPU 核数或热点结论。

补充 P16 DL 三轮（同样 N→X、X→N、N→X）：

| P16 DL / Mbps | native | XTCP |
| --- | ---: | ---: |
| 第 1 轮 | 1526.90 | 1705.04 |
| 第 2 轮 | 1532.85 | 1713.45 |
| 第 3 轮 | 1545.50 | 1678.50 |
| 算术均值 | 1535.08 | 1699.00 |

P16 均值比 1.107，历史 1740/1534≈1.134，约 -2.4%；三轮 XTCP 跨度约 2.1%，
仅作为多流补充观测，不把这一幅度当作已确认的跨提交回归。旧提交 ABBA 条件按本任务
主目标 P1 判断；P16 若需判定小幅变化，仍需另做同场旧/新版本重复对照。

**资格状态**：无 profiler 意味着进程核数与迁移计数缺失；全部 12 格 result=pass、
零零速流、无 runtime_faults、cleanup_ok=true、二进制 hash 不变，但 qualification=fail
（`process_cores_ok`、`ppp_zero_migrations`），runner exit 1。保留这些原始失败状态，
不将吞吐有效与完整 CPU 资格通过混为一谈。

**证据与清理**：私有归档 `build/private/p1-clean-20261101/` 保存构建/测量日志、
驱动、原始 result/qualification、逐格 pgrep/负载门禁、竞争记录和二进制。
`summary.txt` 汇总 literal 状态；竞争记录的 foreign_builds_or_measurements 为空。
归档源码的临时 Git snapshot 仅用于 runner metadata，不冒充上游 commit。
根分区检查记录始终 ≥30 GB（本次构建前 42 GB，结束 41 GB）；取回证据后删除本任务
远端 `src/`、`bin/` 和临时 isolation 目录，保留结果归档，不动其他任务目录。
没有运行正确性/soak、实网、Windows/mobile 验证，没有提交或推送。

### 2.5 文档与代码不一致

XTCP 集成说明 §0 写"直连桥未设置 `OPENPPP2_XTCP_MEMORY_BRIDGE` 时默认尝试"，但
`VEthernetNetworkTcpipConnection.cpp` 的 `XtcpMemoryBridgeEnabled()` 只在值为 `1`
时开启。WS0 需要先确认哪一个是预期行为，再修正另一方。

## 3. 工作流

工作量标记：S（数天）、M（1–2 周）、L（数周以上）。

### WS0 度量与门禁（先做，其他工作流依赖它）

| 项 | 内容 | 量 |
| --- | --- | --- |
| 0.1 | 冻结 revision 指纹流程落地（`ppp_sha256 / git_head / dirty` 记录），所有 A/B 榜结果绑定指纹 | S |
| 0.2 | C 榜阶梯 C0–C7 从设计变成可运行脚本，先做 C0/C1/C2/C7 四档，回答"损失在哪一层" | M |
| 0.3 | 组件基准增强：合成对端协商窗口缩放；新增超大段模式（16–64 KiB GSO 语义段）；分别报告每段固定成本和每字节成本 | M |
| 0.4 | Linux CI 冒烟：组件基准 5 秒短跑，相对基线下降超过 10% 判失败；同时在 CI 跑 xtcp 上游测试 | S |
| 0.5 | 核实 §2.5 的直连桥默认值 | S |

### WS1 正确性前置（阻塞 WS2）

| 项 | 内容 | 量 |
| --- | --- | --- |
| 1.1 | 修本地补丁栈 FIN 顺序 bug：0005+0013 后一个带 FIN 的段若同时清理了过期乱序节点，会跳过 CLOSE-WAIT。改为先处理 FIN（上游 PR 版本已按此顺序） | S |
| 1.2 | 本地补丁栈让 xtcp 上游测试 13–15 个失败：0004 按 Linux 语义把带时间戳的载荷改成 1448 B，需要逐个核实并更新测试预期；0005 的立即 ACK 带 TSecr=0，需修正回显 | M |
| 1.3 | `XTCP-GSO-STALL-001` 根因与修复 | M |
| 1.4 | P64 DL server wedge；direct 路径间歇低值（resume_effective=0 的那一轮） | M |
| 1.5 | 上游合并进展：liulilittle/xtcp#1 合入后，把补丁栈 rebase 到上游新版本，删除已合入的补丁 | S |
| 1.6 | 单连接下行固定上限已定位为 snd_buf 64 KiB；#109 先将 Linux 默认值调为 1 MiB，现已扩展到所有支持 XTCP 的平台，配套 1.7 已合入；当前矩阵见 §2.4.2 | S |
| 1.7 | 缓冲池耗尽死锁已由 #108 的 0039/0040 修复（TX 余量 + 有界 heap overflow，集成说明 §11.188）；继续监测高并发压力 | M |
| 1.8 | P64 UL watchdog 已定位为 iperf 3.18 同核发送时的 TCP_INFO 统计阻塞；runner 对应组合关闭周期统计，保留逐流结果（§2.4.3） | S |
| 1.9 | UL P4/P16 的 G2 缺口：单核 CPU 基本饱和，预算未触顶；继续降低加密、逐块处理与 carrier 成本（§2.4.2） | M |

### WS2 把处理单元做大（主要收益来源）

| 项 | 内容 | 依赖 | 量 |
| --- | --- | --- | --- |
| 2.1 | Linux TUN 边缘 GSO 合并晋升默认开启：门槛是 1.3 修复、full matrix 通过、NetEm campaign 通过 | 1.3, 0.1 | M |
| 2.2 | 查清 direct GRO 13–15 KiB 退化原因（猜测与 32 KiB 池块、ACK 节奏或 window 更新有关），再决定能否突破 12 KiB | 0.3 | M |
| 2.3 | xtcp 缓冲池增加 64 KiB 大块层（有上限，与 upload budget 联动），超大帧整段进协议栈，不再切分 | 2.2 | L |
| 2.4 | NDI TSO 负收益根因：single-flight recovery gate 是否让 TSO 段频繁退化成 MSS；修好后再评估默认开启 | 2.3 | M |
| 2.5 | 直连桥下行：16 KiB、单在途改为更大块、多在途。之前 four-credit 实验因 receiver window 互锁被否决，需要先让 credit 释放和 rwnd 解耦 | 1.4 | M |
| 2.6 | Windows/Android 在 TAP 层做用户态 GRO/GSO：Wintun 一次唤醒读一批包，按同流、连续、仅 ACK/PSH 的规则合并；发送端软件分段后批量写入 | WS5/WS6 基线 | L |

### WS3 线程与唤醒

| 项 | 内容 | 量 |
| --- | --- | --- |
| 3.1 | 生产 second leg（`VirtualEthernetTcpipConnection`）实现 `BatchesPeerSend()/FlushPeerSend()`：一个入站批次只唤醒一次 writer。组件基准上该改动带来约 30% | S |
| 3.2 | 轮询定时器：只在新 deadline 早于已设 deadline 时才重设，减少 `timerfd_settime`（组件剖析中占 6–9%） | S |
| 3.3 | shard 默认数量按核数设置，并验证 B 榜多流扩展性和公平性 | M |
| 3.4 | 抽出通用的"SPSC 环形队列 + 仅在消费方等待时唤醒"组件，替换 TAP→栈、栈→second leg 两处交接 | M |
| 3.5 | Linux 多队列 TUN 的 per-queue affinity（按 MULTIQUEUE_TUN_MODEL 建议方向） | M |
| 3.6 | 单连接流水线：TAP I/O、TCP 状态机、carrier 加密分属三个线程。仅在 WS2 之后、有 C 榜数据证明单线程到顶时再做 | L |

### WS4 carrier 与加解密（合计约 37%）

| 项 | 内容 | 量 |
| --- | --- | --- |
| 4.1 | C4/C5/C6 完整保留率仍待测；本次 perf 定位 AES-256 加密约占 PPP 样本 34%，AES-128 配对没有消除 G2 差距（§2.4.2） | S |
| 4.2 | 当前 gather=65536 / wait=1 ms 已有效：关闭聚合 P4/P16 降约 26%/20%，关闭等待降约 10%/3%；继续查逐流聚合与每块固定成本，保持当前默认（§2.4.2） | M |
| 4.3 | 批量加密：一次处理多个帧，复用已做的 AES-NI 4 路交织 | M |
| 4.4 | 发送零拷贝：帧头和载荷用 writev 拼接，去掉一次复制 | M |

### WS5 Windows

| 项 | 内容 | 量 |
| --- | --- | --- |
| 5.1 | 建立隔离的 Windows 真机或 VM 测试环境（需授权，不能影响现有连接），跑 native 与 XTCP 配对 | M |
| 5.2 | Wintun 批量收发，减少每包一次的环形缓冲操作 | M |
| 5.3 | KCC 在 Windows 的定时器问题：评估高精度可等待定时器；在此之前保持默认 cubic | S |
| 5.4 | 评估 Windows AF_UNIX 桥（只评估，结论已记录在 XTCP 集成说明） | S |

### WS6 Android

| 项 | 内容 | 量 |
| --- | --- | --- |
| 6.1 | 补齐 Android Boost/OpenSSL 依赖，打开 XTCP 构建 | S |
| 6.2 | 真机基线：吞吐、CPU、耗电，至少两款 SoC | M |
| 6.3 | VpnService fd 批量读与用户态 GRO（同 2.6） | L |

## 4. 里程碑

| 里程碑 | 包含 | 验收 |
| --- | --- | --- |
| M0 度量就绪 | 0.1–0.5、1.1、3.1、3.2 | C0/C1/C2/C7 可跑；CI 冒烟上线；xtcp 上游测试在 CI 里跑；FIN bug 修复有测试 |
| M1 正确性清零 | 1.2–1.5 | 本地补丁栈下 xtcp 上游测试全过；GSO-on full matrix 无 stall、无 wedge |
| M2 Linux 大单元 | 2.1、2.2、4.1、4.2 | A 榜 native D0 P1 ≥ 2×；GSO 合并默认开启；XTCP 全矩阵 ≥ 1.2× native |
| M3 栈内大段与多核 | 2.3–2.5、3.3–3.5 | B 榜随核数扩展；单连接 DL 吞吐提升可复现（2026-10-26 B 段：WS3 开关已合入，验收未达成，见 §2.4.4） |
| M4 Windows/Android | WS5、WS6、2.6 | 两个平台都有真机配对基线，主要瓶颈有剖析数据支撑 |
| M5 流水线（视数据决定） | 3.6、4.3、4.4 | 只在 C 榜显示单线程到顶时启动 |

M0 和 M1 可以并行；M2 依赖 M0 的度量和 M1 的 stall 修复；M4 中的测试环境搭建可以与
M2 并行进行。

## 5. 风险

- **补丁栈膨胀**：2.3、2.4 会继续修改 xtcp。每项通用修复都同时向上游提交，降低升级成本。
- **内存**：64 KiB 块乘以连接数会放大内存，大块层必须有上限并接入 upload budget。
- **延迟与公平性**：大段带来突发，需要和 pacing quantum 配合；交互型小包延迟单独测。
- **测量噪声**：共享宿主上的结果不能当严格结论，A 榜必须在隔离环境、同机配对、多轮交错下测。
- **真机授权**：任何启动 PPP、改路由/DNS/网卡的验证都需要事先授权，并在隔离环境进行。

## 6. 待决策

1. §2.5 直连桥的预期默认值。
2. M2 的目标数值是否采用 §1 的 G1/G2。
3. Windows/Android 真机测试环境由谁提供、何时可用。
4. 3.6 单连接流水线是否列入本季度范围，还是等 M2 数据后再定。
