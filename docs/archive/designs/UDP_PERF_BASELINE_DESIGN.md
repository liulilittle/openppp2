# UDP 性能基准闸门（Phase 0）设计
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


- **日期**：2026-07-10
- **状态**：Phase 0 micro/runner/CI smoke 与 WSL E2E 诊断已实现；固定 Linux E2E 证据待采集
- **Last verified**：2026-07-17，`59e2c0e`
- **作者**：HyacinthHaru
- **关联工作**：接替原作者做 openppp2 的 UDP 性能优化 + 模块解耦，期望结果：基准性能 **+10-15%**、各模块解耦、各模块 CPP 不职责紊乱。
- **本文范围**：仅 Phase 0（建立可复现的 UDP 性能基准）。Phase 1（性能优化）、Phase 2（解耦重构）另立 spec。

---

## 1. 背景与目标

openppp2 是一个跨平台 VPN/代理系统，UDP 数据面存在明确的每包开销热点（每包 8-12 次堆分配、4-6 次整包 memcpy、全局分配器单锁、默认加密走 OpenSSL EVP 每包取锁）。优化目标是把"基准性能"提升 10-15%。

仓库现已具备独立 Google Benchmark 套件、冻结配置、micro/E2E runner、真实 micro baseline
和 CI correctness smoke。`validate_fixed_host.py` 要求显式稳定主机 ID、x86-64、
`performance` governor 和可读取 PMU cycles，并拒绝 WSL。共享 CI 不判断性能阈值；固定
Linux x86-64 主机仍是权威的 cycles/packet 与 E2E 采集环境。

权威 micro runner 额外生成 per-case `cycles.json`，分别覆盖 endpoint IPv4、packet
codec 64B/1400B 和 OpenSSL/SIMD crypto chain 64B/1400B。固定主机采集完成后，必须执行
`validate_baseline_bundle.py`，它会从 raw JSON 重算 summary、核对 micro/E2E 同主机与
同 SHA、冻结配置和两档 E2E，并将结构化 cycles/ns Amdahl 结果写入
`baseline-report.json`。只有该完整 bundle gate 通过，结果才可晋级为权威 baseline。

**因此 Phase 0 的目标**：建立一套**可复现、可回归、能诚实验收"+10-15%"**的 UDP 性能基准，作为后续所有优化的立项与验收闸门。Phase 0 **不改一行生产逻辑**。

## 2. 为什么 Phase 0 是前置闸门

没有可复现基准，"+10-15%"既无法立项也无法验收：改进会被测量噪声淹没，局部优化无法归因，也无法证明整体收益。Phase 0 先把"测什么、怎么测、怎么算达标"钉死，才能让 Phase 1 的每一步都拿数字说话。

## 3. 关键决策（评审已确认）

| # | 决策点 | 结论 | 理由 |
|---|---|---|---|
| 1 | 主验收口径 | **小包 pps + 每包 CPU 周期（cycles/packet）** | UDP 优化瓶颈在每包开销，非大包带宽 |
| 2 | 测量形态 | **微基准为主 + 端到端佐证** | 微基准可把每包成本测到 ±1%，端到端 loopback 噪声 ±10-20% 盖不住 15% |
| 3 | 权威测量环境 | **Linux x86-64** | 贴近部署；H4 依赖 x86 AES-NI、H1 需服务端多线程；perf 工具链在 Linux 最全。Mac 仅迭代看趋势 |
| 4 | 微基准框架 | **Google Benchmark**（FetchContent） | 内建重复/取中位/JSON、items_per_second 直给 pps、可接 PMU 读 cycles、RegisterMemoryManager 数分配次数 |
| 5 | 端到端打流 | **iperf3 -u 过 UDP 端口映射** | 标准打流器、复用现成 client.mappings、几乎零自写代码 |

## 4. 整体架构

四个互相独立、可单独运行的部件：

```
                   ┌─────────────────────────────────────────────┐
                   │  ① 微基准套件 (Google Benchmark)             │  ← 主验收
   生产源码 ──只读──│     bench/udp/*.cpp                          │
   (不改逻辑)       │     驱动热点: 加密链/序列化/端点编码/分配器   │
                   │     产出: ns/op + items/s(pps) + cycles/pkt  │
                   └───────────────┬─────────────────────────────┘
                                   │ --benchmark_format=json
                                   ▼
   ┌──────────────────────┐   ┌────────────────────┐
   │ ④ 冻结基准配置        │   │ ③ 对比/判定脚本     │  A.json vs B.json
   │ appsettings.bench.json│   │ tools/bench/compare │  → 中位/IQR/置信区间 → 达标?
   │ bandwidth=0/固定线程  │   └────────▲───────────┘
   └──────────┬───────────┘            │ e2e_A.json vs e2e_B.json
              │                ┌────────┴───────────────────────────┐
              └───────────────▶│ ② 端到端佐证 harness (tools/bench/*.sh)│  ← 辅助佐证
                               │  client+server loopback 双进程        │
                               │  + iperf3 -u 过 UDP 映射 → pps/丢包    │
                               └──────────────────────────────────────┘
```

**隔离原则**：Phase 0 绝不改生产逻辑；四部件彼此独立；不进主 CMake 默认构建，挂 `ENABLE_BENCH` 开关之后。

**被排除的替代**：纯端到端打流（噪声盖不住 15%）、复用内建遥测当基准（聚合口径+1Hz+圆整，精度不足）、自写基准框架（重复造 Google Benchmark 的轮子）。

## 5. 微基准套件

为每个高收益热点建一个微基准，作为"每包成本"的可测代理，尽量直接测公开底层类以零侵入生产代码。

| 微基准 | 对准热点 | 测什么 | 触达方式 | 侵入生产 |
|---|---|---|---|---|
| **BM1a** 底层密码器 | H4 | `Ciphertext`/`EVP`(OpenSSL) vs `aesni::AES`(AES-NI) 加密 {64/512/1400}B 的 ns/op + cycles | 直接实例化公开密码类 | 零 |
| **BM1b** 加密链四层 | H2 | 整条 protocol+transport 打包 ns/op + allocs/iter | `ITransmission` 加密逻辑，需窄钩子 | 极小（编译期隔离） |
| **BM2** 分配器锁争用 | H1 | `BufferswapAllocator` 1/2/4/8 线程并发 Alloc/Free | 直接实例化 + GBench ThreadRange | 零 |
| **BM3** 端点序列化 | H3 | `PACKET_IPEndPoint` 编码+解码 ns/op + allocs/iter | `VirtualEthernetLinklayer` 编解码，需窄钩子 | 极小 |
| **BM4** 包编解码 | H5/H7 | `UdpFrame::ToIp` / `IPFrame::ToArray` + 校验和 ns/op | 直接实例化公开净积木 | 零 |

**指标采集三件套**：
- **ns/op + pps**：Google Benchmark 原生（`items_per_second`）。
- **cycles/packet + IPC**：编译时接 libpfm（`--benchmark_perf_counters=CYCLES,INSTRUCTIONS`）；fallback 用 `perf stat` 外包固定迭代。
- **allocs/iter + bytes**：Google Benchmark `RegisterMemoryManager`，直接量化 H2 的"每包分配几次"。

**触达策略**：BM1a/BM2/BM4 直接测公开底层类，零侵入（已覆盖 H1、H4、包编解码）；BM1b/BM3 若需触达内部，只加 `#if defined(PPP_ENABLE_BENCH)` 编译期隔离的 friend/钩子，运行时逻辑一行不改，默认构建不编译。生产代码侵入上限：**零改动，或 ≤2 处编译期隔离钩子**。

**亮点**：BM1a 本身就是 H4 的验证台——同一份数据分别走 OpenSSL 与 AES-NI，直接量化"切 `simd-aes-*` 省多少 cycles/packet"，不改生产就能证明 H4 值不值得做。

## 6. 端到端佐证 harness

拓扑（全部 loopback 单机）：

```
iperf3 -u client ──▶ openppp2-client ────隧道────▶ openppp2-server ──▶ iperf3 -u server
 --length 64/512/1400  UDP映射 127.0.0.1:7000/udp                       映射目标 :10002/udp
 --time 30 --bitrate 0   → remote :10002/udp
```

流量从 iperf3 灌进 client 的本地 UDP 映射口，穿隧道到 server，转发到本机 iperf3 server，读穿隧道的 pps 与丢包。它只做**方向性佐证**（"整体没退化"），**不设严格阈值**；微基准显示优化但端到端反而掉，即为整体退化信号。

**待验证假设**：UDP 端口映射能否在**无 TUN**下独立工作（判断可以，映射是应用层 FRP，独立于虚拟网卡）。若不行，退路是 proxy 模式 + SOCKS5 UDP。这是 Phase 0 实现的第一个验证点。

## 7. 冻结配置与防陷阱

版本化的 `tools/bench/appsettings.bench.json` + `run_e2e.sh` 环境设置固化下列红线（不锁死则测的不是数据面）：

| 项 | 要求 | 不锁的后果 |
|---|---|---|
| `client.bandwidth` | **=0** | 默认 `10000` 是令牌桶限速器 |
| 服务端 `bandwidth_qos` | 确认不限速 | 双端都会节流 |
| `concurrent` | 固定并记录 | 直接决定并行度，改它波动 >15% |
| 构建类型 | **Release(-O3)**，禁 Debug/ASan | ASan 慢 2-20× |
| `ENABLE_SIMD` | A/B 一致（测 H4 时受控切换） | 改加密吞吐 |
| jemalloc | A/B 一致 | 改分配路径 |
| 数据变换/mux/udp/aggligator 开关 | 全部冻结 | 都改每字节 CPU |
| CPU 频率/turbo/绑核 | 锁频 + `taskset` + 关 turbo | 消除频率漂移 |

`env_fingerprint.sh` 让每次结果自带环境指纹（CPU 型号/频率/编译器/build flags/内核），便于事后核对 A/B 是否同条件。

## 8. A/B 统计判定口径

- **重复与取值**：每微基准 `--benchmark_repetitions=15`，取**中位数**；CV(=stddev/mean) > 2% 判"环境不稳，重测"。
- **真改进判定**：compare.py 对 A、B 中位用 **bootstrap 95% 置信区间**（纯 Python 无依赖）；**仅 CI 不重叠且方向正确才认**，重叠判"噪声之内"。
- **"+10-15%" 定义**：加权后的每包 CPU 成本下降 10-15%（等价 pps 提升 10-15%）。
- **局部→整体汇总（关键产出）**：先产出**每包 CPU 预算分解**（perf/火焰图量出代表性 UDP 包总 cycles 及各热点占比），**整体改进 = Σ(热点占比 × 局部改进)**（Amdahl 加权）。这份分解同时是优化路线图——占比最大者先做，最终排定 Phase 1 的 H4→H3→H2 顺序。按 **64B（小包）/1400B（大包）分档**报，避免稀释。
- **基线锚定**：动优化前在当前 HEAD 跑完整 harness，存 `tools/bench/baseline/`（JSON + 指纹 + git sha）；后续每步验收 = 候选 vs 锚定 baseline。

## 9. 目录结构与 CMake 集成

```
bench/                              ← 顶层，独立于 ppp/，主 GLOB 扫不到
  CMakeLists.txt                    FetchContent GBench + 找 libpfm；ENABLE_BENCH gate
  udp/
    bm_crypto.cpp                   BM1a/b — H4/H2
    bm_allocator.cpp                BM2   — H1
    bm_endpoint_serialize.cpp       BM3   — H3
    bm_packet_codec.cpp             BM4   — H5/H7
    bench_hooks.h                   PPP_ENABLE_BENCH 编译期窄钩子声明
tools/bench/
  run_micro.sh  run_e2e.sh  compare.py  env_fingerprint.sh
  appsettings.bench.json
  baseline/                         ← 锚定基线 JSON + 环境指纹（git 追踪）
docs/superpowers/specs/
  2026-07-10-udp-perf-baseline-design.md   ← 本文
```

- 根 `CMakeLists.txt` 仅加 `OPTION(ENABLE_BENCH ... OFF)` + `IF(ENABLE_BENCH) ADD_SUBDIRECTORY(bench)`，**默认 OFF，现有构建一字不动**。
- `bench/CMakeLists.txt`：FetchContent 拉 `google/benchmark`（pin 版本）；`find_library` 找 libpfm（找不到降级 `perf stat`）；每个 `bm_*.cpp` 编成独立可执行，外科手术式只链接被测的少数 `ppp/*.cpp`。
- **门禁边界**：不碰 MSVC/`ppp.vcxproj`（Phase 0 权威环境是 Linux，bench 只走 CMake）；bench 代码在 `ppp/` 之外 → 主 `GLOB_RECURSE` 收不到 → 不进 `openppp2_lib`、不触发 vcxproj parity（当前 187==187）与 include-boundary 门禁。

## 10. 测试 / CI 策略

- **微基准 self-check**：每个基准先跑正确性断言（加密后能解密还原、端点/包编解码往返一致）再计时，防止测到跑飞的路径。
- **CI（Linux）只做冒烟**：`--benchmark_min_time` 极短，验证能编/能跑/不崩/self-check 过；**性能数字不作 CI gate**（CI 机器噪声）。权威数字在专用机/固定 VM 手动跑。
- 端到端 harness 不进 CI（loopback 争抢不稳），本地/专用机跑。
- 权威结果晋级前必须设置 `BENCH_HOST_ID`，并对 micro/E2E 各自的 `env.json` 执行
  `python3 tools/bench/validate_fixed_host.py <env.json> "$BENCH_HOST_ID"`。门禁失败的结果
  只保留为诊断证据，不得覆盖 `tools/bench/baseline/`。
- 权威 bundle 还必须执行
  `python3 tools/bench/validate_baseline_bundle.py <micro-dir> <e2e-dir> "$BENCH_HOST_ID" <full-git-sha>`，
  将 stdout 保存为 `baseline-report.json`；缺少 per-case cycles、任一 raw/summary、冻结配置或
  64B/1400B E2E 时均不得晋级。

## 11. Phase 0 交付物清单（Definition of Done）

1. `bench/` 微基准套件（BM1a/b、BM2、BM3、BM4）在 Linux x86-64 `-DENABLE_BENCH=ON` 能编、能跑、self-check 过。
2. 指标三件套跑通：ns/op + pps、cycles/packet（libpfm 或 perf stat）、allocs/iter（RegisterMemoryManager）。
3. `tools/bench/` 四脚本可用：run_micro / run_e2e / compare.py / env_fingerprint。
4. 端到端 harness 能起 loopback 双进程 + iperf3 过 UDP 映射，出 pps/丢包 JSON，含"UDP 映射能否无 TUN 工作"的验证结论。
5. `appsettings.bench.json` 冻结配置 + 防陷阱红线落地。
6. 锚定基线：当前 HEAD 完整 baseline（micro + e2e JSON + 环境指纹 + git sha）存入 `tools/bench/baseline/`。
7. 每包 CPU 预算分解 + Amdahl 加权模型：64B/1400B 代表性包的总 cycles 与各热点占比，compare.py 能据此把局部改进汇总成整体百分比。
8. 一次"自证有效"演示：用 H4（BM1a：aes vs simd-aes）跑完整 A/B → compare，证明 harness 能稳定分辨已知性能差异并 Amdahl 加权出整体影响。
9. 设计文档（本文）+ 简短 `tools/bench/README.md`（怎么跑）。

**提交方式**：Phase 0 全部完成后，用本地 SSH 私钥 `~/.ssh/id_ed25519` 一股脑签名提交（署名 HyacinthHaru / hyacinth@haru.ac，无 co-author，短说明）。

## 12. 非目标（Out of Scope）

- 不做任何性能优化（那是 Phase 1）。
- 不做任何解耦重构（那是 Phase 2）。
- 不改生产运行时逻辑（仅允许编译期隔离的 bench 钩子）。
- 不碰 Windows/MSVC 构建、不动 P2P 数据面。
- 不追求端到端绝对吞吐数字的精确性（端到端仅作方向性佐证）。

---

## 附录 A：UDP 每包成本热点索引（截至调研时的 file:line）

> 优化靶点参考，供 Phase 1 使用。行号为调研快照，实施时以代码为准。

| 编号 | 热点 | 位置 | 收益 |
|---|---|---|---|
| H1 | 全局分配器单锁争用 | `ppp/threading/BufferswapAllocator.cpp:128/170` | 高 |
| H2 | 每包多次堆分配（加密链四层各分配+memcpy） | `ppp/transmissions/ITransmission.cpp:826/741/811` | 高 |
| H3 | 端点编成 ASCII 字符串（datagram-relay 每包 string 分配+strtol 解析） | `ppp/app/protocol/VirtualEthernetLinklayer.cpp:1128-1129/105` | 中高 |
| H4 | 默认 aes-cfb 走 OpenSSL EVP 每包取锁+重置 CTX | `ppp/cryptography/EVP.cpp:112-113`；AES-NI 快路径 `common/aesni/aes.cpp:210` | 中高 |
| H5 | MemoryStream 冷启动分配 + 增长 realloc | `ppp/io/MemoryStream.h:40/378`；`ppp/app/protocol/VirtualEthernetLinklayer.cpp:472` | 中 |
| H6 | 客户端 datagram 表每包持锁 | `ppp/app/client/VEthernetExchanger.cpp:1893-1895` | 中 |
| H7 | 回程 IPFrame copy-in/out + 每包 vector | `ppp/net/packet/UdpFrame.cpp:48/57`；`IPFrame.cpp:84/87`；`ppp/ethernet/VEthernet.cpp:959-960` | 中 |
| H8 | static-echo 每包 asio::post | `ppp/app/client/ExchangerStaticEchoChannel.cpp:402-413` | 中低 |
| H9 | aggligator 每包有序 std::map | `common/aggligator/aggligator.cpp:1512` | 中（仅聚合模式） |
| H10 | 写路径协程封装被迫 O0/O1 编译 | `ppp/transmissions/ITransmission.cpp:213-232` | 低中 |

## 附录 B：并发对 UDP 的影响（供 Phase 1/2 参考）

- 每 worker 线程一个 io_context（客户端默认 1、服务端默认 4）；一条 transmission 绑定单 strand，其读→解密→分发与写→加密同线程，故每连接内密码器/写队列基本无争用。
- 两处真正随 `concurrent` 放大的跨线程争用：**全局分配器锁（H1）**（所有线程每包 crypto 分配串行于此）与**客户端 datagram 表锁（H6）**（TAP 输入线程 ≠ 传输接收线程）。这是"解耦即降延迟"（Phase 2 拆锁）的主战场。
</content>
