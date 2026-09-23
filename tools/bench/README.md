# openppp2 UDP 性能基准（Phase 0）

可复现、可回归、能验收「基准性能 +10-15%」的 UDP 每包成本基准。设计见
`docs/UDP_PERF_BASELINE_DESIGN.md`；
每包成本分解与 Amdahl 收益见 `COST_BREAKDOWN.md`。

## 权威环境

Linux **x86-64 + AES-NI**（H4 依赖 x86 AES-NI 指令、H1 需服务端多线程、perf 需可读 PMU）。
在 arm/macOS 上只能看相对趋势，验收数字以 x86-64 Linux 为准。

权威结果必须由操作者声明稳定主机身份，并通过晋级门禁：

```sh
export BENCH_HOST_ID=openppp2-bench-01
export BASELINE_SHA="$(git rev-parse HEAD)"
tools/bench/run_micro.sh tools/bench/results/fixed-micro
sudo --preserve-env=BENCH_HOST_ID \
  tools/bench/run_e2e.sh tools/bench/results/fixed-e2e
python3 tools/bench/validate_fixed_host.py \
  tools/bench/results/fixed-micro/env.json "$BENCH_HOST_ID"
python3 tools/bench/validate_baseline_bundle.py \
  tools/bench/results/fixed-micro tools/bench/results/fixed-e2e \
  "$BENCH_HOST_ID" "$BASELINE_SHA" \
  > tools/bench/results/baseline-report.json
```

门禁只接受 x86-64、`performance` governor 和可读取 PMU cycles 的非 WSL 环境，且
指纹中的 `host_id` 必须与调用者声明一致。共享 CI、WSL 和未声明身份的结果仍可用于
correctness/趋势诊断，但不得复制到 `tools/bench/baseline/` 作为权威性能证据。
`run_micro.sh` 的 `cycles.json` 对 endpoint IPv4、packet codec 64B/1400B、
OpenSSL/SIMD crypto chain 64B/1400B 分别执行精确 perf filter，不再把整个可执行文件
的 cycles 平均到不同 case。`validate_baseline_bundle.py` 会从 raw JSON 重算 summary，
核对冻结配置、同一主机/SHA、64B/1400B E2E，并输出结构化 Amdahl 报告。

## 依赖（Debian/Ubuntu）

```sh
apt-get install -y cmake libbenchmark-dev libssl-dev libboost-all-dev libjemalloc-dev
# 可选（cycles 精确采集，非必需，ns/op 已是等价代理）: linux-perf
```

## 构建（独立 CMake 项目，不改 openppp2 根构建）

```sh
cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench            # 服务器上建议 nice -n 19 ... -j1 护同机服务
```

产出 `bm_crypto`、`bm_crypto_chain`、`bm_allocator`、`bm_endpoint_serialize` 和
`bm_packet_codec`。每个目标启动时先执行 round-trip/self-check。

## 跑 + A/B 对比

```sh
# 生成一次结果（含每 repetition 原始值，供 bootstrap）
tools/bench/run_micro.sh tools/bench/results/mine

# 与锚定基线对比（bootstrap 95% CI 不重叠才算显著）
python3 tools/bench/compare.py tools/bench/baseline/bm_crypto.json tools/bench/results/mine/bm_crypto.json
```

`compare.py` 判定口径：每 benchmark 取中位数、bootstrap 95% CI；仅 CI 不重叠且方向正确才
判 IMPROVED/REGRESSED，否则 noise。已自检：baseline vs 自身全 noise、vs −15% 候选全 IMPROVED。

## 微基准清单

| 微基准 | 对准热点 | 状态 |
|---|---|---|
| `bm_crypto`（BM1a） | H4：OpenSSL EVP vs AES-NI 加密（`simd-aes-*`） | ✅ 已完成 |
| `bm_allocator`（BM2） | H1：`BufferswapAllocator` 锁争用随线程数放大 | ✅ 已完成 |
| `bm_endpoint_serialize`（BM3） | H3：端点 wire format encode/decode | ✅ 已完成 |
| `bm_packet_codec`（BM4） | H5/H7：UDP/IP 完整编解码 | ✅ 已完成 |
| `bm_crypto_chain`（BM1b） | H2：完整四层加密链与 allocs/iter | ✅ 已完成 |

## 关键结果（512B，median，见 COST_BREAKDOWN.md）

- **H4**：切 `simd-aes-*`，加密每包 3300→1063 ns；小包 64B 达 **12.7×**。仅改配置。
- **H1**：`syncobj_` 锁 1→2 线程延迟 +48%、CPU 翻倍（并发串行化）。
- 每包已测成本 H4 单项 **−41%**，远超 +10-15% 目标。

## 测量陷阱（务必冻结，见 spec §7）

`client.bandwidth=0`（默认 10000 是限速器）、固定 `concurrent`、Release(-O3、非 ASan)、
`ENABLE_SIMD`/jemalloc 两侧一致、锁 CPU 频率/关 turbo。`env_fingerprint.sh` 记录环境指纹供核对。

## 隔离说明

- bench 是独立 CMake 项目，**不改 openppp2 根 `CMakeLists.txt`、不碰 MSVC/vcxproj**。
- `bench/support/bench_stubs.cpp` 等桩掉 ppp 深依赖雪球（内存池/Error/Executors/File）——
  仅编译期链接闭合，绝不改生产运行时逻辑。BM2 用真实内存池（buddy 实现由 `buddy_impl.cpp`
  提供，`File::Create/Delete` 由 `bench_pool_stub.cpp` 走轻量 POSIX）。
- 端到端佐证：`run_e2e.sh` 使用冻结的 `appsettings.bench.json`，分别输出
  64B/1400B iperf3 JSON。共享 CI 不执行 E2E，也不以噪声性能数字卡门。

E2E 默认使用固定的 `10M` offered load，避免 `--bitrate 0` 饱和流量主动打断单条
transmission。合格基准机可用 `BENCH_BITRATE` 校准，但 summary 会记录实际值，A/B 必须
保持一致。E2E 结果也必须用同一个 `BENCH_HOST_ID` 采集，并对其 `env.json` 执行上述
完整 bundle 门禁。WSL 结果只验证 harness；E2E baseline 仍须由固定 Linux 主机生成。
