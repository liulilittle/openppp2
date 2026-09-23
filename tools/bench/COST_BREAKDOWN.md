# UDP 每包成本分解与 Amdahl 结果

> 数据源：`baseline/summary.json` 与 `baseline/env.json`。采样于
> `c8342f3` 的 WSL2 Linux x86-64 Release 构建，15 次重复取中位数。
> WSL2 未开放 PMU，因此本次 `cycles/packet` 明确记为 unavailable；权威阈值仍需在固定 Linux x86-64 主机复测。

## 已测路径

| 路径 | 64B ns/op | 1400B ns/op | allocations/op |
|---|---:|---:|---:|
| endpoint encode + decode | 12.0 | 12.0 | 0 |
| UDP → IPv4 → wire → IPv4 → UDP | 361.6 | 489.6 | 9 |
| 完整 crypto chain（OpenSSL） | 2019.8 | 7044.5 | 5 |
| 完整 crypto chain（SIMD） | 380.3 | 4856.6 | 5 |

`bm_crypto_chain` 覆盖 transport cipher、payload mask/shuffle/delta、protocol header cipher 和最终 pack。
它是 bench-only 的生产格式复刻，带 self-check，不进入生产目标。

## Amdahl 加权

按当前已测三段求和：

| 包长 | OpenSSL 总成本 | SIMD 总成本 | crypto 占比 | crypto 局部改善 | Amdahl 整体改善 |
|---|---:|---:|---:|---:|---:|
| 64B | 2393.3 ns | 753.9 ns | 84.4% | 81.2% | **68.5%** |
| 1400B | 7546.1 ns | 5358.2 ns | 93.4% | 31.1% | **29.0%** |

公式：`整体改善 = 热点占比 × 局部改善`。这些百分比只代表已测 CPU 路径，不包含 syscall、调度、TAP、Route/DNS 或真实网络抖动，不能替代 E2E 结论。

## 结论

- 64B 小包仍最受每包 crypto 固定成本影响，SIMD 是最高杠杆项。
- 1400B 大包的 crypto 占比更高，但 SIMD 局部收益较小，最终预测改善约 31%。
- 完整链当前观测到 5 次分配，packet codec 为 9 次；后续优化应先用 profiler 证明分配削减不会把成本转移到共享池锁。
- `run_e2e.sh` 只做方向性佐证；CI 仅运行 correctness/smoke，不设置性能阈值。
