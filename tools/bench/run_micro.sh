#!/bin/bash
# run_micro.sh — 跑 openppp2 UDP 微基准，输出可 A/B 对比的 JSON + 环境指纹。
#
# 用法: tools/bench/run_micro.sh [输出目录]   (默认 tools/bench/results/latest)
# 前置: cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
#
# 注意: 不加 --benchmark_report_aggregates_only，保留每 repetition 原始值供 compare.py
#       做 bootstrap CI。全程 nice -n 19（保护同机其它服务）。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$ROOT/build-bench"
OUT="${1:-$ROOT/tools/bench/results/latest}"

benchmarks=(bm_crypto bm_crypto_chain bm_allocator bm_endpoint_serialize bm_packet_codec)

for bm in "${benchmarks[@]}"; do
    if [ ! -x "$BUILD/$bm" ]; then
        echo "missing $BUILD/$bm — build first:" >&2
        echo "  cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench" >&2
        exit 1
    fi
done

mkdir -p "$OUT"
bash "$HERE/env_fingerprint.sh" > "$OUT/env.json"
echo "env fingerprint -> $OUT/env.json"

perf_available=false
if command -v perf >/dev/null && perf stat -e cycles true >/dev/null 2>&1; then
    perf_available=true
fi

for bm in "${benchmarks[@]}"; do
    echo "running $bm ..."
    runner=(nice -n 19)
    if "$perf_available"; then
        runner+=(perf stat -x, -e cycles -o "$OUT/$bm.perf" --)
    else
        printf 'cycles,unavailable\n' > "$OUT/$bm.perf"
    fi
    "${runner[@]}" "$BUILD/$bm" \
        --benchmark_min_time=0.2 \
        --benchmark_repetitions=15 \
        --benchmark_out="$OUT/$bm.json" \
        --benchmark_out_format=json > "$OUT/$bm.txt" 2>&1
done

python3 "$HERE/summarize.py" "$OUT" > "$OUT/summary.json"
if "$perf_available"; then
    python3 "$HERE/collect_cycles.py" "$BUILD" "$OUT/cycles.json"
else
    python3 "$HERE/collect_cycles.py" --unavailable ignored "$OUT/cycles.json"
fi

echo "done. results in $OUT"
echo "compare with a baseline via: python3 $HERE/compare.py <baseline>/bm_crypto.json $OUT/bm_crypto.json"
