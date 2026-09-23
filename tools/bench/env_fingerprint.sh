#!/bin/bash
# env_fingerprint.sh — 采集环境指纹 JSON，让每次基准结果自带可核对的环境上下文。
# A/B 对比前应确认两侧指纹一致（尤其 governor / 编译 flag / benchmark 库）。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
git_sha="${GIT_SHA:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"
host_id="${BENCH_HOST_ID:-}"

perf_cycles=false
if command -v perf >/dev/null && perf stat -e cycles true >/dev/null 2>&1; then
    perf_cycles=true
fi

mhz=$(lscpu 2>/dev/null | awk -F: '/CPU max MHz|CPU MHz/{gsub(/ /,"",$2);print $2;exit}')
cat <<EOF
{
  "cpu":          "$(lscpu 2>/dev/null | awk -F: '/Model name/{sub(/^ */,"",$2);print $2;exit}')",
  "cpu_mhz":      "${mhz:-unknown}",
  "nproc":        $(nproc),
  "arch":         "$(uname -m)",
  "host_id":      "$host_id",
  "virt":         "$(systemd-detect-virt 2>/dev/null || echo unknown)",
  "kernel":       "$(uname -r)",
  "git_sha":      "$git_sha",
  "compiler":     "$(gcc --version 2>/dev/null | head -1)",
  "bench_flags":  "-O3 -DNDEBUG -maes -msse2 -mpclmul -D__SIMD__",
  "benchmark_lib":"$(dpkg -l libbenchmark-dev 2>/dev/null | awk '/ii  libbenchmark-dev/{print $3}')",
  "boost":        "$(dpkg -l libboost-dev 2>/dev/null | awk '/ii  libboost-dev/{print $3}')",
  "openssl":      "$(openssl version 2>/dev/null)",
  "governor":     "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)",
  "perf_cycles":  $perf_cycles,
  "perf_paranoid":"$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"
}
EOF
