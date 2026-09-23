#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CONFIG="$HERE/appsettings.bench.json"
PPP_BIN="${PPP_BIN:-$ROOT/bin/ppp}"
OUT="${1:-$HERE/results/e2e-latest}"
DURATION="${BENCH_DURATION:-30}"
BITRATE="${BENCH_BITRATE:-10M}"
CLIENT_MODE="${BENCH_CLIENT_MODE:-proxy}"

[[ "$BITRATE" =~ ^[1-9][0-9]*([KMG])?$ ]] || {
    echo "BENCH_BITRATE must be a positive integer with optional K, M, or G suffix" >&2
    exit 2
}

for command in "$PPP_BIN" iperf3; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done
if [ "$(id -u)" -ne 0 ]; then
    echo "run_e2e.sh requires root for the VPN processes" >&2
    exit 1
fi

mkdir -p "$OUT"
bash "$HERE/env_fingerprint.sh" > "$OUT/env.json"
cp "$CONFIG" "$OUT/appsettings.bench.json"

pids=()
cleanup() {
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait "${pids[@]:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PPP_BIN" --mode=server --config="$CONFIG" > "$OUT/server.log" 2>&1 & pids+=("$!")
sleep "${BENCH_SERVER_WAIT:-2}"
if ! kill -0 "${pids[0]}" 2>/dev/null; then
    echo "server exited during startup; inspect $OUT/server.log" >&2
    exit 1
fi
ss -lntup > "$OUT/server-sockets.txt" 2>&1 || true
"$PPP_BIN" --mode="$CLIENT_MODE" --config="$CONFIG" \
    --tun-host=no --tun-vnet=no --tun-protect=no --tun-route=no > "$OUT/client.log" 2>&1 & pids+=("$!")
sleep "${BENCH_STARTUP_WAIT:-5}"
for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "VPN process $pid exited during startup; inspect $OUT/*.log" >&2
        exit 1
    fi
done

for size in 64 1400; do
    timeout "$((DURATION + 15))" iperf3 -s -1 -p 10002 > "$OUT/iperf-server-$size.log" 2>&1 & pids+=("$!")
    sleep 1
    iperf3 -c 127.0.0.1 -p 7000 --connect-timeout 5000 -u --bitrate "$BITRATE" --length "$size" --time "$DURATION" --json \
        > "$OUT/e2e-$size.json"
    python3 "$HERE/validate_e2e.py" "$OUT/e2e-$size.json" "$BITRATE" > "$OUT/e2e-$size.summary.json"
    wait "${pids[-1]}"
    unset 'pids[-1]'
done

echo "E2E results: $OUT"
