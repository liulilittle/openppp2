#!/usr/bin/env bash
# Laboratory-only native D0 P1 UL runner for PPP-DATAPATH-001.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PPP_BIN="${PPP_BIN:-${ROOT}/bin/ppp}"
ARTIFACT_DIR=""
LABEL="p1-ul"
CONCURRENT=1
TUN_SSMT=""
DURATION=10
PERF_RECORD=false
PERF_STAT=false
SCHED_TRACE=false
SYSTEM_CPU_STAT=false
ECHO_LATENCY_MODE="off"
IDLE_ECHO_LATENCY=false
LOADED_ECHO_LATENCY=false
GSO_LEDGER=false
TAP_GSO_MODE="off"
DATAPATH_TELEMETRY=true
PERF_FREQUENCY=99
PERF_DOMAIN="all"
AFFINITY_MODE="default"
AFFINITY_CPUS=""
SYSTEM_CPU_SET=""
ECHO_LATENCY_PORT=5202
ECHO_LATENCY_RATE_HZ=100

usage() {
  cat <<'EOF'
Usage: run_datapath_p1_ul_matrix.sh --artifacts DIR [options]
  --concurrent N       Client concurrent setting (default: 1)
  --tun-ssmt VALUE     Client --tun-ssmt value, e.g. 2 or 4/mq
  --duration SEC       Formal measurement duration; loaded mode excludes a 2-second iperf omit (default: 10)
  --label NAME         Artifact label (default: p1-ul)
  --tap-gso MODE       Explicit TAP GSO merge mode: off or on (default: off)
  --gso-ledger         Enable GSO ledger and boundary-window attribution summary
  --idle-echo-latency  Run 100Hz one-byte in-band echo ping-pong without iperf bulk
  --loaded-echo-latency  Run 100Hz one-byte in-band echo ping-pong on a separate TCP flow during iperf bulk
  --perf-record        Capture client software cpu-clock samples during the formal interval
  --perf-stat          Capture client task-clock, PMU counters, context switches, and migrations
  --sched-trace        Capture system scheduler wakeup/switch trace, filtered to vnet in analysis
  --system-cpu-stat    Capture system-wide perf and softirq snapshots on pinned client CPUs
  --no-datapath-telemetry  Disable OPENPPP2_DATAPATH_PERF_JSON for clean perf runs
  --perf-frequency HZ  perf sample frequency when enabled (default: 99)
  --perf-domain MODE   all, user, kernel, or split samples (default: all; --perf-record only)
  --affinity-mode MODE default, spread, vnet-isolated, or scheduler-collocated
  --affinity-cpus LIST Five CPUs for affinity modes, e.g. 0,1,2,3,4

Runs native D0 (AES-256-CFB, compat mux) P=1 upload in isolated netns. Echo
latency modes measure application in-band request/response latency, not TCP
stack RTT. SSMT needs concurrent > 1 to activate workers; this script rejects
ineffective concurrent=1 + --tun-ssmt combinations.
EOF
}

require_option_value() {
  [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage >&2; exit 2; }
}

while (($#)); do
  case "$1" in
    --artifacts) require_option_value "$@"; ARTIFACT_DIR="$2"; shift 2 ;;
    --concurrent) require_option_value "$@"; CONCURRENT="$2"; shift 2 ;;
    --tun-ssmt) require_option_value "$@"; TUN_SSMT="$2"; shift 2 ;;
    --duration) require_option_value "$@"; DURATION="$2"; shift 2 ;;
    --label) require_option_value "$@"; LABEL="$2"; shift 2 ;;
    --tap-gso) require_option_value "$@"; TAP_GSO_MODE="$2"; shift 2 ;;
    --gso-ledger) GSO_LEDGER=true; shift ;;
    --idle-echo-latency) IDLE_ECHO_LATENCY=true; shift ;;
    --loaded-echo-latency) LOADED_ECHO_LATENCY=true; shift ;;
    --perf-record) PERF_RECORD=true; shift ;;
    --perf-stat) PERF_STAT=true; shift ;;
    --sched-trace) SCHED_TRACE=true; shift ;;
    --system-cpu-stat) SYSTEM_CPU_STAT=true; shift ;;
    --no-datapath-telemetry) DATAPATH_TELEMETRY=false; shift ;;
    --perf-frequency) require_option_value "$@"; PERF_FREQUENCY="$2"; shift 2 ;;
    --perf-domain) require_option_value "$@"; PERF_DOMAIN="$2"; shift 2 ;;
    --affinity-mode) require_option_value "$@"; AFFINITY_MODE="$2"; shift 2 ;;
    --affinity-cpus) require_option_value "$@"; AFFINITY_CPUS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$ARTIFACT_DIR" ]] || { echo "--artifacts is required" >&2; exit 2; }
[[ "$CONCURRENT" =~ ^[1-9][0-9]*$ ]] || { echo "--concurrent must be positive" >&2; exit 2; }
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || { echo "--duration must be positive" >&2; exit 2; }
[[ "$PERF_FREQUENCY" =~ ^[1-9][0-9]*$ ]] || { echo "--perf-frequency must be positive" >&2; exit 2; }
[[ "$PERF_DOMAIN" =~ ^(all|user|kernel|split)$ ]] || { echo "--perf-domain must be all, user, kernel, or split" >&2; exit 2; }
[[ "$AFFINITY_MODE" =~ ^(default|spread|vnet-isolated|scheduler-collocated)$ ]] || { echo "invalid --affinity-mode" >&2; exit 2; }
[[ "$TAP_GSO_MODE" =~ ^(off|on)$ ]] || { echo "--tap-gso must be off or on" >&2; exit 2; }
[[ "$IDLE_ECHO_LATENCY" == false || "$LOADED_ECHO_LATENCY" == false ]] || {
  echo "--idle-echo-latency and --loaded-echo-latency are mutually exclusive" >&2; exit 2;
}
if [[ "$IDLE_ECHO_LATENCY" == true ]]; then ECHO_LATENCY_MODE="idle"; fi
if [[ "$LOADED_ECHO_LATENCY" == true ]]; then ECHO_LATENCY_MODE="loaded"; fi
[[ "$GSO_LEDGER" == false || "$DATAPATH_TELEMETRY" == true ]] || {
  echo "--gso-ledger requires datapath telemetry; remove --no-datapath-telemetry" >&2; exit 2;
}
enabled_perf_modes=0
if [[ "$PERF_RECORD" == true ]]; then ((enabled_perf_modes += 1)); fi
if [[ "$PERF_STAT" == true ]]; then ((enabled_perf_modes += 1)); fi
if [[ "$SCHED_TRACE" == true ]]; then ((enabled_perf_modes += 1)); fi
[[ "$enabled_perf_modes" -le 1 ]] || { echo "--perf-record, --perf-stat, and --sched-trace are mutually exclusive" >&2; exit 2; }
[[ "$SYSTEM_CPU_STAT" == false || "$AFFINITY_MODE" == vnet-isolated ]] || {
  echo "--system-cpu-stat requires --affinity-mode vnet-isolated" >&2; exit 2;
}
[[ "$SYSTEM_CPU_STAT" == false || -n "$AFFINITY_CPUS" ]] || {
  echo "--system-cpu-stat requires --affinity-cpus" >&2; exit 2;
}
if [[ "$SYSTEM_CPU_STAT" == true ]]; then SYSTEM_CPU_SET="$AFFINITY_CPUS"; fi
PERF_EVENT="cpu-clock"
if [[ "$PERF_DOMAIN" == user ]]; then PERF_EVENT="cpu-clock:u"; fi
if [[ "$PERF_DOMAIN" == kernel ]]; then PERF_EVENT="cpu-clock:k"; fi
if [[ "$PERF_DOMAIN" == split ]]; then PERF_EVENT="cpu-clock:u,cpu-clock:k"; fi
[[ -x "$PPP_BIN" ]] || { echo "PPP binary not executable: $PPP_BIN" >&2; exit 1; }
command -v ip >/dev/null || { echo "missing ip" >&2; exit 1; }
[[ "$ECHO_LATENCY_MODE" == idle ]] || command -v iperf3 >/dev/null || { echo "missing iperf3" >&2; exit 1; }
[[ "$enabled_perf_modes" -eq 0 && "$SYSTEM_CPU_STAT" == false ]] || command -v perf >/dev/null || { echo "missing perf" >&2; exit 1; }
command -v taskset >/dev/null || { echo "missing taskset" >&2; exit 1; }
[[ "$ECHO_LATENCY_MODE" == off || -f "$ROOT/tools/tcp_rtt_probe.py" ]] || { echo "missing tcp_rtt_probe.py" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "root is required for netns/TUN" >&2; exit 1; }
[[ -z "$TUN_SSMT" || "$CONCURRENT" -gt 1 ]] || {
  echo "--tun-ssmt requires --concurrent > 1: mta/SSMT workers are otherwise inactive" >&2
  exit 2
}

mkdir -p "$ARTIFACT_DIR"
STATE_DIR="$(mktemp -d)"
SUFFIX="$$-${LABEL//[^[:alnum:]]/-}"
NS_C="pppdp-c-${SUFFIX}"
NS_S="pppdp-s-${SUFFIX}"
NS_T="pppdp-t-${SUFFIX}"
SERVER_PORT=20000
IPERF_PORT=5201
SERVER_IP=198.51.100.1
TARGET_IP=192.0.2.2
pids=()
CPU_SAMPLER_PID=""
PERF_PID=""
PERF_STAT_PID=""
SYSTEM_PERF_STAT_PID=""
SCHED_TRACE_PID=""
IPERF_CLIENT_PID=""
ECHO_LATENCY_CLIENT_PID=""

stop_sched_trace() {
  [[ -z "$SCHED_TRACE_PID" ]] && return
  kill -INT "$SCHED_TRACE_PID" 2>/dev/null || true
  local status=0
  if wait "$SCHED_TRACE_PID"; then
    status=0
  else
    status=$?
  fi
  SCHED_TRACE_PID=""
  [[ "$status" -eq 0 || "$status" -eq 130 ]]
}

stop_perf_recording() {
  [[ -z "$PERF_PID" ]] && return
  kill -INT "$PERF_PID" 2>/dev/null || true
  wait "$PERF_PID" 2>/dev/null || true
  PERF_PID=""
}

stop_perf_stat() {
  [[ -z "$PERF_STAT_PID" ]] && return
  kill -INT "$PERF_STAT_PID" 2>/dev/null || true
  wait "$PERF_STAT_PID" 2>/dev/null || true
  PERF_STAT_PID=""
}

stop_system_perf_stat() {
  [[ -z "$SYSTEM_PERF_STAT_PID" ]] && return
  kill -INT "$SYSTEM_PERF_STAT_PID" 2>/dev/null || true
  wait "$SYSTEM_PERF_STAT_PID" 2>/dev/null || true
  SYSTEM_PERF_STAT_PID=""
}

cleanup() {
  local status=$?
  set +e
  stop_perf_recording
  stop_perf_stat
  stop_system_perf_stat
  stop_sched_trace
  [[ -z "$CPU_SAMPLER_PID" ]] || kill "$CPU_SAMPLER_PID" 2>/dev/null || true
  [[ -z "$IPERF_CLIENT_PID" ]] || kill "$IPERF_CLIENT_PID" 2>/dev/null || true
  [[ -z "$ECHO_LATENCY_CLIENT_PID" ]] || kill "$ECHO_LATENCY_CLIENT_PID" 2>/dev/null || true
  if [[ -d "$STATE_DIR" ]]; then cp -a "$STATE_DIR"/. "$ARTIFACT_DIR"/; fi
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait "${pids[@]:-}" 2>/dev/null || true
  ip netns del "$NS_C" 2>/dev/null || true
  ip netns del "$NS_S" 2>/dev/null || true
  ip netns del "$NS_T" 2>/dev/null || true
  rm -rf "/etc/netns/${NS_C}"
  rm -rf "$STATE_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

ip netns add "$NS_C"; ip netns add "$NS_S"; ip netns add "$NS_T"
ip link add xc-veth type veth peer name xs-veth
ip link add xs2-veth type veth peer name xt-veth
ip link set xc-veth netns "$NS_C"; ip link set xs-veth netns "$NS_S"
ip link set xs2-veth netns "$NS_S"; ip link set xt-veth netns "$NS_T"
ip -n "$NS_C" addr add 198.51.100.2/24 dev xc-veth
ip -n "$NS_S" addr add 198.51.100.1/24 dev xs-veth
ip -n "$NS_S" addr add 192.0.2.1/24 dev xs2-veth
ip -n "$NS_T" addr add 192.0.2.2/24 dev xt-veth
for ns in "$NS_C" "$NS_S" "$NS_T"; do ip -n "$ns" link set lo up; done
ip -n "$NS_C" link set xc-veth up; ip -n "$NS_S" link set xs-veth up
ip -n "$NS_S" link set xs2-veth up; ip -n "$NS_T" link set xt-veth up
ip -n "$NS_C" route add default via 198.51.100.1
ip -n "$NS_T" route add default via 192.0.2.1
mkdir -p "/etc/netns/${NS_C}"
printf 'nameserver 192.0.2.53\n' >"/etc/netns/${NS_C}/resolv.conf"

python3 - "$ROOT" "$STATE_DIR" "$SERVER_IP" "$SERVER_PORT" "$CONCURRENT" <<'PY'
import json, pathlib, sys
root, out, server_ip, server_port, concurrent = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
compat = root / "tools" / "compat"
for name, role in (("server.json", "server"), ("client_proxy.json", "client")):
    cfg = json.loads((compat / name).read_text(encoding="utf-8"))
    if role == "client":
        cfg["concurrent"] = concurrent
    cfg["key"]["transport"] = "aes-256-cfb"
    cfg["mux"]["turbo"] = False
    cfg["tcp"]["listen"]["port"] = server_port if role == "server" else 0
    cfg["udp"]["listen"]["port"] = server_port if role == "server" else 0
    if role == "client":
        cfg["client"]["server"] = f"ppp://{server_ip}:{server_port}/"
        cfg["client"].pop("mappings", None)
    (out / name.replace("_proxy", "")).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY

tap_gso_env=()
if [[ "$TAP_GSO_MODE" == on ]]; then
  tap_gso_env=("OPENPPP2_TAP_GSO_MERGE=1")
else
  tap_gso_env=("OPENPPP2_TAP_GSO_MERGE_DISABLE=1")
fi
server_env=("${tap_gso_env[@]}")
client_env=("${tap_gso_env[@]}")
if [[ "$DATAPATH_TELEMETRY" == true ]]; then
  server_env+=("OPENPPP2_DATAPATH_PERF_JSON=${STATE_DIR}/datapath-server.jsonl")
  client_env+=(
    "OPENPPP2_DATAPATH_PERF_JSON=${STATE_DIR}/datapath-client.jsonl"
    "OPENPPP2_DATAPATH_PERF_MEASUREMENT_BOUNDARIES=1"
  )
else
  : >"$STATE_DIR/datapath-client.jsonl"
fi
if [[ "$GSO_LEDGER" == true ]]; then
  server_env+=("OPENPPP2_DATAPATH_GSO_LEDGER=1" "OPENPPP2_DATAPATH_GSO_MERGEABILITY=1")
  client_env+=("OPENPPP2_DATAPATH_GSO_LEDGER=1" "OPENPPP2_DATAPATH_GSO_MERGEABILITY=1")
fi
ip netns exec "$NS_S" env \
  -u OPENPPP2_TAP_GSO_MERGE -u OPENPPP2_TAP_GSO_MERGE_DISABLE \
  -u OPENPPP2_DATAPATH_GSO_LEDGER -u OPENPPP2_DATAPATH_GSO_MERGEABILITY \
  "${server_env[@]}" stdbuf -oL -eL "$PPP_BIN" --mode=server --config="$STATE_DIR/server.json" \
  >"$STATE_DIR/server.log" 2>&1 & pids+=("$!")
sleep 2
if [[ "$ECHO_LATENCY_MODE" != idle ]]; then
  ip netns exec "$NS_T" iperf3 -s -1 -p "$IPERF_PORT" >"$STATE_DIR/iperf-server.log" 2>&1 & pids+=("$!")
fi
if [[ "$ECHO_LATENCY_MODE" != off ]]; then
  ip netns exec "$NS_T" python3 "$ROOT/tools/tcp_rtt_probe.py" server \
    --host "$TARGET_IP" --port "$ECHO_LATENCY_PORT" >"$STATE_DIR/echo-latency-server.log" 2>&1 & pids+=("$!")
  sleep 0.1
fi
client_args=(--mode=client --config="$STATE_DIR/client.json" --tcp-stack=native)
[[ -z "$TUN_SSMT" ]] || client_args+=("--tun-ssmt=$TUN_SSMT")
ip netns exec "$NS_C" env \
  -u OPENPPP2_TAP_GSO_MERGE -u OPENPPP2_TAP_GSO_MERGE_DISABLE \
  -u OPENPPP2_DATAPATH_GSO_LEDGER -u OPENPPP2_DATAPATH_GSO_MERGEABILITY \
  "${client_env[@]}" stdbuf -oL -eL "$PPP_BIN" "${client_args[@]}" >"$STATE_DIR/client.log" 2>&1 & pids+=("$!")
CLIENT_PID="${pids[-1]}"

TUN_DEV=""
for _ in $(seq 1 30); do
  TUN_DEV="$(ip -n "$NS_C" -o link show 2>/dev/null | sed -n 's/^[0-9]*: \([^:@]*\): <POINTOPOINT.*/\1/p' | head -1)"
  [[ -n "$TUN_DEV" ]] && break
  sleep 0.5
done
[[ -n "$TUN_DEV" ]] || { echo "no client TUN device" >&2; exit 1; }
ip -n "$NS_C" route replace 192.0.2.0/24 dev "$TUN_DEV"
printf 'label=%s\nconcurrent=%s\ntun_ssmt=%s\ntun_device=%s\ntap_gso_requested=%s\ngso_ledger=%s\ndatapath_telemetry=%s\nperf_domain=%s\nsystem_cpu_stat=%s\nsystem_cpu_set=%s\necho_latency_mode=%s\necho_latency_rate_hz=%s\n' "$LABEL" "$CONCURRENT" "${TUN_SSMT:-off}" "$TUN_DEV" "$TAP_GSO_MODE" "$GSO_LEDGER" "$DATAPATH_TELEMETRY" "$PERF_DOMAIN" "$SYSTEM_CPU_STAT" "${SYSTEM_CPU_SET:-off}" "$ECHO_LATENCY_MODE" "$ECHO_LATENCY_RATE_HZ" >"$STATE_DIR/metadata.txt"
ls -l "/proc/${CLIENT_PID}/fd" >"$STATE_DIR/client-fds.txt" 2>&1 || true
ip -n "$NS_C" -d link show "$TUN_DEV" >"$STATE_DIR/tun-link.txt" 2>&1 || true

apply_client_affinity() {
  lscpu -e=CPU,CORE,SOCKET,NODE,ONLINE >"$STATE_DIR/cpu-topology.txt"
  if [[ "$AFFINITY_MODE" == default ]]; then
    taskset -apc "$CLIENT_PID" >"$STATE_DIR/client-affinity.txt"
    return
  fi
  [[ -n "$AFFINITY_CPUS" ]] || { echo "--affinity-cpus is required for $AFFINITY_MODE" >&2; return 1; }
  local -a cpus=() schedulers=() tids=()
  IFS=, read -r -a cpus <<<"$AFFINITY_CPUS"
  [[ "${#cpus[@]}" -ge 5 ]] || { echo "--affinity-cpus needs five CPUs" >&2; return 1; }
  local tid name vnet_tid=""
  for tid_path in /proc/"$CLIENT_PID"/task/*; do
    tid="${tid_path##*/}"; name="$(<"$tid_path/comm")"
    [[ "$name" == scheduler ]] && schedulers+=("$tid")
    [[ "$name" == vnet ]] && vnet_tid="$tid"
    tids+=("$tid")
  done
  [[ -n "$vnet_tid" ]] || { echo "missing vnet thread" >&2; return 1; }
  [[ "${#schedulers[@]}" -eq $((CONCURRENT - 1)) ]] || { echo "unexpected scheduler count: ${#schedulers[@]}" >&2; return 1; }
  if [[ "$AFFINITY_MODE" == scheduler-collocated ]]; then
    [[ "${#schedulers[@]}" -eq 3 ]] || { echo "scheduler-collocated requires concurrent=4" >&2; return 1; }
  fi
  local non_vnet="${cpus[1]},${cpus[2]},${cpus[3]},${cpus[4]}"
  for tid in "${tids[@]}"; do taskset -pc "$non_vnet" "$tid" >/dev/null; done
  taskset -pc "${cpus[0]}" "$vnet_tid" >/dev/null
  case "$AFFINITY_MODE" in
    spread)
      taskset -pc "${cpus[1]}" "$CLIENT_PID" >/dev/null
      for i in "${!schedulers[@]}"; do taskset -pc "${cpus[$((i + 2))]}" "${schedulers[$i]}" >/dev/null; done ;;
    vnet-isolated) ;;
    scheduler-collocated)
      taskset -pc "${cpus[1]}" "$CLIENT_PID" >/dev/null
      taskset -pc "${cpus[2]}" "${schedulers[0]}" >/dev/null
      taskset -pc "${cpus[2]}" "${schedulers[1]}" >/dev/null
      taskset -pc "${cpus[3]}" "${schedulers[2]}" >/dev/null ;;
  esac
  : >"$STATE_DIR/client-affinity.txt"
  for tid in "${tids[@]}"; do printf 'tid=%s name=%s ' "$tid" "$(<"/proc/$CLIENT_PID/task/$tid/comm")" >>"$STATE_DIR/client-affinity.txt"; taskset -pc "$tid" >>"$STATE_DIR/client-affinity.txt"; done
}
apply_client_affinity
printf 'affinity_mode=%s\naffinity_cpus=%s\n' "$AFFINITY_MODE" "${AFFINITY_CPUS:-default}" >>"$STATE_DIR/metadata.txt"

capture_client_sched_snapshot() {
  local phase="$1" task_dir tid stat schedstat status comm ticks runtime wait slices voluntary involuntary
  task_dir="$STATE_DIR/sched-${phase}"
  mkdir -p "$task_dir"
  : >"$STATE_DIR/sched-${phase}.tsv"
  for tid_path in /proc/"$CLIENT_PID"/task/*; do
    [[ -d "$tid_path" ]] || continue
    tid="${tid_path##*/}"
    stat="$tid_path/stat"; schedstat="$tid_path/schedstat"; status="$tid_path/status"; comm="$tid_path/comm"
    [[ -r "$stat" && -r "$schedstat" && -r "$status" && -r "$comm" ]] || continue
    cp "$stat" "$task_dir/$tid.stat"
    cp "$schedstat" "$task_dir/$tid.schedstat"
    cp "$status" "$task_dir/$tid.status"
    cp "$comm" "$task_dir/$tid.comm"
    ticks="$(awk '{print $14 + $15}' "$stat")"
    read -r runtime wait slices <"$schedstat"
    voluntary="$(awk '/^voluntary_ctxt_switches:/ {print $2}' "$status")"
    involuntary="$(awk '/^nonvoluntary_ctxt_switches:/ {print $2}' "$status")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tid" "$(<"$comm")" "${ticks:-0}" "${runtime:-0}" "${wait:-0}" "${slices:-0}" "${voluntary:-0}:${involuntary:-0}" >>"$STATE_DIR/sched-${phase}.tsv"
  done
}

capture_client_sched_snapshot before
cp "$STATE_DIR/sched-before.tsv" "$STATE_DIR/client-thread-map.tsv"

capture_system_cpu_snapshot() {
  local phase="$1"
  cat /proc/softirqs >"$STATE_DIR/system-softirqs-${phase}.txt"
  cat /proc/stat >"$STATE_DIR/system-stat-${phase}.txt"
  ps -eLo pid,tid,psr,comm,time,pcpu | awk 'NR == 1 || index($4, "ksoftirqd/") == 1' >"$STATE_DIR/ksoftirqd-${phase}.txt"
  measurement_timestamp >"$STATE_DIR/system-cpu-${phase}.timestamp"
}

measurement_timestamp() {
  python3 - <<'PY'
import time
print(f'wall_ns={time.time_ns()} monotonic_ns={time.monotonic_ns()}')
PY
}

measurement_monotonic_ns() {
  python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
}

wait_until_monotonic_ns() {
  python3 - "$1" <<'PY'
import sys, time
remaining = (int(sys.argv[1]) - time.monotonic_ns()) / 1_000_000_000
if remaining > 0:
    time.sleep(remaining)
PY
}

start_echo_latency_probe() {
  [[ "$ECHO_LATENCY_MODE" != off && -z "$ECHO_LATENCY_CLIENT_PID" ]] || return 0
  ip netns exec "$NS_C" python3 "$ROOT/tools/tcp_rtt_probe.py" client \
    --host "$TARGET_IP" --port "$ECHO_LATENCY_PORT" \
    --start-monotonic-ns "$MEASUREMENT_START_MONOTONIC_NS" \
    --deadline-monotonic-ns "$MEASUREMENT_DEADLINE_MONOTONIC_NS" \
    --rate-hz "$ECHO_LATENCY_RATE_HZ" --output "$STATE_DIR/echo-latency.csv" \
    >"$STATE_DIR/echo-latency-client.log" 2>&1 &
  ECHO_LATENCY_CLIENT_PID=$!
}

request_measurement_boundary() {
  local boundary="$1"
  if [[ "$DATAPATH_TELEMETRY" == true ]]; then
    kill -USR1 "$CLIENT_PID"
  fi
  # Idle echo traffic drives the first datapath callback that emits this boundary.
  [[ "$boundary" != measurement_start ]] || start_echo_latency_probe
  [[ "$DATAPATH_TELEMETRY" == true ]] || return 0
  for _ in $(seq 1 100); do
    if grep -q "\"measurement_boundary\":\"${boundary}\"" "$STATE_DIR/datapath-client.jsonl" 2>/dev/null; then
      return 0
    fi
    sleep 0.01
  done
  echo "timed out waiting for ${boundary} telemetry snapshot" >&2
  return 1
}

iperf_status=0
echo_latency_status=0
if [[ "$ECHO_LATENCY_MODE" != idle ]]; then
  ip netns exec "$NS_C" iperf3 -c "$TARGET_IP" -p "$IPERF_PORT" -t "$DURATION" -O 2 --json >"$STATE_DIR/iperf-ul-p1.json" 2>&1 &
  IPERF_CLIENT_PID=$!
  sleep 2
fi
MEASUREMENT_START_MONOTONIC_NS="$(measurement_monotonic_ns)"
MEASUREMENT_DEADLINE_MONOTONIC_NS=$((MEASUREMENT_START_MONOTONIC_NS + DURATION * 1000000000))
printf 'measurement_start_requested %s deadline_monotonic_ns=%s\n' "$(measurement_timestamp)" "$MEASUREMENT_DEADLINE_MONOTONIC_NS" >"$STATE_DIR/measurement-boundaries.txt"

if [[ "$PERF_RECORD" == true ]]; then
  perf record -o "$STATE_DIR/perf.data" -e "$PERF_EVENT" -F "$PERF_FREQUENCY" -g --call-graph fp -p "$CLIENT_PID" \
    >"$STATE_DIR/perf-record.log" 2>&1 &
  PERF_PID=$!
fi
if [[ "$PERF_STAT" == true ]]; then
  perf stat -x, -o "$STATE_DIR/perf-stat.csv" \
    -e task-clock,cycles,instructions,branches,branch-misses,cache-references,cache-misses,context-switches,cpu-migrations \
    -p "$CLIENT_PID" -- sleep "$DURATION" \
    >"$STATE_DIR/perf-stat.log" 2>&1 &
  PERF_STAT_PID=$!
fi
if [[ "$SYSTEM_CPU_STAT" == true ]]; then
  perf stat -x, -o "$STATE_DIR/system-perf-stat.csv" -a -C "$SYSTEM_CPU_SET" \
    -e task-clock,context-switches,cpu-migrations \
    -- sleep "$DURATION" >"$STATE_DIR/system-perf-stat.log" 2>&1 &
  SYSTEM_PERF_STAT_PID=$!
fi
if [[ "$SCHED_TRACE" == true ]]; then
  mapfile -t vnet_tids < <(awk -F '\t' '$2 == "vnet" {print $1}' "$STATE_DIR/client-thread-map.tsv")
  [[ "${#vnet_tids[@]}" -eq 1 ]] || { echo "--sched-trace requires exactly one vnet thread; found ${#vnet_tids[@]}" >&2; exit 1; }
  VNET_TID="${vnet_tids[0]}"
  printf 'vnet_target_tid=%s\n' "$VNET_TID" >>"$STATE_DIR/metadata.txt"
  perf record -o "$STATE_DIR/sched-trace.data" -a \
    -e sched:sched_wakeup -e sched:sched_wakeup_new -e sched:sched_switch \
    >"$STATE_DIR/sched-trace-record.log" 2>&1 &
  SCHED_TRACE_PID=$!
  kill -0 "$SCHED_TRACE_PID" 2>/dev/null || { echo "--sched-trace perf record failed; see $STATE_DIR/sched-trace-record.log" >&2; wait "$SCHED_TRACE_PID" || true; SCHED_TRACE_PID=""; exit 1; }
fi
request_measurement_boundary measurement_start
printf 'measurement_start_observed %s\n' "$(measurement_timestamp)" >>"$STATE_DIR/measurement-boundaries.txt"
if [[ "$SYSTEM_CPU_STAT" == true ]]; then
  capture_system_cpu_snapshot start
fi

wait_until_monotonic_ns "$MEASUREMENT_DEADLINE_MONOTONIC_NS"
printf 'measurement_end_requested %s\n' "$(measurement_timestamp)" >>"$STATE_DIR/measurement-boundaries.txt"
request_measurement_boundary measurement_end
printf 'measurement_end_observed %s\n' "$(measurement_timestamp)" >>"$STATE_DIR/measurement-boundaries.txt"
if [[ "$SYSTEM_CPU_STAT" == true ]]; then
  capture_system_cpu_snapshot end
fi

if [[ "$ECHO_LATENCY_MODE" != idle ]]; then
  if wait "$IPERF_CLIENT_PID"; then
    IPERF_CLIENT_PID=""
  else
    iperf_status=$?
  fi
fi
stop_perf_recording
stop_perf_stat
if [[ "$SYSTEM_CPU_STAT" == true ]]; then
  stop_system_perf_stat
  [[ -s "$STATE_DIR/system-perf-stat.csv" ]] || { echo "--system-cpu-stat produced no perf data" >&2; exit 1; }
fi
if [[ "$ECHO_LATENCY_MODE" != off ]]; then
  if wait "$ECHO_LATENCY_CLIENT_PID"; then
    ECHO_LATENCY_CLIENT_PID=""
  else
    echo_latency_status=$?
  fi
  [[ -s "$STATE_DIR/echo-latency.csv" ]] || { echo "echo latency probe produced no samples" >&2; exit 1; }
fi
if [[ "$SCHED_TRACE" == true ]]; then
  if ! stop_sched_trace; then
    echo "--sched-trace perf record failed; see $STATE_DIR/sched-trace-record.log" >&2
    exit 1
  fi
  [[ -s "$STATE_DIR/sched-trace.data" ]] || { echo "--sched-trace produced no perf data" >&2; exit 1; }
  if ! perf script -i "$STATE_DIR/sched-trace.data" >"$STATE_DIR/sched-trace.script" 2>"$STATE_DIR/sched-trace-script.log"; then
    echo "--sched-trace perf script failed; see $STATE_DIR/sched-trace-script.log" >&2
    exit 1
  fi
fi
if [[ "$PERF_RECORD" == true ]]; then
  [[ -s "$STATE_DIR/perf.data" ]] || { echo "--perf-record produced no perf data" >&2; exit 1; }
  if ! perf script -i "$STATE_DIR/perf.data" -F comm,pid,tid,event,ip,sym,dso,callindent >"$STATE_DIR/perf.script" 2>"$STATE_DIR/perf-script.log"; then
    echo "--perf-record perf script failed; see $STATE_DIR/perf-script.log" >&2
    exit 1
  fi
  perf report --stdio --no-children -g none -i "$STATE_DIR/perf.data" >"$STATE_DIR/perf-self.txt" 2>&1 || true
fi
capture_client_sched_snapshot after
ip -n "$NS_C" -s link show "$TUN_DEV" >"$STATE_DIR/tun-stats.txt" 2>&1 || true
[[ "$iperf_status" -eq 0 ]] || exit "$iperf_status"
[[ "$echo_latency_status" -eq 0 ]] || exit "$echo_latency_status"
python3 - "$STATE_DIR/datapath-client.jsonl" "$STATE_DIR/iperf-ul-p1.json" "$STATE_DIR/sched-before.tsv" "$STATE_DIR/sched-after.tsv" "$CLIENT_PID" "${VNET_TID:-}" "$STATE_DIR/sched-trace.script" "$ECHO_LATENCY_MODE" "$DURATION" "$GSO_LEDGER" <<'PY' >"$STATE_DIR/summary.txt"
import json
import os
import sys
from collections import Counter
raw_records = [json.loads(x) for x in open(sys.argv[1], encoding='utf-8') if x.strip()]
echo_latency_mode = sys.argv[8]
gso_ledger_enabled = sys.argv[10] == 'true'
iperf = json.load(open(sys.argv[2], encoding='utf-8')) if os.path.exists(sys.argv[2]) else None
if raw_records:
    start_indexes = [i for i, record in enumerate(raw_records) if record.get('measurement_boundary') == 'measurement_start']
    end_indexes = [i for i, record in enumerate(raw_records) if record.get('measurement_boundary') == 'measurement_end']
    if len(start_indexes) != 1 or len(end_indexes) != 1 or start_indexes[0] >= end_indexes[0]:
        raise RuntimeError(f'invalid telemetry measurement boundaries: starts={start_indexes}, ends={end_indexes}')
    boundary_start_index, boundary_end_index = start_indexes[0], end_indexes[0]
    boundary_start_record, boundary_end_record = raw_records[boundary_start_index], raw_records[boundary_end_index]
    # The start snapshot drains omit-period counters. Every subsequent interval through
    # the end snapshot belongs to the formal runner-controlled measurement window.
    records = raw_records[boundary_start_index + 1:boundary_end_index + 1]
else:
    boundary_start_index = boundary_end_index = -1
    boundary_start_record = boundary_end_record = {}
    records = []
total = Counter(); stage = Counter(); stage_max = Counter(); latency = Counter(); sizes = Counter(); mta_paths = {}; mta_path_max = Counter(); mta_segments = {}; mta_segment_max = Counter(); mta_producer_slots = {}; mta_producer_slot_max = {}; mta_producer_slot_tids = {}; maximum = 0; inflight_maximum = 0
stage_fields = (
    ('tun', 'read_calls'), ('tun', 'read_bytes'), ('tun', 'write_enqueued'), ('tun', 'write_enqueued_bytes'),
    ('tun', 'write_completed'), ('tun', 'write_bytes'), ('tun', 'write_us_sum'), ('tun', 'write_us_max'),
    ('vnet', 'input_calls'), ('vnet', 'input_bytes'), ('vnet', 'input_us_sum'), ('vnet', 'input_us_max'),
    ('vnet', 'output_calls'), ('vnet', 'output_bytes'), ('vnet', 'output_us_sum'), ('vnet', 'output_us_max'),
    ('vnet', 'mta_packet_posted'), ('vnet', 'mta_packet_dispatched'),
    ('vnet', 'mta_packet_queue_us_sum'), ('vnet', 'mta_packet_queue_us_max'),
    ('frame', 'encode_calls'), ('frame', 'plain_bytes'), ('frame', 'cipher_bytes'), ('frame', 'encode_us_sum'), ('frame', 'encode_us_max'),
    ('frame', 'decode_calls'), ('frame', 'decode_plain_bytes'), ('frame', 'decode_us_sum'), ('frame', 'decode_us_max'),
    ('carrier', 'send_calls'), ('carrier', 'send_bytes'), ('carrier', 'send_us_sum'), ('carrier', 'send_us_max'),
    ('carrier', 'recv_calls'), ('carrier', 'recv_bytes'), ('carrier', 'recv_us_sum'), ('carrier', 'recv_us_max'),
    ('vmux', 'accepted_calls'), ('vmux', 'accepted_bytes'), ('vmux', 'socket_write_completed_calls'), ('vmux', 'socket_write_completed_bytes'),
    ('vmux', 'socket_write_us_sum'), ('vmux', 'socket_write_us_max'),
    ('tcpip_bridge', 'socket_read_calls'), ('tcpip_bridge', 'socket_read_bytes'),
    ('tcpip_bridge', 'transmission_write_accepted_calls'), ('tcpip_bridge', 'transmission_write_accepted_bytes'),
    ('tcpip_bridge', 'transmission_read_calls'), ('tcpip_bridge', 'transmission_read_bytes'),
    ('tcpip_bridge', 'socket_write_completed_calls'), ('tcpip_bridge', 'socket_write_completed_bytes'),
)
crypto_stage = Counter(); crypto_stage_max = Counter()
for record in records:
    tun = record.get('tun', {})
    for key in ('direct_write_attempted','direct_write_completed','direct_write_failed','direct_write_bytes','direct_write_us_sum','direct_write_over_100us',
                'direct_write_entry_inflight_0','direct_write_entry_inflight_1','direct_write_entry_inflight_2','direct_write_entry_inflight_3plus'):
        total[key] += tun.get(key, 0)
    for group, key in stage_fields:
        value = record.get(group, {}).get(key, 0)
        if key.endswith('_us_max'):
            stage_max[f'{group}_{key}'] = max(stage_max[f'{group}_{key}'], value)
        else:
            stage[f'{group}_{key}'] += value
    for name, counters in record.get('frame_stages', {}).items():
        for key in ('calls', 'bytes', 'us_sum'):
            crypto_stage[f'{name}_{key}'] += counters.get(key, 0)
        crypto_stage_max[name] = max(crypto_stage_max[name], counters.get('us_max', 0))
    vnet = record.get('vnet', {})
    for name, path in vnet.get('mta_handoff_paths', {}).items():
        counters = mta_paths.setdefault(name, Counter())
        for key in ('posted', 'dispatched', 'bytes', 'queue_us_sum'):
            counters[key] += path.get(key, 0)
        mta_path_max[name] = max(mta_path_max[name], path.get('queue_us_max', 0))
    for name, segment in vnet.get('mta_handoff_segments', {}).items():
        counters = mta_segments.setdefault(name, Counter())
        counters['calls'] += segment.get('calls', 0)
        counters['us_sum'] += segment.get('us_sum', 0)
        mta_segment_max[name] = max(mta_segment_max[name], segment.get('us_max', 0))
    for slot in vnet.get('mta_handoff_producer_slots', []):
        name = str(slot.get('slot', 'other'))
        producer_tid = slot.get('producer_tid')
        if producer_tid is not None:
            mta_producer_slot_tids[name] = str(producer_tid)
        counters = mta_producer_slots.setdefault(name, Counter())
        counters['packets'] += slot.get('packets', 0)
        counters['bytes'] += slot.get('bytes', 0)
        maxima = mta_producer_slot_max.setdefault(name, Counter())
        for segment_name, segment in slot.get('segments', {}).items():
            counters[f'{segment_name}_us_sum'] += segment.get('us_sum', 0)
            maxima[segment_name] = max(maxima[segment_name], segment.get('us_max', 0))
    maximum = max(maximum, tun.get('direct_write_us_max', 0))
    inflight_maximum = max(inflight_maximum, tun.get('direct_write_inflight_max', 0))
    latency.update({x['label']: x['count'] for x in tun.get('direct_write_latency_buckets', [])})
    sizes.update({x['label']: x['count'] for x in tun.get('direct_write_size_buckets', [])})
seconds = iperf['end']['sum_sent']['seconds'] if iperf else float(sys.argv[9])
print(f'echo_latency_mode={echo_latency_mode}')
if iperf:
    bps = iperf['end']['sum_sent']['bits_per_second']
    print(f'ul_goodput_bps={bps:.0f}')
    print(f'ul_retransmits={iperf["end"]["sum_sent"].get("retransmits", 0)}')
else:
    print('ul_goodput_bps=not_applicable_idle_echo')
    print('ul_retransmits=not_applicable_idle_echo')
print(f'telemetry_measurement_boundary_start_index={boundary_start_index}')
print(f'telemetry_measurement_boundary_end_index={boundary_end_index}')
print(f'telemetry_measurement_window_records={len(records)}')

def normalized_key(path):
    return ''.join(character if character.isalnum() else '_' for character in path).strip('_')

def numeric_leaves(value, prefix=''):
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f'{prefix}_{key}' if prefix else str(key)
            yield from numeric_leaves(child, child_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from numeric_leaves(child, f'{prefix}_{index}')
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield normalized_key(prefix), value

def report_boundary_ledger(name):
    start = boundary_start_record.get(name)
    end = boundary_end_record.get(name)
    if not isinstance(end, dict):
        print(f'{name}_available=false')
        return
    print(f'{name}_available=true')
    if isinstance(end.get('framing_domain'), str):
        print(f'{name}_framing_domain={end["framing_domain"]}')
    start_values = dict(numeric_leaves(start)) if isinstance(start, dict) else {}
    end_values = dict(numeric_leaves(end))
    for key in sorted(end_values):
        delta = end_values[key] - start_values.get(key, 0)
        print(f'{name}_{key}_delta={delta}')
        print(f'{name}_{key}_per_s={delta / seconds:.2f}')

if gso_ledger_enabled:
    report_boundary_ledger('tun_gso_ledger')
    report_boundary_ledger('tun_gso_mergeability')
    print('gso_ledger_global_closure=not_applicable')
    print('gso_ledger_closure_note=stage_ledgers_use_distinct_framing_domains_no_global_closure')
print(f'direct_write_calls_per_s={total["direct_write_attempted"]/seconds:.2f}')
print(f'direct_write_bytes_per_s={total["direct_write_bytes"]/seconds:.2f}')
print(f'direct_write_bytes_per_call={total["direct_write_bytes"]/max(total["direct_write_completed"], 1):.2f}')
print(f'direct_write_avg_wall_us={total["direct_write_us_sum"]/max(total["direct_write_attempted"], 1):.3f}')
print(f'direct_write_wall_seconds_per_second={total["direct_write_us_sum"] / 1_000_000 / seconds:.4f}')
print(f'direct_write_us_max={maximum}')
print(f'direct_write_over_100us_per_s={total["direct_write_over_100us"]/seconds:.3f}')
print(f'direct_write_inflight_max={inflight_maximum}')
print('direct_write_entry_inflight=' + json.dumps({
    'already_inflight_0': total['direct_write_entry_inflight_0'],
    'already_inflight_1': total['direct_write_entry_inflight_1'],
    'already_inflight_2': total['direct_write_entry_inflight_2'],
    'already_inflight_3plus': total['direct_write_entry_inflight_3plus'],
}, sort_keys=True))
for group, key in stage_fields:
    field = f'{group}_{key}'
    if key.endswith('_us_max'):
        print(f'stage_max_{field}={stage_max[field]:.0f}')
    else:
        print(f'stage_rate_{field}_per_s={stage[field]/seconds:.2f}')
for key in sorted(crypto_stage):
    print(f'stage_rate_crypto_{key}_per_s={crypto_stage[key]/seconds:.2f}')
for name in sorted(crypto_stage_max):
    print(f'stage_max_crypto_{name}_us={crypto_stage_max[name]:.0f}')
mta_queue_avg_us = stage["vnet_mta_packet_queue_us_sum"] / max(stage["vnet_mta_packet_dispatched"], 1)
mta_posted_per_s = stage["vnet_mta_packet_posted"] / seconds
print(f'vnet_mta_packet_queue_avg_us={mta_queue_avg_us:.3f}')
print(f'estimated_mta_handoff_queue_depth={mta_posted_per_s * mta_queue_avg_us / 1_000_000:.3f}')
print(f'vnet_mta_packet_queue_us_max={stage_max["vnet_mta_packet_queue_us_max"]:.0f}')
for name in sorted(mta_paths):
    counters = mta_paths[name]
    dispatched = max(counters['dispatched'], 1)
    posted_per_s = counters['posted'] / seconds
    queue_avg_us = counters['queue_us_sum'] / dispatched
    print(f'mta_handoff_{name}_posted_per_s={posted_per_s:.2f}')
    print(f'mta_handoff_{name}_dispatched_per_s={counters["dispatched"]/seconds:.2f}')
    print(f'mta_handoff_{name}_bytes_per_s={counters["bytes"]/seconds:.2f}')
    print(f'mta_handoff_{name}_queue_avg_us={queue_avg_us:.3f}')
    print(f'mta_handoff_{name}_queue_us_max={mta_path_max[name]:.0f}')
    print(f'mta_handoff_{name}_estimated_queue_depth={posted_per_s * queue_avg_us / 1_000_000:.3f}')
for name in sorted(mta_segments):
    counters = mta_segments[name]
    calls = max(counters['calls'], 1)
    print(f'mta_handoff_segment_{name}_calls_per_s={counters["calls"]/seconds:.2f}')
    print(f'mta_handoff_segment_{name}_avg_us={counters["us_sum"]/calls:.3f}')
    print(f'mta_handoff_segment_{name}_us_max={mta_segment_max[name]:.0f}')
for name in sorted(mta_producer_slots, key=lambda value: (value == 'other', value)):
    counters = mta_producer_slots[name]
    packets = max(counters['packets'], 1)
    print(f'mta_handoff_producer_slot_{name}_packets_per_s={counters["packets"]/seconds:.2f}')
    print(f'mta_handoff_producer_slot_{name}_bytes_per_s={counters["bytes"]/seconds:.2f}')
    for segment_name in ('prepare', 'post_call', 'executor_queue', 'handler_service'):
        print(f'mta_handoff_producer_slot_{name}_{segment_name}_avg_us={counters[f"{segment_name}_us_sum"]/packets:.3f}')
print('direct_write_latency_buckets=' + json.dumps(latency, sort_keys=True))
print('direct_write_size_buckets=' + json.dumps(sizes, sort_keys=True))
def sched_snapshot(path):
    snapshots = {}
    with open(path, encoding='utf-8') as source:
        for line in source:
            fields = line.rstrip('\n').split('\t')
            if len(fields) != 7:
                continue
            voluntary, involuntary = fields[6].split(':', 1)
            snapshots[fields[0]] = {
                'name': fields[1], 'ticks': int(fields[2]), 'runtime': int(fields[3]),
                'wait': int(fields[4]), 'slices': int(fields[5]),
                'voluntary': int(voluntary), 'involuntary': int(involuntary),
            }
    return snapshots
before, after = sched_snapshot(sys.argv[3]), sched_snapshot(sys.argv[4])
producer_packets = Counter()
for slot, counters in mta_producer_slots.items():
    tid = mta_producer_slot_tids.get(slot)
    if tid is not None:
        producer_packets[tid] += counters['packets']
clock_ticks = __import__('os').sysconf(__import__('os').sysconf_names['SC_CLK_TCK'])
vnet_tid = sys.argv[6]
print(f'client_scheduler_surviving_threads={len(after)}')
for tid, current in sorted(after.items(), key=lambda item: int(item[0])):
    previous = before.get(tid)
    if previous is None:
        continue
    delta = {key: max(0, current[key] - previous[key]) for key in ('ticks', 'runtime', 'wait', 'slices', 'voluntary', 'involuntary')}
    role = 'vnet_target' if tid == vnet_tid else current['name']
    workload_packets = stage['vnet_mta_packet_dispatched']
    producer_packet_count = producer_packets.get(tid, 0)
    packet_divisor = max(workload_packets, 1)
    print('client_scheduler_thread'
          f' tid={tid} name={current["name"]} role={role}'
          f' cpu_ticks={delta["ticks"]} core_seconds={delta["ticks"] / clock_ticks:.6f}'
          f' runtime_ns={delta["runtime"]} runqueue_wait_ns={delta["wait"]} timeslices={delta["slices"]}'
          f' voluntary_switches={delta["voluntary"]} involuntary_switches={delta["involuntary"]}'
          f' workload_packets={workload_packets} producer_packets={producer_packet_count}'
          f' runqueue_wait_us_per_workload_packet={delta["wait"] / 1000 / packet_divisor:.6f}'
          f' voluntary_switches_per_workload_packet={delta["voluntary"] / packet_divisor:.6f}'
          f' involuntary_switches_per_workload_packet={delta["involuntary"] / packet_divisor:.6f}')
for slot, counters in sorted(mta_producer_slots.items(), key=lambda item: (item[0] == 'other', item[0])):
    tid = mta_producer_slot_tids.get(slot)
    if tid is None:
        print(f'mta_handoff_producer_join slot={slot} tid=unavailable packets={counters["packets"]}')
    elif tid in after:
        print(f'mta_handoff_producer_join slot={slot} tid={tid} name={after[tid]["name"]} packets={counters["packets"]}')
    else:
        print(f'mta_handoff_producer_join slot={slot} tid={tid} status=not-surviving packets={counters["packets"]}')
if vnet_tid:
    print(f'vnet_target_tid={vnet_tid} status={"surviving" if vnet_tid in after else "not-surviving"}')
trace_path = sys.argv[7]
if vnet_tid and __import__('os').path.exists(trace_path):
    import re
    events = []
    delays_us = []
    overwritten_wakeups = 0
    wake_pattern = re.compile(r'\s(\d+\.\d+):\s+sched:sched_wakeup(?:_new)?:.*\bpid=(\d+)\b')
    switch_pattern = re.compile(r'\s(\d+\.\d+):\s+sched:sched_switch:.*\bnext_pid=(\d+)\b')
    with open(trace_path, encoding='utf-8', errors='replace') as source:
        for line in source:
            wake = wake_pattern.search(line)
            if wake and wake.group(2) == vnet_tid:
                events.append((float(wake.group(1)), 'wakeup'))
                continue
            switch = switch_pattern.search(line)
            if switch and switch.group(2) == vnet_tid:
                events.append((float(switch.group(1)), 'scheduled'))
    # perf emits per-CPU buffers; script order is not a global time order.
    # A task may be woken repeatedly before it runs. Only the latest wakeup
    # measures its final runnable-to-running interval.
    wakeup_time = None
    for timestamp, event in sorted(events):
        if event == 'wakeup':
            if wakeup_time is not None:
                overwritten_wakeups += 1
            wakeup_time = timestamp
        elif wakeup_time is not None:
            delays_us.append((timestamp - wakeup_time) * 1_000_000)
            wakeup_time = None
    def percentile(values, percentile):
        if not values:
            return 0.0
        values = sorted(values)
        index = (len(values) - 1) * percentile / 100
        lower, upper = int(index), min(int(index) + 1, len(values) - 1)
        return values[lower] + (values[upper] - values[lower]) * (index - lower)
    print(f'sched_trace_vnet_wakeup_to_schedule_calls={len(delays_us)}')
    print(f'sched_trace_vnet_wakeup_to_schedule_p50_us={percentile(delays_us, 50):.3f}')
    print(f'sched_trace_vnet_wakeup_to_schedule_p95_us={percentile(delays_us, 95):.3f}')
    print(f'sched_trace_vnet_wakeup_to_schedule_p99_us={percentile(delays_us, 99):.3f}')
    print(f'sched_trace_vnet_wakeup_to_schedule_max_us={max(delays_us, default=0.0):.3f}')
    print(f'sched_trace_vnet_wakeup_to_schedule_overwritten={overwritten_wakeups}')
    print(f'sched_trace_vnet_wakeup_to_schedule_unmatched={int(wakeup_time is not None)}')
PY

if [[ "$SYSTEM_CPU_STAT" == true ]]; then
  python3 - "$STATE_DIR/system-softirqs-start.txt" "$STATE_DIR/system-softirqs-end.txt" "$STATE_DIR/system-perf-stat.csv" "$SYSTEM_CPU_SET" <<'PY' >"$STATE_DIR/system-cpu-summary.txt"
import csv
import sys

start_path, end_path, perf_path, selected_raw = sys.argv[1:]
selected = {int(cpu) for cpu in selected_raw.split(',')}

for row in csv.reader(open(perf_path, encoding='utf-8')):
    if len(row) < 3 or row[2] not in {'task-clock', 'context-switches', 'cpu-migrations'}:
        continue
    try:
        value = float(row[0])
    except ValueError:
        continue
    key = row[2].replace('-', '_')
    unit = row[1] or 'count'
    print(f'system_perf_{key}={value:.3f} {unit}')

def parse_softirqs(path):
    lines = open(path, encoding='utf-8').read().splitlines()
    cpus = [int(value.removeprefix('CPU')) for value in lines[0].split()]
    counters = {}
    for line in lines[1:]:
        name, separator, values = line.partition(':')
        if not separator:
            continue
        counters[name.strip()] = [int(value) for value in values.split()]
    return cpus, counters

cpus, before = parse_softirqs(start_path)
end_cpus, after = parse_softirqs(end_path)
if cpus != end_cpus:
    raise RuntimeError(f'softirq CPU layout changed: {cpus} != {end_cpus}')
print('system_cpu_scope=' + ','.join(map(str, sorted(selected))))
for name in ('NET_RX', 'NET_TX'):
    first, second = before.get(name, []), after.get(name, [])
    if len(first) != len(cpus) or len(second) != len(cpus):
        raise RuntimeError(f'missing {name} counters')
    deltas = {cpu: second[index] - first[index] for index, cpu in enumerate(cpus)}
    selected_total = sum(delta for cpu, delta in deltas.items() if cpu in selected)
    other_total = sum(delta for cpu, delta in deltas.items() if cpu not in selected)
    print(f'softirq_{name}_selected_delta={selected_total}')
    print(f'softirq_{name}_other_cpu_delta={other_total}')
    for cpu, delta in sorted(deltas.items()):
        if delta:
            scope = 'selected' if cpu in selected else 'other'
            print(f'softirq_{name}_cpu{cpu}_{scope}_delta={delta}')
PY
fi

if [[ "$ECHO_LATENCY_MODE" != off ]]; then
  python3 - "$STATE_DIR/echo-latency.csv" "$ECHO_LATENCY_MODE" <<'PY' >"$STATE_DIR/echo-latency-summary.txt"
import csv
import sys

records = list(csv.DictReader(open(sys.argv[1], encoding='utf-8')))
mode = sys.argv[2]
successes = [int(record['echo_latency_ns']) for record in records if record['status'] == 'ok']
failures = [record for record in records if record['status'] != 'ok']
def percentile(values, value):
    if not values:
        return 0.0
    values = sorted(values)
    index = (len(values) - 1) * value / 100
    low, high = int(index), min(int(index) + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (index - low)
print(f'in_band_echo_latency_mode={mode}')
print(f'in_band_echo_latency_samples={len(records)}')
print(f'in_band_echo_latency_successes={len(successes)}')
print(f'in_band_echo_latency_failures={len(failures)}')
for percentile_value in (50, 95, 99):
    print(f'in_band_echo_latency_p{percentile_value}_us={percentile(successes, percentile_value) / 1000:.3f}')
print(f'in_band_echo_latency_max_us={max(successes, default=0) / 1000:.3f}')
PY
fi

cat "$STATE_DIR/summary.txt"
[[ "$SYSTEM_CPU_STAT" == false ]] || cat "$STATE_DIR/system-cpu-summary.txt"
[[ "$ECHO_LATENCY_MODE" == off ]] || cat "$STATE_DIR/echo-latency-summary.txt"
