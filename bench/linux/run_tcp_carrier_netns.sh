#!/usr/bin/env bash
# Run bm_tcp_carrier across two private network namespaces. No host namespace
# addresses, routes, or traffic controls are created.
set -euo pipefail

usage() {
    printf 'usage: %s --output DIR [--binary PATH] [--duration N] [--warmup N]\n' "$0" >&2
}

output=''
binary="$(cd "$(dirname "$0")/../.." && pwd)/build-bench/bm_tcp_carrier"
duration=1
warmup=0
while (($#)); do
    case "$1" in
        --output) output=${2:?missing --output value}; shift 2 ;;
        --output=*) output=${1#*=}; shift ;;
        --binary) binary=${2:?missing --binary value}; shift 2 ;;
        --binary=*) binary=${1#*=}; shift ;;
        --duration) duration=${2:?missing --duration value}; shift 2 ;;
        --duration=*) duration=${1#*=}; shift ;;
        --warmup) warmup=${2:?missing --warmup value}; shift 2 ;;
        --warmup=*) warmup=${1#*=}; shift ;;
        --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'run_tcp_carrier_netns.sh requires root' >&2
    exit 1
fi
if [[ -z ${output} ]]; then
    usage
    exit 2
fi
if [[ ! -x ${binary} ]]; then
    printf 'benchmark binary is not executable: %s\n' "$binary" >&2
    exit 2
fi
if ! command -v ip >/dev/null; then
    printf '%s\n' 'iproute2 (ip) is required' >&2
    exit 2
fi

mkdir -p "$output"
suffix=$(( $$ % 100000 ))
server_ns="bmtcps${suffix}"
client_ns="bmtcpc${suffix}"
server_veth="bmtcss${suffix}"
client_veth="bmtcsc${suffix}"
server_pid=''
cleanup() {
    local status=$?
    if [[ -n ${server_pid} ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    ip netns del "$server_ns" 2>/dev/null || true
    ip netns del "$client_ns" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT INT TERM

ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "$server_veth" type veth peer name "$client_veth"
ip link set "$server_veth" netns "$server_ns"
ip link set "$client_veth" netns "$client_ns"
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" addr add 198.18.240.1/30 dev "$server_veth"
ip -n "$client_ns" addr add 198.18.240.2/30 dev "$client_veth"
ip -n "$server_ns" link set "$server_veth" up
ip -n "$client_ns" link set "$client_veth" up

ip netns exec "$server_ns" "$binary" --listen 198.18.240.1 --port 51520 >"$output/server.json" 2>"$output/server.log" &
server_pid=$!
# Do not probe the TCP port: the server deliberately accepts one connection only.
sleep 0.1
if ! kill -0 "$server_pid" 2>/dev/null; then
    wait "$server_pid"
fi

ip netns exec "$client_ns" "$binary" --connect 198.18.240.1 --port 51520 --duration "$duration" --warmup "$warmup" >"$output/client.json" 2>"$output/client.log"
wait "$server_pid"
server_pid=''
printf 'saved TCP carrier JSON and logs in %s\n' "$output"
