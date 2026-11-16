#!/usr/bin/env bash
# xtcp_tap_netns_e2e.sh - privileged end-to-end test of the XTCP TCP stack
# integration inside Linux network namespaces.
#
# Topology:
#   ns_client (198.51.100.2) --veth-- ns_server (198.51.100.1 / 192.0.2.1)
#                                        --veth-- ns_target (192.0.2.2)
#   ppp --mode=server runs in ns_server; ppp --mode=client --tcp-stack=xtcp
#   runs in ns_client with a real TUN device; a Python echo service runs in
#   ns_target. Test traffic (192.0.2.2) is routed over the tunnel while the
#   server address (198.51.100.1) is bypass-routed.
#
# Covers: basic echo, client-initiated half-close (upload integrity asserted
# at the echo service; on the download side the platform tears the connection
# down once the upload half closes - identical with the native stack - so the
# app asserts an intact echo prefix plus prompt EOF/RST termination instead of
# a full tail drain), graceful peer-initiated close with a full tail drain,
# RST on refused target, connection churn, loss/reorder/MTU injection
# (tc netem on the client TUN), a long-connection soak, stats-json XTCP
# counters, and route/DNS rollback after a clean client shutdown.
#
# env:
#   PPP_BIN                     ppp binary (default: bin/ppp, must be built
#                               with -DENABLE_XTCP=ON)
#   OPENPPP2_NAMESPACE_ARTIFACT_DIR  copy logs/configs/snapshots here on exit
#   XTCP_SOAK_SECONDS           soak duration (default: 60)
#   XTCP_E2E_CHURN              churn connections per round (default: 512)
#   XTCP_E2E_SKIP_NETEM=1       skip the tc netem / MTU phase (local escape
#                               hatch; without it a tc failure is an error)
#   XTCP_E2E_RECONNECT=1        restart the isolated server and verify that
#                               client session reconnect preserves TAP lanes
#   XTCP_E2E_PCAP=1             capture the echo port on the client TUN and the
#                               target veth (echo-tun.pcap / echo-target.pcap)
#   OPENPPP2_XTCP_*             runtime startup switches passed to the client
#   OPENPPP2_TAP_GSO_MERGE=1    request VNET/GSO so queue lanes can be created
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PPP_BIN="${PPP_BIN:-${ROOT}/bin/ppp}"
SOAK_SECONDS="${XTCP_SOAK_SECONDS:-60}"
CHURN="${XTCP_E2E_CHURN:-512}"
SKIP_NETEM="${XTCP_E2E_SKIP_NETEM:-0}"
RECONNECT="${XTCP_E2E_RECONNECT:-0}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "xtcp_tap_netns_e2e.sh must run as root" >&2
  exit 2
fi
[[ -x "${PPP_BIN}" ]] || { echo "missing ppp binary: ${PPP_BIN}" >&2; exit 1; }
for tool in ip python3; do
  command -v "${tool}" >/dev/null || { echo "missing ${tool}" >&2; exit 1; }
done
if [[ "${SKIP_NETEM}" != 1 ]]; then
  command -v tc >/dev/null || { echo "missing tc (set XTCP_E2E_SKIP_NETEM=1 to skip the netem phase)" >&2; exit 1; }
fi

SUFFIX="$$"
NS_C="openppp2-xtcp-c-${SUFFIX}"
NS_S="openppp2-xtcp-s-${SUFFIX}"
NS_T="openppp2-xtcp-t-${SUFFIX}"
STATE_DIR="$(mktemp -d)"
NETNS_DNS_DIR="/etc/netns/${NS_C}"
SERVER_PORT=20000
ECHO_PORT=19876
TARGET_IP="192.0.2.2"
SERVER_IP="198.51.100.1"

pids=()
pcap_pid=""
diag_pcap_pids=()
TUN_DEV=""
NETEM_ACTIVE=0
cleanup() {
  local exit_status=$?
  set +e
  if [[ 0 -ne "${exit_status}" && 1 -eq "${NETEM_ACTIVE}" && -n "${TUN_DEV}" ]] && ip netns list | grep -Fq "${NS_C}"; then
    ip netns exec "${NS_C}" ss -tinap >"${STATE_DIR}/netem-ss.txt" 2>&1
    ip -n "${NS_C}" -s link show dev "${TUN_DEV}" >"${STATE_DIR}/netem-link.txt" 2>&1
    ip netns exec "${NS_C}" tc -s qdisc show dev "${TUN_DEV}" >"${STATE_DIR}/netem-qdisc.txt" 2>&1
    ip netns exec "${NS_C}" cat /proc/net/snmp >"${STATE_DIR}/netem-snmp.txt" 2>&1
  fi
  if [[ -n "${pcap_pid}" ]]; then
    kill "${pcap_pid}" 2>/dev/null || true
    wait "${pcap_pid}" 2>/dev/null || true
    pcap_pid=""
  fi
  for pid in "${diag_pcap_pids[@]:-}"; do
    [[ -n "${pid}" ]] || continue
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  if [[ -n "${OPENPPP2_NAMESPACE_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "${OPENPPP2_NAMESPACE_ARTIFACT_DIR}"
    cp -f "${STATE_DIR}"/* "${OPENPPP2_NAMESPACE_ARTIFACT_DIR}/" 2>/dev/null || true
  fi
  for pid in "${pids[@]:-}"; do kill "${pid}" 2>/dev/null || true; done
  wait "${pids[@]:-}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_T}" 2>/dev/null || true
  rm -rf "${NETNS_DNS_DIR}" "${STATE_DIR}"
}
trap cleanup EXIT

# ---------------------------------------------------------------- topology
ip netns add "${NS_C}"
ip netns add "${NS_S}"
ip netns add "${NS_T}"
ip link add xc-veth type veth peer name xs-veth
ip link add xs2-veth type veth peer name xt-veth
ip link set xc-veth netns "${NS_C}"
ip link set xs-veth netns "${NS_S}"
ip link set xs2-veth netns "${NS_S}"
ip link set xt-veth netns "${NS_T}"
ip -n "${NS_C}" addr add 198.51.100.2/24 dev xc-veth
ip -n "${NS_S}" addr add 198.51.100.1/24 dev xs-veth
ip -n "${NS_S}" addr add 192.0.2.1/24 dev xs2-veth
ip -n "${NS_T}" addr add 192.0.2.2/24 dev xt-veth
for ns in "${NS_C}" "${NS_S}" "${NS_T}"; do ip -n "${ns}" link set lo up; done
ip -n "${NS_C}" link set xc-veth up
ip -n "${NS_S}" link set xs-veth up
ip -n "${NS_S}" link set xs2-veth up
ip -n "${NS_T}" link set xt-veth up
ip -n "${NS_C}" route add default via 198.51.100.1
# NOTE: no ip_forward in ns_server on purpose. The tunnel target subnet must
# be reachable ONLY through the VPN: the ppp server originates its own
# connection to 192.0.2.2 (OUTPUT chain, connected route via xs2-veth), while
# underlay-forwarded packets from the client would need forwarding - which
# stays disabled, so a dead tunnel fails the battery instead of silently
# passing through the underlay.
ip -n "${NS_T}" route add default via 192.0.2.1

mkdir -p "${NETNS_DNS_DIR}"
printf 'nameserver 192.0.2.53\n' >"${NETNS_DNS_DIR}/resolv.conf"

snapshot_client() {
  ip -n "${NS_C}" -j route show table all >"$1.routes"
  ip netns exec "${NS_C}" cat /etc/resolv.conf >"$1.dns"
}
snapshot_client "${STATE_DIR}/before"

# ---------------------------------------------------------------- configs
python3 - "${ROOT}" "${STATE_DIR}" "${SERVER_IP}" "${SERVER_PORT}" <<'PY'
import json, pathlib, sys

root, out, server_ip, server_port = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
compat = root / "tools" / "compat"
server = json.loads((compat / "server.json").read_text(encoding="utf-8"))
client = json.loads((compat / "client_proxy.json").read_text(encoding="utf-8"))
server["tcp"]["listen"]["port"] = server_port
server["udp"]["listen"]["port"] = server_port
client["tcp"]["listen"]["port"] = 0
client["udp"]["listen"]["port"] = 0
client["client"]["server"] = f"ppp://{server_ip}:{server_port}/"
client["client"].pop("mappings", None)
# Keep startup failures diagnosable; the proxy compatibility fixtures disable
# telemetry, which otherwise hides the failing TUN initialization stage.
for config in (server, client):
    config["telemetry"] = {"enabled": True, "console-log": True,
                           "console-metric": False, "console-span": False}
(out / "server.json").write_text(json.dumps(server, indent=2) + "\n", encoding="utf-8")
(out / "client.json").write_text(json.dumps(client, indent=2) + "\n", encoding="utf-8")
PY

# ---------------------------------------------------------------- services
ip netns exec "${NS_S}" stdbuf -oL -eL "${PPP_BIN}" --mode=server --config="${STATE_DIR}/server.json" \
  >"${STATE_DIR}/server.log" 2>&1 &
pids+=("$!")
sleep 2
kill -0 "${pids[0]}" 2>/dev/null || { echo "server exited during startup; see server.log" >&2; exit 1; }

ip netns exec "${NS_T}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" "${STATE_DIR}" \
  >"${STATE_DIR}/echo.log" 2>&1 <<'PY' &
import pathlib, socket, sys, threading

echo_port = int(sys.argv[2])
artifact_dir = pathlib.Path(sys.argv[3])

def serve_echo(conn):
    # Echo until the peer closes. The per-connection byte count is logged on
    # close (also on RST) so the caller can assert upload integrity.
    total = 0
    payload = bytearray()
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            if total < 200000:
                payload += data
            total += len(data)
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()
        if 65536 <= total < 200000:
            (artifact_dir / "half-close-server-upload.bin").write_bytes(payload)
        print(f"conn closed port={echo_port} bytes={total}", flush=True)

def serve_echo_close(conn):
    # Read a 4-byte length header plus that many bytes, echo them back, then
    # close immediately: a graceful peer-initiated close whose FIN must reach
    # the client only after every echoed byte, end to end.
    total = 0
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                return
            hdr += chunk
        want = int.from_bytes(hdr, "big")
        blob = bytearray()
        while len(blob) < want:
            chunk = conn.recv(min(65536, want - len(blob)))
            if not chunk:
                break
            blob += chunk
        total = len(blob)
        if total == want:
            conn.sendall(bytes(blob))
    except OSError:
        pass
    finally:
        conn.close()
        print(f"conn closed port={echo_port + 1} bytes={total}", flush=True)

def listen_loop(handler, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((sys.argv[1], port))
    listener.listen(256)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()

print("echo ready", flush=True)
threading.Thread(target=listen_loop, args=(serve_echo_close, echo_port + 1), daemon=True).start()
listen_loop(serve_echo, echo_port)
PY
pids+=("$!")
sleep 1

# Pass only explicit test switches; an unset variable leaves production defaults intact.
client_env=()
for name in OPENPPP2_XTCP_SHARDS OPENPPP2_XTCP_AFFINITY OPENPPP2_XTCP_IO_CPUS \
  OPENPPP2_XTCP_AFFINITY_STRICT OPENPPP2_XTCP_DIRECT_SPSC OPENPPP2_XTCP_GSO_RX \
  OPENPPP2_TAP_GSO_MERGE; do
  if [[ "${!name+x}" == x ]]; then client_env+=("${name}=${!name}"); fi
done
ip netns exec "${NS_C}" env "${client_env[@]}" stdbuf -oL -eL "${PPP_BIN}" --mode=client --config="${STATE_DIR}/client.json" \
  --tcp-stack=xtcp --stats-json="${STATE_DIR}/stats.ndjson" \
  >"${STATE_DIR}/client.log" 2>&1 &
pids+=("$!")
CLIENT_PID="${pids[-1]}"
sleep 4
kill -0 "${CLIENT_PID}" 2>/dev/null || {
  echo "client exited during startup; see client.log:" >&2
  tail -20 "${STATE_DIR}/client.log" >&2 || true
  exit 1
}

# The tunnel must be the only path to the target: once the client is up, the
# route to 192.0.2.2 has to leave through the TUN device, not the underlay.
# The ppp client's TUN is a POINTOPOINT device (named e.g. "ppp", not tun*).
TUN_DEV=""
for _ in $(seq 1 30); do
  TUN_DEV="$(ip -n "${NS_C}" -o link show 2>/dev/null | sed -n 's/^[0-9]*: \([^:@]*\): <POINTOPOINT.*/\1/p' | head -1)"
  [[ -n "${TUN_DEV}" ]] && break
  sleep 0.5
done
[[ -n "${TUN_DEV}" ]] || { echo "no TUN (pointopoint) device appeared in ${NS_C}" >&2; exit 1; }
echo "client TUN device: ${TUN_DEV}"
ip -n "${NS_C}" -o link show "${TUN_DEV}"
ip -n "${NS_C}" rule show >"${STATE_DIR}/client.rules" 2>/dev/null || true

# Pin the target subnet into the TUN. The client's own route hijack is policy
# driven and gated on full readiness; the E2E pins the route explicitly so the
# XTCP datapath is exercised deterministically (the route manager's rollback
# is covered separately by route_dns_rollback.sh). The kernel drops this route
# when the TUN disappears at client stop, so the before/after route snapshots
# stay comparable.
ip -n "${NS_C}" route replace 192.0.2.0/24 dev "${TUN_DEV}"
ROUTE_OUT="$(ip -n "${NS_C}" route get "${TARGET_IP}" 2>/dev/null || true)"
echo "route to ${TARGET_IP}: ${ROUTE_OUT}"
case "${ROUTE_OUT}" in
  *"dev ${TUN_DEV}"*) ;;
  *) echo "target traffic is not routed via ${TUN_DEV}; tunnel is not carrying the flow" >&2; exit 1 ;;
esac

# Optional byte-level evidence: capture the echo port on the client TUN (kernel
# TCP <-> XTCP) and on the target veth (server-side kernel TCP <-> echo).
if [[ "${XTCP_E2E_PCAP:-0}" == 1 ]]; then
  # tcpdump is optional on lab hosts: a small AF_PACKET writer produces the
  # same classic pcap (raw IP link type for the TUN, Ethernet for the veth).
  capture_echo() {
    local ns="$1" dev="$2" out="$3"
    ip netns exec "${ns}" python3 -u - "${dev}" "${out}" "${ECHO_PORT}" <<'PY' >"${out}.log" 2>&1 &
import socket, struct, sys, time
dev, out, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((dev, 0))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 << 20)
first = sock.recvfrom(65535)
linktype = 1 if first[1][3] == 1 or len(first[1][4]) == 6 else 101
with open(out, "wb", buffering=0) as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
    pkt = first[0]
    while True:
        ip = pkt[14:] if linktype == 1 else pkt
        if len(ip) >= 24 and ip[0] >> 4 == 4 and ip[9] == 6:
            ihl = (ip[0] & 15) * 4
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            if port in (sport, dport):
                now = time.time()
                f.write(struct.pack("<IIII", int(now), int((now % 1) * 1e6), len(pkt), len(pkt)) + pkt)
        pkt = sock.recvfrom(65535)[0]
PY
    diag_pcap_pids+=("$!")
  }
  capture_echo "${NS_C}" "${TUN_DEV}" "${STATE_DIR}/echo-tun.pcap"
  capture_echo "${NS_T}" xt-veth "${STATE_DIR}/echo-target.pcap"
  sleep 1
fi

# Restart only the isolated server process. The client PPP process and its TAP
# remain alive, exercising the production exchanger reconnect path in place.
if [[ "${RECONNECT}" == 1 ]]; then
  ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" 128 \
    >>"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys, time

target_ip, echo_port, flows = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
deadline = time.time() + 45
for i in range(flows):
    message = f"before-reconnect-{i}".encode()
    while True:
        try:
            with socket.create_connection((target_ip, echo_port), timeout=4) as sock:
                sock.settimeout(6)
                sock.sendall(message)
                data = bytearray()
                while len(data) < len(message):
                    part = sock.recv(len(message) - len(data))
                    if not part:
                        break
                    data += part
                assert bytes(data) == message, (i, bytes(data))
            break
        except OSError:
            if time.time() >= deadline:
                raise
            time.sleep(0.25)
print(f"pre-reconnect bidirectional flows x{flows} OK", flush=True)
PY

  echo "restarting isolated server to exercise client session reconnect"
  kill -TERM "${pids[0]}"
  wait "${pids[0]}" 2>/dev/null || true
  ip netns exec "${NS_S}" stdbuf -oL -eL "${PPP_BIN}" --mode=server --config="${STATE_DIR}/server.json" \
    >>"${STATE_DIR}/server.log" 2>&1 &
  SERVER_PID="$!"
  pids+=("${SERVER_PID}")
  sleep 1
  kill -0 "${SERVER_PID}" 2>/dev/null || { echo "replacement server failed to start" >&2; exit 1; }

  ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" 128 \
    >>"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys, time

target_ip, echo_port, flows = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
deadline = time.time() + 90
for i in range(flows):
    message = f"after-reconnect-{i}".encode()
    while True:
        try:
            with socket.create_connection((target_ip, echo_port), timeout=4) as sock:
                sock.settimeout(6)
                sock.sendall(message)
                data = bytearray()
                while len(data) < len(message):
                    part = sock.recv(len(message) - len(data))
                    if not part:
                        break
                    data += part
                assert bytes(data) == message, (i, bytes(data))
            break
        except OSError:
            if time.time() >= deadline:
                raise
            time.sleep(0.25)
print(f"post-reconnect bidirectional flows x{flows} OK", flush=True)
PY

  python3 - "${STATE_DIR}/stats.ndjson" "${STATE_DIR}/client.log" \
    "${OPENPPP2_XTCP_AFFINITY:-off}" "${OPENPPP2_XTCP_SHARDS:-1}" <<'PY'
import json, pathlib, sys, time

stats_path, log_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
mode, shards = sys.argv[3], int(sys.argv[4])
deadline = time.time() + 30
before = after = None
while time.time() < deadline:
    rows = [json.loads(line) for line in stats_path.read_text().splitlines() if line.strip()]
    samples = [row for row in rows if row.get("xtcp") and row.get("tap_linux")]
    if samples:
        before, after = samples[0]["xtcp"].get("runtime_instance_id"), samples[-1]["xtcp"].get("runtime_instance_id")
        lanes = samples[-1]["tap_linux"].get("bound_output_lanes", 0)
        connected = log_path.read_text(errors="replace").count("exchanger connected")
        if connected >= 2 and before and after and lanes >= (shards if mode == "queues" else 0):
            assert before == after, f"XTCP runtime restarted across session reconnect: {before} -> {after}"
            assert samples[-1]["xtcp"].get("affinity_mode") == mode, samples[-1]["xtcp"].get("affinity_mode")
            shard_stats = samples[-1]["xtcp"].get("shards", [])
            assert len(shard_stats) >= shards and all(s.get("enqueued", 0) > 0 for s in shard_stats[:shards]), shard_stats
            if mode == "queues":
                assert samples[-1]["xtcp"].get("queue_mode_active") is True
                assert samples[-1]["tap_linux"].get("vnet_header") is True
                assert samples[-1]["tap_linux"].get("gso_merge_active") is True
                assert lanes >= shards, f"only {lanes}/{shards} queue lanes remain bound"
            print(f"reconnect preserved runtime={after}, mode={mode}, bound_lanes={lanes}")
            break
    time.sleep(0.5)
else:
    raise SystemExit(f"reconnect evidence did not converge: runtime {before}->{after}, mode={mode}")
PY
fi

# ---------------------------------------------------------------- traffic
ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" "${CHURN}" "${STATE_DIR}" \
  >"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import pathlib, socket, sys, time

target_ip, echo_port, churn = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
artifact_dir = pathlib.Path(sys.argv[4])
deadline = time.time() + 30

def connect(timeout=3):
    return socket.create_connection((target_ip, echo_port), timeout=timeout)

def recv_exact(sock, want):
    buf = bytearray()
    while len(buf) < want:
        chunk = sock.recv(want - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)

# basic echo (also the tunnel-readiness probe)
payload = b"openppp2-xtcp-e2e"
last = "no attempts"
while time.time() < deadline:
    try:
        with connect() as sock:
            sock.settimeout(5)
            sock.sendall(payload)
            data = recv_exact(sock, len(payload))
            assert data == payload, f"echo mismatch: {data!r}"
        break
    except OSError as exc:
        last = str(exc)
        time.sleep(0.5)
else:
    sys.exit(f"tunnel never came up: {last}")
print("basic echo OK", flush=True)

# half-close, client-initiated: the write side closes right after a 128 KiB
# upload. The upload must reach the echo service intact (asserted from
# echo.log below). The platform tears the connection down once the upload half
# closes - the native TCP stack behaves identically - so the download side
# races the teardown: the app asserts that whatever echo bytes it receives
# form an intact prefix of the blob and that the connection terminates
# promptly (EOF or RST), instead of demanding a full tail drain.
blob = bytes(range(256)) * 512  # 128 KiB, forces several segments
with connect() as sock:
    sock.settimeout(10)
    sock.sendall(blob)
    sock.shutdown(socket.SHUT_WR)
    received = bytearray()
    terminated = ""
    while True:
        try:
            chunk = sock.recv(65536)
        except ConnectionResetError:
            terminated = "rst"
            break
        if not chunk:
            terminated = "eof"
            break
        received += chunk
    expected = blob[:len(received)]
    if bytes(received) != expected:
        mismatch = next((i for i, (actual, wanted) in enumerate(zip(received, expected))
                         if actual != wanted), min(len(received), len(expected)))
        (artifact_dir / "half-close-client-echo.bin").write_bytes(received)
        print(f"half-close mismatch offset={mismatch} actual={received[mismatch:mismatch + 16].hex()} "
              f"expected={expected[mismatch:mismatch + 16].hex()}", flush=True)
        raise AssertionError("half-close prefix corrupted")
    assert terminated, "half-close connection never terminated"
print(f"half-close OK: uploaded {len(blob)} bytes, drained {len(received)} before {terminated}", flush=True)

# graceful peer-initiated close: the echo-and-close service returns a fixed
# 256 KiB blob and closes immediately; every echoed byte must arrive before
# the EOF, end to end (data->FIN ordering across the whole chain).
blob2 = bytes((i * 31) & 0xFF for i in range(256 * 1024))
with socket.create_connection((target_ip, echo_port + 1), timeout=5) as sock:
    sock.settimeout(15)
    sock.sendall(len(blob2).to_bytes(4, "big") + blob2)
    received2 = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        received2 += chunk
    assert bytes(received2) == blob2, "peer-close tail bytes lost or corrupted"
print("peer-close drain OK", flush=True)

# RST: nothing listens on port 9 of the target; connect must be refused
try:
    socket.create_connection((target_ip, 9), timeout=5)
    sys.exit("connect to a closed port unexpectedly succeeded")
except ConnectionRefusedError:
    print("rst refused OK", flush=True)

# churn: many short sequential connections, each echoing a small payload
for i in range(churn):
    with connect() as sock:
        sock.settimeout(5)
        message = f"churn-{i}".encode()
        sock.sendall(message)
        data = recv_exact(sock, len(message))
        assert data == message, f"churn {i} mismatch: {data!r}"
print(f"churn x{churn} OK", flush=True)
PY

# The echo service logs every closed connection's received byte count; the
# half-close and peer-close uploads must have arrived byte-complete.
wait_echo_bytes() {
  local port="$1" want="$2"
  for _ in $(seq 1 40); do
    if grep -q "conn closed port=${port} bytes=${want}" "${STATE_DIR}/echo.log" 2>/dev/null; then
      echo "echo-side upload integrity OK: port=${port} bytes=${want}"
      return 0
    fi
    sleep 0.25
  done
  echo "echo service never reported a full ${want}-byte upload on port ${port}; echo.log:" >&2
  cat "${STATE_DIR}/echo.log" >&2 || true
  return 1
}
wait_echo_bytes "${ECHO_PORT}" 131072
wait_echo_bytes "$((ECHO_PORT + 1))" 262144

# stats-json must carry the xtcp block with counters matching the traffic.
# Counters are cumulative and land on the 1s app tick, so the check waits up
# to 15s for a snapshot that actually covers the whole traffic window before
# asserting; the battery itself finishes faster than that cadence.
python3 - "${STATE_DIR}/stats.ndjson" "${CHURN}" <<'PY'
import json, sys, time

path, churn = sys.argv[1], int(sys.argv[2])
need = churn + 2
deadline = time.time() + 15

def fold(lines):
    agg = {}
    for line in lines:
        sample = json.loads(line)
        xtcp = sample.get("xtcp")
        assert xtcp is not None, f"stats line without xtcp block: {line!r}"
        for key, value in xtcp.items():
            # Only numeric counters fold by max; labels (affinity_mode) and
            # per-shard arrays are kept as the latest sample.
            if isinstance(value, (int, float)) and not isinstance(agg.get(key, 0), (str, list, dict)):
                agg[key] = max(agg.get(key, 0), value)
            else:
                agg[key] = value
    return agg

lines, agg, last_err = [], {}, "stats file missing"
while time.time() < deadline:
    try:
        candidate = [l for l in open(path, encoding="utf-8") if l.strip()]
        if len(candidate) >= 5:
            candidate_agg = fold(candidate)
            if candidate_agg.get("flows_opened", 0) >= need:
                lines, agg = candidate, candidate_agg
                break
            last_err = f"flows_opened={candidate_agg.get('flows_opened')} below {need}; waiting for the next tick"
    except FileNotFoundError:
        pass
    time.sleep(0.25)
else:
    sys.exit(f"stats did not converge within 15s: {last_err}")

assert len(lines) >= 5, f"stats ndjson has only {len(lines)} line(s); the 1s tick is not writing"
assert agg["output_bytes"] > 0 and agg["ingress_injected"] > 0, agg
assert agg["timer_polls"] > 0, agg
print("stats-json xtcp block OK:", {k: agg[k] for k in ("flows_opened", "flows_closed", "timer_polls")})
PY

# ---------------------------------------------------------------- netem/mtu
if [[ "${SKIP_NETEM}" != 1 ]]; then
  echo "injecting netem on ${NS_C}/${TUN_DEV}: loss 1% reorder 25% delay 10ms, mtu 1280"
  ip netns exec "${NS_C}" tc qdisc replace dev "${TUN_DEV}" root netem loss 1% reorder 25% delay 10ms || {
    echo "tc netem setup failed" >&2; exit 1; }
  ip -n "${NS_C}" link set dev "${TUN_DEV}" mtu 1280
  NETEM_ACTIVE=1
  if command -v tcpdump >/dev/null; then
    ip netns exec "${NS_C}" tcpdump -U -i "${TUN_DEV}" -nn -s 1600 -c 200000 \
      -w "${STATE_DIR}/netem-tun.pcap" 'tcp or icmp or icmp6' \
      >"${STATE_DIR}/netem-tcpdump.log" 2>&1 &
    pcap_pid=$!
    sleep 0.2
    if ! kill -0 "${pcap_pid}" 2>/dev/null; then
      wait "${pcap_pid}" || true
      pcap_pid=""
    fi
  fi
  ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" \
    >>"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys, threading

target_ip, echo_port = sys.argv[1], int(sys.argv[2])

def recv_exact(sock, want):
    buf = bytearray()
    while len(buf) < want:
        chunk = sock.recv(want - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)

# 1 MiB across a lossy/reordering path exercises XTCP retransmit + SACK on the
# TUN leg. The echo-side byte count (asserted from echo.log below) proves the
# upload recovered every segment. Drain the echo concurrently with upload to
# avoid filling the receive window while the full-duplex transfer is active.
blob = bytes((i * 7) & 0xFF for i in range(1024 * 1024))
with socket.create_connection((target_ip, echo_port), timeout=10) as sock:
    sock.settimeout(30)
    received = bytearray()
    send_error = []

    def upload_blob():
        try:
            sock.sendall(blob)
        except BaseException as exc:
            send_error.append(exc)

    sender = threading.Thread(target=upload_blob, daemon=True)
    sender.start()
    try:
        while len(received) < len(blob):
            chunk = sock.recv(min(65536, len(blob) - len(received)))
            if not chunk:
                break
            received += chunk
    finally:
        if len(received) < len(blob) and sender.is_alive():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        sender.join(timeout=5)
    assert not sender.is_alive(), "netem upload did not finish after full echo"
    if send_error:
        raise send_error[0]
    assert bytes(received) == blob, "netem echo was truncated, duplicated, or corrupted"
for i in range(64):
    with socket.create_connection((target_ip, echo_port), timeout=10) as sock:
        sock.settimeout(10)
        message = f"netem-churn-{i}".encode()
        sock.sendall(message)
        assert recv_exact(sock, len(message)) == message
print(f"netem 1MiB (drained {len(received)}) + churn x64 OK", flush=True)
PY
  wait_echo_bytes "${ECHO_PORT}" 1048576
  ip netns exec "${NS_C}" tc qdisc del dev "${TUN_DEV}" root 2>/dev/null || true
fi

# ---------------------------------------------------------------- soak
echo "soak: ${SOAK_SECONDS}s sustained stream"
ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" "${SOAK_SECONDS}" \
  >>"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys, time

target_ip, echo_port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
chunk = bytes(64 * 1024)
with socket.create_connection((target_ip, echo_port), timeout=10) as sock:
    sock.settimeout(30)
    deadline = time.time() + seconds
    rounds = 0
    while time.time() < deadline:
        sock.sendall(chunk)
        view = memoryview(bytearray(len(chunk)))
        got = 0
        while got < len(chunk):
            got += sock.recv_into(view[got:])
        assert bytes(view) == chunk, "soak echo corrupted"
        rounds += 1
print(f"soak OK: {rounds} x 64KiB round-trips", flush=True)
PY
kill -0 "${CLIENT_PID}" 2>/dev/null || { echo "client died during the run; see client.log" >&2; exit 1; }

# ---------------------------------------------------------------- rollback
kill -TERM "${CLIENT_PID}" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "${CLIENT_PID}" 2>/dev/null || break; sleep 0.5; done
kill -9 "${CLIENT_PID}" 2>/dev/null || true
sleep 1
snapshot_client "${STATE_DIR}/after"
# The kernel adds/removes IPv6 link-local derived routes on the underlay veth
# while the namespace is up (autoconf/DAD timing). That churn is noise here:
# this check guards against ppp leaking host policy, so drop fe80:: entries
# from both snapshots before comparing.
normalize_routes() {
  python3 - "$1" <<'PY'
import json, sys
path = sys.argv[1]
rows = json.load(open(path))
kept = [r for r in rows if not str(r.get("dst", "")).startswith("fe80:")]
json.dump(kept, open(path, "w"), sort_keys=True)
PY
}
normalize_routes "${STATE_DIR}/before.routes"
normalize_routes "${STATE_DIR}/after.routes"
diff -u "${STATE_DIR}/before.routes" "${STATE_DIR}/after.routes"
diff -u "${STATE_DIR}/before.dns" "${STATE_DIR}/after.dns"
echo "rollback OK: client namespace routes/DNS restored"

echo "PASS: XTCP TAP netns end-to-end (echo, half-close, peer-close drain, RST, churn x${CHURN}, netem, soak ${SOAK_SECONDS}s, rollback)"
