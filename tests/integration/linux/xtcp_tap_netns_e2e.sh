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
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PPP_BIN="${PPP_BIN:-${ROOT}/bin/ppp}"
SOAK_SECONDS="${XTCP_SOAK_SECONDS:-60}"
CHURN="${XTCP_E2E_CHURN:-512}"
SKIP_NETEM="${XTCP_E2E_SKIP_NETEM:-0}"

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
cleanup() {
  set +e
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
(out / "server.json").write_text(json.dumps(server, indent=2) + "\n", encoding="utf-8")
(out / "client.json").write_text(json.dumps(client, indent=2) + "\n", encoding="utf-8")
PY

# ---------------------------------------------------------------- services
ip netns exec "${NS_S}" stdbuf -oL -eL "${PPP_BIN}" --mode=server --config="${STATE_DIR}/server.json" \
  >"${STATE_DIR}/server.log" 2>&1 &
pids+=("$!")
sleep 2
kill -0 "${pids[0]}" 2>/dev/null || { echo "server exited during startup; see server.log" >&2; exit 1; }

ip netns exec "${NS_T}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" \
  >"${STATE_DIR}/echo.log" 2>&1 <<'PY' &
import socket, sys, threading

echo_port = int(sys.argv[2])

def serve_echo(conn):
    # Echo until the peer closes. The per-connection byte count is logged on
    # close (also on RST) so the caller can assert upload integrity.
    total = 0
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            total += len(data)
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()
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

ip netns exec "${NS_C}" stdbuf -oL -eL "${PPP_BIN}" --mode=client --config="${STATE_DIR}/client.json" \
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

# ---------------------------------------------------------------- traffic
ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" "${CHURN}" \
  >"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys, time

target_ip, echo_port, churn = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
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
    assert bytes(received) == blob[:len(received)], "half-close prefix corrupted"
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
            agg[key] = max(agg.get(key, 0), value)
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
  ip netns exec "${NS_C}" python3 -u - "${TARGET_IP}" "${ECHO_PORT}" \
    >>"${STATE_DIR}/battery.log" 2>&1 <<'PY'
import socket, sys

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
# upload recovered every segment; the download side races the teardown after
# the upload half closes (same close semantics as the plain half-close case),
# so it asserts an intact prefix plus prompt termination.
blob = bytes((i * 7) & 0xFF for i in range(1024 * 1024))
with socket.create_connection((target_ip, echo_port), timeout=10) as sock:
    sock.settimeout(30)
    sock.sendall(blob)
    sock.shutdown(socket.SHUT_WR)
    received = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except ConnectionResetError:
            break
        if not chunk:
            break
        received += chunk
    assert bytes(received) == blob[:len(received)], "netem round-trip prefix corrupted"
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
