#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PPP_BIN="${PPP_BIN:-${ROOT}/bin/ppp}"
SERVER_PPP_BIN="${SERVER_PPP_BIN:-${PPP_BIN}}"
CLIENT_PPP_BIN="${CLIENT_PPP_BIN:-${PPP_BIN}}"
COMPAT_MODE="${COMPAT_MODE:-match}"
OUT_DIR="${OUT_DIR:-${TMPDIR:-/tmp}/openppp2-client-server-smoke.$$}"
TIMEOUT_SEC="${TIMEOUT_SEC:-20}"
PAYLOAD="${PAYLOAD:-openppp2-android-compat-smoke}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "client_server_compat_smoke.sh requires root" >&2
    exit 1
fi
case "${COMPAT_MODE}" in
    match|mismatch) ;;
    *) echo "COMPAT_MODE must be match or mismatch" >&2; exit 2 ;;
esac
for bin in "${SERVER_PPP_BIN}" "${CLIENT_PPP_BIN}"; do
    [[ -x "${bin}" ]] || { echo "missing executable ppp binary: ${bin}" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "missing python3" >&2; exit 1; }

mkdir -p "${OUT_DIR}"
pids=()
cleanup() {
    set +e
    for pid in "${pids[@]:-}"; do kill "${pid}" 2>/dev/null || true; done
    wait "${pids[@]:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 - "${ROOT}" "${OUT_DIR}" "${COMPAT_MODE}" >"${OUT_DIR}/vars.sh" <<'PY'
import json, pathlib, shlex, socket, sys

root, out, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
compat = root / "tools" / "compat"
server_name = "server.json" if mode == "match" else "server_flag_defaults.json"
server = json.loads((compat / server_name).read_text(encoding="utf-8"))
client = json.loads((compat / "client_proxy.json").read_text(encoding="utf-8"))

def free_ports(count):
    sockets, ports = [], []
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
        ports.append(sock.getsockname()[1])
    for sock in sockets:
        sock.close()
    return ports

server_port, http_port, socks_port, local_port, remote_port = free_ports(5)
server["tcp"]["listen"]["port"] = server_port
server["udp"]["listen"]["port"] = server_port
client["tcp"]["listen"]["port"] = 0
client["udp"]["listen"]["port"] = 0
client["client"]["server"] = f"ppp://127.0.0.1:{server_port}/"
client["client"]["http-proxy"]["port"] = http_port
client["client"]["socks-proxy"]["port"] = socks_port
mapping = client["client"]["mappings"][0]
mapping["local-port"] = local_port
mapping["remote-port"] = remote_port

(out / "server.json").write_text(json.dumps(server, indent=2) + "\n", encoding="utf-8")
(out / "client_proxy.json").write_text(json.dumps(client, indent=2) + "\n", encoding="utf-8")
(out / "ports.json").write_text(json.dumps({
    "mode": mode,
    "server_fixture": server_name,
    "server_port": server_port,
    "http_port": http_port,
    "socks_port": socks_port,
    "local_port": local_port,
    "remote_port": remote_port,
}, indent=2) + "\n", encoding="utf-8")
for key, value in {
    "SERVER_CONFIG": str(out / "server.json"),
    "CLIENT_CONFIG": str(out / "client_proxy.json"),
    "SERVER_PORT": server_port,
    "LOCAL_PORT": local_port,
    "REMOTE_PORT": remote_port,
}.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
. "${OUT_DIR}/vars.sh"

echo "mode=${COMPAT_MODE} out=${OUT_DIR}"
echo "server=${SERVER_PORT} echo-local=${LOCAL_PORT} mapped-remote=${REMOTE_PORT}"
"${SERVER_PPP_BIN}" --mode=server --config="${SERVER_CONFIG}" >"${OUT_DIR}/server.log" 2>&1 &
pids+=("$!")
sleep "${SERVER_WAIT:-2}"
if ! kill -0 "${pids[0]}" 2>/dev/null; then
    echo "server exited during startup; inspect ${OUT_DIR}/server.log" >&2
    exit 1
fi

"${CLIENT_PPP_BIN}" --mode=proxy --config="${CLIENT_CONFIG}" \
    --tun-host=no --tun-vnet=no --tun-protect=no --tun-route=no \
    >"${OUT_DIR}/client.log" 2>&1 &
pids+=("$!")
sleep "${CLIENT_WAIT:-4}"
if [[ "${COMPAT_MODE}" == "match" ]] && ! kill -0 "${pids[1]}" 2>/dev/null; then
    echo "client exited during startup; inspect ${OUT_DIR}/client.log" >&2
    exit 1
fi

python3 -u - "${LOCAL_PORT}" >"${OUT_DIR}/echo.log" 2>&1 <<'PY' &
import socket, sys

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen(16)
print("echo ready", flush=True)
while True:
    conn, _ = listener.accept()
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
PY
pids+=("$!")
sleep 1

set +e
python3 - "${REMOTE_PORT}" "${PAYLOAD}" "${TIMEOUT_SEC}" <<'PY'
import socket, sys, time

port, payload = int(sys.argv[1]), sys.argv[2].encode("utf-8")
deadline, last_error = time.time() + float(sys.argv[3]), "no attempts"
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(3)
            sock.sendall(payload)
            data = sock.recv(len(payload) + 64)
            if data == payload:
                print("echo verified")
                sys.exit(0)
            last_error = f"unexpected echo {data!r}"
    except OSError as exc:
        last_error = str(exc)
    time.sleep(0.5)
print(f"traffic failed: {last_error}", file=sys.stderr)
sys.exit(1)
PY
traffic_status=$?
set -e

if [[ "${COMPAT_MODE}" == "match" ]]; then
    [[ "${traffic_status}" -eq 0 ]] && { echo "match smoke passed"; exit 0; }
    echo "match smoke failed; inspect ${OUT_DIR}/*.log" >&2
    exit 1
fi
if [[ "${traffic_status}" -eq 0 ]]; then
    echo "mismatch smoke failed: traffic unexpectedly succeeded" >&2
    exit 1
fi
if grep -Eiq 'ObfuscationFlagsMismatch|flag mismatch|session rejected|align key\.' \
    "${OUT_DIR}/server.log" "${OUT_DIR}/client.log"; then
    echo "mismatch smoke passed with mismatch diagnostic"
else
    echo "mismatch smoke passed with traffic failure"
fi
