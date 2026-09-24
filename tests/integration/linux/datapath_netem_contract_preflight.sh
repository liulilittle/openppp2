#!/usr/bin/env bash
# Bounded Linux capability preflight for the strict datapath v3 netem contract.
# This is not a PPP run and does not make a performance or benchmark claim.
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
UNIFORM_SOURCE="${ROOT}/tools/uniform.dist"
BPF_SOURCE="${ROOT}/tools/datapath_fixed_loss.bpf.c"
BASE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"

preflight_failure() {
  printf 'preflight failure: %s\n' "$*" >&2
  exit 1
}

capability_failure() {
  printf 'capability failure: %s\n' "$*" >&2
  exit 2
}

if [[ "$(id -u)" -ne 0 ]]; then
  capability_failure "${0##*/} must run as root"
fi

for required in ip tc clang python3 ethtool; do
  command -v "${required}" >/dev/null 2>&1 || capability_failure "required command is unavailable: ${required}"
done
[[ -f "${UNIFORM_SOURCE}" ]] || preflight_failure "missing distribution source: ${UNIFORM_SOURCE}"
[[ -f "${BPF_SOURCE}" ]] || preflight_failure "missing periodic BPF source: ${BPF_SOURCE}"

STATE_DIR=""
CREATED_NAMESPACES=()
ROOT_VETHS=()
CHILD_PIDS=()

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  for pid in "${CHILD_PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${CHILD_PIDS[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done
  # A peer can remain in the initial namespace when a later move fails.
  for link in "${ROOT_VETHS[@]}"; do
    ip link del "${link}" 2>/dev/null || true
  done
  for namespace in "${CREATED_NAMESPACES[@]}"; do
    ip netns del "${namespace}" 2>/dev/null || true
  done
  if [[ -n "${STATE_DIR}" && -d "${STATE_DIR}" ]]; then
    rm -rf -- "${STATE_DIR}"
  fi
  exit "${status}"
}

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openppp2-datapath-netem.XXXXXX")" \
  || capability_failure "cannot allocate private temporary state"
trap cleanup EXIT
: >"${STATE_DIR}/commands.log"

record_command() {
  printf '%q ' "$@" >>"${STATE_DIR}/commands.log"
  printf '\n' >>"${STATE_DIR}/commands.log"
}

run_capability() {
  record_command "$@"
  if ! "$@"; then
    capability_failure "required command failed: $*"
  fi
}

capture_capability() {
  local output=$1
  shift
  record_command "$@"
  if ! "$@" >"${output}"; then
    capability_failure "required command failed while capturing ${output##*/}: $*"
  fi
}

capture_json() {
  local namespace=$1
  local interface=$2
  local output=$3
  capture_capability "${output}" ip netns exec "${namespace}" tc -j -s -d qdisc show dev "${interface}"
  if [[ ! -s "${output}" ]]; then
    preflight_failure "empty qdisc JSON for ${namespace}/${interface}"
  fi
}

capture_clsact_json() {
  local namespace=$1
  local interface=$2
  local output=$3
  capture_capability "${output}" ip netns exec "${namespace}" tc -j -s -d qdisc show dev "${interface}" clsact
  if [[ ! -s "${output}" ]]; then
    preflight_failure "empty clsact qdisc JSON for ${namespace}/${interface}"
  fi
}

capture_filter_json() {
  local namespace=$1
  local interface=$2
  local output=$3
  capture_capability "${output}" ip netns exec "${namespace}" tc -j -s -d filter show dev "${interface}" egress
  if [[ ! -s "${output}" ]]; then
    preflight_failure "empty filter JSON for ${namespace}/${interface}"
  fi
}

capture_link_json() {
  local namespace=$1
  local interface=$2
  local output=$3
  capture_capability "${output}" ip -n "${namespace}" -j -s -d link show dev "${interface}"
  if [[ ! -s "${output}" ]]; then
    preflight_failure "empty link JSON for ${namespace}/${interface}"
  fi
}

wait_for_file() {
  local path=$1
  local description=$2
  local attempt
  for attempt in $(seq 1 80); do
    [[ -e "${path}" ]] && return 0
    sleep 0.05
  done
  preflight_failure "timed out waiting for ${description}"
}

validate_uniform_distribution() {
  local table=$1
  if ! python3 - "${table}" >"${STATE_DIR}/uniform-validation.txt" 2>&1 <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
if not raw.endswith(b"\n"):
    raise SystemExit("uniform.dist must end with exactly one newline")
try:
    lines = raw.decode("ascii").splitlines()
except UnicodeDecodeError as error:
    raise SystemExit(f"uniform.dist is not ASCII: {error}")
if len(lines) != 513:
    raise SystemExit(f"uniform.dist must contain 513 lines, got {len(lines)}")
comments = [line for line in lines if line.startswith("#")]
if len(comments) != 1:
    raise SystemExit(f"uniform.dist must contain one comment line, got {len(comments)}")
values = []
for line_number, line in enumerate(lines, 1):
    if line.startswith("#"):
        continue
    fields = line.split()
    if len(fields) != 8:
        raise SystemExit(f"uniform.dist line {line_number} must contain eight samples")
    for field in fields:
        if not re.fullmatch(r"-?[0-9]+", field):
            raise SystemExit(f"uniform.dist line {line_number} contains a non-decimal sample")
        values.append(int(field))
expected = list(range(-32768, 32753, 16))
if values != expected:
    raise SystemExit("uniform.dist samples are not the exact -32768..32752 step-16 sequence")
print(f"PASS: uniform.dist comment=1 data_lines=512 samples={len(values)} range={values[0]}..{values[-1]} step=16 EOF=newline")
PY
  then
    cat "${STATE_DIR}/uniform-validation.txt" >&2 || true
    preflight_failure "copied uniform distribution does not meet the strict format"
  fi
}

assert_no_netem() {
  if ! python3 - "$@" <<'PY'
import json
import pathlib
import sys

def contains_netem(value):
    if isinstance(value, str):
        return "netem" in value.lower()
    if isinstance(value, dict):
        return any(contains_netem(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_netem(item) for item in value)
    return False

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise SystemExit(f"{path.name}: qdisc evidence is not a JSON array")
    if contains_netem(value):
        raise SystemExit(f"{path.name}: non-target endpoint contains netem")
print("PASS: non-target qdisc snapshots contain no netem")
PY
  then
    preflight_failure "netem was observed on a control or overlay-like sentinel endpoint"
  fi
}

assert_tunnel_veth_slave() {
  local json_path=$1
  local interface=$2
  if ! python3 - "${json_path}" "${interface}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
interface = sys.argv[2]
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit(f"{path.name}: expected exactly one link object")
link = value[0]
if link.get("ifname") != interface:
    raise SystemExit(f"{path.name}: wrong interface")
if link.get("master") != "br0":
    raise SystemExit(f"{interface}: not a br0 slave")
linkinfo = link.get("linkinfo")
if not isinstance(linkinfo, dict) or linkinfo.get("info_kind") != "veth":
    raise SystemExit(f"{interface}: is not a veth")
print(f"PASS: {interface} is a veth slave of br0")
PY
  then
    preflight_failure "tunnel target ${interface} is not the required br0 veth slave"
  fi
}

assert_tx_increased() {
  local before=$1
  local after=$2
  local interface=$3
  local direction=$4
  if ! python3 - "${before}" "${after}" "${interface}" "${direction}" <<'PY'
import json
import pathlib
import sys

before_path, after_path, interface, direction = map(str, sys.argv[1:])

def packets(path):
    value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(f"{path}: malformed link JSON")
    link = value[0]
    if link.get("ifname") != interface:
        raise SystemExit(f"{path}: wrong interface")
    statistics = link.get("stats64", link.get("stats"))
    if not isinstance(statistics, dict) or not isinstance(statistics.get("tx"), dict):
        raise SystemExit(f"{path}: missing TX statistics")
    count = statistics["tx"].get("packets")
    if isinstance(count, bool) or not isinstance(count, int):
        raise SystemExit(f"{path}: TX packet count is invalid")
    return count

start = packets(before_path)
end = packets(after_path)
if end <= start:
    raise SystemExit(f"{direction}: {interface} TX did not increase ({start} -> {end})")
print(f"PASS: {direction} reached {interface} ({start} -> {end} TX packets)")
PY
  then
    preflight_failure "carrier direction placement was not observed for ${direction}"
  fi
}

assert_netem_snapshot() {
  local json_path=$1
  local delay_us=$2
  local jitter_us=$3
  local seed=$4
  local loss_ppm=$5
  if ! python3 - "${json_path}" "${delay_us}" "${jitter_us}" "${seed}" "${loss_ppm}" <<'PY'
import json
import pathlib
import sys
from decimal import Decimal

path = pathlib.Path(sys.argv[1])
delay_us, jitter_us, seed, loss_ppm = map(int, sys.argv[2:])
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, list):
    raise SystemExit(f"{path.name}: qdisc output is not a JSON array")
netems = [entry for entry in value if isinstance(entry, dict) and entry.get("kind") == "netem"]
if len(netems) != 1:
    raise SystemExit(f"{path.name}: expected exactly one netem qdisc")
netem = netems[0]
if netem.get("root") is not True or "parent" in netem:
    raise SystemExit(f"{path.name}: netem is not the root qdisc")
options = netem.get("options")
if not isinstance(options, dict):
    raise SystemExit(f"{path.name}: netem options are absent")
if options.get("limit") != 32768:
    raise SystemExit(f"{path.name}: netem limit is not 32768")
if options.get("seed") != seed:
    raise SystemExit(f"{path.name}: netem seed does not match the applied command")
delay = options.get("delay")
if not isinstance(delay, dict):
    raise SystemExit(f"{path.name}: netem delay options are absent")

def decimal_at(name, expected):
    try:
        actual = Decimal(str(delay.get(name)))
    except Exception as error:
        raise SystemExit(f"{path.name}: invalid delay.{name}: {error}")
    if actual != expected:
        raise SystemExit(f"{path.name}: delay.{name}={actual} != {expected}")

decimal_at("delay", Decimal(delay_us) / Decimal(1_000_000))
decimal_at("jitter", Decimal(jitter_us) / Decimal(1_000_000))
decimal_at("correlation", Decimal(0))
loss = options.get("loss-random")
if loss_ppm:
    if not isinstance(loss, dict):
        raise SystemExit(f"{path.name}: IID loss options are absent")
    try:
        actual_loss = Decimal(str(loss.get("loss")))
        actual_correlation = Decimal(str(loss.get("correlation")))
    except Exception as error:
        raise SystemExit(f"{path.name}: invalid IID loss options: {error}")
    expected_loss = Decimal(loss_ppm) / Decimal(1_000_000)
    if actual_loss != expected_loss or actual_correlation != Decimal(0):
        raise SystemExit(f"{path.name}: IID loss readback does not match the profile")
elif loss is not None:
    raise SystemExit(f"{path.name}: unexpected IID loss options")
for counter in ("bytes", "packets", "drops", "overlimits"):
    observed = netem.get(counter)
    if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
        raise SystemExit(f"{path.name}: invalid netem {counter}")
if netem["overlimits"] != 0:
    raise SystemExit(f"{path.name}: netem overlimits must be zero")
print(f"PASS: {path.name} delay={delay_us}us jitter={jitter_us}us seed={seed} loss_ppm={loss_ppm}")
PY
  then
    preflight_failure "netem JSON readback differs from the applied profile"
  fi
}

assert_periodic_clsact() {
  local json_path=$1
  if ! python3 - "${json_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
    raise SystemExit(f"{path.name}: expected exactly one clsact selector record")
clsact = value[0]
if clsact.get("kind") != "clsact":
    raise SystemExit(f"{path.name}: selector did not return clsact")
if clsact.get("root") is True or clsact.get("parent") != "ffff:fff1":
    raise SystemExit(f"{path.name}: clsact is not the canonical egress attachment qdisc")
print(f"PASS: {path.name} retains one clsact selector record")
PY
  then
    preflight_failure "periodic BPF clsact qdisc was not retained"
  fi
}

assert_netem_traffic() {
  local immediate=$1
  local post=$2
  local loss_ppm=$3
  local allow_action_drops=$4
  if ! python3 - "${immediate}" "${post}" "${loss_ppm}" "${allow_action_drops}" <<'PY'
import json
import pathlib
import sys

immediate_path, post_path = map(pathlib.Path, sys.argv[1:3])
loss_ppm, allow_action_drops = map(int, sys.argv[3:])
if allow_action_drops not in (0, 1):
    raise SystemExit("allow_action_drops must be 0 or 1")

def netem(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    matches = [entry for entry in value if isinstance(entry, dict) and entry.get("kind") == "netem"]
    if len(matches) != 1:
        raise SystemExit(f"{path.name}: expected one netem qdisc")
    return matches[0]

before = netem(immediate_path)
after = netem(post_path)
for field in ("bytes", "packets", "drops", "overlimits"):
    if (
        isinstance(before.get(field), bool)
        or not isinstance(before.get(field), int)
        or before[field] < 0
        or isinstance(after.get(field), bool)
        or not isinstance(after.get(field), int)
        or after[field] < 0
    ):
        raise SystemExit(f"invalid {field} counter")
if after["bytes"] <= before["bytes"] or after["packets"] <= before["packets"]:
    raise SystemExit("UDP echo traffic did not increase netem counters")
if before["overlimits"] != 0 or after["overlimits"] != 0:
    raise SystemExit("netem overlimits must remain zero")
if after["drops"] < before["drops"]:
    raise SystemExit("netem drops must be nondecreasing")
if loss_ppm == 0 and not allow_action_drops and (before["drops"] != 0 or after["drops"] != 0):
    raise SystemExit("no-loss netem profile reported queue drops")
print(f"PASS: netem traffic {immediate_path.name} -> {post_path.name}")
PY
  then
    preflight_failure "netem traffic counters failed their bounded echo check"
  fi
}

assert_empty_filter() {
  local json_path=$1
  if ! python3 - "${json_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
if value != []:
    raise SystemExit(f"{path.name}: expected no egress BPF filter before attachment")
print(f"PASS: {path.name} has no egress filter before attachment")
PY
  then
    preflight_failure "periodic BPF filter was already present before attachment"
  fi
}

assert_periodic_filter() {
  local json_path=$1
  if ! python3 - "${json_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, list) or len(value) not in (1, 2) or not all(isinstance(entry, dict) for entry in value):
    raise SystemExit(f"{path.name}: expected one detailed BPF record and at most one terse companion")
detailed = [entry for entry in value if isinstance(entry.get("options"), dict)]
if len(detailed) != 1:
    raise SystemExit(f"{path.name}: expected exactly one configured BPF filter")
if len(value) == 2:
    terse = next(entry for entry in value if entry not in detailed)
    if "options" in terse or set(terse) != {"protocol", "pref", "kind", "chain"}:
        raise SystemExit(f"{path.name}: terse BPF companion is malformed")
pref = None
for index, record in enumerate(value):
    if record.get("kind") != "bpf" or record.get("protocol") != "all":
        raise SystemExit(f"{path.name}: record {index} is not the all-protocol BPF attachment")
    chain = record.get("chain")
    if isinstance(chain, bool) or not isinstance(chain, int) or chain != 0:
        raise SystemExit(f"{path.name}: record {index} is not the chain-zero BPF attachment")
    record_pref = record.get("pref")
    if isinstance(record_pref, bool) or not isinstance(record_pref, int) or record_pref <= 0:
        raise SystemExit(f"{path.name}: record {index} has no positive preference")
    if pref is None:
        pref = record_pref
    elif record_pref != pref:
        raise SystemExit(f"{path.name}: BPF records have different preferences")
record = detailed[0]
options = record["options"]
if options.get("direct-action") is not True:
    raise SystemExit(f"{path.name}: BPF filter is not direct-action")
if options.get("bpf_name") != "datapath_fixed_loss.bpf.c:[carrier_egress]":
    raise SystemExit(f"{path.name}: BPF source/section identity is not canonical")
if "actions" in record:
    raise SystemExit(f"{path.name}: BPF filter has non-direct tc actions")
program = options.get("prog")
if not isinstance(program, dict) or isinstance(program.get("id"), bool) or not isinstance(program.get("id"), int) or program["id"] <= 0:
    raise SystemExit(f"{path.name}: BPF filter lacks a positive program ID")
print(f"PASS: {path.name} retains one canonical direct-action BPF filter")
PY
  then
    preflight_failure "periodic BPF filter readback is not the requested direct-action attachment"
  fi
}

write_map_reader() {
  cat >"${STATE_DIR}/read_bpf_counters.py" <<'PY'
import ctypes
import ctypes.util
import json
import os
import sys


class BpfProgInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("tag", ctypes.c_ubyte * 8),
        ("jited_prog_len", ctypes.c_uint32),
        ("xlated_prog_len", ctypes.c_uint32),
        ("jited_prog_insns", ctypes.c_uint64),
        ("xlated_prog_insns", ctypes.c_uint64),
        ("load_time", ctypes.c_uint64),
        ("created_by_uid", ctypes.c_uint32),
        ("nr_map_ids", ctypes.c_uint32),
        ("map_ids", ctypes.c_uint64),
        ("name", ctypes.c_char * 16),
        ("ifindex", ctypes.c_uint32),
        ("gpl_compatible_and_pad", ctypes.c_uint32),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
    ]


class BpfMapInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * 16),
        ("ifindex", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
    ]


def fail(message):
    raise RuntimeError(message)


def libbpf_error(operation):
    errno = ctypes.get_errno()
    detail = os.strerror(errno) if errno else "unknown libbpf error"
    fail(f"{operation} failed: {detail}")


BPF_MAP_TYPE_ARRAY = 2


def program_id_from_filter(path):
    document = json.loads(open(path, encoding="utf-8").read())
    if not isinstance(document, list) or len(document) not in (1, 2) or not all(isinstance(entry, dict) for entry in document):
        fail("tc filter JSON must contain one detailed BPF record and at most one terse companion")
    detailed = [entry for entry in document if isinstance(entry.get("options"), dict)]
    if len(detailed) != 1:
        fail("tc filter JSON must expose exactly one configured BPF filter")
    if len(document) == 2:
        terse = next(entry for entry in document if entry not in detailed)
        if "options" in terse or set(terse) != {"protocol", "pref", "kind", "chain"}:
            fail("tc filter JSON terse BPF companion is malformed")
    pref = None
    for index, record in enumerate(document):
        if record.get("kind") != "bpf" or record.get("protocol") != "all":
            fail(f"tc filter JSON record {index} is not the all-protocol BPF attachment")
        chain = record.get("chain")
        if isinstance(chain, bool) or not isinstance(chain, int) or chain != 0:
            fail(f"tc filter JSON record {index} is not a chain-zero attachment")
        record_pref = record.get("pref")
        if isinstance(record_pref, bool) or not isinstance(record_pref, int) or record_pref <= 0:
            fail(f"tc filter JSON record {index} has no positive preference")
        if pref is None:
            pref = record_pref
        elif record_pref != pref:
            fail("tc filter JSON BPF records have different preferences")
    record = detailed[0]
    options = record["options"]
    if options.get("direct-action") is not True:
        fail("tc filter JSON BPF filter is not direct-action")
    if options.get("bpf_name") != "datapath_fixed_loss.bpf.c:[carrier_egress]":
        fail("tc filter JSON BPF source/section identity is not canonical")
    if "actions" in record:
        fail("tc filter JSON BPF filter has non-direct tc actions")
    program = options.get("prog")
    if not isinstance(program, dict):
        fail("tc filter JSON BPF filter lacks program metadata")
    program_id = program.get("id")
    if isinstance(program_id, bool) or not isinstance(program_id, int) or program_id <= 0:
        fail("tc filter JSON BPF filter lacks a positive nested program ID")
    return program_id


def main():
    if len(sys.argv) != 2:
        fail("usage: read_bpf_counters.py FILTER_JSON")
    library_name = ctypes.util.find_library("bpf")
    if not library_name:
        fail("libbpf is unavailable")
    library = ctypes.CDLL(library_name, use_errno=True)
    for symbol in (
        "bpf_prog_get_fd_by_id",
        "bpf_map_get_fd_by_id",
        "bpf_prog_get_info_by_fd",
        "bpf_map_get_info_by_fd",
        "bpf_map_lookup_elem",
    ):
        if not hasattr(library, symbol):
            fail(f"libbpf lacks {symbol}")
    library.bpf_prog_get_fd_by_id.argtypes = [ctypes.c_uint32]
    library.bpf_prog_get_fd_by_id.restype = ctypes.c_int
    library.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint32]
    library.bpf_map_get_fd_by_id.restype = ctypes.c_int
    library.bpf_prog_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    library.bpf_prog_get_info_by_fd.restype = ctypes.c_int
    library.bpf_map_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    library.bpf_map_get_info_by_fd.restype = ctypes.c_int
    library.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    library.bpf_map_lookup_elem.restype = ctypes.c_int

    program_fd = library.bpf_prog_get_fd_by_id(program_id_from_filter(sys.argv[1]))
    if program_fd < 0:
        libbpf_error("program lookup")
    map_fd = -1
    try:
        initial = BpfProgInfo()
        initial_length = ctypes.c_uint32(ctypes.sizeof(initial))
        if library.bpf_prog_get_info_by_fd(program_fd, ctypes.byref(initial), ctypes.byref(initial_length)) != 0:
            libbpf_error("program info lookup")
        if initial.nr_map_ids <= 0 or initial.nr_map_ids > 64:
            fail("program has an invalid map count")
        map_ids = (ctypes.c_uint32 * initial.nr_map_ids)()
        info = BpfProgInfo()
        info.nr_map_ids = initial.nr_map_ids
        info.map_ids = ctypes.addressof(map_ids)
        info_length = ctypes.c_uint32(ctypes.sizeof(info))
        if library.bpf_prog_get_info_by_fd(program_fd, ctypes.byref(info), ctypes.byref(info_length)) != 0:
            libbpf_error("program map-ID lookup")
        if info.nr_map_ids != initial.nr_map_ids:
            fail("program map count changed during lookup")
        counter_map_ids = []
        for map_id in map_ids:
            candidate_fd = library.bpf_map_get_fd_by_id(map_id)
            if candidate_fd < 0:
                libbpf_error(f"map lookup for ID {map_id}")
            try:
                map_info = BpfMapInfo()
                map_info_length = ctypes.c_uint32(ctypes.sizeof(map_info))
                if library.bpf_map_get_info_by_fd(candidate_fd, ctypes.byref(map_info), ctypes.byref(map_info_length)) != 0:
                    libbpf_error(f"map info lookup for ID {map_id}")
                map_name = bytes(map_info.name).split(b"\0", 1)[0]
                if map_name == b"counters":
                    if (
                        map_info.type != BPF_MAP_TYPE_ARRAY
                        or map_info.key_size != ctypes.sizeof(ctypes.c_uint32)
                        or map_info.value_size != 16
                        or map_info.max_entries != 1
                    ):
                        fail("counters map must be a one-entry array with a 4-byte key and 16-byte value")
                    counter_map_ids.append(map_id)
            finally:
                os.close(candidate_fd)
        if len(counter_map_ids) != 1:
            fail("program must expose exactly one counters map")
        map_fd = library.bpf_map_get_fd_by_id(counter_map_ids[0])
        if map_fd < 0:
            libbpf_error("counters map lookup")
        key = ctypes.c_uint32(0)
        values = (ctypes.c_uint64 * 2)()
        if library.bpf_map_lookup_elem(map_fd, ctypes.byref(key), ctypes.byref(values)) != 0:
            libbpf_error("counters map element lookup")
        print(json.dumps({"global_seen": int(values[0]), "global_dropped": int(values[1])}, sort_keys=True))
    finally:
        if map_fd >= 0:
            os.close(map_fd)
        os.close(program_fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"periodic BPF map reader: {error}", file=sys.stderr)
        raise SystemExit(2)
PY
}

read_bpf_counters() {
  local filter_json=$1
  local output=$2
  local stderr_path="${output}.stderr"
  record_command python3 "${STATE_DIR}/read_bpf_counters.py" "${filter_json}"
  if ! python3 "${STATE_DIR}/read_bpf_counters.py" "${filter_json}" >"${output}" 2>"${stderr_path}"; then
    cat "${stderr_path}" >&2 || true
    capability_failure "cannot read periodic BPF counters through libbpf"
  fi
}


assert_periodic_counters() {
  local immediate=$1
  local post=$2
  local every_n=$3
  local traffic=$4
  if ! python3 - "${immediate}" "${post}" "${every_n}" "${traffic}" <<'PY'
import json
import pathlib
import sys

immediate_path, post_path, every_n, traffic_path = sys.argv[1:]
every_n = int(every_n)

def counters(path):
    value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if set(value) != {"global_seen", "global_dropped"}:
        raise SystemExit(f"{path}: unexpected map JSON shape")
    result = []
    for key in ("global_seen", "global_dropped"):
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise SystemExit(f"{path}: invalid {key}")
        result.append(item)
    return result

immediate_seen, immediate_dropped = counters(immediate_path)
post_seen, post_dropped = counters(post_path)
traffic = json.loads(pathlib.Path(traffic_path).read_text(encoding="utf-8"))
if not isinstance(traffic, dict) or not isinstance(traffic.get("received"), int) or traffic["received"] <= 0:
    raise SystemExit("bounded UDP echo did not prove positive traffic")
seen_delta = post_seen - immediate_seen
dropped_delta = post_dropped - immediate_dropped
if seen_delta < every_n:
    raise SystemExit(f"seen delta {seen_delta} is less than PERIODIC_EVERY_N={every_n}")
if dropped_delta <= 0:
    raise SystemExit("no actual periodic carrier-SKB drop was observed")
expected = post_seen // every_n - immediate_seen // every_n
if dropped_delta != expected:
    raise SystemExit(f"drop delta {dropped_delta} != floor-division delta {expected}")
print(f"PASS: periodic N={every_n} seen_delta={seen_delta} dropped_delta={dropped_delta}")
PY
  then
    preflight_failure "periodic BPF counter semantics were not observed"
  fi
}

require_host_capabilities() {
  capture_capability "${STATE_DIR}/clang-version.txt" clang --version
  capture_capability "${STATE_DIR}/clang-targets.txt" clang -print-targets
  if ! grep -Eq '^[[:space:]]*bpf(el|eb)?[[:space:]]+-' "${STATE_DIR}/clang-targets.txt"; then
    capability_failure "clang does not expose a BPF target"
  fi
  record_command tc filter add bpf help
  # iproute2 treats its help text as a usage error (exit 1); its advertised
  # eBPF/direct-action grammar, not that conventional status, is the probe.
  tc filter add bpf help >"${STATE_DIR}/tc-bpf-help.txt" 2>&1 || true
  if ! grep -Fq 'eBPF use case:' "${STATE_DIR}/tc-bpf-help.txt" || ! grep -Fq 'direct-action' "${STATE_DIR}/tc-bpf-help.txt"; then
    capability_failure "tc lacks usable direct-action BPF filter support"
  fi
  if ! python3 - >"${STATE_DIR}/libbpf-capability.txt" 2>&1 <<'PY'
import ctypes
import ctypes.util

name = ctypes.util.find_library("bpf")
if not name:
    raise SystemExit("libbpf is unavailable")
library = ctypes.CDLL(name, use_errno=True)
for symbol in (
    "bpf_prog_get_fd_by_id",
    "bpf_map_get_fd_by_id",
    "bpf_prog_get_info_by_fd",
    "bpf_map_get_info_by_fd",
    "bpf_map_lookup_elem",
):
    if not hasattr(library, symbol):
        raise SystemExit(f"libbpf lacks {symbol}")
print(name)
PY
  then
    cat "${STATE_DIR}/libbpf-capability.txt" >&2 || true
    capability_failure "libbpf map-reading API is unavailable"
  fi
}

create_namespace() {
  local namespace=$1
  run_capability ip netns add "${namespace}"
  CREATED_NAMESPACES+=("${namespace}")
  run_capability ip -n "${namespace}" link set lo up
}

create_veth_pair() {
  local left=$1
  local right=$2
  run_capability ip link add "${left}" type veth peer name "${right}"
  ROOT_VETHS+=("${left}" "${right}")
}

move_to_namespace() {
  local interface=$1
  local namespace=$2
  run_capability ip link set "${interface}" netns "${namespace}"
}

start_receiver() {
  local namespace=$1
  local address=$2
  local port=$3
  local ready=$4
  local received=$5
  local log=$6
  record_command ip netns exec "${namespace}" python3 -u - "${address}" "${port}" "${ready}" "${received}"
  ip netns exec "${namespace}" python3 -u - "${address}" "${port}" "${ready}" "${received}" >"${log}" 2>&1 <<'PY' &
import pathlib
import socket
import sys

address, port, ready, received = sys.argv[1], int(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((address, port))
    ready.write_text("ready\n", encoding="ascii")
    sock.settimeout(5)
    data, _peer = sock.recvfrom(4096)
    received.write_bytes(data)
PY
  CHILD_PIDS+=("$!")
}

send_one_datagram() {
  local namespace=$1
  local address=$2
  local port=$3
  local payload=$4
  record_command ip netns exec "${namespace}" python3 - "${address}" "${port}" "${payload}"
  if ! ip netns exec "${namespace}" python3 - "${address}" "${port}" "${payload}" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(sys.argv[3].encode("ascii"), (sys.argv[1], int(sys.argv[2])))
PY
  then
    preflight_failure "cannot send directional UDP probe"
  fi
}

start_echo_server() {
  local ready=$1
  record_command ip netns exec "${NS_S}" python3 -u - "${SERVER_IP}" "${ECHO_PORT}" "${ready}"
  ip netns exec "${NS_S}" python3 -u - "${SERVER_IP}" "${ECHO_PORT}" "${ready}" >"${STATE_DIR}/udp-echo-server.log" 2>&1 <<'PY' &
import pathlib
import socket
import sys

address, port, ready = sys.argv[1], int(sys.argv[2]), pathlib.Path(sys.argv[3])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((address, port))
    ready.write_text("ready\n", encoding="ascii")
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(data, peer)
PY
  CHILD_PIDS+=("$!")
}

udp_echo_burst() {
  local label=$1
  local count=$2
  local result="${STATE_DIR}/traffic-${label}.json"
  record_command ip netns exec "${NS_C}" python3 - "${SERVER_IP}" "${ECHO_PORT}" "${count}" "${result}"
  if ! ip netns exec "${NS_C}" python3 - "${SERVER_IP}" "${ECHO_PORT}" "${count}" "${result}" <<'PY'
import json
import pathlib
import select
import socket
import struct
import sys
import time

address, port, count, result_path = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), pathlib.Path(sys.argv[4])
if count <= 0:
    raise SystemExit("echo count must be positive")
pending = set(range(count))
received = set()
rounds = 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", 0))
    for rounds in range(1, 7):
        for sequence in sorted(pending):
            sock.sendto(struct.pack("!I", sequence) + b"openppp2-netem-preflight", (address, port))
        deadline = time.monotonic() + 1.5
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([sock], [], [], remaining)
            if not readable:
                break
            data, _peer = sock.recvfrom(65535)
            if len(data) < 4:
                continue
            sequence = struct.unpack("!I", data[:4])[0]
            if sequence in pending:
                pending.remove(sequence)
                received.add(sequence)
        if not pending:
            break
result = {
    "sent": count,
    "received": len(received),
    "missing": len(pending),
    "rounds": rounds,
}
result_path.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
if pending:
    raise SystemExit(f"UDP echo did not recover {len(pending)} of {count} messages")
PY
  then
    preflight_failure "bounded UDP echo failed for ${label}"
  fi
  if ! python3 - "${result}" "${count}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = int(sys.argv[2])
if value.get("sent") != expected or value.get("received") != expected or value.get("missing") != 0:
    raise SystemExit("UDP echo result does not prove complete bounded traffic")
print(f"PASS: UDP echo sent={value['sent']} received={value['received']} rounds={value['rounds']}")
PY
  then
    preflight_failure "bounded UDP echo result was malformed"
  fi
}

loss_percent() {
  case "$1" in
    1000) printf '0.1%%' ;;
    5000) printf '0.5%%' ;;
    10000) printf '1%%' ;;
    *) preflight_failure "unsupported IID loss ppm: $1" ;;
  esac
}

apply_netem() {
  local interface=$1
  local delay_us=$2
  local jitter_us=$3
  local loss_ppm=$4
  local seed=$5
  local tc_environment=(env -i "PATH=${BASE_PATH}" LC_ALL=C LANG=C)
  local tc_command=(tc qdisc replace dev "${interface}" root netem limit 32768 delay "${delay_us}us")
  if [[ "${jitter_us}" -gt 0 ]]; then
    tc_environment+=("TC_LIB_DIR=${TC_LIB_DIR}")
    tc_command+=("${jitter_us}us" 0% distribution uniform)
  fi
  if [[ "${loss_ppm}" -gt 0 ]]; then
    tc_command+=(loss random "$(loss_percent "${loss_ppm}")")
  fi
  tc_command+=(seed "${seed}")
  run_capability ip netns exec "${NS_T}" "${tc_environment[@]}" "${tc_command[@]}"
}

compile_periodic_bpf() {
  local every_n=$1
  local directory="${STATE_DIR}/periodic-${every_n}"
  local source="${directory}/source.c"
  local runtime_object="${directory}/datapath_fixed_loss.bpf.c"
  mkdir -p "${directory}"
  cp -- "${BPF_SOURCE}" "${source}" || preflight_failure "cannot copy periodic BPF source"
  record_command clang -O2 -g -target bpf "-DPERIODIC_EVERY_N=${every_n}" -c "${source}" -o "${runtime_object}"
  if ! clang -O2 -g -target bpf "-DPERIODIC_EVERY_N=${every_n}" -c "${source}" -o "${runtime_object}" \
      >"${directory}/compiler.stdout" 2>"${directory}/compiler.stderr"; then
    cat "${directory}/compiler.stderr" >&2 || true
    capability_failure "periodic BPF compilation failed for N=${every_n}"
  fi
  [[ -s "${runtime_object}" ]] || preflight_failure "periodic BPF compiler created an empty object"
  printf '%s\n' "${runtime_object}"
}

attach_periodic_bpf() {
  local interface=$1
  local object=$2
  run_capability ip netns exec "${NS_T}" tc qdisc replace dev "${interface}" clsact
  run_capability ip netns exec "${NS_T}" tc filter replace dev "${interface}" egress protocol all chain 0 bpf da obj "${object}" sec carrier_egress
}

run_profile() {
  local profile=$1
  local delay_us=$2
  local jitter_us=$3
  local loss_ppm=$4
  local seed_client_to_server=$5
  local seed_server_to_client=$6
  local c2s_immediate="${STATE_DIR}/${profile}-client_to_server-immediate.json"
  local s2c_immediate="${STATE_DIR}/${profile}-server_to_client-immediate.json"
  local c2s_post="${STATE_DIR}/${profile}-client_to_server-post.json"
  local s2c_post="${STATE_DIR}/${profile}-server_to_client-post.json"

  # client_to_server leaves the bridge through the server-facing dt...b port.
  apply_netem "${DT_B}" "${delay_us}" "${jitter_us}" "${loss_ppm}" "${seed_client_to_server}"
  # server_to_client leaves the bridge through the client-facing dt...a port.
  apply_netem "${DT_A}" "${delay_us}" "${jitter_us}" "${loss_ppm}" "${seed_server_to_client}"
  capture_json "${NS_T}" "${DT_B}" "${c2s_immediate}"
  capture_json "${NS_T}" "${DT_A}" "${s2c_immediate}"
  assert_netem_snapshot "${c2s_immediate}" "${delay_us}" "${jitter_us}" "${seed_client_to_server}" "${loss_ppm}"
  assert_netem_snapshot "${s2c_immediate}" "${delay_us}" "${jitter_us}" "${seed_server_to_client}" "${loss_ppm}"

  # The IID profiles use this same bounded echo and deliberately do not require
  # an observed random loss in such a small sample.
  udp_echo_burst "${profile}" 64
  capture_json "${NS_T}" "${DT_B}" "${c2s_post}"
  capture_json "${NS_T}" "${DT_A}" "${s2c_post}"
  assert_netem_snapshot "${c2s_post}" "${delay_us}" "${jitter_us}" "${seed_client_to_server}" "${loss_ppm}"
  assert_netem_snapshot "${s2c_post}" "${delay_us}" "${jitter_us}" "${seed_server_to_client}" "${loss_ppm}"
  assert_netem_traffic "${c2s_immediate}" "${c2s_post}" "${loss_ppm}" 0
  assert_netem_traffic "${s2c_immediate}" "${s2c_post}" "${loss_ppm}" 0
}

run_periodic_profile() {
  local profile=$1
  local every_n=$2
  local seed_client_to_server=$3
  local seed_server_to_client=$4
  local runtime_object
  local side
  local interface
  local seed
  local qdisc_root
  local netem_immediate
  local netem_post
  local qdisc_immediate
  local qdisc_post
  local filter_pre
  local filter_immediate
  local filter_post
  local map_immediate
  local map_post

  runtime_object="$(compile_periodic_bpf "${every_n}")"
  for side in client_to_server server_to_client; do
    if [[ "${side}" == client_to_server ]]; then
      interface="${DT_B}"
      seed="${seed_client_to_server}"
    else
      interface="${DT_A}"
      seed="${seed_server_to_client}"
    fi
    qdisc_root="${STATE_DIR}/${profile}-${side}-qdisc-root.json"
    netem_immediate="${STATE_DIR}/${profile}-${side}-netem-immediate.json"
    netem_post="${STATE_DIR}/${profile}-${side}-netem-post.json"
    qdisc_immediate="${STATE_DIR}/${profile}-${side}-qdisc-immediate.json"
    qdisc_post="${STATE_DIR}/${profile}-${side}-qdisc-post.json"
    filter_pre="${STATE_DIR}/${profile}-${side}-filter-pre.json"
    filter_immediate="${STATE_DIR}/${profile}-${side}-filter-immediate.json"
    filter_post="${STATE_DIR}/${profile}-${side}-filter-post.json"
    map_immediate="${STATE_DIR}/${profile}-${side}-map-immediate.json"
    map_post="${STATE_DIR}/${profile}-${side}-map-post.json"

    apply_netem "${interface}" 37500 10000 0 "${seed}"
    capture_json "${NS_T}" "${interface}" "${qdisc_root}"
    assert_netem_snapshot "${qdisc_root}" 37500 10000 "${seed}" 0
    capture_filter_json "${NS_T}" "${interface}" "${filter_pre}"
    assert_empty_filter "${filter_pre}"
    attach_periodic_bpf "${interface}" "${runtime_object}"
    capture_json "${NS_T}" "${interface}" "${netem_immediate}"
    capture_clsact_json "${NS_T}" "${interface}" "${qdisc_immediate}"
    capture_filter_json "${NS_T}" "${interface}" "${filter_immediate}"
    assert_netem_snapshot "${netem_immediate}" 37500 10000 "${seed}" 0
    assert_periodic_clsact "${qdisc_immediate}"
    assert_periodic_filter "${filter_immediate}"
    read_bpf_counters "${filter_immediate}" "${map_immediate}"
  done

  # At least N+320 datagrams are sent; both carrier directions therefore cross
  # N despite direct-action drops and retransmitted UDP echo requests.
  udp_echo_burst "${profile}" "$((every_n + 320))"

  for side in client_to_server server_to_client; do
    if [[ "${side}" == client_to_server ]]; then
      interface="${DT_B}"
      seed="${seed_client_to_server}"
    else
      interface="${DT_A}"
      seed="${seed_server_to_client}"
    fi
    netem_immediate="${STATE_DIR}/${profile}-${side}-netem-immediate.json"
    netem_post="${STATE_DIR}/${profile}-${side}-netem-post.json"
    qdisc_immediate="${STATE_DIR}/${profile}-${side}-qdisc-immediate.json"
    qdisc_post="${STATE_DIR}/${profile}-${side}-qdisc-post.json"
    filter_immediate="${STATE_DIR}/${profile}-${side}-filter-immediate.json"
    filter_post="${STATE_DIR}/${profile}-${side}-filter-post.json"
    map_immediate="${STATE_DIR}/${profile}-${side}-map-immediate.json"
    map_post="${STATE_DIR}/${profile}-${side}-map-post.json"
    capture_json "${NS_T}" "${interface}" "${netem_post}"
    capture_clsact_json "${NS_T}" "${interface}" "${qdisc_post}"
    capture_filter_json "${NS_T}" "${interface}" "${filter_post}"
    assert_netem_snapshot "${netem_post}" 37500 10000 "${seed}" 0
    assert_periodic_clsact "${qdisc_post}"
    assert_netem_traffic "${netem_immediate}" "${netem_post}" 0 1
    assert_periodic_filter "${filter_post}"
    read_bpf_counters "${filter_post}" "${map_post}"
    assert_periodic_counters "${map_immediate}" "${map_post}" "${every_n}" "${STATE_DIR}/traffic-${profile}.json"
    run_capability ip netns exec "${NS_T}" tc qdisc del dev "${interface}" clsact
  done
}

require_host_capabilities
write_map_reader

printf -v TOKEN '%09x' "$(( ((RANDOM << 21) ^ (RANDOM << 6) ^ RANDOM ^ $$) & 0xfffffffff ))"
NS_C="dpa-c-${TOKEN}"
NS_T="dpa-t-${TOKEN}"
NS_S="dpa-s-${TOKEN}"
DC_A="dc${TOKEN}a"
DT_A="dt${TOKEN}a"
DT_B="dt${TOKEN}b"
DS_A="ds${TOKEN}a"
OC_A="oc${TOKEN}a"
OC_B="oc${TOKEN}b"
OS_A="os${TOKEN}a"
OS_B="os${TOKEN}b"
CLIENT_IP="198.18.100.2"
SERVER_IP="198.18.100.3"
ECHO_PORT=38991
TC_LIB_DIR="${STATE_DIR}/netem-tc-lib"
mkdir -p "${TC_LIB_DIR}"
cp -- "${UNIFORM_SOURCE}" "${TC_LIB_DIR}/uniform.dist" || preflight_failure "cannot copy uniform distribution into private tc library"
validate_uniform_distribution "${TC_LIB_DIR}/uniform.dist"

create_namespace "${NS_C}"
create_namespace "${NS_T}"
create_namespace "${NS_S}"
create_veth_pair "${DC_A}" "${DT_A}"
create_veth_pair "${DS_A}" "${DT_B}"
# These isolated pairs are overlay-like sentinels only; they are not bridge ports.
create_veth_pair "${OC_A}" "${OC_B}"
create_veth_pair "${OS_A}" "${OS_B}"
move_to_namespace "${DC_A}" "${NS_C}"
move_to_namespace "${DT_A}" "${NS_T}"
move_to_namespace "${DS_A}" "${NS_S}"
move_to_namespace "${DT_B}" "${NS_T}"
move_to_namespace "${OC_A}" "${NS_C}"
move_to_namespace "${OC_B}" "${NS_C}"
move_to_namespace "${OS_A}" "${NS_S}"
move_to_namespace "${OS_B}" "${NS_S}"

run_capability ip -n "${NS_T}" link add br0 type bridge
run_capability ip -n "${NS_T}" link set br0 up
for interface in "${DT_A}" "${DT_B}"; do
  run_capability ip -n "${NS_T}" link set "${interface}" master br0
  run_capability ip -n "${NS_T}" link set "${interface}" up
done
run_capability ip -n "${NS_C}" addr add "${CLIENT_IP}/24" dev "${DC_A}"
run_capability ip -n "${NS_C}" link set "${DC_A}" up
run_capability ip -n "${NS_S}" addr add "${SERVER_IP}/24" dev "${DS_A}"
run_capability ip -n "${NS_S}" link set "${DS_A}" up
for interface in "${OC_A}" "${OC_B}"; do
  run_capability ip -n "${NS_C}" link set "${interface}" up
done
for interface in "${OS_A}" "${OS_B}"; do
  run_capability ip -n "${NS_S}" link set "${interface}" up
done

capture_link_json "${NS_T}" "${DT_A}" "${STATE_DIR}/tunnel-client-port.json"
capture_link_json "${NS_T}" "${DT_B}" "${STATE_DIR}/tunnel-server-port.json"
assert_tunnel_veth_slave "${STATE_DIR}/tunnel-client-port.json" "${DT_A}"
assert_tunnel_veth_slave "${STATE_DIR}/tunnel-server-port.json" "${DT_B}"
for interface in "${DT_A}" "${DT_B}"; do
  capture_capability "${STATE_DIR}/ethtool-${interface}.txt" ip netns exec "${NS_T}" ethtool -k "${interface}"
done

capture_json "${NS_C}" "${DC_A}" "${STATE_DIR}/non-target-client-control.json"
capture_json "${NS_S}" "${DS_A}" "${STATE_DIR}/non-target-server-control.json"
capture_json "${NS_C}" "${OC_A}" "${STATE_DIR}/non-target-client-overlay-a.json"
capture_json "${NS_C}" "${OC_B}" "${STATE_DIR}/non-target-client-overlay-b.json"
capture_json "${NS_S}" "${OS_A}" "${STATE_DIR}/non-target-server-overlay-a.json"
capture_json "${NS_S}" "${OS_B}" "${STATE_DIR}/non-target-server-overlay-b.json"
assert_no_netem \
  "${STATE_DIR}/non-target-client-control.json" \
  "${STATE_DIR}/non-target-server-control.json" \
  "${STATE_DIR}/non-target-client-overlay-a.json" \
  "${STATE_DIR}/non-target-client-overlay-b.json" \
  "${STATE_DIR}/non-target-server-overlay-a.json" \
  "${STATE_DIR}/non-target-server-overlay-b.json"

# Prove the mandatory carrier direction mapping before applying netem.
start_receiver "${NS_S}" "${SERVER_IP}" 38981 "${STATE_DIR}/c2s-ready" "${STATE_DIR}/c2s-received" "${STATE_DIR}/c2s-receiver.log"
wait_for_file "${STATE_DIR}/c2s-ready" "client-to-server UDP receiver"
capture_link_json "${NS_T}" "${DT_B}" "${STATE_DIR}/c2s-dtb-before.json"
send_one_datagram "${NS_C}" "${SERVER_IP}" 38981 client-to-server
if ! wait "${CHILD_PIDS[-1]}"; then
  preflight_failure "server did not receive the client-to-server UDP probe"
fi
capture_link_json "${NS_T}" "${DT_B}" "${STATE_DIR}/c2s-dtb-after.json"
assert_tx_increased "${STATE_DIR}/c2s-dtb-before.json" "${STATE_DIR}/c2s-dtb-after.json" "${DT_B}" client_to_server

start_receiver "${NS_C}" "${CLIENT_IP}" 38982 "${STATE_DIR}/s2c-ready" "${STATE_DIR}/s2c-received" "${STATE_DIR}/s2c-receiver.log"
wait_for_file "${STATE_DIR}/s2c-ready" "server-to-client UDP receiver"
capture_link_json "${NS_T}" "${DT_A}" "${STATE_DIR}/s2c-dta-before.json"
send_one_datagram "${NS_S}" "${CLIENT_IP}" 38982 server-to-client
if ! wait "${CHILD_PIDS[-1]}"; then
  preflight_failure "client did not receive the server-to-client UDP probe"
fi
capture_link_json "${NS_T}" "${DT_A}" "${STATE_DIR}/s2c-dta-after.json"
assert_tx_increased "${STATE_DIR}/s2c-dta-before.json" "${STATE_DIR}/s2c-dta-after.json" "${DT_A}" server_to_client

start_echo_server "${STATE_DIR}/udp-echo.ready"
wait_for_file "${STATE_DIR}/udp-echo.ready" "UDP echo service"

NON_PERIODIC_PROFILES=(
  'rtt-35-fixed|17500|0|0'
  'rtt-55-fixed|27500|0|0'
  'rtt-75-fixed|37500|0|0'
  'rtt-90-fixed|45000|0|0'
  'rtt-100-fixed|50000|0|0'
  'rtt-35-j20|17500|10000|0'
  'rtt-55-j20|27500|10000|0'
  'rtt-75-j20|37500|10000|0'
  'rtt-90-j20|45000|10000|0'
  'rtt-100-j20|50000|10000|0'
  'rtt-75-j20-iid-loss-0p1|37500|10000|1000'
  'rtt-75-j20-iid-loss-0p5|37500|10000|5000'
  'rtt-75-j20-iid-loss-1p0|37500|10000|10000'
)
profile_index=0
for record in "${NON_PERIODIC_PROFILES[@]}"; do
  IFS='|' read -r profile delay_us jitter_us loss_ppm <<<"${record}"
  profile_index=$((profile_index + 1))
  run_profile "${profile}" "${delay_us}" "${jitter_us}" "${loss_ppm}" \
    "$((10000 + profile_index * 2))" "$((10001 + profile_index * 2))"
done

run_periodic_profile 'rtt-75-j20-periodic-loss-0p1' 1000 11001 11002
run_periodic_profile 'rtt-75-j20-periodic-loss-0p5' 200 11003 11004
run_periodic_profile 'rtt-75-j20-periodic-loss-1p0' 100 11005 11006

printf 'PASS: bounded datapath netem/BPF contract preflight completed; no performance campaign was run.\n'
