#!/usr/bin/env python3
"""In-tree Linux adapter for the strict datapath acceptance contract.

The adapter intentionally owns only fresh namespace execution and raw evidence
capture.  It never converts an unavailable feature into a synthetic pass: any
missing capability, process identity mismatch, boundary timeout, or malformed
raw output terminates the invocation non-zero without sealing the artifact.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))
import datapath_acceptance as acceptance


BASE_ENVIRONMENT = dict(acceptance.MINIMAL_BASE_ENVIRONMENT)
FORMAL_DURATION_SECONDS = 10
FORMAL_OMIT_SECONDS = 2
CONTROL_PORT = 20000
CONTROL_SERVER_IP = "198.18.0.1"
CONTROL_CLIENT_IP = "198.18.0.2"


class AdapterError(RuntimeError):
    """The local Linux execution environment cannot satisfy the contract."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".strict-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise AdapterError(f"cannot atomically write {path}: {error}") from None


def _atomic_json(path: Path, value: Any) -> None:
    try:
        raw = json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as error:
        raise AdapterError(f"cannot encode JSON for {path}: {error}") from None
    _atomic_bytes(path, raw)


def _write_text(path: Path, value: str) -> None:
    _atomic_bytes(path, value.encode("utf-8"))


def _run(
    arguments: list[str],
    *,
    timeout: float | None = None,
    capture_output: bool = True,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run an argument-vector command and turn failures into local evidence errors."""

    try:
        result = subprocess.run(
            arguments,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            timeout=timeout,
            cwd=cwd,
        )
    except FileNotFoundError as error:
        raise AdapterError(f"required command is unavailable: {arguments[0]} ({error})") from None
    except subprocess.TimeoutExpired as error:
        raise AdapterError(f"command timed out: {' '.join(arguments)} ({error.timeout}s)") from None
    if check and result.returncode != 0:
        stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        stdout = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or f"exit status {result.returncode}"
        raise AdapterError(f"command failed: {' '.join(arguments)}: {detail}")
    return result


def _netns_command(namespace: str, arguments: Iterable[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *arguments]


def _run_in_namespace(
    namespace: str,
    arguments: list[str],
    *,
    timeout: float | None = None,
    capture_output: bool = True,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return _run(
        _netns_command(namespace, arguments),
        timeout=timeout,
        capture_output=capture_output,
        check=check,
        cwd=cwd,
    )


def _popen(arguments: list[str], stdout_path: Path, stderr_path: Path) -> subprocess.Popen[bytes]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
    except OSError as error:
        raise AdapterError(f"cannot open process logs: {error}") from None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            close_fds=True,
        )
    except OSError as error:
        stdout_handle.close()
        stderr_handle.close()
        raise AdapterError(f"cannot launch {' '.join(arguments)}: {error}") from None
    stdout_handle.close()
    stderr_handle.close()
    return process


def _require_libbpf_capability() -> None:
    library_name = ctypes.util.find_library("bpf")
    if not library_name:
        raise AdapterError("strict v3 adapter requires libbpf for periodic BPF map evidence")
    try:
        library = ctypes.CDLL(library_name, use_errno=True)
    except OSError as error:
        raise AdapterError(f"strict v3 adapter cannot load libbpf: {error}") from None
    for symbol in (
        "bpf_prog_get_fd_by_id",
        "bpf_map_get_fd_by_id",
        "bpf_prog_get_info_by_fd",
        "bpf_map_get_info_by_fd",
        "bpf_map_lookup_elem",
    ):
        if not hasattr(library, symbol):
            raise AdapterError(f"strict v3 adapter libbpf lacks required symbol: {symbol}")


def _require_v3_host_capabilities() -> None:
    for command in ("ethtool", "clang"):
        if shutil.which(command, path=BASE_ENVIRONMENT["PATH"]) is None:
            raise AdapterError(f"strict v3 adapter requires command: {command}")
    clang_version = _run(_profile_clean_command(["clang", "--version"]))
    if not (clang_version.stdout or b"").strip():
        raise AdapterError("strict v3 adapter clang --version produced no output")
    bpf_targets = _run(_profile_clean_command(["clang", "-print-targets"]))
    if not re.search(r"(?m)^\s*bpf(?:el|eb)?\s+-", (bpf_targets.stdout or b"").decode("utf-8", errors="replace")):
        raise AdapterError("strict v3 adapter clang does not expose a BPF target")
    bpf_help = _run(_profile_clean_command(["tc", "filter", "add", "bpf", "help"]), check=False)
    bpf_help_text = ((bpf_help.stdout or b"") + (bpf_help.stderr or b"")).decode("utf-8", errors="replace")
    if "eBPF use case:" not in bpf_help_text or "direct-action" not in bpf_help_text:
        raise AdapterError("strict v3 adapter tc lacks usable BPF filter support")
    _require_libbpf_capability()


def _require_host_capabilities(manifest: Mapping[str, Any] | None = None) -> None:
    if platform.system() != "Linux":
        raise AdapterError("strict Linux adapter requires Linux")
    if os.geteuid() != 0:
        raise AdapterError("strict Linux adapter requires root")
    for command in ("ip", "tc", "iperf3", "env", "taskset", "python3"):
        if shutil.which(command, path=BASE_ENVIRONMENT["PATH"]) is None:
            raise AdapterError(f"strict Linux adapter requires command: {command}")
    if not Path("/proc").is_dir() or not Path("/proc/self/status").is_file():
        raise AdapterError("strict Linux adapter requires mounted /proc status data")
    if not Path("/sys/class/net").is_dir():
        raise AdapterError("strict Linux adapter requires network sysfs queue controls")
    if manifest is not None and acceptance.manifest_uses_network_profile(manifest):
        _require_v3_host_capabilities()


def _one_usable_cpu() -> int:
    try:
        usable = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError) as error:
        raise AdapterError(f"cannot determine usable CPU affinity: {error}") from None
    if not usable:
        raise AdapterError("no usable CPU is available for strict single-CPU affinity")
    return usable[0]


def _cpu_mask(cpu: int) -> str:
    if cpu < 0:
        raise AdapterError("CPU number must be non-negative")
    words = [0] * (cpu // 32 + 1)
    words[cpu // 32] = 1 << (cpu % 32)
    return ",".join(f"{word:08x}" for word in reversed(words))


def _safe_name(value: str, description: str, maximum: int) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value) or len(value) > maximum:
        raise AdapterError(f"invalid {description}: {value!r}")
    return value


def _namespace_names(run_uuid: str, ordinal: int) -> dict[str, str]:
    token = hashlib.sha256(f"{os.getpid()}:{run_uuid}:{ordinal}".encode("ascii")).hexdigest()[:9]
    return {
        "client_namespace": _safe_name(f"dpa-c-{token}", "client namespace", 63),
        "server_namespace": _safe_name(f"dpa-s-{token}", "server namespace", 63),
        "tunnel_namespace": _safe_name(f"dpa-t-{token}", "tunnel namespace", 63),
        "client_interface": _safe_name(f"dc{token}a", "client veth", 15),
        "tunnel_client_interface": _safe_name(f"dt{token}a", "tunnel client veth", 15),
        "server_interface": _safe_name(f"ds{token}a", "server veth", 15),
        "tunnel_server_interface": _safe_name(f"dt{token}b", "tunnel server veth", 15),
    }


def _read_proc_bytes(pid: int, leaf: str) -> bytes:
    if pid <= 0 or leaf not in {"status", "sched", "cmdline", "environ", "stat", "exe"}:
        raise AdapterError("unsafe proc identity request")
    path = Path("/proc") / str(pid) / leaf
    try:
        return path.read_bytes()
    except OSError as error:
        raise AdapterError(f"cannot read {path}: {error}") from None


def _process_start_ticks(pid: int) -> int:
    try:
        text = _read_proc_bytes(pid, "stat").decode("ascii")
    except UnicodeDecodeError as error:
        raise AdapterError(f"/proc/{pid}/stat is not ASCII: {error}") from None
    right_parenthesis = text.rfind(")")
    if right_parenthesis < 0:
        raise AdapterError(f"/proc/{pid}/stat has no command terminator")
    # The remaining fields start at field 3; starttime is field 22.
    fields = text[right_parenthesis + 2 :].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        raise AdapterError(f"/proc/{pid}/stat has no valid process start ticks")
    start_ticks = int(fields[19])
    if start_ticks <= 0:
        raise AdapterError(f"/proc/{pid}/stat has non-positive process start ticks")
    return start_ticks


def _split_proc_nul(raw: bytes, description: str) -> list[str]:
    if not raw.endswith(b"\0"):
        raise AdapterError(f"{description} is not NUL-terminated")
    values = raw[:-1].split(b"\0")
    try:
        return [value.decode("utf-8") for value in values]
    except UnicodeDecodeError as error:
        raise AdapterError(f"{description} is not valid UTF-8: {error}") from None


def _process_environment(pid: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for assignment in _split_proc_nul(_read_proc_bytes(pid, "environ"), f"/proc/{pid}/environ"):
        if "=" not in assignment:
            raise AdapterError("process environment contains a non-assignment entry")
        name, value = assignment.split("=", 1)
        if not name or name in result:
            raise AdapterError("process environment has an empty or duplicate variable")
        result[name] = value
    return result


def _observe_client_process(
    process: subprocess.Popen[bytes],
    candidate: Mapping[str, Any],
    expected_argv: list[str],
    expected_environment: Mapping[str, str],
) -> dict[str, Any]:
    if process.poll() is not None:
        raise AdapterError(f"PPP client exited before observation with status {process.returncode}")
    pid = process.pid
    start_ticks = _process_start_ticks(pid)
    try:
        executable = Path(os.readlink(Path("/proc") / str(pid) / "exe")).resolve(strict=True)
    except OSError as error:
        raise AdapterError(f"cannot resolve observed client executable: {error}") from None
    if str(executable) != candidate.get("path"):
        raise AdapterError("observed client executable path does not match prepared candidate")
    observed_hash = acceptance.sha256_file(executable)
    if observed_hash != candidate.get("sha256"):
        raise AdapterError("observed client executable hash does not match prepared candidate")
    cmdline = _split_proc_nul(_read_proc_bytes(pid, "cmdline"), f"/proc/{pid}/cmdline")
    if cmdline != expected_argv:
        raise AdapterError("observed client cmdline is not the exact required PPP argv")
    environment = _process_environment(pid)
    if environment != expected_environment:
        raise AdapterError("observed client environment is not the exact required env -i environment")
    return {
        "pid": pid,
        "start_ticks": start_ticks,
        "executable": {"path": str(executable), "sha256": observed_hash},
        "cmdline": cmdline,
        "environment": environment,
    }


def _wait_for_client_observation(
    process: subprocess.Popen[bytes],
    candidate: Mapping[str, Any],
    expected_argv: list[str],
    expected_environment: Mapping[str, str],
    timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: AdapterError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AdapterError(f"PPP client exited before observation with status {process.returncode}")
        try:
            return _observe_client_process(process, candidate, expected_argv, expected_environment)
        except AdapterError as error:
            last_error = error
            time.sleep(0.05)
    raise AdapterError(f"client process could not be observed: {last_error}")


def _write_proc_snapshot(cell: Path, pid: int, phase: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for leaf in ("status", "sched"):
        raw = _read_proc_bytes(pid, leaf)
        relative = f"cpu-{phase}-{leaf}.txt"
        path = cell / relative
        _atomic_bytes(path, raw)
        result[leaf] = {"path": relative, "sha256": _sha256(raw)}
    return result


def _read_migrations(sched: bytes, description: str) -> int:
    try:
        text = sched.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"{description} is not UTF-8: {error}") from None
    matches = re.findall(r"(?m)^(?:se\.)?nr_migrations\s*:\s*(\d+)\s*$", text)
    if len(matches) != 1:
        raise AdapterError(f"{description} must contain exactly one nr_migrations counter")
    return int(matches[0])


def _status_affinity_cpu(status: bytes, expected_pid: int) -> int:
    try:
        text = status.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"proc status is not UTF-8: {error}") from None
    pid_match = re.search(r"(?m)^Pid:\s*(\d+)\s*$", text)
    affinity_match = re.search(r"(?m)^Cpus_allowed_list:\s*([^\s]+)\s*$", text)
    if not pid_match or not affinity_match or int(pid_match.group(1)) != expected_pid:
        raise AdapterError("proc status does not match the observed client PID")
    values: list[int] = []
    for item in affinity_match.group(1).split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise AdapterError("proc status has invalid Cpus_allowed_list")
        first = int(match.group(1))
        last = int(match.group(2) or match.group(1))
        values.extend(range(first, last + 1))
    if len(values) != 1:
        raise AdapterError("client affinity is not exactly one usable CPU")
    return values[0]


def _queue_helper(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Set and read back strict RPS/XPS queue controls.")
    parser.add_argument("--queue-helper", action="store_true", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--cpu", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parsed = parser.parse_args(arguments)
    try:
        interface = _safe_name(parsed.interface, "queue interface", 15)
        mask = _cpu_mask(parsed.cpu)
        root = Path("/sys/class/net") / interface / "queues"
        if not root.is_dir():
            raise AdapterError(f"queue-control interface has no queues: {interface}")
        reads: list[dict[str, str]] = []
        for kind, pattern in (("rps", "rx-*/rps_cpus"), ("xps", "tx-*/xps_cpus")):
            paths = sorted(root.glob(pattern))
            if not paths:
                raise AdapterError(f"queue-control capability lacks {kind.upper()} files for {interface}")
            for path in paths:
                try:
                    path.write_text(mask + "\n", encoding="ascii")
                    observed = path.read_text(encoding="ascii").strip()
                except OSError as error:
                    raise AdapterError(f"queue-control write/readback failed for {path}: {error}") from None
                if not observed:
                    raise AdapterError(f"queue-control readback is empty for {path}")
                # Kernel formatting may remove leading zero groups.  Numeric
                # equality is stricter than a text-format assumption.
                try:
                    if int(observed.replace(",", ""), 16) != int(mask.replace(",", ""), 16):
                        raise AdapterError(f"queue-control readback mismatch for {path}")
                except ValueError as error:
                    raise AdapterError(f"queue-control readback is not a mask for {path}: {error}") from None
                reads.append({"kind": kind, "path": str(path), "value": observed})
        if not reads or {entry["kind"] for entry in reads} != {"rps", "xps"}:
            raise AdapterError("queue-control readback did not retain both RPS and XPS evidence")
        _atomic_json(parsed.output, {"schema": 1, "interface": interface, "cpu": parsed.cpu, "reads": reads})
        return 0
    except AdapterError as error:
        print(f"datapath strict queue helper: {error}", file=sys.stderr)
        return 2


def _capture_qdisc(cell: Path, namespace: str, interface: str, suffix: str) -> dict[str, str]:
    result = _run_in_namespace(namespace, ["tc", "qdisc", "show", "dev", interface])
    raw = result.stdout or b""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"qdisc readback is not UTF-8: {error}") from None
    if not text.strip() or re.search(r"\bnetem\b", text, flags=re.IGNORECASE):
        raise AdapterError(f"qdisc readback for {interface} is empty or contains netem")
    relative = f"qdisc-{suffix}.txt"
    _atomic_bytes(cell / relative, raw)
    return {"interface": interface, "path": relative, "sha256": _sha256(raw)}


@dataclass
class _ProfileRuntime:
    profile: dict[str, Any]
    targets: list[dict[str, Any]]
    non_targets: list[dict[str, Any]]
    uniform_distribution_source: dict[str, Any] | None = None
    installed_root_interfaces: list[str] = field(default_factory=list)
    installed_clsact_interfaces: list[str] = field(default_factory=list)


def _profile_is_periodic(profile: Mapping[str, Any]) -> bool:
    return profile.get("loss", {}).get("mode") == "periodic_carrier_skb"


def _strict_json_capture(
    cell: Path,
    namespace: str,
    arguments: list[str],
    relative: str,
    description: str,
    *,
    allow_empty_list: bool = False,
) -> dict[str, str]:
    result = _run_in_namespace(namespace, arguments)
    raw = result.stdout or b""
    if not raw.strip():
        raise AdapterError(f"{description} produced empty JSON evidence")
    try:
        document = acceptance.parse_json_bytes(raw, description)
    except acceptance.EvidenceError as error:
        raise AdapterError(str(error)) from None
    if not isinstance(document, list) or (not document and not allow_empty_list):
        requirement = "a JSON array" if allow_empty_list else "a non-empty JSON array"
        raise AdapterError(f"{description} must be {requirement}")
    destination = cell / relative
    _atomic_bytes(destination, raw)
    return _relative_hash_locator(destination, cell)


def _strict_text_capture(
    cell: Path,
    namespace: str,
    arguments: list[str],
    relative: str,
    description: str,
) -> dict[str, str]:
    result = _run_in_namespace(namespace, arguments)
    raw = result.stdout or b""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"{description} is not UTF-8: {error}") from None
    if not text.strip():
        raise AdapterError(f"{description} produced empty text evidence")
    destination = cell / relative
    _atomic_bytes(destination, raw)
    return _relative_hash_locator(destination, cell)


def _capture_v3_qdisc(
    cell: Path,
    namespace: str,
    interface: str,
    relative: str,
    description: str,
    *,
    selector: str | None = None,
    periodic_bpf_phase: str | None = None,
) -> dict[str, str]:
    arguments = ["tc", "-j", "-s", "-d", "qdisc", "show", "dev", interface]
    if selector is not None:
        if selector != "clsact" or periodic_bpf_phase not in {"immediate", "post"}:
            raise AdapterError("clsact qdisc selector is reserved for periodic BPF immediate/post evidence")
        arguments.append(selector)
    elif periodic_bpf_phase in {"immediate", "post"}:
        raise AdapterError("periodic BPF immediate/post qdisc evidence must select clsact")
    elif periodic_bpf_phase not in {None, "pre"}:
        raise AdapterError("periodic BPF qdisc phase is invalid")
    return _strict_json_capture(cell, namespace, arguments, relative, description)


def _capture_v3_filter(
    cell: Path,
    namespace: str,
    interface: str,
    relative: str,
    description: str,
    *,
    allow_empty_list: bool = False,
) -> dict[str, str]:
    return _strict_json_capture(
        cell,
        namespace,
        ["tc", "-j", "-s", "filter", "show", "dev", interface, "egress"],
        relative,
        description,
        allow_empty_list=allow_empty_list,
    )


def _capture_v3_link(
    cell: Path,
    namespace: str,
    interface: str,
    relative: str,
    description: str,
) -> dict[str, str]:
    locator = _strict_json_capture(
        cell,
        namespace,
        ["ip", "-j", "-s", "link", "show", "dev", interface],
        relative,
        description,
    )
    try:
        document = acceptance.parse_json_bytes((cell / relative).read_bytes(), description)
    except (OSError, acceptance.EvidenceError) as error:
        raise AdapterError(f"cannot validate retained {description}: {error}") from None
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise AdapterError(f"{description} must describe exactly one interface")
    if document[0].get("ifname") != interface:
        raise AdapterError(f"{description} does not identify {interface}")
    return locator


def _capture_v3_offload(
    cell: Path,
    namespace: str,
    interface: str,
    relative: str,
    description: str,
) -> dict[str, str]:
    return _strict_text_capture(cell, namespace, ["ethtool", "-k", interface], relative, description)


def _discover_point_to_point_interfaces(namespace: str) -> list[str]:
    links = _run_in_namespace(namespace, ["ip", "-j", "link", "show"])
    raw = links.stdout or b""
    if not raw.strip():
        raise AdapterError(f"point-to-point link discovery for {namespace} produced no JSON")
    try:
        document = acceptance.parse_json_bytes(raw, f"point-to-point link discovery for {namespace}")
    except acceptance.EvidenceError as error:
        raise AdapterError(str(error)) from None
    if not isinstance(document, list):
        raise AdapterError(f"point-to-point link discovery for {namespace} is not a JSON array")
    interfaces: list[str] = []
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise AdapterError(f"point-to-point link discovery for {namespace}[{index}] is not an object")
        flags = entry.get("flags")
        interface = entry.get("ifname")
        if not isinstance(flags, list) or not isinstance(interface, str):
            raise AdapterError(f"point-to-point link discovery for {namespace}[{index}] is malformed")
        if "POINTOPOINT" in flags:
            interfaces.append(_safe_name(interface, "point-to-point overlay interface", 15))
    if len(interfaces) != len(set(interfaces)):
        raise AdapterError(f"point-to-point overlay discovery duplicated an interface in {namespace}")
    return sorted(interfaces)


def _wait_for_one_point_to_point_interface(namespace: str, description: str, timeout_seconds: float = 8.0) -> str:
    deadline = time.monotonic() + timeout_seconds
    last_interfaces: list[str] = []
    while time.monotonic() < deadline:
        last_interfaces = _discover_point_to_point_interfaces(namespace)
        if len(last_interfaces) == 1:
            return last_interfaces[0]
        if len(last_interfaces) > 1:
            raise AdapterError(f"{description} has multiple point-to-point overlay interfaces")
        time.sleep(0.05)
    raise AdapterError(f"{description} point-to-point overlay was not observed (last={last_interfaces!r})")


def _source_inventory_hash(source_inventory: Mapping[str, Any], source_relative: str) -> str:
    entries = source_inventory.get("entries")
    if not isinstance(entries, list):
        raise AdapterError("validated v3 source inventory lacks entries")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == source_relative]
    if len(matches) != 1 or matches[0].get("kind") != "file":
        raise AdapterError(f"v3 source inventory lacks required file: {source_relative}")
    digest = matches[0].get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AdapterError(f"v3 source inventory hash is invalid: {source_relative}")
    return digest


def _copy_profile_source(
    cell: Path,
    source_root: Path,
    source_inventory: Mapping[str, Any],
    source_relative: str,
    destination_relative: str,
) -> dict[str, str]:
    expected_hash = _source_inventory_hash(source_inventory, source_relative)
    source = source_root / source_relative
    try:
        metadata = source.lstat()
    except OSError as error:
        raise AdapterError(f"cannot stat validated profile source {source_relative}: {error}") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AdapterError(f"validated profile source is not a regular non-symlink file: {source_relative}")
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise AdapterError(f"cannot read validated profile source {source_relative}: {error}") from None
    if _sha256(raw) != expected_hash:
        raise AdapterError(f"validated profile source drifted from v3 inventory: {source_relative}")
    destination = cell / destination_relative
    _atomic_bytes(destination, raw)
    try:
        copied = destination.read_bytes()
    except OSError as error:
        raise AdapterError(f"cannot read copied profile source {destination_relative}: {error}") from None
    if copied != raw or _sha256(copied) != expected_hash:
        raise AdapterError(f"copied profile source does not exactly match validated source: {source_relative}")
    return _relative_hash_locator(destination, cell)


class _BpfProgInfo(ctypes.Structure):
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


class _BpfMapInfo(ctypes.Structure):
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
        ("btf_id", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_id", ctypes.c_uint32),
        ("map_extra", ctypes.c_uint64),
    ]


def _libbpf() -> ctypes.CDLL:
    library_name = ctypes.util.find_library("bpf")
    if not library_name:
        raise AdapterError("strict v3 adapter requires libbpf for periodic BPF map evidence")
    try:
        library = ctypes.CDLL(library_name, use_errno=True)
    except OSError as error:
        raise AdapterError(f"strict v3 adapter cannot load libbpf: {error}") from None
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
    return library


def _libbpf_error(operation: str) -> AdapterError:
    error_number = ctypes.get_errno()
    detail = os.strerror(error_number) if error_number else "unknown libbpf error"
    return AdapterError(f"periodic BPF {operation} failed: {detail}")


def _periodic_filter_program_id(cell: Path, locator: Mapping[str, str], description: str) -> int:
    document = _retained_json(cell, locator, description)
    if not isinstance(document, list) or not document or any(not isinstance(entry, dict) for entry in document):
        raise AdapterError("periodic BPF filter evidence must be a non-empty JSON filter array")

    terse_fields = {"protocol", "pref", "kind", "chain"}
    configured: list[dict[str, Any]] = []
    terse: list[dict[str, Any]] = []
    for entry in document:
        chain = entry.get("chain")
        pref = entry.get("pref")
        if (
            entry.get("kind") != "bpf"
            or entry.get("protocol") != "all"
            or isinstance(chain, bool)
            or not isinstance(chain, int)
            or chain != 0
            or isinstance(pref, bool)
            or not isinstance(pref, int)
            or pref <= 0
            or "egress" in entry
            or "actions" in entry
        ):
            raise AdapterError("periodic BPF filter evidence contains an unexpected filter record")
        if "options" not in entry:
            if set(entry) != terse_fields:
                raise AdapterError("periodic BPF terse filter record has an unexpected shape")
            terse.append(entry)
            continue
        options = entry["options"]
        if not isinstance(options, dict) or "section" in options:
            raise AdapterError("periodic BPF configured filter options are malformed")
        configured.append(entry)
    if len(configured) != 1 or len(terse) != 1:
        raise AdapterError("periodic BPF filter evidence must contain one terse and one detailed BPF record")
    for field_name in ("protocol", "pref", "kind", "chain"):
        if terse[0].get(field_name) != configured[0].get(field_name):
            raise AdapterError("periodic BPF terse filter record does not match its detailed companion")

    options = configured[0]["options"]
    if (
        options.get("bpf_name") != acceptance.PERIODIC_CARRIER_BPF_NAME
        or options.get("direct-action") is not True
    ):
        raise AdapterError("periodic BPF configured filter is not the expected direct-action program")
    program = options.get("prog")
    if not isinstance(program, dict):
        raise AdapterError("periodic BPF configured filter lacks program details")
    program_id = program.get("id")
    if isinstance(program_id, bool) or not isinstance(program_id, int) or program_id <= 0:
        raise AdapterError("periodic BPF configured filter lacks one positive program ID")
    return program_id


def _periodic_map_counters(cell: Path, filter_locator: Mapping[str, str]) -> dict[str, int]:
    program_id = _periodic_filter_program_id(cell, filter_locator, "periodic BPF filter evidence")
    library = _libbpf()
    program_fd = library.bpf_prog_get_fd_by_id(program_id)
    if program_fd < 0:
        raise _libbpf_error(f"program lookup for ID {program_id}")
    map_fd = -1
    try:
        initial = _BpfProgInfo()
        initial_length = ctypes.c_uint32(ctypes.sizeof(initial))
        if library.bpf_prog_get_info_by_fd(program_fd, ctypes.byref(initial), ctypes.byref(initial_length)) != 0:
            raise _libbpf_error("program info lookup")
        if initial.nr_map_ids <= 0 or initial.nr_map_ids > 64:
            raise AdapterError("periodic BPF program has an invalid map count")
        map_ids = (ctypes.c_uint32 * initial.nr_map_ids)()
        info = _BpfProgInfo()
        info.nr_map_ids = initial.nr_map_ids
        info.map_ids = ctypes.addressof(map_ids)
        info_length = ctypes.c_uint32(ctypes.sizeof(info))
        if library.bpf_prog_get_info_by_fd(program_fd, ctypes.byref(info), ctypes.byref(info_length)) != 0:
            raise _libbpf_error("program map-ID lookup")
        if info.nr_map_ids != initial.nr_map_ids:
            raise AdapterError("periodic BPF program map count changed during lookup")
        matching_ids: list[int] = []
        for map_id in map_ids:
            candidate_fd = library.bpf_map_get_fd_by_id(map_id)
            if candidate_fd < 0:
                raise _libbpf_error(f"map lookup for ID {map_id}")
            try:
                map_info = _BpfMapInfo()
                map_info_length = ctypes.c_uint32(ctypes.sizeof(map_info))
                if library.bpf_map_get_info_by_fd(candidate_fd, ctypes.byref(map_info), ctypes.byref(map_info_length)) != 0:
                    raise _libbpf_error(f"map info lookup for ID {map_id}")
                map_name = bytes(map_info.name).split(b"\0", 1)[0]
                if map_name == b"counters":
                    if (
                        map_info.type != 2
                        or map_info.max_entries != 1
                        or map_info.key_size != ctypes.sizeof(ctypes.c_uint32)
                        or map_info.value_size != 16
                    ):
                        raise AdapterError("periodic BPF counters map has an unexpected ARRAY layout")
                    matching_ids.append(map_id)
            finally:
                os.close(candidate_fd)
        if len(matching_ids) != 1:
            raise AdapterError("periodic BPF program must expose exactly one counters map")
        map_fd = library.bpf_map_get_fd_by_id(matching_ids[0])
        if map_fd < 0:
            raise _libbpf_error(f"counters map lookup for ID {matching_ids[0]}")
        key = ctypes.c_uint32(0)
        values = (ctypes.c_uint64 * 2)()
        if library.bpf_map_lookup_elem(map_fd, ctypes.byref(key), ctypes.byref(values)) != 0:
            raise _libbpf_error("counters map element lookup")
        return {"global_seen": int(values[0]), "global_dropped": int(values[1])}
    finally:
        if map_fd >= 0:
            os.close(map_fd)
        os.close(program_fd)


def _retained_json(cell: Path, locator: Mapping[str, str], description: str) -> Any:
    try:
        relative = locator["path"]
        digest = locator["sha256"]
    except (KeyError, TypeError) as error:
        raise AdapterError(f"retained {description} locator is incomplete: {error}") from None
    if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AdapterError(f"retained {description} locator is malformed")
    relative_path = Path(relative)
    if relative_path.is_absolute() or relative_path.as_posix() != relative or any(part == ".." for part in relative_path.parts):
        raise AdapterError(f"retained {description} locator path is not a safe relative path")
    path = cell / relative_path
    try:
        if path.relative_to(cell) != relative_path:
            raise ValueError("locator path is not canonical")
        raw = path.read_bytes()
    except (OSError, ValueError) as error:
        raise AdapterError(f"cannot read retained {description}: {error}") from None
    if _sha256(raw) != digest:
        raise AdapterError(f"retained {description} hash does not match its locator")
    try:
        return acceptance.parse_json_bytes(raw, description)
    except acceptance.EvidenceError as error:
        raise AdapterError(f"cannot parse retained {description}: {error}") from None


def _json_contains_netem(value: Any) -> bool:
    if isinstance(value, str):
        return "netem" in value.lower()
    if isinstance(value, Mapping):
        return any(_json_contains_netem(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_json_contains_netem(nested) for nested in value)
    return False


def _capture_v3_non_netem_qdisc(
    cell: Path,
    namespace: str,
    interface: str,
    relative: str,
    description: str,
) -> dict[str, str]:
    # These snapshots prove absence of netem, not traffic volume. Some tc fq
    # statistics emit duplicate "throttled" JSON keys; capture configuration
    # only here and keep strict JSON parsing. Active netem snapshots still
    # use _capture_v3_qdisc with -s for their required counter evidence.
    locator = _strict_json_capture(
        cell, namespace, ["tc", "-j", "-d", "qdisc", "show", "dev", interface], relative, description
    )
    if _json_contains_netem(_retained_json(cell, locator, description)):
        raise AdapterError(f"{description} contains forbidden netem")
    return locator


def _write_periodic_map_counters(
    cell: Path,
    filter_locator: Mapping[str, str],
    relative: str,
) -> dict[str, str]:
    counters = _periodic_map_counters(cell, filter_locator)
    destination = cell / relative
    _atomic_json(destination, counters)
    return _relative_hash_locator(destination, cell)


def _compile_periodic_bpf(cell: Path, every_n: int) -> dict[str, Any]:
    if isinstance(every_n, bool) or not isinstance(every_n, int) or every_n <= 0:
        raise AdapterError("periodic BPF every_n must be a positive integer")
    source_path = "periodic-bpf/source.c"
    object_path = "periodic-bpf/datapath_fixed_loss.bpf.c"
    compiler_argv = [
        "clang",
        "-O2",
        "-g",
        "-target",
        "bpf",
        f"-DPERIODIC_EVERY_N={every_n}",
        "-c",
        source_path,
        "-o",
        object_path,
    ]
    version_result = _run(_profile_clean_command(["clang", "--version"]), cwd=cell, check=False)
    version_raw = version_result.stdout or b""
    _atomic_bytes(cell / "periodic-bpf/compiler-version.txt", version_raw)
    if version_result.returncode != 0 or not version_raw.strip():
        detail = ((version_result.stderr or b"") + version_raw).decode("utf-8", errors="replace").strip()
        raise AdapterError(f"periodic BPF compiler version command failed: {detail or version_result.returncode}")

    compiler_result = _run(_profile_clean_command(compiler_argv), cwd=cell, check=False)
    stdout_path = cell / "periodic-bpf/compiler.stdout"
    stderr_path = cell / "periodic-bpf/compiler.stderr"
    _atomic_bytes(stdout_path, compiler_result.stdout or b"")
    _atomic_bytes(stderr_path, compiler_result.stderr or b"")
    if compiler_result.returncode != 0:
        detail = ((compiler_result.stderr or b"") + (compiler_result.stdout or b"")).decode(
            "utf-8", errors="replace"
        ).strip()
        raise AdapterError(f"periodic BPF compiler failed: {detail or compiler_result.returncode}")
    object_file = cell / object_path
    try:
        metadata = object_file.lstat()
        object_raw = object_file.read_bytes()
    except OSError as error:
        raise AdapterError(f"periodic BPF compiler did not create its object: {error}") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or not object_raw:
        raise AdapterError("periodic BPF compiler object is not a non-empty regular file")
    return {
        "source_path": source_path,
        "object_path": object_path,
        "object": _relative_hash_locator(object_file, cell),
        "compiler": {
            "argv": compiler_argv,
            "stdout": _relative_hash_locator(stdout_path, cell),
            "stderr": _relative_hash_locator(stderr_path, cell),
            "exit_code": compiler_result.returncode,
        },
        "compiler_version": _relative_hash_locator(cell / "periodic-bpf/compiler-version.txt", cell),
    }


def _apply_profile_netem(
    cell: Path,
    namespace: str,
    interface: str,
    profile: Mapping[str, Any],
    directional_seed: int,
) -> tuple[dict[str, str], list[str]]:
    environment = acceptance.expected_netem_environment(cell, profile)
    arguments = acceptance.expected_netem_qdisc_apply_argv(cell, interface, profile, directional_seed)
    _run_in_namespace(namespace, _profile_clean_command(arguments, environment))
    return environment, arguments


def _attach_periodic_bpf(
    cell: Path,
    namespace: str,
    interface: str,
    object_path: str,
) -> tuple[list[str], list[str]]:
    clsact_argv = acceptance.expected_periodic_bpf_clsact_apply_argv(interface)
    filter_argv = acceptance.expected_periodic_bpf_filter_apply_argv(interface, object_path)
    _run_in_namespace(namespace, _profile_clean_command(clsact_argv), cwd=cell)
    _run_in_namespace(namespace, _profile_clean_command(filter_argv), cwd=cell)
    return clsact_argv, filter_argv


def _validate_periodic_counter_delta(
    cell: Path,
    immediate_locator: Mapping[str, str],
    post_locator: Mapping[str, str],
    every_n: int,
    description: str,
) -> None:
    if isinstance(every_n, bool) or not isinstance(every_n, int) or every_n <= 0:
        raise AdapterError(f"{description} has an invalid periodic interval")
    immediate = _retained_json(cell, immediate_locator, f"{description} immediate map")
    post = _retained_json(cell, post_locator, f"{description} post map")
    if not isinstance(immediate, dict) or not isinstance(post, dict):
        raise AdapterError(f"{description} map evidence is not an object")
    try:
        immediate_seen = immediate["global_seen"]
        immediate_dropped = immediate["global_dropped"]
        post_seen = post["global_seen"]
        post_dropped = post["global_dropped"]
    except KeyError as error:
        raise AdapterError(f"{description} map evidence lacks {error.args[0]}") from None
    counters = (immediate_seen, immediate_dropped, post_seen, post_dropped)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counters):
        raise AdapterError(f"{description} map evidence has invalid counters")
    seen_delta = post_seen - immediate_seen
    dropped_delta = post_dropped - immediate_dropped
    if seen_delta < every_n:
        raise AdapterError(f"{description} map evidence saw fewer than one periodic interval of formal traffic")
    if dropped_delta <= 0:
        raise AdapterError(f"{description} map evidence did not prove a periodic drop")
    expected_dropped_delta = post_seen // every_n - immediate_seen // every_n
    if dropped_delta != expected_dropped_delta:
        raise AdapterError(f"{description} map evidence does not satisfy the periodic floor boundary")


def _load_template(path: Path, description: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise AdapterError(f"cannot read {description}: {error}") from None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AdapterError(f"cannot parse {description}: {error}") from None
    if not isinstance(value, dict):
        raise AdapterError(f"{description} must be a JSON object")
    return value


def _build_cell_configs(cell: Path, source_root: Path) -> tuple[Path, Path]:
    server_template = _load_template(source_root / "tools/compat/server.json", "server compatibility config")
    client_template = _load_template(source_root / "tools/compat/client_proxy.json", "client compatibility config")
    for document, description in ((server_template, "server config"), (client_template, "client config")):
        document["concurrent"] = 1
        if document.get("concurrent") != 1:
            raise AdapterError(f"cannot force {description} concurrent=1")
    tcp = server_template.setdefault("tcp", {})
    if not isinstance(tcp, dict):
        raise AdapterError("server config tcp section is not an object")
    listen = tcp.setdefault("listen", {})
    if not isinstance(listen, dict):
        raise AdapterError("server config tcp listen section is not an object")
    listen["port"] = CONTROL_PORT
    client = client_template.setdefault("client", {})
    if not isinstance(client, dict):
        raise AdapterError("client config client section is not an object")
    client["server"] = f"ppp://{CONTROL_SERVER_IP}:{CONTROL_PORT}/"
    client.pop("mappings", None)
    if "mappings" in client:
        raise AdapterError("client config retains forbidden mappings")
    server_path = cell / "server-config.json"
    client_path = cell / "client-config.json"
    _atomic_json(server_path, server_template)
    _atomic_json(client_path, client_template)
    return server_path, client_path


def _create_topology(
    names: Mapping[str, str],
    created_namespaces: list[str],
    root_veths: list[str],
) -> None:
    """Create only the candidate control carrier; formal traffic must traverse the client TUN."""

    for namespace_key in ("client_namespace", "server_namespace", "tunnel_namespace"):
        namespace = names[namespace_key]
        _run(["ip", "netns", "add", namespace])
        created_namespaces.append(namespace)
        _run_in_namespace(namespace, ["ip", "link", "set", "lo", "up"])
    _run(
        [
            "ip",
            "link",
            "add",
            names["client_interface"],
            "type",
            "veth",
            "peer",
            "name",
            names["tunnel_client_interface"],
        ]
    )
    root_veths.extend((names["client_interface"], names["tunnel_client_interface"]))
    _run(["ip", "link", "set", names["client_interface"], "netns", names["client_namespace"]])
    _run(["ip", "link", "set", names["tunnel_client_interface"], "netns", names["tunnel_namespace"]])
    _run(
        [
            "ip",
            "link",
            "add",
            names["server_interface"],
            "type",
            "veth",
            "peer",
            "name",
            names["tunnel_server_interface"],
        ]
    )
    root_veths.extend((names["server_interface"], names["tunnel_server_interface"]))
    _run(["ip", "link", "set", names["server_interface"], "netns", names["server_namespace"]])
    _run(["ip", "link", "set", names["tunnel_server_interface"], "netns", names["tunnel_namespace"]])
    tunnel = names["tunnel_namespace"]
    _run_in_namespace(tunnel, ["ip", "link", "add", "br0", "type", "bridge"])
    _run_in_namespace(tunnel, ["ip", "link", "set", "br0", "up"])
    for key in ("tunnel_client_interface", "tunnel_server_interface"):
        _run_in_namespace(tunnel, ["ip", "link", "set", names[key], "master", "br0"])
        _run_in_namespace(tunnel, ["ip", "link", "set", names[key], "up"])
    client = names["client_namespace"]
    server = names["server_namespace"]
    # A /30 carrier leaves the server-local iperf address outside the client's
    # directly connected prefix.  The adapter installs the sole target route
    # through the client TUN only after that interface is observed.
    _run_in_namespace(client, ["ip", "addr", "add", f"{CONTROL_CLIENT_IP}/30", "dev", names["client_interface"]])
    _run_in_namespace(client, ["ip", "link", "set", names["client_interface"], "up"])
    _run_in_namespace(server, ["ip", "addr", "add", f"{CONTROL_SERVER_IP}/30", "dev", names["server_interface"]])
    _run_in_namespace(server, ["ip", "link", "set", names["server_interface"], "up"])
    _run_in_namespace(server, ["ip", "addr", "add", f"{acceptance.FORMAL_TARGET_HOST}/32", "dev", "lo"])


def _client_command(
    namespace: str,
    cpu: int,
    environment: Mapping[str, str],
    argv: list[str],
) -> list[str]:
    assignments = [f"{name}={environment[name]}" for name in sorted(environment)]
    return _netns_command(
        namespace,
        ["env", "-i", *assignments, "taskset", "-c", str(cpu), *argv],
    )


def _server_environment(identity: acceptance.CellIdentity) -> dict[str, str]:
    environment = {**BASE_ENVIRONMENT, "OPENPPP2_TAP_GSO_MERGE": "1"}
    if identity.stack == "xtcp":
        environment.update(acceptance.XTCP_CLIENT_ENVIRONMENT)
    return environment


def _server_command(
    namespace: str,
    candidate: str,
    config_path: Path,
    identity: acceptance.CellIdentity,
) -> list[str]:
    environment = _server_environment(identity)
    assignments = [f"{name}={environment[name]}" for name in sorted(environment)]
    return _netns_command(
        namespace,
        [
            "env",
            "-i",
            *assignments,
            candidate,
            "--mode=server",
            f"--config={config_path}",
            f"--tcp-stack={identity.stack}",
        ],
    )


def _wait_for_matching_acknowledgement(
    path: Path,
    request: Mapping[str, Any],
    timeout_seconds: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            raw = path.read_bytes()
            acknowledgement = acceptance.parse_json_bytes(raw, "boundary acknowledgement")
        except (OSError, acceptance.EvidenceError):
            time.sleep(0.05)
            continue
        if not isinstance(acknowledgement, dict):
            time.sleep(0.05)
            continue
        if all(acknowledgement.get(key) == request[key] for key in ("schema", "run_uuid", "cell_id", "sequence", "phase")):
            return
        time.sleep(0.05)
    raise AdapterError(f"timed out waiting for matching boundary acknowledgement: {path}")


def _write_and_ack_boundary(
    cell: Path,
    run_uuid: str,
    identity: acceptance.CellIdentity,
    sequence: int,
    phase: str,
) -> None:
    request = {
        "schema": 1,
        "run_uuid": run_uuid,
        "cell_id": identity.relative_directory(),
        "sequence": sequence,
        "phase": phase,
    }
    if set(request) != {"schema", "run_uuid", "cell_id", "sequence", "phase"}:
        raise AdapterError("internal boundary request shape is not exact")
    _atomic_json(cell / "boundary-request.json", request)
    _wait_for_matching_acknowledgement(cell / "boundary-ack.json", request)


def _profile_clean_command(arguments: Iterable[str], environment: Mapping[str, str] | None = None) -> list[str]:
    selected = BASE_ENVIRONMENT if environment is None else environment
    if not isinstance(selected, Mapping) or any(
        not isinstance(name, str) or not isinstance(value, str) for name, value in selected.items()
    ):
        raise AdapterError("profile command environment must contain only string assignments")
    assignments = [f"{name}={selected[name]}" for name in sorted(selected)]
    return ["env", "-i", *assignments, *arguments]


def _clean_command(cpu: int, arguments: Iterable[str]) -> list[str]:
    return _profile_clean_command(["taskset", "-c", str(cpu), *arguments])


def _clean_namespace_command(namespace: str, cpu: int, arguments: Iterable[str]) -> list[str]:
    return _netns_command(namespace, _clean_command(cpu, arguments))


def _client_tun_device(namespace: str, timeout_seconds: float = 8.0) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        links = _run_in_namespace(namespace, ["ip", "-o", "link", "show"])
        try:
            text = (links.stdout or b"").decode("utf-8")
        except UnicodeDecodeError as error:
            raise AdapterError(f"client link enumeration is not UTF-8: {error}") from None
        devices = re.findall(r"(?m)^\d+: ([^:@]+): <[^>]*\bPOINTOPOINT\b", text)
        if len(devices) == 1:
            return _safe_name(devices[0], "client TUN interface", 15)
        if len(devices) > 1:
            raise AdapterError("client link enumeration has multiple point-to-point TUN interfaces")
        time.sleep(0.05)
    raise AdapterError("client point-to-point TUN interface was not observed")


def _install_direct_target_route(cell: Path, namespace: str, tun_device: str) -> dict[str, str]:
    _run_in_namespace(namespace, ["ip", "route", "replace", f"{acceptance.FORMAL_TARGET_HOST}/32", "dev", tun_device])
    route = _run_in_namespace(namespace, ["ip", "route", "get", acceptance.FORMAL_TARGET_HOST])
    link = _run_in_namespace(namespace, ["ip", "-d", "link", "show", "dev", tun_device])
    route_raw = route.stdout or b""
    link_raw = link.stdout or b""
    try:
        route_text = route_raw.decode("utf-8")
        link_text = link_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdapterError(f"client TUN route evidence is not UTF-8: {error}") from None
    if not re.search(rf"(?m)^{re.escape(acceptance.FORMAL_TARGET_HOST)}\b.*\bdev\s+{re.escape(tun_device)}\b", route_text):
        raise AdapterError("client target route does not resolve through the observed TUN interface")
    if not re.search(r"\bPOINTOPOINT\b", link_text):
        raise AdapterError("observed client TUN link is not point-to-point")
    route_path = cell / "target-route.txt"
    link_path = cell / "tun-link.txt"
    _atomic_bytes(route_path, route_raw)
    _atomic_bytes(link_path, link_raw)
    return {
        "interface": tun_device,
        "route": _relative_hash_locator(route_path, cell),
        "link": _relative_hash_locator(link_path, cell),
    }


# Formal traffic uses the observed client TUN directly.
def _start_iperf_server(
    cell: Path,
    names: Mapping[str, str],
    cpu: int,
) -> subprocess.Popen[bytes]:
    server = _popen(
        _clean_namespace_command(
            names["server_namespace"],
            cpu,
            [
                "iperf3",
                "-s",
                "-B",
                acceptance.FORMAL_TARGET_HOST,
                "-p",
                str(acceptance.FORMAL_TARGET_PORT),
                "--json",
            ],
        ),
        cell / "iperf-server.stdout",
        cell / "iperf-server.stderr",
    )
    time.sleep(0.10)
    if server.poll() is not None:
        raise AdapterError(f"persistent iperf server exited during startup with status {server.returncode}")
    return server


def _run_iperf(
    cell: Path,
    names: Mapping[str, str],
    identity: acceptance.CellIdentity,
    cpu: int,
) -> tuple[dict[str, Any], bytes]:
    arguments = [
        "iperf3",
        "-4",
        "-c",
        acceptance.FORMAL_TARGET_HOST,
        "-p",
        str(acceptance.FORMAL_TARGET_PORT),
        "-t",
        str(FORMAL_DURATION_SECONDS),
        "-O",
        str(FORMAL_OMIT_SECONDS),
        "-P",
        str(identity.parallel_flows),
        "--json",
    ]
    if identity.direction == "dl":
        arguments.append("-R")
    result = _run_in_namespace(
        names["client_namespace"],
        _clean_command(cpu, arguments),
        timeout=FORMAL_DURATION_SECONDS + FORMAL_OMIT_SECONDS + 30,
    )
    raw = result.stdout or b""
    destination = cell / identity.iperf_filename()
    _atomic_bytes(destination, raw)
    try:
        parsed_document = acceptance.parse_json_bytes(raw, "raw iperf output")
        _parsed = acceptance.validate_raw_iperf(parsed_document, identity)
    except acceptance.EvidenceError as error:
        raise AdapterError(str(error)) from None
    return parsed_document, raw


def _stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _relative_hash_locator(path: Path, cell: Path) -> dict[str, str]:
    try:
        relative = path.relative_to(cell).as_posix()
        raw = path.read_bytes()
    except (ValueError, OSError) as error:
        raise AdapterError(f"cannot construct retained locator for {path}: {error}") from None
    return {"path": relative, "sha256": _sha256(raw)}


def _assert_client_alive(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        raise AdapterError(f"PPP client exited before evidence completion with status {process.returncode}")


def _execute_v3_cell(
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: acceptance.CellIdentity,
    ordinal: int,
    cpu: int,
    created_namespaces: list[str],
    created_processes: list[subprocess.Popen[bytes]],
    root_veths: list[str],
) -> None:
    if not acceptance.manifest_uses_network_profile(manifest):
        raise AdapterError("v3 cell execution requires a profile-bound manifest")
    cell = artifact_root / identity.relative_directory()
    if cell.exists():
        raise AdapterError(f"cell artifact directory already exists and cannot be reused: {cell}")
    cell.mkdir(parents=True, exist_ok=False)
    names = _namespace_names(str(manifest["run_uuid"]), ordinal)
    _create_topology(names, created_namespaces, root_veths)
    source_root = Path(str(manifest["source"]["root"]))
    server_config, client_config = _build_cell_configs(cell, source_root)
    candidate = manifest["candidate"]
    candidate_path = str(candidate["path"])
    expected_environment = acceptance.expected_cell_environment(artifact_root, identity, str(manifest["run_uuid"]))
    expected_argv = acceptance.expected_client_argv(artifact_root, manifest, identity)
    if expected_argv[2] != f"--config={client_config}" or expected_argv[4] != f"--stats-json={cell / 'stats.ndjson'}":
        raise AdapterError("prepared client argv does not resolve to the canonical cell files")

    ppp_server = _popen(
        _server_command(names["server_namespace"], candidate_path, server_config, identity),
        cell / "ppp-server.stdout",
        cell / "ppp-server.stderr",
    )
    created_processes.append(ppp_server)
    time.sleep(0.20)
    if ppp_server.poll() is not None:
        raise AdapterError(f"PPP server exited during startup with status {ppp_server.returncode}")
    client = _popen(
        _client_command(names["client_namespace"], cpu, expected_environment, expected_argv),
        cell / "ppp-client.stdout",
        cell / "ppp-client.stderr",
    )
    created_processes.append(client)
    observed = _wait_for_client_observation(client, candidate, expected_argv, expected_environment)
    client_overlay = _wait_for_one_point_to_point_interface(
        names["client_namespace"], "client namespace"
    )
    tun = _install_direct_target_route(cell, names["client_namespace"], client_overlay)

    try:
        profile = acceptance.validate_network_profile(manifest.get("network_profile"))
        campaign_seed = acceptance.validate_campaign_seed(manifest.get("netem_seed"))
        source_inventory = acceptance.read_json(artifact_root / "source-inventory.json", "validated v3 source inventory")
    except acceptance.AcceptanceError as error:
        raise AdapterError(f"prepared v3 profile evidence is invalid: {error}") from None
    if not isinstance(source_inventory, Mapping):
        raise AdapterError("validated v3 source inventory must be a JSON object")

    queue_readback_path = cell / "rps-xps.json"
    queue_command = _clean_namespace_command(
        names["client_namespace"],
        cpu,
        [
            str(Path(sys.executable).resolve()),
            "-B",
            str(Path(__file__).resolve()),
            "--queue-helper",
            "--interface",
            names["client_interface"],
            "--cpu",
            str(cpu),
            "--output",
            str(queue_readback_path),
        ],
    )
    _run(queue_command, timeout=15)
    if not queue_readback_path.is_file():
        raise AdapterError("queue-control helper did not create its readback evidence")
    qdiscs = [
        _capture_qdisc(cell, names["client_namespace"], names["client_interface"], "client-control"),
        _capture_qdisc(cell, names["server_namespace"], names["server_interface"], "server-control"),
    ]

    targets: list[dict[str, Any]] = [
        {
            "carrier_direction": "client_to_server",
            "namespace": names["tunnel_namespace"],
            "interface": names["tunnel_server_interface"],
            "interface_role": "tunnel_server_interface",
        },
        {
            "carrier_direction": "server_to_client",
            "namespace": names["tunnel_namespace"],
            "interface": names["tunnel_client_interface"],
            "interface_role": "tunnel_client_interface",
        },
    ]
    non_targets: list[dict[str, Any]] = [
        {
            "role": "client_control",
            "namespace": names["client_namespace"],
            "interface": names["client_interface"],
        },
        {
            "role": "server_control",
            "namespace": names["server_namespace"],
            "interface": names["server_interface"],
        },
        {
            "role": "client_overlay",
            "namespace": names["client_namespace"],
            "interface": client_overlay,
        },
        {
            "role": "server_target_loopback",
            "namespace": names["server_namespace"],
            "interface": "lo",
        },
    ]

    for target in targets:
        direction = str(target["carrier_direction"])
        suffix = direction.replace("_", "-")
        namespace = str(target["namespace"])
        interface = str(target["interface"])
        target["qdisc"] = {
            "pre": _capture_v3_non_netem_qdisc(
                cell,
                namespace,
                interface,
                f"underlay-{suffix}-qdisc-pre.json",
                f"{direction} target qdisc pre",
            )
        }
        target["offload"] = {
            "pre": _capture_v3_offload(
                cell,
                namespace,
                interface,
                f"underlay-{suffix}-offload-pre.txt",
                f"{direction} target offload pre",
            )
        }
    for non_target in non_targets:
        role = str(non_target["role"])
        non_target["qdisc"] = {
            "pre": _capture_v3_non_netem_qdisc(
                cell,
                str(non_target["namespace"]),
                str(non_target["interface"]),
                f"underlay-{role.replace('_', '-')}-qdisc-pre.json",
                f"{role} qdisc pre",
            )
        }

    uniform_distribution_source: dict[str, Any] | None = None
    if profile["jitter_per_direction_us"]:
        uniform_artifact = _copy_profile_source(
            cell,
            source_root,
            source_inventory,
            acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
            "netem-tc-lib/uniform.dist",
        )
        uniform_distribution_source = {
            "source_path": acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
            "source_sha256": _source_inventory_hash(
                source_inventory, acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH
            ),
            "artifact": uniform_artifact,
        }

    for target in targets:
        direction = str(target["carrier_direction"])
        directional_seed = acceptance.derive_directional_netem_seed(
            campaign_seed, profile["id"], identity, direction
        )
        environment, arguments = _apply_profile_netem(
            cell,
            str(target["namespace"]),
            str(target["interface"]),
            profile,
            directional_seed,
        )
        target["tc_environment"] = environment
        target["qdisc_apply_argv"] = arguments
        target["declared_loss"] = dict(profile["loss"])

    periodic_every_n: int | None = None
    if _profile_is_periodic(profile):
        every_n = profile["loss"].get("every_n")
        if isinstance(every_n, bool) or not isinstance(every_n, int) or every_n <= 0:
            raise AdapterError("validated periodic profile has an invalid interval")
        periodic_every_n = every_n
        for target in targets:
            direction = str(target["carrier_direction"])
            suffix = direction.replace("_", "-")
            namespace = str(target["namespace"])
            interface = str(target["interface"])
            qdisc_pre = _capture_v3_qdisc(
                cell,
                namespace,
                interface,
                f"underlay-{suffix}-periodic-bpf-qdisc-pre.json",
                f"{direction} periodic BPF qdisc pre",
                periodic_bpf_phase="pre",
            )
            qdisc_pre_document = _retained_json(cell, qdisc_pre, f"{direction} periodic BPF qdisc pre")
            if (
                not isinstance(qdisc_pre_document, list)
                or not _json_contains_netem(qdisc_pre_document)
                or any(
                    isinstance(entry, Mapping) and entry.get("kind") in {"clsact", "bpf"}
                    for entry in qdisc_pre_document
                )
            ):
                raise AdapterError(
                    f"{direction} periodic BPF qdisc pre does not prove root netem before clsact installation"
                )
            filter_pre = _capture_v3_filter(
                cell,
                namespace,
                interface,
                f"underlay-{suffix}-periodic-bpf-filter-pre.json",
                f"{direction} periodic BPF filter pre",
                allow_empty_list=True,
            )
            if _retained_json(cell, filter_pre, f"{direction} periodic BPF filter pre") != []:
                raise AdapterError(f"{direction} periodic BPF filter pre is not an empty JSON array")
            target["periodic_bpf"] = {
                "qdisc": {"pre": qdisc_pre},
                "filters": {"pre": filter_pre},
                "maps": {},
            }

        periodic_source = _copy_profile_source(
            cell,
            source_root,
            source_inventory,
            acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH,
            "periodic-bpf/source.c",
        )
        compiled = _compile_periodic_bpf(cell, periodic_every_n)
        for target in targets:
            periodic_bpf = target["periodic_bpf"]
            if not isinstance(periodic_bpf, dict):
                raise AdapterError("periodic BPF runtime evidence is malformed")
            clsact_argv, filter_argv = _attach_periodic_bpf(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                str(compiled["object_path"]),
            )
            periodic_bpf.update(
                {
                    "source": periodic_source,
                    "object": compiled["object"],
                    "compiler": compiled["compiler"],
                    "compiler_version": compiled["compiler_version"],
                    "clsact_apply_argv": clsact_argv,
                    "filter_apply_argv": filter_argv,
                }
            )

    iperf_server = _start_iperf_server(cell, names, cpu)
    created_processes.append(iperf_server)

    for target in targets:
        direction = str(target["carrier_direction"])
        suffix = direction.replace("_", "-")
        target_qdisc = target["qdisc"]
        if not isinstance(target_qdisc, dict):
            raise AdapterError("target qdisc evidence is malformed")
        immediate = _capture_v3_qdisc(
            cell,
            str(target["namespace"]),
            str(target["interface"]),
            f"underlay-{suffix}-qdisc-immediate.json",
            f"{direction} target qdisc immediate",
        )
        if not _json_contains_netem(_retained_json(cell, immediate, f"{direction} target qdisc immediate")):
            raise AdapterError(f"{direction} target qdisc immediate does not contain root netem")
        target_qdisc["immediate"] = immediate
        # Link stability is measured across traffic, after the intentional
        # netem/BPF setup. Taking this before setup compares noqueue to netem
        # and falsely reports configuration drift. The qdisc pre snapshot
        # above still proves the original no-netem state.
        target["link"] = {
            "pre": _capture_v3_link(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                f"underlay-{suffix}-link-pre.json",
                f"{direction} target link pre",
            )
        }
    for non_target in non_targets:
        role = str(non_target["role"])
        non_target_qdisc = non_target["qdisc"]
        if not isinstance(non_target_qdisc, dict):
            raise AdapterError("non-target qdisc evidence is malformed")
        non_target_qdisc["immediate"] = _capture_v3_non_netem_qdisc(
            cell,
            str(non_target["namespace"]),
            str(non_target["interface"]),
            f"underlay-{role.replace('_', '-')}-qdisc-immediate.json",
            f"{role} qdisc immediate",
        )
    before = _write_proc_snapshot(cell, observed["pid"], "before")
    affinity_cpu = _status_affinity_cpu((cell / before["status"]["path"]).read_bytes(), observed["pid"])
    if affinity_cpu != cpu:
        raise AdapterError("client process affinity readback does not equal the selected usable CPU")
    migration_before = _read_migrations((cell / before["sched"]["path"]).read_bytes(), "before proc sched")
    if periodic_every_n is not None:
        for target in targets:
            direction = str(target["carrier_direction"])
            suffix = direction.replace("_", "-")
            periodic_bpf = target["periodic_bpf"]
            if not isinstance(periodic_bpf, dict):
                raise AdapterError("periodic BPF runtime evidence is malformed")
            periodic_qdisc = periodic_bpf["qdisc"]
            periodic_filters = periodic_bpf["filters"]
            periodic_maps = periodic_bpf["maps"]
            if not all(isinstance(value, dict) for value in (periodic_qdisc, periodic_filters, periodic_maps)):
                raise AdapterError("periodic BPF evidence groups are malformed")
            periodic_qdisc["immediate"] = _capture_v3_qdisc(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                f"underlay-{suffix}-periodic-bpf-qdisc-immediate.json",
                f"{direction} periodic BPF qdisc immediate",
                selector="clsact",
                periodic_bpf_phase="immediate",
            )
            periodic_filters["immediate"] = _capture_v3_filter(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                f"underlay-{suffix}-periodic-bpf-filter-immediate.json",
                f"{direction} periodic BPF filter immediate",
            )
            periodic_maps["immediate"] = _write_periodic_map_counters(
                cell,
                periodic_filters["immediate"],
                f"underlay-{suffix}-periodic-bpf-map-immediate.json",
            )

    _write_and_ack_boundary(cell, str(manifest["run_uuid"]), identity, 1, "measurement_start")
    _assert_client_alive(client)
    if iperf_server.poll() is not None:
        raise AdapterError(f"persistent iperf server exited before formal traffic with status {iperf_server.returncode}")
    raw_iperf_document, raw_iperf = _run_iperf(cell, names, identity, cpu)
    _assert_client_alive(client)
    if iperf_server.poll() is not None:
        raise AdapterError(f"persistent iperf server exited during formal traffic with status {iperf_server.returncode}")
    _write_and_ack_boundary(cell, str(manifest["run_uuid"]), identity, 2, "measurement_end")
    _assert_client_alive(client)

    after = _write_proc_snapshot(cell, observed["pid"], "after")
    affinity_after = _status_affinity_cpu((cell / after["status"]["path"]).read_bytes(), observed["pid"])
    if affinity_after != cpu:
        raise AdapterError("client process affinity changed after formal traffic")
    migration_after = _read_migrations((cell / after["sched"]["path"]).read_bytes(), "after proc sched")
    if migration_after != migration_before:
        raise AdapterError("client process migrated during formal traffic")

    for target in targets:
        direction = str(target["carrier_direction"])
        suffix = direction.replace("_", "-")
        namespace = str(target["namespace"])
        interface = str(target["interface"])
        target_link = target["link"]
        target_offload = target["offload"]
        target_qdisc = target["qdisc"]
        if not all(isinstance(value, dict) for value in (target_link, target_offload, target_qdisc)):
            raise AdapterError("target post-traffic evidence is malformed")
        target_link["post"] = _capture_v3_link(
            cell,
            namespace,
            interface,
            f"underlay-{suffix}-link-post.json",
            f"{direction} target link post",
        )
        target_offload["post"] = _capture_v3_offload(
            cell,
            namespace,
            interface,
            f"underlay-{suffix}-offload-post.txt",
            f"{direction} target offload post",
        )
        post = _capture_v3_qdisc(
            cell,
            namespace,
            interface,
            f"underlay-{suffix}-qdisc-post.json",
            f"{direction} target qdisc post",
        )
        if not _json_contains_netem(_retained_json(cell, post, f"{direction} target qdisc post")):
            raise AdapterError(f"{direction} target qdisc post does not contain root netem")
        target_qdisc["post"] = post
    for non_target in non_targets:
        role = str(non_target["role"])
        non_target_qdisc = non_target["qdisc"]
        if not isinstance(non_target_qdisc, dict):
            raise AdapterError("non-target qdisc evidence is malformed")
        non_target_qdisc["post"] = _capture_v3_non_netem_qdisc(
            cell,
            str(non_target["namespace"]),
            str(non_target["interface"]),
            f"underlay-{role.replace('_', '-')}-qdisc-post.json",
            f"{role} qdisc post",
        )
    if periodic_every_n is not None:
        for target in targets:
            direction = str(target["carrier_direction"])
            suffix = direction.replace("_", "-")
            periodic_bpf = target["periodic_bpf"]
            if not isinstance(periodic_bpf, dict):
                raise AdapterError("periodic BPF runtime evidence is malformed")
            periodic_qdisc = periodic_bpf["qdisc"]
            periodic_filters = periodic_bpf["filters"]
            periodic_maps = periodic_bpf["maps"]
            if not all(isinstance(value, dict) for value in (periodic_qdisc, periodic_filters, periodic_maps)):
                raise AdapterError("periodic BPF evidence groups are malformed")
            periodic_qdisc["post"] = _capture_v3_qdisc(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                f"underlay-{suffix}-periodic-bpf-qdisc-post.json",
                f"{direction} periodic BPF qdisc post",
                selector="clsact",
                periodic_bpf_phase="post",
            )
            periodic_filters["post"] = _capture_v3_filter(
                cell,
                str(target["namespace"]),
                str(target["interface"]),
                f"underlay-{suffix}-periodic-bpf-filter-post.json",
                f"{direction} periodic BPF filter post",
            )
            periodic_maps["post"] = _write_periodic_map_counters(
                cell,
                periodic_filters["post"],
                f"underlay-{suffix}-periodic-bpf-map-post.json",
            )
            _validate_periodic_counter_delta(
                cell,
                periodic_maps["immediate"],
                periodic_maps["post"],
                periodic_every_n,
                f"{direction} periodic BPF",
            )

    stats_path = cell / "stats.ndjson"
    try:
        raw_stats = stats_path.read_bytes()
        locators = acceptance.find_stats_boundary_locators(
            raw_stats, str(manifest["run_uuid"]), identity.relative_directory()
        )
    except (OSError, acceptance.AcceptanceError) as error:
        raise AdapterError(f"cannot construct raw stats proof: {error}") from None

    try:
        parsed_iperf = acceptance.validate_raw_iperf(raw_iperf_document, identity)
    except acceptance.EvidenceError as error:
        raise AdapterError(str(error)) from None
    underlay_impairment: dict[str, Any] = {
        "schema": acceptance.UNDERLAY_IMPAIRMENT_SCHEMA_V3,
        "network_profile": profile,
        "campaign_seed": campaign_seed,
        "execution_index": ordinal,
        "targets": targets,
        "non_targets": non_targets,
    }
    if uniform_distribution_source is not None:
        underlay_impairment["uniform_distribution_source"] = uniform_distribution_source
    launch = {
        "schema": acceptance.LAUNCH_SCHEMA_V3,
        "run_uuid": manifest["run_uuid"],
        "role": "client",
        "cell": identity.as_dict(),
        "environment_mode": "env -i",
        "environment": expected_environment,
        "candidate": dict(candidate),
        "argv": expected_argv,
        "config": _relative_hash_locator(client_config, cell),
        "server_config": _relative_hash_locator(server_config, cell),
        "stats": {"path": "stats.ndjson"},
        "boundary_request": {"path": "boundary-request.json"},
        "boundary_acknowledgement": {"path": "boundary-ack.json"},
        "observed_process": observed,
        "cpu": {
            "affinity_cpu": cpu,
            "before": before,
            "after": after,
            "migration_before": migration_before,
            "migration_after": migration_after,
            "migration_delta": migration_after - migration_before,
        },
        "tun": tun,
        "qdisc": qdiscs,
        "rps_xps": _relative_hash_locator(queue_readback_path, cell),
        "underlay_impairment": underlay_impairment,
    }
    result = {
        "schema": acceptance.RESULT_SCHEMA_V3,
        **identity.as_dict(),
        "run_uuid": manifest["run_uuid"],
        "cell": identity.as_dict(),
        "status": "complete",
        "formal_traffic": {
            "program": "iperf3",
            "duration_seconds": FORMAL_DURATION_SECONDS,
            "omit_seconds": FORMAL_OMIT_SECONDS,
            "parallel_flows": identity.parallel_flows,
            "reverse": identity.direction == "dl",
            "json": True,
        },
        "iperf": {"path": identity.iperf_filename(), "sha256": _sha256(raw_iperf)},
        "delivered_goodput_bps": raw_iperf_document["end"][
            "sum_sent" if identity.direction == "ul" else "sum_received"
        ]["bits_per_second"],
        "delivered_payload_bytes": parsed_iperf["delivered_payload_bytes"],
        "network_profile": profile,
        "netem_seed": campaign_seed,
    }
    try:
        acceptance.validate_v3_launch_record(launch, artifact_root, manifest, identity)
    except acceptance.EvidenceError as error:
        raise AdapterError(f"raw v3 underlay evidence is invalid: {error}") from None
    # Write high-level evidence only after all raw process, CPU, queue, qdisc,
    # underlay, boundary, and iperf evidence is present and locally validated.
    if identity.stack == "xtcp":
        direct_proof = {
            "schema": acceptance.DIRECT_PROOF_SCHEMA,
            "run_uuid": manifest["run_uuid"],
            "cell": identity.as_dict(),
            "raw_stats": {
                "path": "stats.ndjson",
                "sha256": _sha256(raw_stats),
                "measurement_start": locators["measurement_start"],
                "measurement_end": locators["measurement_end"],
            },
        }
        try:
            acceptance.validate_direct_proof(
                direct_proof,
                identity,
                str(manifest["run_uuid"]),
                cell_directory_path=cell,
                delivered_payload_bytes=parsed_iperf["delivered_payload_bytes"],
                launch_observation={
                    "pid": observed["pid"],
                    "start_ticks": observed["start_ticks"],
                    "stats_path": stats_path,
                    "stats_relative_path": "stats.ndjson",
                    "final_acknowledgement": acceptance.read_json(
                        cell / "boundary-ack.json", "retained boundary acknowledgement"
                    ),
                },
            )
        except acceptance.EvidenceError as error:
            raise AdapterError(f"raw XTCP direct admission evidence is invalid: {error}") from None
        acceptance.write_json(cell / "direct-proof.json", direct_proof)
    acceptance.write_json(cell / "launch.json", launch)
    acceptance.write_json(cell / "result.json", result)


def _execute_cell(
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: acceptance.CellIdentity,
    ordinal: int,
    cpu: int,
    created_namespaces: list[str],
    created_processes: list[subprocess.Popen[bytes]],
    root_veths: list[str],
) -> None:
    if acceptance.manifest_uses_network_profile(manifest):
        _execute_v3_cell(
            artifact_root,
            manifest,
            identity,
            ordinal,
            cpu,
            created_namespaces,
            created_processes,
            root_veths,
        )
        return
    cell = artifact_root / identity.relative_directory()
    if cell.exists():
        raise AdapterError(f"cell artifact directory already exists and cannot be reused: {cell}")
    cell.mkdir(parents=True, exist_ok=False)
    names = _namespace_names(str(manifest["run_uuid"]), ordinal)
    _create_topology(names, created_namespaces, root_veths)
    source_root = Path(str(manifest["source"]["root"]))
    server_config, client_config = _build_cell_configs(cell, source_root)
    candidate = manifest["candidate"]
    candidate_path = str(candidate["path"])
    expected_environment = acceptance.expected_cell_environment(artifact_root, identity, str(manifest["run_uuid"]))
    expected_argv = acceptance.expected_client_argv(artifact_root, manifest, identity)
    if expected_argv[2] != f"--config={client_config}" or expected_argv[4] != f"--stats-json={cell / 'stats.ndjson'}":
        raise AdapterError("prepared client argv does not resolve to the canonical cell files")

    ppp_server = _popen(
        _server_command(names["server_namespace"], candidate_path, server_config, identity),
        cell / "ppp-server.stdout",
        cell / "ppp-server.stderr",
    )
    created_processes.append(ppp_server)
    # Give an immediate configuration/process failure a chance to surface; no
    # port probe is trusted as substitute evidence for the later client proof.
    time.sleep(0.20)
    if ppp_server.poll() is not None:
        raise AdapterError(f"PPP server exited during startup with status {ppp_server.returncode}")
    client = _popen(
        _client_command(names["client_namespace"], cpu, expected_environment, expected_argv),
        cell / "ppp-client.stdout",
        cell / "ppp-client.stderr",
    )
    created_processes.append(client)
    observed = _wait_for_client_observation(client, candidate, expected_argv, expected_environment)
    tun = _install_direct_target_route(cell, names["client_namespace"], _client_tun_device(names["client_namespace"]))
    iperf_server = _start_iperf_server(cell, names, cpu)
    created_processes.append(iperf_server)

    queue_readback_path = cell / "rps-xps.json"
    queue_command = _clean_namespace_command(
        names["client_namespace"],
        cpu,
        [
            str(Path(sys.executable).resolve()),
            "-B",
            str(Path(__file__).resolve()),
            "--queue-helper",
            "--interface",
            names["client_interface"],
            "--cpu",
            str(cpu),
            "--output",
            str(queue_readback_path),
        ],
    )
    _run(queue_command, timeout=15)
    if not queue_readback_path.is_file():
        raise AdapterError("queue-control helper did not create its readback evidence")
    qdiscs = [
        _capture_qdisc(cell, names["client_namespace"], names["client_interface"], "client-control"),
        _capture_qdisc(cell, names["server_namespace"], names["server_interface"], "server-control"),
    ]

    before = _write_proc_snapshot(cell, observed["pid"], "before")
    affinity_cpu = _status_affinity_cpu((cell / before["status"]["path"]).read_bytes(), observed["pid"])
    if affinity_cpu != cpu:
        raise AdapterError("client process affinity readback does not equal the selected usable CPU")
    migration_before = _read_migrations((cell / before["sched"]["path"]).read_bytes(), "before proc sched")

    _write_and_ack_boundary(cell, str(manifest["run_uuid"]), identity, 1, "measurement_start")
    _assert_client_alive(client)
    if iperf_server.poll() is not None:
        raise AdapterError(f"persistent iperf server exited before formal traffic with status {iperf_server.returncode}")
    raw_iperf_document, raw_iperf = _run_iperf(cell, names, identity, cpu)
    _assert_client_alive(client)
    if iperf_server.poll() is not None:
        raise AdapterError(f"persistent iperf server exited during formal traffic with status {iperf_server.returncode}")
    _write_and_ack_boundary(cell, str(manifest["run_uuid"]), identity, 2, "measurement_end")
    _assert_client_alive(client)

    after = _write_proc_snapshot(cell, observed["pid"], "after")
    affinity_after = _status_affinity_cpu((cell / after["status"]["path"]).read_bytes(), observed["pid"])
    if affinity_after != cpu:
        raise AdapterError("client process affinity changed after formal traffic")
    migration_after = _read_migrations((cell / after["sched"]["path"]).read_bytes(), "after proc sched")
    if migration_after != migration_before:
        raise AdapterError("client process migrated during formal traffic")

    stats_path = cell / "stats.ndjson"
    try:
        raw_stats = stats_path.read_bytes()
        locators = acceptance.find_stats_boundary_locators(
            raw_stats, str(manifest["run_uuid"]), identity.relative_directory()
        )
    except (OSError, acceptance.AcceptanceError) as error:
        raise AdapterError(f"cannot construct raw stats proof: {error}") from None

    try:
        parsed_iperf = acceptance.validate_raw_iperf(raw_iperf_document, identity)
    except acceptance.EvidenceError as error:
        raise AdapterError(str(error)) from None
    launch = {
        "schema": acceptance.LAUNCH_SCHEMA,
        "run_uuid": manifest["run_uuid"],
        "role": "client",
        "cell": identity.as_dict(),
        "environment_mode": "env -i",
        "environment": expected_environment,
        "candidate": dict(candidate),
        "argv": expected_argv,
        "config": _relative_hash_locator(client_config, cell),
        "server_config": _relative_hash_locator(server_config, cell),
        "stats": {"path": "stats.ndjson"},
        "boundary_request": {"path": "boundary-request.json"},
        "boundary_acknowledgement": {"path": "boundary-ack.json"},
        "observed_process": observed,
        "cpu": {
            "affinity_cpu": cpu,
            "before": before,
            "after": after,
            "migration_before": migration_before,
            "migration_after": migration_after,
            "migration_delta": migration_after - migration_before,
        },
        "tun": tun,
        "qdisc": qdiscs,
        "rps_xps": _relative_hash_locator(queue_readback_path, cell),
    }
    result = {
        "schema": acceptance.RESULT_SCHEMA,
        **identity.as_dict(),
        "run_uuid": manifest["run_uuid"],
        "cell": identity.as_dict(),
        "status": "complete",
        "formal_traffic": {
            "program": "iperf3",
            "duration_seconds": FORMAL_DURATION_SECONDS,
            "omit_seconds": FORMAL_OMIT_SECONDS,
            "parallel_flows": identity.parallel_flows,
            "reverse": identity.direction == "dl",
            "json": True,
        },
        "iperf": {"path": identity.iperf_filename(), "sha256": _sha256(raw_iperf)},
        "delivered_goodput_bps": raw_iperf_document["end"][
            "sum_sent" if identity.direction == "ul" else "sum_received"
        ]["bits_per_second"],
        "delivered_payload_bytes": parsed_iperf["delivered_payload_bytes"],
    }
    # Write high-level evidence only after all raw process, CPU, queue, qdisc,
    # boundary, and iperf evidence exists.  A failing cell therefore cannot
    # manufacture a complete-looking result record.
    if identity.stack == "xtcp":
        direct_proof = {
            "schema": acceptance.DIRECT_PROOF_SCHEMA,
            "run_uuid": manifest["run_uuid"],
            "cell": identity.as_dict(),
            "raw_stats": {
                "path": "stats.ndjson",
                "sha256": _sha256(raw_stats),
                "measurement_start": locators["measurement_start"],
                "measurement_end": locators["measurement_end"],
            },
        }
        try:
            acceptance.validate_direct_proof(
                direct_proof,
                identity,
                str(manifest["run_uuid"]),
                cell_directory_path=cell,
                delivered_payload_bytes=parsed_iperf["delivered_payload_bytes"],
                launch_observation={
                    "pid": observed["pid"],
                    "start_ticks": observed["start_ticks"],
                    "stats_path": stats_path,
                    "stats_relative_path": "stats.ndjson",
                    "final_acknowledgement": acceptance.read_json(
                        cell / "boundary-ack.json", "retained boundary acknowledgement"
                    ),
                },
            )
        except acceptance.EvidenceError as error:
            raise AdapterError(f"raw XTCP direct admission evidence is invalid: {error}") from None
        acceptance.write_json(cell / "direct-proof.json", direct_proof)
    # Native statistics are still retained and launch-bound, but no XTCP proof
    # belongs in a native cell.
    acceptance.write_json(cell / "launch.json", launch)
    acceptance.write_json(cell / "result.json", result)


def _cleanup(
    processes: list[subprocess.Popen[bytes]],
    namespaces: list[str],
    root_veths: list[str],
) -> None:
    for process in reversed(processes):
        _stop_process(process)
    for namespace in reversed(namespaces):
        # Only names created by this invocation are recorded here.  Namespace
        # deletion also removes the veth queue-control state; artifact files
        # are intentionally never removed.
        _run(["ip", "netns", "del", namespace], check=False)
    for interface in reversed(root_veths):
        _run(["ip", "link", "del", interface], check=False)


def _assert_adapter_root_is_fresh(artifact_root: Path) -> None:
    permitted = {
        "acceptance-manifest.json",
        "acceptance-manifest.sha256",
        "source-inventory.json",
        "launch-environment.json",
    }
    try:
        children = list(os.scandir(artifact_root))
    except OSError as error:
        raise AdapterError(f"cannot enumerate prepared artifact root: {error}") from None
    unexpected = sorted(child.name for child in children if child.name not in permitted)
    if unexpected:
        raise AdapterError(
            "strict adapter refuses a non-fresh prepared artifact root: " + ", ".join(unexpected)
        )
    for child in children:
        try:
            mode = child.stat(follow_symlinks=False).st_mode
        except OSError as error:
            raise AdapterError(f"cannot stat prepared artifact entry {child.name}: {error}") from None
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise AdapterError(f"prepared artifact entry is not a regular file: {child.name}")


def run_adapter(artifacts: Path, manifest_path: Path, candidate: Path) -> None:
    # Validate the supplied path before resolution so a final symlink cannot
    # disappear during canonicalisation.  Do not touch the host until the
    # prepared run's immutable identity has been revalidated.
    supplied_artifacts = Path(artifacts).expanduser()
    manifest = acceptance.validate_prepared_run(supplied_artifacts, manifest_path, candidate)
    _require_host_capabilities(manifest)
    try:
        artifact_root = supplied_artifacts.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise AdapterError(f"cannot resolve validated artifact root: {error}") from None
    _assert_adapter_root_is_fresh(artifact_root)
    cpu = _one_usable_cpu()
    namespaces: list[str] = []
    processes: list[subprocess.Popen[bytes]] = []
    root_veths: list[str] = []
    try:
        for ordinal, identity in enumerate(acceptance.expected_cells(), start=1):
            _execute_cell(
                artifact_root,
                manifest,
                identity,
                ordinal,
                cpu,
                namespaces,
                processes,
                root_veths,
            )
            # Each cell has its own topology and processes.  Tear down exactly
            # those objects before moving on, retaining all evidence files.
            _cleanup(processes, namespaces, root_veths)
            processes.clear()
            namespaces.clear()
            root_veths.clear()
    finally:
        _cleanup(processes, namespaces, root_veths)


def _normal_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--queue-helper" in arguments:
        return _queue_helper(arguments)
    parsed = _normal_parser().parse_args(arguments)
    try:
        run_adapter(parsed.artifacts, parsed.manifest, parsed.candidate)
        return 0
    except (AdapterError, acceptance.AcceptanceError) as error:
        print(f"datapath strict adapter: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
