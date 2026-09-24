#!/usr/bin/env python3
"""Transactional IRQ/RPS/XPS isolation evidence for Linux datapath tests."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any


def parse_cpulist(value: str) -> list[int]:
    cpus: list[int] = []
    for item in value.strip().split(",") if value.strip() else []:
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise ValueError(f"invalid CPU-list item: {item!r}")
        first, last = int(match.group(1)), int(match.group(2) or match.group(1))
        if last < first:
            raise ValueError(f"descending CPU range: {item!r}")
        cpus.extend(range(first, last + 1))
    if not cpus:
        raise ValueError("CPU-list is empty")
    if len(cpus) != len(set(cpus)):
        raise ValueError("CPU-list contains duplicate CPUs")
    return sorted(cpus)


def normalize_cpulist(value: str) -> str:
    cpus = parse_cpulist(value)
    ranges: list[str] = []
    first = previous = cpus[0]
    for cpu in cpus[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(first) if first == previous else f"{first}-{previous}")
        first = previous = cpu
    ranges.append(str(first) if first == previous else f"{first}-{previous}")
    return ",".join(ranges)


def cpumask_for_cpu(cpu: int) -> str:
    if cpu < 0:
        raise ValueError("CPU must be non-negative")
    groups = [0] * (cpu // 32 + 1)
    groups[cpu // 32] = 1 << (cpu % 32)
    return ",".join(f"{group:08x}" for group in reversed(groups))


def normalize_cpumask(value: str) -> str:
    groups = value.strip().lower().replace(" ", "").split(",")
    if not groups or any(not re.fullmatch(r"[0-9a-f]{1,8}", group) for group in groups):
        raise ValueError(f"invalid CPU mask: {value!r}")
    while len(groups) > 1 and int(groups[0], 16) == 0:
        groups.pop(0)
    return ",".join(f"{int(group, 16):08x}" for group in groups)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _setting(path: Path, kind: str, device: str, *, effective_path: Path | None = None) -> dict[str, Any]:
    raw = _read(path)
    entry: dict[str, Any] = {
        "device": device,
        "kind": kind,
        "path": str(path),
        "original_raw": raw,
        "original": normalize_cpumask(raw),
    }
    if effective_path is not None:
        entry["effective_path"] = str(effective_path)
        entry["original_effective_raw"] = _read(effective_path)
        entry["original_effective"] = normalize_cpumask(entry["original_effective_raw"])
    return entry


def _device_irqs(device: str, sys_root: Path, proc_root: Path) -> list[int]:
    irqs: set[int] = set()
    msi_dir = sys_root / "class" / "net" / device / "device" / "msi_irqs"
    if msi_dir.is_dir():
        irqs.update(int(path.name) for path in msi_dir.iterdir() if path.name.isdigit())
    interrupts = proc_root / "interrupts"
    if interrupts.is_file():
        for line in interrupts.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"\s*(\d+):", line)
            if match and re.search(rf"(?<![\w-]){re.escape(device)}(?![\w-])", line):
                irqs.add(int(match.group(1)))
    return sorted(irqs)


def snapshot(
    state_path: Path,
    devices: list[str],
    target_cpu: int,
    *,
    persistent_devices: set[str] | None = None,
    sys_root: Path = Path("/sys"),
    proc_root: Path = Path("/proc"),
    namespace: str | None = None,
) -> dict[str, Any]:
    persistent_devices = persistent_devices or set()
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "namespace": namespace,
        "target_cpu": target_cpu,
        "target_cpulist": str(target_cpu),
        "target_mask": cpumask_for_cpu(target_cpu),
        "devices": {},
        "settings": [],
        "phases": {},
    }
    errors: list[str] = []
    for device in devices:
        net_path = sys_root / "class" / "net" / device
        device_entry: dict[str, Any] = {
            "present": net_path.exists(),
            "persistent": device in persistent_devices,
            "queue_files": [],
            "rps_files": 0,
            "xps_files": 0,
            "queue_support": "unsupported",
            "irqs": [],
            "irq_status": "not_applicable",
        }
        evidence["devices"][device] = device_entry
        if not net_path.exists():
            errors.append(f"device missing: {device}")
            continue
        for kind, pattern in (("rps", "queues/rx-*/rps_cpus"), ("xps", "queues/tx-*/xps_cpus")):
            for path in sorted(net_path.glob(pattern)):
                try:
                    entry = _setting(path, kind, device)
                except (OSError, ValueError) as error:
                    errors.append(f"{path}: {error}")
                    continue
                evidence["settings"].append(entry)
                device_entry["queue_files"].append(str(path))
                device_entry[f"{kind}_files"] += 1
        if device_entry["queue_files"]:
            device_entry["queue_support"] = "supported"
        for irq in _device_irqs(device, sys_root, proc_root):
            affinity = proc_root / "irq" / str(irq) / "smp_affinity"
            effective = proc_root / "irq" / str(irq) / "effective_affinity"
            try:
                entry = _setting(affinity, "irq_affinity", device, effective_path=effective)
            except (OSError, ValueError) as error:
                errors.append(f"IRQ {irq}: {error}")
                continue
            entry["irq"] = irq
            evidence["settings"].append(entry)
            device_entry["irqs"].append(irq)
        if device_entry["irqs"]:
            device_entry["irq_status"] = "applicable"
    evidence["phases"]["snapshot"] = {
        "status": "fail" if errors else "pass",
        "errors": errors,
        "timestamp_monotonic_ns": time.monotonic_ns(),
    }
    _atomic_json(state_path, evidence)
    return evidence


def _load(state_path: Path) -> dict[str, Any]:
    return json.loads(state_path.read_text(encoding="utf-8"))


def apply(state_path: Path) -> dict[str, Any]:
    evidence = _load(state_path)
    target = evidence["target_mask"]
    errors: list[str] = []
    for entry in evidence["settings"]:
        path = Path(entry["path"])
        try:
            current = normalize_cpumask(_read(path))
            if current != entry["original"]:
                entry["apply"] = {"status": "conflict_external_change", "observed": current}
                errors.append(f"external change before apply: {path}")
                continue
            path.write_text(target + "\n", encoding="utf-8")
            applied = normalize_cpumask(_read(path))
            entry["apply"] = {"status": "applied" if applied == target else "readback_mismatch", "observed": applied}
            if applied != target:
                errors.append(f"apply readback mismatch: {path}")
        except (OSError, ValueError) as error:
            entry["apply"] = {"status": "error", "error": str(error)}
            errors.append(f"apply failed: {path}: {error}")
    evidence["phases"]["apply"] = {
        "status": "fail" if errors else "pass",
        "errors": errors,
        "timestamp_monotonic_ns": time.monotonic_ns(),
    }
    _atomic_json(state_path, evidence)
    return evidence


def readback(state_path: Path) -> dict[str, Any]:
    evidence = _load(state_path)
    target = evidence["target_mask"]
    errors: list[str] = []
    for entry in evidence["settings"]:
        path = Path(entry["path"])
        try:
            observed = normalize_cpumask(_read(path))
            result: dict[str, Any] = {"observed": observed, "target_match": observed == target}
            if observed != target:
                errors.append(f"target mismatch: {path}")
            if entry["kind"] == "irq_affinity":
                effective_path = Path(entry["effective_path"])
                effective = normalize_cpumask(_read(effective_path))
                result.update(effective=effective, effective_target_match=effective == target)
                if effective != target:
                    errors.append(f"effective IRQ mismatch: {effective_path}")
            result["status"] = "pass" if result["target_match"] and result.get("effective_target_match", True) else "fail"
        except (OSError, ValueError) as error:
            result = {"status": "error", "error": str(error)}
            errors.append(f"readback failed: {path}: {error}")
        entry["readback"] = result
    for device_name, device in evidence["devices"].items():
        if device["irq_status"] == "not_applicable":
            device["irq_qualification"] = {"status": "pass", "result": "not_applicable"}
        else:
            irq_entries = [entry for entry in evidence["settings"] if entry["device"] == device_name and entry["kind"] == "irq_affinity"]
            passed = bool(irq_entries) and all(entry.get("readback", {}).get("status") == "pass" for entry in irq_entries)
            device["irq_qualification"] = {"status": "pass" if passed else "fail", "result": "applicable"}
    evidence["phases"]["readback"] = {
        "status": "fail" if errors else "pass",
        "errors": errors,
        "timestamp_monotonic_ns": time.monotonic_ns(),
    }
    _atomic_json(state_path, evidence)
    return evidence


def restore(state_path: Path, *, sys_root: Path = Path("/sys")) -> dict[str, Any]:
    evidence = _load(state_path)
    target = evidence["target_mask"]
    errors: list[str] = []
    for entry in reversed(evidence["settings"]):
        path = Path(entry["path"])
        device = evidence["devices"][entry["device"]]
        net_path = sys_root / "class" / "net" / entry["device"]
        try:
            if not path.exists():
                if not net_path.exists() and not device["persistent"]:
                    entry["restore"] = {"status": "no_persistent_leak"}
                    continue
                entry["restore"] = {"status": "missing_required_device" if device["persistent"] else "missing_setting"}
                errors.append(f"restore path missing: {path}")
                continue
            current = normalize_cpumask(_read(path))
            if current == entry["original"]:
                restore_result: dict[str, Any] = {"status": "already_original", "observed": current}
                if entry["kind"] == "irq_affinity":
                    effective = normalize_cpumask(_read(Path(entry["effective_path"])))
                    restore_result["effective"] = effective
                    restore_result["effective_original_match"] = effective == entry["original_effective"]
                    if not restore_result["effective_original_match"]:
                        restore_result["status"] = "effective_readback_mismatch"
                        errors.append(f"IRQ effective affinity not restored: {entry['effective_path']}")
                entry["restore"] = restore_result
                continue
            if current != target:
                entry["restore"] = {"status": "conflict_external_change", "observed": current}
                errors.append(f"external change blocks restore: {path}")
                continue
            path.write_text(entry["original_raw"] + "\n", encoding="utf-8")
            restored = normalize_cpumask(_read(path))
            passed = restored == entry["original"]
            restore_result: dict[str, Any] = {"observed": restored}
            if entry["kind"] == "irq_affinity":
                effective_path = Path(entry["effective_path"])
                restored_effective = normalize_cpumask(_read(effective_path))
                restore_result["effective"] = restored_effective
                restore_result["effective_original_match"] = restored_effective == entry["original_effective"]
                passed = passed and restore_result["effective_original_match"]
            restore_result["status"] = "restored" if passed else "readback_mismatch"
            entry["restore"] = restore_result
            if not passed:
                errors.append(f"restore readback mismatch: {path}")
        except (OSError, ValueError) as error:
            entry["restore"] = {"status": "error", "error": str(error)}
            errors.append(f"restore failed: {path}: {error}")
    evidence["phases"]["restore"] = {
        "status": "fail" if errors else "pass",
        "errors": errors,
        "timestamp_monotonic_ns": time.monotonic_ns(),
    }
    _atomic_json(state_path, evidence)
    return evidence


def capture_threads(
    output: Path,
    target_cpu: int,
    processes: list[str],
    *,
    allow_terminated_processes: set[str] | None = None,
) -> dict[str, Any]:
    expected = str(target_cpu)
    records: list[dict[str, Any]] = []
    process_records: list[dict[str, Any]] = []
    errors: list[str] = []
    allow_terminated_processes = allow_terminated_processes or set()
    for process in processes:
        role, separator, pid_text = process.partition("=")
        if not separator or not pid_text.isdigit():
            raise ValueError(f"invalid process descriptor: {process!r}")
        pid = int(pid_text)
        task_dir = Path("/proc") / str(pid) / "task"
        tids = sorted((path for path in task_dir.glob("[0-9]*") if path.name.isdigit()), key=lambda path: int(path.name))
        process_state = None
        try:
            process_state = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8").rpartition(")")[2].split()[0]
        except (OSError, IndexError):
            pass
        if process in allow_terminated_processes and (process_state == "Z" or not tids):
            process_records.append({
                "role": role,
                "pid": pid,
                "status": "terminated_after_interval",
                "affinity": "not_applicable",
                "qualification": "pass",
                "thread_count": 0,
            })
            continue
        if not tids:
            errors.append(f"{role} process has no TIDs: {pid}")
        process_records.append({
            "role": role,
            "pid": pid,
            "status": "alive",
            "affinity": "verified",
            "qualification": "pass",
            "thread_count": len(tids),
        })
        for task in tids:
            entry: dict[str, Any] = {"role": role, "pid": pid, "tid": int(task.name)}
            try:
                status = (task / "status").read_text(encoding="utf-8")
                match = re.search(r"^Cpus_allowed_list:\s*(\S+)\s*$", status, re.MULTILINE)
                if not match:
                    raise ValueError("Cpus_allowed_list missing")
                raw = match.group(1)
                normalized = normalize_cpulist(raw)
                entry.update(cpus_allowed_list_raw=raw, cpus_allowed_list=normalized, target_match=normalized == expected)
                if normalized != expected:
                    errors.append(f"{role} TID {task.name} allowed {normalized}, expected {expected}")
            except (OSError, ValueError) as error:
                entry["error"] = str(error)
                entry["target_match"] = False
                errors.append(f"{role} TID {task.name}: {error}")
            records.append(entry)
    evidence = {
        "target_cpu": target_cpu,
        "target_cpulist": expected,
        "timestamp_monotonic_ns": time.monotonic_ns(),
        "status": "fail" if errors else "pass",
        "errors": errors,
        "processes": process_records,
        "threads": records,
    }
    _atomic_json(output, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--state", type=Path, required=True)
    snapshot_parser.add_argument("--target-cpu", type=int, required=True)
    snapshot_parser.add_argument("--device", action="append", required=True)
    snapshot_parser.add_argument("--persistent-device", action="append", default=[])
    snapshot_parser.add_argument("--namespace")
    for command in ("apply", "readback", "restore"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--state", type=Path, required=True)
    threads_parser = subparsers.add_parser("threads")
    threads_parser.add_argument("--output", type=Path, required=True)
    threads_parser.add_argument("--target-cpu", type=int, required=True)
    threads_parser.add_argument("--process", action="append", required=True)
    threads_parser.add_argument("--allow-terminated-process", action="append", default=[])
    arguments = parser.parse_args()
    if arguments.command == "snapshot":
        result = snapshot(arguments.state, arguments.device, arguments.target_cpu, persistent_devices=set(arguments.persistent_device), namespace=arguments.namespace)
    elif arguments.command == "apply":
        result = apply(arguments.state)
    elif arguments.command == "readback":
        result = readback(arguments.state)
    elif arguments.command == "restore":
        result = restore(arguments.state)
    else:
        result = capture_threads(
            arguments.output,
            arguments.target_cpu,
            arguments.process,
            allow_terminated_processes=set(arguments.allow_terminated_process),
        )
        return 0 if result["status"] == "pass" else 1
    return 0 if result["phases"][arguments.command]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
