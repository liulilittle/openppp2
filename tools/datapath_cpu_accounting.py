#!/usr/bin/env python3
"""Pure parsers and result accounting for Linux datapath CPU experiments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


PERF_EVENTS = ("task-clock", "context-switches", "cpu-migrations")


def parse_cpu_list(value: str) -> list[int]:
    """Expand Linux CPU-list syntax such as ``0-2,4`` into ordered CPU IDs."""
    cpus: list[int] = []
    if not value.strip():
        return cpus
    for item in value.strip().split(","):
        if not item:
            raise ValueError("empty CPU-list item")
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise ValueError(f"invalid CPU-list item: {item!r}")
        first, last = int(match.group(1)), int(match.group(2) or match.group(1))
        if last < first:
            raise ValueError(f"descending CPU range: {item!r}")
        cpus.extend(range(first, last + 1))
    if len(cpus) != len(set(cpus)):
        raise ValueError("duplicate CPU")
    return cpus


def parse_proc_stat(text: str) -> dict[int, dict[str, int]]:
    """Return the per-CPU scheduler tick counters needed for CPU accounting."""
    result: dict[int, dict[str, int]] = {}
    fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    for line in text.splitlines():
        match = re.match(r"^cpu(\d+)\s+(.+)$", line)
        if not match:
            continue
        values = match.group(2).split()
        if len(values) < len(fields):
            raise ValueError(f"short /proc/stat row for cpu{match.group(1)}")
        try:
            counters = [int(value) for value in values[: len(fields)]]
        except ValueError as error:
            raise ValueError(f"non-integer /proc/stat row for cpu{match.group(1)}") from error
        result[int(match.group(1))] = dict(zip(fields, counters))
    if not result:
        raise ValueError("no per-CPU /proc/stat rows")
    return result


def proc_stat_delta(before: str, after: str, selected_cpus: list[int], clock_ticks: int) -> dict[str, dict[str, int]]:
    """Aggregate selected/other CPU scheduler deltas and convert ticks to ns."""
    if clock_ticks <= 0:
        raise ValueError("clock ticks must be positive")
    before_rows, after_rows = parse_proc_stat(before), parse_proc_stat(after)
    if any(cpu not in before_rows or cpu not in after_rows for cpu in selected_cpus):
        raise ValueError("selected CPU missing from /proc/stat")
    buckets = {"selected": {"nonidle_ticks": 0, "system_ticks": 0, "softirq_ticks": 0}, "other": {"nonidle_ticks": 0, "system_ticks": 0, "softirq_ticks": 0}}
    for cpu in sorted(set(before_rows) & set(after_rows)):
        delta = {name: after_rows[cpu][name] - before_rows[cpu][name] for name in before_rows[cpu]}
        if any(value < 0 for value in delta.values()):
            raise ValueError(f"counter decreased for cpu{cpu}")
        bucket = "selected" if cpu in selected_cpus else "other"
        buckets[bucket]["nonidle_ticks"] += delta["user"] + delta["nice"] + delta["system"] + delta["irq"] + delta["softirq"] + delta["steal"]
        buckets[bucket]["system_ticks"] += delta["system"]
        buckets[bucket]["softirq_ticks"] += delta["softirq"]
    for bucket in buckets.values():
        for name, value in tuple(bucket.items()):
            bucket[name.replace("_ticks", "_ns")] = value * 1_000_000_000 // clock_ticks
    return buckets


def parse_softirqs(text: str) -> dict[str, list[int]]:
    """Parse NET_RX/NET_TX counters from /proc/softirqs."""
    counters: dict[str, list[int]] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(NET_RX|NET_TX):\s*(.*)$", line)
        if not match:
            continue
        try:
            counters[match.group(1)] = [int(value) for value in match.group(2).split()]
        except ValueError as error:
            raise ValueError(f"invalid {match.group(1)} softirq counter") from error
    if set(counters) != {"NET_RX", "NET_TX"}:
        raise ValueError("NET_RX/NET_TX missing from /proc/softirqs")
    return counters


def softirq_delta(before: str, after: str, selected_cpus: list[int]) -> dict[str, dict[str, int]]:
    """Return NET_RX/NET_TX deltas split between selected and other CPUs."""
    before_rows, after_rows = parse_softirqs(before), parse_softirqs(after)
    result: dict[str, dict[str, int]] = {}
    for event in ("NET_RX", "NET_TX"):
        if len(before_rows[event]) != len(after_rows[event]):
            raise ValueError(f"{event} CPU count changed")
        if any(cpu >= len(before_rows[event]) for cpu in selected_cpus):
            raise ValueError(f"selected CPU missing from {event}")
        deltas = [end - start for start, end in zip(before_rows[event], after_rows[event])]
        if any(value < 0 for value in deltas):
            raise ValueError(f"{event} counter decreased")
        result[event] = {
            "selected": sum(deltas[cpu] for cpu in selected_cpus),
            "other": sum(value for cpu, value in enumerate(deltas) if cpu not in selected_cpus),
        }
    return result


def parse_perf_csv(text: str) -> dict[str, int | float]:
    """Parse `perf stat -x,` counters without relying on PMU-only events."""
    values: dict[str, int | float] = {}
    for line in text.splitlines():
        columns = [column.strip() for column in line.split(",")]
        event = next((column for column in columns if column in PERF_EVENTS), None)
        if event is None:
            continue
        raw_value = columns[0].replace(" ", "")
        if raw_value.startswith("<") or not raw_value:
            raise ValueError(f"perf did not count {event}")
        try:
            value = float(raw_value)
        except ValueError as error:
            raise ValueError(f"invalid perf value for {event}: {raw_value!r}") from error
        if value < 0:
            raise ValueError(f"negative perf value for {event}")
        if event == "task-clock":
            values["task_clock_ns"] = values.get("task_clock_ns", 0) + round(value * 1_000_000)
            if columns[-1] == "CPUs utilized":
                try:
                    values["cpus_utilized"] = float(columns[-2])
                except (IndexError, ValueError):
                    raise ValueError("invalid CPUs utilized value") from None
        else:
            name = event.replace("-", "_")
            values[name] = values.get(name, 0) + round(value)
    missing = {"task_clock_ns", "context_switches", "cpu_migrations"} - set(values)
    if missing:
        raise ValueError(f"perf counters missing: {','.join(sorted(missing))}")
    return values


def iperf_payload_bytes(iperf: dict[str, Any], direction: str) -> int:
    aggregate_key = "sum_sent" if direction == "ul" else "sum_received"
    aggregate = iperf.get("end", {}).get(aggregate_key)
    if not isinstance(aggregate, dict) or not isinstance(aggregate.get("bytes"), int) or aggregate["bytes"] <= 0:
        raise ValueError(f"iperf {aggregate_key}.bytes missing or non-positive")
    return aggregate["bytes"]


def _read(path: Path | None) -> str:
    if path is None or not path.is_file():
        raise ValueError(f"missing raw file: {path}")
    return path.read_text(encoding="utf-8")


def _per_byte(value: int | None, payload_bytes: int) -> float | None:
    return None if value is None else value / payload_bytes


def unavailable_measurement(profile: str, affinity_cpus: list[int]) -> dict[str, Any]:
    return {
        "profile": profile,
        "status": "unavailable",
        "cpu_list": affinity_cpus,
        "affinity_verified": False,
        "formal_interval": None,
        "payload_bytes": None,
        "raw_files": {},
        "process_perf": None,
        "iperf_perf": None,
        "system_perf": None,
        "proc_stat": None,
        "softirqs": None,
        "migration_warning": {
            "present": False,
            "reasons": [],
        },
    }


def build_measurement(*, profile: str, affinity_cpus: list[int], affinity_verified: bool, collection_verified: bool, formal_start_ns: int | None, formal_end_ns: int | None, payload_bytes: int | None, clock_ticks: int | None, raw_files: dict[str, str], raw_dir: Path, process_perf_enabled: bool, system_perf_enabled: bool) -> dict[str, Any]:
    """Build the stable result object; report collection failures without hiding them."""
    if profile == "none":
        return unavailable_measurement(profile, affinity_cpus)
    result: dict[str, Any] = {
        "profile": profile,
        "status": "failed",
        "cpu_list": affinity_cpus,
        "affinity_verified": affinity_verified,
        "formal_interval": {"start_monotonic_ns": formal_start_ns, "end_monotonic_ns": formal_end_ns, "duration_ns": None},
        "payload_bytes": payload_bytes,
        "raw_files": raw_files,
        "process_perf": None,
        "iperf_perf": None,
        "system_perf": None,
        "proc_stat": None,
        "softirqs": None,
        "migration_warning": {
            "present": False,
            "reasons": [],
        },
    }
    try:
        if not affinity_verified:
            raise ValueError("CPU affinity was not fully verified")
        if not collection_verified:
            raise ValueError("CPU formal-window snapshot collection failed")
        if payload_bytes is None or payload_bytes <= 0:
            raise ValueError("payload bytes unavailable")
        if formal_start_ns is None or formal_end_ns is None or formal_end_ns <= formal_start_ns:
            raise ValueError("formal interval unavailable")
        if clock_ticks is None:
            raise ValueError("clock tick rate unavailable")
        result["formal_interval"]["duration_ns"] = formal_end_ns - formal_start_ns
        proc = proc_stat_delta(_read(raw_dir / raw_files.get("proc_stat_start", "")), _read(raw_dir / raw_files.get("proc_stat_end", "")), affinity_cpus, clock_ticks)
        for bucket in proc.values():
            for key in ("nonidle_ns", "system_ns", "softirq_ns"):
                bucket[f"{key}_per_payload_byte"] = _per_byte(bucket[key], payload_bytes)
        result["proc_stat"] = proc
        softirqs = softirq_delta(_read(raw_dir / raw_files.get("softirqs_start", "")), _read(raw_dir / raw_files.get("softirqs_end", "")), affinity_cpus)
        result["softirqs"] = softirqs
        if process_perf_enabled:
            process = parse_perf_csv(_read(raw_dir / raw_files.get("process_perf", "")))
            for key in ("task_clock_ns", "context_switches", "cpu_migrations"):
                process[f"{key}_per_payload_byte"] = _per_byte(process[key], payload_bytes)
            result["process_perf"] = process
        if profile == "client-single-core":
            iperf = parse_perf_csv(_read(raw_dir / raw_files.get("iperf_perf", "")))
            for key in ("task_clock_ns", "context_switches", "cpu_migrations"):
                iperf[f"{key}_per_payload_byte"] = _per_byte(iperf[key], payload_bytes)
            result["iperf_perf"] = iperf
        if system_perf_enabled:
            system = parse_perf_csv(_read(raw_dir / raw_files.get("system_perf", "")))
            for key in ("task_clock_ns", "context_switches", "cpu_migrations"):
                system[f"{key}_per_payload_byte"] = _per_byte(system[key], payload_bytes)
            result["system_perf"] = system
        warning_reasons = []
        if softirqs["NET_RX"]["other"] > 0:
            warning_reasons.append("other_cpu_net_rx")
        if softirqs["NET_TX"]["other"] > 0:
            warning_reasons.append("other_cpu_net_tx")
        result["migration_warning"] = {
            "present": bool(warning_reasons),
            "reasons": warning_reasons,
        }
        result["status"] = "measured"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        result["error"] = str(error)
    return result
