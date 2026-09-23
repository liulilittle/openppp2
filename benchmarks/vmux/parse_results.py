#!/usr/bin/env python3
"""Validate VMUX result files and print a scenario summary as JSON."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys


TOP_LEVEL = {
    "schema_version",
    "scenario",
    "duration_seconds",
    "environment",
    "config",
    "metrics",
    "runtime_state",
}
TOP_ALLOWED = TOP_LEVEL | {"iperf", "endpoints", "reorder_limits"}
ENVIRONMENT_FIELDS = {"architecture", "kernel", "cpu", "git_commit", "fingerprint"}
CONFIG_FIELDS = {"mux_mode", "flows", "netem_profile", "fingerprint"}
RUNTIME_FIELDS = {"requested_mode", "effective_mode", "fallback_reason"}
METRICS = {
    "throughput_mbps": (float, int),
    "p50_latency_ms": (float, int),
    "p99_latency_ms": (float, int),
    "reorder_depth": (int,),
    "buffered_bytes": (int,),
    "active_links": (int,),
    "disconnects": (int,),
}
OPTIONAL_METRICS = {"reorder_entries": (int,)}
ENDPOINT_FIELDS = {"platform", "device_class", "device_id", "git_commit"}
SCENARIOS = {
    "off-one-flow": ("off", 1),
    "compat-one-flow": ("compat", 1),
    "flow-one-flow": ("flow", 1),
    "compat-eight-flows": ("compat", 8),
    "flow-eight-flows": ("flow", 8),
    "balance-eight-flows": ("balance", 8),
    "carrier-delay": ("balance", 8),
    "carrier-loss": ("balance", 8),
    "carrier-removal": ("balance", 8),
    "turbo-churn": ("flow", 8),
}


def fail(path, message):
    raise ValueError(f"{path}: {message}")


def require_object(path, value, fields, allowed=None):
    if not isinstance(value, dict):
        fail(path, "must be an object")
    missing = fields - value.keys()
    if missing:
        fail(path, "missing " + ", ".join(sorted(missing)))
    unexpected = value.keys() - (allowed if allowed is not None else fields)
    if unexpected:
        fail(path, "additional properties: " + ", ".join(sorted(unexpected)))


def require_string(path, value):
    if not isinstance(value, str):
        fail(path, "must be a string")


def validate(path, result):
    require_object(path, result, TOP_LEVEL, TOP_ALLOWED)
    if type(result["schema_version"]) is not int or result["schema_version"] != 1:
        fail(path, "unsupported schema_version")
    require_string(path, result["scenario"])
    if not result["scenario"]:
        fail(path, "scenario must not be empty")
    duration = result["duration_seconds"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration <= 0
    ):
        fail(path, "duration_seconds must be positive")

    environment_base_fields = {"architecture", "kernel", "cpu", "git_commit"}
    require_object(path, result["environment"], ENVIRONMENT_FIELDS)
    for name in ENVIRONMENT_FIELDS:
        require_string(path, result["environment"][name])
        if not result["environment"][name]:
            fail(path, f"environment.{name} must not be empty")
    fingerprint_source = {
        name: result["environment"][name] for name in environment_base_fields
    }
    expected_fingerprint = "sha256:" + hashlib.sha256(
        json.dumps(fingerprint_source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if result["environment"]["fingerprint"] != expected_fingerprint:
        fail(path, "environment.fingerprint mismatch")

    require_object(path, result["config"], CONFIG_FIELDS)
    if result["config"]["mux_mode"] not in {"off", "compat", "flow", "balance", "turbo"}:
        fail(path, "unknown config.mux_mode")
    flows = result["config"]["flows"]
    if isinstance(flows, bool) or not isinstance(flows, int) or flows < 1:
        fail(path, "config.flows must be a positive integer")
    if result["config"]["netem_profile"] not in {"none", "carrier-delay", "carrier-loss"}:
        fail(path, "unknown config.netem_profile")
    require_string(path, result["config"]["fingerprint"])
    if not result["config"]["fingerprint"]:
        fail(path, "config.fingerprint must not be empty")
    expected_config = SCENARIOS.get(result["scenario"])
    if expected_config is None:
        fail(path, "unknown scenario")
    if expected_config != (result["config"]["mux_mode"], flows):
        fail(path, "scenario does not match mux_mode/flows")

    require_object(
        path,
        result["metrics"],
        set(METRICS),
        set(METRICS) | set(OPTIONAL_METRICS),
    )
    for name, types in {**METRICS, **OPTIONAL_METRICS}.items():
        if name not in result["metrics"]:
            continue
        value = result["metrics"][name]
        if (
            isinstance(value, bool)
            or not isinstance(value, types)
            or not math.isfinite(value)
            or value < 0
        ):
            fail(path, f"metrics.{name} must be a non-negative number")

    rollout_fields = (
        "endpoints" in result,
        "reorder_limits" in result,
        "reorder_entries" in result["metrics"],
    )
    if any(rollout_fields) and not all(rollout_fields):
        fail(path, "rollout attestation fields must be provided together")
    if all(rollout_fields):
        require_object(path, result["endpoints"], {"client", "server"})
        for role in ("client", "server"):
            endpoint = result["endpoints"][role]
            require_object(path, endpoint, ENDPOINT_FIELDS)
            if endpoint["platform"] not in {"linux", "android", "ios"}:
                fail(path, f"endpoints.{role}.platform is unsupported")
            if endpoint["device_class"] not in {"physical", "virtual"}:
                fail(path, f"endpoints.{role}.device_class is unsupported")
            require_string(path, endpoint["device_id"])
            if not endpoint["device_id"]:
                fail(path, f"endpoints.{role}.device_id must not be empty")
            if not isinstance(endpoint["git_commit"], str) or not re.fullmatch(
                r"[0-9a-f]{40}", endpoint["git_commit"]
            ):
                fail(path, f"endpoints.{role}.git_commit must be a full commit")
        require_object(path, result["reorder_limits"], {"bytes", "entries"})
        for name in ("bytes", "entries"):
            value = result["reorder_limits"][name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                fail(path, f"reorder_limits.{name} must be a positive integer")

    require_object(path, result["runtime_state"], RUNTIME_FIELDS)
    for name in RUNTIME_FIELDS:
        require_string(path, result["runtime_state"][name])
    expected_mode = result["config"]["mux_mode"]
    if expected_mode == "off":
        if result["metrics"]["active_links"] != 0:
            fail(path, "off scenario requires active_links == 0")
        if result["runtime_state"]["fallback_reason"] not in {"", "mux_inactive"}:
            fail(path, "off scenario fallback must be empty or mux_inactive")
    else:
        if result["runtime_state"]["requested_mode"] != expected_mode:
            fail(path, "runtime requested_mode does not match scenario")
        if result["runtime_state"]["effective_mode"] != expected_mode:
            fail(path, "runtime effective_mode does not match scenario")
        if result["runtime_state"]["fallback_reason"]:
            fail(path, "fallback result cannot be used as requested mode evidence")

    if "iperf" in result:
        if not isinstance(result["iperf"], dict):
            fail(path, "iperf must be an object")
        if result["iperf"].get("error"):
            fail(path, f"iperf error: {result['iperf']['error']}")


def metric_summary(values):
    return {
        "min": min(values),
        "mean": statistics.fmean(values),
        "max": max(values),
    }


def summarize(results):
    scenarios = {}
    for result in results:
        scenarios.setdefault(result["scenario"], []).append(result)
    return {
        "schema_version": 1,
        "result_count": len(results),
        "scenarios": {
            scenario: {
                name: metric_summary([item["metrics"][name] for item in items])
                for name in METRICS
            }
            for scenario, items in sorted(scenarios.items())
        },
    }


def validate_rollout_gate(results):
    groups = {}
    for result in results:
        if "endpoints" not in result:
            fail("rollout", "every result requires endpoint attestation")
        client = result["endpoints"]["client"]
        if client["device_class"] != "physical":
            fail("rollout", "client evidence must come from a physical device")
        if result["metrics"]["buffered_bytes"] > result["reorder_limits"]["bytes"]:
            fail("rollout", "buffered bytes exceed the configured limit")
        if result["metrics"]["reorder_entries"] > result["reorder_limits"]["entries"]:
            fail("rollout", "reorder entries exceed the configured limit")
        if result["metrics"]["disconnects"] != 0:
            fail("rollout", "disconnects must remain zero")
        key = json.dumps(result["endpoints"], sort_keys=True, separators=(",", ":"))
        groups.setdefault(key, []).append(result)

    platforms = set()
    for items in groups.values():
        client = items[0]["endpoints"]["client"]
        platforms.add(client["platform"])
        if client["platform"] == "linux":
            environment = items[0]["environment"]
            if environment["architecture"] not in {"x86_64", "amd64"}:
                fail("rollout", "Linux client evidence requires x86-64")
            kernel = environment["kernel"].lower()
            if "linux" not in kernel or "microsoft" in kernel or "wsl" in kernel:
                fail("rollout", "Linux client evidence must not come from WSL")
            if client["git_commit"] != environment["git_commit"]:
                fail("rollout", "Linux client commit must match the runner commit")
        if len({item["environment"]["fingerprint"] for item in items}) != 1:
            fail("rollout", "paired results require the same environment fingerprint")
        if len({item["duration_seconds"] for item in items}) != 1:
            fail("rollout", "paired results require the same duration")
        by_scenario = {}
        for item in items:
            by_scenario.setdefault(item["scenario"], []).append(item)
        if "off-one-flow" not in by_scenario or "flow-one-flow" not in by_scenario:
            fail("rollout", "each client requires off-one-flow and flow-one-flow")
        off = by_scenario["off-one-flow"]
        flow = by_scenario["flow-one-flow"]
        off_throughput = statistics.fmean(i["metrics"]["throughput_mbps"] for i in off)
        flow_throughput = statistics.fmean(i["metrics"]["throughput_mbps"] for i in flow)
        if flow_throughput < off_throughput * 0.95:
            fail("rollout", "flow throughput is below 95% of mux-off")
        off_p99 = statistics.fmean(i["metrics"]["p99_latency_ms"] for i in off)
        flow_p99 = statistics.fmean(i["metrics"]["p99_latency_ms"] for i in flow)
        if flow_p99 > off_p99 * 1.10:
            fail("rollout", "flow p99 exceeds 110% of mux-off")

    if "linux" not in platforms or not platforms.intersection({"android", "ios"}):
        fail("rollout", "physical Linux and Android/iOS client evidence is required")
    return {"passed": True, "client_platforms": sorted(platforms)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--rollout-gate", action="store_true")
    parser.add_argument("results", nargs="+", type=Path)
    args = parser.parse_args(argv)
    results = []
    try:
        for path in args.results:
            with path.open(encoding="utf-8") as stream:
                result = json.load(
                    stream,
                    parse_constant=lambda value: fail(path, f"invalid number {value}"),
                )
            validate(path, result)
            results.append(result)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    summary = summarize(results)
    if args.rollout_gate:
        try:
            summary["rollout_gate"] = validate_rollout_gate(results)
        except ValueError as error:
            print(error, file=sys.stderr)
            return 1
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
