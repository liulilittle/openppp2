#!/usr/bin/env python3
import json
from pathlib import Path
import sys


def validate_environment(environment, expected_host_id, expected_git_sha=None):
    kernel = str(environment.get("kernel", "")).lower()
    if (
        str(environment.get("virt", "")).lower() == "wsl"
        or "microsoft" in kernel
        or "wsl" in kernel
    ):
        return "WSL is diagnostic-only and cannot provide a fixed-host baseline"
    if environment.get("arch") not in ("x86_64", "amd64"):
        return "fixed-host baselines require Linux x86-64"
    if environment.get("governor") != "performance":
        return "fixed-host baselines require the performance governor"
    if environment.get("perf_cycles") is not True:
        return "fixed-host baselines require readable perf cycles"
    if not expected_host_id or environment.get("host_id") != expected_host_id:
        return "environment host_id does not match the expected fixed host"
    if expected_git_sha is not None and environment.get("git_sha") != expected_git_sha:
        return "environment git_sha does not match the expected commit"
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_fixed_host.py ENV_JSON EXPECTED_HOST_ID", file=sys.stderr)
        return 2

    environment = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    error = validate_environment(environment, sys.argv[2])
    if error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
