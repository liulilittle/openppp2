#!/usr/bin/env python3
"""Capture the client exec envelope without changing PID or inherited affinity."""

import argparse
import json
import os
from pathlib import Path

POLICY_NAMES = ("SHARDS", "SPSC_INGRESS", "AFFINITY", "IO_CPUS", "AFFINITY_STRICT", "AUTO_SHARDS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requested", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("exec command is required")
    allowed = sorted(os.sched_getaffinity(0))
    if args.requested != "inherited" and set(allowed) != set(map(int, args.requested.split(","))):
        raise SystemExit("startup affinity does not match requested envelope")
    args.output.write_text(json.dumps({
        "method": "taskset-at-exec" if args.requested != "inherited" else "inherited-at-exec",
        "requested_cpus": args.requested, "allowed_cpus": allowed,
        "pid": os.getpid(), "netns": os.readlink("/proc/self/ns/net"),
        "requested_env": {"OPENPPP2_XTCP_" + name: os.environ.get("OPENPPP2_XTCP_" + name) for name in POLICY_NAMES},
    }, indent=2) + "\n", encoding="utf-8")
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
