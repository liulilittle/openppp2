#!/usr/bin/env python3
"""Write the machine-readable evidence summary for lifecycle CI jobs.

The Linux unit job can prove offline contracts and (when the privileged step
completes) namespace rollback.  Host-specific scenarios remain explicitly
unverified until a protected platform runner is configured.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


VALID_JOB_STATUSES = {"success", "failure", "cancelled", "skipped"}


def build_summary(job_status: str) -> dict[str, object]:
    if job_status not in VALID_JOB_STATUSES:
        raise ValueError(f"unsupported GitHub job status: {job_status!r}")

    offline_status = "passed" if job_status == "success" else "failed"
    return {
        "schema_version": 1,
        "job": "cpp-linux",
        "job_status": job_status,
        "evidence": [
            {
                "id": "offline-contracts",
                "status": offline_status,
                "scope": "repository",
                "reason": "static contracts and CTest are run by this job",
            },
            {
                "id": "linux-namespace-rollback",
                "status": offline_status,
                "scope": "privileged-linux",
                "reason": "sudo namespace rollback step is run by this job",
            },
            {
                "id": "windows-host-dns-route",
                "status": "unverified",
                "scope": "windows-host",
                "reason": "no protected Windows network acceptance runner is configured",
            },
            {
                "id": "macos-host-network",
                "status": "unverified",
                "scope": "macos-host",
                "reason": "no privileged macOS network acceptance runner is configured",
            },
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--job-status", required=True)
    args = parser.parse_args()
    summary = build_summary(args.job_status)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
