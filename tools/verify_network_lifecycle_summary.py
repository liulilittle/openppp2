#!/usr/bin/env python3
"""Validate the lifecycle evidence summary used by release gates.

The summary is deliberately conservative: offline and privileged Linux
evidence must be passed for a releasable test job, while platform-host checks
that are not configured must remain explicitly ``unverified``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_EVIDENCE = {
    "offline-contracts": "passed",
    "linux-namespace-rollback": "passed",
    "windows-host-dns-route": "unverified",
    "macos-host-network": "unverified",
}


def validate_summary(summary: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(summary, dict):
        return ["summary must be a JSON object"]

    if summary.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if summary.get("job") != "cpp-linux":
        errors.append("job must be cpp-linux")
    if summary.get("job_status") != "success":
        errors.append("job_status must be success")

    evidence = summary.get("evidence")
    if not isinstance(evidence, list):
        return errors + ["evidence must be a list"]

    by_id: dict[str, object] = {}
    for row in evidence:
        if not isinstance(row, dict):
            errors.append("each evidence row must be an object")
            continue
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id:
            errors.append("each evidence row must have a non-empty id")
            continue
        if row_id in by_id:
            errors.append(f"duplicate evidence id: {row_id}")
            continue
        by_id[row_id] = row

    for row_id, expected_status in REQUIRED_EVIDENCE.items():
        row = by_id.get(row_id)
        if not isinstance(row, dict):
            errors.append(f"missing evidence row: {row_id}")
            continue
        if row.get("status") != expected_status:
            errors.append(
                f"{row_id} must be {expected_status}, got {row.get('status')!r}"
            )

    return errors


def validate_file(path: Path) -> list[str]:
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read {path}: {exc}"]
    return validate_summary(summary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    errors = validate_file(args.summary)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print(f"validated lifecycle summary: {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
