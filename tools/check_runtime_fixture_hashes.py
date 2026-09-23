#!/usr/bin/env python3
"""Verify runtime fixtures and all language loaders use one canonical bundle."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def check_repository(root: Path) -> list[str]:
    root = root.resolve()
    fixture_dir = root / "tests/contracts/runtime-snapshot"
    manifest = fixture_dir / "SHA256SUMS"
    violations: list[str] = []
    expected: dict[str, str] = {}
    if not manifest.exists():
        violations.append("tests/contracts/runtime-snapshot/SHA256SUMS: missing fixture hash manifest")
    else:
        for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
            parts = line.split()
            if len(parts) != 2:
                violations.append(f"{manifest.relative_to(root)}:{line_number}: invalid hash entry")
                continue
            expected[parts[1]] = parts[0].lower()

    actual_files = sorted(fixture_dir.glob("*.json")) if fixture_dir.exists() else []
    for path in actual_files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected.get(path.name) != digest:
            violations.append(
                f"{path.relative_to(root)}: fixture hash mismatch"
            )
    for name in sorted(set(expected) - {path.name for path in actual_files}):
        violations.append(f"tests/contracts/runtime-snapshot/{name}: manifest entry has no fixture")

    loaders = {
        "tests/cpp/CMakeLists.txt": ("tests/contracts/runtime-snapshot",),
        "android/test/runtime_snapshot_test.dart": ("../tests/contracts/runtime-snapshot/",),
        "ios/App/Tests/OpenPPP2LogicTests/RuntimeSnapshotTests.swift": (
            'appendingPathComponent("tests")',
            'appendingPathComponent("contracts")',
            'appendingPathComponent("runtime-snapshot")',
        ),
    }
    for relative, tokens in loaders.items():
        path = root / relative
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        if not all(token in text for token in tokens):
            violations.append(f"{relative}: runtime fixture loader is not canonical")
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    violations = check_repository(root)
    if violations:
        print("Runtime fixture violations:")
        for violation in violations:
            print(violation)
        return 1
    print("PASS: runtime fixture hashes and canonical loaders")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
