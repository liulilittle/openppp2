#!/usr/bin/env python3
"""Reproducibility metadata and paired performance gate helpers."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout


def _is_sensitive_path(path: bytes) -> bool:
    parts = [part.lower() for part in path.split(b"/")]
    name = parts[-1]
    return (
        any(part in {b".ssh", b"credentials", b"secrets"} for part in parts[:-1])
        or name == b".env" or name.startswith(b".env.")
        or name in {b"id_rsa", b"id_dsa", b"id_ecdsa", b"id_ed25519"}
        or name.endswith((b".key", b".pem", b".p12", b".pfx"))
        or any(word in name for word in (b"credential", b"secret", b"token"))
    )


def collect_version_fingerprint(root: Path, ppp_bin: Path) -> dict:
    stat = ppp_bin.stat()
    binary_sha256 = hashlib.sha256()
    with ppp_bin.open("rb") as binary_file:
        for chunk in iter(lambda: binary_file.read(1024 * 1024), b""):
            binary_sha256.update(chunk)

    changed_paths = [
        path for path in _git(root, "diff", "--name-only", "-z", "HEAD", "--").split(b"\0") if path
    ]
    diff_paths = [path for path in changed_paths if not _is_sensitive_path(path)]
    tracked_diff = _git(
        root, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv",
        "--no-color", "--no-renames", "--diff-algorithm=myers", "HEAD", "--", *(
            path.decode("utf-8", "surrogateescape") for path in diff_paths
        )
    ) if diff_paths else b""
    untracked_paths = sorted(
        path for path in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0") if path
    )
    untracked_fingerprint = hashlib.sha256()
    for path in untracked_paths:
        untracked_fingerprint.update(path)
        untracked_fingerprint.update(b"\0")

    xtcp_dir = root / "third-party" / "xtcp"
    revision_marker = xtcp_dir / ".openppp2-xtcp-revision"
    patch_marker = xtcp_dir / ".openppp2-xtcp-patches"
    return {
        "ppp_binary": {
            "path": str(ppp_bin.resolve()),
            "sha256": binary_sha256.hexdigest(),
            "size_bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        },
        "git": {
            "head": _git(root, "rev-parse", "HEAD").decode().strip(),
            "describe": _git(root, "describe", "--always", "--tags", "--long").decode().strip(),
            "tracked_diff_sha256": hashlib.sha256(tracked_diff).hexdigest(),
            "tracked_diff_excluded_sensitive_path_count": len(changed_paths) - len(diff_paths),
            "untracked_paths_sha256": untracked_fingerprint.hexdigest(),
            "untracked_path_count": len(untracked_paths),
        },
        "xtcp": {
            "revision": revision_marker.read_text(encoding="utf-8").strip() if revision_marker.is_file() else "unavailable",
            "patch_stamp": patch_marker.read_text(encoding="utf-8").strip() if patch_marker.is_file() else "unavailable",
        },
    }


def flatten_version_fingerprint(fingerprint: dict) -> dict[str, str]:
    return {
        "ppp_binary_path": fingerprint["ppp_binary"]["path"],
        "ppp_binary_sha256": fingerprint["ppp_binary"]["sha256"],
        "ppp_binary_size_bytes": str(fingerprint["ppp_binary"]["size_bytes"]),
        "ppp_binary_mtime_ns": str(fingerprint["ppp_binary"]["mtime_ns"]),
        "git_head": fingerprint["git"]["head"],
        "git_describe": fingerprint["git"]["describe"],
        "git_tracked_diff_sha256": fingerprint["git"]["tracked_diff_sha256"],
        "git_tracked_diff_excluded_sensitive_path_count": str(fingerprint["git"]["tracked_diff_excluded_sensitive_path_count"]),
        "git_untracked_paths_sha256": fingerprint["git"]["untracked_paths_sha256"],
        "git_untracked_path_count": str(fingerprint["git"]["untracked_path_count"]),
        "xtcp_revision": fingerprint["xtcp"]["revision"],
        "xtcp_patch_stamp": fingerprint["xtcp"]["patch_stamp"],
    }


def evaluate_performance_gate(records: list[dict], mode: str, threshold: float) -> dict:
    if mode == "off":
        return {"mode": mode, "threshold": threshold, "status": "off", "pairs": [], "failed_pairs": []}

    grouped = {}
    for record in records:
        key = (
            record.get("round"), record.get("parallel_flows"), record.get("direction"),
            record.get("requested_tap_gso"), record.get("active_tap_gso"),
        )
        stacks = grouped.setdefault(key, {})
        if record.get("requested_tcp_stack") in {"native", "xtcp"}:
            stacks[record["requested_tcp_stack"]] = record

    pairs = []
    for key, stacks in sorted(grouped.items()):
        pair = {
            "round": key[0], "parallel_flows": key[1], "direction": key[2],
            "requested_tap_gso": key[3], "active_tap_gso": key[4],
        }
        if "native" not in stacks or "xtcp" not in stacks:
            pair.update(status="fail", reason="incomplete_pair", ratio=None)
        else:
            native_bps = stacks["native"].get("goodput_bps")
            xtcp_bps = stacks["xtcp"].get("goodput_bps")
            pair.update(native_bps=native_bps, xtcp_bps=xtcp_bps)
            if not isinstance(native_bps, (int, float)) or native_bps <= 0 or not isinstance(xtcp_bps, (int, float)):
                pair.update(status="fail", reason="invalid_goodput", ratio=None)
            else:
                ratio = xtcp_bps / native_bps
                pair.update(status="pass" if ratio >= threshold else "fail", ratio=ratio)
                if ratio < threshold:
                    pair["reason"] = "below_threshold"
        pairs.append(pair)

    failed_pairs = [pair for pair in pairs if pair["status"] == "fail"]
    status = "pass" if pairs and not failed_pairs else ("warning" if mode == "warn" else "fail")
    return {"mode": mode, "threshold": threshold, "status": status, "pairs": pairs, "failed_pairs": failed_pairs}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ppp-bin", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--text-output", type=Path, required=True)
    arguments = parser.parse_args()
    fingerprint = collect_version_fingerprint(arguments.root, arguments.ppp_bin)
    arguments.json_output.write_text(json.dumps(fingerprint, indent=2) + "\n", encoding="utf-8")
    arguments.text_output.write_text(
        "".join(f"{key}={value}\n" for key, value in flatten_version_fingerprint(fingerprint).items()),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
