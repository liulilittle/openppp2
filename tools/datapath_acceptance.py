#!/usr/bin/env python3
"""Fail-closed v2/v3 acceptance contract for Linux native/XTCP datapath runs.

This module owns the fixed acceptance matrix and validates only retained raw
artifacts.  It deliberately does not select a production binary, discover an
adapter, or infer direct-path evidence from summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping


# v2 aliases remain the public default for historic artifacts and callers.
ACCEPTANCE_SCHEMA_V2 = "openppp2.datapath.acceptance/v2"
INVENTORY_SCHEMA_V2 = "openppp2.datapath.inventory/v2"
LAUNCH_ENVIRONMENT_SCHEMA_V2 = "openppp2.datapath.launch-environment/v2"
LAUNCH_SCHEMA_V2 = "openppp2.datapath.launch/v2"
RESULT_SCHEMA_V2 = "openppp2.datapath.result/v2"
DIRECT_PROOF_SCHEMA_V2 = "openppp2.datapath.direct-proof/v2"
FREEZE_SCHEMA_V2 = "openppp2.datapath.freeze/v2"
FREEZE_MANIFEST_SCHEMA_V2 = "openppp2.datapath.freeze-manifest/v2"

ACCEPTANCE_SCHEMA_V3 = "openppp2.datapath.acceptance/v3"
INVENTORY_SCHEMA_V3 = "openppp2.datapath.inventory/v3"
LAUNCH_SCHEMA_V3 = "openppp2.datapath.launch/v3"
RESULT_SCHEMA_V3 = "openppp2.datapath.result/v3"
UNDERLAY_IMPAIRMENT_SCHEMA_V3 = "openppp2.datapath.underlay-impairment/v3"

ACCEPTANCE_SCHEMA = ACCEPTANCE_SCHEMA_V2
INVENTORY_SCHEMA = INVENTORY_SCHEMA_V2
LAUNCH_ENVIRONMENT_SCHEMA = LAUNCH_ENVIRONMENT_SCHEMA_V2
LAUNCH_SCHEMA = LAUNCH_SCHEMA_V2
RESULT_SCHEMA = RESULT_SCHEMA_V2
DIRECT_PROOF_SCHEMA = DIRECT_PROOF_SCHEMA_V2
FREEZE_SCHEMA = FREEZE_SCHEMA_V2
FREEZE_MANIFEST_SCHEMA = FREEZE_MANIFEST_SCHEMA_V2

CAMPAIGN_SEED_MINIMUM = 1
CAMPAIGN_SEED_MAXIMUM = 2_147_483_647
CARRIER_DIRECTIONS = ("client_to_server", "server_to_client")
UNIFORM_DISTRIBUTION_SOURCE_PATH = "tools/uniform.dist"
PERIODIC_CARRIER_BPF_SOURCE_PATH = "tools/datapath_fixed_loss.bpf.c"
PERIODIC_CARRIER_BPF_NAME = "datapath_fixed_loss.bpf.c:[carrier_egress]"
PERIODIC_CARRIER_BPF_SECTION = "carrier_egress"

# v3 names describe the new profile-bound records; v2 aliases above deliberately
# retain their literal values for old prepared/sealed artifacts.
ACCEPTANCE_SCHEMAS = frozenset((ACCEPTANCE_SCHEMA_V2, ACCEPTANCE_SCHEMA_V3))
LAUNCH_SCHEMAS = frozenset((LAUNCH_SCHEMA_V2, LAUNCH_SCHEMA_V3))
RESULT_SCHEMAS = frozenset((RESULT_SCHEMA_V2, RESULT_SCHEMA_V3))

STACKS = ("native", "xtcp")
PARALLEL_FLOWS = (1, 4, 16)
DIRECTIONS = ("ul", "dl")
ROUNDS = (1, 2, 3)
TAP_GSO = "on"
MINIMUM_THRESHOLD = Decimal("1.20")
FORMAL_TARGET_HOST = "198.18.0.4"
FORMAL_TARGET_PORT = 5201


def _freeze_profile_value(value: Any) -> Any:
    """Recursively make the closed catalog immutable without changing JSON types."""

    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_profile_value(nested) for key, nested in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_profile_value(nested) for nested in value)
    return value


def _profile_definition(
    profile_id: str,
    target_rtt_ms: int,
    *,
    jitter_per_direction_us: int = 0,
    loss: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": profile_id,
        "target_rtt_ms": target_rtt_ms,
        "one_way_delay_us": target_rtt_ms * 500,
        "jitter_per_direction_us": jitter_per_direction_us,
        "jitter_distribution": "uniform" if jitter_per_direction_us else "none",
        "queue_limit_packets": 32768,
        "loss": loss or {"mode": "none"},
    }


_PROFILE_DEFINITIONS = (
    *(
        profile
        for rtt in (35, 55, 75, 90, 100)
        for profile in (
            _profile_definition(f"rtt-{rtt}-fixed", rtt),
            _profile_definition(f"rtt-{rtt}-j20", rtt, jitter_per_direction_us=10000),
        )
    ),
    *(
        _profile_definition(
            f"rtt-75-j20-periodic-loss-{suffix}",
            75,
            jitter_per_direction_us=10000,
            loss={"mode": "periodic_carrier_skb", "every_n": every_n},
        )
        for suffix, every_n in (("0p1", 1000), ("0p5", 200), ("1p0", 100))
    ),
    *(
        _profile_definition(
            f"rtt-75-j20-iid-loss-{suffix}",
            75,
            jitter_per_direction_us=10000,
            loss={"mode": "iid_random", "probability_ppm": probability_ppm},
        )
        for suffix, probability_ppm in (("0p1", 1000), ("0p5", 5000), ("1p0", 10000))
    ),
)
NETWORK_PROFILE_CATALOG: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {profile["id"]: _freeze_profile_value(profile) for profile in _PROFILE_DEFINITIONS}
)
NETWORK_PROFILE_IDS = tuple(NETWORK_PROFILE_CATALOG)


def _profile_copy(value: Any) -> Any:
    """Return a JSON-safe defensive copy of a frozen catalog value."""

    if isinstance(value, Mapping):
        return {key: _profile_copy(nested) for key, nested in value.items()}
    if isinstance(value, tuple):
        return [_profile_copy(nested) for nested in value]
    return value


def validate_network_profile(profile: Any, *, expected_id: str | None = None) -> dict[str, Any]:
    """Validate the exact v3 profile object shape and return its canonical copy.

    A valid profile has only `id`, RTT/delay/jitter fields, `queue_limit_packets`,
    and an exact loss object.  Callers must use this rather than accepting free tc
    parameters; it fails closed unless the object is byte-for-byte equivalent in
    JSON value terms to one member of the closed catalog.
    """

    if not isinstance(profile, dict):
        raise AcceptanceError("network profile must be a JSON object")
    expected_keys = {
        "id",
        "target_rtt_ms",
        "one_way_delay_us",
        "jitter_per_direction_us",
        "jitter_distribution",
        "queue_limit_packets",
        "loss",
    }
    if set(profile) != expected_keys:
        raise AcceptanceError("network profile has an incomplete or unexpected v3 shape")
    profile_id = profile.get("id")
    if not isinstance(profile_id, str) or profile_id not in NETWORK_PROFILE_CATALOG:
        raise AcceptanceError("network profile id is not in the closed catalog")
    if expected_id is not None and profile_id != expected_id:
        raise AcceptanceError("network profile id does not match the requested catalog entry")
    for field_name in (
        "target_rtt_ms",
        "one_way_delay_us",
        "jitter_per_direction_us",
        "queue_limit_packets",
    ):
        value = profile.get(field_name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise AcceptanceError(f"network profile {field_name} must be a non-boolean integer")
    loss = profile.get("loss")
    if not isinstance(loss, dict) or not isinstance(loss.get("mode"), str):
        raise AcceptanceError("network profile loss is malformed")
    mode = loss["mode"]
    expected_loss_keys = {
        "none": {"mode"},
        "periodic_carrier_skb": {"mode", "every_n"},
        "iid_random": {"mode", "probability_ppm"},
    }
    if mode not in expected_loss_keys or set(loss) != expected_loss_keys[mode]:
        raise AcceptanceError("network profile loss has an incomplete or unexpected shape")
    if mode == "periodic_carrier_skb" and (
        isinstance(loss.get("every_n"), bool) or not isinstance(loss.get("every_n"), int)
    ):
        raise AcceptanceError("network profile loss every_n must be a non-boolean integer")
    if mode == "iid_random" and (
        isinstance(loss.get("probability_ppm"), bool) or not isinstance(loss.get("probability_ppm"), int)
    ):
        raise AcceptanceError("network profile loss probability_ppm must be a non-boolean integer")
    expected = _profile_copy(NETWORK_PROFILE_CATALOG[profile_id])
    if profile != expected:
        raise AcceptanceError("network profile does not exactly match its closed catalog entry")
    return expected


def _validated_network_profile(profile: Any, *, expected_id: str | None = None) -> dict[str, Any]:
    """Translate public profile-validation failures into retained-evidence failures."""

    try:
        return validate_network_profile(profile, expected_id=expected_id)
    except AcceptanceError as error:
        raise EvidenceError(str(error)) from None


def _validated_campaign_seed(value: Any) -> int:
    """Translate public campaign-seed failures into retained-evidence failures."""

    try:
        return validate_campaign_seed(value)
    except AcceptanceError as error:
        raise EvidenceError(str(error)) from None


def network_profile(profile_id: str) -> dict[str, Any]:
    """Return a defensive JSON-safe copy of one closed v3 profile catalog entry."""

    if not isinstance(profile_id, str) or profile_id not in NETWORK_PROFILE_CATALOG:
        raise AcceptanceError("network profile id is not in the closed catalog")
    return validate_network_profile(_profile_copy(NETWORK_PROFILE_CATALOG[profile_id]), expected_id=profile_id)


def network_profile_catalog() -> dict[str, dict[str, Any]]:
    """Return defensive copies of all closed v3 profile catalog entries."""

    return {profile_id: network_profile(profile_id) for profile_id in NETWORK_PROFILE_IDS}


def validate_campaign_seed(value: Any) -> int:
    """Accept only a non-boolean campaign seed in 1..2147483647 inclusive."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise AcceptanceError("campaign seed must be a non-boolean integer")
    if not CAMPAIGN_SEED_MINIMUM <= value <= CAMPAIGN_SEED_MAXIMUM:
        raise AcceptanceError(
            f"campaign seed must be in {CAMPAIGN_SEED_MINIMUM}..{CAMPAIGN_SEED_MAXIMUM}"
        )
    return value


def derive_directional_netem_seed(
    campaign_seed: Any,
    profile_id: str,
    identity: "CellIdentity",
    carrier_direction: str,
) -> int:
    """Derive a nonzero tc-compatible seed from canonical campaign/cell inputs.

    The canonical input deliberately includes only round, parallel flows, and
    formal direction from `CellIdentity`, so a native/XTCP pair gets identical
    seeds while the two carrier directions receive distinct domain-separated
    inputs.
    """

    seed = validate_campaign_seed(campaign_seed)
    if not isinstance(profile_id, str) or profile_id not in NETWORK_PROFILE_CATALOG:
        raise AcceptanceError("network profile id is not in the closed catalog")
    if not isinstance(identity, CellIdentity):
        raise AcceptanceError("directional seed identity must be a CellIdentity")
    if carrier_direction not in CARRIER_DIRECTIONS:
        raise AcceptanceError("carrier direction is invalid")
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "campaign_seed": seed,
                "carrier_direction": carrier_direction,
                "cell": {
                    "direction": identity.direction,
                    "parallel_flows": identity.parallel_flows,
                    "round": identity.round,
                },
                "profile_id": profile_id,
            }
        )
    ).digest()
    # Linux tc accepts positive signed integer seeds.  Keep the two directions
    # in disjoint valid ranges so their returned seeds differ by construction,
    # not merely with overwhelming probability from their domain-separated hash.
    direction_span = 1_073_741_823
    offset = 0 if carrier_direction == "client_to_server" else direction_span
    return offset + (int.from_bytes(digest[:8], "big") % direction_span) + 1


# Source identity is deliberately narrow.  Nothing outside this list is even
# traversed, so an arbitrary file at the source-root cannot become evidence.
SOURCE_ALLOWLIST_EXACT_FILES = (
    "CMakeLists.txt",
    "main.cpp",
    "tools/compat/server.json",
    "tools/compat/client_proxy.json",
    "tools/datapath_acceptance.py",
    "tools/run_datapath_linux_acceptance.sh",
    "tools/datapath_linux_strict_adapter.py",
)
SOURCE_ALLOWLIST_TREES = (
    "cmake",
    "common",
    "ppp",
    "linux",
    "third-party/xtcp",
)
# V3 extends only its own source identity; the v2 constants above remain
# byte-for-byte historical inputs for existing manifests and frozen records.
SOURCE_ALLOWLIST_V3_EXACT_FILES = (
    *SOURCE_ALLOWLIST_EXACT_FILES,
    UNIFORM_DISTRIBUTION_SOURCE_PATH,
    PERIODIC_CARRIER_BPF_SOURCE_PATH,
)
SOURCE_SKIPPED_COMPONENTS = (
    ".git",
    ".hg",
    ".svn",
    "build",
    "build-*",
    "artifacts",
    ".tmp-*",
    "CMakeFiles",
    "cmake-build-*",
    "__pycache__",
    ".cache",
    "node_modules",
    "dist",
    "out",
    "target",
    "generated",
    "gen",
)
SENSITIVE_EXTENSIONS = frozenset(
    {".key", ".pem", ".p12", ".pfx", ".crt", ".cer", ".der", ".jks", ".kdbx"}
)
SENSITIVE_COMPONENT_STEMS = (
    "credentials",
    "credential",
    "secret",
    "private-key",
    "private_key",
    "key-material",
    "key_material",
    "id_rsa",
)

# These files are verifier output/self references.  Everything else in a
# sealed artifact root participates in the artifact identity.
CONTROL_ARTIFACT_PATHS = (
    "acceptance-report.json",
    "run-inventory.json",
    "run-inventory.sha256",
)

MINIMAL_BASE_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
}
COMMON_CLIENT_ENVIRONMENT_NAMES = (
    "OPENPPP2_TAP_GSO_MERGE",
    "OPENPPP2_DATAPATH_ACCEPTANCE_RUN_UUID",
    "OPENPPP2_DATAPATH_ACCEPTANCE_CELL_ID",
    "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_REQUEST",
    "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_ACK",
)
XTCP_CLIENT_ENVIRONMENT = {
    "OPENPPP2_XTCP_MEMORY_BRIDGE": "1",
    "OPENPPP2_XTCP_CC": "kcc",
    "OPENPPP2_XTCP_SHARDS": "1",
    "OPENPPP2_XTCP_SNDBUF_BYTES": "65536",
    "OPENPPP2_XTCP_GRO_BYTES": "12288",
    "OPENPPP2_XTCP_DIRECT_UPLOAD_GATHER_BYTES": "61440",
}
FORBIDDEN_ENVIRONMENT_NAMES = frozenset(
    {
        "OPENPPP2_XTCP_NDI_TSO_TX",
        "OPENPPP2_XTCP_PERF_JSON",
        "OPENPPP2_DATAPATH_PERF_JSON",
        "OPENPPP2_DATAPATH_PERF_MEASUREMENT_BOUNDARIES",
    }
)


class AcceptanceError(RuntimeError):
    """A preparation, sealing, or integrity-contract failure."""


class EvidenceError(AcceptanceError):
    """Supplied evidence cannot safely be assessed."""


@dataclass(frozen=True)
class CellIdentity:
    """One immutable member of the fixed acceptance matrix."""

    round: int
    stack: str
    parallel_flows: int
    direction: str
    tap_gso: str = TAP_GSO

    def as_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "requested_tcp_stack": self.stack,
            "active_tcp_stack": self.stack,
            "requested_tap_gso": self.tap_gso,
            "active_tap_gso": self.tap_gso,
            "parallel_flows": self.parallel_flows,
            "direction": self.direction,
        }

    def relative_directory(self) -> str:
        return (
            f"round-{self.round}/"
            f"{self.stack}-gso-{self.tap_gso}-p{self.parallel_flows}-{self.direction}"
        )

    def iperf_filename(self) -> str:
        return f"iperf-{self.direction}-p{self.parallel_flows}.json"


@dataclass(frozen=True)
class PairIdentity:
    """The native/XTCP comparison for one workload cell."""

    round: int
    parallel_flows: int
    direction: str
    tap_gso: str = TAP_GSO

    def as_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "parallel_flows": self.parallel_flows,
            "direction": self.direction,
            "tap_gso": self.tap_gso,
        }

    def cell(self, stack: str) -> CellIdentity:
        return CellIdentity(
            round=self.round,
            stack=stack,
            parallel_flows=self.parallel_flows,
            direction=self.direction,
            tap_gso=self.tap_gso,
        )


@dataclass
class CellEvidence:
    """Canonical evidence collected for one expected cell."""

    identity: CellIdentity
    result_path: Path
    record: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    delivered_goodput_bps: Decimal | None = None
    delivered_payload_bytes: int | None = None
    direct_admission_evidence: dict[str, int] | None = None


def expected_cells() -> tuple[CellIdentity, ...]:
    """Return the only accepted 36 cells in a stable, public order."""

    return tuple(
        CellIdentity(
            round=round_number,
            stack=stack,
            parallel_flows=parallel_flows,
            direction=direction,
        )
        for round_number in ROUNDS
        for parallel_flows in PARALLEL_FLOWS
        for direction in DIRECTIONS
        for stack in STACKS
    )


def expected_pairs() -> tuple[PairIdentity, ...]:
    """Return the corresponding 18 native/XTCP comparisons."""

    return tuple(
        PairIdentity(
            round=round_number,
            parallel_flows=parallel_flows,
            direction=direction,
        )
        for round_number in ROUNDS
        for parallel_flows in PARALLEL_FLOWS
        for direction in DIRECTIONS
    )


def cell_relative_directory(identity: CellIdentity) -> str:
    return identity.relative_directory()


def cell_directory(artifact_root: Path, identity: CellIdentity) -> Path:
    return Path(artifact_root) / identity.relative_directory()


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize deterministic, finite JSON for identities and manifests."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r} is forbidden")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r} is forbidden")
        result[key] = value
    return result


def _reject_nonfinite_json_numbers(value: Any) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number is forbidden")
    elif isinstance(value, dict):
        for nested in value.values():
            _reject_nonfinite_json_numbers(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_nonfinite_json_numbers(nested)


def parse_json_text(text: str, description: str) -> Any:
    """Parse JSON without duplicate keys, NaN, or overflowed exponents."""

    try:
        value = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        _reject_nonfinite_json_numbers(value)
        return value
    except (json.JSONDecodeError, ValueError) as error:
        raise EvidenceError(f"{description}: invalid JSON: {error}") from None


def parse_json_bytes(raw: bytes, description: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description}: cannot decode UTF-8 JSON: {error}") from None
    return parse_json_text(text, description)


def _lstat(path: Path, description: str, error_type: type[AcceptanceError] = AcceptanceError) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise error_type(f"cannot stat {description}: {error}") from None


def _path_entry_exists(path: Path, description: str) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise AcceptanceError(f"cannot stat {description}: {error}") from None
    return True


def _require_regular_file(
    path: Path,
    description: str,
    error_type: type[AcceptanceError] = EvidenceError,
) -> os.stat_result:
    metadata = _lstat(path, description, error_type)
    if stat.S_ISLNK(metadata.st_mode):
        raise error_type(f"{description} must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise error_type(f"{description} must be a regular file")
    return metadata


def write_json(path: Path, value: Any) -> None:
    """Write readable JSON without following a pre-existing symlink."""

    path = Path(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise AcceptanceError(f"cannot stat JSON output {path}: {error}") from None
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AcceptanceError(f"JSON output must be a regular file or absent: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError) as error:
        raise AcceptanceError(f"cannot write JSON output {path}: {error}") from None


def read_json(path: Path, description: str | None = None) -> Any:
    label = description or str(path)
    _require_regular_file(Path(path), label)
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError(f"{label}: cannot read UTF-8 JSON: {error}") from None
    return parse_json_text(text, label)


def sha256_file(path: Path) -> str:
    """Hash each byte of a regular, non-symlink file."""

    _require_regular_file(Path(path), str(path), AcceptanceError)
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise AcceptanceError(f"cannot hash {path}: {error}") from None
    return digest.hexdigest()


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validated_source_root(source_root: Path) -> Path:
    """Resolve a real source root only after rejecting a supplied root symlink."""

    supplied = Path(source_root).expanduser()
    metadata = _lstat(supplied, f"source root {supplied}")
    if stat.S_ISLNK(metadata.st_mode):
        raise AcceptanceError(f"symlink is forbidden in source root: {supplied}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise AcceptanceError(f"source root is not a directory: {supplied}")
    try:
        resolved = supplied.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise AcceptanceError(f"cannot resolve source root {source_root}: {error}") from None
    resolved_metadata = _lstat(resolved, "source root")
    if stat.S_ISLNK(resolved_metadata.st_mode) or not stat.S_ISDIR(resolved_metadata.st_mode):
        raise AcceptanceError(f"source root is not a real directory: {resolved}")
    return resolved


def _source_relative_path(root: Path, relative: str) -> Path:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise AcceptanceError(f"unsafe allowlisted source path: {relative!r}")
    return root.joinpath(*parts)


def _source_path_without_symlinks(root: Path, relative: str) -> Path:
    """Return an allowlisted source path after lstat-checking each component."""

    current = root
    parts = _source_relative_path(root, relative).relative_to(root).parts
    for index, component in enumerate(parts):
        current = current / component
        metadata = _lstat(current, f"source path {current}")
        if stat.S_ISLNK(metadata.st_mode):
            raise AcceptanceError(f"symlink is forbidden in source identity: {relative}")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise AcceptanceError(f"source path component is not a directory: {relative}")
    return current


def _resolve_artifact_root_argument(artifact_root: Path) -> Path:
    supplied = Path(artifact_root).expanduser()
    try:
        metadata = supplied.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise AcceptanceError(f"cannot stat artifact root {supplied}: {error}") from None
    else:
        if stat.S_ISLNK(metadata.st_mode):
            raise AcceptanceError(f"artifact root must not be a symlink: {supplied}")
    try:
        return supplied.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as error:
        raise AcceptanceError(f"cannot resolve artifact root {supplied}: {error}") from None


def _normalise_relative_exclusions(excluded_paths: Iterable[str]) -> tuple[str, ...]:
    normalised: set[str] = set()
    for raw_path in excluded_paths:
        candidate = str(raw_path).replace("\\", "/").strip("/")
        if not candidate or candidate == ".":
            raise AcceptanceError("inventory exclusion must be a non-empty relative path")
        parts = candidate.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise AcceptanceError(f"unsafe inventory exclusion: {raw_path!r}")
        normalised.add(candidate)
    return tuple(sorted(normalised))


def _is_excluded(relative_path: str, exclusions: tuple[str, ...]) -> bool:
    return any(
        relative_path == exclusion or relative_path.startswith(exclusion + "/")
        for exclusion in exclusions
    )


def build_inventory(root: Path, excluded_paths: Iterable[str] = ()) -> dict[str, Any]:
    """Build a strict generic inventory for a sealed artifact tree.

    This helper is intentionally *not* used for source identity.  Artifact
    evidence may be recursively enumerated; source identity uses the dedicated
    allowlist below instead.
    """

    try:
        root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise AcceptanceError(f"cannot resolve inventory root {root}: {error}") from None
    root_metadata = _lstat(root, "inventory root")
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise AcceptanceError(f"inventory root is not a real directory: {root}")
    exclusions = _normalise_relative_exclusions(excluded_paths)
    entries: list[dict[str, Any]] = []

    def visit(directory: Path, prefix: str) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise AcceptanceError(f"cannot enumerate {directory}: {error}") from None
        for entry in children:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if _is_excluded(relative, exclusions):
                continue
            child = directory / entry.name
            metadata = _lstat(child, f"inventory path {child}")
            mode = metadata.st_mode
            permissions = f"{stat.S_IMODE(mode):04o}"
            if stat.S_ISLNK(mode):
                raise AcceptanceError(f"symlink is forbidden in artifact inventory: {child}")
            if stat.S_ISREG(mode):
                entries.append(
                    {
                        "path": relative,
                        "kind": "file",
                        "mode": permissions,
                        "size_bytes": metadata.st_size,
                        "sha256": sha256_file(child),
                    }
                )
            elif stat.S_ISDIR(mode):
                entries.append({"path": relative, "kind": "directory", "mode": permissions})
                visit(child, relative)
            else:
                raise AcceptanceError(
                    f"unsupported filesystem entry in artifact inventory: {child} (mode {mode:o})"
                )

    visit(root, "")
    digest_input = {
        "schema": INVENTORY_SCHEMA,
        "root": str(root),
        "excluded_paths": list(exclusions),
        "entries": entries,
    }
    return {**digest_input, "sha256": canonical_json_sha256(digest_input)}


def _inventory_digest(inventory: Mapping[str, Any]) -> str:
    return canonical_json_sha256(
        {
            "schema": inventory.get("schema"),
            "root": inventory.get("root"),
            "excluded_paths": inventory.get("excluded_paths"),
            "entries": inventory.get("entries"),
        }
    )


def _source_inventory_contract(version: int) -> tuple[str, tuple[str, ...]]:
    """Return the schema and exact-file list for one source identity version."""

    if isinstance(version, bool) or not isinstance(version, int):
        raise AcceptanceError("source inventory version must be 2 or 3")
    if version == 2:
        return INVENTORY_SCHEMA_V2, SOURCE_ALLOWLIST_EXACT_FILES
    if version == 3:
        return INVENTORY_SCHEMA_V3, SOURCE_ALLOWLIST_V3_EXACT_FILES
    raise AcceptanceError("source inventory version must be 2 or 3")


def source_allowlist(version: int = 2) -> dict[str, Any]:
    """Return the exact source allowlist for a v2 or v3 identity."""

    _schema, exact_files = _source_inventory_contract(version)
    return {
        "exact_files": list(exact_files),
        "trees": list(SOURCE_ALLOWLIST_TREES),
        "skipped_components": list(SOURCE_SKIPPED_COMPONENTS),
    }


def source_inventory_exclusions(_source_root: Path, _artifact_root: Path | None = None) -> tuple[str, ...]:
    """Compatibility accessor for paths omitted inside allowed source trees.

    It is deliberately not an input to source hashing.  The source collector
    never walks arbitrary root entries and therefore has no dynamic artifact
    exclusion to compute.
    """

    return tuple(SOURCE_SKIPPED_COMPONENTS)


def _is_skipped_source_component(name: str) -> bool:
    return any(
        name == pattern if "*" not in pattern else _glob_component_match(name, pattern)
        for pattern in SOURCE_SKIPPED_COMPONENTS
    )


def _glob_component_match(name: str, pattern: str) -> bool:
    # Only the documented suffix wildcard is supported, avoiding a dependency
    # on broad path matching semantics.
    return pattern.endswith("*") and name.startswith(pattern[:-1])


def _is_sensitive_source_component(name: str) -> bool:
    lowered = name.lower()
    if lowered == ".env" or lowered.startswith(".env."):
        return True
    suffix = Path(lowered).suffix
    if suffix in SENSITIVE_EXTENSIONS or lowered in SENSITIVE_EXTENSIONS:
        return True
    # Match named sensitive components and their normal file suffixes, while
    # intentionally not treating arbitrary identifiers containing "key" as
    # sensitive source material.
    stem = lowered
    for separator in (".", "-", "_"):
        # Preserve hyphen/underscore names in the sensitive list; only strip a
        # conventional extension from the right.
        if separator == "." and "." in stem:
            stem = stem.rsplit(".", 1)[0]
    for sensitive in SENSITIVE_COMPONENT_STEMS:
        if (
            lowered == sensitive
            or lowered.startswith(sensitive + ".")
            or lowered.startswith(sensitive + "-")
            or lowered.startswith(sensitive + "_")
            or stem == sensitive
        ):
            return True
    return False


def _source_entry(path: Path, relative: str) -> tuple[dict[str, Any], os.stat_result]:
    metadata = _lstat(path, f"source path {path}")
    mode = metadata.st_mode
    if stat.S_ISLNK(mode):
        raise AcceptanceError(f"symlink is forbidden in source identity: {relative}")
    if stat.S_ISREG(mode):
        return (
            {
                "path": relative,
                "kind": "file",
                "mode": f"{stat.S_IMODE(mode):04o}",
                "size_bytes": metadata.st_size,
            },
            metadata,
        )
    if stat.S_ISDIR(mode):
        return (
            {"path": relative, "kind": "directory", "mode": f"{stat.S_IMODE(mode):04o}"},
            metadata,
        )
    raise AcceptanceError(f"unsupported filesystem entry in source identity: {relative}")


def build_source_inventory(source_root: Path, version: int = 2) -> dict[str, Any]:
    """Collect a versioned allowlisted source identity in preflight-then-hash phases.

    The preflight phase performs only directory enumeration and lstat calls.
    It completes for every allowed tree before any file content is read or
    hashed, which prevents a later sensitive path from causing partial source
    content consumption.
    """

    inventory_schema, exact_files = _source_inventory_contract(version)
    root = _validated_source_root(source_root)

    preflight: list[tuple[dict[str, Any], Path, os.stat_result]] = []

    def inspect_file(relative: str) -> None:
        if _is_sensitive_source_component(Path(relative).name):
            raise AcceptanceError(f"sensitive source path is forbidden: {relative}")
        path = _source_path_without_symlinks(root, relative)
        entry, metadata = _source_entry(path, relative)
        if entry["kind"] != "file":
            raise AcceptanceError(f"allowlisted source file is not a regular file: {relative}")
        preflight.append((entry, path, metadata))

    def inspect_tree(path: Path, relative: str) -> None:
        entry, metadata = _source_entry(path, relative)
        if entry["kind"] != "directory":
            raise AcceptanceError(f"allowlisted source tree is not a directory: {relative}")
        preflight.append((entry, path, metadata))
        try:
            children = sorted(os.scandir(path), key=lambda child: child.name)
        except OSError as error:
            raise AcceptanceError(f"cannot enumerate allowlisted source tree {relative}: {error}") from None
        for child in children:
            child_relative = f"{relative}/{child.name}"
            # Skips happen before lstat and are never traversed or hashed.
            if _is_skipped_source_component(child.name):
                continue
            if _is_sensitive_source_component(child.name):
                raise AcceptanceError(f"sensitive source path is forbidden: {child_relative}")
            child_path = _source_path_without_symlinks(root, child_relative)
            child_entry, child_metadata = _source_entry(child_path, child_relative)
            preflight.append((child_entry, child_path, child_metadata))
            if child_entry["kind"] == "directory":
                # Remove the just-added directory and let the recursive call
                # add it once before walking its children.
                preflight.pop()
                inspect_tree(child_path, child_relative)

    # Complete all lstat/scandir preflight work before the hashing phase.
    for relative in exact_files:
        inspect_file(relative)
    for relative in SOURCE_ALLOWLIST_TREES:
        if _is_sensitive_source_component(Path(relative).name):
            raise AcceptanceError(f"sensitive source path is forbidden: {relative}")
        inspect_tree(_source_path_without_symlinks(root, relative), relative)

    entries: list[dict[str, Any]] = []
    for entry, path, preflight_metadata in sorted(preflight, key=lambda item: item[0]["path"]):
        current = _lstat(path, f"source path {path}")
        if (
            stat.S_IFMT(current.st_mode) != stat.S_IFMT(preflight_metadata.st_mode)
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(preflight_metadata.st_mode)
            or (stat.S_ISREG(current.st_mode) and current.st_size != preflight_metadata.st_size)
        ):
            raise AcceptanceError(f"source path changed during preflight: {entry['path']}")
        final_entry = dict(entry)
        if final_entry["kind"] == "file":
            final_entry["sha256"] = sha256_file(path)
            after_hash = _lstat(path, f"source path {path}")
            if (
                stat.S_IFMT(after_hash.st_mode) != stat.S_IFMT(current.st_mode)
                or after_hash.st_size != current.st_size
                or after_hash.st_mtime_ns != current.st_mtime_ns
            ):
                raise AcceptanceError(f"source file changed while hashing: {entry['path']}")
        entries.append(final_entry)

    allowlist = source_allowlist(version)
    digest_input = {
        "schema": inventory_schema,
        "root": str(root),
        "allowlist": allowlist,
        "entries": entries,
    }
    return {**digest_input, "sha256": canonical_json_sha256(digest_input)}


def _source_inventory_digest(inventory: Mapping[str, Any]) -> str:
    return canonical_json_sha256(
        {
            "schema": inventory.get("schema"),
            "root": inventory.get("root"),
            "allowlist": inventory.get("allowlist"),
            "entries": inventory.get("entries"),
        }
    )


def collect_candidate_identity(candidate: Path, source_root: Path) -> dict[str, Any]:
    """Return a byte-complete identity for an explicit external executable."""

    supplied = Path(candidate).expanduser()
    if not supplied.is_absolute():
        raise AcceptanceError("candidate path must be absolute")
    metadata = _lstat(supplied, f"candidate {supplied}")
    if stat.S_ISLNK(metadata.st_mode):
        raise AcceptanceError(f"candidate must not be a symlink: {supplied}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceError(f"candidate is not a regular file: {supplied}")
    if not os.access(supplied, os.X_OK):
        raise AcceptanceError(f"candidate is not executable: {supplied}")
    try:
        resolved_candidate = supplied.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise AcceptanceError(f"cannot resolve candidate: {error}") from None
    resolved_source = _validated_source_root(source_root)
    source_bin = (resolved_source / "bin").resolve(strict=False)
    if _path_is_within(resolved_candidate, source_bin):
        raise AcceptanceError(
            f"candidate must be external to the source bin directory, not {resolved_candidate}"
        )
    return {
        "path": str(resolved_candidate),
        "sha256": sha256_file(resolved_candidate),
        "size_bytes": metadata.st_size,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "mtime_ns": metadata.st_mtime_ns,
    }


def _validate_candidate_shape(candidate: Any) -> None:
    if not isinstance(candidate, dict):
        raise AcceptanceError("manifest candidate identity is not an object")
    if set(candidate) != {"path", "sha256", "size_bytes", "mode", "mtime_ns"}:
        raise AcceptanceError("manifest candidate identity has an unexpected shape")
    path = candidate.get("path")
    if not isinstance(path, str) or not path or not Path(path).is_absolute():
        raise AcceptanceError("manifest candidate path must be absolute")
    if not isinstance(candidate.get("sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", candidate["sha256"]
    ):
        raise AcceptanceError("manifest candidate SHA-256 is invalid")
    for field_name in ("size_bytes", "mtime_ns"):
        _exact_integer(candidate.get(field_name), f"manifest candidate {field_name}")
    if not isinstance(candidate.get("mode"), str) or not re.fullmatch(r"[0-7]{4}", candidate["mode"]):
        raise AcceptanceError("manifest candidate mode is invalid")


def parse_threshold(value: Any) -> Decimal:
    """Parse a finite threshold and enforce the non-negotiable 1.20 floor."""

    if isinstance(value, bool):
        raise AcceptanceError("threshold must be a decimal value, not a boolean")
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            raise AcceptanceError("threshold must be a finite non-negative decimal")
        text = value
    elif isinstance(value, Decimal):
        text = format(value, "f")
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise AcceptanceError("threshold must be finite")
        text = str(value)
    else:
        raise AcceptanceError("threshold must be a decimal value")
    try:
        threshold = Decimal(text)
    except InvalidOperation as error:
        raise AcceptanceError(f"invalid threshold {value!r}") from error
    if not threshold.is_finite():
        raise AcceptanceError("threshold must be finite")
    if threshold < MINIMUM_THRESHOLD:
        raise AcceptanceError(
            f"threshold {format(threshold, 'f')} is below the required "
            f"{format(MINIMUM_THRESHOLD, 'f')}"
        )
    return threshold


def decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _finite_decimal(value: Any, field_name: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{field_name} must be a non-boolean JSON number")
    if isinstance(value, float) and not math.isfinite(value):
        raise EvidenceError(f"{field_name} must be finite")
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise EvidenceError(f"{field_name} is not a valid decimal") from error
    if not result.is_finite():
        raise EvidenceError(f"{field_name} must be finite")
    if positive and result <= 0:
        raise EvidenceError(f"{field_name} must be greater than zero")
    return result


def _exact_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{field_name} must be a non-boolean integer")
    return value


def _positive_integer(value: Any, field_name: str) -> int:
    result = _exact_integer(value, field_name)
    if result <= 0:
        raise EvidenceError(f"{field_name} must be greater than zero")
    return result


def _counter(value: Any, field_name: str) -> int:
    result = _exact_integer(value, field_name)
    if result < 0:
        raise EvidenceError(f"{field_name} must not be negative")
    return result


def validate_raw_iperf(document: Any, identity: CellIdentity) -> dict[str, Any]:
    """Validate raw iperf3 JSON and retain delivered traffic independently."""

    if not isinstance(document, dict):
        raise EvidenceError("raw iperf document must be a JSON object")
    start = document.get("start")
    if not isinstance(start, dict):
        raise EvidenceError("raw iperf document lacks object start")
    connecting_to = start.get("connecting_to")
    if not isinstance(connecting_to, dict):
        raise EvidenceError("raw iperf document lacks object start.connecting_to")
    connecting_host = connecting_to.get("host")
    if not isinstance(connecting_host, str):
        raise EvidenceError("start.connecting_to.host must be a string")
    connecting_port = _exact_integer(connecting_to.get("port"), "start.connecting_to.port")
    if connecting_host != FORMAL_TARGET_HOST or connecting_port != FORMAL_TARGET_PORT:
        raise EvidenceError(
            f"start.connecting_to must be {FORMAL_TARGET_HOST}:{FORMAL_TARGET_PORT}"
        )
    connected = start.get("connected")
    if not isinstance(connected, list) or len(connected) != identity.parallel_flows:
        count = len(connected) if isinstance(connected, list) else "non-list"
        raise EvidenceError(
            f"raw iperf document has {count} connected streams; "
            f"expected {identity.parallel_flows}"
        )
    for index, connection in enumerate(connected):
        if not isinstance(connection, dict):
            raise EvidenceError(f"start.connected[{index}] must be an object")
        remote_host = connection.get("remote_host")
        if not isinstance(remote_host, str):
            raise EvidenceError(f"start.connected[{index}].remote_host must be a string")
        remote_port = _exact_integer(
            connection.get("remote_port"), f"start.connected[{index}].remote_port"
        )
        if remote_host != FORMAL_TARGET_HOST or remote_port != FORMAL_TARGET_PORT:
            raise EvidenceError(
                f"start.connected[{index}] must target {FORMAL_TARGET_HOST}:{FORMAL_TARGET_PORT}"
            )
    end = document.get("end")
    if not isinstance(end, dict):
        raise EvidenceError("raw iperf document lacks object end")
    aggregate_name = "sum_sent" if identity.direction == "ul" else "sum_received"
    stream_name = "sender" if identity.direction == "ul" else "receiver"
    aggregate = end.get(aggregate_name)
    if not isinstance(aggregate, dict):
        raise EvidenceError(f"raw iperf document lacks end.{aggregate_name}")
    goodput = _finite_decimal(
        aggregate.get("bits_per_second"),
        f"end.{aggregate_name}.bits_per_second",
        positive=True,
    )
    payload_bytes = _positive_integer(aggregate.get("bytes"), f"end.{aggregate_name}.bytes")
    seconds = _finite_decimal(aggregate.get("seconds"), f"end.{aggregate_name}.seconds", positive=True)
    streams = end.get("streams")
    if not isinstance(streams, list) or len(streams) != identity.parallel_flows:
        count = len(streams) if isinstance(streams, list) else "non-list"
        raise EvidenceError(
            f"raw iperf document has {count} {stream_name} streams; "
            f"expected {identity.parallel_flows}"
        )
    for index, stream in enumerate(streams):
        if not isinstance(stream, dict) or not isinstance(stream.get(stream_name), dict):
            raise EvidenceError(f"raw iperf stream {index} lacks {stream_name} object")
        _finite_decimal(
            stream[stream_name].get("bits_per_second"),
            f"end.streams[{index}].{stream_name}.bits_per_second",
            positive=True,
        )
    return {
        "delivered_goodput_bps": goodput,
        "delivered_payload_bytes": payload_bytes,
        "seconds": seconds,
    }


def _canonical_cell_root(artifact_root: Path, identity: CellIdentity) -> Path:
    root = Path(artifact_root).resolve(strict=False)
    return root / identity.relative_directory()


def expected_cell_environment(
    artifact_root: Path,
    identity: CellIdentity,
    run_uuid: str,
) -> dict[str, str]:
    """Return the one exact clean client environment for a matrix cell."""

    if not isinstance(run_uuid, str) or not run_uuid:
        raise AcceptanceError("run UUID is required for the client environment")
    cell = _canonical_cell_root(artifact_root, identity)
    environment = {
        **MINIMAL_BASE_ENVIRONMENT,
        "OPENPPP2_TAP_GSO_MERGE": "1",
        "OPENPPP2_DATAPATH_ACCEPTANCE_RUN_UUID": run_uuid,
        "OPENPPP2_DATAPATH_ACCEPTANCE_CELL_ID": identity.relative_directory(),
        "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_REQUEST": str(cell / "boundary-request.json"),
        "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_ACK": str(cell / "boundary-ack.json"),
    }
    if identity.stack == "xtcp":
        environment.update(XTCP_CLIENT_ENVIRONMENT)
    return environment


def expected_client_argv(
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> list[str]:
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict) or not isinstance(candidate.get("path"), str):
        raise AcceptanceError("manifest candidate identity is malformed")
    cell = _canonical_cell_root(artifact_root, identity)
    return [
        candidate["path"],
        "--mode=client",
        f"--config={cell / 'client-config.json'}",
        f"--tcp-stack={identity.stack}",
        f"--stats-json={cell / 'stats.ndjson'}",
    ]


def launch_environment_contract() -> dict[str, Any]:
    """Describe the immutable `env -i` contract, without ambient knobs."""

    return {
        "schema": LAUNCH_ENVIRONMENT_SCHEMA,
        "environment_mode": "env -i",
        "base_environment": dict(MINIMAL_BASE_ENVIRONMENT),
        "common_client_environment_names": list(COMMON_CLIENT_ENVIRONMENT_NAMES),
        "xtcp_client_environment": dict(XTCP_CLIENT_ENVIRONMENT),
        "forbidden_environment_names": sorted(FORBIDDEN_ENVIRONMENT_NAMES),
        "forbidden_environment_substrings": ["diagnostic", "perf", "sigusr1"],
        "stats_transport": "--stats-json=<absolute cell path>",
    }


def expected_launch_record(
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> dict[str, Any]:
    """Return the static portion of a launch record.

    Observed process, CPU, qdisc, and RPS/XPS evidence must be added only after
    a real launch.  This helper intentionally cannot construct valid proof by
    itself.
    """

    run_uuid = manifest.get("run_uuid")
    if not isinstance(run_uuid, str):
        raise AcceptanceError("manifest run UUID is malformed")
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise AcceptanceError("manifest candidate identity is malformed")
    return {
        "schema": LAUNCH_SCHEMA,
        "run_uuid": run_uuid,
        "role": "client",
        "cell": identity.as_dict(),
        "environment_mode": "env -i",
        "environment": expected_cell_environment(artifact_root, identity, run_uuid),
        "candidate": dict(candidate),
        "argv": expected_client_argv(artifact_root, manifest, identity),
        "config": {"path": "client-config.json", "sha256": "<observed-after-launch>"},
        "server_config": {"path": "server-config.json", "sha256": "<observed-after-launch>"},
        "stats": {"path": "stats.ndjson"},
        "boundary_request": {"path": "boundary-request.json"},
        "boundary_acknowledgement": {"path": "boundary-ack.json"},
    }


def _is_forbidden_environment_name(name: str) -> bool:
    lowered = name.lower()
    return name in FORBIDDEN_ENVIRONMENT_NAMES or any(
        marker in lowered for marker in ("diagnostic", "perf", "sigusr1")
    )


def _validate_exact_environment(
    environment: Any,
    expected: Mapping[str, str],
    description: str,
) -> None:
    if not isinstance(environment, dict) or any(
        not isinstance(name, str) or not isinstance(value, str) for name, value in environment.items()
    ):
        raise EvidenceError(f"{description} must be an object of string values")
    forbidden = sorted(name for name in environment if _is_forbidden_environment_name(name))
    if forbidden:
        raise EvidenceError(f"{description} contains forbidden environment variable(s): {', '.join(forbidden)}")
    if set(environment) != set(expected):
        unexpected = sorted(set(environment) - set(expected))
        missing = sorted(set(expected) - set(environment))
        detail = []
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        if missing:
            detail.append("missing=" + ",".join(missing))
        raise EvidenceError(f"{description} is not the exact clean environment ({'; '.join(detail)})")
    for name, value in expected.items():
        if environment.get(name) != value:
            raise EvidenceError(f"{description} {name} does not match the contract")


def _safe_relative_file(cell: Path, raw_path: Any, description: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise EvidenceError(f"{description} path must be a non-empty relative string")
    if raw_path.startswith("/") or "\\" in raw_path:
        raise EvidenceError(f"{description} path must be normalized relative to its cell")
    parts = raw_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise EvidenceError(f"{description} path is unsafe")
    root_metadata = _lstat(cell, f"cell directory {cell}", EvidenceError)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError(f"cell directory is not a real directory: {cell}")
    current = cell
    for index, part in enumerate(parts):
        current = current / part
        metadata = _lstat(current, f"{description} {raw_path}", EvidenceError)
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"{description} must not traverse a symlink: {raw_path}")
        if index != len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"{description} has a non-directory parent: {raw_path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{description} must identify a regular file: {raw_path}")
    return current


def _read_hashed_locator(cell: Path, locator: Any, description: str) -> tuple[Path, bytes]:
    if not isinstance(locator, dict) or set(locator) != {"path", "sha256"}:
        raise EvidenceError(f"{description} must contain exactly path and sha256")
    path = _safe_relative_file(cell, locator.get("path"), description)
    expected_hash = locator.get("sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise EvidenceError(f"{description} SHA-256 is invalid")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {description}: {error}") from None
    if _sha256_bytes(raw) != expected_hash:
        raise EvidenceError(f"{description} SHA-256 does not match retained bytes")
    return path, raw


def _validate_server_config(document: Any) -> None:
    if not isinstance(document, dict):
        raise EvidenceError("server config must be a JSON object")
    if _exact_integer(document.get("concurrent"), "server config concurrent") != 1:
        raise EvidenceError("server config must parse concurrent as integer 1")
    tcp = document.get("tcp")
    if not isinstance(tcp, dict):
        raise EvidenceError("server config tcp must be an object")
    listen = tcp.get("listen")
    if not isinstance(listen, dict):
        raise EvidenceError("server config tcp.listen must be an object")
    if _exact_integer(listen.get("port"), "server config tcp.listen.port") != 20000:
        raise EvidenceError("server config tcp.listen.port must be integer 20000")


def _validate_client_config(document: Any) -> None:
    if not isinstance(document, dict):
        raise EvidenceError("client config must be a JSON object")
    if _exact_integer(document.get("concurrent"), "client config concurrent") != 1:
        raise EvidenceError("client config must parse concurrent as integer 1")
    client = document.get("client")
    if not isinstance(client, dict):
        raise EvidenceError("client config client must be an object")
    if client.get("server") != "ppp://198.18.0.1:20000/":
        raise EvidenceError("client config client.server must be ppp://198.18.0.1:20000/")
    if "mappings" in client:
        raise EvidenceError("client config client.mappings is forbidden")


def _parse_cpu_list(value: str, description: str) -> list[int]:
    cpus: list[int] = []
    for item in value.strip().split(",") if value.strip() else []:
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise EvidenceError(f"{description} has an invalid CPU list")
        first = int(match.group(1))
        last = int(match.group(2) or match.group(1))
        if last < first:
            raise EvidenceError(f"{description} has a descending CPU range")
        cpus.extend(range(first, last + 1))
    if not cpus or len(cpus) != len(set(cpus)):
        raise EvidenceError(f"{description} has an invalid CPU list")
    return cpus


def _status_cpu_and_pid(raw: bytes, description: str) -> tuple[int, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description} is not UTF-8 proc status: {error}") from None
    pid_match = re.search(r"(?m)^Pid:\s*(\d+)\s*$", text)
    cpu_match = re.search(r"(?m)^Cpus_allowed_list:\s*([^\s]+)\s*$", text)
    if not pid_match or not cpu_match:
        raise EvidenceError(f"{description} lacks Pid or Cpus_allowed_list")
    pid = int(pid_match.group(1))
    cpus = _parse_cpu_list(cpu_match.group(1), description)
    if pid <= 0 or len(cpus) != 1:
        raise EvidenceError(f"{description} does not prove one process pinned to one CPU")
    return pid, cpus[0]


def _sched_migrations(raw: bytes, description: str) -> int:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description} is not UTF-8 proc sched: {error}") from None
    matches = re.findall(r"(?m)^(?:se\.)?nr_migrations\s*:\s*(\d+)\s*$", text)
    if len(matches) != 1:
        raise EvidenceError(f"{description} must contain exactly one nr_migrations counter")
    return int(matches[0])


ACCEPTANCE_BOUNDARY_FIELDS = frozenset(
    {
        "schema",
        "run_uuid",
        "cell_id",
        "sequence",
        "phase",
        "monotonic_ms",
        "process_pid",
        "process_start_ticks",
        "xtcp_runtime_instance_id",
    }
)


def _validate_acceptance_boundary(
    boundary: Any,
    *,
    run_uuid: str,
    cell_id: str,
    sequence: int | None,
    phase: str,
    description: str,
    root_monotonic_ms: int | None = None,
    expected_runtime_id: int | None = None,
    require_positive_runtime_id: bool = False,
) -> dict[str, Any]:
    if not isinstance(boundary, dict) or set(boundary) != ACCEPTANCE_BOUNDARY_FIELDS:
        raise EvidenceError(f"{description} must contain exactly the nine production boundary fields")
    if _exact_integer(boundary.get("schema"), f"{description}.schema") != 1:
        raise EvidenceError(f"{description}.schema must be integer 1")
    if any(not isinstance(boundary.get(field), str) for field in ("run_uuid", "cell_id", "phase")):
        raise EvidenceError(f"{description} string fields are invalid")
    if (
        boundary["run_uuid"] != run_uuid
        or boundary["cell_id"] != cell_id
        or boundary["phase"] != phase
    ):
        raise EvidenceError(f"{description} does not bind this run/cell/phase")
    actual_sequence = _positive_integer(boundary.get("sequence"), f"{description}.sequence")
    if sequence is not None and actual_sequence != sequence:
        raise EvidenceError(f"{description} sequence does not match the required boundary")
    monotonic_ms = _counter(boundary.get("monotonic_ms"), f"{description}.monotonic_ms")
    if root_monotonic_ms is not None and monotonic_ms != root_monotonic_ms:
        raise EvidenceError(f"{description} monotonic_ms does not match root ppp-stats monotonic_ms")
    _boundary_process_identity(boundary, description)
    runtime_id = _counter(
        boundary.get("xtcp_runtime_instance_id"), f"{description}.xtcp_runtime_instance_id"
    )
    if require_positive_runtime_id and runtime_id <= 0:
        raise EvidenceError(f"{description}.xtcp_runtime_instance_id must be greater than zero")
    if expected_runtime_id is not None and runtime_id != expected_runtime_id:
        raise EvidenceError(f"{description} runtime ID does not match XTCP runtime ID")
    return boundary


def _validate_final_boundary_request(
    path: Path,
    run_uuid: str,
    identity: CellIdentity,
) -> dict[str, Any]:
    request = read_json(path, "retained boundary request")
    expected_keys = {"schema", "run_uuid", "cell_id", "sequence", "phase"}
    if not isinstance(request, dict) or set(request) != expected_keys:
        raise EvidenceError("retained boundary request must contain exactly the five protocol fields")
    if _exact_integer(request.get("schema"), "retained boundary request.schema") != 1:
        raise EvidenceError("retained boundary request schema must be integer 1")
    if any(not isinstance(request.get(field), str) for field in ("run_uuid", "cell_id", "phase")):
        raise EvidenceError("retained boundary request string fields are invalid")
    if (
        request["run_uuid"] != run_uuid
        or request["cell_id"] != identity.relative_directory()
        or _positive_integer(request.get("sequence"), "retained boundary request.sequence") != 2
        or request["phase"] != "measurement_end"
    ):
        raise EvidenceError("retained boundary request is not the final matching measurement request")
    return request


def _validate_final_boundary_ack(
    path: Path,
    request: Mapping[str, Any],
    observed_pid: int,
    observed_start_ticks: int,
) -> dict[str, Any]:
    acknowledgement = read_json(path, "retained boundary acknowledgement")
    validated = _validate_acceptance_boundary(
        acknowledgement,
        run_uuid=request["run_uuid"],
        cell_id=request["cell_id"],
        sequence=request["sequence"],
        phase=request["phase"],
        description="retained boundary acknowledgement",
    )
    acknowledgement_pid, acknowledgement_start_ticks = _boundary_process_identity(
        validated, "retained boundary acknowledgement"
    )
    if acknowledgement_pid != observed_pid or acknowledgement_start_ticks != observed_start_ticks:
        raise EvidenceError("retained boundary acknowledgement process identity does not match the observed launch")
    return validated


def _validate_v2_launch_record(
    document: Any,
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> dict[str, Any]:
    """Validate exact v2 launch arguments and retained process evidence."""

    if not isinstance(document, dict):
        raise EvidenceError("launch record must be a JSON object")
    expected_keys = {
        "schema",
        "run_uuid",
        "role",
        "cell",
        "environment_mode",
        "environment",
        "candidate",
        "argv",
        "config",
        "server_config",
        "stats",
        "boundary_request",
        "boundary_acknowledgement",
        "observed_process",
        "cpu",
        "tun",
        "qdisc",
        "rps_xps",
    }
    if set(document) != expected_keys:
        raise EvidenceError("launch record has an incomplete or unexpected v2 shape")
    if document.get("schema") != LAUNCH_SCHEMA:
        raise EvidenceError(f"launch record schema must be {LAUNCH_SCHEMA!r}")
    run_uuid = manifest.get("run_uuid")
    if document.get("run_uuid") != run_uuid:
        raise EvidenceError("launch record run UUID does not match the manifest")
    if document.get("role") != "client":
        raise EvidenceError("launch record role must be client")
    if document.get("cell") != identity.as_dict():
        raise EvidenceError("launch record cell identity does not match its artifact path")
    if document.get("environment_mode") != "env -i":
        raise EvidenceError("launch record must declare environment_mode=env -i")
    if not isinstance(run_uuid, str):
        raise EvidenceError("manifest run UUID is malformed")
    expected_environment = expected_cell_environment(artifact_root, identity, run_uuid)
    _validate_exact_environment(document.get("environment"), expected_environment, "launch record environment")

    candidate = document.get("candidate")
    manifest_candidate = manifest.get("candidate")
    if not isinstance(candidate, dict) or candidate != manifest_candidate:
        raise EvidenceError("launch record candidate identity does not match the manifest")
    expected_argv = expected_client_argv(artifact_root, manifest, identity)
    if document.get("argv") != expected_argv:
        raise EvidenceError("launch record argv is not the exact client command")

    cell = _canonical_cell_root(artifact_root, identity)
    config_path, config_raw = _read_hashed_locator(cell, document.get("config"), "client config")
    if document["config"].get("path") != "client-config.json":
        raise EvidenceError("client config locator must be client-config.json")
    _validate_client_config(parse_json_bytes(config_raw, "client config"))
    server_config_path, server_config_raw = _read_hashed_locator(
        cell, document.get("server_config"), "server config"
    )
    if document["server_config"].get("path") != "server-config.json":
        raise EvidenceError("server config locator must be server-config.json")
    _ = server_config_path
    _validate_server_config(parse_json_bytes(server_config_raw, "server config"))

    stats = document.get("stats")
    if not isinstance(stats, dict) or set(stats) != {"path"} or stats.get("path") != "stats.ndjson":
        raise EvidenceError("launch stats locator must be the relative stats.ndjson path")
    stats_path = _safe_relative_file(cell, stats.get("path"), "launch stats")
    request = document.get("boundary_request")
    if not isinstance(request, dict) or set(request) != {"path"} or request.get("path") != "boundary-request.json":
        raise EvidenceError("launch boundary request locator is invalid")
    request_path = _safe_relative_file(cell, request.get("path"), "boundary request")
    acknowledgement = document.get("boundary_acknowledgement")
    if (
        not isinstance(acknowledgement, dict)
        or set(acknowledgement) != {"path"}
        or acknowledgement.get("path") != "boundary-ack.json"
    ):
        raise EvidenceError("launch boundary acknowledgement locator is invalid")
    acknowledgement_path = _safe_relative_file(cell, acknowledgement.get("path"), "boundary acknowledgement")
    final_request = _validate_final_boundary_request(request_path, run_uuid, identity)

    observed = document.get("observed_process")
    if not isinstance(observed, dict) or set(observed) != {
        "pid", "start_ticks", "executable", "cmdline", "environment"
    }:
        raise EvidenceError("launch record observed_process has an incomplete shape")
    observed_pid = _positive_integer(observed.get("pid"), "observed process pid")
    observed_start_ticks = _positive_integer(observed.get("start_ticks"), "observed process start_ticks")
    executable = observed.get("executable")
    if not isinstance(executable, dict) or set(executable) != {"path", "sha256"}:
        raise EvidenceError("observed executable must contain exactly path and sha256")
    if executable.get("path") != manifest_candidate.get("path") or executable.get("sha256") != manifest_candidate.get("sha256"):
        raise EvidenceError("observed executable path/hash does not match the candidate")
    if observed.get("cmdline") != expected_argv:
        raise EvidenceError("observed cmdline is not the exact client argv")
    _validate_exact_environment(observed.get("environment"), expected_environment, "observed process environment")
    final_acknowledgement = _validate_final_boundary_ack(
        acknowledgement_path,
        final_request,
        observed_pid,
        observed_start_ticks,
    )

    cpu = document.get("cpu")
    expected_cpu_keys = {
        "affinity_cpu",
        "before",
        "after",
        "migration_before",
        "migration_after",
        "migration_delta",
    }
    if not isinstance(cpu, dict) or set(cpu) != expected_cpu_keys:
        raise EvidenceError("CPU proof has an incomplete shape")
    affinity_cpu = _exact_integer(cpu.get("affinity_cpu"), "CPU affinity_cpu")
    if affinity_cpu < 0:
        raise EvidenceError("CPU affinity_cpu must be non-negative")
    before = cpu.get("before")
    after = cpu.get("after")
    if not isinstance(before, dict) or set(before) != {"status", "sched"}:
        raise EvidenceError("CPU before proof must contain status and sched")
    if not isinstance(after, dict) or set(after) != {"status", "sched"}:
        raise EvidenceError("CPU after proof must contain status and sched")
    before_status_path, before_status = _read_hashed_locator(cell, before["status"], "CPU before status")
    _ = before_status_path
    before_sched_path, before_sched = _read_hashed_locator(cell, before["sched"], "CPU before sched")
    _ = before_sched_path
    after_status_path, after_status = _read_hashed_locator(cell, after["status"], "CPU after status")
    _ = after_status_path
    after_sched_path, after_sched = _read_hashed_locator(cell, after["sched"], "CPU after sched")
    _ = after_sched_path
    for status_raw, label in ((before_status, "CPU before status"), (after_status, "CPU after status")):
        status_pid, status_cpu = _status_cpu_and_pid(status_raw, label)
        if status_pid != observed_pid or status_cpu != affinity_cpu:
            raise EvidenceError(f"{label} does not match observed process identity/affinity")
    actual_before_migrations = _sched_migrations(before_sched, "CPU before sched")
    actual_after_migrations = _sched_migrations(after_sched, "CPU after sched")
    if cpu.get("migration_before") != actual_before_migrations or cpu.get("migration_after") != actual_after_migrations:
        raise EvidenceError("CPU migration counters do not match retained proc sched evidence")
    if cpu.get("migration_delta") != actual_after_migrations - actual_before_migrations:
        raise EvidenceError("CPU migration delta does not match retained proc sched evidence")
    if cpu.get("migration_delta") != 0:
        raise EvidenceError("CPU migration delta must be zero during formal traffic")

    tun = document.get("tun")
    if not isinstance(tun, dict) or set(tun) != {"interface", "route", "link"}:
        raise EvidenceError("TUN proof has an incomplete shape")
    tun_interface = tun.get("interface")
    if not isinstance(tun_interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", tun_interface):
        raise EvidenceError("TUN proof interface is invalid")
    route_path, route_raw = _read_hashed_locator(cell, tun.get("route"), "TUN target route")
    link_path, link_raw = _read_hashed_locator(cell, tun.get("link"), "TUN link")
    if route_path.name != "target-route.txt" or link_path.name != "tun-link.txt":
        raise EvidenceError("TUN proof must retain canonical target-route.txt and tun-link.txt")
    try:
        route_text = route_raw.decode("utf-8")
        link_text = link_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"TUN proof is not UTF-8: {error}") from None
    if not re.search(
        rf"(?m)^{re.escape(FORMAL_TARGET_HOST)}\b.*\bdev\s+{re.escape(tun_interface)}\b",
        route_text,
    ):
        raise EvidenceError(
            f"TUN target route does not resolve {FORMAL_TARGET_HOST} through the recorded interface"
        )
    if not re.search(r"\bPOINTOPOINT\b", link_text):
        raise EvidenceError("TUN link proof does not show a point-to-point interface")

    qdiscs = document.get("qdisc")
    if not isinstance(qdiscs, list) or not qdiscs:
        raise EvidenceError("qdisc proof must contain retained readbacks")
    qdisc_paths: set[str] = set()
    for index, qdisc in enumerate(qdiscs):
        if not isinstance(qdisc, dict) or set(qdisc) != {"interface", "path", "sha256"}:
            raise EvidenceError(f"qdisc proof {index} has an invalid shape")
        interface = qdisc.get("interface")
        if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            raise EvidenceError(f"qdisc proof {index} interface is invalid")
        if qdisc["path"] in qdisc_paths:
            raise EvidenceError("qdisc proof reuses a retained readback path")
        qdisc_paths.add(qdisc["path"])
        _path, qdisc_raw = _read_hashed_locator(
            cell, {"path": qdisc["path"], "sha256": qdisc["sha256"]}, f"qdisc readback {index}"
        )
        try:
            qdisc_text = qdisc_raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"qdisc readback {index} is not UTF-8: {error}") from None
        if not qdisc_text.strip() or re.search(r"\bnetem\b", qdisc_text, flags=re.IGNORECASE):
            raise EvidenceError(f"qdisc readback {index} is empty or contains netem")

    _rps_path, rps_raw = _read_hashed_locator(cell, document.get("rps_xps"), "RPS/XPS readback")
    rps_document = parse_json_bytes(rps_raw, "RPS/XPS readback")
    if not isinstance(rps_document, dict) or not isinstance(rps_document.get("reads"), list):
        raise EvidenceError("RPS/XPS readback must contain a reads list")
    kinds: set[str] = set()
    for index, readback in enumerate(rps_document["reads"]):
        if not isinstance(readback, dict):
            raise EvidenceError(f"RPS/XPS readback {index} is not an object")
        kind = readback.get("kind")
        value = readback.get("value")
        path = readback.get("path")
        if kind not in {"rps", "xps"} or not isinstance(path, str) or not path or not isinstance(value, str) or not value.strip():
            raise EvidenceError(f"RPS/XPS readback {index} is incomplete")
        kinds.add(kind)
    if kinds != {"rps", "xps"}:
        raise EvidenceError("RPS/XPS readback must contain non-empty RPS and XPS reads")

    return {
        "pid": observed_pid,
        "start_ticks": observed_start_ticks,
        "stats_path": stats_path,
        "stats_relative_path": stats["path"],
        "final_acknowledgement": final_acknowledgement,
    }


_V3_QDISC_DYNAMIC_FIELDS = frozenset(
    {
        "backlog",
        "bytes",
        "drops",
        "handle",
        "overlimits",
        "packets",
        "qlen",
        "requeues",
        "refcnt",
        "xstats",
    }
)
_V3_FILTER_DYNAMIC_FIELDS = _V3_QDISC_DYNAMIC_FIELDS | frozenset({"in_hw", "not_in_hw"})
_V3_INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_V3_TUNNEL_NAMESPACE_PATTERN = re.compile(r"dpa-t-([0-9a-f]{9})")


def _v3_profile_copy(profile: Any) -> Any:
    """Convert a catalog mapping to ordinary JSON values before validation."""

    return _profile_copy(profile) if isinstance(profile, Mapping) else profile


def expected_netem_environment(cell: Path, profile: Any) -> dict[str, str]:
    """Return the one clean environment allowed for a v3 netem command."""

    canonical_profile = validate_network_profile(_v3_profile_copy(profile))
    try:
        cell_path = Path(cell)
    except TypeError as error:
        raise AcceptanceError("netem cell path is invalid") from error
    environment = dict(MINIMAL_BASE_ENVIRONMENT)
    if canonical_profile["jitter_per_direction_us"]:
        environment["TC_LIB_DIR"] = str((cell_path / "netem-tc-lib").resolve(strict=False))
    return environment


def _iid_loss_percentage(profile: Mapping[str, Any]) -> str:
    probability_ppm = profile["loss"]["probability_ppm"]
    percentages = {1000: "0.1%", 5000: "0.5%", 10000: "1%"}
    try:
        return percentages[probability_ppm]
    except KeyError as error:
        raise AcceptanceError("closed iid profile has an unsupported loss probability") from error


def expected_netem_qdisc_apply_argv(
    cell: Path,
    interface: str,
    profile: Any,
    seed: Any,
) -> list[str]:
    """Return the exact profile-derived root-netem command for one carrier side."""

    canonical_profile = validate_network_profile(_v3_profile_copy(profile))
    if not isinstance(interface, str) or not _V3_INTERFACE_PATTERN.fullmatch(interface):
        raise AcceptanceError("netem interface is invalid")
    campaign_seed = validate_campaign_seed(seed)
    # The environment helper validates the cell path and preserves the public
    # command/environment pairing even though the cell is not an argv operand.
    _ = expected_netem_environment(cell, canonical_profile)
    argv = [
        "tc",
        "qdisc",
        "replace",
        "dev",
        interface,
        "root",
        "netem",
        "limit",
        str(canonical_profile["queue_limit_packets"]),
        "delay",
        f"{canonical_profile['one_way_delay_us']}us",
    ]
    if canonical_profile["jitter_per_direction_us"]:
        argv.extend(
            [
                f"{canonical_profile['jitter_per_direction_us']}us",
                "0%",
                "distribution",
                "uniform",
            ]
        )
    if canonical_profile["loss"]["mode"] == "iid_random":
        argv.extend(["loss", "random", _iid_loss_percentage(canonical_profile)])
    argv.extend(["seed", str(campaign_seed)])
    return argv


def _v3_read_json_locator(cell: Path, locator: Any, description: str) -> Any:
    _path, raw = _read_hashed_locator(cell, locator, description)
    return parse_json_bytes(raw, description)


def _v3_exact_local_locator(
    cell: Path,
    locator: Any,
    expected_path: str,
    description: str,
) -> tuple[Path, bytes]:
    if not isinstance(locator, dict) or locator.get("path") != expected_path:
        raise EvidenceError(f"{description} must be the local {expected_path} locator")
    return _read_hashed_locator(cell, locator, description)


def expected_periodic_bpf_compiler_argv(source_path: str, object_path: str, every_n: int) -> list[str]:
    """Return the exact local command used to compile a periodic carrier BPF object."""

    return [
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


def expected_periodic_bpf_clsact_apply_argv(interface: str) -> list[str]:
    """Return the exact clsact command for a periodic carrier target."""

    return ["tc", "qdisc", "replace", "dev", interface, "clsact"]


def expected_periodic_bpf_filter_apply_argv(interface: str, object_path: str) -> list[str]:
    """Return the exact direct-action egress filter command for a local BPF object."""

    return [
        "tc",
        "filter",
        "replace",
        "dev",
        interface,
        "egress",
        "protocol",
        "all",
        "chain",
        "0",
        "bpf",
        "da",
        "obj",
        object_path,
        "sec",
        PERIODIC_CARRIER_BPF_SECTION,
    ]


def _v3_qdisc_snapshot(cell: Path, locator: Any, description: str) -> list[dict[str, Any]]:
    document = _v3_read_json_locator(cell, locator, description)
    if not isinstance(document, list) or not document:
        raise EvidenceError(f"{description} must be a non-empty JSON array")
    snapshots: list[dict[str, Any]] = []
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise EvidenceError(f"{description}[{index}] must be a JSON object")
        kind = entry.get("kind")
        if not isinstance(kind, str) or not kind:
            raise EvidenceError(f"{description}[{index}] has no qdisc kind")
        snapshots.append(entry)
    return snapshots


def _v3_contains_netem(value: Any) -> bool:
    if isinstance(value, str):
        return "netem" in value.lower()
    if isinstance(value, dict):
        return any(_v3_contains_netem(item) for item in value.values())
    if isinstance(value, list):
        return any(_v3_contains_netem(item) for item in value)
    return False


def _v3_normalized_qdiscs(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in entry.items() if key not in _V3_QDISC_DYNAMIC_FIELDS}
        for entry in entries
    ]


def _v3_decimal(value: Any, description: str) -> Decimal:
    return _finite_decimal(value, description)


def _v3_require_decimal(value: Any, expected: Decimal, description: str) -> None:
    if _v3_decimal(value, description) != expected:
        raise EvidenceError(f"{description} does not match the closed network profile")


def _v3_validate_netem_options(
    options: Any,
    profile: Mapping[str, Any],
    seed: int,
    description: str,
) -> None:
    if not isinstance(options, dict):
        raise EvidenceError(f"{description} options must be an object")
    mode = profile["loss"]["mode"]
    allowed = {"limit", "delay", "seed", "ecn", "gap"}
    if mode == "iid_random":
        allowed.add("loss-random")
    unexpected = sorted(set(options) - allowed)
    if unexpected:
        raise EvidenceError(f"{description} has forbidden netem option(s): {', '.join(unexpected)}")
    required = {"limit", "delay", "seed"}
    if not required.issubset(options):
        raise EvidenceError(f"{description} lacks required netem options")
    if _exact_integer(options.get("limit"), f"{description}.limit") != profile["queue_limit_packets"]:
        raise EvidenceError(f"{description}.limit does not match the closed network profile")
    if _exact_integer(options.get("seed"), f"{description}.seed") != seed:
        raise EvidenceError(f"{description}.seed does not match the derived directional seed")
    delay = options.get("delay")
    if not isinstance(delay, dict) or set(delay) != {"delay", "jitter", "correlation"}:
        raise EvidenceError(f"{description}.delay has an incomplete or unexpected shape")
    _v3_require_decimal(
        delay.get("delay"),
        Decimal(profile["one_way_delay_us"]) / Decimal(1_000_000),
        f"{description}.delay.delay",
    )
    _v3_require_decimal(
        delay.get("jitter"),
        Decimal(profile["jitter_per_direction_us"]) / Decimal(1_000_000),
        f"{description}.delay.jitter",
    )
    _v3_require_decimal(delay.get("correlation"), Decimal(0), f"{description}.delay.correlation")
    if "ecn" in options and options["ecn"] is not False:
        raise EvidenceError(f"{description}.ecn must be false when present")
    if "gap" in options and _exact_integer(options["gap"], f"{description}.gap") != 0:
        raise EvidenceError(f"{description}.gap must be zero when present")
    if mode == "iid_random":
        loss = options.get("loss-random")
        if not isinstance(loss, dict) or set(loss) != {"loss", "correlation"}:
            raise EvidenceError(f"{description}.loss-random has an incomplete or unexpected shape")
        _v3_require_decimal(
            loss.get("loss"),
            Decimal(profile["loss"]["probability_ppm"]) / Decimal(1_000_000),
            f"{description}.loss-random.loss",
        )
        _v3_require_decimal(loss.get("correlation"), Decimal(0), f"{description}.loss-random.correlation")
    elif "loss-random" in options:
        raise EvidenceError(f"{description} must not configure netem random loss for this profile")


def _v3_validate_active_qdiscs(
    entries: list[dict[str, Any]],
    profile: Mapping[str, Any],
    seed: int,
    description: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    root_netem = [entry for entry in entries if entry.get("kind") == "netem"]
    clsacts = [entry for entry in entries if entry.get("kind") == "clsact"]
    expected_count = 2 if profile["loss"]["mode"] == "periodic_carrier_skb" else 1
    if len(entries) != expected_count or len(root_netem) != 1 or len(clsacts) != expected_count - 1:
        raise EvidenceError(f"{description} must contain only the required root netem qdisc")
    netem = root_netem[0]
    if netem.get("root") is not True or "parent" in netem:
        raise EvidenceError(f"{description} netem must be the root qdisc")
    _v3_validate_netem_options(netem.get("options"), profile, seed, f"{description} netem")
    clsact = clsacts[0] if clsacts else None
    if clsact is not None and (
        clsact.get("root") is True or clsact.get("parent") != "ffff:fff1"
    ):
        raise EvidenceError(f"{description} clsact must be the canonical non-root clsact qdisc")
    return netem, clsact


def _v3_qdisc_counters(entry: Mapping[str, Any], description: str) -> tuple[int, int, int, int]:
    return (
        _counter(entry.get("bytes"), f"{description}.bytes"),
        _counter(entry.get("packets"), f"{description}.packets"),
        _counter(entry.get("drops"), f"{description}.drops"),
        _counter(entry.get("overlimits"), f"{description}.overlimits"),
    )


def _v3_validate_qdisc_evidence(
    cell: Path,
    value: Any,
    profile: Mapping[str, Any],
    seed: int,
    description: str,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(value, dict) or set(value) != {"pre", "immediate", "post"}:
        raise EvidenceError(f"{description} must contain exactly pre, immediate, and post locators")
    pre = _v3_qdisc_snapshot(cell, value["pre"], f"{description} pre")
    if _v3_contains_netem(pre):
        raise EvidenceError(f"{description} pre snapshot contains netem")
    immediate = _v3_qdisc_snapshot(cell, value["immediate"], f"{description} immediate")
    post = _v3_qdisc_snapshot(cell, value["post"], f"{description} post")
    immediate_netem, immediate_clsact = _v3_validate_active_qdiscs(
        immediate, profile, seed, f"{description} immediate"
    )
    post_netem, post_clsact = _v3_validate_active_qdiscs(post, profile, seed, f"{description} post")
    if _v3_normalized_qdiscs(immediate) != _v3_normalized_qdiscs(post):
        raise EvidenceError(f"{description} static qdisc configuration changed during formal traffic")
    immediate_bytes, immediate_packets, immediate_drops, immediate_overlimits = _v3_qdisc_counters(
        immediate_netem, f"{description} immediate netem"
    )
    post_bytes, post_packets, post_drops, post_overlimits = _v3_qdisc_counters(
        post_netem, f"{description} post netem"
    )
    if post_bytes <= immediate_bytes or post_packets <= immediate_packets:
        raise EvidenceError(f"{description} netem traffic counters must increase during formal traffic")
    if post_drops < immediate_drops or post_overlimits < immediate_overlimits:
        raise EvidenceError(f"{description} netem counters must be nondecreasing")
    loss_mode = profile["loss"]["mode"]
    if loss_mode == "none" and any(
        (immediate_drops, immediate_overlimits, post_drops, post_overlimits)
    ):
        raise EvidenceError(f"{description} no-loss netem counters must remain zero")
    # Direct-action TC_ACT_SHOT may be charged to root netem drops by the
    # kernel.  For periodic carrier-SKB loss, the BPF counters below are the
    # authoritative loss proof; root drops remain only nondecreasing.
    if immediate_overlimits != 0 or post_overlimits != 0:
        raise EvidenceError(f"{description} netem overlimits must remain zero")
    return immediate_netem, immediate_clsact, post_clsact, immediate, post


def _v3_link_snapshot(
    cell: Path,
    locator: Any,
    interface: str,
    description: str,
) -> tuple[dict[str, Any], int, int]:
    document = _v3_read_json_locator(cell, locator, description)
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise EvidenceError(f"{description} must be a one-interface JSON array")
    link = document[0]
    if link.get("ifname") != interface:
        raise EvidenceError(f"{description} does not identify the target interface")
    stats = link.get("stats64")
    if not isinstance(stats, dict) or not isinstance(stats.get("tx"), dict):
        raise EvidenceError(f"{description} lacks stats64.tx")
    tx = stats["tx"]
    return (
        link,
        _counter(tx.get("bytes"), f"{description}.stats64.tx.bytes"),
        _counter(tx.get("packets"), f"{description}.stats64.tx.packets"),
    )


def _v3_validate_link_evidence(cell: Path, value: Any, interface: str, description: str) -> None:
    if not isinstance(value, dict) or set(value) != {"pre", "post"}:
        raise EvidenceError(f"{description} must contain exactly pre and post locators")
    pre, pre_bytes, pre_packets = _v3_link_snapshot(cell, value["pre"], interface, f"{description} pre")
    post, post_bytes, post_packets = _v3_link_snapshot(cell, value["post"], interface, f"{description} post")
    normalized_pre = {key: nested for key, nested in pre.items() if key not in {"stats", "stats64"}}
    normalized_post = {key: nested for key, nested in post.items() if key not in {"stats", "stats64"}}
    if normalized_pre != normalized_post:
        raise EvidenceError(f"{description} configuration changed during formal traffic")
    if post_bytes <= pre_bytes or post_packets <= pre_packets:
        raise EvidenceError(f"{description} TX bytes and packets must increase during formal traffic")


def _v3_validate_offload_evidence(cell: Path, value: Any, description: str) -> None:
    if not isinstance(value, dict) or set(value) != {"pre", "post"}:
        raise EvidenceError(f"{description} must contain exactly pre and post locators")
    _pre_path, pre = _read_hashed_locator(cell, value["pre"], f"{description} pre")
    _post_path, post = _read_hashed_locator(cell, value["post"], f"{description} post")
    try:
        pre.decode("utf-8")
        post.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description} is not UTF-8: {error}") from None
    if not pre.strip() or pre != post:
        raise EvidenceError(f"{description} must be non-empty and byte-identical before and after traffic")


def _v3_normalized_filter(entry: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {key: value for key, value in entry.items() if key not in _V3_FILTER_DYNAMIC_FIELDS}
    options = normalized.get("options")
    if isinstance(options, dict):
        copied_options = {key: value for key, value in options.items() if key != "handle"}
        program = copied_options.get("prog")
        if isinstance(program, dict):
            copied_options["prog"] = {key: value for key, value in program.items() if key != "id"}
        normalized["options"] = copied_options
    return normalized


def _v3_periodic_filter_snapshot(cell: Path, locator: Any, description: str) -> list[dict[str, Any]]:
    """Validate tc's detailed BPF record with its optional terse companion."""

    document = _v3_read_json_locator(cell, locator, description)
    if not isinstance(document, list) or len(document) not in (1, 2):
        raise EvidenceError(f"{description} must contain one detailed BPF filter and at most one terse companion")
    if not all(isinstance(record, dict) for record in document):
        raise EvidenceError(f"{description} filter records must be JSON objects")

    filter_records: list[dict[str, Any]] = document
    detailed_records = [record for record in filter_records if isinstance(record.get("options"), dict)]
    if len(detailed_records) != 1:
        raise EvidenceError(f"{description} must contain exactly one configured BPF filter")
    if len(filter_records) == 2:
        terse_record = next(record for record in filter_records if record not in detailed_records)
        if "options" in terse_record or set(terse_record) != {"protocol", "pref", "kind", "chain"}:
            raise EvidenceError(f"{description} terse BPF companion is malformed")

    pref: int | None = None
    for index, filter_record in enumerate(filter_records):
        if filter_record.get("kind") != "bpf":
            raise EvidenceError(f"{description}[{index}] must be a BPF filter")
        if (
            filter_record.get("protocol") != "all"
            or _exact_integer(filter_record.get("chain"), f"{description}[{index}].chain") != 0
        ):
            raise EvidenceError(f"{description}[{index}] is not the expected all-protocol chain-zero filter")
        record_pref = _positive_integer(filter_record.get("pref"), f"{description}[{index}].pref")
        if pref is None:
            pref = record_pref
        elif record_pref != pref:
            raise EvidenceError(f"{description} BPF filter records have different preferences")

    detailed_record = detailed_records[0]
    options = detailed_record["options"]
    if (
        options.get("bpf_name") != PERIODIC_CARRIER_BPF_NAME
        or options.get("direct-action") is not True
    ):
        raise EvidenceError(f"{description} does not bind the periodic direct-action BPF program")
    if "actions" in detailed_record:
        raise EvidenceError(f"{description} must not add non-direct tc actions")
    program = options.get("prog")
    if not isinstance(program, dict):
        raise EvidenceError(f"{description} lacks BPF program metadata")
    _positive_integer(program.get("id"), f"{description}.options.prog.id")
    return filter_records


def _v3_periodic_map_snapshot(cell: Path, locator: Any, description: str) -> tuple[int, int]:
    document = _v3_read_json_locator(cell, locator, description)
    if not isinstance(document, dict) or set(document) != {"global_seen", "global_dropped"}:
        raise EvidenceError(f"{description} has an incomplete or unexpected map shape")
    return (
        _counter(document.get("global_seen"), f"{description}.global_seen"),
        _counter(document.get("global_dropped"), f"{description}.global_dropped"),
    )


def _v3_validate_periodic_bpf_qdisc_snapshot(
    cell: Path,
    locator: Any,
    *,
    phase: str,
    description: str,
) -> dict[str, Any] | None:
    entries = _v3_qdisc_snapshot(cell, locator, description)
    clsacts = [entry for entry in entries if entry.get("kind") == "clsact"]
    filters = [entry for entry in entries if entry.get("kind") == "bpf"]
    if phase == "pre":
        if clsacts or filters:
            raise EvidenceError(f"{description} must prove no clsact or BPF filter before installation")
        return None
    if len(entries) != 1 or len(clsacts) != 1 or filters:
        raise EvidenceError(f"{description} must contain exactly the installed clsact qdisc")
    clsact = clsacts[0]
    if clsact.get("root") is True or clsact.get("parent") != "ffff:fff1":
        raise EvidenceError(f"{description} clsact must be the canonical non-root clsact qdisc")
    return clsact


def _v3_source_inventory_file_sha256(
    source_inventory: Mapping[str, Any],
    source_path: str,
    description: str,
) -> str:
    entries = source_inventory.get("entries")
    if not isinstance(entries, list):
        raise EvidenceError("validated source inventory lacks entries")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == source_path]
    if len(matches) != 1 or matches[0].get("kind") != "file":
        raise EvidenceError(f"{description} is not present as a file in the v3 source inventory")
    source_hash = matches[0].get("sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise EvidenceError(f"{description} source inventory SHA-256 is invalid")
    return source_hash


def _v3_validate_periodic_bpf(
    cell: Path,
    value: Any,
    profile: Mapping[str, Any],
    interface: str,
    source_inventory: Mapping[str, Any],
    description: str,
) -> None:
    expected_keys = {
        "source",
        "object",
        "compiler",
        "compiler_version",
        "clsact_apply_argv",
        "filter_apply_argv",
        "qdisc",
        "filters",
        "maps",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise EvidenceError(f"{description} has an incomplete or unexpected shape")
    source_path = "periodic-bpf/source.c"
    object_path = "periodic-bpf/datapath_fixed_loss.bpf.c"
    source_locator = value.get("source")
    _source_path, source_raw = _v3_exact_local_locator(cell, source_locator, source_path, f"{description}.source")
    if not isinstance(source_locator, dict):
        raise EvidenceError(f"{description}.source must be a local source locator")
    expected_source_hash = _v3_source_inventory_file_sha256(
        source_inventory,
        PERIODIC_CARRIER_BPF_SOURCE_PATH,
        f"{description}.source",
    )
    if source_locator.get("sha256") != expected_source_hash or _sha256_bytes(source_raw) != expected_source_hash:
        raise EvidenceError(f"{description}.source does not match the v3 source inventory")
    _object_path, object_raw = _v3_exact_local_locator(cell, value.get("object"), object_path, f"{description}.object")
    if not object_raw:
        raise EvidenceError(f"{description}.object must be non-empty")
    compiler = value.get("compiler")
    if not isinstance(compiler, dict) or set(compiler) != {"argv", "stdout", "stderr", "exit_code"}:
        raise EvidenceError(f"{description}.compiler has an incomplete or unexpected shape")
    every_n = profile["loss"]["every_n"]
    if compiler.get("argv") != expected_periodic_bpf_compiler_argv(source_path, object_path, every_n):
        raise EvidenceError(f"{description}.compiler argv is not the exact local periodic BPF build command")
    if _exact_integer(compiler.get("exit_code"), f"{description}.compiler.exit_code") != 0:
        raise EvidenceError(f"{description}.compiler exit_code must be zero")
    for stream in ("stdout", "stderr"):
        _stream_path, raw = _v3_exact_local_locator(
            cell,
            compiler.get(stream),
            f"periodic-bpf/compiler.{stream}",
            f"{description}.compiler.{stream}",
        )
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"{description}.compiler.{stream} is not UTF-8: {error}") from None
    _version_path, version_raw = _v3_exact_local_locator(
        cell,
        value.get("compiler_version"),
        "periodic-bpf/compiler-version.txt",
        f"{description}.compiler_version",
    )
    try:
        version_text = version_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description}.compiler_version is not UTF-8: {error}") from None
    if not version_text.strip():
        raise EvidenceError(f"{description}.compiler_version must be non-empty")
    if value.get("clsact_apply_argv") != expected_periodic_bpf_clsact_apply_argv(interface):
        raise EvidenceError(f"{description}.clsact_apply_argv is not the exact clsact command")
    if value.get("filter_apply_argv") != expected_periodic_bpf_filter_apply_argv(interface, object_path):
        raise EvidenceError(f"{description}.filter_apply_argv is not the exact direct-action BPF command")
    qdisc = value.get("qdisc")
    if not isinstance(qdisc, dict) or set(qdisc) != {"pre", "immediate", "post"}:
        raise EvidenceError(f"{description}.qdisc has an incomplete or unexpected shape")
    _v3_validate_periodic_bpf_qdisc_snapshot(cell, qdisc["pre"], phase="pre", description=f"{description}.qdisc pre")
    immediate_clsact = _v3_validate_periodic_bpf_qdisc_snapshot(
        cell, qdisc["immediate"], phase="immediate", description=f"{description}.qdisc immediate"
    )
    post_clsact = _v3_validate_periodic_bpf_qdisc_snapshot(
        cell, qdisc["post"], phase="post", description=f"{description}.qdisc post"
    )
    filters = value.get("filters")
    maps = value.get("maps")
    if not isinstance(filters, dict) or set(filters) != {"pre", "immediate", "post"}:
        raise EvidenceError(f"{description}.filters has an incomplete or unexpected shape")
    if not isinstance(maps, dict) or set(maps) != {"immediate", "post"}:
        raise EvidenceError(f"{description}.maps has an incomplete or unexpected shape")
    pre_filters = _v3_read_json_locator(cell, filters["pre"], f"{description}.filters pre")
    if not isinstance(pre_filters, list) or pre_filters:
        raise EvidenceError(f"{description}.filters pre must prove no BPF filter")
    immediate_filters = _v3_periodic_filter_snapshot(
        cell, filters["immediate"], f"{description}.filters immediate"
    )
    post_filters = _v3_periodic_filter_snapshot(cell, filters["post"], f"{description}.filters post")
    if [
        _v3_normalized_filter(filter_record) for filter_record in immediate_filters
    ] != [
        _v3_normalized_filter(filter_record) for filter_record in post_filters
    ]:
        raise EvidenceError(f"{description} BPF filter configuration changed during formal traffic")
    immediate_seen, immediate_dropped = _v3_periodic_map_snapshot(
        cell, maps["immediate"], f"{description}.maps immediate"
    )
    post_seen, post_dropped = _v3_periodic_map_snapshot(cell, maps["post"], f"{description}.maps post")
    if post_seen < immediate_seen or post_dropped < immediate_dropped:
        raise EvidenceError(f"{description} map counters must be nondecreasing")
    seen_delta = post_seen - immediate_seen
    if seen_delta < every_n:
        raise EvidenceError(
            f"{description} map counters must prove at least PERIODIC_EVERY_N carrier SKBs after the immediate baseline"
        )
    dropped_delta = post_dropped - immediate_dropped
    if dropped_delta <= 0:
        raise EvidenceError(f"{description} map counters must prove an actual periodic carrier-SKB drop")
    immediate_packets = _counter(immediate_clsact.get("packets"), f"{description}.qdisc immediate clsact.packets")
    post_packets = _counter(post_clsact.get("packets"), f"{description}.qdisc post clsact.packets")
    if post_packets < immediate_packets:
        raise EvidenceError(f"{description} clsact packets must be nondecreasing")
    if post_packets - immediate_packets != seen_delta:
        raise EvidenceError(f"{description} clsact packet delta does not match global_seen delta")
    expected_drop_delta = post_seen // every_n - immediate_seen // every_n
    if dropped_delta != expected_drop_delta:
        raise EvidenceError(f"{description} map counters do not prove global periodic carrier-SKB loss")


def _v3_validate_uniform_distribution(
    cell: Path,
    value: Any,
    source_inventory: Mapping[str, Any],
) -> None:
    if not isinstance(value, dict) or set(value) != {"source_path", "source_sha256", "artifact"}:
        raise EvidenceError("uniform distribution source has an incomplete or unexpected shape")
    if value.get("source_path") != UNIFORM_DISTRIBUTION_SOURCE_PATH:
        raise EvidenceError("uniform distribution source path is not the fixed tools/uniform.dist")
    source_hash = value.get("source_sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise EvidenceError("uniform distribution source SHA-256 is invalid")
    expected_source_hash = _v3_source_inventory_file_sha256(
        source_inventory,
        UNIFORM_DISTRIBUTION_SOURCE_PATH,
        "uniform distribution source",
    )
    if source_hash != expected_source_hash:
        raise EvidenceError("uniform distribution source SHA-256 does not match the v3 source inventory")
    artifact = value.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("path") != "netem-tc-lib/uniform.dist":
        raise EvidenceError("uniform distribution artifact must be netem-tc-lib/uniform.dist")
    _artifact_path, raw = _read_hashed_locator(cell, artifact, "uniform distribution artifact")
    if not raw or artifact.get("sha256") != source_hash:
        raise EvidenceError("uniform distribution artifact does not match the captured source identity")


def _v3_tunnel_token(namespace: Any, description: str) -> str:
    if not isinstance(namespace, str):
        raise EvidenceError(f"{description} namespace is invalid")
    match = _V3_TUNNEL_NAMESPACE_PATTERN.fullmatch(namespace)
    if not match:
        raise EvidenceError(f"{description} namespace must be dpa-t-<9 lowercase hex>")
    return match.group(1)


def _v3_safe_interface(value: Any, description: str) -> str:
    if not isinstance(value, str) or not _V3_INTERFACE_PATTERN.fullmatch(value):
        raise EvidenceError(f"{description} interface is invalid")
    return value


def _v3_validate_target(
    cell: Path,
    target: Any,
    profile: Mapping[str, Any],
    campaign_seed: int,
    identity: CellIdentity,
    source_inventory: Mapping[str, Any],
    description: str,
) -> tuple[str, str]:
    target_keys = {
        "carrier_direction",
        "namespace",
        "interface",
        "interface_role",
        "tc_environment",
        "qdisc_apply_argv",
        "declared_loss",
        "qdisc",
        "link",
        "offload",
    }
    if profile["loss"]["mode"] == "periodic_carrier_skb":
        target_keys.add("periodic_bpf")
    if not isinstance(target, dict) or set(target) != target_keys:
        raise EvidenceError(f"{description} has an incomplete or unexpected shape")
    carrier_direction = target.get("carrier_direction")
    if carrier_direction not in CARRIER_DIRECTIONS:
        raise EvidenceError(f"{description} carrier_direction is invalid")
    token = _v3_tunnel_token(target.get("namespace"), description)
    interface = _v3_safe_interface(target.get("interface"), description)
    expected_role = {
        "client_to_server": "tunnel_server_interface",
        "server_to_client": "tunnel_client_interface",
    }[carrier_direction]
    expected_interface = f"dt{token}{'b' if carrier_direction == 'client_to_server' else 'a'}"
    if target.get("interface_role") != expected_role or interface != expected_interface:
        raise EvidenceError(f"{description} does not bind the generated tunnel carrier interface")
    _validate_exact_environment(
        target.get("tc_environment"),
        expected_netem_environment(cell, profile),
        f"{description} tc environment",
    )
    directional_seed = derive_directional_netem_seed(
        campaign_seed, profile["id"], identity, carrier_direction
    )
    if target.get("qdisc_apply_argv") != expected_netem_qdisc_apply_argv(
        cell, interface, profile, directional_seed
    ):
        raise EvidenceError(f"{description} qdisc apply argv is not the exact profile-derived tc command")
    if target.get("declared_loss") != profile["loss"]:
        raise EvidenceError(f"{description} declared_loss does not match the closed network profile")
    _immediate_netem, _immediate_clsact, _post_clsact, _immediate, _post = _v3_validate_qdisc_evidence(
        cell, target.get("qdisc"), profile, directional_seed, f"{description} qdisc"
    )
    _v3_validate_link_evidence(cell, target.get("link"), interface, f"{description} link")
    _v3_validate_offload_evidence(cell, target.get("offload"), f"{description} offload")
    if profile["loss"]["mode"] == "periodic_carrier_skb":
        _v3_validate_periodic_bpf(
            cell,
            target.get("periodic_bpf"),
            profile,
            interface,
            source_inventory,
            f"{description} periodic BPF",
        )
    return carrier_direction, token


def _v3_validate_non_targets(cell: Path, value: Any, tunnel_token: str) -> None:
    if not isinstance(value, list) or len(value) != 4:
        raise EvidenceError("underlay impairment non_targets must contain exactly four records")
    expected_roles = {
        "client_control": (f"dpa-c-{tunnel_token}", f"dc{tunnel_token}a"),
        "server_control": (f"dpa-s-{tunnel_token}", f"ds{tunnel_token}a"),
        "client_overlay": (f"dpa-c-{tunnel_token}", None),
        "server_target_loopback": (f"dpa-s-{tunnel_token}", "lo"),
    }
    seen_roles: set[str] = set()
    for index, record in enumerate(value):
        description = f"underlay impairment non_target {index}"
        if not isinstance(record, dict) or set(record) != {"role", "namespace", "interface", "qdisc"}:
            raise EvidenceError(f"{description} has an incomplete or unexpected shape")
        role = record.get("role")
        if role not in expected_roles or role in seen_roles:
            raise EvidenceError(f"{description} role is invalid or duplicated")
        seen_roles.add(role)
        namespace, expected_interface = expected_roles[role]
        if record.get("namespace") != namespace:
            raise EvidenceError(f"{description} namespace does not match the generated topology token")
        interface = _v3_safe_interface(record.get("interface"), description)
        if expected_interface is not None and interface != expected_interface:
            raise EvidenceError(f"{description} interface does not match the generated topology contract")
        qdisc = record.get("qdisc")
        if not isinstance(qdisc, dict) or set(qdisc) != {"pre", "immediate", "post"}:
            raise EvidenceError(f"{description} qdisc has an incomplete or unexpected shape")
        for phase in ("pre", "immediate", "post"):
            snapshot = _v3_qdisc_snapshot(cell, qdisc[phase], f"{description} qdisc {phase}")
            if _v3_contains_netem(snapshot):
                raise EvidenceError(f"{description} qdisc {phase} contains forbidden netem")
    if seen_roles != set(expected_roles):
        raise EvidenceError(
            "underlay impairment non_targets does not cover every control, client-overlay, and server target-service loopback location"
        )


def _validate_underlay_impairment(
    value: Any,
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> None:
    profile = _validated_network_profile(manifest.get("network_profile"))
    campaign_seed = _validated_campaign_seed(manifest.get("netem_seed"))
    expected_keys = {
        "schema",
        "network_profile",
        "campaign_seed",
        "execution_index",
        "targets",
        "non_targets",
    }
    if profile["jitter_per_direction_us"]:
        expected_keys.add("uniform_distribution_source")
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise EvidenceError("underlay impairment has an incomplete or unexpected v3 shape")
    if value.get("schema") != UNDERLAY_IMPAIRMENT_SCHEMA_V3:
        raise EvidenceError(f"underlay impairment schema must be {UNDERLAY_IMPAIRMENT_SCHEMA_V3!r}")
    recorded_profile = _validated_network_profile(value.get("network_profile"))
    if recorded_profile != profile:
        raise EvidenceError("underlay impairment network profile does not match the manifest")
    if _validated_campaign_seed(value.get("campaign_seed")) != campaign_seed:
        raise EvidenceError("underlay impairment campaign seed does not match the manifest")
    _positive_integer(value.get("execution_index"), "underlay impairment execution_index")
    try:
        source_inventory = _validated_recorded_source_inventory(
            artifact_root,
            manifest.get("source"),
            3,
        )
    except AcceptanceError as error:
        raise EvidenceError(str(error)) from None
    cell = _canonical_cell_root(artifact_root, identity)
    if profile["jitter_per_direction_us"]:
        _v3_validate_uniform_distribution(cell, value.get("uniform_distribution_source"), source_inventory)
    targets = value.get("targets")
    if not isinstance(targets, list) or len(targets) != len(CARRIER_DIRECTIONS):
        raise EvidenceError("underlay impairment targets must contain exactly two carrier records")
    directions: set[str] = set()
    tokens: set[str] = set()
    for index, target in enumerate(targets):
        direction, token = _v3_validate_target(
            cell,
            target,
            profile,
            campaign_seed,
            identity,
            source_inventory,
            f"underlay impairment target {index}",
        )
        directions.add(direction)
        tokens.add(token)
    if directions != set(CARRIER_DIRECTIONS) or len(tokens) != 1:
        raise EvidenceError("underlay impairment targets do not bind both directions to one tunnel topology")
    _v3_validate_non_targets(cell, value.get("non_targets"), next(iter(tokens)))


def validate_v3_launch_record(
    document: Any,
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> dict[str, Any]:
    """Validate profile-bound v3 launch evidence while retaining all v2 checks."""

    v2_keys = {
        "schema",
        "run_uuid",
        "role",
        "cell",
        "environment_mode",
        "environment",
        "candidate",
        "argv",
        "config",
        "server_config",
        "stats",
        "boundary_request",
        "boundary_acknowledgement",
        "observed_process",
        "cpu",
        "tun",
        "qdisc",
        "rps_xps",
    }
    expected_keys = v2_keys | {"underlay_impairment"}
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise EvidenceError("launch record has an incomplete or unexpected v3 shape")
    if document.get("schema") != LAUNCH_SCHEMA_V3:
        raise EvidenceError(f"launch record schema must be {LAUNCH_SCHEMA_V3!r}")
    v2_document = {key: value for key, value in document.items() if key != "underlay_impairment"}
    v2_document["schema"] = LAUNCH_SCHEMA_V2
    observation = _validate_v2_launch_record(v2_document, artifact_root, manifest, identity)
    _validate_underlay_impairment(document.get("underlay_impairment"), artifact_root, manifest, identity)
    return observation


def validate_launch_record(
    document: Any,
    artifact_root: Path,
    manifest: Mapping[str, Any],
    identity: CellIdentity,
) -> dict[str, Any]:
    """Dispatch launch validation by the immutable v2/v3 manifest contract."""

    if manifest_uses_network_profile(manifest):
        return validate_v3_launch_record(document, artifact_root, manifest, identity)
    return _validate_v2_launch_record(document, artifact_root, manifest, identity)


def _boundary_process_identity(boundary: Mapping[str, Any], description: str) -> tuple[int, int]:
    return (
        _positive_integer(boundary.get("process_pid"), f"{description}.process_pid"),
        _positive_integer(boundary.get("process_start_ticks"), f"{description}.process_start_ticks"),
    )


def _validate_stats_record(
    record: Any,
    identity: CellIdentity,
    run_uuid: str,
    phase: str,
    description: str,
) -> tuple[dict[str, int], int, int, int, int]:
    if not isinstance(record, dict):
        raise EvidenceError(f"{description} must be a JSON object")
    if record.get("type") != "ppp-stats" or record.get("version") != 1:
        raise EvidenceError(f"{description} is not a ppp-stats v1 record")
    tcp_stack = record.get("tcp_stack")
    if not isinstance(tcp_stack, dict) or tcp_stack.get("requested") != "xtcp" or tcp_stack.get("active") != "xtcp":
        raise EvidenceError(f"{description} does not prove requested/active XTCP")
    tap_linux = record.get("tap_linux")
    if not isinstance(tap_linux, dict) or tap_linux.get("gso_merge_active") is not True:
        raise EvidenceError(f"{description} does not prove active TAP GSO merge")
    xtcp = record.get("xtcp")
    if not isinstance(xtcp, dict):
        raise EvidenceError(f"{description} lacks XTCP runtime data")
    runtime_id = _positive_integer(xtcp.get("runtime_instance_id"), f"{description}.xtcp.runtime_instance_id")
    if xtcp.get("ndi_gso_enabled") is not False:
        raise EvidenceError(f"{description}.xtcp.ndi_gso_enabled must be false")
    counters = {
        field_name: _counter(xtcp.get(field_name), f"{description}.xtcp.{field_name}")
        for field_name in (
            "direct_bridge_starts",
            "direct_bridge_fallbacks",
            "connector_read_bytes",
            "connector_written_bytes",
            "direct_upload_accepted_bytes",
            "direct_download_accepted_bytes",
        )
    }
    root_monotonic_ms = _counter(record.get("monotonic_ms"), f"{description}.monotonic_ms")
    boundary = _validate_acceptance_boundary(
        record.get("acceptance_boundary"),
        run_uuid=run_uuid,
        cell_id=identity.relative_directory(),
        sequence=None,
        phase=phase,
        description=f"{description}.acceptance_boundary",
        root_monotonic_ms=root_monotonic_ms,
        expected_runtime_id=runtime_id,
        require_positive_runtime_id=True,
    )
    sequence = boundary["sequence"]
    pid, start_ticks = _boundary_process_identity(boundary, f"{description}.acceptance_boundary")
    return counters, sequence, pid, start_ticks, runtime_id


def _raw_stats_line(raw: bytes, locator: Any, description: str) -> Any:
    if not isinstance(locator, dict) or set(locator) != {"byte_offset", "line_sha256"}:
        raise EvidenceError(f"{description} must contain byte_offset and line_sha256")
    offset = locator.get("byte_offset")
    digest = locator.get("line_sha256")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise EvidenceError(f"{description} byte_offset is invalid")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EvidenceError(f"{description} line_sha256 is invalid")
    if offset >= len(raw) or (offset != 0 and raw[offset - 1 : offset] != b"\n"):
        raise EvidenceError(f"{description} byte_offset is not a complete-line start")
    newline = raw.find(b"\n", offset)
    if newline < 0:
        raise EvidenceError(f"{description} does not identify a complete NDJSON line")
    line = raw[offset:newline]
    if not line:
        raise EvidenceError(f"{description} identifies an empty NDJSON line")
    if _sha256_bytes(line) != digest:
        raise EvidenceError(f"{description} line_sha256 does not match retained raw stats")
    return parse_json_bytes(line, description)


def stats_boundary_locator(raw: bytes, byte_offset: int) -> dict[str, Any]:
    """Build one raw NDJSON locator; used by the strict adapter after capture."""

    if byte_offset < 0 or byte_offset >= len(raw) or (byte_offset and raw[byte_offset - 1 : byte_offset] != b"\n"):
        raise AcceptanceError("stats byte offset is not a complete-line start")
    newline = raw.find(b"\n", byte_offset)
    if newline < 0 or newline == byte_offset:
        raise AcceptanceError("stats byte offset does not identify a complete line")
    return {"byte_offset": byte_offset, "line_sha256": _sha256_bytes(raw[byte_offset:newline])}


def find_stats_boundary_locators(
    raw: bytes,
    run_uuid: str,
    cell_id: str,
) -> dict[str, dict[str, Any]]:
    """Find exactly one retained start and end boundary line in raw NDJSON."""

    matches: dict[str, list[int]] = {"measurement_start": [], "measurement_end": []}
    offset = 0
    while offset < len(raw):
        newline = raw.find(b"\n", offset)
        if newline < 0:
            raise AcceptanceError("raw stats ends with an incomplete NDJSON line")
        line = raw[offset:newline]
        if line:
            try:
                document = parse_json_bytes(line, "raw stats line")
            except EvidenceError as error:
                raise AcceptanceError(str(error)) from None
            boundary = document.get("acceptance_boundary") if isinstance(document, dict) else None
            if isinstance(boundary, dict) and boundary.get("run_uuid") == run_uuid and boundary.get("cell_id") == cell_id:
                phase = boundary.get("phase")
                if phase in matches:
                    matches[phase].append(offset)
        offset = newline + 1
    result: dict[str, dict[str, Any]] = {}
    for phase, offsets in matches.items():
        if len(offsets) != 1:
            raise AcceptanceError(f"raw stats must contain exactly one {phase} boundary line")
        result[phase] = stats_boundary_locator(raw, offsets[0])
    return result


def validate_direct_proof(
    document: Any,
    identity: CellIdentity,
    run_uuid: str,
    *,
    cell_directory_path: Path | None = None,
    delivered_payload_bytes: int | None = None,
    launch_observation: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Derive direct-path admission evidence solely from retained raw stats."""

    if not isinstance(document, dict):
        raise EvidenceError("direct proof must be a JSON object")
    if set(document) != {"schema", "run_uuid", "cell", "raw_stats"}:
        raise EvidenceError("direct proof must contain only immutable raw-stats locators")
    if document.get("schema") != DIRECT_PROOF_SCHEMA:
        raise EvidenceError(f"direct proof schema must be {DIRECT_PROOF_SCHEMA!r}")
    if document.get("run_uuid") != run_uuid:
        raise EvidenceError("direct proof run UUID does not match the manifest")
    if document.get("cell") != identity.as_dict():
        raise EvidenceError("direct proof cell identity does not match its artifact path")
    if cell_directory_path is None or delivered_payload_bytes is None or launch_observation is None:
        raise EvidenceError("direct proof requires cell, delivered-payload, and launch identity context")
    if not isinstance(delivered_payload_bytes, int) or isinstance(delivered_payload_bytes, bool) or delivered_payload_bytes <= 0:
        raise EvidenceError("direct proof requires positive validated delivered payload bytes")
    raw_stats = document.get("raw_stats")
    if not isinstance(raw_stats, dict) or set(raw_stats) != {
        "path",
        "sha256",
        "measurement_start",
        "measurement_end",
    }:
        raise EvidenceError("direct proof raw_stats has an incomplete shape")
    stats_path, raw = _read_hashed_locator(
        cell_directory_path,
        {"path": raw_stats.get("path"), "sha256": raw_stats.get("sha256")},
        "direct proof raw stats",
    )
    expected_stats_relative = launch_observation.get("stats_relative_path")
    if raw_stats.get("path") != expected_stats_relative or stats_path != launch_observation.get("stats_path"):
        raise EvidenceError("direct proof raw stats locator does not match the observed launch stats path")
    start_record = _raw_stats_line(raw, raw_stats.get("measurement_start"), "measurement_start raw stats")
    end_record = _raw_stats_line(raw, raw_stats.get("measurement_end"), "measurement_end raw stats")
    try:
        unique_locators = find_stats_boundary_locators(raw, run_uuid, identity.relative_directory())
    except AcceptanceError as error:
        raise EvidenceError(f"direct proof raw stats boundary selection is invalid: {error}") from None
    if (
        raw_stats.get("measurement_start") != unique_locators["measurement_start"]
        or raw_stats.get("measurement_end") != unique_locators["measurement_end"]
    ):
        raise EvidenceError("direct proof raw stats locators do not select the unique matching boundary lines")
    start_counters, start_sequence, start_pid, start_ticks, start_runtime = _validate_stats_record(
        start_record, identity, run_uuid, "measurement_start", "measurement_start raw stats"
    )
    end_counters, end_sequence, end_pid, end_ticks, end_runtime = _validate_stats_record(
        end_record, identity, run_uuid, "measurement_end", "measurement_end raw stats"
    )
    if end_sequence <= start_sequence:
        raise EvidenceError("raw stats boundary sequences must strictly increase")
    if (
        start_pid != end_pid
        or start_ticks != end_ticks
        or start_pid != launch_observation.get("pid")
        or start_ticks != launch_observation.get("start_ticks")
    ):
        raise EvidenceError("raw stats process identity does not match the observed launch")
    if start_runtime != end_runtime:
        raise EvidenceError("raw stats XTCP runtime instance ID changed across boundaries")
    final_acknowledgement = launch_observation.get("final_acknowledgement")
    if final_acknowledgement != end_record.get("acceptance_boundary"):
        raise EvidenceError("retained final boundary acknowledgement does not equal selected raw measurement_end acceptance_boundary")
    deltas = {name: end_counters[name] - start_counters[name] for name in start_counters}
    negative = sorted(name for name, value in deltas.items() if value < 0)
    if negative:
        raise EvidenceError("raw stats counters regressed: " + ", ".join(negative))
    if deltas["direct_bridge_starts"] < identity.parallel_flows:
        raise EvidenceError(
            f"direct admission direct_bridge_starts={deltas['direct_bridge_starts']} "
            f"is below P={identity.parallel_flows}"
        )
    if deltas["direct_bridge_fallbacks"] != 0:
        raise EvidenceError("direct admission direct_bridge_fallbacks must be zero")
    if deltas["connector_read_bytes"] != 0 or deltas["connector_written_bytes"] != 0:
        raise EvidenceError("direct admission connector byte counters must both be zero")
    accepted_name = (
        "direct_upload_accepted_bytes"
        if identity.direction == "ul"
        else "direct_download_accepted_bytes"
    )
    if deltas[accepted_name] < delivered_payload_bytes:
        raise EvidenceError(
            f"direct admission {accepted_name} is below validated delivered iperf payload bytes"
        )
    return deltas


def _manifest_path(artifact_root: Path) -> Path:
    return artifact_root / "acceptance-manifest.json"


def _manifest_hash_path(artifact_root: Path) -> Path:
    return artifact_root / "acceptance-manifest.sha256"


def _source_inventory_path(artifact_root: Path) -> Path:
    return artifact_root / "source-inventory.json"


def _launch_environment_path(artifact_root: Path) -> Path:
    return artifact_root / "launch-environment.json"


def _run_inventory_path(artifact_root: Path) -> Path:
    return artifact_root / "run-inventory.json"


def _run_inventory_hash_path(artifact_root: Path) -> Path:
    return artifact_root / "run-inventory.sha256"


def _freeze_path(artifact_root: Path) -> Path:
    return artifact_root / "freeze.json"


def _freeze_manifest_path(artifact_root: Path) -> Path:
    return artifact_root / "freeze-manifest.json"


def _freeze_manifest_hash_path(artifact_root: Path) -> Path:
    return artifact_root / "freeze-manifest.sha256"


def artifact_inventory(artifact_root: Path) -> dict[str, Any]:
    return build_inventory(artifact_root, CONTROL_ARTIFACT_PATHS)


def _parse_hash_file(path: Path, description: str) -> str:
    _require_regular_file(path, description, AcceptanceError)
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise AcceptanceError(f"cannot read {description}: {error}") from None
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AcceptanceError(f"{description} is not a SHA-256 digest")
    return value


def prepare_run(
    artifact_root: Path,
    source_root: Path,
    candidate: Path,
    threshold: Any = MINIMUM_THRESHOLD,
    *,
    network_profile: str | None = None,
    netem_seed: Any | None = None,
) -> dict[str, Any]:
    """Create a one-use run root, preserving literal v2 absent a profile.

    `network_profile` and `netem_seed` are an all-or-nothing v3 request.  The
    no-profile branch intentionally constructs the historic v2 manifest with
    the exact old keys and values; profile requests bind the complete catalog
    object and campaign seed in an exact v3 manifest.
    """

    if (network_profile is None) != (netem_seed is None):
        raise AcceptanceError("network_profile and netem_seed must be specified together")
    profile: dict[str, Any] | None = None
    campaign_seed: int | None = None
    if network_profile is not None:
        if not isinstance(network_profile, str) or network_profile not in NETWORK_PROFILE_CATALOG:
            raise AcceptanceError("network profile id is not in the closed catalog")
        profile = _profile_copy(NETWORK_PROFILE_CATALOG[network_profile])
        campaign_seed = validate_campaign_seed(netem_seed)
    threshold_decimal = parse_threshold(threshold)
    source_root = _validated_source_root(source_root)
    artifact_root = _resolve_artifact_root_argument(artifact_root)
    if _path_entry_exists(artifact_root, "artifact root"):
        raise AcceptanceError(f"artifact root already exists and cannot be reused: {artifact_root}")
    candidate_identity = collect_candidate_identity(candidate, source_root)
    if _path_is_within(Path(candidate_identity["path"]), artifact_root):
        raise AcceptanceError("candidate must not be located inside its artifact root")

    # A failed preparation deliberately leaves a non-reusable partial root.
    artifact_root.mkdir(parents=True, exist_ok=False)
    source_identity = build_source_inventory(source_root, version=3 if profile is not None else 2)
    launch_contract = launch_environment_contract()
    # Keep this literal v2 construction intact for historical artifact identity.
    manifest = {
        "schema": ACCEPTANCE_SCHEMA,
        "kind": "run",
        "run_uuid": str(uuid.uuid4()),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "threshold": decimal_text(threshold_decimal),
        "expected_cells": [identity.as_dict() for identity in expected_cells()],
        "expected_pairs": [identity.as_dict() for identity in expected_pairs()],
        "source": {
            "root": str(source_root),
            "inventory_sha256": source_identity["sha256"],
            "allowlist_sha256": canonical_json_sha256(source_identity["allowlist"]),
        },
        "candidate": candidate_identity,
        "launch_environment_sha256": canonical_json_sha256(launch_contract),
    }
    if profile is not None:
        manifest = {
            **manifest,
            "schema": ACCEPTANCE_SCHEMA_V3,
            "network_profile": profile,
            "netem_seed": campaign_seed,
        }
    write_json(_manifest_path(artifact_root), manifest)
    _manifest_hash_path(artifact_root).write_text(canonical_json_sha256(manifest) + "\n", encoding="ascii")
    write_json(_source_inventory_path(artifact_root), source_identity)
    write_json(_launch_environment_path(artifact_root), launch_contract)
    return manifest


def manifest_schema_version(manifest: Any) -> int | None:
    """Return 2 or 3 only for a known acceptance manifest schema."""

    if not isinstance(manifest, Mapping):
        return None
    if manifest.get("schema") == ACCEPTANCE_SCHEMA_V2:
        return 2
    if manifest.get("schema") == ACCEPTANCE_SCHEMA_V3:
        return 3
    return None


def manifest_uses_network_profile(manifest: Any) -> bool:
    """Whether a manifest is the profile-bound v3 acceptance contract."""

    return manifest_schema_version(manifest) == 3


def _check_manifest(manifest: Any, artifact_root: Path) -> tuple[list[str], Decimal]:
    errors: list[str] = []
    threshold = MINIMUM_THRESHOLD
    if not isinstance(manifest, dict):
        return ["acceptance manifest must be a JSON object"], threshold
    version = manifest_schema_version(manifest)
    if version is None or manifest.get("kind") != "run":
        errors.append("manifest must be a known v2 or v3 acceptance run")
    if version == 2:
        v2_keys = {
            "schema", "kind", "run_uuid", "created_at_utc", "threshold", "expected_cells",
            "expected_pairs", "source", "candidate", "launch_environment_sha256",
        }
        if set(manifest) != v2_keys:
            errors.append("manifest has an incomplete or unexpected v2 shape")
    elif version == 3:
        v3_keys = {
            "schema", "kind", "run_uuid", "created_at_utc", "threshold", "expected_cells",
            "expected_pairs", "source", "candidate", "launch_environment_sha256",
            "network_profile", "netem_seed",
        }
        if set(manifest) != v3_keys:
            errors.append("manifest has an incomplete or unexpected v3 shape")
        try:
            profile = validate_network_profile(manifest.get("network_profile"))
            if profile.get("id") not in NETWORK_PROFILE_CATALOG:
                raise AcceptanceError("network profile id is not in the closed catalog")
            validate_campaign_seed(manifest.get("netem_seed"))
        except AcceptanceError as error:
            errors.append(str(error))
    try:
        uuid.UUID(str(manifest.get("run_uuid")))
    except (TypeError, ValueError, AttributeError):
        errors.append("manifest run_uuid is invalid")
    if not isinstance(manifest.get("created_at_utc"), str) or not manifest["created_at_utc"]:
        errors.append("manifest created_at_utc is missing")
    try:
        threshold = parse_threshold(manifest.get("threshold"))
    except AcceptanceError as error:
        errors.append(str(error))
    if manifest.get("expected_cells") != [identity.as_dict() for identity in expected_cells()]:
        errors.append("manifest expected_cells does not match the fixed 36-cell matrix")
    if manifest.get("expected_pairs") != [identity.as_dict() for identity in expected_pairs()]:
        errors.append("manifest expected_pairs does not match the fixed 18-pair matrix")
    source = manifest.get("source")
    if not isinstance(source, dict) or set(source) != {"root", "inventory_sha256", "allowlist_sha256"}:
        errors.append("manifest source identity is malformed")
    else:
        root = source.get("root")
        if not isinstance(root, str) or not Path(root).is_absolute():
            errors.append("manifest source root must be absolute")
        for field_name in ("inventory_sha256", "allowlist_sha256"):
            value = source.get(field_name)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                errors.append(f"manifest source {field_name} is invalid")
    try:
        _validate_candidate_shape(manifest.get("candidate"))
    except AcceptanceError as error:
        errors.append(str(error))
    launch_hash = manifest.get("launch_environment_sha256")
    if not isinstance(launch_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", launch_hash):
        errors.append("manifest launch environment SHA-256 is invalid")
    return errors, threshold


def _verify_manifest_hash(artifact_root: Path, manifest: Any) -> list[str]:
    try:
        expected = _parse_hash_file(_manifest_hash_path(artifact_root), "manifest hash")
        if canonical_json_sha256(manifest) != expected:
            return ["manifest SHA-256 does not match acceptance-manifest.sha256"]
    except AcceptanceError as error:
        return [str(error)]
    return []


def _verify_launch_environment_contract(artifact_root: Path, manifest: Mapping[str, Any]) -> list[str]:
    try:
        contract = read_json(_launch_environment_path(artifact_root), "launch environment contract")
        if contract != launch_environment_contract():
            return ["launch environment contract does not match the strict env -i contract"]
        if canonical_json_sha256(contract) != manifest.get("launch_environment_sha256"):
            return ["launch environment contract SHA-256 does not match manifest"]
    except EvidenceError as error:
        return [str(error)]
    return []


def _source_identity_version_from_manifest(manifest: Any) -> int:
    version = manifest_schema_version(manifest)
    if version is None:
        raise EvidenceError("cannot derive source identity version from manifest schema")
    return version


def _validated_recorded_source_inventory(
    artifact_root: Path,
    source: Any,
    version: int,
) -> dict[str, Any]:
    if not isinstance(source, dict):
        raise EvidenceError("cannot verify missing source identity")
    inventory_schema, _exact_files = _source_inventory_contract(version)
    root_value = source.get("root")
    expected_hash = source.get("inventory_sha256")
    allowlist_hash = source.get("allowlist_sha256")
    if not isinstance(root_value, str) or not Path(root_value).is_absolute():
        raise EvidenceError("manifest source root is missing or not absolute")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise EvidenceError("manifest source inventory SHA-256 is invalid")
    if allowlist_hash != canonical_json_sha256(source_allowlist(version)):
        raise EvidenceError("manifest source allowlist SHA-256 is invalid")
    root = _validated_source_root(Path(root_value))
    recorded = read_json(_source_inventory_path(artifact_root), "source inventory")
    if not isinstance(recorded, dict):
        raise EvidenceError("source inventory must be an object")
    if (
        recorded.get("schema") != inventory_schema
        or recorded.get("root") != str(root)
        or recorded.get("allowlist") != source_allowlist(version)
        or not isinstance(recorded.get("entries"), list)
        or _source_inventory_digest(recorded) != recorded.get("sha256")
        or recorded.get("sha256") != expected_hash
    ):
        raise EvidenceError("recorded source inventory does not match the strict allowlist identity")
    return recorded


def _verify_source_identity_from_reference(
    artifact_root: Path,
    source: Any,
    manifest: Any | None = None,
) -> list[str]:
    try:
        version = 2 if manifest is None else _source_identity_version_from_manifest(manifest)
        recorded = _validated_recorded_source_inventory(artifact_root, source, version)
        current = build_source_inventory(Path(recorded["root"]), version=version)
        if current["sha256"] != recorded["sha256"]:
            raise EvidenceError("source content identity drifted after run preparation")
    except (AcceptanceError, EvidenceError, KeyError, OSError, RuntimeError, ValueError) as error:
        return [str(error)]
    return []


def _verify_source_identity(artifact_root: Path, manifest: Mapping[str, Any]) -> list[str]:
    return _verify_source_identity_from_reference(artifact_root, manifest.get("source"), manifest)


def _verify_candidate_identity(manifest: Mapping[str, Any]) -> list[str]:
    candidate = manifest.get("candidate")
    source = manifest.get("source")
    if not isinstance(candidate, dict) or not isinstance(source, dict):
        return ["cannot verify missing candidate or source identity"]
    try:
        current = collect_candidate_identity(Path(candidate["path"]), Path(source["root"]))
        if current != candidate:
            return ["candidate content identity drifted after run preparation"]
    except (AcceptanceError, KeyError, TypeError, OSError, RuntimeError, ValueError) as error:
        return [str(error)]
    return []


def validate_prepared_run(
    artifact_root: Path,
    manifest_path: Path | None = None,
    candidate: Path | None = None,
) -> dict[str, Any]:
    """Revalidate a fresh prepared run before an adapter may launch anything."""

    artifact_root = _resolve_artifact_root_argument(artifact_root)
    if not artifact_root.is_dir():
        raise AcceptanceError(f"artifact root is not a directory: {artifact_root}")
    expected_manifest_path = _manifest_path(artifact_root)
    if manifest_path is not None:
        supplied = Path(manifest_path).expanduser()
        if not supplied.is_absolute():
            raise AcceptanceError("adapter manifest path must be absolute")
        try:
            if supplied.resolve(strict=True) != expected_manifest_path.resolve(strict=True):
                raise AcceptanceError("adapter manifest path must be the prepared root manifest")
        except (OSError, RuntimeError, ValueError) as error:
            raise AcceptanceError(f"cannot resolve adapter manifest path: {error}") from None
    if _path_entry_exists(_run_inventory_path(artifact_root), "run inventory"):
        raise AcceptanceError("prepared run is already sealed")
    try:
        manifest = read_json(expected_manifest_path, "acceptance manifest")
    except EvidenceError as error:
        raise AcceptanceError(str(error)) from None
    if not isinstance(manifest, dict):
        raise AcceptanceError("acceptance manifest must be an object")
    errors, _threshold = _check_manifest(manifest, artifact_root)
    errors.extend(_verify_manifest_hash(artifact_root, manifest))
    errors.extend(_verify_launch_environment_contract(artifact_root, manifest))
    errors.extend(_verify_source_identity(artifact_root, manifest))
    errors.extend(_verify_candidate_identity(manifest))
    if candidate is not None:
        try:
            supplied_identity = collect_candidate_identity(Path(candidate), Path(manifest["source"]["root"]))
        except (AcceptanceError, KeyError, TypeError) as error:
            errors.append(str(error))
        else:
            if supplied_identity != manifest.get("candidate"):
                errors.append("adapter candidate identity does not match the prepared manifest")
    if errors:
        raise AcceptanceError("prepared run is invalid: " + "; ".join(dict.fromkeys(errors)))
    return manifest


def _safe_artifact_files(artifact_root: Path) -> list[Path]:
    """Walk artifact files without following symlinks or hiding special files."""

    root_metadata = _lstat(artifact_root, "artifact root", EvidenceError)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError("artifact root is not a real directory")
    files: list[Path] = []

    def walk(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda child: child.name)
        except OSError as error:
            raise EvidenceError(f"cannot enumerate artifact directory {directory}: {error}") from None
        for child in children:
            path = directory / child.name
            metadata = _lstat(path, f"artifact path {path}", EvidenceError)
            if stat.S_ISLNK(metadata.st_mode):
                raise EvidenceError(f"symlink is forbidden in artifact evidence: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                walk(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.append(path)
            else:
                raise EvidenceError(f"unsupported artifact filesystem entry: {path}")

    walk(artifact_root)
    return files


def _parse_result_identity(record: Any) -> tuple[CellIdentity | None, list[str]]:
    if not isinstance(record, dict):
        return None, ["result.json must be a JSON object"]
    errors: list[str] = []
    try:
        round_number = _exact_integer(record.get("round"), "result round")
    except EvidenceError as error:
        errors.append(str(error))
        round_number = -1
    stack = record.get("requested_tcp_stack")
    if stack not in STACKS:
        errors.append("result requested_tcp_stack must be native or xtcp")
        stack = ""
    if record.get("active_tcp_stack") != stack:
        errors.append("result active_tcp_stack must equal requested_tcp_stack")
    if record.get("requested_tap_gso") != TAP_GSO or record.get("active_tap_gso") != TAP_GSO:
        errors.append("result requested and active TAP GSO must both be on")
    try:
        parallel_flows = _exact_integer(record.get("parallel_flows"), "result parallel_flows")
    except EvidenceError as error:
        errors.append(str(error))
        parallel_flows = -1
    direction = record.get("direction")
    if direction not in DIRECTIONS:
        errors.append("result direction must be ul or dl")
        direction = ""
    if errors:
        return None, errors
    identity = CellIdentity(round_number, stack, parallel_flows, direction)
    if identity not in expected_cells():
        return None, ["result identity is outside the fixed acceptance matrix"]
    return identity, []


def _add_error(evidence: CellEvidence, message: str) -> None:
    if message not in evidence.errors:
        evidence.errors.append(message)


def _scan_cell_results(
    artifact_root: Path,
) -> tuple[dict[CellIdentity, CellEvidence], dict[str, Any], list[str]]:
    cells = expected_cells()
    expected_locations = {f"{cell.relative_directory()}/result.json": cell for cell in cells}
    evidence = {
        cell: CellEvidence(cell, artifact_root / cell.relative_directory() / "result.json") for cell in cells
    }
    coverage: dict[str, Any] = {
        "expected_cells": len(cells),
        "discovered_result_files": 0,
        "missing": [],
        "duplicates": [],
        "extra": [],
    }
    global_errors: list[str] = []
    claimed: dict[CellIdentity, list[str]] = {cell: [] for cell in cells}
    try:
        result_paths = [
            path
            for path in _safe_artifact_files(artifact_root)
            if path.name == "result.json"
        ]
    except EvidenceError as error:
        result_paths = []
        global_errors.append(str(error))
    coverage["discovered_result_files"] = len(result_paths)
    for path in result_paths:
        relative = path.relative_to(artifact_root).as_posix()
        path_identity = expected_locations.get(relative)
        try:
            record = read_json(path, f"result artifact {relative}")
        except EvidenceError as error:
            if path_identity is None:
                coverage["extra"].append({"path": relative, "identity": None})
                global_errors.append(str(error))
            else:
                _add_error(evidence[path_identity], str(error))
            continue
        claimed_identity, errors = _parse_result_identity(record)
        if path_identity is None:
            coverage["extra"].append(
                {"path": relative, "identity": claimed_identity.as_dict() if claimed_identity else None}
            )
            if claimed_identity is not None:
                claimed[claimed_identity].append(relative)
                _add_error(evidence[claimed_identity], f"extra result artifact at {relative}")
            else:
                global_errors.extend(f"extra {relative}: {error}" for error in errors)
            continue
        if claimed_identity is None:
            for error in errors:
                _add_error(evidence[path_identity], f"{relative}: {error}")
            continue
        claimed[claimed_identity].append(relative)
        if claimed_identity != path_identity:
            _add_error(evidence[path_identity], "result identity does not match its canonical artifact path")
            _add_error(evidence[claimed_identity], f"result claims this identity from {relative}")
            continue
        if evidence[path_identity].record is not None:
            _add_error(evidence[path_identity], "duplicate canonical result artifact")
            continue
        evidence[path_identity].record = record
    for identity, locations in claimed.items():
        if len(locations) > 1:
            paths = sorted(locations)
            coverage["duplicates"].append({"identity": identity.as_dict(), "paths": paths})
            _add_error(evidence[identity], "duplicate result identities: " + ", ".join(paths))
    for identity, cell in evidence.items():
        if cell.record is None:
            coverage["missing"].append(identity.as_dict())
            _add_error(cell, "missing canonical result artifact")
    return evidence, coverage, global_errors


def _validate_formal_traffic(value: Any, identity: CellIdentity) -> None:
    expected = {
        "program": "iperf3",
        "duration_seconds": 10,
        "omit_seconds": 2,
        "parallel_flows": identity.parallel_flows,
        "reverse": identity.direction == "dl",
        "json": True,
    }
    if value != expected:
        raise EvidenceError("result formal_traffic does not record the fixed raw iperf3 window")


def _validate_cell_artifacts(
    artifact_root: Path,
    manifest: Mapping[str, Any],
    cell: CellEvidence,
) -> None:
    if cell.record is None:
        return
    record = cell.record
    identity = cell.identity
    if manifest_uses_network_profile(manifest):
        v2_result_keys = {
            "schema",
            "round",
            "requested_tcp_stack",
            "active_tcp_stack",
            "requested_tap_gso",
            "active_tap_gso",
            "parallel_flows",
            "direction",
            "run_uuid",
            "cell",
            "status",
            "formal_traffic",
            "iperf",
            "delivered_goodput_bps",
            "delivered_payload_bytes",
        }
        if set(record) != v2_result_keys | {"network_profile", "netem_seed"}:
            _add_error(cell, "result has an incomplete or unexpected v3 shape")
        if record.get("schema") != RESULT_SCHEMA_V3:
            _add_error(cell, f"result schema must be {RESULT_SCHEMA_V3!r}")
        try:
            if _validated_network_profile(record.get("network_profile")) != _validated_network_profile(
                manifest.get("network_profile")
            ):
                raise EvidenceError("result network profile does not match the manifest")
            if _validated_campaign_seed(record.get("netem_seed")) != _validated_campaign_seed(
                manifest.get("netem_seed")
            ):
                raise EvidenceError("result netem seed does not match the manifest")
        except EvidenceError as error:
            _add_error(cell, str(error))
    elif record.get("schema") != RESULT_SCHEMA:
        _add_error(cell, f"result schema must be {RESULT_SCHEMA!r}")
    if record.get("run_uuid") != manifest.get("run_uuid"):
        _add_error(cell, "result run UUID does not match the manifest")
    if record.get("cell") != identity.as_dict():
        _add_error(cell, "result cell identity does not match its artifact path")
    if record.get("status") != "complete":
        _add_error(cell, "result status must be complete; acceptance status is verifier-owned")
    try:
        _validate_formal_traffic(record.get("formal_traffic"), identity)
    except EvidenceError as error:
        _add_error(cell, str(error))

    cell_path = cell.result_path.parent
    try:
        iperf = record.get("iperf")
        if not isinstance(iperf, dict) or iperf.get("path") != identity.iperf_filename():
            raise EvidenceError(f"result iperf locator must be {identity.iperf_filename()}")
        _iperf_path, iperf_raw = _read_hashed_locator(cell_path, iperf, "raw iperf artifact")
        parsed = validate_raw_iperf(parse_json_bytes(iperf_raw, "raw iperf artifact"), identity)
        summary_goodput = _finite_decimal(
            record.get("delivered_goodput_bps"), "result delivered_goodput_bps", positive=True
        )
        if summary_goodput != parsed["delivered_goodput_bps"]:
            raise EvidenceError("result delivered_goodput_bps does not equal validated raw iperf goodput")
        if record.get("delivered_payload_bytes") != parsed["delivered_payload_bytes"]:
            raise EvidenceError("result delivered_payload_bytes does not equal validated raw iperf payload")
        cell.delivered_goodput_bps = parsed["delivered_goodput_bps"]
        cell.delivered_payload_bytes = parsed["delivered_payload_bytes"]
    except EvidenceError as error:
        _add_error(cell, str(error))

    observation: dict[str, Any] | None = None
    try:
        launch = read_json(cell_path / "launch.json", "cell launch record")
        observation = validate_launch_record(launch, artifact_root, manifest, identity)
    except EvidenceError as error:
        _add_error(cell, str(error))

    direct_path = cell_path / "direct-proof.json"
    if identity.stack == "xtcp":
        try:
            proof = read_json(direct_path, "direct proof")
            if observation is None or cell.delivered_payload_bytes is None:
                raise EvidenceError("direct proof cannot be assessed without valid launch and raw iperf evidence")
            cell.direct_admission_evidence = validate_direct_proof(
                proof,
                identity,
                str(manifest.get("run_uuid")),
                cell_directory_path=cell_path,
                delivered_payload_bytes=cell.delivered_payload_bytes,
                launch_observation=observation,
            )
        except EvidenceError as error:
            _add_error(cell, str(error))
    elif _path_entry_exists(direct_path, "native direct proof"):
        _add_error(cell, "native cell must not contain an XTCP direct proof")


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _verify_run_inventory(artifact_root: Path) -> list[str]:
    try:
        recorded = read_json(_run_inventory_path(artifact_root), "run inventory")
        if not isinstance(recorded, dict):
            raise EvidenceError("run inventory must be an object")
        if (
            recorded.get("schema") != INVENTORY_SCHEMA
            or recorded.get("root") != str(artifact_root)
            or recorded.get("excluded_paths") != sorted(CONTROL_ARTIFACT_PATHS)
            or not isinstance(recorded.get("entries"), list)
            or _inventory_digest(recorded) != recorded.get("sha256")
        ):
            raise EvidenceError("run inventory has an invalid strict shape or digest")
        detached = _parse_hash_file(_run_inventory_hash_path(artifact_root), "run inventory hash")
        if detached != recorded["sha256"]:
            raise EvidenceError("run inventory hash does not match run-inventory.json")
        if artifact_inventory(artifact_root)["sha256"] != recorded["sha256"]:
            raise EvidenceError("run artifact content identity drifted after sealing")
    except (AcceptanceError, EvidenceError, KeyError, TypeError) as error:
        return [str(error)]
    return []


def _empty_cells(artifact_root: Path) -> dict[CellIdentity, CellEvidence]:
    return {
        identity: CellEvidence(identity, artifact_root / identity.relative_directory() / "result.json")
        for identity in expected_cells()
    }


def _empty_coverage() -> dict[str, Any]:
    return {
        "expected_cells": len(expected_cells()),
        "discovered_result_files": 0,
        "missing": [identity.as_dict() for identity in expected_cells()],
        "duplicates": [],
        "extra": [],
    }


def _report_shell(
    artifact_root: Path,
    threshold: Decimal,
    global_errors: list[str],
    coverage: Mapping[str, Any],
    cells: Mapping[CellIdentity, CellEvidence],
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    report = {
        "schema": ACCEPTANCE_SCHEMA,
        "artifact_root": str(artifact_root),
        "threshold": decimal_text(threshold),
        "status": "not_assessed",
        "global_evidence_errors": list(global_errors),
        "coverage": dict(coverage),
        "cells": [
            {
                "identity": identity.as_dict(),
                "evidence_valid": not cell.errors,
                "errors": list(cell.errors),
                "delivered_goodput_bps": (
                    decimal_text(cell.delivered_goodput_bps)
                    if cell.delivered_goodput_bps is not None
                    else None
                ),
                "delivered_payload_bytes": cell.delivered_payload_bytes,
                "direct_admission_evidence": cell.direct_admission_evidence,
            }
            for identity, cell in sorted(
                cells.items(),
                key=lambda item: (
                    item[0].round,
                    item[0].parallel_flows,
                    item[0].direction,
                    item[0].stack,
                ),
            )
        ],
        "pairs": [],
    }
    if manifest is not None and manifest_uses_network_profile(manifest):
        report.update(
            {
                "schema": ACCEPTANCE_SCHEMA_V3,
                "network_profile": manifest.get("network_profile"),
                "netem_seed": manifest.get("netem_seed"),
            }
        )
    return report


def _assess_normal_run(artifact_root: Path, *, require_seal: bool) -> dict[str, Any]:
    global_errors: list[str] = []
    threshold = MINIMUM_THRESHOLD
    manifest: dict[str, Any] | None = None
    try:
        loaded = read_json(_manifest_path(artifact_root), "acceptance manifest")
        if isinstance(loaded, dict):
            manifest = loaded
        else:
            _append_unique(global_errors, "acceptance manifest must be a JSON object")
    except EvidenceError as error:
        _append_unique(global_errors, str(error))
    if manifest is not None:
        for error in _verify_manifest_hash(artifact_root, manifest):
            _append_unique(global_errors, error)
        manifest_errors, threshold = _check_manifest(manifest, artifact_root)
        for error in manifest_errors:
            _append_unique(global_errors, error)
        for verifier in (_verify_launch_environment_contract, _verify_source_identity):
            for error in verifier(artifact_root, manifest):
                _append_unique(global_errors, error)
        for error in _verify_candidate_identity(manifest):
            _append_unique(global_errors, error)
    else:
        _append_unique(global_errors, "acceptance manifest is unavailable")
    if require_seal:
        for error in _verify_run_inventory(artifact_root):
            _append_unique(global_errors, error)

    cells, coverage, scan_errors = _scan_cell_results(artifact_root)
    for error in scan_errors:
        _append_unique(global_errors, error)
    if manifest is not None:
        for cell in cells.values():
            _validate_cell_artifacts(artifact_root, manifest, cell)
    report = _report_shell(artifact_root, threshold, global_errors, coverage, cells, manifest)
    pairs: list[dict[str, Any]] = []
    for pair in expected_pairs():
        native = cells[pair.cell("native")]
        xtcp = cells[pair.cell("xtcp")]
        evidence_errors: list[str] = []
        if global_errors:
            evidence_errors.append("global acceptance evidence is invalid")
        for error in native.errors:
            _append_unique(evidence_errors, f"native: {error}")
        for error in xtcp.errors:
            _append_unique(evidence_errors, f"xtcp: {error}")
        if native.delivered_goodput_bps is None:
            _append_unique(evidence_errors, "native: validated delivered iperf goodput is unavailable")
        if xtcp.delivered_goodput_bps is None:
            _append_unique(evidence_errors, "xtcp: validated delivered iperf goodput is unavailable")
        pair_report: dict[str, Any] = {
            "identity": pair.as_dict(),
            "status": "not_assessed",
            "ratio": None,
            "native_delivered_goodput_bps": (
                decimal_text(native.delivered_goodput_bps)
                if native.delivered_goodput_bps is not None
                else None
            ),
            "xtcp_delivered_goodput_bps": (
                decimal_text(xtcp.delivered_goodput_bps)
                if xtcp.delivered_goodput_bps is not None
                else None
            ),
            "evidence_errors": evidence_errors,
        }
        if not evidence_errors:
            ratio = xtcp.delivered_goodput_bps / native.delivered_goodput_bps
            pair_report["ratio"] = decimal_text(ratio)
            pair_report["status"] = "pass" if ratio >= threshold else "assessed_fail"
        pairs.append(pair_report)
    report["pairs"] = pairs
    if any(pair["status"] == "not_assessed" for pair in pairs):
        report["status"] = "not_assessed"
    elif any(pair["status"] == "assessed_fail" for pair in pairs):
        report["status"] = "assessed_fail"
    else:
        report["status"] = "pass"
    report["counts"] = {
        status: sum(pair["status"] == status for pair in pairs)
        for status in ("pass", "assessed_fail", "not_assessed")
    }
    return report


def seal_run(artifact_root: Path) -> dict[str, Any]:
    """Seal only complete normal evidence; an assessed ratio failure may seal."""

    artifact_root = _resolve_artifact_root_argument(artifact_root)
    if not artifact_root.is_dir():
        raise AcceptanceError(f"artifact root is not a directory: {artifact_root}")
    if _path_entry_exists(_freeze_path(artifact_root), "freeze record"):
        raise AcceptanceError("frozen artifacts are sealed by freeze and cannot be sealed as a normal run")
    if (
        _path_entry_exists(_run_inventory_path(artifact_root), "run inventory")
        or _path_entry_exists(_run_inventory_hash_path(artifact_root), "run inventory hash")
    ):
        raise AcceptanceError("run is already sealed and cannot be resealed")
    report = _assess_normal_run(artifact_root, require_seal=False)
    if report["status"] == "not_assessed":
        details = report["global_evidence_errors"]
        for cell in report["cells"]:
            details.extend(cell["errors"])
        raise AcceptanceError(
            "cannot seal incomplete or malformed normal evidence: "
            + ("; ".join(dict.fromkeys(details)) if details else "assessment is unavailable")
        )
    inventory = artifact_inventory(artifact_root)
    write_json(_run_inventory_path(artifact_root), inventory)
    _run_inventory_hash_path(artifact_root).write_text(inventory["sha256"] + "\n", encoding="ascii")
    return inventory


def _validate_command(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise AcceptanceError("freeze command must be a non-empty JSON array of strings")
    return list(value)


def _validate_freeze_status(status: Any) -> str:
    if status not in {"not_assessed", "assessed_fail"}:
        raise AcceptanceError("freeze status must be exactly not_assessed or assessed_fail")
    return str(status)


def freeze_run(
    artifact_root: Path,
    source_root: Path,
    *,
    status: str,
    stage: str,
    reason: str,
    command: Any,
    log: Path,
    candidate: Path | None = None,
) -> dict[str, Any]:
    """Freeze a non-pass outcome in a fresh, immediately sealed artifact root."""

    frozen_status = _validate_freeze_status(status)
    if not isinstance(stage, str) or not stage.strip():
        raise AcceptanceError("freeze stage must be a non-empty string")
    if not isinstance(reason, str) or not reason.strip():
        raise AcceptanceError("freeze reason must be a non-empty string")
    command_array = _validate_command(command)
    source_root = _validated_source_root(source_root)
    artifact_root = _resolve_artifact_root_argument(artifact_root)
    if _path_entry_exists(artifact_root, "artifact root"):
        raise AcceptanceError(f"artifact root already exists and cannot be reused: {artifact_root}")
    supplied_log = Path(log).expanduser()
    log_metadata = _require_regular_file(supplied_log, "freeze log", AcceptanceError)
    if not supplied_log.is_absolute():
        # A relative log remains legal but must resolve before it is copied.
        supplied_log = supplied_log.resolve(strict=True)
    candidate_identity = collect_candidate_identity(candidate, source_root) if candidate is not None else None
    artifact_root.mkdir(parents=True, exist_ok=False)
    source_identity = build_source_inventory(source_root)
    copied_log = artifact_root / "frozen-log.txt"
    try:
        shutil.copyfile(supplied_log, copied_log)
    except OSError as error:
        raise AcceptanceError(f"cannot copy freeze log: {error}") from None
    if copied_log.stat().st_size != log_metadata.st_size:
        raise AcceptanceError("copied freeze log size does not match its input")
    freeze = {
        "schema": FREEZE_SCHEMA,
        "run_uuid": str(uuid.uuid4()),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": frozen_status,
        "stage": stage,
        "reason": reason,
        "command": command_array,
        "log": {
            "path": "frozen-log.txt",
            "sha256": sha256_file(copied_log),
            "size_bytes": copied_log.stat().st_size,
        },
        "source": {
            "root": str(source_root),
            "inventory_sha256": source_identity["sha256"],
            "allowlist_sha256": canonical_json_sha256(source_identity["allowlist"]),
        },
        "candidate": candidate_identity,
    }
    freeze_manifest = {
        "schema": FREEZE_MANIFEST_SCHEMA,
        "freeze_sha256": canonical_json_sha256(freeze),
        "run_uuid": freeze["run_uuid"],
        "status": frozen_status,
        "source": freeze["source"],
        "candidate": candidate_identity,
    }
    write_json(_source_inventory_path(artifact_root), source_identity)
    write_json(_freeze_path(artifact_root), freeze)
    write_json(_freeze_manifest_path(artifact_root), freeze_manifest)
    _freeze_manifest_hash_path(artifact_root).write_text(
        canonical_json_sha256(freeze_manifest) + "\n", encoding="ascii"
    )
    inventory = artifact_inventory(artifact_root)
    write_json(_run_inventory_path(artifact_root), inventory)
    _run_inventory_hash_path(artifact_root).write_text(inventory["sha256"] + "\n", encoding="ascii")
    return freeze


def _verify_frozen_run(artifact_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    freeze: dict[str, Any] | None = None
    try:
        loaded = read_json(_freeze_path(artifact_root), "freeze record")
        if isinstance(loaded, dict):
            freeze = loaded
        else:
            errors.append("freeze record must be a JSON object")
    except EvidenceError as error:
        errors.append(str(error))
    if freeze is not None:
        expected_freeze_keys = {
            "schema", "run_uuid", "created_at_utc", "status", "stage", "reason", "command", "log", "source", "candidate"
        }
        if set(freeze) != expected_freeze_keys or freeze.get("schema") != FREEZE_SCHEMA:
            errors.append("freeze record has an incomplete or unexpected v2 shape")
        try:
            uuid.UUID(str(freeze.get("run_uuid")))
        except (ValueError, TypeError, AttributeError):
            errors.append("freeze run_uuid is invalid")
        try:
            _validate_freeze_status(freeze.get("status"))
            if not isinstance(freeze.get("stage"), str) or not freeze["stage"].strip():
                raise AcceptanceError("freeze stage must be non-empty")
            if not isinstance(freeze.get("reason"), str) or not freeze["reason"].strip():
                raise AcceptanceError("freeze reason must be non-empty")
            _validate_command(freeze.get("command"))
            log = freeze.get("log")
            if not isinstance(log, dict) or set(log) != {"path", "sha256", "size_bytes"}:
                raise EvidenceError("freeze log locator is malformed")
            if log.get("path") != "frozen-log.txt" or not isinstance(log.get("size_bytes"), int) or log["size_bytes"] < 0:
                raise EvidenceError("freeze log metadata is invalid")
            log_path = _safe_relative_file(artifact_root, log["path"], "freeze log")
            if log_path.stat().st_size != log["size_bytes"] or sha256_file(log_path) != log["sha256"]:
                raise EvidenceError("copied freeze log identity does not match")
        except (AcceptanceError, EvidenceError) as error:
            errors.append(str(error))
        for error in _verify_source_identity_from_reference(artifact_root, freeze.get("source")):
            _append_unique(errors, error)
        frozen_candidate = freeze.get("candidate")
        if frozen_candidate is not None:
            try:
                _validate_candidate_shape(frozen_candidate)
                current = collect_candidate_identity(
                    Path(frozen_candidate["path"]), Path(freeze["source"]["root"])
                )
                if current != frozen_candidate:
                    raise EvidenceError("frozen candidate content identity drifted")
            except (AcceptanceError, EvidenceError, KeyError, TypeError) as error:
                _append_unique(errors, str(error))
        try:
            freeze_manifest = read_json(_freeze_manifest_path(artifact_root), "freeze manifest")
            expected_hash = _parse_hash_file(_freeze_manifest_hash_path(artifact_root), "freeze manifest hash")
            if not isinstance(freeze_manifest, dict) or canonical_json_sha256(freeze_manifest) != expected_hash:
                raise EvidenceError("freeze manifest SHA-256 is invalid")
            expected_manifest = {
                "schema": FREEZE_MANIFEST_SCHEMA,
                "freeze_sha256": canonical_json_sha256(freeze),
                "run_uuid": freeze["run_uuid"],
                "status": freeze["status"],
                "source": freeze["source"],
                "candidate": freeze["candidate"],
            }
            if freeze_manifest != expected_manifest:
                raise EvidenceError("freeze manifest does not bind the freeze record")
        except (AcceptanceError, EvidenceError, KeyError, TypeError) as error:
            _append_unique(errors, str(error))
    for error in _verify_run_inventory(artifact_root):
        _append_unique(errors, error)
    status = freeze.get("status") if freeze is not None and not errors else "not_assessed"
    return {
        "schema": ACCEPTANCE_SCHEMA,
        "artifact_root": str(artifact_root),
        "status": status,
        "frozen": True,
        "freeze_status": freeze.get("status") if freeze is not None else None,
        "global_evidence_errors": errors,
        "stage": freeze.get("stage") if freeze is not None else None,
        "reason": freeze.get("reason") if freeze is not None else None,
        "pairs": [],
        "counts": {"pass": 0, "assessed_fail": 0, "not_assessed": 0},
    }


def verify_run(artifact_root: Path) -> dict[str, Any]:
    """Verify a sealed normal or frozen artifact, failing closed on gaps."""

    try:
        artifact_root = _resolve_artifact_root_argument(artifact_root)
    except AcceptanceError as error:
        raw_root = Path(artifact_root).expanduser()
        report = _report_shell(raw_root, MINIMUM_THRESHOLD, [str(error)], _empty_coverage(), _empty_cells(raw_root))
        report["pairs"] = [
            {
                "identity": pair.as_dict(),
                "status": "not_assessed",
                "ratio": None,
                "native_delivered_goodput_bps": None,
                "xtcp_delivered_goodput_bps": None,
                "evidence_errors": ["artifact root is invalid"],
            }
            for pair in expected_pairs()
        ]
        report["counts"] = {"pass": 0, "assessed_fail": 0, "not_assessed": len(expected_pairs())}
        return report
    if not artifact_root.is_dir():
        report = _report_shell(
            artifact_root,
            MINIMUM_THRESHOLD,
            [f"artifact root is not a directory: {artifact_root}"],
            _empty_coverage(),
            _empty_cells(artifact_root),
        )
        report["pairs"] = [
            {
                "identity": pair.as_dict(),
                "status": "not_assessed",
                "ratio": None,
                "native_delivered_goodput_bps": None,
                "xtcp_delivered_goodput_bps": None,
                "evidence_errors": ["artifact root is not a directory"],
            }
            for pair in expected_pairs()
        ]
        report["counts"] = {"pass": 0, "assessed_fail": 0, "not_assessed": len(expected_pairs())}
        return report
    if _path_entry_exists(_freeze_path(artifact_root), "freeze record"):
        report = _verify_frozen_run(artifact_root)
    else:
        report = _assess_normal_run(artifact_root, require_seal=True)
    try:
        write_json(artifact_root / "acceptance-report.json", report)
    except AcceptanceError:
        # The returned result remains fail-closed; an attacker cannot turn an
        # inability to write a verifier report into a pass.
        if report.get("status") == "pass":
            report["status"] = "not_assessed"
            report.setdefault("global_evidence_errors", []).append("cannot write acceptance report")
    return report


def _print_json(value: Any) -> None:
    print(json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True))


def _parse_command_json(value: str) -> list[str]:
    try:
        parsed = parse_json_text(value, "--command-json")
    except EvidenceError as error:
        raise AcceptanceError(str(error)) from None
    return _validate_command(parsed)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print the immutable 36-cell acceptance plan")

    prepare = subparsers.add_parser("prepare", help="create a fresh acceptance artifact root")
    prepare.add_argument("--artifacts", type=Path, required=True)
    prepare.add_argument("--source-root", type=Path, default=Path.cwd())
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--threshold", default=decimal_text(MINIMUM_THRESHOLD))
    prepare.add_argument("--network-profile", choices=NETWORK_PROFILE_IDS)
    prepare.add_argument("--netem-seed", type=int)

    seal = subparsers.add_parser("seal", help="seal complete normal evidence")
    seal.add_argument("--artifacts", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify a sealed strict acceptance artifact")
    verify.add_argument("--artifacts", type=Path, required=True)

    freeze = subparsers.add_parser("freeze", help="freeze and immediately seal a non-pass outcome")
    freeze.add_argument("--artifacts", type=Path, required=True)
    freeze.add_argument("--source-root", type=Path, default=Path.cwd())
    freeze.add_argument("--status", required=True, choices=("not_assessed", "assessed_fail"))
    freeze.add_argument("--stage", required=True)
    freeze.add_argument("--reason", required=True)
    freeze.add_argument("--command-json", required=True)
    freeze.add_argument("--log", type=Path, required=True)
    freeze.add_argument("--candidate", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command == "plan":
            _print_json(
                {
                    "schema": ACCEPTANCE_SCHEMA,
                    "minimum_threshold": decimal_text(MINIMUM_THRESHOLD),
                    "cells": [identity.as_dict() for identity in expected_cells()],
                    "pairs": [identity.as_dict() for identity in expected_pairs()],
                }
            )
            return 0
        if arguments.command == "prepare":
            manifest = prepare_run(
                arguments.artifacts,
                arguments.source_root,
                arguments.candidate,
                arguments.threshold,
                network_profile=arguments.network_profile,
                netem_seed=arguments.netem_seed,
            )
            _print_json(
                {
                    "artifacts": str(Path(arguments.artifacts).resolve(strict=False)),
                    "run_uuid": manifest["run_uuid"],
                    "manifest_sha256": canonical_json_sha256(manifest),
                }
            )
            return 0
        if arguments.command == "seal":
            inventory = seal_run(arguments.artifacts)
            _print_json(
                {
                    "artifacts": str(Path(arguments.artifacts).resolve(strict=False)),
                    "inventory_sha256": inventory["sha256"],
                }
            )
            return 0
        if arguments.command == "verify":
            report = verify_run(arguments.artifacts)
            _print_json(report)
            return 0 if report["status"] == "pass" else 1
        if arguments.command == "freeze":
            frozen = freeze_run(
                arguments.artifacts,
                arguments.source_root,
                status=arguments.status,
                stage=arguments.stage,
                reason=arguments.reason,
                command=_parse_command_json(arguments.command_json),
                log=arguments.log,
                candidate=arguments.candidate,
            )
            _print_json(
                {
                    "artifacts": str(Path(arguments.artifacts).resolve(strict=False)),
                    "run_uuid": frozen["run_uuid"],
                    "status": frozen["status"],
                }
            )
            return 0
        raise AssertionError(f"unhandled command {arguments.command!r}")
    except AcceptanceError as error:
        print(f"datapath acceptance: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
