#!/usr/bin/env python3
"""Synthetic contract tests for strict datapath acceptance v2/v3 tooling."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "datapath_acceptance.py"
WRAPPER = ROOT / "tools" / "run_datapath_linux_acceptance.sh"
ADAPTER = ROOT / "tools" / "datapath_linux_strict_adapter.py"
sys.path.insert(0, str(ROOT / "tools"))
import datapath_acceptance as acceptance


@dataclass
class Fixture:
    root: Path
    source: Path
    candidate: Path
    artifacts: Path
    manifest: dict[str, Any]


def assertion_error(expected: str, actual: BaseException | None = None) -> AssertionError:
    suffix = f"; got {actual!r}" if actual is not None else ""
    return AssertionError(expected + suffix)


def expect_error(callback: Callable[[], Any], text: str | None = None) -> acceptance.AcceptanceError:
    try:
        callback()
    except acceptance.AcceptanceError as error:
        if text is not None and text not in str(error):
            raise assertion_error(f"expected error containing {text!r}", error) from error
        return error
    raise assertion_error("expected AcceptanceError")


def assert_contains(values: list[str], expected: str) -> None:
    if not any(expected in value for value in values):
        raise assertion_error(f"missing {expected!r} in {values!r}")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def pair_for(identity: acceptance.CellIdentity) -> acceptance.PairIdentity:
    return acceptance.PairIdentity(
        round=identity.round,
        parallel_flows=identity.parallel_flows,
        direction=identity.direction,
        tap_gso=identity.tap_gso,
    )


def pair_report(report: dict[str, Any], pair: acceptance.PairIdentity) -> dict[str, Any]:
    for candidate in report["pairs"]:
        if candidate["identity"] == pair.as_dict():
            return candidate
    raise assertion_error(f"missing pair report for {pair.as_dict()!r}")


def cell_report(report: dict[str, Any], identity: acceptance.CellIdentity) -> dict[str, Any]:
    for candidate in report["cells"]:
        if candidate["identity"] == identity.as_dict():
            return candidate
    raise assertion_error(f"missing cell report for {identity.as_dict()!r}")


def assert_cell_not_assessed(
    report: dict[str, Any], identity: acceptance.CellIdentity, expected: str
) -> None:
    pair = pair_report(report, pair_for(identity))
    assert report["status"] == "not_assessed", report
    assert pair["status"] == "not_assessed", pair
    assert pair["ratio"] is None, pair
    assert_contains(pair["evidence_errors"], expected)


def write_source_fixture(source: Path) -> None:
    files = {
        "CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)\n",
        "main.cpp": "int main() { return 0; }\n",
        "tools/compat/server.json": '{"concurrent":1}\n',
        "tools/compat/client_proxy.json": '{"concurrent":1}\n',
        "tools/datapath_acceptance.py": "# source identity fixture\n",
        "tools/run_datapath_linux_acceptance.sh": "#!/usr/bin/env bash\n",
        "tools/datapath_linux_strict_adapter.py": "#!/usr/bin/env python3\n",
        "cmake/Coverage.cmake": "# cmake fixture\n",
        "common/base.h": "#pragma once\n",
        "ppp/runtime.cpp": "int runtime_fixture = 1;\n",
        "linux/tap.cpp": "int tap_fixture = 1;\n",
        "third-party/xtcp/include/xtcp.h": "#pragma once\n",
    }
    source.mkdir(parents=True, exist_ok=False)
    for relative, content in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    # This deliberately lies at the source root but outside the strict
    # allowlist.  It must never be traversed, opened, or hashed.
    (source / "credential-material.txt").write_text("not-source-evidence\n", encoding="utf-8")


def write_v3_source_inputs(source: Path) -> None:
    uniform = source / acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH
    uniform.parent.mkdir(parents=True, exist_ok=True)
    uniform.write_bytes(b"# synthetic uniform netem distribution\n0 1\n")
    periodic_bpf = source / acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH
    periodic_bpf.write_bytes(
        b"#define SEC(NAME) __attribute__((section(NAME), used))\n"
        b"SEC(\"carrier_egress\") int carrier_egress(void *ctx) { return 0; }\n"
        b"char LICENSE[] SEC(\"license\") = \"GPL\";\n"
    )


@contextmanager
def prepared_fixture() -> Iterator[Fixture]:
    with tempfile.TemporaryDirectory(prefix="datapath-acceptance-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        candidate = root / "candidate-ppp"
        candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        artifacts = root / "artifacts"
        manifest = acceptance.prepare_run(artifacts, source, candidate)
        yield Fixture(root, source, candidate, artifacts, manifest)


@contextmanager
def prepared_v3_fixture(
    profile_id: str = "rtt-75-j20", netem_seed: int = 73
) -> Iterator[Fixture]:
    with tempfile.TemporaryDirectory(prefix="datapath-acceptance-v3-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        write_v3_source_inputs(source)
        candidate = root / "candidate-ppp"
        candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        artifacts = root / "artifacts"
        manifest = acceptance.prepare_run(
            artifacts,
            source,
            candidate,
            network_profile=profile_id,
            netem_seed=netem_seed,
        )
        yield Fixture(root, source, candidate, artifacts, manifest)


def raw_iperf(identity: acceptance.CellIdentity, goodput_bps: int) -> tuple[dict[str, Any], bytes]:
    aggregate_name = "sum_sent" if identity.direction == "ul" else "sum_received"
    stream_name = "sender" if identity.direction == "ul" else "receiver"
    payload_bytes = goodput_bps * 10
    document = {
        "start": {
            "connecting_to": {
                "host": acceptance.FORMAL_TARGET_HOST,
                "port": acceptance.FORMAL_TARGET_PORT,
            },
            "connected": [
                {
                    "socket": index + 5,
                    "local_host": "10.0.0.2",
                    "local_port": 40000 + index,
                    "remote_host": acceptance.FORMAL_TARGET_HOST,
                    "remote_port": acceptance.FORMAL_TARGET_PORT,
                }
                for index in range(identity.parallel_flows)
            ],
        },
        "end": {
            aggregate_name: {
                "bits_per_second": goodput_bps,
                "bytes": payload_bytes,
                "seconds": 1,
            },
            "streams": [
                {stream_name: {"bits_per_second": max(1, goodput_bps // identity.parallel_flows)}}
                for _ in range(identity.parallel_flows)
            ],
        },
    }
    return document, json_bytes(document)


def _stats_record(
    fixture: Fixture,
    identity: acceptance.CellIdentity,
    phase: str,
    sequence: int,
    counters: dict[str, int],
    runtime_id: int = 99,
) -> dict[str, Any]:
    monotonic_ms = 1000 + sequence
    return {
        "type": "ppp-stats",
        "version": 1,
        "monotonic_ms": monotonic_ms,
        "tcp_stack": {"requested": "xtcp", "active": "xtcp"},
        "tap_linux": {"vnet_header": True, "gso_merge_active": True},
        "xtcp": {
            "runtime_instance_id": runtime_id,
            "ndi_gso_enabled": False,
            "ndi_gso_rejected": 17 + sequence,
            **counters,
        },
        "acceptance_boundary": {
            "schema": 1,
            "run_uuid": fixture.manifest["run_uuid"],
            "cell_id": identity.relative_directory(),
            "sequence": sequence,
            "phase": phase,
            "monotonic_ms": monotonic_ms,
            "process_pid": 4242,
            "process_start_ticks": 777,
            "xtcp_runtime_instance_id": runtime_id,
        },
    }


def raw_xtcp_stats(
    fixture: Fixture, identity: acceptance.CellIdentity, payload_bytes: int
) -> bytes:
    start_counters = {
        "direct_bridge_starts": 100,
        "direct_bridge_fallbacks": 0,
        "connector_read_bytes": 0,
        "connector_written_bytes": 0,
        "direct_upload_accepted_bytes": 2000,
        "direct_download_accepted_bytes": 3000,
    }
    end_counters = dict(start_counters)
    end_counters["direct_bridge_starts"] += identity.parallel_flows
    accepted = (
        "direct_upload_accepted_bytes"
        if identity.direction == "ul"
        else "direct_download_accepted_bytes"
    )
    end_counters[accepted] += payload_bytes
    records = (
        _stats_record(fixture, identity, "measurement_start", 1, start_counters),
        _stats_record(fixture, identity, "measurement_end", 2, end_counters),
    )
    return b"".join(json_bytes(record) + b"\n" for record in records)


def raw_locator(path: Path, cell: Path) -> dict[str, str]:
    return {"path": path.relative_to(cell).as_posix(), "sha256": sha256(path.read_bytes())}


def write_cpu_proof(cell: Path) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    status = b"Name:\tppp\nPid:\t4242\nCpus_allowed_list:\t3\n"
    sched = b"se.nr_migrations                             : 7\n"
    before: dict[str, dict[str, str]] = {}
    after: dict[str, dict[str, str]] = {}
    for phase, result in (("before", before), ("after", after)):
        for kind, raw in (("status", status), ("sched", sched)):
            path = cell / f"cpu-{phase}-{kind}.txt"
            write_bytes(path, raw)
            result[kind] = raw_locator(path, cell)
    return before, after


def write_cell(fixture: Fixture, identity: acceptance.CellIdentity, goodput_bps: int) -> None:
    cell = acceptance.cell_directory(fixture.artifacts, identity)
    cell.mkdir(parents=True, exist_ok=False)
    server_config = cell / "server-config.json"
    client_config = cell / "client-config.json"
    acceptance.write_json(server_config, {"concurrent": 1, "tcp": {"listen": {"port": 20000}}})
    acceptance.write_json(
        client_config,
        {"concurrent": 1, "client": {"server": "ppp://198.18.0.1:20000/"}},
    )
    request = {
        "schema": 1,
        "run_uuid": fixture.manifest["run_uuid"],
        "cell_id": identity.relative_directory(),
        "sequence": 2,
        "phase": "measurement_end",
    }
    _iperf_document, raw_iperf_document = raw_iperf(identity, goodput_bps)
    iperf_path = cell / identity.iperf_filename()
    write_bytes(iperf_path, raw_iperf_document)
    payload_bytes = goodput_bps * 10
    stats_path = cell / "stats.ndjson"
    if identity.stack == "xtcp":
        raw_stats = raw_xtcp_stats(fixture, identity, payload_bytes)
        acknowledgement = json.loads(raw_stats.splitlines()[-1])["acceptance_boundary"]
    else:
        raw_stats = b'{"type":"native-stats-placeholder"}\n'
        acknowledgement = {
            "schema": 1,
            "run_uuid": fixture.manifest["run_uuid"],
            "cell_id": identity.relative_directory(),
            "sequence": 2,
            "phase": "measurement_end",
            "monotonic_ms": 1002,
            "process_pid": 4242,
            "process_start_ticks": 777,
            "xtcp_runtime_instance_id": 0,
        }
    acceptance.write_json(cell / "boundary-request.json", request)
    acceptance.write_json(cell / "boundary-ack.json", acknowledgement)
    write_bytes(stats_path, raw_stats)
    before, after = write_cpu_proof(cell)
    qdisc_paths = []
    for suffix, interface in (("client", "eth0"), ("server", "eth1")):
        path = cell / f"qdisc-{suffix}.txt"
        write_bytes(path, f"qdisc fq_codel 0: root refcnt 2 dev {interface}\n".encode("ascii"))
        qdisc_paths.append({"interface": interface, **raw_locator(path, cell)})
    target_route = cell / "target-route.txt"
    tun_link = cell / "tun-link.txt"
    write_bytes(
        target_route,
        f"{acceptance.FORMAL_TARGET_HOST} dev ppp0 src 10.0.0.2\n".encode("ascii"),
    )
    write_bytes(tun_link, b"7: ppp0: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN\n")
    rps_xps = cell / "rps-xps.json"
    acceptance.write_json(
        rps_xps,
        {
            "schema": 1,
            "reads": [
                {"kind": "rps", "path": "/sys/class/net/eth0/queues/rx-0/rps_cpus", "value": "00000008"},
                {"kind": "xps", "path": "/sys/class/net/eth0/queues/tx-0/xps_cpus", "value": "00000008"},
            ],
        },
    )
    environment = acceptance.expected_cell_environment(
        fixture.artifacts, identity, fixture.manifest["run_uuid"]
    )
    launch = {
        "schema": acceptance.LAUNCH_SCHEMA,
        "run_uuid": fixture.manifest["run_uuid"],
        "role": "client",
        "cell": identity.as_dict(),
        "environment_mode": "env -i",
        "environment": environment,
        "candidate": dict(fixture.manifest["candidate"]),
        "argv": acceptance.expected_client_argv(fixture.artifacts, fixture.manifest, identity),
        "config": raw_locator(client_config, cell),
        "server_config": raw_locator(server_config, cell),
        "stats": {"path": "stats.ndjson"},
        "boundary_request": {"path": "boundary-request.json"},
        "boundary_acknowledgement": {"path": "boundary-ack.json"},
        "observed_process": {
            "pid": 4242,
            "start_ticks": 777,
            "executable": {
                "path": fixture.manifest["candidate"]["path"],
                "sha256": fixture.manifest["candidate"]["sha256"],
            },
            "cmdline": acceptance.expected_client_argv(fixture.artifacts, fixture.manifest, identity),
            "environment": dict(environment),
        },
        "cpu": {
            "affinity_cpu": 3,
            "before": before,
            "after": after,
            "migration_before": 7,
            "migration_after": 7,
            "migration_delta": 0,
        },
        "tun": {
            "interface": "ppp0",
            "route": raw_locator(target_route, cell),
            "link": raw_locator(tun_link, cell),
        },
        "qdisc": qdisc_paths,
        "rps_xps": raw_locator(rps_xps, cell),
    }
    result = {
        "schema": acceptance.RESULT_SCHEMA,
        **identity.as_dict(),
        "run_uuid": fixture.manifest["run_uuid"],
        "cell": identity.as_dict(),
        "status": "complete",
        "formal_traffic": {
            "program": "iperf3",
            "duration_seconds": 10,
            "omit_seconds": 2,
            "parallel_flows": identity.parallel_flows,
            "reverse": identity.direction == "dl",
            "json": True,
        },
        "iperf": raw_locator(iperf_path, cell),
        "delivered_goodput_bps": goodput_bps,
        "delivered_payload_bytes": payload_bytes,
    }
    acceptance.write_json(cell / "launch.json", launch)
    if identity.stack == "xtcp":
        locators = acceptance.find_stats_boundary_locators(
            raw_stats, fixture.manifest["run_uuid"], identity.relative_directory()
        )
        acceptance.write_json(
            cell / "direct-proof.json",
            {
                "schema": acceptance.DIRECT_PROOF_SCHEMA,
                "run_uuid": fixture.manifest["run_uuid"],
                "cell": identity.as_dict(),
                "raw_stats": {
                    "path": "stats.ndjson",
                    "sha256": sha256(raw_stats),
                    "measurement_start": locators["measurement_start"],
                    "measurement_end": locators["measurement_end"],
                },
            },
        )
    acceptance.write_json(cell / "result.json", result)


def write_json_evidence(cell: Path, name: str, value: Any) -> dict[str, str]:
    path = cell / name
    write_bytes(path, json_bytes(value))
    return raw_locator(path, cell)


def v3_netem_options(profile: dict[str, Any], directional_seed: int) -> dict[str, Any]:
    options: dict[str, Any] = {
        "limit": profile["queue_limit_packets"],
        "delay": {
            "delay": profile["one_way_delay_us"] / 1_000_000,
            "jitter": profile["jitter_per_direction_us"] / 1_000_000,
            "correlation": 0,
        },
        "seed": directional_seed,
    }
    if profile["loss"]["mode"] == "iid_random":
        options["loss-random"] = {
            "loss": profile["loss"]["probability_ppm"] / 1_000_000,
            "correlation": 0,
        }
    return options


def write_v3_qdisc_evidence(
    cell: Path,
    prefix: str,
    profile: dict[str, Any],
    directional_seed: int,
    *,
    immediate_packets: int = 0,
    post_packets: int = 1000,
) -> dict[str, dict[str, str]]:
    periodic = profile["loss"]["mode"] == "periodic_carrier_skb"

    def active_snapshot(packets: int) -> list[dict[str, Any]]:
        snapshot: list[dict[str, Any]] = [
            {
                "kind": "netem",
                "root": True,
                "options": v3_netem_options(profile, directional_seed),
                "bytes": packets * 1500,
                "packets": packets,
                "drops": 0,
                "overlimits": 0,
            }
        ]
        if periodic:
            snapshot.append({"kind": "clsact", "parent": "ffff:fff1", "packets": packets})
        return snapshot

    return {
        "pre": write_json_evidence(
            cell, f"{prefix}-qdisc-pre.json", [{"kind": "fq_codel", "root": True, "options": {}}]
        ),
        "immediate": write_json_evidence(
            cell, f"{prefix}-qdisc-immediate.json", active_snapshot(immediate_packets)
        ),
        "post": write_json_evidence(cell, f"{prefix}-qdisc-post.json", active_snapshot(post_packets)),
    }


def write_v3_link_evidence(cell: Path, prefix: str, interface: str) -> dict[str, dict[str, str]]:
    base = {"ifname": interface, "mtu": 1500, "operstate": "UP"}
    return {
        "pre": write_json_evidence(
            cell,
            f"{prefix}-link-pre.json",
            [{**base, "stats64": {"tx": {"bytes": 0, "packets": 0}}}],
        ),
        "post": write_json_evidence(
            cell,
            f"{prefix}-link-post.json",
            [{**base, "stats64": {"tx": {"bytes": 1_500_000, "packets": 1000}}}],
        ),
    }


def write_v3_offload_evidence(cell: Path, prefix: str) -> dict[str, dict[str, str]]:
    raw = b"generic-segmentation-offload: off\n"
    pre = cell / f"{prefix}-offload-pre.txt"
    post = cell / f"{prefix}-offload-post.txt"
    write_bytes(pre, raw)
    write_bytes(post, raw)
    return {"pre": raw_locator(pre, cell), "post": raw_locator(post, cell)}


def write_v3_periodic_bpf_evidence(
    fixture: Fixture,
    cell: Path,
    prefix: str,
    interface: str,
    profile: dict[str, Any],
    directional_seed: int,
    every_n: int,
    *,
    immediate_seen: int = 0,
    post_seen: int = 1000,
) -> dict[str, Any]:
    source_relative_path = "periodic-bpf/source.c"
    object_relative_path = "periodic-bpf/datapath_fixed_loss.bpf.c"
    source = cell / source_relative_path
    object_path = cell / object_relative_path
    stdout = cell / "periodic-bpf/compiler.stdout"
    stderr = cell / "periodic-bpf/compiler.stderr"
    compiler_version = cell / "periodic-bpf/compiler-version.txt"
    write_bytes(source, (fixture.source / acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH).read_bytes())
    write_bytes(object_path, b"\x7fELFsynthetic-periodic-bpf\n")
    write_bytes(stdout, b"synthetic periodic BPF compile\n")
    write_bytes(stderr, b"")
    write_bytes(compiler_version, b"clang version synthetic\n")
    terse_filter_record = {"protocol": "all", "pref": 49152, "kind": "bpf", "chain": 0}
    filter_record = {
        "protocol": "all",
        "pref": 49152,
        "kind": "bpf",
        "chain": 0,
        "options": {
            "handle": "0x1",
            "bpf_name": acceptance.PERIODIC_CARRIER_BPF_NAME,
            "direct-action": True,
            "not_in_hw": True,
            "prog": {"id": 1108, "name": "datapath_fixed_"},
        },
    }
    clsact_immediate = [{"kind": "clsact", "parent": "ffff:fff1", "options": {}, "packets": immediate_seen}]
    clsact_post = [{"kind": "clsact", "parent": "ffff:fff1", "options": {}, "packets": post_seen}]
    return {
        "source": raw_locator(source, cell),
        "object": raw_locator(object_path, cell),
        "compiler": {
            "argv": acceptance.expected_periodic_bpf_compiler_argv(
                source_relative_path, object_relative_path, every_n
            ),
            "stdout": raw_locator(stdout, cell),
            "stderr": raw_locator(stderr, cell),
            "exit_code": 0,
        },
        "compiler_version": raw_locator(compiler_version, cell),
        "clsact_apply_argv": acceptance.expected_periodic_bpf_clsact_apply_argv(interface),
        "filter_apply_argv": acceptance.expected_periodic_bpf_filter_apply_argv(
            interface, object_relative_path
        ),
        "qdisc": {
            "pre": write_json_evidence(
                cell,
                f"{prefix}-periodic-qdisc-pre.json",
                [
                    {
                        "kind": "netem",
                        "root": True,
                        "options": v3_netem_options(profile, directional_seed),
                        "bytes": 0,
                        "packets": 0,
                        "drops": 0,
                        "overlimits": 0,
                    }
                ],
            ),
            "immediate": write_json_evidence(
                cell, f"{prefix}-periodic-qdisc-immediate.json", clsact_immediate
            ),
            "post": write_json_evidence(cell, f"{prefix}-periodic-qdisc-post.json", clsact_post),
        },
        "filters": {
            "pre": write_json_evidence(cell, f"{prefix}-periodic-filter-pre.json", []),
            "immediate": write_json_evidence(
                cell, f"{prefix}-periodic-filter-immediate.json", [terse_filter_record, filter_record]
            ),
            "post": write_json_evidence(
                cell, f"{prefix}-periodic-filter-post.json", [terse_filter_record, filter_record]
            ),
        },
        "maps": {
            "immediate": write_json_evidence(
                cell,
                f"{prefix}-periodic-map-immediate.json",
                {"global_seen": immediate_seen, "global_dropped": immediate_seen // every_n},
            ),
            "post": write_json_evidence(
                cell,
                f"{prefix}-periodic-map-post.json",
                {"global_seen": post_seen, "global_dropped": post_seen // every_n},
            ),
        },
    }


def write_v3_non_target_qdisc(cell: Path, prefix: str) -> dict[str, dict[str, str]]:
    return {
        phase: write_json_evidence(
            cell,
            f"{prefix}-qdisc-{phase}.json",
            [{"kind": "fq_codel", "root": True, "options": {}}],
        )
        for phase in ("pre", "immediate", "post")
    }


def write_v3_underlay_impairment(
    fixture: Fixture,
    identity: acceptance.CellIdentity,
    *,
    immediate_seen: int = 0,
    post_seen: int = 1000,
) -> dict[str, Any]:
    cell = acceptance.cell_directory(fixture.artifacts, identity)
    profile = fixture.manifest["network_profile"]
    campaign_seed = fixture.manifest["netem_seed"]
    token = "012345678"
    targets: list[dict[str, Any]] = []
    for carrier_direction, suffix, role in (
        ("client_to_server", "b", "tunnel_server_interface"),
        ("server_to_client", "a", "tunnel_client_interface"),
    ):
        interface = f"dt{token}{suffix}"
        directional_seed = acceptance.derive_directional_netem_seed(
            campaign_seed, profile["id"], identity, carrier_direction
        )
        prefix = f"underlay-{carrier_direction}"
        target: dict[str, Any] = {
            "carrier_direction": carrier_direction,
            "namespace": f"dpa-t-{token}",
            "interface": interface,
            "interface_role": role,
            "tc_environment": acceptance.expected_netem_environment(cell, profile),
            "qdisc_apply_argv": acceptance.expected_netem_qdisc_apply_argv(
                cell, interface, profile, directional_seed
            ),
            "declared_loss": dict(profile["loss"]),
            "qdisc": write_v3_qdisc_evidence(
                cell,
                prefix,
                profile,
                directional_seed,
                immediate_packets=immediate_seen if profile["loss"]["mode"] == "periodic_carrier_skb" else 0,
                post_packets=post_seen if profile["loss"]["mode"] == "periodic_carrier_skb" else 1000,
            ),
            "link": write_v3_link_evidence(cell, prefix, interface),
            "offload": write_v3_offload_evidence(cell, prefix),
        }
        if profile["loss"]["mode"] == "periodic_carrier_skb":
            target["periodic_bpf"] = write_v3_periodic_bpf_evidence(
                fixture,
                cell,
                prefix,
                interface,
                profile,
                directional_seed,
                profile["loss"]["every_n"],
                immediate_seen=immediate_seen,
                post_seen=post_seen,
            )
        targets.append(target)

    non_targets = [
        {
            "role": role,
            "namespace": namespace,
            "interface": interface,
            "qdisc": write_v3_non_target_qdisc(cell, f"underlay-{role}"),
        }
        for role, namespace, interface in (
            ("client_control", f"dpa-c-{token}", f"dc{token}a"),
            ("server_control", f"dpa-s-{token}", f"ds{token}a"),
            ("client_overlay", f"dpa-c-{token}", "ppp0"),
            ("server_target_loopback", f"dpa-s-{token}", "lo"),
        )
    ]
    impairment: dict[str, Any] = {
        "schema": acceptance.UNDERLAY_IMPAIRMENT_SCHEMA_V3,
        "network_profile": profile,
        "campaign_seed": campaign_seed,
        "execution_index": 1,
        "targets": targets,
        "non_targets": non_targets,
    }
    if profile["jitter_per_direction_us"]:
        source = fixture.source / acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH
        raw = source.read_bytes()
        artifact = cell / "netem-tc-lib" / "uniform.dist"
        write_bytes(artifact, raw)
        impairment["uniform_distribution_source"] = {
            "source_path": acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
            "source_sha256": sha256(raw),
            "artifact": raw_locator(artifact, cell),
        }
    return impairment


def write_v3_cell(
    fixture: Fixture,
    identity: acceptance.CellIdentity,
    goodput_bps: int,
    *,
    immediate_seen: int = 0,
    post_seen: int = 1000,
) -> None:
    write_cell(fixture, identity, goodput_bps)
    cell = acceptance.cell_directory(fixture.artifacts, identity)
    launch = acceptance.read_json(cell / "launch.json")
    launch["schema"] = acceptance.LAUNCH_SCHEMA_V3
    launch["underlay_impairment"] = write_v3_underlay_impairment(
        fixture,
        identity,
        immediate_seen=immediate_seen,
        post_seen=post_seen,
    )
    acceptance.write_json(cell / "launch.json", launch)
    result = acceptance.read_json(cell / "result.json")
    result.update(
        {
            "schema": acceptance.RESULT_SCHEMA_V3,
            "network_profile": fixture.manifest["network_profile"],
            "netem_seed": fixture.manifest["netem_seed"],
        }
    )
    acceptance.write_json(cell / "result.json", result)


def populate_complete_v3_run(
    fixture: Fixture,
    goodput_overrides: dict[acceptance.CellIdentity, int] | None = None,
    *,
    immediate_seen: int = 0,
    post_seen: int = 1000,
) -> None:
    overrides = goodput_overrides or {}
    for identity in acceptance.expected_cells():
        default = 100 if identity.stack == "native" else 120
        write_v3_cell(
            fixture,
            identity,
            overrides.get(identity, default),
            immediate_seen=immediate_seen,
            post_seen=post_seen,
        )


@contextmanager
def complete_v3_run(
    *,
    profile_id: str = "rtt-75-j20",
    netem_seed: int = 73,
    goodput_overrides: dict[acceptance.CellIdentity, int] | None = None,
    immediate_seen: int = 0,
    post_seen: int = 1000,
) -> Iterator[Fixture]:
    with prepared_v3_fixture(profile_id, netem_seed) as fixture:
        populate_complete_v3_run(
            fixture,
            goodput_overrides,
            immediate_seen=immediate_seen,
            post_seen=post_seen,
        )
        acceptance.seal_run(fixture.artifacts)
        yield fixture


def populate_complete_run(
    fixture: Fixture, goodput_overrides: dict[acceptance.CellIdentity, int] | None = None
) -> None:
    overrides = goodput_overrides or {}
    for identity in acceptance.expected_cells():
        default = 100 if identity.stack == "native" else 120
        write_cell(fixture, identity, overrides.get(identity, default))


@contextmanager
def complete_run(
    *, goodput_overrides: dict[acceptance.CellIdentity, int] | None = None,
) -> Iterator[Fixture]:
    with prepared_fixture() as fixture:
        populate_complete_run(fixture, goodput_overrides)
        acceptance.seal_run(fixture.artifacts)
        yield fixture


def rewrite_direct_proof_for_stats(fixture: Fixture, identity: acceptance.CellIdentity, raw: bytes) -> None:
    cell = acceptance.cell_directory(fixture.artifacts, identity)
    write_bytes(cell / "stats.ndjson", raw)
    proof = acceptance.read_json(cell / "direct-proof.json")
    first_newline = raw.find(b"\n")
    if first_newline <= 0:
        raise assertion_error("synthetic raw stats lacks its first complete line")
    second_offset = first_newline + 1
    proof["raw_stats"]["sha256"] = sha256(raw)
    proof["raw_stats"]["measurement_start"] = acceptance.stats_boundary_locator(raw, 0)
    proof["raw_stats"]["measurement_end"] = acceptance.stats_boundary_locator(raw, second_offset)
    acceptance.write_json(cell / "direct-proof.json", proof)


def mutate_xtcp_stats(
    fixture: Fixture,
    identity: acceptance.CellIdentity,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    cell = acceptance.cell_directory(fixture.artifacts, identity)
    records = [json.loads(line) for line in (cell / "stats.ndjson").read_bytes().splitlines() if line]
    assert len(records) == 2
    mutate(records[0], records[1])
    raw = b"".join(json_bytes(record) + b"\n" for record in records)
    rewrite_direct_proof_for_stats(fixture, identity, raw)


def mutate_launch(
    fixture: Fixture,
    identity: acceptance.CellIdentity,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    path = acceptance.cell_directory(fixture.artifacts, identity) / "launch.json"
    document = acceptance.read_json(path)
    mutate(document)
    acceptance.write_json(path, document)


def rewrite_json_locator(cell: Path, locator: dict[str, str], value: Any) -> None:
    path = cell / locator["path"]
    write_bytes(path, json_bytes(value))
    locator["sha256"] = sha256(path.read_bytes())


def test_v3_network_profile_catalog_and_directional_seeds_are_closed() -> None:
    expected_ids = (
        "rtt-35-fixed",
        "rtt-35-j20",
        "rtt-55-fixed",
        "rtt-55-j20",
        "rtt-75-fixed",
        "rtt-75-j20",
        "rtt-90-fixed",
        "rtt-90-j20",
        "rtt-100-fixed",
        "rtt-100-j20",
        "rtt-75-j20-periodic-loss-0p1",
        "rtt-75-j20-periodic-loss-0p5",
        "rtt-75-j20-periodic-loss-1p0",
        "rtt-75-j20-iid-loss-0p1",
        "rtt-75-j20-iid-loss-0p5",
        "rtt-75-j20-iid-loss-1p0",
    )
    assert acceptance.NETWORK_PROFILE_IDS == expected_ids
    catalog = acceptance.network_profile_catalog()
    assert tuple(catalog) == expected_ids
    assert catalog["rtt-75-j20"]["one_way_delay_us"] == 37_500
    assert catalog["rtt-75-j20"]["jitter_per_direction_us"] == 10_000
    assert catalog["rtt-75-j20-iid-loss-0p5"]["loss"] == {
        "mode": "iid_random",
        "probability_ppm": 5000,
    }
    for profile_id, candidate in catalog.items():
        assert candidate["one_way_delay_us"] == candidate["target_rtt_ms"] * 500
        assert candidate["queue_limit_packets"] == 32768
        if "-j20" in profile_id:
            assert candidate["jitter_per_direction_us"] == 10_000
            assert candidate["jitter_distribution"] == "uniform"
        else:
            assert candidate["jitter_per_direction_us"] == 0
            assert candidate["jitter_distribution"] == "none"
    catalog["rtt-75-j20"]["loss"]["mode"] = "changed"
    assert acceptance.network_profile("rtt-75-j20")["loss"] == {"mode": "none"}
    try:
        acceptance.NETWORK_PROFILE_CATALOG["new"] = {}  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise assertion_error("closed network profile catalog was mutable")
    try:
        acceptance.NETWORK_PROFILE_CATALOG["rtt-75-j20"]["loss"]["mode"] = "changed"  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise assertion_error("nested network profile catalog data was mutable")

    profile = acceptance.network_profile("rtt-75-j20")
    for invalid in (
        {**profile, "unknown": True},
        {**profile, "one_way_delay_us": 1},
        {**profile, "loss": {"mode": "none", "unexpected": 1}},
    ):
        expect_error(lambda invalid=invalid: acceptance.validate_network_profile(invalid))
    for invalid_seed in (True, 0, acceptance.CAMPAIGN_SEED_MAXIMUM + 1, "73"):
        expect_error(lambda invalid_seed=invalid_seed: acceptance.validate_campaign_seed(invalid_seed))

    native = acceptance.CellIdentity(1, "native", 4, "ul")
    xtcp = acceptance.CellIdentity(1, "xtcp", 4, "ul")
    c2s = acceptance.derive_directional_netem_seed(73, profile["id"], native, "client_to_server")
    s2c = acceptance.derive_directional_netem_seed(73, profile["id"], native, "server_to_client")
    assert c2s == acceptance.derive_directional_netem_seed(73, profile["id"], xtcp, "client_to_server")
    assert s2c == acceptance.derive_directional_netem_seed(73, profile["id"], xtcp, "server_to_client")
    assert c2s != s2c
    assert acceptance.CAMPAIGN_SEED_MINIMUM <= c2s <= acceptance.CAMPAIGN_SEED_MAXIMUM
    assert acceptance.CAMPAIGN_SEED_MINIMUM <= s2c <= acceptance.CAMPAIGN_SEED_MAXIMUM


def test_v2_prepare_remains_literal_and_v3_requires_profile_seed_pair() -> None:
    with prepared_fixture() as fixture:
        assert fixture.manifest["schema"] == acceptance.ACCEPTANCE_SCHEMA_V2
        assert set(fixture.manifest) == {
            "schema",
            "kind",
            "run_uuid",
            "created_at_utc",
            "threshold",
            "expected_cells",
            "expected_pairs",
            "source",
            "candidate",
            "launch_environment_sha256",
        }
        assert "network_profile" not in fixture.manifest
        assert "netem_seed" not in fixture.manifest
    with prepared_v3_fixture() as fixture:
        assert fixture.manifest["schema"] == acceptance.ACCEPTANCE_SCHEMA_V3
        assert fixture.manifest["network_profile"] == acceptance.network_profile("rtt-75-j20")
        assert fixture.manifest["netem_seed"] == 73
        expect_error(
            lambda: acceptance.prepare_run(
                fixture.root / "profile-only", fixture.source, fixture.candidate, network_profile="rtt-75-j20"
            ),
            "specified together",
        )
        expect_error(
            lambda: acceptance.prepare_run(
                fixture.root / "seed-only", fixture.source, fixture.candidate, netem_seed=73
            ),
            "specified together",
        )

    with tempfile.TemporaryDirectory(prefix="datapath-cli-v3-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        candidate = root / "candidate"
        candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        for option in ("--network-profile", "--netem-seed"):
            command = [
                sys.executable,
                "-B",
                str(TOOL),
                "prepare",
                "--artifacts",
                str(root / option.removeprefix("--")),
                "--source-root",
                str(source),
                "--candidate",
                str(candidate),
                option,
                "rtt-75-j20" if option == "--network-profile" else "73",
            ]
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            assert completed.returncode == 2
            assert "specified together" in completed.stderr


def test_v3_source_inventory_is_versioned_and_required() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-source-versioned-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        v2_before = acceptance.build_source_inventory(source)
        assert v2_before["schema"] == acceptance.INVENTORY_SCHEMA_V2
        assert acceptance.source_allowlist() == acceptance.source_allowlist(2)
        assert acceptance.source_allowlist()["exact_files"] == list(acceptance.SOURCE_ALLOWLIST_EXACT_FILES)
        for invalid_version in (True, False, 2.0, "2", None):
            expect_error(lambda invalid_version=invalid_version: acceptance.source_allowlist(invalid_version))
        assert acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH not in {
            entry["path"] for entry in v2_before["entries"]
        }
        assert acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH not in {
            entry["path"] for entry in v2_before["entries"]
        }

        write_v3_source_inputs(source)
        v2_after = acceptance.build_source_inventory(source)
        v3 = acceptance.build_source_inventory(source, version=3)
        assert v2_after == v2_before
        assert v3["schema"] == acceptance.INVENTORY_SCHEMA_V3
        assert acceptance.source_allowlist(3)["exact_files"] == [
            *acceptance.SOURCE_ALLOWLIST_EXACT_FILES,
            acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
            acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH,
        ]
        assert {
            acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
            acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH,
        }.issubset({entry["path"] for entry in v3["entries"]})

        candidate = root / "candidate"
        candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        v2_artifacts = root / "v2-artifacts"
        acceptance.prepare_run(v2_artifacts, source, candidate)
        (source / acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH).write_bytes(b"changed after v2 prepare\n")
        acceptance.validate_prepared_run(v2_artifacts)

        for index, changed_path in enumerate(
            (acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH, acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH)
        ):
            v3_artifacts = root / f"v3-artifacts-{index}"
            acceptance.prepare_run(
                v3_artifacts,
                source,
                candidate,
                network_profile="rtt-75-j20",
                netem_seed=73,
            )
            (source / changed_path).write_bytes(f"changed after v3 prepare {index}\n".encode("ascii"))
            expect_error(
                lambda v3_artifacts=v3_artifacts: acceptance.validate_prepared_run(v3_artifacts),
                "source content identity drifted after run preparation",
            )

    for missing in (
        acceptance.UNIFORM_DISTRIBUTION_SOURCE_PATH,
        acceptance.PERIODIC_CARRIER_BPF_SOURCE_PATH,
    ):
        with tempfile.TemporaryDirectory(prefix="datapath-source-v3-required-") as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            write_source_fixture(source)
            write_v3_source_inputs(source)
            (source / missing).unlink()
            candidate = root / "candidate"
            candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
            candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
            expect_error(
                lambda: acceptance.prepare_run(
                    root / "artifacts",
                    source,
                    candidate,
                    network_profile="rtt-75-j20",
                    netem_seed=73,
                ),
                f"cannot stat source path {source / missing}",
            )


def test_v3_complete_profile_bound_run_passes_and_reports_binding() -> None:
    with complete_v3_run() as fixture:
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "pass", report
    assert report["schema"] == acceptance.ACCEPTANCE_SCHEMA_V3
    assert report["network_profile"] == acceptance.network_profile("rtt-75-j20")
    assert report["netem_seed"] == 73
    assert report["counts"] == {"pass": 18, "assessed_fail": 0, "not_assessed": 0}


def test_v3_result_profile_and_seed_mismatches_fail_closed() -> None:
    identity = acceptance.CellIdentity(1, "native", 1, "ul")
    for field, value, expected in (
        ("network_profile", acceptance.network_profile("rtt-75-fixed"), "result network profile does not match"),
        ("netem_seed", 74, "result netem seed does not match"),
    ):
        with complete_v3_run() as fixture:
            path = acceptance.cell_directory(fixture.artifacts, identity) / "result.json"
            result = acceptance.read_json(path)
            result[field] = value
            acceptance.write_json(path, result)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_v3_underlay_launch_evidence_is_strict() -> None:
    identity = acceptance.CellIdentity(1, "native", 1, "ul")

    def missing_target(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["targets"].pop()

    def duplicate_direction(launch: dict[str, Any]) -> None:
        impairment = launch["underlay_impairment"]
        impairment["targets"][1] = dict(impairment["targets"][0])

    def historical_direction_mapping(launch: dict[str, Any]) -> None:
        targets = launch["underlay_impairment"]["targets"]
        targets[0]["interface"] = "dt012345678a"
        targets[0]["interface_role"] = "tunnel_client_interface"
        targets[1]["interface"] = "dt012345678b"
        targets[1]["interface_role"] = "tunnel_server_interface"

    def altered_argv(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["targets"][0]["qdisc_apply_argv"][-1] = "1"

    def wrong_profile(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["network_profile"] = acceptance.network_profile("rtt-75-fixed")

    def wrong_seed(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["campaign_seed"] = 74

    cases: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (missing_target, "targets must contain exactly two"),
        (duplicate_direction, "targets do not bind both directions"),
        (historical_direction_mapping, "does not bind the generated tunnel carrier interface"),
        (altered_argv, "qdisc apply argv is not the exact"),
        (wrong_profile, "network profile does not match the manifest"),
        (wrong_seed, "campaign seed does not match the manifest"),
    )
    for mutate, expected in cases:
        with complete_v3_run() as fixture:
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_v3_netem_and_non_target_tampering_fail_closed() -> None:
    identity = acceptance.CellIdentity(1, "native", 1, "ul")

    def alter_option(launch: dict[str, Any], field: str, value: int) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["immediate"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["options"]["delay"][field] = value
        rewrite_json_locator(cell, locator, snapshot)

    def netem_seed(launch: dict[str, Any]) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["options"]["seed"] = 1
        rewrite_json_locator(cell, locator, snapshot)

    def delay(launch: dict[str, Any]) -> None:
        alter_option(launch, "delay", 0)

    def non_target_netem(launch: dict[str, Any]) -> None:
        non_target = launch["underlay_impairment"]["non_targets"][0]
        locator = non_target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["kind"] = "netem"
        rewrite_json_locator(cell, locator, snapshot)

    def server_sentinel_role(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["non_targets"][3]["role"] = "server_overlay"

    def server_sentinel_namespace(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["non_targets"][3]["namespace"] = "dpa-c-012345678"

    def server_sentinel_interface(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["non_targets"][3]["interface"] = "ppp1"

    current_fixture: Fixture
    cases: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (netem_seed, "seed does not match the derived directional seed"),
        (delay, "delay.delay does not match the closed network profile"),
        (non_target_netem, "contains forbidden netem"),
        (server_sentinel_role, "role is invalid or duplicated"),
        (server_sentinel_namespace, "namespace does not match the generated topology token"),
        (server_sentinel_interface, "interface does not match the generated topology contract"),
    )
    for mutate, expected in cases:
        with complete_v3_run(profile_id="rtt-75-j20") as fixture:
            current_fixture = fixture
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)

    def no_loss_drop(launch: dict[str, Any]) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["drops"] = 1
        rewrite_json_locator(cell, locator, snapshot)

    with complete_v3_run(profile_id="rtt-75-fixed") as fixture:
        current_fixture = fixture
        mutate_launch(fixture, identity, no_loss_drop)
        report = acceptance.verify_run(fixture.artifacts)
    assert_cell_not_assessed(report, identity, "no-loss netem counters must remain zero")

    def loss_overlimit(launch: dict[str, Any]) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["overlimits"] = 1
        rewrite_json_locator(cell, locator, snapshot)

    with complete_v3_run(profile_id="rtt-75-j20-iid-loss-0p1") as fixture:
        current_fixture = fixture
        mutate_launch(fixture, identity, loss_overlimit)
        report = acceptance.verify_run(fixture.artifacts)
    assert_cell_not_assessed(report, identity, "netem overlimits must remain zero")

    def periodic_root_drop(launch: dict[str, Any]) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["drops"] = 1
        rewrite_json_locator(cell, locator, snapshot)

    with prepared_v3_fixture(profile_id="rtt-75-j20-periodic-loss-0p1") as fixture:
        current_fixture = fixture
        populate_complete_v3_run(fixture)
        mutate_launch(fixture, identity, periodic_root_drop)
        acceptance.seal_run(fixture.artifacts)
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "pass", report

    def stalled_root_traffic(launch: dict[str, Any]) -> None:
        target = launch["underlay_impairment"]["targets"][0]
        locator = target["qdisc"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot[0]["bytes"] = 0
        snapshot[0]["packets"] = 0
        rewrite_json_locator(cell, locator, snapshot)

    with complete_v3_run(profile_id="rtt-75-fixed") as fixture:
        current_fixture = fixture
        mutate_launch(fixture, identity, stalled_root_traffic)
        report = acceptance.verify_run(fixture.artifacts)
    assert_cell_not_assessed(report, identity, "netem traffic counters must increase during formal traffic")


def test_v3_periodic_bpf_evidence_is_strict() -> None:
    identity = acceptance.CellIdentity(1, "native", 1, "ul")
    with complete_v3_run(
        profile_id="rtt-75-j20-periodic-loss-0p1", immediate_seen=999, post_seen=1999
    ) as fixture:
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "pass", report

    with prepared_v3_fixture(profile_id="rtt-75-j20-periodic-loss-0p1") as fixture:
        populate_complete_v3_run(fixture, immediate_seen=999, post_seen=1999)
        cell = acceptance.cell_directory(fixture.artifacts, identity)
        launch = acceptance.read_json(cell / "launch.json")
        evidence = launch["underlay_impairment"]["targets"][0]["periodic_bpf"]
        for phase in ("immediate", "post"):
            locator = evidence["filters"][phase]
            records = acceptance.read_json(cell / locator["path"])
            rewrite_json_locator(cell, locator, [records[1]])
        acceptance.write_json(cell / "launch.json", launch)
        acceptance.seal_run(fixture.artifacts)
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "pass", report

    def periodic(launch: dict[str, Any]) -> dict[str, Any]:
        return launch["underlay_impairment"]["targets"][0]["periodic_bpf"]

    def compiler_argv(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["argv"][0] = "cc"

    def wrong_every_n(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["argv"][5] = "-DPERIODIC_EVERY_N=999"

    def wrong_compiler_source_operand(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["argv"][7] = "periodic-bpf/alias-source.c"

    def wrong_compiler_object_operand(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["argv"][9] = "periodic-bpf/alias-object.bpf.c"

    def aliased_source_locator(launch: dict[str, Any]) -> None:
        periodic(launch)["source"]["path"] = "periodic-bpf/datapath_fixed_loss.bpf.c"

    def aliased_object_locator(launch: dict[str, Any]) -> None:
        periodic(launch)["object"]["path"] = "periodic-bpf/source.c"

    def aliased_stdout_locator(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["stdout"]["path"] = "periodic-bpf/compiler.stderr"

    def aliased_stderr_locator(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler"]["stderr"]["path"] = "periodic-bpf/compiler.stdout"

    def aliased_compiler_version_locator(launch: dict[str, Any]) -> None:
        periodic(launch)["compiler_version"]["path"] = "periodic-bpf/compiler.stdout"

    def source_bytes_not_bound_to_inventory(launch: dict[str, Any]) -> None:
        locator = periodic(launch)["source"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        path = cell / locator["path"]
        write_bytes(path, b"not the allowlisted periodic BPF source\n")
        locator["sha256"] = sha256(path.read_bytes())

    def clsact_apply_argv(launch: dict[str, Any]) -> None:
        periodic(launch)["clsact_apply_argv"][-1] = "ingress"

    def filter_apply_argv(launch: dict[str, Any]) -> None:
        periodic(launch)["filter_apply_argv"][-1] = "wrong-section"

    def qdisc_pre_contains_clsact(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["qdisc"]["pre"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot.append({"kind": "clsact", "parent": "ffff:fff1"})
        rewrite_json_locator(cell, locator, snapshot)

    def qdisc_immediate_has_extra_qdisc(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["qdisc"]["immediate"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        snapshot = acceptance.read_json(cell / locator["path"])
        snapshot.append({"kind": "fq_codel", "root": True, "options": {}})
        rewrite_json_locator(cell, locator, snapshot)

    def filter_pre_contains_bpf(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["filters"]["pre"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        filter_record = acceptance.read_json(cell / evidence["filters"]["immediate"]["path"])
        rewrite_json_locator(cell, locator, filter_record)

    def filter_program(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["filters"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        record = acceptance.read_json(cell / locator["path"])
        record[1]["options"]["bpf_name"] = "wrong"
        rewrite_json_locator(cell, locator, record)

    def malformed_terse_filter(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["filters"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        record = acceptance.read_json(cell / locator["path"])
        record[0]["pref"] = 49153
        rewrite_json_locator(cell, locator, record)

    def duplicate_detailed_filter(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["filters"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        record = acceptance.read_json(cell / locator["path"])
        record.append(dict(record[1]))
        rewrite_json_locator(cell, locator, record)

    def map_counters(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        locator = evidence["maps"]["post"]
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        counters = acceptance.read_json(cell / locator["path"])
        counters["global_dropped"] += 1
        rewrite_json_locator(cell, locator, counters)

    def too_short_periodic_traffic(launch: dict[str, Any]) -> None:
        evidence = periodic(launch)
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        post_locator = evidence["maps"]["post"]
        post_counters = acceptance.read_json(cell / post_locator["path"])
        post_counters["global_seen"] = 999
        post_counters["global_dropped"] = 0
        rewrite_json_locator(cell, post_locator, post_counters)
        clsact_locator = evidence["qdisc"]["post"]
        clsact = acceptance.read_json(cell / clsact_locator["path"])
        clsact[0]["packets"] = 999
        rewrite_json_locator(cell, clsact_locator, clsact)

    current_fixture: Fixture
    cases: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (compiler_argv, "compiler argv is not the exact"),
        (wrong_every_n, "compiler argv is not the exact"),
        (wrong_compiler_source_operand, "compiler argv is not the exact"),
        (wrong_compiler_object_operand, "compiler argv is not the exact"),
        (aliased_source_locator, "source must be the local periodic-bpf/source.c locator"),
        (aliased_object_locator, "object must be the local periodic-bpf/datapath_fixed_loss.bpf.c locator"),
        (aliased_stdout_locator, "compiler.stdout must be the local periodic-bpf/compiler.stdout locator"),
        (aliased_stderr_locator, "compiler.stderr must be the local periodic-bpf/compiler.stderr locator"),
        (
            aliased_compiler_version_locator,
            "compiler_version must be the local periodic-bpf/compiler-version.txt locator",
        ),
        (source_bytes_not_bound_to_inventory, "source does not match the v3 source inventory"),
        (clsact_apply_argv, "clsact_apply_argv is not the exact clsact command"),
        (filter_apply_argv, "filter_apply_argv is not the exact direct-action BPF command"),
        (qdisc_pre_contains_clsact, "must prove no clsact or BPF filter before installation"),
        (qdisc_immediate_has_extra_qdisc, "must contain exactly the installed clsact qdisc"),
        (filter_pre_contains_bpf, "filters pre must prove no BPF filter"),
        (filter_program, "does not bind the periodic direct-action"),
        (malformed_terse_filter, "BPF filter records have different preferences"),
        (duplicate_detailed_filter, "one detailed BPF filter"),
        (map_counters, "map counters do not prove global periodic"),
        (too_short_periodic_traffic, "at least PERIODIC_EVERY_N carrier SKBs"),
    )
    for mutate, expected in cases:
        with complete_v3_run(profile_id="rtt-75-j20-periodic-loss-0p1") as fixture:
            current_fixture = fixture
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_v3_uniform_distribution_evidence_is_strict() -> None:
    identity = acceptance.CellIdentity(1, "native", 1, "ul")

    def wrong_source_hash(launch: dict[str, Any]) -> None:
        launch["underlay_impairment"]["uniform_distribution_source"]["source_sha256"] = "0" * 64

    def missing_uniform_evidence(launch: dict[str, Any]) -> None:
        del launch["underlay_impairment"]["uniform_distribution_source"]

    for mutate, expected in (
        (wrong_source_hash, "source SHA-256 does not match the v3 source inventory"),
        (missing_uniform_evidence, "incomplete or unexpected v3 shape"),
    ):
        with complete_v3_run(profile_id="rtt-75-j20") as fixture:
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_fixed_plan_threshold_and_environment_contract() -> None:
    cells = acceptance.expected_cells()
    pairs = acceptance.expected_pairs()
    assert len(cells) == 36
    assert len(set(cells)) == 36
    assert len(pairs) == 18
    assert len(set(pairs)) == 18
    assert cells[0] == acceptance.CellIdentity(1, "native", 1, "ul")
    assert cells[-1] == acceptance.CellIdentity(3, "xtcp", 16, "dl")
    assert acceptance.parse_threshold("1.20") == Decimal("1.20")
    assert acceptance.parse_threshold("1.200") == Decimal("1.200")
    for value in ("1.19", 1.19, Decimal("1.19"), True, "NaN", "Infinity", float("nan"), float("inf")):
        expect_error(lambda value=value: acceptance.parse_threshold(value))

    with prepared_fixture() as fixture:
        native = acceptance.CellIdentity(1, "native", 1, "ul")
        xtcp = acceptance.CellIdentity(1, "xtcp", 1, "ul")
        native_environment = acceptance.expected_cell_environment(
            fixture.artifacts, native, fixture.manifest["run_uuid"]
        )
        xtcp_environment = acceptance.expected_cell_environment(
            fixture.artifacts, xtcp, fixture.manifest["run_uuid"]
        )
    assert set(native_environment) == {
        *acceptance.MINIMAL_BASE_ENVIRONMENT,
        "OPENPPP2_TAP_GSO_MERGE",
        "OPENPPP2_DATAPATH_ACCEPTANCE_RUN_UUID",
        "OPENPPP2_DATAPATH_ACCEPTANCE_CELL_ID",
        "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_REQUEST",
        "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_ACK",
    }
    assert set(xtcp_environment) == set(native_environment) | set(acceptance.XTCP_CLIENT_ENVIRONMENT)
    assert all(name not in native_environment for name in acceptance.XTCP_CLIENT_ENVIRONMENT)
    assert xtcp_environment["OPENPPP2_XTCP_MEMORY_BRIDGE"] == "1"
    assert xtcp_environment["OPENPPP2_XTCP_CC"] == "kcc"
    assert all(name not in xtcp_environment for name in acceptance.FORBIDDEN_ENVIRONMENT_NAMES)


def test_source_inventory_is_allowlisted_and_sensitive_preflight_is_read_free() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-source-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        credential = source / "credential-material.txt"
        original_open = Path.open

        def reject_root_credential(self: Path, *arguments: Any, **kwargs: Any) -> Any:
            if self == credential:
                raise AssertionError("root credential material was read")
            return original_open(self, *arguments, **kwargs)

        with patch.object(Path, "open", reject_root_credential):
            inventory = acceptance.build_source_inventory(source)
        paths = {entry["path"] for entry in inventory["entries"]}
        assert "credential-material.txt" not in paths
        assert inventory["allowlist"] == acceptance.source_allowlist()
        assert all(not path.startswith("build") for path in paths)

        sensitive = source / "ppp" / "secret.pem"
        sensitive.write_text("must-not-be-read\n", encoding="utf-8")

        def reject_all_opens(self: Path, *arguments: Any, **kwargs: Any) -> Any:
            raise AssertionError(f"source content was read before sensitive preflight rejection: {self}")

        with patch.object(Path, "open", reject_all_opens):
            error = expect_error(lambda: acceptance.build_source_inventory(source))
        assert "sensitive source path" in str(error)


def test_source_identity_rejects_root_and_allowlisted_component_symlinks() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-source-symlink-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        source_link = root / "source-link"
        source_link.symlink_to(source, target_is_directory=True)
        expect_error(lambda: acceptance.build_source_inventory(source_link), "symlink is forbidden in source root")

    with tempfile.TemporaryDirectory(prefix="datapath-source-symlink-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        tools_target = root / "tools-target"
        (source / "tools").rename(tools_target)
        (source / "tools").symlink_to(tools_target, target_is_directory=True)
        expect_error(
            lambda: acceptance.build_source_inventory(source),
            "symlink is forbidden in source identity: tools/compat/server.json",
        )

    with tempfile.TemporaryDirectory(prefix="datapath-source-symlink-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        ppp_target = root / "ppp-target"
        (source / "ppp").rename(ppp_target)
        (source / "ppp").symlink_to(ppp_target, target_is_directory=True)
        expect_error(lambda: acceptance.build_source_inventory(source), "symlink is forbidden in source identity: ppp")


def test_valid_complete_run_passes_and_ndi_rejected_counters_do_not_invalidate_it() -> None:
    identity = acceptance.CellIdentity(1, "xtcp", 1, "ul")
    with complete_run() as fixture:
        raw = (acceptance.cell_directory(fixture.artifacts, identity) / "stats.ndjson").read_bytes()
        records = [json.loads(line) for line in raw.splitlines()]
        assert records[0]["xtcp"]["ndi_gso_rejected"] > 0
        assert records[1]["xtcp"]["ndi_gso_rejected"] > 0
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "pass", report
    assert report["schema"] == acceptance.ACCEPTANCE_SCHEMA_V2
    assert "network_profile" not in report
    assert "netem_seed" not in report
    assert report["counts"] == {"pass": 18, "assessed_fail": 0, "not_assessed": 0}
    assert all(Decimal(pair["ratio"]) == Decimal("1.2") for pair in report["pairs"])
    assert all(cell["evidence_valid"] for cell in report["cells"])
    xtcp_cell = cell_report(report, identity)
    assert xtcp_cell["direct_admission_evidence"]["direct_bridge_starts"] >= 1


def test_low_goodput_is_assessed_failure_and_still_seals() -> None:
    native = acceptance.CellIdentity(1, "native", 1, "ul")
    xtcp = acceptance.CellIdentity(1, "xtcp", 1, "ul")
    with complete_run(goodput_overrides={native: 100, xtcp: 119}) as fixture:
        report = acceptance.verify_run(fixture.artifacts)
    selected = pair_report(report, pair_for(native))
    assert report["status"] == "assessed_fail", report
    assert selected["status"] == "assessed_fail", selected
    assert Decimal(selected["ratio"]) == Decimal("1.19")
    assert not selected["evidence_errors"]


def test_launch_requires_exact_environments_and_forbidden_knobs() -> None:
    native = acceptance.CellIdentity(1, "native", 1, "dl")
    xtcp = acceptance.CellIdentity(1, "xtcp", 1, "dl")
    cases: tuple[tuple[str, acceptance.CellIdentity, Callable[[dict[str, Any]], None], str], ...] = (
        (
            "native XTCP environment",
            native,
            lambda launch: launch["environment"].update({"OPENPPP2_XTCP_MEMORY_BRIDGE": "1"}),
            "exact clean environment",
        ),
        (
            "unexpected ambient environment",
            xtcp,
            lambda launch: launch["environment"].update({"HOME": "/root"}),
            "exact clean environment",
        ),
        (
            "forbidden NDI knob",
            xtcp,
            lambda launch: launch["environment"].update({"OPENPPP2_XTCP_NDI_TSO_TX": "1"}),
            "OPENPPP2_XTCP_NDI_TSO_TX",
        ),
        (
            "forbidden perf knob",
            xtcp,
            lambda launch: launch["observed_process"]["environment"].update(
                {"OPENPPP2_DATAPATH_PERF_JSON": "bad"}
            ),
            "OPENPPP2_DATAPATH_PERF_JSON",
        ),
    )
    for _name, identity, mutate, expected in cases:
        with complete_run() as fixture:
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_launch_validates_candidate_config_process_cpu_qdisc_and_queue_readbacks() -> None:
    identity = acceptance.CellIdentity(1, "native", 4, "ul")

    def candidate_mutation(launch: dict[str, Any]) -> None:
        launch["candidate"]["sha256"] = "0" * 64

    def config_digest_mutation(launch: dict[str, Any]) -> None:
        launch["config"]["sha256"] = "0" * 64

    def server_port_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        config = cell / launch["server_config"]["path"]
        document = acceptance.read_json(config)
        document["tcp"]["listen"]["port"] = 20001
        acceptance.write_json(config, document)
        launch["server_config"]["sha256"] = sha256(config.read_bytes())

    def client_server_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        config = cell / launch["config"]["path"]
        document = acceptance.read_json(config)
        document["client"]["server"] = "ppp://198.18.0.1:20001/"
        acceptance.write_json(config, document)
        launch["config"]["sha256"] = sha256(config.read_bytes())

    def client_mappings_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        config = cell / launch["config"]["path"]
        document = acceptance.read_json(config)
        document["client"]["mappings"] = []
        acceptance.write_json(config, document)
        launch["config"]["sha256"] = sha256(config.read_bytes())

    def process_mutation(launch: dict[str, Any]) -> None:
        launch["observed_process"]["pid"] = 9999

    def cpu_mutation(launch: dict[str, Any]) -> None:
        launch["cpu"]["migration_delta"] = 1

    def qdisc_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        qdisc = cell / launch["qdisc"][0]["path"]
        write_bytes(qdisc, b"qdisc netem 1: root delay 1ms\n")
        launch["qdisc"][0]["sha256"] = sha256(qdisc.read_bytes())

    def queue_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        rps_xps = cell / launch["rps_xps"]["path"]
        acceptance.write_json(rps_xps, {"reads": [{"kind": "rps", "path": "x", "value": "1"}]})
        launch["rps_xps"]["sha256"] = sha256(rps_xps.read_bytes())

    def target_route_mutation(launch: dict[str, Any]) -> None:
        cell = acceptance.cell_directory(current_fixture.artifacts, identity)
        route = cell / launch["tun"]["route"]["path"]
        write_bytes(route, b"127.0.0.2 dev ppp0 src 10.0.0.2\n")
        launch["tun"]["route"]["sha256"] = sha256(route.read_bytes())

    # Fixture-aware mutators remain local so every run is isolated.
    current_fixture: Fixture
    cases: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (candidate_mutation, "candidate identity"),
        (config_digest_mutation, "client config SHA-256"),
        (server_port_mutation, "server config tcp.listen.port must be integer 20000"),
        (client_server_mutation, "client config client.server must be ppp://198.18.0.1:20000/"),
        (client_mappings_mutation, "client config client.mappings is forbidden"),
        (process_mutation, "retained boundary acknowledgement process identity"),
        (cpu_mutation, "migration delta"),
        (qdisc_mutation, "contains netem"),
        (queue_mutation, "RPS/XPS readback must contain"),
        (target_route_mutation, "TUN target route does not resolve"),
    )
    for mutate, expected in cases:
        with complete_run() as fixture:
            current_fixture = fixture
            mutate_launch(fixture, identity, mutate)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_raw_stats_direct_proof_is_derived_from_immutable_raw_lines() -> None:
    identity = acceptance.CellIdentity(1, "xtcp", 4, "ul")

    def break_full_hash(fixture: Fixture) -> None:
        path = acceptance.cell_directory(fixture.artifacts, identity) / "stats.ndjson"
        write_bytes(path, path.read_bytes() + b" ")

    def break_offset(fixture: Fixture) -> None:
        path = acceptance.cell_directory(fixture.artifacts, identity) / "direct-proof.json"
        proof = acceptance.read_json(path)
        proof["raw_stats"]["measurement_start"]["byte_offset"] = 1
        acceptance.write_json(path, proof)

    def break_line_hash(fixture: Fixture) -> None:
        path = acceptance.cell_directory(fixture.artifacts, identity) / "direct-proof.json"
        proof = acceptance.read_json(path)
        proof["raw_stats"]["measurement_end"]["line_sha256"] = "0" * 64
        acceptance.write_json(path, proof)

    def duplicate_matching_boundary(fixture: Fixture) -> None:
        cell = acceptance.cell_directory(fixture.artifacts, identity)
        raw = (cell / "stats.ndjson").read_bytes()
        first_line = raw.splitlines(keepends=True)[0]
        rewrite_direct_proof_for_stats(fixture, identity, raw + first_line)

    def boundary_mismatch(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, _end: start["acceptance_boundary"].update({"cell_id": "wrong-cell"}),
        )

    def process_pid_alias(fixture: Fixture) -> None:
        def mutate(start: dict[str, Any], end: dict[str, Any]) -> None:
            for record in (start, end):
                boundary = record["acceptance_boundary"]
                boundary["pid"] = boundary.pop("process_pid")

        mutate_xtcp_stats(fixture, identity, mutate)

    def extra_boundary_field(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, _end: start["acceptance_boundary"].update({"unexpected": 1}),
        )

    def missing_boundary_timestamp(fixture: Fixture) -> None:
        def mutate(start: dict[str, Any], _end: dict[str, Any]) -> None:
            del start["acceptance_boundary"]["monotonic_ms"]

        mutate_xtcp_stats(fixture, identity, mutate)

    def boundary_timestamp_mismatch(fixture: Fixture) -> None:
        def mutate(start: dict[str, Any], _end: dict[str, Any]) -> None:
            boundary = start["acceptance_boundary"]
            boundary["monotonic_ms"] += 1

        mutate_xtcp_stats(fixture, identity, mutate)

    def pid_mismatch(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, end: (
                start["acceptance_boundary"].update({"process_pid": 7}),
                end["acceptance_boundary"].update({"process_pid": 7}),
            ),
        )

    def start_ticks_mismatch(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, end: (
                start["acceptance_boundary"].update({"process_start_ticks": 778}),
                end["acceptance_boundary"].update({"process_start_ticks": 778}),
            ),
        )

    def runtime_mismatch(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda _start, end: (
                end["xtcp"].update({"runtime_instance_id": 101}),
                end["acceptance_boundary"].update({"xtcp_runtime_instance_id": 101}),
            ),
        )

    def gso_disabled(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, _end: start["tap_linux"].update({"gso_merge_active": False}),
        )

    def ndi_enabled(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda _start, end: end["xtcp"].update({"ndi_gso_enabled": True}),
        )

    def too_few_starts(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, end: end["xtcp"].update(
                {"direct_bridge_starts": start["xtcp"]["direct_bridge_starts"] + identity.parallel_flows - 1}
            ),
        )

    def fallback(fixture: Fixture) -> None:
        mutate_xtcp_stats(fixture, identity, lambda _start, end: end["xtcp"].update({"direct_bridge_fallbacks": 1}))

    def connector(fixture: Fixture) -> None:
        mutate_xtcp_stats(fixture, identity, lambda _start, end: end["xtcp"].update({"connector_read_bytes": 1}))

    def insufficient_admission(fixture: Fixture) -> None:
        mutate_xtcp_stats(
            fixture,
            identity,
            lambda start, end: end["xtcp"].update(
                {"direct_upload_accepted_bytes": start["xtcp"]["direct_upload_accepted_bytes"]}
            ),
        )

    cases: tuple[tuple[Callable[[Fixture], None], str], ...] = (
        (break_full_hash, "raw stats SHA-256"),
        (break_offset, "byte_offset"),
        (break_line_hash, "line_sha256"),
        (duplicate_matching_boundary, "exactly one measurement_start boundary line"),
        (boundary_mismatch, "exactly one measurement_start boundary line"),
        (process_pid_alias, "exactly the nine production boundary fields"),
        (extra_boundary_field, "exactly the nine production boundary fields"),
        (missing_boundary_timestamp, "exactly the nine production boundary fields"),
        (boundary_timestamp_mismatch, "monotonic_ms does not match root ppp-stats monotonic_ms"),
        (pid_mismatch, "process identity"),
        (start_ticks_mismatch, "process identity"),
        (runtime_mismatch, "runtime instance ID changed"),
        (gso_disabled, "TAP GSO"),
        (ndi_enabled, "ndi_gso_enabled"),
        (too_few_starts, "direct_bridge_starts"),
        (fallback, "direct_bridge_fallbacks"),
        (connector, "connector byte counters"),
        (insufficient_admission, "accepted_bytes"),
    )
    for mutate, expected in cases:
        with complete_run() as fixture:
            mutate(fixture)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_final_acknowledgement_must_equal_selected_raw_end_boundary() -> None:
    identity = acceptance.CellIdentity(1, "xtcp", 4, "ul")
    with complete_run() as fixture:
        acknowledgement_path = acceptance.cell_directory(fixture.artifacts, identity) / "boundary-ack.json"
        acknowledgement = acceptance.read_json(acknowledgement_path)
        acknowledgement["monotonic_ms"] += 1
        acceptance.write_json(acknowledgement_path, acknowledgement)
        report = acceptance.verify_run(fixture.artifacts)
    assert_cell_not_assessed(
        report,
        identity,
        "retained final boundary acknowledgement does not equal selected raw measurement_end acceptance_boundary",
    )


def test_scheduler_migration_counter_accepts_kernel_spelling_and_rejects_ambiguity() -> None:
    adapter = __import__("datapath_linux_strict_adapter")
    kernel_counter = b"se.nr_migrations                             : 7\n"
    legacy_counter = b"nr_migrations                                : 8\n"
    ambiguous = kernel_counter + legacy_counter
    assert acceptance._sched_migrations(kernel_counter, "kernel scheduler") == 7
    assert acceptance._sched_migrations(legacy_counter, "legacy scheduler") == 8
    assert adapter._read_migrations(kernel_counter, "kernel scheduler") == 7
    assert adapter._read_migrations(legacy_counter, "legacy scheduler") == 8
    expect_error(
        lambda: acceptance._sched_migrations(ambiguous, "ambiguous scheduler"),
        "exactly one nr_migrations counter",
    )
    try:
        adapter._read_migrations(ambiguous, "ambiguous scheduler")
    except adapter.AdapterError as error:
        assert "exactly one nr_migrations counter" in str(error), error
    else:
        raise assertion_error("expected AdapterError for ambiguous scheduler counter")


def test_adapter_build_cell_configs_uses_fixed_root_contract() -> None:
    adapter = __import__("datapath_linux_strict_adapter")
    with tempfile.TemporaryDirectory(prefix="datapath-adapter-config-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        cell = root / "cell"
        write_source_fixture(source)
        cell.mkdir()
        server_path, client_path = adapter._build_cell_configs(cell, source)
        server = acceptance.read_json(server_path)
        client = acceptance.read_json(client_path)
    assert server["concurrent"] == 1
    assert server["tcp"]["listen"]["port"] == 20000
    assert client["concurrent"] == 1
    assert client["client"]["server"] == "ppp://198.18.0.1:20000/"
    assert "mappings" not in client["client"]


def test_result_coverage_and_raw_iperf_validation_are_fail_closed() -> None:
    missing = acceptance.CellIdentity(1, "native", 1, "ul")
    duplicate = acceptance.CellIdentity(1, "xtcp", 1, "dl")
    with complete_run() as fixture:
        (acceptance.cell_directory(fixture.artifacts, missing) / "result.json").unlink()
        record = acceptance.read_json(acceptance.cell_directory(fixture.artifacts, duplicate) / "result.json")
        acceptance.write_json(fixture.artifacts / "noncanonical" / "result.json", record)
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "not_assessed"
    assert missing.as_dict() in report["coverage"]["missing"]
    assert report["coverage"]["duplicates"] == [
        {
            "identity": duplicate.as_dict(),
            "paths": ["noncanonical/result.json", f"{duplicate.relative_directory()}/result.json"],
        }
    ]

    identity = acceptance.CellIdentity(1, "native", 1, "dl")
    with complete_run() as fixture:
        cell = acceptance.cell_directory(fixture.artifacts, identity)
        raw = acceptance.read_json(cell / identity.iperf_filename())
        raw["end"]["sum_received"]["bytes"] = True
        raw_bytes = json_bytes(raw)
        iperf_path = cell / identity.iperf_filename()
        write_bytes(iperf_path, raw_bytes)
        result = acceptance.read_json(cell / "result.json")
        result["iperf"]["sha256"] = sha256(raw_bytes)
        acceptance.write_json(cell / "result.json", result)
        report = acceptance.verify_run(fixture.artifacts)
    assert_cell_not_assessed(report, identity, "bytes must be a non-boolean integer")

    for field, value, expected in (
        ("connecting_to", {"host": "127.0.0.2", "port": acceptance.FORMAL_TARGET_PORT}, "start.connecting_to must be"),
        ("connected", [{"remote_host": "127.0.0.2", "remote_port": acceptance.FORMAL_TARGET_PORT}], "start.connected[0] must target"),
    ):
        with complete_run() as fixture:
            cell = acceptance.cell_directory(fixture.artifacts, identity)
            raw = acceptance.read_json(cell / identity.iperf_filename())
            raw["start"][field] = value
            raw_bytes = json_bytes(raw)
            iperf_path = cell / identity.iperf_filename()
            write_bytes(iperf_path, raw_bytes)
            result = acceptance.read_json(cell / "result.json")
            result["iperf"]["sha256"] = sha256(raw_bytes)
            acceptance.write_json(cell / "result.json", result)
            report = acceptance.verify_run(fixture.artifacts)
        assert_cell_not_assessed(report, identity, expected)


def test_seal_rejects_incomplete_or_malformed_normal_evidence() -> None:
    with prepared_fixture() as fixture:
        error = expect_error(lambda: acceptance.seal_run(fixture.artifacts))
    assert "cannot seal incomplete or malformed normal evidence" in str(error)

    identity = acceptance.CellIdentity(1, "native", 1, "ul")
    with prepared_fixture() as fixture:
        populate_complete_run(fixture)
        config = acceptance.cell_directory(fixture.artifacts, identity) / "client-config.json"
        acceptance.write_json(config, {"concurrent": 2})
        error = expect_error(lambda: acceptance.seal_run(fixture.artifacts))
    assert "cannot seal incomplete or malformed normal evidence" in str(error)


def test_source_candidate_and_sealed_artifact_drift_are_global_failures() -> None:
    with complete_run() as fixture:
        (fixture.source / "CMakeLists.txt").write_text("changed\n", encoding="utf-8")
        fixture.candidate.write_bytes(b"#!/bin/sh\nexit 1\n")
        (fixture.artifacts / "unsealed-extra.txt").write_text("drift\n", encoding="utf-8")
        report = acceptance.verify_run(fixture.artifacts)
    assert report["status"] == "not_assessed"
    assert_contains(report["global_evidence_errors"], "source content identity drifted")
    assert_contains(report["global_evidence_errors"], "candidate content identity drifted")
    assert_contains(report["global_evidence_errors"], "run artifact content identity drifted")


def test_prepare_rejects_reuse_relative_or_source_bin_candidates() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-prepare-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        candidate = root / "candidate"
        candidate.write_bytes(b"candidate\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        reused = root / "reused"
        reused.mkdir()
        expect_error(lambda: acceptance.prepare_run(reused, source, candidate), "cannot be reused")
        expect_error(lambda: acceptance.collect_candidate_identity(Path("relative-candidate"), source), "absolute")
        source_candidate = source / "bin" / "ppp"
        source_candidate.parent.mkdir()
        source_candidate.write_bytes(b"candidate\n")
        source_candidate.chmod(source_candidate.stat().st_mode | stat.S_IXUSR)
        expect_error(
            lambda: acceptance.prepare_run(root / "fresh", source, source_candidate), "source bin directory"
        )


def test_freeze_creates_a_fresh_sealed_nonpass_artifact_and_malformed_freezes_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-freeze-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        candidate = root / "candidate"
        candidate.write_bytes(b"candidate\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        log = root / "runner.log"
        log.write_text("unsupported kernel queue control\n", encoding="utf-8")
        artifacts = root / "frozen"
        frozen = acceptance.freeze_run(
            artifacts,
            source,
            status="assessed_fail",
            stage="capability-check",
            reason="queue control unavailable",
            command=["strict-adapter", "--candidate", str(candidate)],
            log=log,
            candidate=candidate,
        )
        assert frozen["status"] == "assessed_fail"
        assert (artifacts / "frozen-log.txt").read_bytes() == log.read_bytes()
        report = acceptance.verify_run(artifacts)
        assert report["status"] == "assessed_fail", report
        assert report["frozen"] is True
        expect_error(
            lambda: acceptance.freeze_run(
                artifacts,
                source,
                status="not_assessed",
                stage="retry",
                reason="must not reuse",
                command=["strict-adapter"],
                log=log,
            ),
            "cannot be reused",
        )
        freeze_path = artifacts / "freeze.json"
        malformed = acceptance.read_json(freeze_path)
        malformed["status"] = "pass"
        acceptance.write_json(freeze_path, malformed)
        report = acceptance.verify_run(artifacts)
        assert report["status"] == "not_assessed", report
        assert_contains(report["global_evidence_errors"], "freeze status")


def test_adapter_rejects_symlink_root_and_creates_no_direct_iperf_path() -> None:
    adapter = __import__("datapath_linux_strict_adapter")

    with tempfile.TemporaryDirectory(prefix="datapath-adapter-root-v2-") as temporary_directory:
        root = Path(temporary_directory)
        source = root / "source"
        write_source_fixture(source)
        candidate = root / "candidate"
        candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
        candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
        artifacts = root / "artifacts"
        acceptance.prepare_run(artifacts, source, candidate)
        artifacts_link = root / "artifacts-link"
        artifacts_link.symlink_to(artifacts, target_is_directory=True)
        with patch.object(adapter, "_require_host_capabilities"):
            expect_error(
                lambda: adapter.run_adapter(
                    artifacts_link,
                    artifacts_link / "acceptance-manifest.json",
                    candidate,
                ),
                "artifact root must not be a symlink",
            )

    calls: list[tuple[str, str | None, list[str]]] = []

    def record_host(arguments: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(("host", None, list(arguments)))
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    def record_namespace(
        namespace: str, arguments: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(("namespace", namespace, list(arguments)))
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    names = adapter._namespace_names("00000000-0000-0000-0000-000000000001", 1)
    created: list[str] = []
    root_veths: list[str] = []
    with patch.object(adapter, "_run", record_host), patch.object(adapter, "_run_in_namespace", record_namespace):
        adapter._create_topology(names, created, root_veths)

    assert set(names) == {
        "client_namespace",
        "server_namespace",
        "tunnel_namespace",
        "client_interface",
        "tunnel_client_interface",
        "server_interface",
        "tunnel_server_interface",
    }
    assert created == [names["client_namespace"], names["server_namespace"], names["tunnel_namespace"]]
    veth_commands = [arguments for scope, _namespace, arguments in calls if scope == "host" and arguments[:3] == ["ip", "link", "add"]]
    assert len(veth_commands) == 2
    assert all(command[4:6] == ["type", "veth"] for command in veth_commands)
    target_address_calls = [
        (namespace, arguments)
        for scope, namespace, arguments in calls
        if f"{acceptance.FORMAL_TARGET_HOST}/32" in arguments
    ]
    assert target_address_calls == [
        (
            names["server_namespace"],
            ["ip", "addr", "add", f"{acceptance.FORMAL_TARGET_HOST}/32", "dev", "lo"],
        )
    ]
    assert not any(
        scope == "namespace"
        and namespace == names["client_namespace"]
        and arguments[:3] == ["ip", "route", "replace"]
        and f"{acceptance.FORMAL_TARGET_HOST}/32" in arguments
        for scope, namespace, arguments in calls
    )


def test_adapter_iperf_uses_only_the_formal_target() -> None:
    adapter = __import__("datapath_linux_strict_adapter")
    identity = acceptance.CellIdentity(1, "native", 4, "ul")
    observed: list[tuple[str, list[str]]] = []
    document, raw = raw_iperf(identity, 100)

    def record_namespace(
        namespace: str, arguments: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append((namespace, list(arguments)))
        return subprocess.CompletedProcess(arguments, 0, raw, b"")

    with tempfile.TemporaryDirectory(prefix="datapath-adapter-iperf-v2-") as temporary_directory:
        cell = Path(temporary_directory)
        with patch.object(adapter, "_run_in_namespace", record_namespace):
            parsed, captured = adapter._run_iperf(cell, {"client_namespace": "client-ns"}, identity, 3)

    assert parsed == document
    assert captured == raw
    assert len(observed) == 1
    command = observed[0][1]
    assert command[0:3] == ["env", "-i", "LANG=C"]
    iperf_index = command.index("iperf3")
    assert command[iperf_index : iperf_index + 6] == [
        "iperf3",
        "-4",
        "-c",
        acceptance.FORMAL_TARGET_HOST,
        "-p",
        str(acceptance.FORMAL_TARGET_PORT),
    ]
    assert not any(argument.startswith("127.") for argument in command)


def test_adapter_discovers_exactly_one_point_to_point_tun() -> None:
    adapter = __import__("datapath_linux_strict_adapter")

    def one_tun(
        _namespace: str, _arguments: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            _arguments,
            0,
            b"1: lo: <LOOPBACK,UP> mtu 65536\n7: ppp0: <POINTOPOINT,UP> mtu 1500\n",
            b"",
        )

    with patch.object(adapter, "_run_in_namespace", one_tun):
        assert adapter._client_tun_device("client-ns", timeout_seconds=0.1) == "ppp0"

    def ambiguous_tuns(
        _namespace: str, _arguments: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            _arguments,
            0,
            b"7: ppp0: <POINTOPOINT,UP> mtu 1500\n8: ppp1: <POINTOPOINT,UP> mtu 1500\n",
            b"",
        )

    with patch.object(adapter, "_run_in_namespace", ambiguous_tuns):
        try:
            adapter._client_tun_device("client-ns", timeout_seconds=0.1)
        except adapter.AdapterError as error:
            assert "multiple point-to-point TUN interfaces" in str(error), error
        else:
            raise assertion_error("expected AdapterError for ambiguous TUN discovery")


def test_adapter_installs_target_route_and_retains_evidence() -> None:
    adapter = __import__("datapath_linux_strict_adapter")
    calls: list[list[str]] = []

    def route_evidence(
        _namespace: str, arguments: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(list(arguments))
        if arguments[:3] == ["ip", "route", "get"]:
            return subprocess.CompletedProcess(
                arguments,
                0,
                f"{acceptance.FORMAL_TARGET_HOST} dev ppp0 src 10.0.0.2\n".encode("ascii"),
                b"",
            )
        if arguments[:4] == ["ip", "-d", "link", "show"]:
            return subprocess.CompletedProcess(
                arguments,
                0,
                b"7: ppp0: <POINTOPOINT,UP,LOWER_UP> mtu 1500\n",
                b"",
            )
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    with tempfile.TemporaryDirectory(prefix="datapath-adapter-route-v2-") as temporary_directory:
        cell = Path(temporary_directory)
        with patch.object(adapter, "_run_in_namespace", route_evidence):
            proof = adapter._install_direct_target_route(cell, "client-ns", "ppp0")
        assert proof["interface"] == "ppp0"
        assert proof["route"] == raw_locator(cell / "target-route.txt", cell)
        assert proof["link"] == raw_locator(cell / "tun-link.txt", cell)
        assert (cell / "target-route.txt").read_text(encoding="ascii") == (
            f"{acceptance.FORMAL_TARGET_HOST} dev ppp0 src 10.0.0.2\n"
        )
        assert "POINTOPOINT" in (cell / "tun-link.txt").read_text(encoding="ascii")
    assert calls == [
        ["ip", "route", "replace", f"{acceptance.FORMAL_TARGET_HOST}/32", "dev", "ppp0"],
        ["ip", "route", "get", acceptance.FORMAL_TARGET_HOST],
        ["ip", "-d", "link", "show", "dev", "ppp0"],
    ]


def test_cli_freeze_and_fixed_adapter_entrypoints_are_narrow() -> None:
    for command in (
        [sys.executable, "-B", str(TOOL), "--help"],
        [str(WRAPPER), "--help"],
        [str(ADAPTER), "--help"],
    ):
        completed = subprocess.run(command, text=True, capture_output=True, check=True)
        assert "Usage" in completed.stdout or "usage:" in completed.stdout
    rejected = subprocess.run(
        [str(WRAPPER), "run", "--artifacts", "/tmp/unused", "--candidate", "/tmp/unused", "--adapter", "/tmp/unused"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "does not permit --adapter" in rejected.stderr
    wrapper_source = WRAPPER.read_text(encoding="utf-8")
    adapter_source = ADAPTER.read_text(encoding="utf-8")
    legacy_identifier = "run_datapath_linux_matrix"
    assert legacy_identifier not in wrapper_source
    assert legacy_identifier not in adapter_source
    assert os.access(WRAPPER, os.X_OK)
    assert os.access(ADAPTER, os.X_OK)


def test_adapter_non_netem_qdisc_uses_configuration_only() -> None:
    adapter = __import__("datapath_linux_strict_adapter")
    configuration = b'[{"kind":"fq","root":true,"options":{}}]'
    # Real tc fq extended statistics can repeat this key. The sentinel only
    # needs configuration, while active netem evidence still needs counters.
    statistics = b'[{"kind":"fq","throttled":0,"throttled":0}]'
    calls: list[list[str]] = []

    def capture(namespace: str, arguments: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert namespace == "test-ns"
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, statistics if "-s" in arguments else configuration, b"")

    with tempfile.TemporaryDirectory(prefix="datapath-qdisc-config-") as temporary_directory:
        cell = Path(temporary_directory)
        with patch.object(adapter, "_run_in_namespace", capture):
            for phase in ("pre", "immediate", "post"):
                locator = adapter._capture_v3_non_netem_qdisc(
                    cell, "test-ns", "ppp", f"sentinel-{phase}.json", "sentinel"
                )
                assert (cell / locator["path"]).read_bytes() == configuration
                assert calls[-1] == ["tc", "-j", "-d", "qdisc", "show", "dev", "ppp"]

            for configuration, message in (
                (b'[{"kind":"netem","root":true}]', "contains forbidden netem"),
                (b'[{"kind":"fq","kind":"netem"}]', "duplicate JSON object key"),
            ):
                try:
                    adapter._capture_v3_non_netem_qdisc(cell, "test-ns", "ppp", "invalid.json", "sentinel")
                except adapter.AdapterError as error:
                    assert message in str(error)
                else:
                    raise AssertionError(f"expected adapter rejection: {message}")
            statistics = b'[{"kind":"netem","bytes":1200,"packets":1,"drops":0,"overlimits":0}]'
            locator = adapter._capture_v3_qdisc(cell, "test-ns", "carrier", "target.json", "target")
            assert "-s" in calls[-1]
            assert (cell / locator["path"]).read_bytes() == statistics


def test_v3_link_baseline_still_rejects_configuration_drift() -> None:
    with tempfile.TemporaryDirectory(prefix="datapath-link-baseline-") as temporary_directory:
        cell = Path(temporary_directory)
        pre = {"ifname": "carrier", "qdisc": "netem", "mtu": 1500, "stats64": {"tx": {"bytes": 10, "packets": 1}}}
        post = {**pre, "stats64": {"tx": {"bytes": 1200, "packets": 10}}}
        evidence = {
            "pre": write_json_evidence(cell, "link-pre.json", [pre]),
            "post": write_json_evidence(cell, "link-post.json", [post]),
        }
        acceptance._v3_validate_link_evidence(cell, evidence, "carrier", "link")
        for field, value in (("qdisc", "fq"), ("mtu", 1400)):
            evidence["post"] = write_json_evidence(cell, "changed.json", [{**post, field: value}])
            expect_error(
                lambda: acceptance._v3_validate_link_evidence(cell, evidence, "carrier", "link"),
                "configuration changed",
            )
        evidence["post"] = write_json_evidence(cell, "idle.json", [pre])
        expect_error(
            lambda: acceptance._v3_validate_link_evidence(cell, evidence, "carrier", "link"),
            "TX bytes and packets must increase",
        )


def main() -> None:
    test_v3_link_baseline_still_rejects_configuration_drift()
    test_adapter_non_netem_qdisc_uses_configuration_only()
    test_v3_network_profile_catalog_and_directional_seeds_are_closed()
    test_v2_prepare_remains_literal_and_v3_requires_profile_seed_pair()
    test_v3_source_inventory_is_versioned_and_required()
    test_v3_complete_profile_bound_run_passes_and_reports_binding()
    test_v3_result_profile_and_seed_mismatches_fail_closed()
    test_v3_underlay_launch_evidence_is_strict()
    test_v3_netem_and_non_target_tampering_fail_closed()
    test_v3_periodic_bpf_evidence_is_strict()
    test_v3_uniform_distribution_evidence_is_strict()
    test_fixed_plan_threshold_and_environment_contract()
    test_source_inventory_is_allowlisted_and_sensitive_preflight_is_read_free()
    test_source_identity_rejects_root_and_allowlisted_component_symlinks()
    test_valid_complete_run_passes_and_ndi_rejected_counters_do_not_invalidate_it()
    test_low_goodput_is_assessed_failure_and_still_seals()
    test_launch_requires_exact_environments_and_forbidden_knobs()
    test_launch_validates_candidate_config_process_cpu_qdisc_and_queue_readbacks()
    test_raw_stats_direct_proof_is_derived_from_immutable_raw_lines()
    test_final_acknowledgement_must_equal_selected_raw_end_boundary()
    test_scheduler_migration_counter_accepts_kernel_spelling_and_rejects_ambiguity()
    test_adapter_build_cell_configs_uses_fixed_root_contract()
    test_result_coverage_and_raw_iperf_validation_are_fail_closed()
    test_seal_rejects_incomplete_or_malformed_normal_evidence()
    test_source_candidate_and_sealed_artifact_drift_are_global_failures()
    test_prepare_rejects_reuse_relative_or_source_bin_candidates()
    test_freeze_creates_a_fresh_sealed_nonpass_artifact_and_malformed_freezes_fail_closed()
    test_adapter_rejects_symlink_root_and_creates_no_direct_iperf_path()
    test_adapter_iperf_uses_only_the_formal_target()
    test_adapter_discovers_exactly_one_point_to_point_tun()
    test_adapter_installs_target_route_and_retains_evidence()
    test_cli_freeze_and_fixed_adapter_entrypoints_are_narrow()
    print("datapath acceptance v2/v3 contract: pass")


if __name__ == "__main__":
    main()
