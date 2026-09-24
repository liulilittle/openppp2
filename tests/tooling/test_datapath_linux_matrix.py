#!/usr/bin/env python3
"""Non-privileged contract for the datapath matrix cell planner."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools" / "run_datapath_linux_matrix.sh"
sys.path.insert(0, str(ROOT / "tools"))
from datapath_cpu_accounting import build_measurement, iperf_payload_bytes, parse_perf_csv, proc_stat_delta, softirq_delta
from datapath_cpu_isolation import apply, cpumask_for_cpu, normalize_cpulist, normalize_cpumask, readback, restore, snapshot
from datapath_matrix_metadata import collect_version_fingerprint, evaluate_performance_gate, flatten_version_fingerprint
from datapath_qualifier import PROCESS_CORES_MAX, PROCESS_CORES_MIN, qualify_cell


def plan(*arguments: str) -> list[str]:
    completed = subprocess.run(
        [str(RUNNER), "--artifacts", "/tmp/datapath-matrix-plan", "--dry-run", *arguments],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.splitlines()


def field(line: str, name: str) -> str:
    prefix = name + "="
    for token in line.split():
        if token.startswith(prefix):
            return token[len(prefix) :]
    raise AssertionError(f"missing {name} in {line!r}")


def invalid(*arguments: str) -> None:
    completed = subprocess.run(
        [str(RUNNER), "--artifacts", "/tmp/datapath-matrix-plan", "--dry-run", *arguments],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode != 0, completed.stdout


def test_runner_help() -> None:
    completed = subprocess.run([str(RUNNER), "--help"], check=True, text=True, capture_output=True)
    assert "--paired-performance-gate MODE" in completed.stdout
    assert "off|warn|fail (default: off)" in completed.stdout
    assert "--paired-performance-threshold RATIO" in completed.stdout
    assert "default: 1.20" in completed.stdout
    assert "--xtcp-direct-upload-gather-bytes BYTES" in completed.stdout
    assert "0/1 disables (default: 32768)" in completed.stdout


def test_performance_gate() -> None:
    def record(stack: str, goodput: float, *, gso: str = "off") -> dict:
        return {
            "round": 1, "parallel_flows": 4, "direction": "ul",
            "requested_tap_gso": gso, "active_tap_gso": gso,
            "requested_tcp_stack": stack, "goodput_bps": goodput,
        }

    assert evaluate_performance_gate([record("native", 100), record("xtcp", 1)], "off", 1.20) == {
        "mode": "off", "threshold": 1.20, "status": "off", "pairs": [], "failed_pairs": [],
    }
    warning = evaluate_performance_gate([record("native", 100), record("xtcp", 119)], "warn", 1.20)
    assert warning["status"] == "warning"
    assert warning["failed_pairs"][0]["ratio"] == 1.19
    assert warning["failed_pairs"][0]["reason"] == "below_threshold"
    hard_fail = evaluate_performance_gate([record("native", 100), record("xtcp", 119)], "fail", 1.20)
    assert hard_fail["status"] == "fail"
    assert evaluate_performance_gate([record("native", 100), record("xtcp", 120)], "fail", 1.20)["status"] == "pass"
    assert evaluate_performance_gate([record("native", 100), record("xtcp", 121)], "fail", 1.20)["status"] == "pass"
    incomplete_warning = evaluate_performance_gate([record("native", 100)], "warn", 1.20)
    assert incomplete_warning["status"] == "warning"
    assert incomplete_warning["failed_pairs"][0]["status"] == "fail"
    assert incomplete_warning["failed_pairs"][0]["reason"] == "incomplete_pair"
    incomplete = evaluate_performance_gate([record("native", 100)], "fail", 1.20)
    assert incomplete["status"] == "fail"
    assert incomplete["failed_pairs"][0]["reason"] == "incomplete_pair"
    lwip_only = evaluate_performance_gate([record("lwip", 100)], "fail", 1.20)
    assert lwip_only["status"] == "fail"
    assert lwip_only["failed_pairs"][0]["reason"] == "incomplete_pair"


def test_version_fingerprint() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        tracked = root / "tracked.txt"
        tracked.write_text("base\n", encoding="utf-8")
        tracked_secret = root / "tracked-token.txt"
        tracked_secret.write_text("base-secret\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "tracked.txt", "tracked-token.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True)
        tracked.write_text("changed\n", encoding="utf-8")
        tracked_secret.write_text("changed-secret\n", encoding="utf-8")
        untracked = root / "untracked.txt"
        untracked.write_text("must-not-be-read\n", encoding="utf-8")
        secret = root / "private-token.txt"
        secret.write_text("do-not-leak\n", encoding="utf-8")
        xtcp = root / "third-party" / "xtcp"
        xtcp.mkdir(parents=True)
        (xtcp / ".openppp2-xtcp-revision").write_text("revision-1\n", encoding="utf-8")
        (xtcp / ".openppp2-xtcp-patches").write_text("patch-1\n", encoding="utf-8")
        binary = root / "ppp"
        binary.write_bytes(b"ppp-binary")

        fingerprint = collect_version_fingerprint(root, binary)
        flattened = flatten_version_fingerprint(fingerprint)
        assert fingerprint["ppp_binary"]["sha256"] == hashlib.sha256(b"ppp-binary").hexdigest()
        assert fingerprint["ppp_binary"]["size_bytes"] == 10
        assert fingerprint["ppp_binary"]["mtime_ns"] > 0
        assert len(fingerprint["git"]["head"]) == 40
        assert fingerprint["git"]["describe"]
        assert len(fingerprint["git"]["tracked_diff_sha256"]) == 64
        assert fingerprint["git"]["tracked_diff_excluded_sensitive_path_count"] == 1
        assert len(fingerprint["git"]["untracked_paths_sha256"]) == 64
        assert fingerprint["git"]["untracked_path_count"] >= 4
        assert fingerprint["xtcp"] == {"revision": "revision-1", "patch_stamp": "patch-1"}
        assert flattened["ppp_binary_size_bytes"] == "10"
        original_untracked_hash = fingerprint["git"]["untracked_paths_sha256"]
        untracked.write_text("different-content\n", encoding="utf-8")
        assert collect_version_fingerprint(root, binary)["git"]["untracked_paths_sha256"] == original_untracked_hash
        assert "private-token.txt" not in json.dumps(fingerprint)
        assert "do-not-leak" not in json.dumps(fingerprint)
        assert "changed-secret" not in json.dumps(fingerprint)


def test_cpu_accounting() -> None:
    before_stat = "cpu 0 0 0 0 0 0 0 0\ncpu0 10 0 3 7 0 1 2 0\ncpu1 5 0 1 4 0 0 1 0\n"
    after_stat = "cpu 0 0 0 0 0 0 0 0\ncpu0 12 0 5 8 0 2 4 0\ncpu1 6 0 2 5 0 0 2 0\n"
    stat = proc_stat_delta(before_stat, after_stat, [0], 100)
    assert stat["selected"]["nonidle_ns"] == 7 * 10_000_000
    assert stat["selected"]["system_ns"] == 2 * 10_000_000
    softirqs_before = "                    CPU0 CPU1\n      NET_RX: 1 2\n      NET_TX: 3 4\n"
    softirqs_after = "                    CPU0 CPU1\n      NET_RX: 3 3\n      NET_TX: 3 7\n"
    softirqs = softirq_delta(softirqs_before, softirqs_after, [0])
    assert softirqs == {"NET_RX": {"selected": 2, "other": 1}, "NET_TX": {"selected": 0, "other": 3}}
    perf = parse_perf_csv("12.5,msec,task-clock\n7,,context-switches\n2,,cpu-migrations\n")
    assert perf == {"task_clock_ns": 12_500_000, "context_switches": 7, "cpu_migrations": 2}
    system_perf = parse_perf_csv("5000,msec,task-clock,1,100.00,1.000,CPUs utilized\n0,,context-switches\n0,,cpu-migrations\n")
    assert system_perf["cpus_utilized"] == 1.0
    assert iperf_payload_bytes({"end": {"sum_sent": {"bytes": 100}}}, "ul") == 100
    with tempfile.TemporaryDirectory() as directory:
        raw_dir = Path(directory)
        raw = {
            "proc_stat_start": "start.stat", "proc_stat_end": "end.stat",
            "softirqs_start": "start.softirqs", "softirqs_end": "end.softirqs",
            "process_perf": "process.csv", "system_perf": "system.csv",
        }
        (raw_dir / raw["proc_stat_start"]).write_text(before_stat, encoding="utf-8")
        (raw_dir / raw["proc_stat_end"]).write_text(after_stat, encoding="utf-8")
        (raw_dir / raw["softirqs_start"]).write_text(softirqs_before, encoding="utf-8")
        (raw_dir / raw["softirqs_end"]).write_text(softirqs_after, encoding="utf-8")
        for name in ("process_perf", "system_perf"):
            (raw_dir / raw[name]).write_text("12.5,msec,task-clock\n7,,context-switches\n2,,cpu-migrations\n", encoding="utf-8")
        measurement = build_measurement(
            profile="client-vnet-isolated", affinity_cpus=[0], affinity_verified=True, collection_verified=True,
            formal_start_ns=1, formal_end_ns=101, payload_bytes=100, clock_ticks=100,
            raw_files=raw, raw_dir=raw_dir, process_perf_enabled=True, system_perf_enabled=True,
        )
    assert measurement["status"] == "measured"
    assert measurement["softirqs"]["NET_RX"]["other"] == 1
    assert measurement["migration_warning"] == {
        "present": True,
        "reasons": ["other_cpu_net_rx", "other_cpu_net_tx"],
    }
    assert measurement["process_perf"]["task_clock_ns_per_payload_byte"] == 125_000
    unavailable = build_measurement(
        profile="none", affinity_cpus=[], affinity_verified=False, collection_verified=False,
        formal_start_ns=None, formal_end_ns=None, payload_bytes=None, clock_ticks=None,
        raw_files={}, raw_dir=Path("."), process_perf_enabled=False, system_perf_enabled=False,
    )
    assert unavailable["migration_warning"] == {"present": False, "reasons": []}


def write_strict_evidence(state: Path, *, queue_match: bool = True, restore_status: str = "pass") -> None:
    affinity = {
        "status": "pass",
        "processes": [
            {"role": "ppp", "pid": 10, "status": "alive", "affinity": "verified", "qualification": "pass", "thread_count": 1},
            {"role": "iperf", "pid": 20, "status": "alive", "affinity": "verified", "qualification": "pass", "thread_count": 1},
        ],
        "threads": [
            {"role": "ppp", "tid": 10, "cpus_allowed_list": "0", "target_match": True},
            {"role": "iperf", "tid": 20, "cpus_allowed_list": "0", "target_match": True},
        ],
    }
    for boundary in ("launch", "start", "end"):
        (state / f"cpu-{boundary}-affinity.json").write_text(json.dumps(affinity), encoding="utf-8")
    isolation = {
        "target_cpu": 0,
        "target_mask": "00000001",
        "devices": {
            "xc-veth": {"queue_support": "supported", "irq_qualification": {"status": "pass", "result": "not_applicable"}},
            "tun0": {"queue_support": "supported", "irq_qualification": {"status": "pass", "result": "not_applicable"}},
        },
        "settings": [
            {"device": "xc-veth", "kind": "rps", "readback": {"target_match": queue_match}},
            {"device": "tun0", "kind": "xps", "readback": {"target_match": queue_match}},
        ],
        "phases": {"snapshot": {"status": "pass"}, "apply": {"status": "pass"}, "readback": {"status": "pass"}, "restore": {"status": restore_status}},
    }
    (state / "cpu-isolation-restore.json").write_text(json.dumps(isolation), encoding="utf-8")


def test_cpu_isolation() -> None:
    assert [cpumask_for_cpu(cpu) for cpu in (0, 31, 32, 63)] == [
        "00000001", "80000000", "00000001,00000000", "80000000,00000000",
    ]
    assert normalize_cpumask("00000000,00000001") == "00000001"
    assert normalize_cpumask("1,00000000") == "00000001,00000000"
    assert normalize_cpulist("0-2,4,6-7") == "0-2,4,6-7"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        sys_root, proc_root = root / "sys", root / "proc"
        for device in ("xc-veth", "tun0"):
            for relative in ("queues/rx-0/rps_cpus", "queues/tx-0/xps_cpus"):
                path = sys_root / "class/net" / device / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("00000003\n", encoding="utf-8")
        proc_root.mkdir(parents=True)
        (proc_root / "interrupts").write_text(
            "           CPU0 CPU1\n 55: 1 2 PCI-MSI xc-veth\n", encoding="utf-8"
        )
        irq_dir = proc_root / "irq/55"
        irq_dir.mkdir(parents=True)
        (irq_dir / "smp_affinity").write_text("00000003\n", encoding="utf-8")
        (irq_dir / "effective_affinity").write_text("00000003\n", encoding="utf-8")
        state = root / "evidence.json"
        evidence = snapshot(state, ["xc-veth", "tun0"], 32, persistent_devices={"xc-veth"}, sys_root=sys_root, proc_root=proc_root, namespace="fake")
        assert evidence["devices"]["xc-veth"]["irq_status"] == "applicable"
        assert evidence["devices"]["tun0"]["irq_status"] == "not_applicable"
        assert evidence["devices"]["tun0"]["queue_support"] == "supported"
        assert apply(state)["phases"]["apply"]["status"] == "pass"
        (irq_dir / "effective_affinity").write_text("00000001,00000000\n", encoding="utf-8")
        readback_evidence = readback(state)
        assert readback_evidence["phases"]["readback"]["status"] == "pass"
        assert readback_evidence["devices"]["xc-veth"]["irq_qualification"]["status"] == "pass"
        assert readback_evidence["devices"]["tun0"]["irq_qualification"] == {"status": "pass", "result": "not_applicable"}
        rps = sys_root / "class/net/xc-veth/queues/rx-0/rps_cpus"
        assert rps.read_text(encoding="utf-8").strip() == "00000001,00000000"
        rps.write_text("80000000\n", encoding="utf-8")
        wrong = readback(state)
        assert wrong["phases"]["readback"]["status"] == "fail"
        conflicted = restore(state, sys_root=sys_root)
        assert conflicted["phases"]["restore"]["status"] == "fail"
        assert rps.read_text(encoding="utf-8").strip() == "80000000"
        rps.write_text("00000001,00000000\n", encoding="utf-8")
        (irq_dir / "effective_affinity").write_text("00000003\n", encoding="utf-8")
        restored = restore(state, sys_root=sys_root)
        assert restored["phases"]["restore"]["status"] == "pass"
        assert rps.read_text(encoding="utf-8").strip() == "00000003"


def test_qualifier() -> None:
    def base_record(profile="client-vnet-isolated", stack="native", task_clock_ns=20_000_000_000, migrations=0, retransmits=0):
        return {
            "status": "pass",
            "requested_tcp_stack": stack,
            "active_tcp_stack": stack,
            "requested_tap_gso": "off",
            "active_tap_gso": "off",
            "retransmits": retransmits,
            "fairness": {"zero_rate_flows": 0, "min_bps": 1, "p50_bps": 1, "p90_bps": 1, "max_bps": 1, "max_min_ratio": 1.0},
            "cpu_measurement": {
                "status": "measured",
                "affinity_verified": True,
                "profile": profile,
                "payload_bytes": 1_000_000_000,
                "formal_interval": {"start_monotonic_ns": 0, "end_monotonic_ns": 20_000_000_000},
                "process_perf": {"task_clock_ns": task_clock_ns, "cpu_migrations": migrations},
                "iperf_perf": {"task_clock_ns": 1_000_000_000, "cpu_migrations": 0},
                "proc_stat": {"selected": {"nonidle_ns": 19_800_000_000}},
                "softirqs": {"NET_RX": {"selected": 100, "other": 10}, "NET_TX": {"selected": 0, "other": 0}},
                "migration_warning": {"present": True, "reasons": ["other_cpu_net_rx"]},
            },
        }

    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory)
        # No datapath JSONL -> diagnostics absent; non-XTCP passes push-failure check.
        passed = qualify_cell(base_record(), state)
        assert passed["status"] == "pass", passed
        assert passed["process_cores"] <= PROCESS_CORES_MAX
        assert passed["details"]["migration_warning_present"] is True

        # Task-clock twice the wall time -> process cores ~2 -> fail.
        failed = qualify_cell(base_record(task_clock_ns=40_000_000_000), state)
        assert failed["status"] == "fail", failed
        assert "process_cores_ok" in failed["failed_checks"]

        # Task-clock far below the wall time (e.g. 0.4 core) -> starved,
        # not a valid single-core result -> fail.
        starved = qualify_cell(base_record(task_clock_ns=8_000_000_000), state)
        assert starved["status"] == "fail", starved
        assert "process_cores_ok" in starved["failed_checks"]
        assert starved["process_cores"] < PROCESS_CORES_MIN

        # Borderline low cores (0.95) -> pass.
        borderline = qualify_cell(base_record(task_clock_ns=19_000_000_000), state)
        assert borderline["status"] == "pass", borderline

        # Non-zero migrations -> fail.
        migrated = qualify_cell(base_record(migrations=1), state)
        assert migrated["status"] == "fail"
        assert "ppp_zero_migrations" in migrated["failed_checks"]

        # XTCP with a tun_output/first_push_failure present and non-none -> fail.
        datapath = state / "datapath-client.jsonl"
        datapath.write_text(
            '{"timestamp_ms":1,"tun_output":{"invalid":0,"disposed":0,"first_push_failure":'
            '{"terminal":{"kind":"ordinary","outcome":"negative"}}}}\n',
            encoding="utf-8",
        )
        xtcp_failed = qualify_cell(base_record(stack="xtcp"), state)
        assert xtcp_failed["status"] == "fail"
        assert "first_push_failure_none" in xtcp_failed["failed_checks"]

        # XTCP with first_push_failure kind none -> pass.
        datapath.write_text(
            '{"timestamp_ms":1,"tun_output":{"invalid":0,"disposed":0,"first_push_failure":'
            '{"terminal":{"kind":"none","outcome":"none"}}}}\n',
            encoding="utf-8",
        )
        xtcp_passed = qualify_cell(base_record(stack="xtcp"), state)
        assert xtcp_passed["status"] == "pass", xtcp_passed

        # DL cells have no iperf retransmit counter (receiver side): None must
        # be N/A (pass), not a failure.
        dl_none = qualify_cell(base_record(retransmits=None), state)
        assert dl_none["status"] == "pass", dl_none
        assert dl_none["details"]["retransmits"] is None

        write_strict_evidence(state)
        strict = qualify_cell(base_record(profile="client-single-core"), state)
        assert strict["status"] == "pass", strict
        assert strict["details"]["other_cpu_net_softirq_delta"] == 10
        assert strict["details"]["migration_warning_present"] is True
        strict_low_ppp = qualify_cell(base_record(profile="client-single-core", task_clock_ns=8_000_000_000), state)
        assert strict_low_ppp["status"] == "pass", strict_low_ppp
        assert strict_low_ppp["warnings"] == ["ppp_process_cores_below_0.9_same_core_contention"]
        over_capacity = base_record(profile="client-single-core")
        over_capacity["cpu_measurement"]["proc_stat"]["selected"]["nonidle_ns"] = 20_500_000_000
        assert "selected_cpu_capacity_ok" in qualify_cell(over_capacity, state)["failed_checks"]
        over_system_capacity = base_record(profile="client-single-core")
        over_system_capacity["cpu_measurement"]["system_perf"] = {"cpus_utilized": 1.03}
        assert "selected_cpu_capacity_ok" in qualify_cell(over_system_capacity, state)["failed_checks"]
        terminated = json.loads((state / "cpu-end-affinity.json").read_text(encoding="utf-8"))
        terminated["processes"][1].update(status="terminated_after_interval", affinity="not_applicable", thread_count=0)
        terminated["threads"] = [thread for thread in terminated["threads"] if thread["role"] != "iperf"]
        (state / "cpu-end-affinity.json").write_text(json.dumps(terminated), encoding="utf-8")
        strict_terminated = qualify_cell(base_record(profile="client-single-core"), state)
        assert strict_terminated["status"] == "pass", strict_terminated
        assert strict_terminated["checks"]["end_affinity_or_terminated"] is True
        wrong_mask = json.loads((state / "cpu-isolation-restore.json").read_text(encoding="utf-8"))
        wrong_mask["settings"][0]["readback"]["target_match"] = False
        (state / "cpu-isolation-restore.json").write_text(json.dumps(wrong_mask), encoding="utf-8")
        strict_wrong = qualify_cell(base_record(profile="client-single-core"), state)
        assert "rps_xps_target_mask" in strict_wrong["failed_checks"]
        write_strict_evidence(state)
        unsupported = json.loads((state / "cpu-isolation-restore.json").read_text(encoding="utf-8"))
        unsupported["devices"]["tun0"]["queue_support"] = "unsupported"
        (state / "cpu-isolation-restore.json").write_text(json.dumps(unsupported), encoding="utf-8")
        assert "rps_xps_supported" in qualify_cell(base_record(profile="client-single-core"), state)["failed_checks"]
        write_strict_evidence(state)
        strict_migrated = base_record(profile="client-single-core")
        strict_migrated["cpu_measurement"]["iperf_perf"]["cpu_migrations"] = 1
        assert "iperf_zero_migrations" in qualify_cell(strict_migrated, state)["failed_checks"]
        datapath.write_text(
            '{"tun_output":{"first_push_failure":{"terminal":{"kind":"none",'
            '"packet_shape":{"excess_bytes":1}}}}}\n', encoding="utf-8")
        assert "no_oversized_l3_rejected" in qualify_cell(base_record(profile="client-single-core", stack="xtcp"), state)["failed_checks"]


def main() -> None:
    lines = plan(
        "--stacks",
        "native,lwip,xtcp",
        "--tap-gso",
        "off,on",
        "--parallel",
        "1",
        "--directions",
        "ul",
        "--rounds",
        "2",
    )
    assert len(lines) == 12, lines
    assert [(field(line, "stack"), field(line, "tap_gso")) for line in lines[:6]] == [
        ("native", "off"),
        ("lwip", "off"),
        ("xtcp", "off"),
        ("native", "on"),
        ("lwip", "on"),
        ("xtcp", "on"),
    ]
    assert [(field(line, "stack"), field(line, "tap_gso")) for line in lines[6:]] == [
        ("lwip", "off"),
        ("xtcp", "off"),
        ("native", "on"),
        ("lwip", "on"),
        ("xtcp", "on"),
        ("native", "off"),
    ]
    assert field(lines[0], "cell_path") == "round-1/native-gso-off-p1-ul"
    assert field(lines[11], "cell_path") == "round-2/native-gso-off-p1-ul"
    assert field(lines[0], "cpu_profile") == "none"
    assert field(lines[0], "affinity_cpus") == "none"
    assert field(lines[0], "xtcp_memory_bridge") == "false"
    assert field(lines[0], "xtcp_ndi_tso_tx") == "false"
    assert field(lines[0], "xtcp_direct_upload_gather_bytes") == "default"
    assert field(lines[0], "paired_performance_gate") == "off"
    assert field(lines[0], "paired_performance_threshold") == "1.20"

    laboratory_features = plan(
        "--stacks", "xtcp", "--tap-gso", "off", "--parallel", "1", "--directions", "ul",
        "--xtcp-memory-bridge", "--xtcp-ndi-tso-tx",
    )
    assert field(laboratory_features[0], "xtcp_memory_bridge") == "true"
    assert field(laboratory_features[0], "xtcp_ndi_tso_tx") == "true"
    assert field(laboratory_features[0], "xtcp_direct_upload_gather_bytes") == "default"

    default_modes = plan(
        "--parallel",
        "1",
        "--directions",
        "ul",
        "--tap-gso",
        "off,on",
    )
    assert [(field(line, "stack"), field(line, "tap_gso")) for line in default_modes] == [
        ("native", "off"),
        ("lwip", "off"),
        ("xtcp", "off"),
        ("native", "on"),
        ("lwip", "on"),
        ("xtcp", "on"),
    ]

    single_mode = plan(
        "--stacks",
        "native,lwip",
        "--tap-gso",
        "on",
        "--parallel",
        "1",
        "--directions",
        "dl",
    )
    assert [(field(line, "stack"), field(line, "tap_gso")) for line in single_mode] == [
        ("native", "on"),
        ("lwip", "on"),
    ]

    available_cpus = sorted(os.sched_getaffinity(0))
    assert len(available_cpus) >= 2, available_cpus
    affinity = f"{available_cpus[0]},{available_cpus[1]}"
    cpu_profile = plan("--stacks", "native", "--tap-gso", "off", "--parallel", "1", "--directions", "ul", "--cpu-profile", "client-vnet-isolated", "--affinity-cpus", affinity)
    assert field(cpu_profile[0], "cpu_profile") == "client-vnet-isolated"
    assert field(cpu_profile[0], "affinity_cpus") == affinity
    invalid("--cpu-profile", "client-vnet-isolated")
    invalid("--process-perf-stat")
    invalid("--system-cpu-stat")
    invalid("--cpu-profile", "client-vnet-isolated", "--affinity-cpus", "999999")
    invalid("--cpu-profile", "client-vnet-isolated", "--affinity-cpus", "01,1")
    invalid("--cpu-profile", "client-vnet-isolated", "--affinity-cpus", str(available_cpus[0]))
    single = plan("--stacks", "native", "--tap-gso", "off", "--parallel", "1", "--directions", "ul", "--cpu-profile", "client-single-core", "--affinity-cpus", str(available_cpus[0]))
    assert field(single[0], "cpu_profile") == "client-single-core"
    assert field(single[0], "affinity_cpus") == str(available_cpus[0])
    invalid("--cpu-profile", "client-single-core")
    invalid("--cpu-profile", "client-single-core", "--affinity-cpus", affinity)
    invalid("--paired-performance-gate", "error")
    invalid("--paired-performance-threshold", "0")
    invalid("--paired-performance-threshold", "not-a-ratio")
    gather = plan("--stacks", "xtcp", "--tap-gso", "off", "--parallel", "1", "--directions", "ul", "--xtcp-direct-upload-gather-bytes", "49152")
    assert field(gather[0], "xtcp_direct_upload_gather_bytes") == "49152"
    invalid("--xtcp-direct-upload-gather-bytes", "not-a-byte-count")
    test_runner_help()
    test_performance_gate()
    test_version_fingerprint()
    test_cpu_accounting()
    test_cpu_isolation()
    test_qualifier()
    print("datapath linux matrix planner and CPU accounting contract: pass")


if __name__ == "__main__":
    main()
