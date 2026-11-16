#!/usr/bin/env python3
"""Offline M3 runner contracts: no PPP, namespace, or network operations."""

import json
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from datapath_matrix_metadata import check_isolation, is_mountpoint, runtime_policy_metadata
from datapath_m3_manifest import campaign
from datapath_cpu_isolation import apply, readback, restore, snapshot

RUNNER = ROOT / "tools/run_datapath_linux_matrix.sh"
NAMES = ("SHARDS", "SPSC_INGRESS", "AFFINITY", "IO_CPUS", "AFFINITY_STRICT", "AUTO_SHARDS")


class Prerequisites(unittest.TestCase):
    def plan(self, *flags, env=None):
        return subprocess.run(["bash", str(RUNNER), "--dry-run", "--artifacts", "/unused",
                               "--stacks", "xtcp", "--parallel", "1", "--directions", "dl", *flags],
                              env=env, capture_output=True, text=True)

    def test_policies_and_pollution(self):
        env = dict(os.environ, **{"OPENPPP2_XTCP_" + name: "polluted" for name in NAMES})
        for shards in ("auto", "unset", *map(str, range(1, 9))):
            result = self.plan("--xtcp-shards", shards, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"xtcp_shards_requested={shards}", result.stdout)
            self.assertNotIn("polluted", result.stdout)
        rollback = self.plan("--xtcp-shards", "auto", "--xtcp-auto-shards", "0")
        self.assertIn("xtcp_auto_shards=0", rollback.stdout)
        for flag, value in (("--xtcp-shards", "0"), ("--xtcp-shards", "9"),
                            ("--xtcp-shards", "2junk"), ("--xtcp-affinity-strict", "yes"),
                            ("--xtcp-auto-shards", "false"), ("--xtcp-io-cpus", "1,1"),
                            ("--xtcp-io-cpus", "1-2"), ("--xtcp-spsc-ingress", "2")):
            self.assertEqual(self.plan(flag, value).returncode, 2)

    def test_exec_envelope_and_scrubbing(self):
        source = RUNNER.read_text()
        self.assertEqual(source.count('env "${POLICY_UNSET[@]}"'), 2)
        for name in NAMES:
            self.assertIn("-u OPENPPP2_XTCP_" + name, source)
        self.assertIn('client_cpu_prefix=(taskset -c "$AFFINITY_CPUS")', source)
        self.assertIn('"${client_cpu_prefix[@]}" python3', source)
        self.assertIn('isolation_helper snapshot', source)
        # Execute the runner's actual parsing/array construction, stopping before
        # its dry-run exit and all runtime operations. Probe a harmless child.
        preamble = source.split('if [[ "$DRY_RUN" == true ]]; then', 1)[0]
        probe = '\nenv "${POLICY_UNSET[@]}" "${POLICY_ENV[@]}" python3 -c \'import os,json; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith("OPENPPP2_XTCP_")}))\''
        env = dict(os.environ, **{"OPENPPP2_XTCP_" + name: "polluted" for name in NAMES})
        for flags, expected in (([], {}), (["--xtcp-shards", "unset"], {}),
                                (["--xtcp-shards", "auto", "--xtcp-auto-shards", "0", "--xtcp-spsc-ingress", "1"],
                                 {"OPENPPP2_XTCP_SHARDS": "auto", "OPENPPP2_XTCP_AUTO_SHARDS": "0", "OPENPPP2_XTCP_SPSC_INGRESS": "1"})):
            result = subprocess.run(["bash", "-c", preamble + probe, str(RUNNER),
                                     "--dry-run", "--artifacts", "/unused", *flags],
                                    env=env, check=True, capture_output=True, text=True)
            actual = json.loads(result.stdout)
            self.assertEqual({key: value for key, value in actual.items() if key in {"OPENPPP2_XTCP_" + name for name in NAMES}}, expected)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            output = Path(directory) / "startup.json"
            cpu = min(os.sched_getaffinity(0))
            result = subprocess.run(["taskset", "-c", str(cpu), sys.executable,
                                     str(ROOT / "tools/datapath_startup_exec.py"),
                                     "--output", str(output), "--requested", str(cpu), "--",
                                     sys.executable, "-c", "import os; print(os.getpid())"],
                                    check=True, capture_output=True, text=True)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["allowed_cpus"], [cpu])
            self.assertEqual(evidence["pid"], int(result.stdout))

    def test_mountpoint_detects_same_filesystem_bind_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            info = Path(directory) / "mountinfo"
            info.write_text("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
                            "2 1 8:1 /home/x/etc-netns /etc/netns rw - ext4 /dev/sda1 rw\n")
            self.assertTrue(is_mountpoint("/etc/netns", str(info)))
            self.assertFalse(is_mountpoint("/etc/netns-not-mounted", str(info)))

    def test_isolation_fails_before_mutation(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                check_isolation()
        env = {key: value for key, value in os.environ.items() if not key.startswith("OPENPPP2_M3_")}
        result = subprocess.run(["bash", str(RUNNER), "--artifacts", "/unused", "--ppp-bin", "/unused/ppp"],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runner requires run_m3_isolated.sh", result.stderr)
        source = RUNNER.read_text()
        self.assertLess(source.index("--check-isolation"), source.index('ip netns add "$ns_c"'))
        wrapper = (ROOT / "tools/run_m3_isolated.sh").read_text()
        self.assertLess(wrapper.index("mount --make-rprivate"), wrapper.index("mount --bind"))
        self.assertIn('run-netns" /run/netns', wrapper)
        self.assertIn('etc-netns" /etc/netns', wrapper)
        self.assertIn("mount -t sysfs", wrapper)
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            # Mock unshare to prove the initial namespace performs no mount/network command.
            fake = Path(directory) / "unshare"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=str(fake.parent) + ":" + os.environ["PATH"])
            result = subprocess.run(["bash", str(ROOT / "tools/run_m3_isolated.sh"),
                                     "--run-dir", directory, "--", "true"], env=env,
                                    capture_output=True, text=True)
            # Missing host mountpoints is also a valid fail-closed preflight.
            self.assertTrue(result.returncode == 0 or "existing host mountpoints" in result.stderr)
            if result.returncode == 0:
                self.assertIn("--net\n--mount\n--fork\n--kill-child", result.stdout)

    def test_runtime_metadata(self):
        self.assertEqual(runtime_policy_metadata([])["status"], "unavailable")
        policy = runtime_policy_metadata([{"xtcp": {"shard_count": 2, "shard_policy_requested": "auto",
                                                  "worker_bindings": [{"tid": 123, "effective_cpus": [1]}]}}])
        self.assertEqual(policy["effective"]["shard_count"], 2)
        self.assertEqual(policy["effective"]["shard_policy_requested"], "auto")
        self.assertEqual(policy["effective"]["worker_bindings"][0]["tid"], 123)

    def test_same_filesystem_bind_mount_isolation(self):
        env = {"OPENPPP2_M3_ISOLATION_ROOT": "/private",
               "OPENPPP2_M3_INITIAL_NET": "host-net",
               "OPENPPP2_M3_INITIAL_MNT": "host-mnt"}
        mounts = ("10 1 8:1 /private/etc-netns /etc/netns rw - ext4 /dev/sda1 rw\n"
                  "11 1 8:1 /private/run-netns /run/netns rw - ext4 /dev/sda1 rw\n")
        with patch.dict(os.environ, env, clear=True), \
             patch("os.readlink", return_value="isolated"), \
             patch("os.path.realpath", side_effect=lambda path: path), \
             patch("os.path.ismount", side_effect=lambda path: path == "/sys"), \
             patch("os.path.samefile", return_value=True), \
             patch.object(Path, "read_text", return_value=mounts):
            check_isolation()
            with patch.object(Path, "read_text", return_value=mounts.splitlines()[0]):
                with self.assertRaisesRegex(SystemExit, "backing mount missing"):
                    check_isolation()
            with patch("os.path.samefile", return_value=False):
                with self.assertRaisesRegex(SystemExit, "backing mount missing"):
                    check_isolation()

    def test_wrapper_mocked_mount_order_and_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            root = Path(directory)
            log = root / "calls"
            for command in ("readlink", "mount", "python3", "ip"):
                script = root / command
                script.write_text('#!/bin/sh\nprintf "%s %s\\n" "' + command + '" "$*" >> "$M3_TEST_LOG"\n' +
                                  ('printf "isolated\\n"\n' if command == "readlink" else 'exit 0\n'))
                script.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], M3_TEST_LOG=str(log),
                       OPENPPP2_M3_INITIAL_NET="host-net", OPENPPP2_M3_INITIAL_MNT="host-mnt",
                       OPENPPP2_M3_ISOLATION_ROOT=str(root))
            result = subprocess.run(["bash", str(ROOT / "tools/run_m3_isolated.sh"), "--inside", "false"],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            calls = log.read_text().splitlines()
            self.assertEqual(calls[0], "readlink /proc/self/ns/net")
            self.assertEqual(calls[1], "readlink /proc/self/ns/mnt")
            self.assertEqual(calls[2], "mount --make-rprivate /")
            self.assertIn("/etc/netns", calls[3])
            self.assertIn("/run/netns", calls[4])
            self.assertTrue(calls[5].startswith("mount -t sysfs"))
            self.assertIn("--check-isolation", calls[6])
            self.assertEqual(calls[-1], "ip netns list")

    def test_manifest_cells(self):
        manifest = json.loads((ROOT / "build/m3/AB_MANIFEST.json").read_text())
        summaries, rows = campaign(manifest, list(range(8)), "/home/ppp-m2/m3/A2-campaign")
        self.assertEqual(summaries["S1"]["cells"], 80)
        self.assertEqual(summaries["S1"]["pending_cells"], 32)
        self.assertEqual(summaries["S1"]["max_planned_cells"], 112)
        self.assertEqual(summaries["S2"]["cells"], 0)
        self.assertEqual(summaries["validation"]["measurement_cells"], 0)
        decisions = dict(screening_passed=True, affinity_shortlist=["2", "4"], s1_complete=True,
                         guards_passed=True, evidence="synthetic-test-only", survivors=["affinity-shards2-workers", "scale-shards4"])
        summaries, rows = campaign(manifest, list(range(8)), "/home/ppp-m2/m3/A2-campaign", decisions)
        self.assertEqual(summaries["S1"]["cells"], 112)
        self.assertEqual(summaries["S2"]["cells"], 288)
        s2 = [row for row in rows if row["stage"] == "S2"]
        for offset in range(0, len(s2), 8):
            group = s2[offset:offset + 8]
            self.assertEqual(["control" if "-control-" in row["cell"] else "candidate" for row in group],
                             ["control", "control", "candidate", "candidate", "candidate", "candidate", "control", "control"])
        bad_budget = copy.deepcopy(manifest)
        bad_budget["stages"]["S1"]["max_cells"] = 111
        with self.assertRaisesRegex(ValueError, "S1 budget exceeded"):
            campaign(bad_budget, list(range(8)), "/unused")
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            path = Path(directory) / "over-budget.json"
            path.write_text(json.dumps(bad_budget))
            result = subprocess.run([sys.executable, str(ROOT / "tools/datapath_m3_manifest.py"),
                                     "--manifest", str(path), "--cpus", "0,1,2,3,4,5,6,7",
                                     "--run-dir", "/unused", "--dry-run"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("S1 budget exceeded", result.stderr)
            self.assertEqual(result.stdout, "")
        expanded = copy.deepcopy(manifest)
        expanded["stages"]["S1"]["parallel"] = [1, 4, 16, 64]
        expanded["stages"]["S1"]["max_cells"] = 999
        with self.assertRaisesRegex(ValueError, "S1 budget exceeded"):
            campaign(expanded, list(range(8)), "/unused")
        for invalid in (dict(survivors=["scale-shards2"]),
                        dict(decisions, survivors=["unknown"]),
                        dict(decisions, affinity_shortlist=["auto", "4"]),
                        dict(decisions, survivors=["scale-shards1", "scale-shards2", "scale-shards4"])):
            with self.assertRaises(ValueError):
                campaign(manifest, list(range(8)), "/unused", invalid)
        names = set()
        flag_sets = set()
        available = sorted(os.sched_getaffinity(0))
        if len(available) < 8:
            self.skipTest("manifest validation requires eight allowed CPU IDs")
        _, rows = campaign(manifest, available[:8], "/home/ppp-m2/m3/A2-campaign", decisions)
        for cell in rows:
            self.assertNotIn(cell["cell"], names)
            names.add(cell["cell"])
            argv = cell["argv"]
            if cell["stage"] == "validation":
                self.assertIn("--dry-run", argv)
                self.assertNotIn("tools/run_m3_isolated.sh", argv)
            else:
                self.assertIn("tools/run_m3_isolated.sh", argv)
                self.assertEqual(argv[argv.index("--kernel-steering") + 1], "off")
                expected_duration = "10" if cell["stage"] == "S1" else "45"
                self.assertEqual(argv[argv.index("--duration") + 1], expected_duration)
                self.assertEqual(argv[argv.index("--omit") + 1], "2")
            runner_index = argv.index("tools/run_datapath_linux_matrix.sh")
            flags = tuple(argv[runner_index + 1:])
            flag_sets.add((flags, cell["expected_exit"]))
        for flags, expected in flag_sets:
            result = subprocess.run(["bash", str(RUNNER), *flags, "--dry-run"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_default_isolation_lifecycle_mocked(self):
        source = RUNNER.read_text()
        self.assertIn('KERNEL_STEERING="on"', source)
        functions = source.split("  isolation_helper() {", 1)[1].split("  snapshot_process() {", 1)[0]
        functions = "isolation_helper() {" + functions
        script = '''set -euo pipefail
            ROOT=$1; state_dir=$2; KERNEL_STEERING=$3; fail_phase=$4
            CPU_PROFILE=client-single-core; CPU_LIST=(0); ns_c=owned-test; tun_dev=tun-test
            isolation_state=$state_dir/state.json; isolation_active=false; isolation_restore_failed=false
            ip() {
              local phase arg
              for arg in "$@"; do
                case "$arg" in snapshot|apply|readback|restore) phase=$arg;; esac
              done
              printf '%s|%s\\n' "$phase" "$*" >> "$state_dir/calls"
              printf '{}\\n' > "$isolation_state"
              [[ "$phase" != "$fail_phase" ]]
            }
        ''' + functions + '''
            setup_result=0; setup_cpu_isolation || setup_result=$?
            restore_result=0; restore_cpu_isolation || restore_result=$?
            restore_cpu_isolation || true
            printf '%s %s %s\\n' "$setup_result" "$restore_result" "$isolation_restore_failed"
        '''
        for mode, failure, expected, results in (
            ("on", "none", ["snapshot", "apply", "readback", "restore"], "0 0 false"),
            ("off", "none", [], "0 0 false"),
            ("on", "apply", ["snapshot", "apply", "restore"], "1 0 false"),
            ("on", "restore", ["snapshot", "apply", "readback", "restore", "restore"], "0 1 true"),
        ):
            with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
                result = subprocess.run(["bash", "-c", script, "mock-isolation", str(ROOT), directory, mode, failure],
                                        capture_output=True, text=True, check=True)
                log = Path(directory) / "calls"
                lines = log.read_text().splitlines() if log.exists() else []
                self.assertEqual([line.split("|", 1)[0] for line in lines], expected)
                self.assertEqual(result.stdout.strip(), results)
                for line in lines:
                    self.assertIn("netns exec owned-test unshare --mount --propagation private", line)
                    self.assertIn("mount -t sysfs", line)
                if mode == "on":
                    self.assertTrue((Path(directory) / "cpu-isolation-restore.json").exists())

    def test_irq_writes_refused_even_for_legacy_or_mislabeled_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            root = Path(directory)
            irq = root / "proc/irq/55/smp_affinity"
            irq.parent.mkdir(parents=True)
            irq.write_text("00000002\n")
            (irq.parent / "effective_affinity").write_text("00000002\n")
            alias = root / "sys/class/net/test/queues/rx-0/rps_cpus"
            alias.parent.mkdir(parents=True)
            alias.symlink_to(irq)
            state = root / "state.json"
            (root / "proc/interrupts").write_text("55: 0 0 PCI-MSI test\n")
            evidence = snapshot(state, ["test"], 1, sys_root=root / "sys", proc_root=root / "proc", namespace="fake")
            self.assertEqual(evidence["phases"]["snapshot"]["status"], "fail")
            self.assertEqual(evidence["devices"]["test"]["irq_status"], "forbidden")
            self.assertEqual(readback(state)["phases"]["readback"]["status"], "fail")
            for kind, path in (("irq_affinity", irq), ("rps", irq), ("rps", alias)):
                state.write_text(json.dumps({"target_mask": "00000002", "settings": [
                    dict(kind=kind, path=str(path), device="test", original="00000001", original_raw="00000001")],
                    "devices": {"test": {"persistent": True}}, "phases": {}}))
                original_write = Path.write_text
                def guarded_write(path, *args, **kwargs):
                    self.assertNotEqual(path.resolve(), irq, "attempted IRQ write")
                    return original_write(path, *args, **kwargs)
                with patch.object(Path, "write_text", guarded_write):
                    self.assertEqual(apply(state)["phases"]["apply"]["status"], "fail")
                    self.assertEqual(restore(state, sys_root=root / "sys")["phases"]["restore"]["status"], "fail")
                self.assertEqual(irq.read_text(), "00000002\n")

    def test_wrapper_mocked_cleanup_checks_pid_namespace(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/m3") as directory:
            root = Path(directory)
            bodies = {
                "mount": "exit 0",
                "python3": "exit 0",
                "stat": "printf 'net:[777]\\n'",
                "readlink": '''case "$1" in
                    /proc/4242/ns/net) printf 'net:[777]\\n';;
                    /proc/4243/ns/net) printf 'host-net\\n';;
                    *) printf 'isolated\\n';;
                    esac''',
                "ip": '''printf '%s\\n' "$*" >> "$M3_TEST_LOG"
                    case "$*" in
                    'netns list') printf 'owned-test\\n';;
                    'netns pids owned-test') test -f "$M3_TEST_DONE" || printf '4242\\n4243\\n';;
                    esac
                    exit 0''',
            }
            for command, body in bodies.items():
                script = root / command
                script.write_text("#!/bin/sh\n" + body + "\n")
                script.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"],
                       M3_TEST_LOG=str(root / "calls"), M3_TEST_DONE=str(root / "done"),
                       OPENPPP2_M3_INITIAL_NET="host-net", OPENPPP2_M3_INITIAL_MNT="host-mnt",
                       OPENPPP2_M3_ISOLATION_ROOT=str(root))
            # Override Bash's kill builtin: all process/namespace operations here are mocks.
            script = '''kill() { printf 'kill %s\\n' "$*" >> "$M3_TEST_LOG";
                         if [[ "$1" == -KILL ]]; then touch "$M3_TEST_DONE"; fi; }
                        source "$1" --inside true'''
            result = subprocess.run(["bash", "-c", script, "mock-cleanup", str(ROOT / "tools/run_m3_isolated.sh")],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            calls = (root / "calls").read_text()
            self.assertIn("kill -TERM 4242", calls)
            self.assertIn("kill -KILL 4242", calls)
            self.assertNotIn("kill -TERM 4243", calls)
            self.assertNotIn("kill -KILL 4243", calls)
            self.assertIn("netns del owned-test", calls)


if __name__ == "__main__":
    unittest.main()
