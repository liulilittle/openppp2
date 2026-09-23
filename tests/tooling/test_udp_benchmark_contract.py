from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UdpBenchmarkContractTests(unittest.TestCase):
    def _validate_udp_bundle(self, micro, e2e, git_sha):
        validator = ROOT / "tools" / "bench" / "validate_baseline_bundle.py"
        return subprocess.run(
            [sys.executable, validator, micro, e2e, "bench-01", git_sha],
            capture_output=True,
            text=True,
        )

    def _write_udp_bundle(self, root):
        micro = root / "micro"
        e2e = root / "e2e"
        micro.mkdir()
        e2e.mkdir()
        git_sha = "a" * 40
        environment = {
            "cpu": "fixed test cpu",
            "arch": "x86_64",
            "host_id": "bench-01",
            "virt": "none",
            "kernel": "6.8.0",
            "git_sha": git_sha,
            "compiler": "gcc test",
            "bench_flags": "-O3 -DNDEBUG",
            "governor": "performance",
            "perf_cycles": True,
        }
        for directory in (micro, e2e):
            (directory / "env.json").write_text(
                json.dumps(environment), encoding="utf-8"
            )

        metrics = lambda ns, pps, allocations: {
            "ns_per_op": ns,
            "pps": pps,
            "allocations_per_op": allocations,
        }
        summary = {
            "bm_allocator": {"benchmarks": {"BM_AllocFree/256": metrics(200, 5000000, 1)}},
            "bm_crypto": {"benchmarks": {"BM_Encrypt/aes/64": metrics(60, 16000000, 1)}},
            "bm_endpoint_serialize": {
                "benchmarks": {"BM_EndpointRoundTrip/ipv4": metrics(10, 100000000, 0)}
            },
            "bm_packet_codec": {
                "benchmarks": {
                    "BM_PacketCodec/64": metrics(300, 3333333, 9),
                    "BM_PacketCodec/1400": metrics(500, 2000000, 9),
                }
            },
            "bm_crypto_chain": {
                "benchmarks": {
                    "BM_CryptoChain/openssl/64": metrics(2000, 500000, 5),
                    "BM_CryptoChain/simd/64": metrics(400, 2500000, 5),
                    "BM_CryptoChain/openssl/1400": metrics(7000, 142857, 5),
                    "BM_CryptoChain/simd/1400": metrics(4800, 208333, 5),
                }
            },
        }
        (micro / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        for target in summary:
            rows = []
            for name, values in summary[target]["benchmarks"].items():
                rows.append({
                    "name": name,
                    "run_type": "iteration",
                    "real_time": values["ns_per_op"],
                    "items_per_second": values["pps"],
                    "allocations": values["allocations_per_op"],
                    "iterations": 1,
                })
            (micro / f"{target}.json").write_text(
                json.dumps({"benchmarks": rows}),
                encoding="utf-8",
            )
        cycles = {
            "available": True,
            "cases": {
                "endpoint_ipv4": {"cycles_per_packet": 30},
                "packet_codec_64": {"cycles_per_packet": 900},
                "packet_codec_1400": {"cycles_per_packet": 1500},
                "crypto_openssl_64": {"cycles_per_packet": 6000},
                "crypto_simd_64": {"cycles_per_packet": 1200},
                "crypto_openssl_1400": {"cycles_per_packet": 21000},
                "crypto_simd_1400": {"cycles_per_packet": 14400},
            },
        }
        (micro / "cycles.json").write_text(json.dumps(cycles), encoding="utf-8")

        frozen = (ROOT / "tools" / "bench" / "appsettings.bench.json").read_text(
            encoding="utf-8"
        )
        (e2e / "appsettings.bench.json").write_text(frozen, encoding="utf-8")
        for size in (64, 1400):
            raw = {"end": {"sum": {"seconds": 10, "packets": 1000}}}
            result = {
                "seconds": 10,
                "packets": 1000,
                "pps": 100,
                "offered_bitrate": "10M",
                "lost_packets": 0,
                "lost_percent": 0,
                "bits_per_second": 10000000,
            }
            (e2e / f"e2e-{size}.json").write_text(json.dumps(raw), encoding="utf-8")
            (e2e / f"e2e-{size}.summary.json").write_text(
                json.dumps(result), encoding="utf-8"
            )
        return micro, e2e, git_sha

    def test_fixed_host_bundle_reports_per_size_costs_and_amdahl(self):
        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            result = self._validate_udp_bundle(micro, e2e, git_sha)

        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(git_sha, report["git_sha"])
        self.assertEqual({"64", "1400"}, set(report["packets"]))
        self.assertEqual(6930, report["packets"]["64"]["openssl_cycles_per_packet"])
        self.assertGreater(report["packets"]["64"]["amdahl_improvement_percent"], 0)
        self.assertEqual(100, report["packets"]["1400"]["e2e"]["pps"])

    def test_fixed_host_bundle_rejects_summaries_that_disagree_with_raw_results(self):
        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            summary_path = micro / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["bm_packet_codec"]["benchmarks"]["BM_PacketCodec/64"][
                "ns_per_op"
            ] = 1
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            micro_mismatch = self._validate_udp_bundle(micro, e2e, git_sha)

        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            (e2e / "e2e-64.json").write_text(
                json.dumps({"end": {"sum": {"seconds": 10, "packets": 0}}}),
                encoding="utf-8",
            )
            e2e_mismatch = self._validate_udp_bundle(micro, e2e, git_sha)

        self.assertNotEqual(0, micro_mismatch.returncode)
        self.assertNotEqual(0, e2e_mismatch.returncode)

    def test_fixed_host_bundle_rejects_frozen_config_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            config_path = e2e / "appsettings.bench.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["concurrent"] = 3
            config_path.write_text(json.dumps(config), encoding="utf-8")
            result = self._validate_udp_bundle(micro, e2e, git_sha)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("frozen config", result.stderr)

    def test_fixed_host_bundle_rejects_environment_commit_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            environment_path = e2e / "env.json"
            environment = json.loads(environment_path.read_text(encoding="utf-8"))
            environment["git_sha"] = "b" * 40
            environment_path.write_text(json.dumps(environment), encoding="utf-8")
            result = self._validate_udp_bundle(micro, e2e, git_sha)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("expected commit", result.stderr)

    def test_fixed_host_bundle_requires_complete_stable_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
            for result_dir in (micro, e2e):
                environment_path = result_dir / "env.json"
                environment = json.loads(
                    environment_path.read_text(encoding="utf-8")
                )
                environment.pop("compiler")
                environment_path.write_text(
                    json.dumps(environment), encoding="utf-8"
                )
            result = self._validate_udp_bundle(micro, e2e, git_sha)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("compiler", result.stderr)

    def test_fixed_host_bundle_rejects_missing_or_unavailable_cycles(self):
        results = []
        for cycles_payload in (None, {"available": False, "cases": {}}):
            with tempfile.TemporaryDirectory() as directory:
                micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
                cycles_path = micro / "cycles.json"
                if cycles_payload is None:
                    cycles_path.unlink()
                else:
                    cycles_path.write_text(
                        json.dumps(cycles_payload), encoding="utf-8"
                    )
                results.append(self._validate_udp_bundle(micro, e2e, git_sha))

        self.assertTrue(all(result.returncode != 0 for result in results))

    def test_fixed_host_bundle_requires_both_e2e_packet_sizes(self):
        results = []
        for size in (64, 1400):
            with tempfile.TemporaryDirectory() as directory:
                micro, e2e, git_sha = self._write_udp_bundle(Path(directory))
                (e2e / f"e2e-{size}.json").unlink()
                results.append(self._validate_udp_bundle(micro, e2e, git_sha))

        self.assertTrue(all(result.returncode != 0 for result in results))

    def _validate_fixed_host(self, environment, expected_host_id="bench-01"):
        validator = ROOT / "tools" / "bench" / "validate_fixed_host.py"
        with tempfile.TemporaryDirectory() as directory:
            fingerprint = Path(directory) / "env.json"
            fingerprint.write_text(json.dumps(environment), encoding="utf-8")
            return subprocess.run(
                [sys.executable, validator, fingerprint, expected_host_id],
                capture_output=True,
                text=True,
            )

    def test_fixed_host_validator_rejects_wsl(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "wsl",
                "governor": "performance",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("WSL", result.stderr)

    def test_fixed_host_validator_rejects_wsl_kernel_even_if_virt_is_wrong(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "none",
                "kernel": "6.6-microsoft-standard-WSL2",
                "governor": "performance",
                "perf_cycles": True,
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("WSL", result.stderr)

    def test_fixed_host_validator_requires_x86_64(self):
        result = self._validate_fixed_host(
            {
                "arch": "aarch64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "performance",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("x86-64", result.stderr)

    def test_fixed_host_validator_requires_performance_governor(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "unknown",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("performance governor", result.stderr)

    def test_fixed_host_validator_requires_perf_cycles(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "performance",
                "perf_cycles": False,
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("cycles", result.stderr)

    def test_fixed_host_validator_requires_nonempty_host_id(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "",
                "virt": "none",
                "governor": "performance",
                "perf_cycles": True,
            },
            expected_host_id="",
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("host_id", result.stderr)

    def test_all_microbenchmarks_are_built_and_smoke_tested(self):
        cmake = (ROOT / "bench" / "CMakeLists.txt").read_text(encoding="utf-8")

        for target in ("bm_crypto_chain", "bm_endpoint_serialize", "bm_packet_codec"):
            self.assertIn(f"ppp_add_bench({target}", cmake)
            self.assertIn(f"COMMAND {target} --benchmark_min_time=0.001", cmake)

    def test_linux_smoke_uses_the_built_boost_headers(self):
        cmake = (ROOT / "bench" / "CMakeLists.txt").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "build-linux-amd64.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("OPENPPP2_BOOST_INCLUDE_DIR", cmake)
        self.assertIn(
            '-DOPENPPP2_BOOST_INCLUDE_DIR="$TP/boost"',
            workflow,
        )

    def test_debian10_installs_git_before_checkout(self):
        workflow = (ROOT / ".github" / "workflows" / "build-linux-amd64.yml").read_text(
            encoding="utf-8"
        )
        debian10 = workflow.split("  build-debian10:", 1)[1].split(
            "\n  build-asan:", 1
        )[0]

        self.assertIn("Install Git for checkout", debian10)
        bootstrap = debian10.index("Install Git for checkout")
        checkout = debian10.index("uses: actions/checkout@v4")
        self.assertLess(bootstrap, checkout)
        self.assertIn("apt-get install -y --no-install-recommends git ca-certificates", debian10[:checkout])

    def test_micro_runner_records_every_required_metric(self):
        runner = (ROOT / "tools" / "bench" / "run_micro.sh").read_text(encoding="utf-8")

        for target in (
            "bm_crypto",
            "bm_crypto_chain",
            "bm_allocator",
            "bm_endpoint_serialize",
            "bm_packet_codec",
        ):
            self.assertIn(target, runner)
        self.assertIn("perf stat", runner)
        self.assertIn("cycles", runner)

        for source in (
            "bm_crypto.cpp",
            "bm_crypto_chain.cpp",
            "bm_allocator.cpp",
            "bm_endpoint_serialize.cpp",
            "bm_packet_codec.cpp",
        ):
            text = (ROOT / "bench" / "udp" / source).read_text(encoding="utf-8")
            self.assertIn('counters["allocations"]', text)

    def test_micro_runner_collects_per_case_cycles(self):
        collector = ROOT / "tools" / "bench" / "collect_cycles.py"
        result = subprocess.run(
            [sys.executable, collector, "--list"], capture_output=True, text=True
        )
        self.assertEqual(0, result.returncode, result.stderr)
        cases = json.loads(result.stdout)
        self.assertEqual(
            {
                "endpoint_ipv4",
                "packet_codec_64",
                "packet_codec_1400",
                "crypto_openssl_64",
                "crypto_simd_64",
                "crypto_openssl_1400",
                "crypto_simd_1400",
            },
            set(cases),
        )
        runner = (ROOT / "tools" / "bench" / "run_micro.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("collect_cycles.py", runner)
        self.assertIn("cycles.json", runner)

    def test_environment_fingerprint_records_fixed_host_eligibility(self):
        fingerprint = (ROOT / "tools" / "bench" / "env_fingerprint.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("BENCH_HOST_ID", fingerprint)
        self.assertIn('"arch"', fingerprint)
        self.assertIn('"host_id"', fingerprint)
        self.assertIn('"perf_cycles"', fingerprint)
        self.assertIn("perf stat -e cycles", fingerprint)

    def test_docs_require_complete_fixed_host_bundle_validation(self):
        readme = (ROOT / "tools" / "bench" / "README.md").read_text(
            encoding="utf-8"
        )
        design = (
            ROOT / "docs" / "archive" / "designs" / "UDP_PERF_BASELINE_DESIGN.md"
        ).read_text(
            encoding="utf-8"
        )
        for document in (readme, design):
            self.assertIn("cycles.json", document)
            self.assertIn("validate_baseline_bundle.py", document)
            self.assertIn("baseline-report.json", document)

    def test_e2e_harness_uses_frozen_config_and_json_output(self):
        runner = ROOT / "tools" / "bench" / "run_e2e.sh"
        config = ROOT / "tools" / "bench" / "appsettings.bench.json"

        self.assertTrue(runner.is_file())
        self.assertTrue(config.is_file())
        script = runner.read_text(encoding="utf-8")
        self.assertIn("appsettings.bench.json", script)
        self.assertIn("iperf3", script)
        self.assertIn("64 1400", script)
        self.assertIn("env_fingerprint.sh", script)
        self.assertIn("kill -0", script)
        self.assertIn("--connect-timeout", script)
        self.assertIn("BENCH_SERVER_WAIT", script)
        self.assertIn('timeout "$((DURATION + 15))" iperf3 -s', script)
        self.assertIn("validate_e2e.py", script)
        self.assertIn('BITRATE="${BENCH_BITRATE:-10M}"', script)
        self.assertIn('--bitrate "$BITRATE"', script)
        self.assertNotIn("--bitrate 0", script)
        self.assertIn('"$BITRATE" > "$OUT/e2e-$size.summary.json"', script)
        self.assertIn("BENCH_BITRATE must be a positive integer", script)

    def test_e2e_validator_rejects_iperf_errors_and_reports_pps(self):
        validator = ROOT / "tools" / "bench" / "validate_e2e.py"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            result.write_text(json.dumps({"error": "mapping failed"}), encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, validator, result, "100M"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, failed.returncode)

            result.write_text(
                json.dumps({"end": {"sum": {"seconds": 2, "packets": 100, "lost_packets": 1}}}),
                encoding="utf-8",
            )
            passed = subprocess.run(
                [sys.executable, validator, result, "100M"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, passed.returncode, passed.stderr)
            summary = json.loads(passed.stdout)
            self.assertEqual(50, summary["pps"])
            self.assertEqual("100M", summary["offered_bitrate"])

            invalid_bitrate = subprocess.run(
                [sys.executable, validator, result, "0"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, invalid_bitrate.returncode)


if __name__ == "__main__":
    unittest.main()
