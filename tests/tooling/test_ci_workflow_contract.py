import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def load_lifecycle_summary_module():
    path = ROOT / "tools" / "write_network_lifecycle_summary.py"
    spec = importlib.util.spec_from_file_location("network_lifecycle_summary", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_lifecycle_validator_module():
    path = ROOT / "tools" / "verify_network_lifecycle_summary.py"
    spec = importlib.util.spec_from_file_location("network_lifecycle_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CIWorkflowContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_network_lifecycle_contracts_run_in_linux_unit_job(self) -> None:
        workflow = self.read("test.yml")
        required_commands = (
            "tests.tooling.test_windows_dns_snapshot_contract",
            "tests.tooling.test_windows_network_resource_contract",
            "tests.tooling.test_windows_ipv6_contract",
            "tests.tooling.test_lifecycle_wiring",
            "tests.tooling.test_ci_workflow_contract",
        )
        for command in required_commands:
            self.assertIn(command, workflow)

    def test_cpp_and_desktop_jobs_have_build_and_test_gates(self) -> None:
        workflow = self.read("test.yml")
        self.assertIn("cmake -S tests/cpp -B build/test", workflow)
        self.assertIn("ctest --test-dir build/test --output-on-failure", workflow)
        self.assertIn("npm test", workflow)
        self.assertIn("npm run build", workflow)
        self.assertIn("cargo test --locked --manifest-path src-tauri/Cargo.toml", workflow)
        self.assertIn("os: [ubuntu-24.04, windows-2022]", workflow)

    def test_upstream_xtcp_suite_is_blocking_with_one_retry(self) -> None:
        workflow = self.read("test.yml")
        start = workflow.index("      - name: Run upstream XTCP suite")
        end = workflow.index("      - name:", start + 1)
        step = workflow[start:end]
        self.assertIn("--repeat until-pass:2", step)
        self.assertNotIn("continue-on-error", step)

    def test_lifecycle_sanitizers_cover_durable_recovery_and_ownership(self) -> None:
        script = (ROOT / "scripts" / "run-lifecycle-sanitizers.sh").read_text(
            encoding="utf-8"
        )
        for target in (
            "network_recovery_journal_test",
            "network_ownership_test",
            "route_coordinator_test",
            "route_snapshot_contract_test",
            "windows_route_snapshot_test",
            "route_platform_adapters_test",
            "linux_route_platform_contract_test",
        ):
            self.assertGreaterEqual(script.count(target), 2)
        self.assertIn("ENABLE_SANITIZERS=ON", script)

    def test_lifecycle_acceptance_summary_is_retained_even_on_failure(self) -> None:
        workflow = self.read("test.yml")
        self.assertIn("tools/write_network_lifecycle_summary.py", workflow)
        self.assertIn("tools/verify_network_lifecycle_summary.py", workflow)
        self.assertIn("JOB_STATUS: ${{ job.status }}", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("lifecycle-acceptance-summary", workflow)
        self.assertIn("if-no-files-found: error", workflow)

    def test_lifecycle_summary_marks_host_gaps_unverified(self) -> None:
        summary = load_lifecycle_summary_module()
        passed = summary.build_summary("success")
        self.assertEqual(passed["schema_version"], 1)
        evidence = {row["id"]: row for row in passed["evidence"]}
        self.assertEqual(evidence["offline-contracts"]["status"], "passed")
        self.assertEqual(evidence["linux-namespace-rollback"]["status"], "passed")
        self.assertEqual(evidence["windows-host-dns-route"]["status"], "unverified")
        self.assertEqual(evidence["macos-host-network"]["status"], "unverified")

        failed = summary.build_summary("failure")
        failed_evidence = {row["id"]: row for row in failed["evidence"]}
        self.assertEqual(failed_evidence["offline-contracts"]["status"], "failed")
        self.assertEqual(failed_evidence["linux-namespace-rollback"]["status"], "failed")
        self.assertEqual(failed_evidence["windows-host-dns-route"]["status"], "unverified")

    def test_release_validator_requires_passed_linux_and_unverified_host_gaps(self) -> None:
        summary_module = load_lifecycle_summary_module()
        validator = load_lifecycle_validator_module()
        self.assertEqual(validator.validate_summary(summary_module.build_summary("success")), [])

        invalid = summary_module.build_summary("success")
        evidence = {row["id"]: row for row in invalid["evidence"]}
        evidence["windows-host-dns-route"]["status"] = "passed"
        errors = validator.validate_summary(invalid)
        self.assertTrue(any("windows-host-dns-route must be unverified" in error for error in errors))

        invalid["job_status"] = "failure"
        errors = validator.validate_summary(invalid)
        self.assertTrue(any("job_status must be success" in error for error in errors))

    def test_release_requires_same_sha_success_and_complete_packages(self) -> None:
        workflow = self.read("release.yml")
        for required in (
            "build-windows-x64.yml",
            "build-windows-arm64.yml",
            "build-macos.yml",
            "test.yml",
            '[[ \"$run_sha\" != \"$RELEASE_SHA\" || \"$conclusion\" != \"success\" ]]',
            "if [[ ! -s \"release-assets/${name}\" ]]; then",
            "Expected exactly ${#required_package_assets[@]} package assets",
            "lifecycle-acceptance-summary",
            "tools/verify_network_lifecycle_summary.py",
            "Lifecycle acceptance summary is missing or empty",
        ):
            self.assertIn(required, workflow)

    def test_windows_x64_build_reports_missing_artifacts(self) -> None:
        workflow = self.read("build-windows-x64.yml")
        self.assertIn("pull_request:", workflow)
        self.assertIn("branches: [main, codex/runtime-ui-lifecycle-integration]", workflow)
        self.assertIn("if-no-files-found: error", workflow)

    def test_windows_arm64_is_explicitly_manual_or_main_only(self) -> None:
        workflow = self.read("build-windows-arm64.yml")
        self.assertIn("push:\n    branches: [main]", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)


if __name__ == "__main__":
    unittest.main()
