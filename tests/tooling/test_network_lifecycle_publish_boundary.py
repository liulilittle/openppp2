import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class NetworkLifecyclePublishBoundaryTests(unittest.TestCase):
    def test_lifecycle_documents_are_present(self) -> None:
        for relative in (
            "docs/architecture/NETWORK_LIFECYCLE_CONTRACT.md",
            "docs/architecture/NETWORK_LIFECYCLE_CONTRACT_CN.md",
            "docs/architecture/NETWORK_LIFECYCLE_ISSUES.md",
            "docs/design/NETWORK_ROUTE_JOURNAL_PERSISTENCE.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_new_cpp_sources_are_in_the_windows_project(self) -> None:
        project = (ROOT / "ppp.vcxproj").read_text(encoding="utf-8")
        for relative in (
            "ppp\\app\\client\\WindowsIPv6Snapshot.cpp",
            "ppp\\app\\client\\route\\WindowsRouteSnapshot.cpp",
            "ppp\\app\\client\\route\\WindowsRouteSnapshotWin32.cpp",
            "windows\\ppp\\win32\\network\\WindowsRouteSnapshotWin32.h",
        ):
            self.assertIn(relative, project)

    def test_new_cpp_sources_are_in_the_test_build(self) -> None:
        cmake = (ROOT / "tests/cpp/CMakeLists.txt").read_text(encoding="utf-8")
        for relative in (
            "WindowsIPv6Snapshot.cpp",
            "WindowsRouteSnapshot.cpp",
            "WindowsRouteSnapshotWin32.cpp",
            "windows_ipv6_snapshot_test.cpp",
            "windows_route_snapshot_test.cpp",
            "route_snapshot_contract_test.cpp",
        ):
            self.assertIn(relative, cmake)

    def test_ci_runs_lifecycle_contract_and_release_summary_gates(self) -> None:
        test_workflow = (ROOT / ".github/workflows/test.yml").read_text(
            encoding="utf-8"
        )
        release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("test_network_lifecycle_issue_pack", test_workflow)
        self.assertIn("write_network_lifecycle_summary.py", test_workflow)
        self.assertIn("verify_network_lifecycle_summary.py", test_workflow)
        self.assertIn("lifecycle-acceptance-summary", release_workflow)
        self.assertIn("verify_network_lifecycle_summary.py", release_workflow)


if __name__ == "__main__":
    unittest.main()
