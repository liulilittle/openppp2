import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CIWorkspacePermissionTests(unittest.TestCase):
    def workflow(self) -> str:
        return (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")

    def test_namespace_artifact_directory_exists_before_sudo(self) -> None:
        workflow = self.workflow()
        step = workflow[
            workflow.index("- name: Linux namespace Route/DNS rollback") :
            workflow.index("- name: Upload Route/DNS rollback snapshots")
        ]
        create = step.index('mkdir -p "$PWD/build/route-dns-rollback"')
        privileged = step.index("sudo OPENPPP2_NAMESPACE_ARTIFACT_DIR=")
        self.assertLess(create, privileged)

    def test_workspace_permission_regression_runs_in_ci(self) -> None:
        self.assertIn(
            "python3 -m unittest tests.tooling.test_ci_workspace_permissions -v",
            self.workflow(),
        )


if __name__ == "__main__":
    unittest.main()
