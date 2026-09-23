import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_release_publishes_only_nonempty_distributable_assets(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("find artifacts -type f -size +0c", workflow)
        self.assertIn("-name '*.zip'", workflow)
        self.assertIn("-name '*.tar.gz'", workflow)
        self.assertIn("-name '*.apk'", workflow)
        self.assertIn("files: release-assets/*", workflow)
        self.assertIn("fail_on_unmatched_files: true", workflow)
        self.assertNotIn("files: artifacts/**/*", workflow)

    def test_release_assets_are_built_from_the_tag_commit(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("actions: read", workflow)
        self.assertIn("ref: ${{ inputs.tag }}", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn('git rev-parse --verify "refs/tags/${RELEASE_TAG}^{commit}"', workflow)
        self.assertIn('--commit="$RELEASE_SHA"', workflow)
        self.assertIn('run_sha=$(gh run view "$run_id" --json headSha', workflow)
        self.assertIn("target_commitish: ${{ steps.release.outputs.tag_sha }}", workflow)
        self.assertIn("No successful $workflow run found", workflow)
        self.assertNotIn("--branch=main", workflow)
        self.assertNotIn('|| echo "No artifacts for $workflow"', workflow)


if __name__ == "__main__":
    unittest.main()
