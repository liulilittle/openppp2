import unittest
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    def test_release_requires_latest_same_sha_build_and_ci_runs(self):
        for workflow in (
            "build-android.yml",
            "build-linux-amd64.yml",
            "build-linux-cross.yml",
            "build-macos.yml",
            "build-windows-x64.yml",
            "build-windows-arm64.yml",
            "build-go-guardian.yml",
            "test.yml",
            "docs.yml",
            "test-linux-coverage.yml",
        ):
            self.assertIn(f'"{workflow}"', self.workflow)

        self.assertIn('--commit="$RELEASE_SHA"', self.workflow)
        self.assertIn("--limit=1", self.workflow)
        self.assertIn("--json headSha,conclusion", self.workflow)
        self.assertIn('"$conclusion" != "success"', self.workflow)
        self.assertNotIn("--status=success", self.workflow)

    def test_build_downloads_require_nonempty_packages_and_android_apk(self):
        self.assertIn('gh run download "$run_id" --dir "$artifact_dir"', self.workflow)
        self.assertIn("produced no distributable archives", self.workflow)
        self.assertIn('if [[ ! -s "$package" ]]', self.workflow)
        self.assertIn("Android release APK is missing or empty", self.workflow)
        self.assertIn("find artifacts/build-android -type f -name '*.apk' -size +0c", self.workflow)

    def test_assets_reject_duplicate_names_and_publish_checksums(self):
        self.assertIn("declare -A seen_names=()", self.workflow)
        self.assertIn("Duplicate release asset basename", self.workflow)
        self.assertIn("sha256sum -- * > SHA256SUMS.txt", self.workflow)
        self.assertIn("files: release-assets/*", self.workflow)
        self.assertIn("fail_on_unmatched_files: true", self.workflow)

    def test_release_requires_exact_32_asset_matrix(self):
        start = self.workflow.index("required_package_assets=(")
        end = self.workflow.index("\n          )", start)
        manifest = self.workflow[start:end]
        actual = re.findall(r'"([^"]+)"', manifest)

        expected = ["app-release.apk"]
        expected.extend(f"guardian-{os}-{arch}.{extension}" for os, arch, extension in (
            ("linux", "amd64", "tar.gz"),
            ("linux", "arm64", "tar.gz"),
            ("darwin", "amd64", "tar.gz"),
            ("darwin", "arm64", "tar.gz"),
            ("windows", "amd64", "zip"),
        ))
        expected.extend(f"openppp2-android-{abi}.zip" for abi in (
            "arm64-v8a", "armeabi-v7a", "x86", "x86_64",
        ))
        expected.extend(f"openppp2-darwin-{arch}.zip" for arch in ("arm64", "x86_64"))
        expected.extend(f"openppp2-darwin-{arch}-asan.zip" for arch in ("arm64", "x86_64"))
        expected.extend(
            f"openppp2-linux-{arch}-cross.zip"
            for arch in ("aarch64", "armv7l", "riscv64", "ppc64el", "s390x", "mipsel")
        )
        expected.extend(
            f"openppp2-linux-amd64{suffix}.zip"
            for suffix in (
                "", "-io-uring", "-simd", "-tc", "-tc-io-uring",
                "-tc-simd", "-io-uring-simd", "-tc-io-uring-simd",
                "-debian10", "-asan",
            )
        )
        expected.extend((
            "openppp2-windows-x64-Release.zip",
            "openppp2-windows-ARM64-Release.zip",
        ))

        self.assertEqual(len(expected), 32)
        self.assertEqual(actual, expected)
        self.assertIn("exactly 32 assets", self.workflow)
        self.assertIn("Required release package is missing or empty", self.workflow)
        self.assertIn("Expected exactly ${#required_package_assets[@]} package assets", self.workflow)

    def test_expected_asset_names_follow_current_build_packaging(self):
        workflows = {
            name: (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            for name in (
                "build-android.yml",
                "build-linux-amd64.yml",
                "build-linux-cross.yml",
                "build-macos.yml",
                "build-windows-x64.yml",
                "build-windows-arm64.yml",
                "build-go-guardian.yml",
            )
        }
        self.assertIn("ARTIFACT=openppp2-android-${{ matrix.abi }}.zip", workflows["build-android.yml"])
        self.assertIn("path: android/build/app/outputs/flutter-apk/app-release.apk", workflows["build-android.yml"])
        self.assertIn('ARTIFACT="guardian-${SUFFIX}.tar.gz"', workflows["build-go-guardian.yml"])
        self.assertIn('echo "ARTIFACT=guardian-${SUFFIX}.zip"', workflows["build-go-guardian.yml"])
        self.assertIn("ARTIFACT=openppp2-darwin-${{ matrix.arch }}.zip", workflows["build-macos.yml"])
        self.assertIn("ARTIFACT=openppp2-darwin-${{ matrix.arch }}-asan.zip", workflows["build-macos.yml"])
        self.assertIn('ARTIFACT="openppp2-${PLATFORM_SAFE}-cross.zip"', workflows["build-linux-cross.yml"])
        self.assertIn('ARTIFACT="openppp2-linux-amd64${{ matrix.suffix }}.zip"', workflows["build-linux-amd64.yml"])
        self.assertIn('ARTIFACT="openppp2-linux-amd64-debian10.zip"', workflows["build-linux-amd64.yml"])
        self.assertIn('ARTIFACT="openppp2-linux-amd64-asan.zip"', workflows["build-linux-amd64.yml"])
        self.assertIn('"openppp2-windows-${{ matrix.platform }}-${{ matrix.configuration }}.zip"', workflows["build-windows-x64.yml"])
        self.assertIn('"openppp2-windows-${{ matrix.platform }}-${{ matrix.configuration }}.zip"', workflows["build-windows-arm64.yml"])

    def test_asan_archives_are_retained_and_labeled_diagnostic(self):
        self.assertIn("-name '*.zip'", self.workflow)
        self.assertIn("ASan archives are diagnostic builds", self.workflow)
        self.assertNotIn("*-asan.zip", self.workflow)

    def test_published_release_retries_require_identical_assets(self):
        self.assertIn("id: published", self.workflow)
        self.assertIn("if: steps.published.outputs.reuse != 'true'", self.workflow)
        self.assertIn(".tag_name == $tag and .draft == false", self.workflow)
        self.assertIn("--paginate --slurp", self.workflow)
        self.assertIn("diff -u expected-assets.tsv published-assets.tsv", self.workflow)
        self.assertIn(".digest", self.workflow)
        self.assertIn("Published release type differs", self.workflow)
        self.assertIn("REUSE_PUBLISHED: ${{ steps.published.outputs.reuse }}", self.workflow)
        self.assertLess(self.workflow.index("Remote tag changed before publication"),
                        self.workflow.index('if [[ "$REUSE_PUBLISHED" == "true" ]]'))

    def test_remote_tag_sha_is_verified_before_checkout_release_and_publication(self):
        self.assertIn("ref: ${{ inputs.tag }}", self.workflow)
        self.assertIn('git rev-parse --verify "refs/tags/${RELEASE_TAG}^{commit}"', self.workflow)
        self.assertIn('repos/${GITHUB_REPOSITORY}/git/ref/tags/${RELEASE_TAG}', self.workflow)
        self.assertIn("Remote tag points to", self.workflow)
        self.assertIn("Remote tag changed before publication", self.workflow)
        self.assertIn("draft: true", self.workflow)
        self.assertIn("id: draft", self.workflow)
        self.assertIn("RELEASE_ID: ${{ steps.draft.outputs.id }}", self.workflow)
        self.assertIn('[[ ! "$RELEASE_ID" =~ ^[0-9]+$ ]]', self.workflow)
        self.assertIn('releases/${RELEASE_ID}', self.workflow)
        self.assertNotIn('releases/tags/${RELEASE_TAG}', self.workflow)
        self.assertIn('-F draft=false', self.workflow)
        self.assertLess(
            self.workflow.index("Remote tag changed before publication"),
            self.workflow.index("-F draft=false"),
        )


if __name__ == "__main__":
    unittest.main()
