import hashlib
import tempfile
import unittest
from pathlib import Path

from tools import check_runtime_fixture_hashes


class RuntimeFixtureHashTests(unittest.TestCase):
    def fixture(self, files: dict[str, str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents.encode("utf-8"))
        return root

    def test_hash_mismatch_is_rejected(self) -> None:
        root = self.fixture(
            {
                "tests/contracts/runtime-snapshot/idle.json": "{}\n",
                "tests/contracts/runtime-snapshot/SHA256SUMS": "bad  idle.json\n",
                "tests/cpp/CMakeLists.txt": "tests/contracts/runtime-snapshot",
                "android/test/runtime_snapshot_test.dart": "../tests/contracts/runtime-snapshot/",
                "ios/App/Tests/OpenPPP2LogicTests/RuntimeSnapshotTests.swift": (
                    'appendingPathComponent("tests")\n'
                    'appendingPathComponent("contracts")\n'
                    'appendingPathComponent("runtime-snapshot")\n'
                ),
            }
        )
        violations = check_runtime_fixture_hashes.check_repository(root)
        self.assertTrue(any("fixture hash mismatch" in item for item in violations))

    def test_canonical_loaders_and_hash_pass(self) -> None:
        body = "{}\n"
        digest = hashlib.sha256(body.encode()).hexdigest()
        root = self.fixture(
            {
                "tests/contracts/runtime-snapshot/idle.json": body,
                "tests/contracts/runtime-snapshot/SHA256SUMS": f"{digest}  idle.json\n",
                "tests/cpp/CMakeLists.txt": "tests/contracts/runtime-snapshot",
                "android/test/runtime_snapshot_test.dart": "../tests/contracts/runtime-snapshot/",
                "ios/App/Tests/OpenPPP2LogicTests/RuntimeSnapshotTests.swift": (
                    'appendingPathComponent("tests")\n'
                    'appendingPathComponent("contracts")\n'
                    'appendingPathComponent("runtime-snapshot")\n'
                ),
            }
        )
        self.assertEqual([], check_runtime_fixture_hashes.check_repository(root))


if __name__ == "__main__":
    unittest.main()
