import tempfile
import unittest
from pathlib import Path

from tools import check_docs


class DocumentationChecksTests(unittest.TestCase):
    def fixture(self, files: dict[str, str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root

    def assert_violation(self, root: Path, expected: str) -> None:
        violations = check_docs.check_repository(root)
        self.assertTrue(
            any(expected in violation for violation in violations),
            f"missing {expected!r} in {violations!r}",
        )

    def test_design_requires_metadata(self) -> None:
        root = self.fixture({"docs/design/NEW.md": "# New design\n"})
        self.assert_violation(root, "missing document metadata")

    def test_broken_relative_link_is_rejected(self) -> None:
        root = self.fixture(
            {
                "docs/README.md": "[missing](MISSING.md)\n",
            }
        )
        self.assert_violation(root, "broken relative link")

    def test_document_map_requires_both_language_files(self) -> None:
        root = self.fixture(
            {
                "docs/README.md": (
                    "| Runtime | [English](RUNTIME.md) | [Chinese](RUNTIME_CN.md) |\n"
                ),
                "docs/RUNTIME.md": "# Runtime\n",
            }
        )
        self.assert_violation(root, "missing bilingual document")

    def test_grandfathered_metadata_debt_is_exact_path(self) -> None:
        root = self.fixture(
            {
                "docs/design/OLD.md": "# Old design\n",
                "docs/governance/METADATA_GRANDFATHERED.txt": (
                    "docs/design/OLD.md\n"
                ),
            }
        )
        self.assertEqual([], check_docs.check_repository(root))


if __name__ == "__main__":
    unittest.main()
