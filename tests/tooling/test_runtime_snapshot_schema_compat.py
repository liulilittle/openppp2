import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class RuntimeSnapshotSchemaCompatibilityTests(unittest.TestCase):
    def test_v1_keeps_legacy_p2p_strings_forward_compatible(self):
        schema = json.loads(
            (ROOT / "schemas/runtime-snapshot-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )

        for field in ("p2p_state", "effective_path"):
            definition = schema["properties"][field]
            self.assertEqual(definition["type"], "string")
            self.assertNotIn("enum", definition)


if __name__ == "__main__":
    unittest.main()
