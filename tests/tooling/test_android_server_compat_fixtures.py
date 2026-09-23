import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KEY_FLAGS = ("masked", "plaintext", "delta-encode", "shuffle-data")


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def load_android_default_key() -> dict:
    source = (ROOT / "android/lib/services/profile_store.dart").read_text(
        encoding="utf-8"
    )
    match = re.search(r"defaultJson\s*=\s*'''(.*?)'''", source, re.S)
    if match is None:
        raise AssertionError("ProfileStore.defaultJson block was not found")
    return json.loads(match.group(1))["key"]


class AndroidServerCompatFixtureTests(unittest.TestCase):
    def test_android_default_key_flags_are_explicitly_disabled(self) -> None:
        key = load_android_default_key()

        for flag in KEY_FLAGS:
            self.assertIs(key[flag], False)

    def test_android_key_fixture_matches_profile_store_key_fields(self) -> None:
        profile_key = load_android_default_key()
        fixture_key = load_json("tools/compat/android_default_key.json")

        for key, value in profile_key.items():
            self.assertEqual(value, fixture_key[key], key)

    def test_client_and_server_fixtures_use_android_default_key(self) -> None:
        android_key = load_json("tools/compat/android_default_key.json")

        for relative in ("tools/compat/server.json", "tools/compat/client_proxy.json"):
            with self.subTest(relative=relative):
                self.assertEqual(android_key, load_json(relative)["key"])

    def test_server_samples_document_android_compatible_flags(self) -> None:
        android_key = load_json("tools/compat/android_default_key.json")
        server_key = load_json("tools/compat/server.json")["key"]
        defaults_key = load_json("tools/compat/server_flag_defaults.json")["key"]
        minimal_key = load_json("appsettings-server-minimal.json")["key"]

        for flag in KEY_FLAGS:
            self.assertIs(server_key[flag], False)
            self.assertNotIn(flag, defaults_key)
            self.assertIs(minimal_key[flag], False)

        for key in ("kf", "protocol-key", "transport-key"):
            self.assertEqual(android_key[key], minimal_key[key])

    def test_linux_amd64_ci_runs_compat_smoke(self) -> None:
        workflow = (ROOT / ".github/workflows/build-linux-amd64.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Client/server Android-key compat smoke", workflow)
        self.assertIn("COMPAT_MODE=match", workflow)
        self.assertIn("COMPAT_MODE=mismatch", workflow)
        self.assertIn("tools/client_server_compat_smoke.sh", workflow)


if __name__ == "__main__":
    unittest.main()
