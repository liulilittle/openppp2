import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('metadata', Path(__file__).resolve().parents[2] / 'tools/datapath_matrix_metadata.py')
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class FrozenSourceTest(unittest.TestCase):
    def test_snapshot_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.cpp'
            source.write_bytes(b'example')
            binary = root / 'ppp'
            binary.write_bytes(b'not executable')
            manifest = root / 'manifest.json'
            value = dict(files={'source.cpp': hashlib.sha256(source.read_bytes()).hexdigest()},
                         binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                         git={}, xtcp={}, archive_sha256='example')
            manifest.write_text(json.dumps(value))
            with patch.dict(os.environ, OPENPPP2_FROZEN_SOURCE_MANIFEST=str(manifest)):
                result = metadata.collect_version_fingerprint(root, binary)
                self.assertEqual(result['frozen_source']['file_count'], 1)
                source.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'source mismatch'):
                    metadata.collect_version_fingerprint(root, binary)
                source.write_bytes(b'example')
                binary.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'binary mismatch'):
                    metadata.collect_version_fingerprint(root, binary)
                value['files'] = {'../outside': 'example'}
                manifest.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'invalid frozen source path'):
                    metadata.collect_version_fingerprint(root, binary)
                value['files'] = {}
                manifest.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'empty frozen'):
                    metadata.collect_version_fingerprint(root, binary)


if __name__ == '__main__':
    unittest.main()
