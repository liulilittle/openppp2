import os
import tempfile
import unittest
from unittest import mock

from tools.xtcp_ul_stall_input import EvidenceError, finite_number, integer, load_document, sampling_role


class XtcpUlStallInputTests(unittest.TestCase):
    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(text)
        handle.close()
        return handle.name

    def load_text(self, text):
        with mock.patch("builtins.open", mock.mock_open(read_data=text)):
            return load_document("evidence.json")

    def document(self, **overrides):
        doc = {
            "start": {
                "test_start": {"protocol": "TCP", "reverse": 0, "num_streams": 2},
                "connected": [{"socket": 7}, {"socket": 3}],
            }
        }
        doc["start"].update(overrides.pop("start_overrides", {}))
        doc.update(overrides)
        return doc

    def test_load_document_accepts_object(self):
        path = self.write('{"value": 1}')
        self.assertEqual(load_document(path), {"value": 1})

    def test_load_document_preserves_real_temp_input(self):
        text = '{"value": 1.000337, "start": {"test_start": {}}}'
        path = self.write(text)
        self.assertEqual(load_document(path), {"value": 1.000337, "start": {"test_start": {}}})
        with open(path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), text)

    def test_load_document_rejects_missing_file(self):
        with self.assertRaises(EvidenceError):
            load_document(os.path.join(tempfile.gettempdir(), "does-not-exist-here"))

    def test_load_document_rejects_non_object_root(self):
        with self.assertRaises(EvidenceError):
            load_document(self.write("[]"))

    def test_load_document_rejects_duplicate_keys(self):
        with self.assertRaises(EvidenceError):
            load_document(self.write('{"a": 1, "a": 2}'))

    def test_load_document_rejects_invalid_json_and_constant(self):
        with self.assertRaises(EvidenceError):
            load_document(self.write("{"))
        with self.assertRaises(EvidenceError):
            load_document(self.write('{"value": NaN}'))

    def test_load_document_rejects_json_infinity(self):
        for text in ('{"value": 1e400}', '{"value": -1e400}'):
            with self.assertRaises(EvidenceError):
                self.load_text(text)

    def test_load_document_accepts_finite_floats(self):
        cases = (
            ('{"value": 1.000337}', 1.000337),
            ('{"value": 0.0}', 0.0),
            ('{"value": -0.5}', -0.5),
        )
        for text, expected in cases:
            self.assertEqual(self.load_text(text), {"value": expected})

    def test_load_document_rejects_nested_json_infinity(self):
        with self.assertRaises(EvidenceError):
            self.load_text('{"start": {"test_start": {"value": 1e400}}}')

    def test_load_document_rejects_unicode_and_parse_exceptions(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="")) as opened:
            opened.return_value.__enter__.return_value.read.side_effect = UnicodeError("bad")
            with self.assertRaises(EvidenceError):
                load_document("evidence.json")
        with mock.patch("tools.xtcp_ul_stall_input.json.load") as loaded:
            loaded.side_effect = RecursionError("too deep")
            with mock.patch("builtins.open", mock.mock_open(read_data="{}")):
                with self.assertRaises(EvidenceError) as context:
                    load_document("evidence.json")
            self.assertTrue(loaded.called)
            self.assertIsInstance(context.exception.__cause__, RecursionError)

    def test_finite_number_accepts_modes(self):
        self.assertEqual(finite_number(1.5, "value"), 1.5)
        self.assertEqual(finite_number(2, "value", positive=True), 2)
        self.assertEqual(finite_number(0, "value"), 0)

    def test_finite_number_rejects_bad_types(self):
        for value in (True, "1", float("nan"), float("inf"), -1):
            with self.assertRaises(EvidenceError):
                finite_number(value, "value")
        for value in (False, 0, "2", float("nan")):
            with self.assertRaises(EvidenceError):
                finite_number(value, "value", positive=True)

    def test_finite_number_preserves_arbitrary_precision_integers(self):
        large = 10 ** 400
        self.assertEqual(finite_number(large, "value"), large)
        self.assertEqual(finite_number(large, "value", positive=True), large)
        for value in (-large, -10 ** 400):
            with self.assertRaises(EvidenceError):
                finite_number(value, "value")
            with self.assertRaises(EvidenceError):
                finite_number(value, "value", positive=True)

    def test_integer_rejects_non_natural_values(self):
        self.assertEqual(integer(3, "socket"), 3)
        for value in (True, False, 1.0, "3", -1):
            with self.assertRaises(EvidenceError):
                integer(value, "socket")

    def test_sampling_role_accepts_zero_false_and_omitted_bidir(self):
        doc = self.document()
        self.assertEqual(sampling_role(doc), [7, 3])
        doc["start"]["test_start"]["reverse"] = False
        doc["start"]["test_start"]["bidir"] = False
        self.assertEqual(sampling_role(doc), [7, 3])

    def test_sampling_role_extracts_connected_socket_objects(self):
        doc = {
            "start": {
                "test_start": {"protocol": "TCP", "reverse": 0, "num_streams": 2},
                "connected": [{"socket": 5}, {"socket": 7}],
            }
        }
        self.assertEqual(sampling_role(doc), [5, 7])

    def test_sampling_role_accepts_connection_metadata(self):
        metadata = {
            "local_host": "127.0.0.1",
            "local_port": 5001,
            "remote_host": "127.0.0.1",
            "remote_port": 6001,
        }
        doc = self.document(
            start_overrides={
                "connected": [{"socket": 5, **metadata}, {"socket": 7, **metadata}]
            }
        )
        self.assertEqual(sampling_role(doc), [5, 7])

    def test_sampling_role_rejects_protocol_reverse_bidir(self):
        for field, value in (
            ("protocol", "UDP"),
            ("reverse", True),
            ("reverse", 1),
            ("reverse", None),
            ("bidir", True),
            ("bidir", 1),
        ):
            doc = self.document()
            doc["start"]["test_start"][field] = value
            with self.assertRaises(EvidenceError):
                sampling_role(doc)

    def test_sampling_role_rejects_stream_shape(self):
        cases = (
            (2, [1]),
            (2, [1, 1]),
            (2, [{"socket": 1}, {"socket": 1}]),
            (2, [{"socket": 0}, {"socket": -1}]),
            (2, [{"socket": 1}, 2]),
            (2, [{"socket": 1}, {}]),
            (2, [{"socket": 1}, {"port": 2}]),
            (2, [{"socket": 1}, {"socket": "2"}]),
            (2, [{"socket": 1}, {"socket": True}]),
            (2, [{"socket": 1}, {"socket": 1.0}]),
            (True, [{"socket": 0}, {"socket": 0}]),
            ("2", [{"socket": 0}, {"socket": 0}]),
        )
        for streams, sockets in cases:
            doc = self.document()
            doc["start"]["test_start"]["num_streams"] = streams
            doc["start"]["connected"] = sockets
            with self.assertRaises(EvidenceError):
                sampling_role(doc)

    def test_sampling_role_rejects_non_object_fields(self):
        with self.assertRaises(EvidenceError):
            sampling_role(self.document(start_overrides={"test_start": []}))
        with self.assertRaises(EvidenceError):
            sampling_role(self.document(start_overrides={"connected": {"0": 0}}))

    def test_sampling_role_rejects_non_object_documents(self):
        for document in ([], None, "object"):
            with self.assertRaises(EvidenceError):
                sampling_role(document)
