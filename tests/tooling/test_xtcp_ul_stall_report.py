import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.xtcp_ul_stall_report import analyze_document, main


def document(counts=None, boundaries=None):
    counts = counts or [[10, 10, 10], [10, 10, 10]]
    boundaries = boundaries or list(range(len(counts[0]) + 1))
    sockets = [5 + 2*i for i in range(len(counts))]
    rows = []
    for index in range(len(boundaries) - 1):
        rows.append({"streams": [
            {"socket": socket, "start": boundaries[index], "end": boundaries[index + 1],
             "bytes": counts[i][index], "sender": True, "omitted": False}
            for i, socket in enumerate(sockets)]})
    return {
        "start": {"test_start": {"protocol": "TCP", "reverse": 0,
                                  "num_streams": len(sockets), "duration": boundaries[-1]},
                  "connected": [{"socket": socket, "local_host": "127.0.0.1"} for socket in sockets]},
        "intervals": rows,
        "end": {"streams": [
            {"sender": {"socket": socket, "start": 0, "end": boundaries[-1],
                        "bytes": sum(counts[i]), "sender": True}}
            for i, socket in enumerate(sockets)]},
    }


class StallReportTests(unittest.TestCase):
    def assert_invalid(self, doc, text=None):
        report = analyze_document(doc)
        self.assertEqual(report["status"], "not_assessed", report)
        self.assertTrue(report["reasons"])
        self.assertEqual(report["flows"], [])
        self.assertIsNone(report["fairness"])
        if text:
            self.assertIn(text, report["reasons"][0])

    def test_progress_and_fairness(self):
        result = analyze_document(document())
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertEqual(result["sampling_side"], "sender")
        self.assertEqual(result["fairness"]["overall_jain"], 1)
        self.assertEqual(len(result["fairness"]["intervals"]), 3)

    def test_mid_run_stall_nonzero_total(self):
        result = analyze_document(document([[10, 0, 0, 10], [10]*4]))
        self.assertEqual(result["status"], "observed_stall")
        self.assertEqual(result["flows"][0]["max_zero_seconds"], 2)
        self.assertEqual(result["flows"][0]["bytes"], 20)

    def test_unequal_sampling_lengths(self):
        result = analyze_document(document([[1, 0, 0]], [0, 0.5, 1.3, 2.5]))
        self.assertEqual(result["status"], "observed_stall")
        self.assertEqual(result["flows"][0]["measured_seconds"], 2.5)

    def test_below_threshold_not_rounded_up(self):
        result = analyze_document(document([[1, 0]], [0, 1, 2.999999]))
        self.assertEqual(result["status"], "no_observed_stall")

    def test_positive_interval_breaks_zero_run(self):
        result = analyze_document(document([[0, 1, 0]]))
        self.assertEqual(result["flows"][0]["max_zero_seconds"], 1)
        self.assertEqual(result["status"], "no_observed_stall")

    def test_tolerated_overlap_not_counted_twice(self):
        doc = document([[1, 0, 0]], [0, 1, 2, 2.9999995])
        doc["intervals"][2]["streams"][0]["start"] = 1.9999995
        result = analyze_document(doc)
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertLess(result["flows"][0]["max_zero_seconds"], 2)

    def test_tolerated_gap_not_counted_as_zero_observation(self):
        doc = document([[1, 0, 0]], [0, 1, 2, 3])
        doc["intervals"][2]["streams"][0]["start"] = 2.0000005
        result = analyze_document(doc)
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertLess(result["flows"][0]["max_zero_seconds"], 2)

    def test_unfair_but_nonzero(self):
        result = analyze_document(document([[1000]*3, [1]*3]))
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertLess(result["fairness"]["overall_jain"], 0.51)

    def test_all_zero_jain_undefined(self):
        result = analyze_document(document([[0]*3, [0]*3]))
        self.assertEqual(result["status"], "observed_stall")
        self.assertIsNone(result["fairness"]["overall_jain"])

    def test_omit_reset_excluded(self):
        doc = document()
        warmup = copy.deepcopy(doc["intervals"][0])
        for stream in warmup["streams"]:
            stream.update(start=0, end=10, omitted=True, bytes=999999)
        doc["intervals"].insert(0, warmup)
        result = analyze_document(doc)
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertEqual(result["flows"][0]["bytes"], 30)

    def test_omit_after_measurement_rejected(self):
        doc = document()
        doc["intervals"][1]["streams"][0]["omitted"] = True
        self.assert_invalid(doc, "omit after")

    def test_row_stream_order_not_identity(self):
        doc = document([[0, 0, 10], [10]*3])
        doc["intervals"][1]["streams"].reverse()
        result = analyze_document(doc)
        self.assertEqual(result["flows"][0]["socket"], 5)
        self.assertTrue(result["flows"][0]["observed_stall"])

    def test_missing_duplicate_unknown_socket(self):
        for mode in ("missing", "duplicate", "unknown"):
            doc = document()
            values = doc["intervals"][1]["streams"]
            if mode == "missing":
                values.pop()
            else:
                values[1]["socket"] = 5 if mode == "duplicate" else 99
            self.assert_invalid(doc)

    def test_missing_head_tail_and_middle(self):
        for index in (0, 1, 2):
            doc = document()
            doc["intervals"].pop(index)
            self.assert_invalid(doc)

    def test_summary_cannot_hide_short_run(self):
        doc = document()
        doc["intervals"].pop()
        for entry in doc["end"]["streams"]:
            entry["sender"].update(end=2, bytes=20)
        self.assert_invalid(doc, "head/tail")

    def test_gap_overlap_and_unordered(self):
        for start in (1.00001, 0.99999, 0):
            doc = document()
            doc["intervals"][1]["streams"][0]["start"] = start
            self.assert_invalid(doc)
        doc = document()
        doc["intervals"].reverse()
        self.assert_invalid(doc)

    def test_missing_summary_and_mismatched_bytes(self):
        doc = document()
        del doc["end"]
        self.assert_invalid(doc)
        doc = document()
        doc["end"]["streams"][0]["sender"]["bytes"] += 1
        self.assert_invalid(doc, "byte mismatch")

    def test_summary_socket_integrity(self):
        for change in ("missing", "duplicate", "unknown"):
            doc = document()
            values = doc["end"]["streams"]
            if change == "missing":
                values.pop()
            else:
                values[1]["sender"]["socket"] = 5 if change == "duplicate" else 99
            self.assert_invalid(doc)

    def test_sender_and_omit_are_required_booleans(self):
        for field, value in (("sender", False), ("sender", 1), ("sender", None),
                             ("omitted", 0), ("omitted", None)):
            doc = document()
            doc["intervals"][0]["streams"][0][field] = value
            self.assert_invalid(doc)

    def test_bad_numeric_fields(self):
        for field in ("start", "end", "bytes"):
            for value in (-1, True, None, "1", float("nan"), float("inf"), 10**400):
                doc = document()
                doc["intervals"][0]["streams"][0][field] = value
                self.assert_invalid(doc)

    def test_no_valid_measurement(self):
        for doc in ({}, [], None, {"error": "failed"}):
            self.assert_invalid(doc)
        doc = document()
        for row in doc["intervals"]:
            for stream in row["streams"]:
                stream["omitted"] = True
        self.assert_invalid(doc)

    def test_unaligned_fairness_not_interpolated(self):
        doc = document()
        doc["intervals"][0]["streams"][1]["end"] = 1.01
        doc["intervals"][1]["streams"][1]["start"] = 1.01
        result = analyze_document(doc)
        self.assertEqual(result["status"], "no_observed_stall")
        self.assertEqual(result["fairness"]["overall_jain"], 1)
        self.assertEqual(result["fairness"]["interval_status"], "not_assessed")
        self.assertEqual(result["fairness"]["intervals"], [])

    def test_threshold_validation(self):
        for value in (0, -1, True, None, float("inf"), float("nan"), 10**400):
            result = analyze_document(document(), value)
            self.assertEqual(result["status"], "not_assessed")
            json.dumps(result, allow_nan=False)

    def test_cli_exit_codes_and_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "iperf.json"
            for doc, code in ((document(), 0), (document([[0]*3]), 1), ({}, 2)):
                raw = json.dumps(doc).encode()
                path.write_bytes(raw)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main([str(path)]), code)
                self.assertEqual(json.loads(output.getvalue())["schema_version"], 1)
                self.assertEqual(path.read_bytes(), raw)
            path.write_text('{"broken":', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main([str(path)]), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "not_assessed")

    def test_cli_invalid_arguments_are_json(self):
        for args in ([], ["--bad"], ["missing", "--stall-seconds", "wrong"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(args), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "not_assessed")

    def test_standalone_cli_import(self):
        script = Path(__file__).resolve().parents[2] / "tools/xtcp_ul_stall_report.py"
        completed = subprocess.run([sys.executable, str(script), "missing.json"],
                                   capture_output=True, text=True, cwd=tempfile.gettempdir())
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "not_assessed")

    def test_malformed_shapes_always_produce_json_report(self):
        paths = [
            ["start"], ["start", "test_start"], ["start", "test_start", "duration"],
            ["intervals"], ["intervals", 0], ["intervals", 0, "streams"],
            ["intervals", 0, "streams", 0], ["intervals", 0, "streams", 0, "start"],
            ["intervals", 0, "streams", 0, "end"], ["intervals", 0, "streams", 0, "bytes"],
            ["end"], ["end", "streams"], ["end", "streams", 0],
            ["end", "streams", 0, "sender"],
        ]
        values = [None, False, True, {}, [], [{}], -1, 0, 1, 1.5, "1",
                  float("nan"), float("inf"), 10**400]
        for path in paths:
            for value in values:
                with self.subTest(path=path, value=value):
                    doc = document()
                    parent = doc
                    for key in path[:-1]:
                        parent = parent[key]
                    parent[path[-1]] = value
                    report = analyze_document(doc)
                    self.assertIn(report["status"],
                                  ("no_observed_stall", "observed_stall", "not_assessed"))
                    json.dumps(report, allow_nan=False)

    def test_document_not_mutated(self):
        doc = document([[10, 0, 0], [10]*3])
        original = copy.deepcopy(doc)
        analyze_document(doc)
        self.assertEqual(doc, original)


if __name__ == "__main__":
    unittest.main()
