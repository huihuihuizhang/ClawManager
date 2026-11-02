"""Isolated synthetic log tests; no network, Go build, SQL or credentials."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("system-backup-b-capture-timing.py")
SPEC = importlib.util.spec_from_file_location("b_capture_timing", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
PIN = "a" * 64


def fixture():
    return {
        "schema_version": "database-capture-timing.v1",
        "invocation_sha256": PIN,
        "candidate_returned": False,
        "samples": [
            {"stage": "key_check", "calls": 2, "failures": 1, "total_ns": 40, "max_ns": 25},
            {"stage": "worker_total", "calls": 1, "failures": 1, "total_ns": 100, "max_ns": 100},
        ],
        "original_key_window": {"known": True, "start_remaining_us": 1000, "end_remaining_us": -4},
        "source_window": {"known": False, "start_remaining_us": 0, "end_remaining_us": 0},
        "request_window": {"known": True, "start_remaining_us": 9000, "end_remaining_us": 8000},
    }


def line(report):
    return b"2026/11/02 fixture-prefix " + TOOL.MARKER + json.dumps(report).encode() + b"\n"


class TimingAnalysisTests(unittest.TestCase):
    def rejected(self, code, lines, pin=PIN):
        with self.assertRaises(TOOL.Rejected) as caught:
            TOOL.analyze_lines(lines, pin)
        self.assertEqual(str(caught.exception), code)

    def test_selects_original_pin_without_summing_parents_or_clamping_windows(self):
        other = fixture()
        other["invocation_sha256"] = "b" * 64
        result = TOOL.analyze_lines([b"unrelated private log bytes\n", line(other), line(fixture())], PIN)
        self.assertEqual(result["invocation_sha256"], PIN)
        self.assertEqual(result["unselected_report_count"], 1)
        self.assertFalse(result["sum_all_samples_valid"])
        self.assertFalse(result["authoritative_evidence"])
        self.assertFalse(result["full_chain_passed"])
        self.assertEqual(result["original_key_window"]["end_remaining_us"], -4)
        self.assertFalse(result["source_window"]["known"])
        self.assertEqual(result["samples"][0]["mean_ns"], 20)
        self.assertNotIn("private", json.dumps(result))

    def test_candidate_is_diagnostic_only(self):
        report = fixture()
        report["candidate_returned"] = True
        report["samples"][0]["failures"] = 0
        report["samples"][1]["failures"] = 0
        result = TOOL.analyze_lines([line(report)], PIN)
        self.assertTrue(result["candidate_returned"])
        self.assertTrue(result["diagnostic_only"])
        self.assertFalse(result["full_chain_passed"])

    def test_identical_copies_are_not_new_checks(self):
        report = fixture()
        result = TOOL.analyze_lines([line(report), line(report)], PIN)
        self.assertEqual(result["identical_report_copies"], 2)
        self.assertEqual(result["samples"][0]["calls"], 2)

    def test_conflicting_reports_for_same_pin_are_ambiguous(self):
        first, second = fixture(), fixture()
        second["samples"][0]["total_ns"] = 41
        self.rejected("ambiguous_invocation_reports", [line(first), line(second)])

    def test_does_not_infer_an_expected_pin(self):
        self.rejected("expected_report_missing", [line(fixture())], "b" * 64)
        self.rejected("invalid_expected_invocation_sha256", [line(fixture())], "PRIVATE_NOT_A_PIN")
        self.rejected("expected_report_missing", [b"[legacy-worker] complete=true\n"])

    def test_strict_schema_and_integer_contract(self):
        changes = [
            ("unsupported_schema", lambda r: r.update(schema_version="future.v2")),
            ("unexpected_fields", lambda r: r.update(password="PRIVATE")),
            ("invalid_invocation_sha256", lambda r: r.update(invocation_sha256=4)),
            ("invalid_candidate_flag", lambda r: r.update(candidate_returned=0)),
            ("invalid_samples", lambda r: r.update(samples=[])),
            ("invalid_or_duplicate_stage", lambda r: r["samples"][0].update(stage="PRIVATE_SQL")),
            ("invalid_or_duplicate_stage", lambda r: r["samples"].append(copy.deepcopy(r["samples"][0]))),
            ("invalid_integer", lambda r: r["samples"][0].update(calls=True)),
            ("invalid_integer", lambda r: r["samples"][0].update(calls=0)),
            ("invalid_integer", lambda r: r["samples"][0].update(calls=1 << 64)),
            ("invalid_integer", lambda r: r["samples"][0].update(failures=3)),
            ("invalid_integer", lambda r: r["samples"][0].update(total_ns=-1)),
            ("invalid_integer", lambda r: r["samples"][0].update(total_ns=1 << 63)),
            ("invalid_integer", lambda r: r["samples"][0].update(total_ns=1.0)),
            ("invalid_integer", lambda r: r["samples"][0].update(max_ns=41)),
            ("inconsistent_duration", lambda r: r["samples"][0].update(max_ns=19)),
            ("inconsistent_worker_total", lambda r: r["samples"].pop()),
            ("inconsistent_worker_total", lambda r: r["samples"][1].update(failures=0)),
            ("inconsistent_candidate_report", lambda r: (r.update(candidate_returned=True), r["samples"][1].update(failures=0))),
            ("invalid_window", lambda r: r["source_window"].update(known=1)),
            ("inferred_unknown_window", lambda r: r["source_window"].update(end_remaining_us=1)),
            ("invalid_integer", lambda r: r["original_key_window"].update(end_remaining_us=-(1 << 63)-1)),
        ]
        for code, change in changes:
            with self.subTest(code=code):
                report = fixture()
                change(report)
                self.rejected(code, [line(report)])

    def test_json_corruption_duplicate_fields_and_marker_ambiguity(self):
        self.rejected("duplicate_json_field", [TOOL.MARKER + b'{"samples":[],"samples":[]}'])
        self.rejected("duplicate_json_field", [TOOL.MARKER + b'{"x":{"known":true,"known":false}}'])
        self.rejected("non_finite_json_number", [TOOL.MARKER + b'{"x":NaN}'])
        for data in [b"{", b"{} trailing", b"\xff", b"[" * 1100 + b"]" * 1100]:
            with self.subTest(data_length=len(data)):
                self.rejected("malformed_timing_report", [TOOL.MARKER + data])
        self.rejected("ambiguous_log_marker", [TOOL.MARKER + TOOL.MARKER + b"{}"])

    def test_log_budget_and_foreign_corruption_fail_closed(self):
        self.rejected("log_capacity_exceeded", [b"x" * (TOOL.MAX_LINE_BYTES + 1)])
        original = TOOL.MAX_LOG_BYTES
        try:
            TOOL.MAX_LOG_BYTES = 10
            self.rejected("log_capacity_exceeded", [b"123456", b"78901"])
        finally:
            TOOL.MAX_LOG_BYTES = original
        self.rejected("malformed_timing_report", [line(fixture()), TOOL.MARKER + b"PRIVATE_BROKEN_BODY"])

    def test_cli_is_read_only_and_outputs_safe_errors(self):
        with tempfile.TemporaryDirectory(prefix="cm-b-timing-") as directory:
            path = Path(directory) / "worker.log"
            path.write_bytes(line(fixture()))
            before = path.read_bytes()
            good = subprocess.run([sys.executable, "-B", str(SCRIPT), "--log", str(path), "--invocation-sha256", PIN], capture_output=True, timeout=10)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            self.assertFalse(json.loads(good.stdout)["full_chain_passed"])
            path.write_bytes(TOOL.MARKER + b"PRIVATE_PASSWORD_BROKEN_JSON")
            bad = subprocess.run([sys.executable, "-B", str(SCRIPT), "--log", str(path), "--invocation-sha256", PIN], capture_output=True, timeout=10)
            self.assertEqual(bad.returncode, 2)
            self.assertNotIn(b"PRIVATE_PASSWORD", bad.stdout + bad.stderr)
            self.assertEqual(json.loads(bad.stdout)["code"], "malformed_timing_report")
            missing = subprocess.run([sys.executable, "-B", str(SCRIPT), "--log", str(path.parent / "absent.log"), "--invocation-sha256", PIN], capture_output=True, timeout=10)
            self.assertEqual(missing.returncode, 2)
            self.assertEqual(json.loads(missing.stdout)["code"], "log_unavailable")
        self.assertFalse(Path(directory).exists(), "owned synthetic CLI fixture not cleaned")

    def test_stage_labels_match_the_actual_go_recorder(self):
        # Compatibility check of the emitted diagnostic vocabulary, not an
        # authorization check or a replacement for the blocked Go package tests.
        source = SCRIPT.parent.parent / "backend/internal/systembackup/domain/capture_timing.go"
        go = source.read_text(encoding="utf-8")
        labels = go.split("var captureTimingLabels = [...]string{", 1)[1].split("}", 1)[0]
        import re
        self.assertEqual(tuple(re.findall(r'"([a-z_]+)"', labels)), TOOL.STAGES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
