#!/usr/bin/env python3
"""Read B's local timing DATA for ONE independently selected invocation.

No network, SQL, provider, authorization, migration or task state changes.
This is a log reader, not an evidence verifier or an acceptance decision.
"""

import argparse
import contextlib
import json
import os
import re
import stat
import sys


MARKER = b"[system-backup-database-timing] "
MAX_LINE_BYTES = 16 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_UINT64 = (1 << 64) - 1
MAX_INT64 = (1 << 63) - 1
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
STAGES = (
    "guard", "key_check", "source_authorize", "sql_query", "sql_next", "row_scan",
    "connection", "session_before", "session_after", "begin_rr", "catalog_initial",
    "exact_counts", "catalog_locked", "commit_rr", "domain_capture", "snapshot_verify",
    "encode_compress", "dek_use", "cipher_staging", "envelope_staging", "worker_total",
)
REPORT_FIELDS = {
    "schema_version", "invocation_sha256", "candidate_returned", "samples",
    "original_key_window", "source_window", "request_window",
}
SAMPLE_FIELDS = {"stage", "calls", "failures", "total_ns", "max_ns"}
WINDOW_FIELDS = {"known", "start_remaining_us", "end_remaining_us"}


class Rejected(ValueError):
    """A fixed safe code; never include input bytes, paths or error bodies."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_field")
        result[key] = value
    return result


def reject_constant(_):
    raise Rejected("non_finite_json_number")


def exact_fields(value, expected):
    if type(value) is not dict or set(value) != expected:
        raise Rejected("unexpected_fields")


def integer(value, minimum=0, maximum=MAX_INT64):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected("invalid_integer")


def validate_window(window):
    exact_fields(window, WINDOW_FIELDS)
    if type(window["known"]) is not bool:
        raise Rejected("invalid_window")
    for field in ("start_remaining_us", "end_remaining_us"):
        integer(window[field], -(1 << 63))
        if not window["known"] and window[field] != 0:
            raise Rejected("inferred_unknown_window")


def validate_report(report):
    exact_fields(report, REPORT_FIELDS)
    if report["schema_version"] != "database-capture-timing.v1":
        raise Rejected("unsupported_schema")
    if type(report["invocation_sha256"]) is not str or not DIGEST.fullmatch(report["invocation_sha256"]):
        raise Rejected("invalid_invocation_sha256")
    if type(report["candidate_returned"]) is not bool:
        raise Rejected("invalid_candidate_flag")
    samples = report["samples"]
    if type(samples) is not list or not 1 <= len(samples) <= len(STAGES):
        raise Rejected("invalid_samples")
    seen = {}
    for sample in samples:
        exact_fields(sample, SAMPLE_FIELDS)
        stage = sample["stage"]
        if type(stage) is not str or stage not in STAGES or stage in seen:
            raise Rejected("invalid_or_duplicate_stage")
        integer(sample["calls"], 1, MAX_UINT64)
        integer(sample["failures"], 0, sample["calls"])
        integer(sample["total_ns"])
        integer(sample["max_ns"], 0, sample["total_ns"])
        if sample["total_ns"] > sample["max_ns"] * sample["calls"]:
            raise Rejected("inconsistent_duration")
        seen[stage] = sample
    total = seen.get("worker_total")
    if total is None or total["calls"] != 1 or total["failures"] != int(not report["candidate_returned"]):
        raise Rejected("inconsistent_worker_total")
    if report["candidate_returned"] and any(sample["failures"] for sample in samples):
        raise Rejected("inconsistent_candidate_report")
    for name in ("original_key_window", "source_window", "request_window"):
        validate_window(report[name])


def analyze_lines(lines, invocation_sha256):
    if type(invocation_sha256) is not str or not DIGEST.fullmatch(invocation_sha256):
        raise Rejected("invalid_expected_invocation_sha256")
    selected = None
    selected_count, other_count, total_bytes = 0, 0, 0
    for line in lines:
        total_bytes += len(line)
        if len(line) > MAX_LINE_BYTES or total_bytes > MAX_LOG_BYTES:
            raise Rejected("log_capacity_exceeded")
        if MARKER not in line:
            continue
        if line.count(MARKER) != 1:
            raise Rejected("ambiguous_log_marker")
        raw = line.split(MARKER, 1)[1]
        try:
            report = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
        except Rejected:
            raise
        except (UnicodeError, ValueError, RecursionError):
            raise Rejected("malformed_timing_report") from None
        validate_report(report)
        if report["invocation_sha256"] != invocation_sha256:
            other_count += 1
            continue
        if selected is not None and selected != report:
            # Never pick the last/best result of a retry or sum two invocations.
            raise Rejected("ambiguous_invocation_reports")
        selected = report
        selected_count += 1
    if selected is None:
        raise Rejected("expected_report_missing")
    by_stage = {sample["stage"]: sample for sample in selected["samples"]}
    samples = []
    for stage in STAGES:
        if stage in by_stage:
            value = dict(by_stage[stage])
            value["mean_ns"] = value["total_ns"] // value["calls"]
            samples.append(value)
    return {
        "schema_version": "b-capture-timing-analysis.v1",
        "diagnostic_only": True,
        "authoritative_evidence": False,
        "full_chain_passed": False,
        "invocation_sha256": invocation_sha256,
        "candidate_returned": selected["candidate_returned"],
        "identical_report_copies": selected_count,
        "unselected_report_count": other_count,
        "durations_are_inclusive": True,
        "sum_all_samples_valid": False,
        "key_check_scope": "B explicit checks inside RunFormalCapture, not all A/controller RPCs",
        "outside_worker_total": ["ready", "key_job_open", "source_open", "report_candidate"],
        "samples": samples,
        **{name: selected[name] for name in ("original_key_window", "source_window", "request_window")},
    }


def read_log(path):
    # Nonblocking open also refuses to hang on a FIFO in a supplied log path.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise Rejected("regular_log_file_required")
        if info.st_size > MAX_LOG_BYTES:
            raise Rejected("log_capacity_exceeded")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while True:
                line = source.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                yield line
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="local worker log; never fetched remotely")
    parser.add_argument("--invocation-sha256", required=True, help="original invocation pin from D's independent record")
    args = parser.parse_args(argv)
    try:
        with contextlib.closing(read_log(args.log)) as lines:
            result = analyze_lines(lines, args.invocation_sha256)
    except Rejected as error:
        print(json.dumps({"diagnostic_only": True, "status": "rejected", "code": str(error)}))
        return 2
    except OSError:
        print(json.dumps({"diagnostic_only": True, "status": "rejected", "code": "log_unavailable"}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
