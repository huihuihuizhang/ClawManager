#!/usr/bin/env python3
"""Read-only resolution of an original enable attempt; never sends POST/PUT.

Uses the original journal/actor/request hash/key and authenticated live operation
pages with EOF. Absence is UNKNOWN, never permission to submit a new operation.
Pod/readiness acceptance remains separate, including after a restart.
"""
import argparse
import getpass
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
import time
import urllib.parse

spec = importlib.util.spec_from_file_location("enable", Path(__file__).with_name("system-backup-d-enable.py"))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
r = e.r
OPERATIONS = "/api/v1/admin/system-backup-operations"


def journal(directory, installation):
    def read(name):
        path = directory / name
        info = path.lstat()
        r.require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144 and
                  (e.os.name == "nt" or info.st_mode & 0o077 == 0), "original_private_journal_required")
        return r.decode(path.read_bytes())
    original, binding, intent = read("request.json"), read("request-binding.json"), read("submission-intent.json")
    request = original["request"]
    r.require(original["installation"] == installation == binding["installation"] and
        original["idempotency_key"] == binding["idempotency_key"] == intent["idempotency_key"] and
        re.fullmatch(r"d-enable-[0-9a-f]{48}", original["idempotency_key"]) and
        set(request) == {"expected_version", "change_reason", "config"} and
        type(request["expected_version"]) is int and 1 <= request["expected_version"] < 9007199254740991 and
        request["config"]["enabled"] is True and
        r.sha(r.canonical(request)) == binding["request_bytes_sha256"] and
        e.request_digest(installation, binding["actor_id"], request) == binding["request_hash"],
        "original_request_binding_mismatch")
    return original, binding


def live(api, path):
    status, headers, body = api.request(path)
    r.require(status == 200 and headers.get("X-System-Backup-Data-Source") == "live", "operation_live_read_unavailable")
    return body


def resolve(api, original, binding, max_pages=20):
    r.require(type(max_pages) is int and 1 <= max_pages <= 100, "invalid_page_budget")
    installation, key, request = original["installation"], original["idempotency_key"], original["request"]
    cursor, seen_cursors, seen_ids, matches = None, set(), set(), []
    deadline = time.monotonic() + 120
    for index in range(max_pages):
        r.require(time.monotonic() < deadline, "operation_scan_budget_exhausted_outcome_unknown")
        query = {"limit": "100"}
        if cursor:
            query["cursor"] = cursor
        page = live(api, OPERATIONS + "?" + urllib.parse.urlencode(query))
        r.require(page.get("consistency") == "stable_cutoff" and isinstance(page.get("items"), list) and
                  len(page["items"]) <= 100 and "next_cursor" in page, "operation_page_invalid")
        for operation in page["items"]:
            r.require(isinstance(operation, dict) and operation.get("schema_version") == "system-backup-operation.v1",
                      "operation_page_item_invalid")
            op_id = operation.get("public_id", "")
            r.require(operation.get("origin_installation_id") == installation and
                re.fullmatch(r"sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", op_id) and
                op_id not in seen_ids, "operation_page_identity_or_repetition_invalid")
            seen_ids.add(op_id)
            if operation.get("idempotency_key") == key:
                matches.append(operation)
        cursor = page["next_cursor"]
        if cursor is None:
            break
        r.require(isinstance(cursor, str) and 0 < len(cursor) <= 4096 and cursor not in seen_cursors and
                  page["items"], "operation_cursor_invalid_or_repeated")
        seen_cursors.add(cursor)
    else:
        raise r.Refused("operation_scan_budget_exhausted_outcome_unknown")
    r.require(len(matches) <= 1, "multiple_original_operations_unconfirmed")
    if not matches:
        return {"status": "NOT_OBSERVED_OUTCOME_UNKNOWN", "resubmit_allowed": False,
                "pages_read": index + 1, "eof": True}
    operation = matches[0]
    r.require(operation.get("operation_type") == "config_update" and operation.get("target_type") == "system" and
        operation.get("target_public_id") == installation and operation.get("actor_type") == "admin" and
        operation.get("actor_id") == binding["actor_id"] and operation.get("endpoint") == "updateSystemBackupConfig" and
        operation.get("request_hash") == binding["request_hash"], "original_operation_binding_mismatch")
    reread = live(api, OPERATIONS + "/" + operation["public_id"])
    r.require(reread == operation, "original_operation_changed_during_readback")
    if operation.get("status") != "succeeded":
        return {"status": "ORIGINAL_OPERATION_NOT_SUCCESSFUL_OUTCOME_UNCONFIRMED", "resubmit_allowed": False,
                "operation_public_id": operation["public_id"], "operation_status": operation.get("status")}
    version = request["expected_version"] + 1
    r.require(operation.get("result_config_version") == version and operation.get("http_status") == 200,
              "original_operation_result_unconfirmed")
    config = live(api, r.CONFIG + "/versions/" + str(version))
    r.require(config.get("schema_version") == "system-backup-config.v1" and
        config.get("origin_installation_id") == installation and config.get("version") == version and
        config.get("config") == request["config"] and config.get("created_by") == binding["actor_id"] and
        config.get("change_reason") == request["change_reason"], "original_config_version_readback_mismatch")
    # Current config may have advanced or readiness may be unavailable. Those
    # facts cannot erase a verified historical original commit or permit retry.
    return {"status": "ORIGINAL_ENABLE_COMMIT_VERIFIED", "operation_public_id": operation["public_id"],
            "config_version": version, "resubmit_allowed": False, "deployment_readiness_verified": False,
            "browser_path_verified": False, "pages_read": index + 1, "eof": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("origin", "ca-sha256", "installation"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "journal-directory"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--max-pages", type=int, default=20)
    args = parser.parse_args()
    try:
        original, binding = journal(args.journal_directory, args.installation)
        api = r.API(args.origin, args.ca_file, args.ca_sha256, getpass.getpass("Existing normal login bearer token (hidden): "))
        result = resolve(api, original, binding, args.max_pages)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "ORIGINAL_ENABLE_COMMIT_VERIFIED" else 2
    except r.Refused as error:
        reason = str(error)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, r.urllib.error.URLError):
        reason = "original_outcome_unconfirmed"
    print(json.dumps({"status": "OUTCOME_UNKNOWN", "reason": reason, "resubmit_allowed": False}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
