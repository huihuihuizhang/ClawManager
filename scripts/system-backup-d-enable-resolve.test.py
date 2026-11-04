"""Read-only original-identity resolution regressions; no field operations."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

spec = importlib.util.spec_from_file_location("resolve", Path(__file__).with_name("system-backup-d-enable-resolve.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    original = {"installation": "installation_test", "idempotency_key": "d-enable-" + "a" * 48,
        "request": {"expected_version": 1, "change_reason": "original reason",
                    "config": {"enabled": True, "other": "original"}}}
    binding = {"actor_id": "7", "request_hash": m.e.request_digest("installation_test", "7", original["request"]),
        "request_bytes_sha256": m.r.sha(m.r.canonical(original["request"])),
        "installation": original["installation"], "idempotency_key": original["idempotency_key"]}
    operation = {"schema_version": "system-backup-operation.v1", "origin_installation_id": "installation_test",
        "public_id": "sop_00000000-0000-4000-8000-000000000001", "operation_type": "config_update",
        "target_type": "system", "target_public_id": "installation_test", "actor_type": "admin", "actor_id": "7",
        "endpoint": "updateSystemBackupConfig", "request_hash": binding["request_hash"],
        "idempotency_key": original["idempotency_key"], "status": "succeeded", "result_config_version": 2, "http_status": 200}
    config = {"schema_version": "system-backup-config.v1", "origin_installation_id": "installation_test",
        "version": 2, "config": original["request"]["config"], "created_by": "7", "change_reason": "original reason",
        "active": False}  # A later config must not hide the original successful commit.
    return original, binding, operation, config


class API:
    def __init__(self):
        self.original, self.binding, self.operation, self.config = fixture()
        self.pages = [{"items": [self.operation], "consistency": "stable_cutoff", "next_cursor": None}]
        self.calls = []

    def request(self, path, method="GET"):
        assert method == "GET", "resolver must never issue a mutation"
        self.calls.append(path)
        if "?" in path:
            index = len([p for p in self.calls if "?" in p]) - 1
            body = self.pages[index]
        elif path.startswith(m.OPERATIONS + "/"):
            body = self.operation
        elif path == m.r.CONFIG + "/versions/2":
            body = self.config
        else:
            raise AssertionError("unexpected read: " + path)
        return 200, {"X-System-Backup-Data-Source": "live"}, copy.deepcopy(body)


class ResolveTests(unittest.TestCase):
    def test_lost_ack_is_resolved_by_original_operation_and_version_only(self):
        api = API()
        result = m.resolve(api, api.original, api.binding)
        self.assertEqual(result["status"], "ORIGINAL_ENABLE_COMMIT_VERIFIED")
        self.assertFalse(result["resubmit_allowed"])
        self.assertFalse(result["deployment_readiness_verified"])
        self.assertTrue(result["eof"])
        self.assertEqual(len(api.calls), 3)

    def test_empty_complete_page_does_not_claim_no_commit(self):
        api = API()
        api.pages[0]["items"] = []
        result = m.resolve(api, api.original, api.binding)
        self.assertEqual(result["status"], "NOT_OBSERVED_OUTCOME_UNKNOWN")
        self.assertFalse(result["resubmit_allowed"])

    def test_all_pages_consumed_even_after_finding_original(self):
        api = API()
        api.pages[0]["next_cursor"] = "original+cursor/with=special"
        api.pages.append({"items": [], "consistency": "stable_cutoff", "next_cursor": None})
        result = m.resolve(api, api.original, api.binding)
        self.assertEqual(result["pages_read"], 2)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(api.calls[1]).query)["cursor"],
                         ["original+cursor/with=special"])

    def test_wrong_actor_or_hash_refuses_same_key(self):
        for field, value in (("actor_id", "8"), ("request_hash", "f" * 64), ("target_public_id", "installation_other")):
            with self.subTest(field=field):
                api = API()
                api.operation[field] = value
                with self.assertRaisesRegex(m.r.Refused, "original_operation_binding_mismatch"):
                    m.resolve(api, api.original, api.binding)

    def test_incomplete_scan_does_not_resolve_even_if_match_found(self):
        api = API()
        api.pages[0]["next_cursor"] = "more"
        with self.assertRaisesRegex(m.r.Refused, "budget_exhausted"):
            m.resolve(api, api.original, api.binding, max_pages=1)

    def test_duplicate_operation_and_repeated_cursor_refused(self):
        api = API()
        api.pages[0]["items"].append(api.operation)
        with self.assertRaisesRegex(m.r.Refused, "repetition_invalid"):
            m.resolve(api, api.original, api.binding)

    def test_config_with_another_reason_is_not_original_request(self):
        api = API()
        api.config["change_reason"] = "other reason"
        with self.assertRaisesRegex(m.r.Refused, "original_config_version_readback_mismatch"):
            m.resolve(api, api.original, api.binding)

    def test_journal_tampering_and_missing_binding_refused(self):
        original, binding, _, _ = fixture()
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent)
            for name, value in (("request.json", original), ("request-binding.json", binding),
                                ("submission-intent.json", {"idempotency_key": original["idempotency_key"]})):
                m.e.save(directory, name, value)
            self.assertEqual(m.journal(directory, "installation_test"), (original, binding))
            original["request"]["config"]["other"] = "tampered"
            (directory / "request.json").write_bytes(m.r.canonical(original))
            with self.assertRaisesRegex(m.r.Refused, "original_request_binding_mismatch"):
                m.journal(directory, "installation_test")


if __name__ == "__main__":
    unittest.main()
