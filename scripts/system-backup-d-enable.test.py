"""Client orchestration regressions, not a production authorization fixture."""
import copy
import base64
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("enable", Path(__file__).with_name("system-backup-d-enable.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class API:
    def __init__(self, lost=False, readiness=False):
        self.token = "test-token"
        self.config = {"schema_version": "system-backup-config.v1", "origin_installation_id": "installation_test",
            "version": 1, "row_version": 1, "active": True, "effective_enabled": False,
            "config": {"enabled": False, "other_original_field": "unchanged"}}
        self.lost, self.ready, self.puts = lost, readiness, 0

    def send(self, path, method, value, headers=None):
        if path == m.PROOF:
            self.proof_request = copy.deepcopy(value)
            self.proof_header = base64.b64encode(m.r.canonical({"schema_version": "system-backup-strong-auth-proof.v1",
                "payload": {"subject": "user:7", "session": m.r.sha(self.token.encode()),
                    "endpoint": value["endpoint"], "idempotency_key": value["idempotency_key"],
                    "nonce": "test-secret-nonce", "request_hash": m.request_digest("installation_test", "7", value["request"])}})).decode()
            return 200, {}, {"header_name": "X-Strong-Auth-Proof", "header_value": self.proof_header}
        self.puts += 1
        assert value == self.proof_request["request"]
        assert headers["Idempotency-Key"] == self.proof_request["idempotency_key"]
        assert headers["X-Strong-Auth-Proof"] == self.proof_header
        self.config.update(version=2, row_version=2, effective_enabled=True, config=copy.deepcopy(value["config"]))
        self.operation = {"schema_version": "system-backup-operation.v1", "origin_installation_id": "installation_test",
            "target_public_id": "installation_test", "operation_type": "config_update", "endpoint": "updateSystemBackupConfig",
            "idempotency_key": headers["Idempotency-Key"], "status": "succeeded", "result_config_version": 2,
            "request_hash": m.request_digest("installation_test", "7", value), "actor_id": "7",
            "public_id": "sop_00000000-0000-4000-8000-000000000001"}
        self.config_operation_response_raw = m.r.canonical(self.operation)
        if self.lost:
            raise OSError("simulated lost response after commit")
        return 200, {}, self.operation

    def request(self, path, method="GET"):
        headers = {"X-System-Backup-Data-Source": "live"}
        if path == m.r.CONFIG:
            return 200, headers, copy.deepcopy(self.config)
        if path.startswith("/api/v1/admin/system-backup-operations/"):
            return 200, headers, copy.deepcopy(self.operation)
        if not self.ready:
            return 503, headers, {"code": "not_ready"}
        overview = {"schema_version": "system-backup-overview.v1", "origin_installation_id": "installation_test",
            "config_version": 2, "effective_enabled": True, "backup_recovery_readiness": True,
            "source_writer_state": "clean", "observed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        overview.update({k: "healthy" for k in ("controller_health", "database_health", "artifact_target_health",
                                              "evidence_store_health", "catalog_health")})
        return 200, headers, overview


def prompt(text):
    return "123456" if "TOTP" in text else "existing-password"


class EnableTests(unittest.TestCase):
    def test_success_only_changes_enabled_and_uses_server_proof(self):
        with tempfile.TemporaryDirectory() as parent:
            api = API(readiness=True)
            journal = Path(parent) / "operation"
            result = m.enable(api, "installation_test", journal, lambda: None, prompt)
            self.assertEqual(result["status"], "ENABLED_AND_API_READBACK_VERIFIED")
            self.assertEqual(api.puts, 1)
            self.assertEqual(api.config["config"], {"enabled": True, "other_original_field": "unchanged"})
            saved = "".join(p.read_text() for p in journal.iterdir())
            for secret in ("existing-password", api.proof_header, "test-secret-nonce", "123456"):
                self.assertNotIn(secret, saved)

    def test_staged_enable_retains_exact_commit_without_claiming_readiness(self):
        with tempfile.TemporaryDirectory() as parent:
            api = API()
            journal = Path(parent) / "operation"
            result = m.enable(api, "installation_test", journal, lambda: None, prompt, verify_readiness=False)
            self.assertEqual(result["status"], "ENABLE_COMMIT_READBACK_VERIFIED_READINESS_PENDING")
            self.assertFalse(result["readiness_verified"])
            self.assertEqual(result["config_version"], 2)
            self.assertEqual(api.puts, 1)
            self.assertTrue((journal / "committed-readback.json").is_file())
            self.assertFalse((journal / "readiness.json").exists())
            with self.assertRaises(FileExistsError):
                m.enable(api, "installation_test", journal, lambda: None, prompt, verify_readiness=False)
            self.assertEqual(api.puts, 1)

    def test_actual_operation_response_bytes_are_retained_without_reencoding(self):
        class TransportBytes(API):
            def send(self, path, method, value, headers=None):
                result = super().send(path, method, value, headers)
                if (path, method) == (m.r.CONFIG, "PUT"):
                    self.config_operation_response_raw = json.dumps(self.operation, indent=1).encode() + b"\n"
                return result
        with tempfile.TemporaryDirectory() as parent:
            api = TransportBytes()
            journal = Path(parent) / "operation"
            result = m.enable(api, "installation_test", journal, lambda: None, prompt, verify_readiness=False)
            raw = (journal / "operation-response.raw.json").read_bytes()
            self.assertEqual(raw, api.config_operation_response_raw)
            self.assertNotEqual(raw, m.r.canonical(api.operation))
            self.assertEqual(result["status"], "ENABLE_COMMIT_READBACK_VERIFIED_READINESS_PENDING")
            self.assertEqual(api.puts, 1)
            # This model proves byte retention, not native bridge authority.
            # A's real decoder/SQL/evidence comparison remains mandatory.

    def test_original_operation_byte_reader_uses_only_live_fixed_get(self):
        from email.message import Message
        operation_id = "sop_00000000-0000-4000-8000-000000000001"
        raw = b'{"public_id":"' + operation_id.encode() + b'"}'
        calls = []
        class Response:
            code = 200
            def __init__(self):
                self.headers = Message(); self.headers["Content-Type"] = "application/json"
                self.headers["X-System-Backup-Data-Source"] = "live"
            def read(self, maximum):
                self.maximum = maximum
                return raw[:maximum]
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Opener:
            def open(self, request, timeout):
                calls.append((request, timeout))
                return Response()
        api = object.__new__(m.API); api.origin = "https://actual.example"; api.token = "test-token"; api.opener = Opener()
        actual, body = api.operation_bytes(operation_id)
        self.assertEqual(actual, raw); self.assertEqual(body["public_id"], operation_id)
        request, timeout = calls[0]
        self.assertEqual(request.get_method(), "GET"); self.assertIsNone(request.data)
        self.assertEqual(request.full_url, "https://actual.example/api/v1/admin/system-backup-operations/" + operation_id)
        self.assertEqual(timeout, 20)
        with self.assertRaises(m.r.Refused): api.operation_bytes(operation_id + "?different=1")
        self.assertEqual(len(calls), 1)

    def test_lost_response_never_retries_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as parent:
            api = API(lost=True)
            journal = Path(parent) / "operation"
            with self.assertRaises(OSError):
                m.enable(api, "installation_test", journal, lambda: None, prompt)
            original = (journal / "request.json").read_bytes()
            self.assertTrue((journal / "submission-intent.json").exists())
            with self.assertRaises(FileExistsError):
                m.enable(api, "installation_test", journal, lambda: None, prompt)
            self.assertEqual((journal / "request.json").read_bytes(), original)
            self.assertEqual(api.puts, 1)

    def test_missing_readiness_keeps_successful_operation_without_rollback(self):
        with tempfile.TemporaryDirectory() as parent:
            api = API()
            journal = Path(parent) / "operation"
            with self.assertRaisesRegex(m.r.Refused, "readiness_endpoint_unavailable"):
                m.enable(api, "installation_test", journal, lambda: None, prompt)
            saved = json.loads((journal / "committed-readback.json").read_bytes())
            self.assertTrue(saved["enabled"])
            self.assertFalse(saved["readiness_verified"])
            self.assertEqual(api.puts, 1)

    def test_changed_pod_stops_before_put(self):
        with tempfile.TemporaryDirectory() as parent:
            api = API()
            def changed():
                raise m.r.Refused("identity_changed_reissue_required")
            with self.assertRaisesRegex(m.r.Refused, "identity_changed"):
                m.enable(api, "installation_test", Path(parent) / "operation", changed, prompt)
            self.assertEqual(api.puts, 0)

    def test_hash_matches_existing_a_update_vector(self):
        path = Path(__file__).parents[1] / "docs/evidence/a-config-canonical-request-vectors-20261014.json"
        vectors = json.loads(path.read_bytes())["vectors"]
        for vector in vectors:
            source = vector["input"]
            if source["endpoint"] == "updateSystemBackupConfig":
                self.assertEqual(m.request_digest(source["origin_installation_id"], source["actor_id"], source["request"]),
                                 vector["request_sha256"])

    def test_proof_for_other_request_stops_before_put(self):
        class WrongProof(API):
            def send(self, path, method, value, headers=None):
                status, fields, proof = super().send(path, method, value, headers)
                if path == m.PROOF:
                    doc = m.r.decode(base64.b64decode(proof["header_value"]))
                    doc["payload"]["request_hash"] = "0" * 64
                    proof["header_value"] = base64.b64encode(m.r.canonical(doc)).decode()
                return status, fields, proof
        with tempfile.TemporaryDirectory() as parent:
            api = WrongProof()
            with self.assertRaisesRegex(m.r.Refused, "server_proof_request_hash_mismatch"):
                m.enable(api, "installation_test", Path(parent) / "operation", lambda: None, prompt)
            self.assertEqual(api.puts, 0)


if __name__ == "__main__":
    unittest.main()
