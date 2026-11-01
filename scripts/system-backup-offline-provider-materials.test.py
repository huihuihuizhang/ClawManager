"""Protocol tests only; reject any accidental socket or provider construction."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

root = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, root / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


offline = load("offline_provider", "system-backup-offline-provider-materials.py")
fixture = load("signing_fixture", "system-backup-a-apply-signing-policy.test.py")
kek_fixture = load("kek_fixture", "system-backup-a-apply-kek-policy.test.py")


class OfflineProviderTests(unittest.TestCase):
    def test_kek_compile_separates_generate_and_recovery_unwrap(self):
        kek_fixture.PolicyTests.setUpClass()
        raw = json.dumps(kek_fixture.PolicyTests.plan).encode()
        for operation in ("backup_dek_generate", "backup_dek_unwrap"):
            identity = {"namespace": "local-test", "service_account": "local-worker",
                        "service_account_uid": "local-sa-uid", "pod_uid": "local-pod-uid", "job_uid": "local-job-uid",
                        "invocation_sha256": "a" * 64, "execution_grant_sha256": "b" * 64, "operation": operation}
            identity_raw = json.dumps(identity).encode()
            with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), patch.object(offline.kek, "Provider", side_effect=AssertionError("provider forbidden")):
                result = offline.compile_plan("kek", raw, hashlib.sha256(raw).hexdigest(), workload_raw=identity_raw, workload_sha=hashlib.sha256(identity_raw).hexdigest())
            self.assertEqual(len(result["roles"]), 1)
            role = next(iter(result["roles"].values()))
            self.assertTrue(role["token_policies"][0].endswith("-" + operation.removeprefix("backup_dek_")))
            self.assertFalse(result["production_ready"])
        identity["operation"] = "sign"
        identity_raw = json.dumps(identity).encode()
        with self.assertRaises(Exception):
            offline.compile_plan("kek", raw, hashlib.sha256(raw).hexdigest(), workload_raw=identity_raw, workload_sha=hashlib.sha256(identity_raw).hexdigest())
        with self.assertRaises(Exception):
            offline.compile_plan("kek", raw, hashlib.sha256(raw).hexdigest(), workload_raw=identity_raw, workload_sha="0" * 64)

    def test_compiler_uses_existing_three_purpose_contract_without_io(self):
        raw = json.dumps(fixture.fixture()).encode()
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), patch.object(offline.kek, "Provider", side_effect=AssertionError("provider forbidden")):
            result = offline.compile_plan("signing", raw, hashlib.sha256(raw).hexdigest(), "https://provider.example:8200")
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["status"], "review_only_not_authorized")
        self.assertEqual(len(result["policies"]), 3)
        self.assertEqual(len(result["roles"]), 3)

    def test_identity_purpose_version_and_pin_rejected_after_rehash(self):
        for mutation in (
            lambda p: p["bindings"][0].update(installation_id="foreign"),
            lambda p: p["bindings"][0].update(purpose="catalog_record"),
            lambda p: p["bindings"][0].update(provider_version="latest"),
            lambda p: p["workloads"][0].update(pod_uid=""),
        ):
            plan = fixture.fixture()
            mutation(plan)
            raw = json.dumps(plan).encode()
            with self.assertRaises(Exception):
                offline.compile_plan("signing", raw, hashlib.sha256(raw).hexdigest(), "https://provider.example:8200")
        raw = json.dumps(fixture.fixture()).encode()
        with self.assertRaises(Exception):
            offline.compile_plan("signing", raw, "0" * 64, "https://provider.example:8200")

    def test_network_file_paths_refused_before_open(self):
        for name in (r"\\server\share\material.json", "//server/share/x", "https://provider.invalid/x"):
            with patch.object(Path, "open", side_effect=AssertionError("must not open")):
                with self.assertRaises(offline.kek.Rejected):
                    offline.read_local(name)


if __name__ == "__main__":
    unittest.main()
