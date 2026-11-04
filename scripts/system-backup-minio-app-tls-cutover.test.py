import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

root = Path(__file__).resolve().parents[2]
file = Path(__file__).with_name("system-backup-minio-app-tls-cutover.py")
spec = importlib.util.spec_from_file_location("app_cutover", file)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
helper = file.with_name("system-backup-minio-first-hop-tls.py")
if not helper.is_file():
    helper = root / ".a-minio-first-hop-tls-20261104/scripts/system-backup-minio-first-hop-tls.py"
a.m = a.load_helper(helper)


class Cutover(unittest.TestCase):
    def prepare(self, parent, roots=b"-----BEGIN CERTIFICATE-----\nORIGINAL\n-----END CERTIFICATE-----\n"):
        ca = b"-----BEGIN CERTIFICATE-----\nMINIO\n-----END CERTIFICATE-----\n"
        minio = parent / "minio"
        minio.mkdir()
        a.m.durable(minio / "ca.pem", ca)
        password = parent / "password"
        a.m.durable(password, b"fixture-not-an-actual-password")
        before = {"metadata": {"name": "app", "uid": "app-uid", "resourceVersion": "1"}, "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "original@sha256:original", "env": [{"name": "OBJECT_STORAGE_BUCKET", "value": "original-business"}, {"name": "OBJECT_STORAGE_SECRET_KEY", "valueFrom": {"secretKeyRef": {"name": "original", "key": "password"}}}]}]}}}}
        class Source:
            ns = "original-system"
            plan = {"LocalAdminUsername": "actual-plan-username"}
            def authority(self):
                pass
            def get(self, kind, name):
                return copy.deepcopy(before)
            def kube(self, *args, data=None):
                result = copy.deepcopy(before)
                self.dry = "--dry-run=server" in args
                for op in json.loads(data):
                    if op["path"] == "/spec":
                        result["spec"] = op["value"]
                return a.m.raw(result)
        source = Source()
        args = SimpleNamespace(minio_state_directory=minio, minio_plan_sha256="actual-pin", app_deployment="app", local_admin_password_file=password, state_directory=parent / "app", service="minio", installation_plan_sha256="installation-pin")
        def execute(actor, *cmd):
            return b"/etc/ssl/certs/ca-certificates.crt" if cmd[0] == "/bin/sh" else roots
        with patch.object(a.m, "load", return_value={"operation": "original-op", "ca_sha256": a.m.sha(ca)}), patch.object(a, "app_source", return_value=(before, [(None, None, None)])), patch.object(a, "app_exec", side_effect=lambda src, actor, *cmd: execute(actor, *cmd)), patch.object(a, "business_download", return_value={"state": "actual_original_admin_session_verified"}):
            result = a.prepare(source, args)
        return before, source, json.loads(a.m.read_private(args.state_directory / "plan.json")), result

    def test_original_image_accounts_bucket_and_system_roots_preserved(self):
        with tempfile.TemporaryDirectory(prefix="a-app-tls-") as name:
            before, source, plan, result = self.prepare(Path(name))
            c = plan["desired_spec"]["template"]["spec"]["containers"][0]
            self.assertEqual(c["image"], before["spec"]["template"]["spec"]["containers"][0]["image"])
            for old in before["spec"]["template"]["spec"]["containers"][0]["env"]:
                self.assertIn(old, c["env"])
            env = {e["name"]: e.get("value") for e in c["env"]}
            self.assertEqual(env["OBJECT_STORAGE_USE_SSL"], "true")
            self.assertTrue(env["SSL_CERT_FILE"].endswith("/roots.pem"))
            self.assertTrue(env["OBJECT_STORAGE_TLS_CA_FILE"].endswith("/minio-ca.pem"))
            self.assertIn("ORIGINAL", plan["ca_object"]["data"]["roots.pem"])
            self.assertIn("MINIO", plan["ca_object"]["data"]["roots.pem"])
            self.assertTrue(source.dry)
            self.assertEqual(result["state"], "business_cutover_prepared_only")

    def test_private_material_cannot_be_used_as_public_system_roots(self):
        with tempfile.TemporaryDirectory(prefix="a-app-tls-") as name:
            with self.assertRaises(a.m.Refused):
                self.prepare(Path(name), b"-----BEGIN PRIVATE KEY-----\nnot-public\n")
            self.assertFalse((Path(name) / "app").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
