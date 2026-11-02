"""Local structural DATA only, not Go config/signature/cluster admission proof."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("candidate", ROOT / "scripts/system-backup-d-controller-candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class CandidateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".tmp-controller-candidate-", dir=ROOT)
        self.root = Path(self.temp.name).resolve()
        self.assertEqual(self.root.parent, ROOT)
        self.plan = {"schema_version": candidate.VERSION, "release_commit": "a" * 40,
                     "namespace": "local-data", "namespace_uid": "11111111-2222-3333-4444-555555555555",
                     "app_image": "local/app@sha256:" + "b" * 64, "worker_image": "local/worker@sha256:" + "c" * 64,
                     "service_account": {"name": "local-controller", "uid": "99999999-2222-3333-4444-555555555555"}, "files": []}
        self.env = [{"name": "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "value": "public-v1"},
                    {"name": "SYSTEM_BACKUP_ENABLED", "value": "false"},
                    {"name": "CLAWMANAGER_LEADER_ELECTION", "value": "true"},
                    {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}]
        for name in ("DB_USER", "DB_PASSWORD"):
            self.env.append({"name": name, "valueFrom": {"secretKeyRef": {"name": "local-db", "key": name}}})
        paths = []
        for index, (file_env, hash_env) in enumerate(candidate.PAIRS):
            item = self.material("material" + str(index), b"LOCAL STRUCTURE DATA")
            paths.append(item["mount_path"])
            self.env.extend([{"name": file_env, "value": item["mount_path"]}, {"name": hash_env, "value": item["sha256"]}])
        self.config = {"schema_version": "system-backup-public-deployment.v1", "capture_scope": "six-part",
                       "namespace": self.plan["namespace"], "namespace_uid": self.plan["namespace_uid"],
                       "worker_image": self.plan["worker_image"], "key_directory": "/run/private"}
        for field, path in zip(("formal_verifier", "publication_signers", "publisher_verifier", "capture_modules", "publication_target"), paths[1:]):
            self.config[field] = {"path": path}
        for field in ("profile_file", "capacity_file", "source_dsn_file", "server_certificate", "server_key", "issuer_certificate", "issuer_key"):
            self.config[field] = self.material(field, b"LOCAL STRUCTURE DATA")["mount_path"]
        for field, hash_env in (("forward_grant", "SYSTEM_BACKUP_FORWARD_GRANT_SHA256"), ("recovery_grant", "SYSTEM_BACKUP_RECOVERY_GRANT_SHA256")):
            item = self.material(field, b"LOCAL NOT A SIGNED GRANT")
            self.config[field] = {"path": item["mount_path"]}
            self.env.append({"name": hash_env, "value": item["sha256"]})
        raw = json.dumps(self.config).encode()
        (self.root / "material0").write_bytes(raw)
        self.plan["files"][0]["sha256"] = candidate.sha(raw)
        next(e for e in self.env if e["name"] == candidate.PAIRS[0][1])["value"] = candidate.sha(raw)
        self.container = {"name": "controller", "image": self.plan["app_image"],
                          "command": ["/usr/local/bin/system-backup-v2-controller"], "env": self.env,
                          "volumeMounts": [{"name": "private", "mountPath": "/run/private", "readOnly": True}]}
        self.manifest = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "controller", "namespace": self.plan["namespace"]},
                         "spec": {"replicas": 0, "selector": {"matchLabels": {"app": "local-controller"}},
                                  "template": {"metadata": {"labels": {"app": "local-controller"}}, "spec": {"serviceAccountName": "local-controller", "containers": [self.container],
                                   "volumes": [{"name": "private", "secret": {"secretName": "local-materials"}}]}}}}

    def tearDown(self):
        self.temp.cleanup()

    def material(self, name, raw):
        (self.root / name).write_bytes(raw)
        item = {"file": name, "sha256": candidate.sha(raw), "mount_path": "/run/private/" + name,
                "kind": "Secret", "name": "local-materials", "key": name}
        self.plan["files"].append(item)
        return item

    def prepare(self):
        raw = json.dumps(self.manifest).encode()
        (self.root / "controller.json").write_bytes(raw)
        self.plan["deployment"] = {"file": "controller.json", "sha256": candidate.sha(raw)}
        path = self.root / "plan.json"
        path.write_text(json.dumps(self.plan))
        return candidate.prepare(path)

    def test_paused_pins_only_never_authorization(self):
        manifest, report = self.prepare()
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(manifest["spec"]["replicas"], 0)
        self.assertFalse(report["authorization_verified"])
        self.assertFalse(report["live_resources_verified"])
        self.assertFalse(report["full_acceptance"])

    def test_changed_private_bytes_rejected(self):
        (self.root / "source_dsn_file").write_bytes(b"CHANGED LOCAL DATA")
        with self.assertRaises(ValueError): self.prepare()

    def test_pod_name_field_ref_accepts_default_or_v1_only(self):
        field = next(e for e in self.env if e["name"] == "POD_NAME")["valueFrom"]["fieldRef"]
        self.prepare()  # Omitted apiVersion uses Kubernetes v1 default.
        field["apiVersion"] = "v1"
        self.prepare()
        field["apiVersion"] = "v2"
        with self.assertRaises(ValueError): self.prepare()
        field["apiVersion"] = "v1"
        field["fieldPath"] = "metadata.namespace"
        with self.assertRaises(ValueError): self.prepare()
        field["fieldPath"] = "metadata.name"
        field["unexpected"] = "v1"
        with self.assertRaises(ValueError): self.prepare()

    def test_cli_writes_only_candidate_and_report_without_private_material_bytes(self):
        self.prepare()
        output = self.root / "output"
        argv = ["candidate", "--plan", str(self.root / "plan.json"), "--output", str(output)]
        captured = io.StringIO()
        with patch("sys.argv", argv), contextlib.redirect_stdout(captured):
            candidate.main()
        self.assertEqual({p.name for p in output.iterdir()}, {"controller.paused.json", "report.json"})
        self.assertEqual(json.loads((output / "controller.paused.json").read_text()), self.manifest)
        self.assertNotIn("LOCAL NOT A SIGNED GRANT", captured.getvalue())
        self.assertNotIn("LOCAL STRUCTURE DATA", captured.getvalue())
        with patch("sys.argv", argv), self.assertRaises(FileExistsError):
            candidate.main()

    def test_wrong_mount_object_rejected(self):
        self.plan["files"][0]["name"] = "wrong-object"
        with self.assertRaises(ValueError): self.prepare()

    def test_running_or_forward_enabled_rejected(self):
        self.manifest["spec"]["replicas"] = 1
        with self.assertRaises(ValueError): self.prepare()
        self.manifest["spec"]["replicas"] = 0
        next(e for e in self.env if e["name"] == "SYSTEM_BACKUP_ENABLED")["value"] = "true"
        with self.assertRaises(ValueError): self.prepare()

    def test_inline_database_password_rejected(self):
        entry = next(e for e in self.env if e["name"] == "DB_PASSWORD")
        entry.clear()
        entry.update({"name": "DB_PASSWORD", "value": "LOCAL PRIVATE DATA MUST NOT BE COPIED"})
        with self.assertRaises(ValueError): self.prepare()

    def test_duplicate_json_and_foreign_source_rejected(self):
        with self.assertRaises(ValueError): candidate.decode(b'{"x":1,"x":2}')
        self.plan["files"][0]["file"] = "../foreign"
        with self.assertRaises(ValueError): self.prepare()


if __name__ == "__main__":
    unittest.main()
