"""Sidecar custody/dispatch models only; no SQL/cluster/native qualification."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("database_only_sidecar_model", Path(__file__).with_name("system-backup-original-database-maintenance.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DatabaseOnlySidecarModels(unittest.TestCase):
    def fixture(self, root):
        release, run, tools = [root / v for v in ("release", "run", "tools")]
        for directory in (release, run, tools):
            directory.mkdir()
        (release / "scripts").mkdir()
        (release / "bin").mkdir()
        archive, proof = b"model-copy-only", b"model-readproof-only"
        (release / "copy.tar.gz").write_bytes(archive)
        (release / "bin/system-backup-legacy-upgrade177-proof").write_bytes(proof)
        stub = '''import fcntl, json
from pathlib import Path
COPY_NAME="copy.tar.gz"
COPY_SHA=ARCHIVE_SHA
PROOF_SHA=READPROOF_SHA
REPEATABLE={"query","recover","recover-controller","rollback","finish-release","cancel","cleanup","early-query","early-cancel"}
def save(path,value):
    with path.open("x") as output:output.write(json.dumps(value))
class Operator:
    def __init__(self,a):self.a=a;self.root=a.release_directory;self.run=a.run_directory
    def open(self):self.kube=self.run/"operator.kubeconfig.json"
    def invoke(self,stage,argv,repeat=False,env=None):
        marker=self.run/(stage+".send-unknown.json")
        if marker.exists() and not repeat:raise RuntimeError("stage already sent")
        if not repeat:marker.write_text("model send only")
        record={"stage":stage,"argv":[str(v) for v in argv],"repeat":repeat,"KUBECONFIG":env["KUBECONFIG"]}
        (self.run/"model-dispatch.json").write_text(json.dumps(record))
        return {"state":"model-native-state-not-qualified"},self.run/"model-private-receipt"
'''.replace("ARCHIVE_SHA", repr(d.sha(archive))).replace("READPROOF_SHA", repr(d.sha(proof)))
        entry = release / "scripts/system-backup-zhanghui08-operator.py"
        entry.write_text(stub, encoding="utf-8")
        pins = {"files": {"scripts/system-backup-zhanghui08-operator.py": d.sha(entry.read_bytes())}}
        pins_path = release / "operator-release-pins.json"
        pins_path.write_text(json.dumps(pins))
        operation = {"operation": "3" * 32, "release_sha256": d.sha(pins_path.read_bytes())}
        (run / "operation.json").write_text(json.dumps(operation))
        (run / "operator.kubeconfig.json").write_bytes(b"model-only")
        files = {}
        for name in ("system-backup-original-upgrade199.py", "system-backup-upgrade199-copy-qualification.py"):
            raw = b"# model never executed\n"
            (tools / name).write_bytes(raw)
            files[name] = d.sha(raw)
        manifest = {"version": "original-database-maintenance-tools.v1", "files": files,
                    "copy_archive": {"File": "copy.tar.gz", "SHA256": d.sha(archive)},
                    "readproof": {"File": "bin/system-backup-legacy-upgrade177-proof", "SHA256": d.sha(proof)}}
        manifest_path = tools / "database-maintenance-tools.json"
        manifest_path.write_text(json.dumps(manifest))
        argv = [str(Path(d.__file__)), "prepare", "--release-directory", str(release), "--run-directory", str(run),
                "--expected-operation", operation["operation"], "--tools-directory", str(tools),
                "--tools-manifest-sha256", d.sha(manifest_path.read_bytes()), "--copy-receipts-directory", str(root/"actual-copy-receipts")]
        return argv, release, run, tools

    def invoke(self, argv):
        output = io.StringIO()
        with patch.object(d.sys, "argv", argv), contextlib.redirect_stdout(output):
            d.main()
        return json.loads(output.getvalue())

    def test_same_original_operation_journal_one_prepare_no_auto_ddl_or_source_proof(self):
        with tempfile.TemporaryDirectory(prefix="database-only-model-") as directory:
            argv, release, run, tools = self.fixture(Path(directory).resolve())
            original = (run/"operation.json").read_bytes()
            result = self.invoke(argv)
            sent = json.loads((run/"model-dispatch.json").read_text())
            self.assertEqual(sent["stage"], "db-prepare")
            self.assertEqual(sent["argv"][2:4], [str(tools/"system-backup-original-upgrade199.py"), "prepare"])
            self.assertEqual(sent["argv"][sent["argv"].index("--operation-directory")+1], str(run/"original199"))
            self.assertFalse(sent["repeat"])
            self.assertNotIn("apply", sent["argv"])
            self.assertFalse(result["workspace_native_proof_produced"])
            self.assertFalse(result["backup_readiness_proven"])
            self.assertEqual((run/"operation.json").read_bytes(), original)
            with self.assertRaisesRegex(RuntimeError, "already sent"):
                self.invoke(argv)
        self.assertFalse(Path(directory).exists())

    def test_foreign_operation_old_release_change_or_tool_hash_change_refuses(self):
        for fault in ("operation", "release", "tool"):
            with tempfile.TemporaryDirectory(prefix="database-only-model-") as directory:
                argv, release, run, tools = self.fixture(Path(directory).resolve())
                if fault == "operation":
                    argv[argv.index("--expected-operation")+1] = "4" * 32
                elif fault == "release":
                    (release/"operator-release-pins.json").write_bytes(b"changed")
                else:
                    (tools/"system-backup-original-upgrade199.py").write_bytes(b"changed")
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    self.invoke(argv)
                self.assertFalse((run/"model-dispatch.json").exists())

    def test_nonroot_cannot_select_code_or_dispatch_original_maintenance(self):
        with tempfile.TemporaryDirectory(prefix="database-only-nonroot-") as directory:
            argv, release, run, tools = self.fixture(Path(directory).resolve())
            with patch.object(d.os, "geteuid", return_value=1000), self.assertRaises(ValueError):
                self.invoke(argv)
            self.assertFalse((run/"model-dispatch.json").exists())
            self.assertFalse((run/"db-prepare.send-unknown.json").exists())
            self.assertFalse((run/"database-maintenance-code-selection.json").exists())


if __name__ == "__main__":
    unittest.main()
