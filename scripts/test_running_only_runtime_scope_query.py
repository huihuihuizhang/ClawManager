"""Exercise the actual v2 query route without launching a producer."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m = load("system-backup-operator-deployment")
operator = load("system-backup-zhanghui08-operator")
source = load("system-backup-initial-source-data")
complete = load("system-backup-initial-complete-inputs")


class QueryReadbackModels(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.stage = "initial-source-coordinates"
        self.run = root / "run"
        self.staging = self.run / "deployment"
        self.staging.mkdir(parents=True)
        self.mirror = root / "runtime"
        self.output = self.mirror / self.stage
        self.output.mkdir(parents=True)
        patched = patch.object(m, "RUNTIME", str(self.mirror))
        patched.start()
        self.addCleanup(patched.stop)
        self.target = {"InstallationID": "original", "Namespace": "source", "NamespaceUID": "ns-uid", "ServerUUID": "server", "Database": "db"}
        self.operation = "3" * 32
        self.roster = "7,8,11:12,13,14"
        rows = [dict(ID=i, UserID=1, Generation=1, Type=t, Mode=mode, Status=status, OS="linux")
                for i, t, mode, status in [(7, "openclaw", "lite", "running"), (8, "hermes", "lite", "running"),
                                          (11, "openclaw", "lite", "running"), (12, "openclaw", "pro", "stopped"),
                                          (13, "opencode", "lite", "error"), (14, "deepseek-harness", "lite", "error")]]
        data = dict(self.target, Version="original-initial-source-coordinates.v1", Instances=rows,
                    RuntimeTestScope=dict(self.target, Version="explicit-running-only-runtime-test-scope.v2",
                                          Deferred=rows[3:], OriginalInstancesSHA256=m.digest(m.encoded(rows))))
        self.owner_file = self.mirror / "operator-owner.json"
        self.write(self.owner_file, {"operation": self.operation, "run": str(self.run)})
        self.coordinates_file = self.output / "initial-source-coordinates.json"
        self.census_file = self.output / "initial-source-kubernetes.private.json"
        self.write(self.coordinates_file, data)
        self.write(self.census_file, {"Pods": [], "Deployments": [], "Claims": []})
        self.native = {"Version": "original-initial-source-data-authored.v1", "WriterQualified": False, "BackupReady": False,
                       "Coordinates": m.pin(self.coordinates_file), "KubernetesSnapshot": m.pin(self.census_file), "InstanceCount": 6}
        self.intent_file = self.staging / (self.stage + ".send-unknown.json")
        self.receipt_file = self.staging / (self.stage + ".readback.json")
        self.stdout = self.staging / (self.stage + ".stdout.private")
        self.stderr = self.staging / (self.stage + ".stderr.private")
        self.write(self.stdout, self.native)
        self.stderr.touch(mode=0o600)
        self.intent = {"stage": self.stage, "operation": self.operation, "input": None,
                       "argv": ["sealed-coordinates", "author-initial-source-coordinates", "--output-directory", str(self.output),
                                "--running-only-runtime-test", self.roster]}
        self.receipt = {"stage": self.stage, "stdout": m.pin(self.stdout), "stderr_sha256": m.digest(b""), "exit_code": 0}
        self.write(self.intent_file, self.intent)
        self.write(self.receipt_file, self.receipt)
        op = operator.Operator(SimpleNamespace(release_directory=root, run_directory=self.run))
        self.stages = SimpleNamespace(a=SimpleNamespace(running_only_runtime_test=self.roster), directory=self.staging,
                                      operation=self.operation, run=self.run, op=op,
                                      common=lambda: ([], None, {"Target": self.target}, None), binary=lambda name: "sealed-coordinates",
                                      runtime_mirror=self.forbidden, retain=self.forbidden, call=self.forbidden)

    def forbidden(self, *args, **kwargs):
        self.fail("query must not dispatch or write a producer receipt")

    def write(self, path, value):
        path.write_bytes(m.encoded(value))
        path.chmod(0o600)

    def query(self):
        return complete.runtime_test_scope_action(m, self.stages, source, query_only=True)

    def test_retained_readback_without_wrapper_or_binding_returns_scope_without_writes(self):
        before = {path.name for path in self.staging.iterdir()}
        value = self.query()
        self.assertEqual(value["SQLInstanceCount"], 6)
        self.assertEqual(value["PlannedRuntimeInstanceCount"], 3)
        self.assertEqual({path.name for path in self.staging.iterdir()}, before)

    def test_missing_intent_with_readback_refuses_without_dispatch(self):
        self.intent_file.unlink()
        with self.assertRaisesRegex(m.Refused, "intent_and_readback_required"):
            self.query()

    def test_tampered_intent_operation_or_command_refuses(self):
        for changed in [{**self.intent, "operation": "4" * 32}, {**self.intent, "argv": self.intent["argv"][:-1]}, {**self.intent, "input": {}}]:
            with self.subTest(changed=changed):
                self.write(self.intent_file, changed)
                with self.assertRaisesRegex(m.Refused, "query_intent_changed"):
                    self.query()

    def test_tampered_readback_receipt_or_stdout_refuses(self):
        for changed in [{**self.receipt, "exit_code": 1}, {**self.receipt, "stage": "other"},
                        {**self.receipt, "stdout": {**self.receipt["stdout"], "File": str(self.census_file)}}]:
            with self.subTest(changed=changed):
                self.write(self.receipt_file, changed)
                with self.assertRaisesRegex(m.Refused, "query_readback_changed"):
                    self.query()
        self.write(self.receipt_file, self.receipt)
        self.write(self.stdout, {**self.native, "InstanceCount": 5})
        with self.assertRaisesRegex(m.Refused, "producer_file_pin_changed"):
            self.query()

    def test_tampered_stderr_and_native_nested_pin_refuse(self):
        self.stderr.write_bytes(b"changed")
        with self.assertRaisesRegex(operator.Stop, "actual_producer_file_pin_changed"):
            self.query()
        self.stderr.write_bytes(b"")
        self.write(self.coordinates_file, {"changed": True})
        with self.assertRaisesRegex(m.Refused, "producer_file_pin_changed"):
            self.query()

    def test_tampered_existing_binding_refuses_without_replacement(self):
        binding = self.staging / "initial-runtime-test-scope.binding-data.json"
        self.write(binding, {"changed": True})
        with self.assertRaisesRegex(m.Refused, "binding_changed_no_replacement"):
            self.query()
        self.assertEqual(binding.read_bytes(), m.encoded({"changed": True}))


if __name__ == "__main__":
    unittest.main()
