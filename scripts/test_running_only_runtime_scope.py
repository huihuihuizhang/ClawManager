"""Source-only models of the native coordinate receipt and operator wiring."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


source = load("system-backup-initial-source-data")
complete = load("system-backup-initial-complete-inputs")


def need(ok, code):
    if not ok:
        raise ValueError(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class RunningOnlyScopeModels(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = {"InstallationID": "original", "Namespace": "source", "NamespaceUID": "namespace-uid", "ServerUUID": "server", "Database": "db"}
        self.rows = [dict(ID=i, UserID=1, Generation=1, Type=t, Mode=m, Status=s, OS="linux")
                     for i, t, m, s in [(7, "openclaw", "lite", "running"), (8, "hermes", "lite", "running"),
                                        (11, "openclaw", "lite", "running"), (12, "openclaw", "pro", "stopped"),
                                        (13, "opencode", "lite", "error"), (14, "deepseek-harness", "lite", "error")]]
        self.data = dict(self.target, Version="original-initial-source-coordinates.v1", Instances=self.rows,
                         RuntimeTestScope=dict(self.target, Version="explicit-running-only-runtime-test-scope.v2",
                                               Deferred=self.rows[3:], OriginalInstancesSHA256=digest(encode(self.rows))))
        self.known = {"File": "coordinates", "SHA256": "known-model-pin"}
        self.events = []
        self.outputs = {}
        self.m = SimpleNamespace(need=need, encoded=encode, digest=digest, decode=json.loads,
                                 pinned=lambda selected, **kw: encode(self.data) if selected == self.known else b"{}")
        self.stages = SimpleNamespace(a=SimpleNamespace(running_only_runtime_test="7,8,11:12,13,14"), directory=self.root,
                                      common=lambda: ([], None, {"Target": self.target}, None), runtime_mirror=lambda: self.root,
                                      binary=lambda name: name, call=self.native, retain=lambda name, value: self.outputs.update({name: value}))

    def native(self, stage, argv):
        self.events.append((stage, argv))
        return {"Version": "original-initial-source-data-authored.v1", "WriterQualified": False, "BackupReady": False,
                "Coordinates": self.known, "KubernetesSnapshot": {"File": "model-census"}, "InstanceCount": 6}, {"File": "receipt"}

    def test_live_author_option_and_complete_snapshot_flow_to_scope_binding(self):
        data, pin, _ = source.coordinates(self.m, self.stages)
        self.assertEqual(self.events[0][1][-2:], ["--running-only-runtime-test", "7,8,11:12,13,14"])
        binding = complete.running_only_scope_binding(self.m, self.stages, data, pin)
        self.assertEqual(binding["SQLInstanceCount"], 6)
        self.assertEqual(binding["PlannedRuntimeInstanceCount"], 3)
        self.assertEqual([i["ID"] for i in binding["Deferred"]], [12, 13, 14])
        self.assertFalse(binding["FullRuntimeCoverage"])
        self.assertFalse(binding["ScopeSignedOrAdmitted"])

    def test_same_shape_substitution_refuses_with_original_approved_roster(self):
        self.rows[3]["ID"] = 10
        self.data["RuntimeTestScope"]["OriginalInstancesSHA256"] = digest(encode(self.rows))
        with self.assertRaisesRegex(ValueError, "approved_runtime_test_roster"):
            source.coordinates(self.m, self.stages)

    def test_v2_without_explicit_option_refuses(self):
        self.stages.a.running_only_runtime_test = None
        with self.assertRaisesRegex(ValueError, "explicit_running_only_runtime_test_option"):
            source.coordinates(self.m, self.stages)

    def test_scope_binding_refuses_wrong_snapshot_or_role(self):
        self.rows[3]["Status"] = "running"
        self.data["RuntimeTestScope"]["OriginalInstancesSHA256"] = digest(encode(self.rows))
        with self.assertRaisesRegex(ValueError, "exact_original_running_only_scope"):
            complete.running_only_scope_binding(self.m, self.stages, self.data, self.known)


if __name__ == "__main__":
    unittest.main()
