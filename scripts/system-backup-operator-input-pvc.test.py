"""Finite offline models; uses actual create-only journal, no cluster/native IO."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_deployment", BASE/"system-backup-operator-deployment.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InputsPVCModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".pvc-model-", dir=BASE)
        self.directory = Path(self.temp.name).resolve()
        # Verify cleanup target BEFORE TemporaryDirectory's recursive cleanup.
        self.assertTrue(self.directory.is_relative_to(BASE))
        self.addCleanup(self.temp.cleanup)
        self.tool = m.DeploymentStages.__new__(m.DeploymentStages)
        self.tool.directory = self.directory
        self.tool.operation = "a"*32
        self.tool.prefix = "sbk-"+"a"*12
        self.tool.a = types.SimpleNamespace(deployment_inputs_storage_class="longhorn-rwx")
        self.storage = {"metadata": {"name": "longhorn-rwx", "uid": "actual-class-uid"},
                        "provisioner": "driver.longhorn.io", "volumeBindingMode": "WaitForFirstConsumer", "parameters": {"replicas": "3"}}
        self.tool.op = types.SimpleNamespace(k=lambda *args: m.encoded(self.storage), kube=self.directory/"original.kube")
        self.current = None
        self.tool.get = lambda kind, name: copy.deepcopy(self.current)

    def native_create(self, argv, **kwargs):
        self.current = json.loads(kwargs["input"])
        self.current["metadata"].update(uid="actual-original-inputs-uid", resourceVersion="1")
        self.current["status"] = {"phase": "Pending"}
        kwargs["stdout"].write(m.encoded(self.current))
        return types.SimpleNamespace(returncode=0)

    def test_one_create_pending_then_bound_reused_same_uid_and_spec(self):
        with patch.object(m.subprocess, "run", side_effect=self.native_create) as create:
            first = self.tool.prepare_inputs_pvc()
            self.assertEqual(first["status"]["phase"], "Pending")
            self.assertEqual(first["spec"]["accessModes"], ["ReadWriteMany"])
            self.assertEqual(first["spec"]["storageClassName"], "longhorn-rwx")
            self.assertEqual(first["metadata"]["annotations"][m.MARKER], self.tool.operation)
            self.current["spec"]["volumeName"] = "actual-native-pv"
            self.current["status"]["phase"] = "Bound"
            second = self.tool.prepare_inputs_pvc()
            self.assertEqual(first["metadata"]["uid"], second["metadata"]["uid"])
            self.assertEqual(create.call_count, 1)
            self.assertEqual(self.tool.pvc_definition("private", "1Gi", "longhorn")["spec"]["accessModes"], ["ReadWriteOnce"])

    def test_foreign_uid_owner_class_spec_and_rebinding_refused_without_create(self):
        with patch.object(m.subprocess, "run", side_effect=self.native_create) as create:
            self.tool.prepare_inputs_pvc()
            original = copy.deepcopy(self.current)
            for mutate in (lambda x: x["metadata"].update(uid="foreign"),
                           lambda x: x["metadata"]["annotations"].update({m.MARKER: "foreign"}),
                           lambda x: x["spec"].update(storageClassName="longhorn"),
                           lambda x: x["spec"].update(accessModes=["ReadWriteOnce"]),
                           lambda x: x["spec"].update(dataSource={"kind": "VolumeSnapshot", "name": "foreign"})):
                self.current = copy.deepcopy(original)
                mutate(self.current)
                with self.assertRaises(m.Refused):
                    self.tool.prepare_inputs_pvc()
            self.current = copy.deepcopy(original)
            self.current["spec"]["volumeName"] = "first-native-pv"
            self.tool.prepare_inputs_pvc()
            self.current["spec"]["volumeName"] = "foreign-pv"
            with self.assertRaises(m.Refused):
                self.tool.prepare_inputs_pvc()
            self.assertEqual(create.call_count, 1)
            self.storage["metadata"]["uid"] = "replaced-class"
            with self.assertRaises(m.Refused):
                self.tool.prepare_inputs_pvc()

    def test_unknown_send_keeps_original_intent_and_never_resends(self):
        with patch.object(m.subprocess, "run", side_effect=subprocess.TimeoutExpired("original-create", 1)) as create:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.tool.prepare_inputs_pvc()
            with self.assertRaises(m.Refused):
                self.tool.prepare_inputs_pvc()
            self.assertEqual(create.call_count, 1)

    def test_actual_new_image_creates_before_patch_and_rollout_host_reuses(self):
        tree = ast.parse((BASE/"system-backup-operator-deployment.py").read_bytes())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DeploymentStages")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "new_image")
        calls = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        prepare = min(n.lineno for n in calls if n.func.attr == "prepare_inputs_pvc" and n.col_offset == 21)
        patch_line = next(n.lineno for n in calls if n.func.attr == "kubectl" and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "new-image-app-patch")
        rollout = next(n.lineno for n in calls if n.func.attr == "business_rollout")
        self.assertLess(prepare, patch_line)
        self.assertLess(patch_line, rollout)
        host = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "host_observer")
        self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "prepare_inputs_pvc" for n in ast.walk(host)))


if __name__ == "__main__":
    unittest.main()
