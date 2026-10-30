import argparse
import contextlib
import importlib.util
import io
import json
import pathlib
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("isolated", pathlib.Path(__file__).with_name("system-backup-seal-isolated-probe.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProbeTests(unittest.TestCase):
    def args(self, **kw):
        return argparse.Namespace(**(dict(image="registry/probe@sha256:" + "a" * 64,
            controller_node="node-a", worker_node="node-b", context="test",
            kubectl="kubectl", storage_class="test", execute=True) | kw))

    def test_plan_has_no_cluster_calls(self):
        with patch.object(module.subprocess, "run") as call, contextlib.redirect_stdout(io.StringIO()):
            module.run(self.args(execute=False))
        call.assert_not_called()

    def test_unpinned_or_same_node_rejected(self):
        for args in [self.args(image="registry/probe:latest"), self.args(worker_node="node-a")]:
            with self.assertRaises(ValueError), patch.object(module.subprocess, "run") as call:
                module.run(args)
            call.assert_not_called()

    def scenario(self, fail_probe=False, fail_delete=False, fail_ready=False):
        objects, deletes, creates = {}, [], []
        def execute(argv, input=None, **kwargs):
            out = {}
            if "create" in argv:
                out = json.loads(input)
                kind = out["kind"].lower()
                kind = {"persistentvolumeclaim": "pvc"}.get(kind, kind)
                out["metadata"]["uid"] = kind + "-" + out["metadata"]["name"]
                creates.append(kind)
                if kind == "pod":
                    out["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}], "containerStatuses": [{"imageID": "registry/probe@sha256:" + "a" * 64}]}
                    if fail_ready:
                        out["status"] = {"phase": "Failed", "reason": "OutOfpods", "message": "110/110"}
                if kind == "pvc":
                    out["spec"]["volumeName"] = "pv-" + out["metadata"]["name"]
                objects[kind, out["metadata"]["name"]] = out
            elif "get" in argv:
                idx = argv.index("get")
                kind, name = argv[idx + 1:idx + 3]
                if kind == "node":
                    out = {"metadata": {"uid": name}, "status": {"nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}}}
                elif kind == "storageclass":
                    out = {"metadata": {"uid": "sc"}, "reclaimPolicy": "Delete"}
                elif kind == "pv":
                    out = {"metadata": {"name": name, "uid": name + "-uid"}, "spec": {
                        "persistentVolumeReclaimPolicy": "Delete", "claimRef": {"uid": "pvc-" + name[3:]}}}
                elif kind == "pvc" and name == "-o":
                    out = {"items": [v for (k, n), v in objects.items() if k == "pvc"]}
                elif kind == "pod,pvc":
                    self.assertFalse(deletes, "diagnostics must precede deletion")
                    out = {"items": [v for (k, n), v in objects.items() if k in ("pod", "pvc")]}
                elif kind == "events":
                    out = {"items": [{"reason": "OutOfpods", "message": "test capacity failure"}]}
                else:
                    out = objects[kind, name]
            elif "delete" in argv:
                deletes.append(json.loads(input))
                if fail_delete:
                    return types.SimpleNamespace(returncode=1, stderr="deletion refused", stdout="")
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr="")
        output = io.StringIO()
        # Keep the real probe module, replacing only its run function after import.
        original = module.importlib.util.module_from_spec
        def imported(s):
            result = original(s)
            loader = s.loader
            original_exec = loader.exec_module
            def load(m):
                original_exec(m)
                def probe_run(args):
                    self.assertEqual(args.worker_node, "node-b")
                    if fail_probe:
                        raise RuntimeError("probe failed")
                m.run = probe_run
            loader.exec_module = load
            return result
        with patch.object(module.subprocess, "run", side_effect=execute), patch.object(module.importlib.util, "module_from_spec", side_effect=imported), contextlib.redirect_stdout(output):
            if fail_probe or fail_delete or fail_ready:
                with self.assertRaises(RuntimeError):
                    module.run(self.args())
            else:
                module.run(self.args())
        report = json.loads(output.getvalue().splitlines()[-1])
        self.assertFalse(report["production_accepted"])
        self.assertEqual(report["passed"], not (fail_probe or fail_ready))
        self.assertEqual(report["cleaned"], not fail_delete)
        self.assertEqual(deletes[0]["preconditions"]["uid"], report["namespace_uid"])
        self.assertEqual(creates.count("pvc"), 2)
        if fail_ready:
            self.assertEqual(report["failure_stage"], "wait-controller-ready")
            self.assertEqual(report["diagnostics"]["events"][0]["reason"], "OutOfpods")
            self.assertEqual(len(report["diagnostics"]["resources"]), 3)

    def test_success_cleanup(self):
        self.scenario()

    def test_probe_failure_cleanup(self):
        self.scenario(fail_probe=True)

    def test_cleanup_failure_not_success(self):
        self.scenario(fail_delete=True)

    def test_startup_failure_keeps_diagnostics_then_cleans(self):
        self.scenario(fail_ready=True)

    def test_diagnostics_reject_replaced_namespace(self):
        from unittest.mock import Mock
        command = Mock()
        with self.assertRaises(ValueError):
            module.startup_diagnostics(command, Mock(return_value={"metadata": {"uid": "replacement"}}), "run", "original")
        command.assert_not_called()

    def test_terminal_pod_fails_without_sleep(self):
        from unittest.mock import Mock
        pod = {"metadata": {"uid": "uid"}, "status": {"phase": "Failed", "reason": "OutOfpods"}}
        with patch.object(module.time, "sleep") as sleep, self.assertRaisesRegex(RuntimeError, "OutOfpods"):
            module.wait_controller_ready(Mock(return_value=pod), "uid")
        sleep.assert_not_called()

    def test_pending_pod_deadline_is_bounded(self):
        from unittest.mock import Mock
        pod = {"metadata": {"uid": "uid"}, "status": {"phase": "Pending"}}
        with patch.object(module.time, "monotonic", side_effect=[0, 301]), patch.object(module.time, "sleep") as sleep, self.assertRaisesRegex(RuntimeError, "timeout"):
            module.wait_controller_ready(Mock(return_value=pod), "uid")
        sleep.assert_not_called()

    def test_capacity_inventory_only_reads_and_counts_active_pods(self):
        node = {"metadata": {"name": "node", "uid": "node-uid"}, "status": {"allocatable": {"pods": "110"}, "conditions": [{"type": "Ready", "status": "True"}]}}
        pods = [{"spec": {"nodeName": "node"}, "status": {"phase": phase}} for phase in ["Running", "Pending", "Failed", "Succeeded"]]
        results = [types.SimpleNamespace(returncode=0, stdout=json.dumps({"items": items})) for items in [[node], pods]]
        with patch.object(module.subprocess, "run", side_effect=results) as command:
            result = module.node_capacity_inventory("kubectl", "test")
        row = result["nodes"][0]
        self.assertEqual(row["active_pods"], 2)
        self.assertEqual(row["total_bound_pods"], 4)
        self.assertEqual(row["estimated_free_pods"], 108)
        self.assertTrue(result["read_only"])
        for call in command.call_args_list:
            self.assertIn("get", call.args[0])
            self.assertNotIn("create", call.args[0])


if __name__ == "__main__":
    unittest.main()
