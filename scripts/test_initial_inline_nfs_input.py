"""Actual producer models; metadata only, never native source qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import secrets
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("initial_inline_nfs_input_model", Path(__file__).with_name("system-backup-initial-complete-inputs.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InlineNFSInputModels(unittest.TestCase):
    def fixture(self):
        token = secrets.token_hex(5)
        provider, consumer = "provider-" + token, "consumer-" + token
        names = {k: k + "-" + token for k in ("service", "pod", "claim", "pv", "node")}
        uid = lambda key: names.get(key, key) + "-uid"
        records, calls = [], []
        data = {"RuntimeTestScope": None, "Instances": [{"ID": 7, "UserID": 3, "Generation": 2, "Workspace": "/work/users/3/instances/7"}]}
        service = {"metadata": {"name": names["service"], "namespace": provider, "uid": uid("service")}, "spec": {"clusterIP": "10.99.1.2", "selector": {"role": "server"}}}
        pv_spec = {"claimRef": {"uid": uid("claim"), "name": names["claim"], "namespace": provider}, "hostPath": {"path": "/srv/" + token}}
        objects = {
            ("namespace", provider, None): {"metadata": {"name": provider, "uid": uid(provider)}},
            ("endpoints", names["service"], provider): {"metadata": {"uid": uid("endpoints")}, "subsets": [{"addresses": [{"ip": "10.2.1.3", "targetRef": {"kind": "Pod", "namespace": provider, "name": names["pod"], "uid": uid("pod")}}]}]},
            ("pod", names["pod"], provider): {"metadata": {"name": names["pod"], "uid": uid("pod"), "labels": {"role": "server"}}, "status": {"podIP": "10.2.1.3"}, "spec": {"nodeName": names["node"], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": names["claim"]}}], "containers": [{"name": "server", "volumeMounts": [{"name": "data", "mountPath": "/exports/" + token}]}]}},
            ("pvc", names["claim"], provider): {"metadata": {"name": names["claim"], "uid": uid("claim")}, "spec": {"volumeName": names["pv"]}, "status": {"phase": "Bound"}},
            ("pv", names["pv"], None): {"metadata": {"name": names["pv"], "uid": uid("pv")}, "spec": pv_spec},
            ("node", names["node"], None): {"metadata": {"name": names["node"], "uid": uid("node")}},
        }
        def command(*args):
            calls.append(args)
            self.assertIn("get", args)
            self.assertFalse({"exec", "patch", "create", "delete", "scale", "apply"}.intersection(args))
            if args == ("get", "services", "-A", "-o", "json"):
                return json.dumps({"items": [service]}).encode()
            ns = args[1] if args[0] == "-n" else None
            index = args.index("get")
            return json.dumps(objects[(args[index+1], args[index+2], ns)]).encode()
        def need(value, code):
            if not value:
                raise ValueError(code)
        module = types.SimpleNamespace(need=need, decode=json.loads)
        stages = types.SimpleNamespace(op=types.SimpleNamespace(k=command), retain=lambda name, value: records.append((name, value)))
        return module, stages, data, {"server": "10.99.1.2", "path": "/"}, records, calls, provider, consumer, objects, names

    def test_random_namespace_provider_and_original_sql_paths_consumed(self):
        for _ in range(8):
            module, stages, data, source, records, calls, provider, consumer, objects, names = self.fixture()
            result = m.inline_nfs_workspace(module, stages, data, "/work", "", source, "stage-node")
            self.assertEqual(result["claim"], "")
            self.assertEqual(result["nfs"]["provider"]["Namespace"], provider)
            self.assertNotEqual(provider, consumer)
            self.assertEqual(result["nfs"]["original_paths"], [{"InstanceID": 7, "UserID": 3, "Generation": 2, "SubPath": "users/3/instances/7"}])
            self.assertEqual(result["nfs"]["provider"]["PVSpec"], objects[("pv", names["pv"], None)]["spec"])
            self.assertFalse(records[0][1]["physical_export_mapping_proven"])
            self.assertFalse(records[0][1]["writers_fenced"])
            self.assertTrue(all(consumer not in c for c in calls))

    def test_foreign_claim_binding_and_whole_root_or_escape_rejected(self):
        for fault in ("claim", "root", "escape"):
            f = self.fixture()
            module, stages, data, source, _, _, _, _, objects, names = f
            if fault == "claim":
                objects[("pv", names["pv"], None)]["spec"]["claimRef"]["uid"] = "foreign-claim"
            else:
                data["Instances"][0]["Workspace"] = "/work" if fault == "root" else "/work/../foreign"
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.inline_nfs_workspace(module, stages, data, "/work", "", source, "stage-node")


class ActualOperatorInlineNFSBranchModels(unittest.TestCase):
    def test_actual_entry_uses_bound_NFS_without_localizing_and_PVC_keeps_original_guard(self):
        entry = importlib.util.spec_from_file_location("actual_operator_nfs_model", Path(__file__).with_name("system-backup-zhanghui08-operator.py"))
        operator_module = importlib.util.module_from_spec(entry)
        entry.loader.exec_module(operator_module)
        for nfs_mode in (False, True):
            actions = []
            owner = operator_module.Operator.__new__(operator_module.Operator)
            app = {"metadata": {"uid": "app-uid"}, "spec": {"template": {"spec": {"volumes": [{"name": "share", "nfs": {"server": "10.99.1.2", "path": "/"}}]}}}}
            owner.open = lambda: {"app": app, "app_deployment_uid": "app-uid", "namespace_uid": "consumer-uid"}
            owner.final_binding = lambda: {"deployment": {"File": "model-core", "SHA256": "model-only"}}
            owner.pin_value = lambda value: "model-core"
            core = {"namespace_uid": "consumer-uid", "workspace": {"claim": "original-claim"}}
            if nfs_mode:
                core["workspace"] = {"claim": "", "nfs": {"server": "10.99.1.2", "export": "/", "original_paths": [{"InstanceID": 7}], "provider": {"ServiceUID": "actual-service-uid"}}}
            workspace = types.SimpleNamespace(verify_localized=lambda op: actions.append("original-localized-readback"))
            runtime = types.SimpleNamespace(verify_current=lambda op: actions.append("actual-runtime-readback"))
            with patch.object(operator_module, "load", return_value=core), patch.object(operator_module, "workspace_module", return_value=workspace), patch.object(operator_module, "business_runtime_module", return_value=runtime):
                owner.require_current_runtime_qualification()
            self.assertEqual(actions, ["actual-runtime-readback"] if nfs_mode else ["original-localized-readback", "actual-runtime-readback"])


if __name__ == "__main__":
    unittest.main()
