"""Isolated Kubernetes response models. No cluster, SSH, SQL or subprocess."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name("system-backup-b-writer-inventory.py")
SPEC = importlib.util.spec_from_file_location("b_writer_inventory", SOURCE)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.counts = {}
        self.change = None

    def get(self, resource, namespace=None, name=None):
        self.calls.append((resource, namespace, name))
        self.counts[resource] = self.counts.get(resource, 0) + 1
        if resource == "namespace":
            value = {"metadata": {"name": "test", "uid": "ns-original"}}
        elif resource == "node":
            value = {"metadata": {"name": "node", "uid": "node-uid"}, "status": {"nodeInfo": {"operatingSystem": "linux", "architecture": "amd64"}}}
        elif resource == "pv":
            value = {"metadata": {"name": "pv", "uid": "pv-uid"}, "spec": {"claimRef": {"namespace": "test", "name": "data", "uid": "claim-uid"}, "hostPath": {"path": "/data/owned", "type": "Directory"}}}
        else:
            items = []
            if resource == "pods":
                items = [{"metadata": {"namespace": "test", "name": "runtime", "uid": "pod-uid", "resourceVersion": "1"}, "spec": {"nodeName": "node", "containers": [{"name": "agent", "image": "image@sha256:fixture", "env": [{"name": "PASSWORD", "value": "PRIVATE_PASSWORD"}], "args": ["PRIVATE_ARGUMENT"], "volumeMounts": [{"name": "data", "mountPath": "/workspaces", "subPath": "user/instance"}]}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}, {"name": "identity", "projected": {"sources": [{"secret": {"name": "PRIVATE_SECRET_REF"}}]}}]}, "status": {"phase": "Running", "containerStatuses": [{"name": "agent", "state": {"running": {"startedAt": "2026-11-03T00:00:00Z"}}, "ready": True, "containerID": "containerd://fixture"}]}}]
            elif resource == "persistentvolumeclaims":
                items = [{"metadata": {"namespace": "test", "name": "data", "uid": "claim-uid", "resourceVersion": "2"}, "spec": {"volumeName": "pv"}, "status": {"phase": "Bound"}}]
            value = {"items": items}  # typed-list items may omit TypeMeta
        if self.change:
            value = self.change(resource, self.counts[resource], copy.deepcopy(value))
        return value


class InventoryTests(unittest.TestCase):
    def test_collects_read_only_projection_without_claiming_fence(self):
        api = FakeAPI()
        result = TOOL.collect(api, "test", "ns-original")
        self.assertEqual(result["status"], "observed")
        self.assertFalse(result["physical_fence_proven"])
        self.assertFalse(result["complete_writer_inventory_proven"])
        self.assertFalse(result["first_adoption_authorized"])
        self.assertEqual(len(result["resources"]), 2)
        self.assertEqual(result["persistent_volumes"][0]["storage"]["path"], "/data/owned")
        self.assertEqual(api.counts["namespace"], 2)
        for resource in TOOL.RESOURCES:
            self.assertEqual(api.counts[resource], 2)
        self.assertNotIn("secrets", {r for r, _, _ in api.calls})

    def test_does_not_export_inline_credentials_args_or_projected_secret_refs(self):
        raw = json.dumps(TOOL.collect(FakeAPI(), "test", "ns-original"))
        for value in ("PRIVATE_PASSWORD", "PRIVATE_ARGUMENT", "PRIVATE_SECRET_REF"):
            self.assertNotIn(value, raw)

    def test_wrong_namespace_stops_before_resource_reads(self):
        api = FakeAPI()
        with self.assertRaisesRegex(TOOL.Refused, "namespace_identity_changed"):
            TOOL.collect(api, "test", "wrong")
        self.assertEqual(len(api.calls), 1)

    def test_tail_namespace_replacement_refuses(self):
        api = FakeAPI()
        def replace(resource, count, value):
            if resource == "namespace" and count == 2:
                value["metadata"]["uid"] = "replacement"
            return value
        api.change = replace
        with self.assertRaisesRegex(TOOL.Refused, "namespace_identity_changed"):
            TOOL.collect(api, "test", "ns-original")

    def test_pod_drift_is_not_stability_or_stop_proof(self):
        api = FakeAPI()
        def replace(resource, count, value):
            if resource == "pods" and count == 2:
                value["items"][0]["metadata"]["uid"] = "replacement"
            return value
        api.change = replace
        result = TOOL.collect(api, "test", "ns-original")
        self.assertEqual(result["status"], "observed_drift")
        self.assertEqual(result["changed_resources"], [{"resource": "pods", "name": "runtime"}])
        self.assertFalse(result["physical_fence_proven"])

    def test_incomplete_lists_and_invalid_identities_refuse(self):
        for fault in ("continue", "foreign", "missing-uid", "duplicate", "too-many"):
            with self.subTest(fault=fault):
                api = FakeAPI()
                def change(resource, count, value):
                    if resource == "pods":
                        if fault == "continue": value["metadata"] = {"continue": "more"}
                        elif fault == "foreign": value["items"][0]["metadata"]["namespace"] = "foreign"
                        elif fault == "missing-uid": value["items"][0]["metadata"]["uid"] = ""
                        elif fault == "duplicate": value["items"].append(copy.deepcopy(value["items"][0]))
                        else: value["items"] *= 5001
                    return value
                api.change = change
                with self.assertRaises(TOOL.Refused):
                    TOOL.collect(api, "test", "ns-original")

    def test_storage_classes_are_not_guessed_from_unknown_volume(self):
        unknown = TOOL.volume_source({"csi": {"driver": "unknown", "volumeAttributes": {"password": "PRIVATE"}}})
        self.assertEqual(unknown["kind"], "unsupported_or_unknown")
        self.assertTrue(unknown["requires_owner_review"])
        self.assertNotIn("PRIVATE", json.dumps(unknown))


if __name__ == "__main__":
    unittest.main(verbosity=2)
