"""Synthetic component cases only; no kubectl, cluster, or filesystem outputs."""

import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "b_scheduling_preflight", Path(__file__).with_name("system-backup-b-scheduling-preflight.py")
)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def node():
    return {"metadata": {"name": "node1", "uid": "node-uid", "resourceVersion": "4"},
            "spec": {}, "status": {"allocatable": {"pods": "110"},
            "conditions": [{"type": "Ready", "status": "True"}]}}


class SchedulingObservationTests(unittest.TestCase):
    def test_full_node_and_terminal_objects_stay_distinct(self):
        result = preflight.summarize_node(node(), "P|Running|\n" * 109 + "P|Succeeded|\n", 1)
        self.assertEqual(result["bound_pods"], 110)
        self.assertEqual(result["nonterminal_pods"], 109)
        self.assertEqual(result["headroom_all_bound"], 0)
        self.assertEqual(result["headroom_nonterminal"], 1)
        self.assertEqual(result["conservative_slot_shortfall"], 1)

    def test_pending_terminating_and_unreported_count_as_occupied(self):
        result = preflight.summarize_node(node(), "P|Pending|\nP|Running|2026-11-02T10:00:00Z\nP||\n", 2)
        self.assertEqual(result["bound_pods"], 3)
        self.assertEqual(result["nonterminal_pods"], 3)
        self.assertEqual(result["terminating_bound_pods"], 1)
        self.assertEqual(result["phases"]["Unknown"], 1)

    def test_empty_node_and_overcommitted_node(self):
        self.assertEqual(preflight.summarize_node(node(), "", 2)["headroom_all_bound"], 110)
        result = preflight.summarize_node(node(), "P|Running|\n" * 111, 1)
        self.assertEqual(result["headroom_all_bound"], -1)
        self.assertEqual(result["conservative_slot_shortfall"], 2)

    def test_invalid_phases_and_allocatable_rejected(self):
        for raw in ("Running\n", "P|Other|\n", "P|Running|extra|field\n"):
            with self.assertRaises(preflight.ObservationError):
                preflight.summarize_node(node(), raw, 1)
        invalid = node()
        invalid["status"]["allocatable"]["pods"] = "110m"
        with self.assertRaises(preflight.ObservationError):
            preflight.summarize_node(invalid, "", 1)

    def test_node_replacement_or_deletion_rejected(self):
        with self.assertRaises(preflight.ObservationError):
            preflight.identity(node(), "node1", "different-uid", "identity")
        deleting = node()
        deleting["metadata"]["deletionTimestamp"] = "2026-11-02T10:00:00Z"
        with self.assertRaises(preflight.ObservationError):
            preflight.identity(deleting, "node1", "node-uid", "identity")

    def test_claim_binding_and_output_exclude_storage_locations(self):
        claim = {"metadata": {"name": "staging", "namespace": "target", "uid": "claim-uid"},
                 "spec": {"volumeName": "staging-pv", "accessModes": ["ReadWriteOnce"]},
                 "status": {"phase": "Bound"}}
        volume = {"metadata": {"name": "staging-pv", "uid": "pv-uid"}, "spec": {
            "claimRef": {"namespace": "target", "name": "staging", "uid": "claim-uid"},
            "hostPath": {"path": "DO-NOT-PRINT-STORAGE-PATH"}}}
        result = preflight.summarize_claim("target", claim, volume)
        self.assertEqual(result["storage_kind"], "hostPath")
        self.assertNotIn("DO-NOT-PRINT", json.dumps(result))
        self.assertEqual(result["job_volume_topology_fit"], "not_verified")
        volume["spec"]["claimRef"]["uid"] = "replacement-claim"
        with self.assertRaises(preflight.ObservationError):
            preflight.summarize_claim("target", claim, volume)


if __name__ == "__main__":
    unittest.main()
