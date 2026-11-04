import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).with_name("system-backup-minio-first-hop-tls.py")
spec = importlib.util.spec_from_file_location("minio_first_hop_actual", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class JournalTests(unittest.TestCase):
    def test_lost_response_is_query_only_and_can_confirm_original(self):
        for committed in (False, True):
            with self.subTest(committed=committed), tempfile.TemporaryDirectory(prefix="a-minio-tls-test-") as tmp:
                directory = Path(tmp)
                sends = []
                target = []
                def send():
                    sends.append(1)
                    self.assertTrue((directory / "tls.sent.json").is_file())
                    if committed:
                        target.append({"uid": "original"})
                    raise OSError("reply lost")
                query = lambda: target[0] if target else None
                with self.assertRaises(OSError):
                    m.step(directory, "tls", {"intended": "original"}, send, query)
                if committed:
                    self.assertEqual(m.step(directory, "tls", {"intended": "original"}, send, query), {"uid": "original"})
                else:
                    with self.assertRaises(m.Refused):
                        m.step(directory, "tls", {"intended": "original"}, send, query)
                self.assertEqual(len(sends), 1)

    def test_confirmed_replacement_and_changed_intent_refuse(self):
        with tempfile.TemporaryDirectory(prefix="a-minio-tls-test-") as tmp:
            directory = Path(tmp)
            m.step(directory, "tls", {"original": 1}, lambda: None, lambda: {"uid": "first"})
            with self.assertRaises(m.Refused):
                m.step(directory, "tls", {"original": 1}, lambda: self.fail("replayed"), lambda: {"uid": "replacement"})
            m.durable(directory / "pending.sent.json", m.raw({"original": 1}))
            with self.assertRaises(m.Refused):
                m.step(directory, "pending", {"other": 1}, lambda: self.fail("replayed"), lambda: {"uid": "first"})

    def test_cas_rollback_fences_late_original_patch(self):
        class ActualCASModel:
            def __init__(self):
                self.current = {"metadata": {"name": "minio", "uid": "dep-1", "resourceVersion": "7"}, "spec": {"original": True}}
            def get(self, kind, name):
                return copy.deepcopy(self.current)
            def authority(self):
                pass
            def kube(self, *args, data=None, timeout=45):
                if args[0] == "rollout":
                    return b""
                patch = json.loads(data)
                old = copy.deepcopy(self.current)
                for item in patch:
                    if item["op"] == "test":
                        field = item["path"].split("/")[-1]
                        if old["metadata"][field] != item["value"]:
                            raise m.Refused("CAS conflict")
                for item in patch:
                    if item["path"] == "/spec":
                        self.current["spec"] = item["value"]
                    if item["path"] == "/metadata/annotations":
                        self.current["metadata"]["annotations"] = item["value"]
                self.current["metadata"]["resourceVersion"] = str(int(old["metadata"]["resourceVersion"]) + 1)
                return m.raw(self.current)
        source = ActualCASModel()
        before = copy.deepcopy(source.current)
        plan = {"deployment": before, "desired_spec": {"tls": True}, "operation": "operation-1"}
        with tempfile.TemporaryDirectory(prefix="a-minio-tls-test-") as tmp:
            directory = Path(tmp)
            m.durable(directory / "deployment.sent.json", m.raw({"original": "unknown"}))
            result = m.rollback(source, directory, plan)
            self.assertEqual(result["state"], "original_spec_restored_late_install_fenced")
            self.assertEqual(source.current["spec"], before["spec"])
            with self.assertRaises(m.Refused):
                m.source_patch(source, before, plan["desired_spec"])
            # A confirmed recovery is read back without another mutation.
            rv = source.current["metadata"]["resourceVersion"]
            m.rollback(source, directory, plan)
            self.assertEqual(source.current["metadata"]["resourceVersion"], rv)

    def test_rollback_preserves_foreign_spec(self):
        class Changed:
            def get(self, kind, name):
                return {"metadata": {"name": "minio", "uid": "dep"}, "spec": {"foreign": 1}}
        with tempfile.TemporaryDirectory(prefix="a-minio-tls-test-") as tmp:
            directory = Path(tmp)
            with self.assertRaises(m.Refused):
                m.rollback(Changed(), directory, {"deployment": {"metadata": {"name": "minio", "uid": "dep"}, "spec": {}}, "desired_spec": {"tls": 1}, "operation": "one"})
            self.assertEqual(list(directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
