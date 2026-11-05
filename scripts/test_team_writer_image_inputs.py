"""Pure original-receipt projection tests; no live/native acceptance claim."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("team_writer_image_inputs", Path(__file__).with_name("system-backup-initial-complete-inputs.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Refused(Exception):
    pass

class Model:
    @staticmethod
    def need(ok, code):
        if not ok:
            raise Refused(code)
    @staticmethod
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()
    @staticmethod
    def decode(raw):
        return json.loads(raw)
    @staticmethod
    def image_id(value):
        return value.rsplit("@", 1)[-1].removeprefix("containerd://").removeprefix("docker://")
    def pin(self, path):
        raw = self.files[str(path)]
        return {"File": str(path), "SHA256": self.digest(raw)}
    def pinned(self, value):
        raw = self.files[value["File"]]
        self.need(self.digest(raw) == value["SHA256"], "pin drift")
        return raw

class OriginalWriterImagesTest(unittest.TestCase):
    def fixture(self):
        m = Model()
        directory = Path("/original/deployment")
        image = {"reference": "original/app@sha256:" + "a" * 64, "manifest_sha256": "a" * 64,
                 "config_digest": "sha256:" + "c" * 64, "commit": "1" * 40}
        images = {"app": image, "worker": {"reference": "original/worker@sha256:" + "b" * 64}}
        app = {"metadata": {"name": "app", "namespace": "source", "uid": "deployment-uid"},
               "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "business", "image": image["reference"]}]}}}}
        plan = {"images": images, "original_uid": "deployment-uid", "desired_spec": copy.deepcopy(app["spec"])}
        m.files = {str(directory / "new-image.plan.json"): m.encoded(plan), str(directory / "images.actual.json"): m.encoded(images)}
        result = {"version": "operator-new-image-result.v1", "state": "actual_full_business_mysql_tls_template_and_same_release_rollout_verified",
                  "images": images, "plan": m.pin(directory / "new-image.plan.json"),
                  "app": {"Name": "app", "UID": "deployment-uid", "SpecSHA256": m.digest(m.encoded(app["spec"]))},
                  "business_pods": [{"PodUID": "pod-uid", "ReplicaSetUID": "rs-uid", "ContainerID": "container-id", "ImageID": "docker://" + image["config_digest"]}]}
        m.files[str(directory / "new-image.result.json")] = m.encoded(result)
        return m, SimpleNamespace(directory=directory), app

    def test_uses_business_release_with_distinct_worker(self):
        m, stages, app = self.fixture()
        result = module.team_writer_images(m, stages, app, "source")
        pin = result["deployment/source/app"][0]
        self.assertEqual(pin["Container"], "business")
        self.assertEqual(pin["Image"], "original/app@sha256:" + "a" * 64)
        self.assertEqual(pin["BuildCommit"], "1" * 40)
        self.assertEqual(pin["ConfigDigest"], "sha256:" + "c" * 64)

    def test_live_drift_cannot_supply_expected_release(self):
        for drift in ("uid", "image", "env", "namespace"):
            with self.subTest(drift=drift):
                m, stages, app = self.fixture()
                if drift == "uid":
                    app["metadata"]["uid"] = "foreign"
                elif drift == "namespace":
                    app["metadata"]["namespace"] = "foreign"
                elif drift == "image":
                    app["spec"]["template"]["spec"]["containers"][0]["image"] = "foreign/app@sha256:" + "d" * 64
                else:
                    app["spec"]["template"]["spec"]["containers"][0]["env"] = [{"name": "DRIFT", "value": "yes"}]
                with self.assertRaises(Refused):
                    module.team_writer_images(m, stages, app, "source")

    def test_receipt_drift_and_missing_pods_refuse(self):
        for drift in ("images", "pod-content", "missing-pods", "plan"):
            with self.subTest(drift=drift):
                m, stages, app = self.fixture()
                path = str(stages.directory / "new-image.result.json")
                result = m.decode(m.files[path])
                if drift == "images":
                    result["images"]["app"]["reference"] = "foreign/app@sha256:" + "d" * 64
                elif drift == "pod-content":
                    result["business_pods"][0]["ImageID"] = "containerd://sha256:" + "b" * 64
                elif drift == "missing-pods":
                    result["business_pods"] = []
                else:
                    result["plan"]["SHA256"] = "0" * 64
                m.files[path] = m.encoded(result)
                with self.assertRaises(Refused):
                    module.team_writer_images(m, stages, app, "source")

if __name__ == "__main__":
    unittest.main()
