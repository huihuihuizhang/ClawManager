#!/usr/bin/env python3
"""Root-run regression source. No field, Docker, Go or real authority issuance."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("deployment_stages", Path(__file__).with_name("system-backup-operator-deployment.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Response(io.BytesIO):
    status = 200


class Content:
    def __init__(self, corrupt=None, plain=False):
        self.commit = "a" * 40
        bodies = [b"first-layer-real-EOF" * 100, b"second-layer-real-EOF" * 50]
        self.layers = [bodies[0] if plain else gzip.compress(bodies[0], mtime=0), gzip.compress(bodies[1], mtime=0)]
        config = {"os": "linux", "architecture": "amd64", "config": {"Labels": {"org.opencontainers.image.revision": self.commit}}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + m.digest(b) for b in bodies]}}
        self.config = m.encoded(config)
        self.config_sha = m.digest(self.config)
        descriptor = [{"digest": "sha256:" + m.digest(b), "size": len(b), "mediaType": "application/vnd.oci.image.layer.v1.tar" + ("" if plain and index == 0 else "+gzip")} for index, b in enumerate(self.layers)]
        self.manifest = m.encoded({"schemaVersion": 2, "config": {"digest": "sha256:" + self.config_sha, "size": len(self.config)}, "layers": descriptor})
        self.manifest_sha = m.digest(self.manifest)
        self.mapping = {"manifests/sha256:" + self.manifest_sha: self.manifest, "blobs/sha256:" + self.config_sha: self.config}
        for index, raw in enumerate(self.layers):
            value = raw
            if index == 1 and corrupt == "short":
                value = raw[:-3]
            if index == 1 and corrupt == "changed":
                value = raw[:-1] + bytes([raw[-1] ^ 1])
            self.mapping["blobs/sha256:" + m.digest(raw)] = value
        self.calls = []

    def open(self, request, timeout):
        self.calls.append(request.full_url)
        key = request.full_url.split("/test/", 1)[1]
        return Response(self.mapping[key])

    def qualify(self, expected=None):
        return m.registry_image("10.130.14.23:5000/test@sha256:" + self.manifest_sha,
                                {"config_digest": "sha256:" + (expected or self.config_sha)}, self.commit)


class RegistryTests(unittest.TestCase):
    def test_all_actual_layers_and_uncompressed_diffs(self):
        for plain in (False, True):
            with self.subTest(plain=plain):
                source = Content(plain=plain)
                with patch.object(m.urllib.request, "build_opener", return_value=source):
                    value = source.qualify()
                self.assertEqual(len(value["layers"]), 2)
                self.assertEqual(len(source.calls), 4)

    def test_truncated_or_changed_last_blob_is_not_qualified(self):
        for corruption in ("short", "changed"):
            with self.subTest(corruption=corruption):
                source = Content(corrupt=corruption)
                with patch.object(m.urllib.request, "build_opener", return_value=source), self.assertRaises((m.Refused, m.zlib.error)):
                    source.qualify()

    def test_foreign_release_config_stops_before_any_layer(self):
        source = Content()
        with patch.object(m.urllib.request, "build_opener", return_value=source), self.assertRaises(m.Refused):
            source.qualify("f" * 64)
        self.assertEqual(len(source.calls), 1)

    def test_non_original_origin_or_mutable_reference_rejected(self):
        for value in ("https://other.invalid/test@sha256:" + "a" * 64, "10.130.14.23:5000/test:latest", "10.130.14.23:5000/../test@sha256:" + "a" * 64):
            with self.subTest(value=value), self.assertRaises(m.Refused):
                m.registry_image(value, {}, "a" * 40)


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.original = {"metadata": {"uid": "actual-deployment", "resourceVersion": "10"}, "spec": {"template": {"spec": {"containers": [{"name": "controller", "volumeMounts": [{"name": "inputs", "mountPath": "/run/system-backup"}]}], "volumes": [{"name": "inputs", "persistentVolumeClaim": {"claimName": "actual-inputs"}}]}}}}

    def producer(self, name, rv="10"):
        return [{"op": "test", "path": "/metadata/uid", "value": "actual-deployment"}, {"op": "test", "path": "/metadata/resourceVersion", "value": rv},
                {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": name, "emptyDir": {}}},
                {"op": "add", "path": "/spec/template/spec/initContainers", "value": [{"name": name + "-install"}]},
                {"op": "test", "path": "/spec/template/spec/containers/0/name", "value": "controller"},
                {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": name, "mountPath": "/var/run/" + name}}]

    def test_multiple_no_existing_init_patches_preserve_every_installer(self):
        before = copy.deepcopy(self.original)
        actual = m.merge_material_patches(self.original, [self.producer("redis"), self.producer("provider", rv="11"), self.producer("minio", rv="12")])
        self.assertEqual([c["name"] for c in actual["template"]["spec"]["initContainers"]], ["redis-install", "provider-install", "minio-install"])
        self.assertEqual(len(actual["template"]["spec"]["volumes"]), 4)
        self.assertEqual(self.original, before)

    def test_foreign_uid_replacement_or_duplicate_mount_refused(self):
        variants = []
        foreign = self.producer("redis"); foreign[0]["value"] = "other"; variants.append([foreign])
        replace = self.producer("redis"); replace.append({"op": "replace", "path": "/spec/replicas", "value": 5}); variants.append([replace])
        variants.append([self.producer("redis"), self.producer("redis")])
        overlap = self.producer("redis"); overlap[-1]["value"]["mountPath"] = "/run/system-backup/private"; variants.append([overlap])
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(m.Refused):
                m.merge_material_patches(self.original, variant)


class IntentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tool = m.DeploymentStages.__new__(m.DeploymentStages)
        self.tool.directory = Path(self.temporary.name).resolve()
        self.tool.operation = "a" * 32

    def test_unknown_intent_never_resubmits(self):
        self.tool.retain("native.send-unknown.json", {"stage": "native", "argv": ["exact-producer"], "input": None, "operation": self.tool.operation})
        with patch.object(m.subprocess, "run") as native, self.assertRaises(m.Refused):
            self.tool.call("native", ["exact-producer"])
        native.assert_not_called()

    def test_completed_exact_original_send_can_be_read_without_second_mutation(self):
        def native(argv, **kwargs):
            kwargs["stdout"].write(b'{"state":"actual-producer-result"}\n')
            return types.SimpleNamespace(returncode=0)
        with patch.object(m.subprocess, "run", side_effect=native) as send:
            first, first_pin = self.tool.call("native", ["exact-producer"], b"exact-private-input")
            second, second_pin = self.tool.call("native", ["exact-producer"], b"exact-private-input")
        self.assertEqual(first, second)
        self.assertEqual(first_pin, second_pin)
        self.assertEqual(send.call_count, 1)
        with patch.object(m.subprocess, "run") as send, self.assertRaises(m.Refused):
            self.tool.call("native", ["exact-producer"], b"changed-input")
        send.assert_not_called()

    def test_duplicate_json_key_refused(self):
        with self.assertRaises(m.Refused):
            m.decode(b'{"state":"a","state":"b"}')

    def test_definition_encoding_is_exact_canonical_utf8_without_trailing_bytes(self):
        self.assertEqual(m.encoded({"z": "", "a": "ü"}), '{"a":"ü","z":""}'.encode("utf-8"))
        self.assertEqual(m.encoded({"\ue000": 2, "\U00010000": 1}), '{"\U00010000":1,"\ue000":2}'.encode("utf-8"))
        for value in (float("nan"), 1.5, 9007199254740992):
            with self.subTest(value=value), self.assertRaises(m.Refused):
                m.encoded({"counter": value})


class ControllerIdentityTests(unittest.TestCase):
    def test_pod_or_container_drift_is_not_same_host(self):
        tool = m.DeploymentStages.__new__(m.DeploymentStages)
        dep = {"metadata": {"uid": "dep"}, "spec": {"replicas": 1}}
        pod = {"metadata": {"uid": "pod"}, "spec": {"serviceAccountName": "sa"}, "status": {"phase": "Running", "containerStatuses": [{"name": "controller", "containerID": "cri", "imageID": "image", "state": {"running": {}}}]}}
        identity = {"Deployment": "dep-name", "DeploymentUID": "dep", "DeploymentSpecSHA256": m.digest(m.encoded(dep["spec"])), "Pod": "pod-name", "PodUID": "pod", "PodSpecSHA256": m.digest(m.encoded(pod["spec"])), "Containers": {"controller": {"ContainerID": "cri", "ImageID": "image"}}}
        tool.get = lambda resource, name: copy.deepcopy(dep if resource == "deployment" else pod)
        self.assertEqual(tool.check_host(identity)["metadata"]["uid"], "pod")
        pod["status"]["containerStatuses"][0]["containerID"] = "new-cri"
        with self.assertRaises(m.Refused):
            tool.check_host(identity)
        pod["status"]["containerStatuses"][0]["containerID"] = "cri"
        pod["metadata"]["uid"] = "replacement-pod"
        with self.assertRaises(m.Refused):
            tool.check_host(identity)


class NewImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.tool = m.DeploymentStages.__new__(m.DeploymentStages)
        self.tool.directory, self.tool.root = root, root
        self.tool.operation, self.tool.prefix = "a" * 32, "sbk-model"
        self.tool.a = types.SimpleNamespace(deployment_app_image="actual-app-reference", deployment_worker_image="actual-worker-reference", deployment_inputs_storage_class="longhorn-inputs")
        self.storage = {"metadata": {"name": "longhorn-inputs", "uid": "original-storage-class"}, "provisioner": "driver.longhorn.io", "volumeBindingMode": "WaitForFirstConsumer"}
        self.tool.op = types.SimpleNamespace(upgraded_released=lambda: None, k=lambda *args: m.encoded(self.storage))
        self.tool.common = lambda: ([], {}, {}, {})
        self.tool.scope = {"app_deployment_uid": "app-deployment"}
        self.original = {"metadata": {"uid": "app-deployment", "resourceVersion": "17"}, "spec": {"replicas": 0, "template": {"spec": {"containers": [{"name": "app", "image": "old-image", "env": [{"name": "DB_USER", "value": "original-primary-app-user"}, {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "original-app-secret", "key": "db-password"}}}], "envFrom": [{"configMapRef": {"name": "original-business-config"}}], "volumeMounts": [{"name": "original-config", "mountPath": "/app/config.yaml", "subPath": "config.yaml"}]}], "volumes": [{"name": "original-config", "configMap": {"name": "original-business-config"}}]}}}}
        self.pvc = None
        def get(resource, name):
            if resource == "pvc":
                self.assertEqual(name, "sbk-model-inputs")
                return copy.deepcopy(self.pvc)
            self.assertEqual((resource, name), ("deployment", "clawmanager-app"))
            return copy.deepcopy(self.original)
        self.tool.get = get
        self.events, self.sent_patch = [], None
        def create_object(stage, obj):
            self.events.append("ca-create")
            return {**obj, "metadata": {**obj["metadata"], "uid": "created-ca"}}
        self.tool.create_object = create_object
        def kubectl(stage, args, patch):
            if stage == "host-pvc-inputs":
                self.assertEqual(args, ["create", "-f", "-", "-o", "json"])
                self.assertEqual(patch["kind"], "PersistentVolumeClaim")
                self.events.append("inputs-pvc-create")
                self.pvc = copy.deepcopy(patch)
                self.pvc["metadata"]["uid"] = "original-inputs-pvc"
                self.pvc["status"] = {"phase": "Pending"}
                return copy.deepcopy(self.pvc), {}
            self.events.append("app-patch")
            self.sent_patch = patch
            return {"metadata": {"uid": "app-deployment"}, "spec": copy.deepcopy(patch[-1]["value"])}, {}
        self.tool.kubectl = kubectl
        def rollout(images):
            self.events.append("business-rollout")
            value = copy.deepcopy(self.sent_patch[-1]["value"])
            value["replicas"] = 1
            return {"metadata": {"uid": "app-deployment"}, "spec": value}, [{"PodUID": "model-only-not-native-proof"}]
        self.tool.business_rollout = rollout
        def selected_file(name, raw):
            p = root / name
            return m.write(p, raw)
        ca = selected_file("ca.pem", b"model-public-ca-no-native-issuance")
        plan = selected_file("tls-plan.json", m.encoded({"DNSNames": ["mysql.original.svc"]}))
        source = selected_file("mysql-source-tls.json", m.encoded({"ca_file": ca["File"], "ca_sha256": ca["SHA256"], "server_name": "mysql.original.svc"}))
        self.tool.completed = lambda stage: {"OperatorSQLTLSVerified": True, "PlanFile": plan["File"], "PlanSHA256": plan["SHA256"], "CAFile": ca["File"], "CASHA256": ca["SHA256"], "SourceTLSFile": source["File"], "SourceTLSSHA256": source["SHA256"]}
        selected_file("build-receipt.json", m.encoded({"commit": "a" * 40, "images": {"app": {}, "worker": {}}}))
        def image(reference, built, commit):
            self.events.append("registry-" + reference)
            return {"reference": reference, "manifest_sha256": "b" * 64, "config_digest": "sha256:" + "c" * 64}
        self.image = image

    def test_original_main_app_credentials_and_configuration_are_preserved(self):
        with patch.object(m, "registry_image", side_effect=self.image):
            result = self.tool.new_image()
        desired = self.sent_patch[-1]["value"]
        container = desired["template"]["spec"]["containers"][0]
        env = {e["name"]: e for e in container["env"]}
        self.assertEqual(env["DB_USER"]["value"], "original-primary-app-user")
        self.assertEqual(env["DB_PASSWORD"], self.original["spec"]["template"]["spec"]["containers"][0]["env"][1])
        self.assertEqual(container["envFrom"], [{"configMapRef": {"name": "original-business-config"}}])
        self.assertEqual(desired["replicas"], 0)
        self.assertFalse(desired["template"]["spec"].get("initContainers"))
        ca_mount = next(v for v in container["volumeMounts"] if v["name"] == "sbk-business-mysql-ca")
        self.assertEqual(ca_mount["subPath"], "ca.crt")
        self.assertEqual(container["volumeMounts"][-1], {"name": "sbk-original-runtime-inputs", "mountPath": m.RUNTIME_MOUNT, "readOnly": True})
        self.assertEqual(desired["template"]["spec"]["volumes"][-1]["persistentVolumeClaim"], {"claimName": "sbk-model-inputs", "readOnly": True})
        self.assertEqual(result["inputs_pvc"], {"Name": "sbk-model-inputs", "UID": "original-inputs-pvc"})
        self.assertEqual(self.pvc["spec"]["accessModes"], ["ReadWriteMany"])
        self.assertEqual(env["SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED"]["value"], "false")
        self.assertFalse(result["configuration_enabled"])
        self.assertEqual(self.events, ["registry-actual-app-reference", "registry-actual-worker-reference", "inputs-pvc-create", "ca-create", "app-patch", "business-rollout"])

    def test_registry_rejection_precedes_any_kubernetes_mutation(self):
        with patch.object(m, "registry_image", side_effect=m.Refused("different-release")), self.assertRaises(m.Refused):
            self.tool.new_image()
        self.assertEqual(self.events, [])

    def test_worker_registry_rejection_precedes_any_kubernetes_mutation(self):
        def image(reference, built, commit):
            if reference == "actual-worker-reference":
                raise m.Refused("different-worker-release")
            return self.image(reference, built, commit)
        with patch.object(m, "registry_image", side_effect=image), self.assertRaises(m.Refused):
            self.tool.new_image()
        self.assertEqual(self.events, ["registry-actual-app-reference"])

    def test_inputs_pvc_readback_drift_prevents_app_patch_and_start(self):
        get = self.tool.get
        def changed(resource, name):
            actual = get(resource, name)
            if resource == "pvc":
                actual["metadata"]["uid"] = "replacement-inputs-pvc"
            return actual
        self.tool.get = changed
        with patch.object(m, "registry_image", side_effect=self.image), self.assertRaises(m.Refused):
            self.tool.new_image()
        self.assertEqual(self.events, ["registry-actual-app-reference", "registry-actual-worker-reference", "inputs-pvc-create"])

    def test_patch_readback_drift_prevents_business_start(self):
        def changed(stage, args, patch):
            value = copy.deepcopy(patch[-1]["value"])
            value["replicas"] = 4
            return {"metadata": {"uid": "app-deployment"}, "spec": value}, {}
        original_kubectl = self.tool.kubectl
        self.tool.kubectl = lambda stage, args, patch: original_kubectl(stage, args, patch) if stage == "host-pvc-inputs" else changed(stage, args, patch)
        with patch.object(m, "registry_image", side_effect=self.image), self.assertRaises(m.Refused):
            self.tool.new_image()
        self.assertNotIn("business-rollout", self.events)


if __name__ == "__main__":
    unittest.main()
