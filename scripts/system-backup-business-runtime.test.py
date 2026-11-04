"""Source models for actual template preservation; no native authority claims."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("business_runtime", Path(__file__).with_name("system-backup-business-runtime.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Refused(Exception):
    pass


class Module:
    MARKER = "original-operation"

    @staticmethod
    def need(value, reason):
        if not value:
            raise Refused(reason)

    overlap = staticmethod(runtime.overlap)

    @staticmethod
    def encoded(value):
        return json.dumps(value, sort_keys=True).encode()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value).hexdigest()


def original(kind="openclaw"):
    image = "10.130.14.23:5000/" + runtime.IMAGES[kind]["repository"] + "@sha256:" + runtime.IMAGES[kind]["base"]
    env = [{"name": "CLAWMANAGER_RUNTIME_TYPE", "value": kind}, {"name": "CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME", "value": kind + "-runtime"},
           {"name": "CLAWMANAGER_DEPLOYMENT_NAME", "value": kind + "-runtime"}, {"name": "CLAWMANAGER_RUNTIME_IMAGE_REF", "value": image},
           {"name": "CLAWMANAGER_RUNTIME_IMAGE_DIGEST", "value": image.split("@", 1)[1]}]
    for name, key in (("RUNTIME_AGENT_CONTROL_TOKEN", "control"), ("RUNTIME_AGENT_REPORT_TOKEN", "report")):
        env.append({"name": name, "valueFrom": {"secretKeyRef": {"name": "original-agent-token", "key": key}}})
    if kind == "hermes":
        for name, key in (("CLAWMANAGER_AGENT_CONTROL_TOKEN", "control"), ("CLAWMANAGER_AGENT_REPORT_TOKEN", "report")):
            env.append({"name": name, "valueFrom": {"secretKeyRef": {"name": "original-agent-token", "key": key}}})
    else:
        env.append({"name": "OPENCLAW_GATEWAY_TOKEN", "valueFrom": {"secretKeyRef": {"name": "original-gateway-token", "key": "gateway"}}})
    env.append({"name": "POD_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}})
    labels = {"app": kind + "-runtime", runtime.LABEL: kind}
    return {"metadata": {"namespace": "original-namespace", "name": kind + "-runtime", "uid": kind + "-original-uid", "resourceVersion": "actual-rv", "labels": labels},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1}},
                     "template": {"metadata": {"labels": labels}, "spec": {"serviceAccountName": "original-runtime", "containers": [{"name": "runtime", "image": image, "env": env,
                                                                                                                                                "volumeMounts": [{"name": "workspaces", "mountPath": "/workspaces"}]}],
                                                                                              "volumes": [{"name": "workspaces", "persistentVolumeClaim": {"claimName": "original-workspaces"}}]}}}}


class RuntimeTemplateTests(unittest.TestCase):
    def test_real_single_secret_reference_shape_is_preserved_without_loading(self):
        for kind in runtime.IMAGES:
            value = original(kind)
            before = copy.deepcopy(value)
            actual_kind, desired = runtime.desired_spec(value, "actual-operation", Module)
            self.assertEqual(actual_kind, kind)
            self.assertEqual(value, before)
            original_pod = value["spec"]["template"]["spec"]
            result_pod = desired["template"]["spec"]
            self.assertEqual(result_pod["volumes"], original_pod["volumes"])
            self.assertEqual(result_pod["serviceAccountName"], original_pod["serviceAccountName"])
            result_refs = [e for e in result_pod["containers"][0]["env"] if "valueFrom" in e]
            self.assertEqual([e for e in result_refs if e["name"] != "POD_UID"], [e for e in original_pod["containers"][0]["env"] if "valueFrom" in e])
            self.assertEqual([e for e in result_refs if e["name"] == "POD_UID"], [{"name": "POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}}])
            self.assertEqual(desired["replicas"], 1)
            self.assertEqual(desired["strategy"], {"type": "Recreate"})

    def test_native_layout_or_sidecar_is_refused_before_desired_template(self):
        for sidecar in (True, False):
            value = original()
            if sidecar:
                value["spec"]["template"]["spec"]["containers"].append({"name": "other"})
            else:
                value["metadata"]["labels"]["clawmanager.io/runtime-layout"] = "pool-slot-v1"
            with self.assertRaises(Refused):
                runtime.desired_spec(value, "operation", Module)


class QueryModule(Module):
    NS = "original-namespace"

    @staticmethod
    def decode(raw):
        return json.loads(raw)

    @staticmethod
    def read(path, expected=None):
        raw = Path(path).read_bytes()
        Module.need(expected is None or Module.digest(raw) == expected, "changed_private_original_pin")
        return raw

    @staticmethod
    def pin(path):
        return {"File": str(path), "SHA256": Module.digest(Path(path).read_bytes())}

    @staticmethod
    def write(path, raw):
        Module.need(not Path(path).exists(), "create_only_original_artifact")
        Path(path).write_bytes(raw)
        return QueryModule.pin(path)

    @staticmethod
    def pinned(pin):
        return QueryModule.read(pin["File"], pin["SHA256"])

    @staticmethod
    def image_id(value):
        return value

    @staticmethod
    def only_controller(item, kind):
        owners = [v for v in item["metadata"].get("ownerReferences", []) if v.get("controller")]
        Module.need(len(owners) == 1 and owners[0]["kind"] == kind, "wrong_original_owner")
        return owners[0]


def tls_transport_model(universe, query=False):
    """Transport-component stand-in for the independent old query model.

    This model does not claim a live TLS handshake or any native source proof.
    Actual certificate purpose/Secret projection/negative inputs are separate.
    """
    return ({"materials_receipt": {"File": "/transport-component-model", "SHA256": "d" * 64}},
            {"Targets": [{"DeploymentUID": d["metadata"]["uid"], "Deployment": d["metadata"]["name"], "SecretName": "model-tls"} for d in universe]})


def lost_patch_reply_fixture(directory):
    """Fake Kubernetes transport; invokes the REAL query and continuation code.

    No native owner/hold/capability is supplied or claimed by this model.
    """
    directory = Path(directory)
    objects, plan, image_values = {}, [], {}
    operation = "original-operation"
    for kind in runtime.IMAGES:
        before = original(kind)
        _, desired = runtime.desired_spec(before, operation, QueryModule)
        deployment = copy.deepcopy(before)
        deployment["spec"] = desired
        deployment["metadata"].update({"generation": 2, "resourceVersion": "after-real-patch"})
        deployment["status"] = {"observedGeneration": 2, "updatedReplicas": 1, "availableReplicas": 1}
        pod_name, rs_name = kind + "-actual-pod", kind + "-actual-rs"
        pod = {"metadata": {"name": pod_name, "uid": kind + "-actual-pod-uid", "namespace": QueryModule.NS,
                            "labels": copy.deepcopy(desired["template"]["metadata"]["labels"]),
                            "ownerReferences": [{"kind": "ReplicaSet", "name": rs_name, "uid": rs_name + "-uid", "controller": True}]},
               "spec": {**copy.deepcopy(desired["template"]["spec"]), "nodeName": "actual-node"},
               "status": {"phase": "Running", "containerStatuses": [{"name": "runtime", "ready": True, "state": {"running": {}},
                                                                           "containerID": "containerd://" + kind + "-actual-cri", "imageID": "sha256:" + runtime.IMAGES[kind]["manifest"]}]}}
        rs = {"metadata": {"uid": rs_name + "-uid", "ownerReferences": [{"kind": "Deployment", "name": deployment["metadata"]["name"], "uid": deployment["metadata"]["uid"], "controller": True}]}}
        objects[("deployment", deployment["metadata"]["name"])] = deployment
        objects[("pod", pod_name)] = pod
        objects[("replicaset", rs_name)] = rs
        plan.append({"runtime": kind, "original": before, "desired": desired})
        receipt = directory / (kind + "-actual-image-receipt.private.json")
        receipt.write_bytes(b"original image publication receipt model")
        image_values[kind] = {"reference": runtime.reference(kind), "manifest": "sha256:" + runtime.IMAGES[kind]["manifest"],
                              "config": "sha256:" + "c" * 64, "native_receipt": QueryModule.pin(receipt)}
    startup = directory / "original-startup-inputs.json"
    startup.write_bytes(b"original OCI input model, not native proof")
    (directory / "runtime-images.result.json").write_bytes(QueryModule.encoded({"images": image_values, "startup_images": QueryModule.pin(startup)}))
    (directory / "runtime-rollout.plan.json").write_bytes(QueryModule.encoded({"version": "operator-original-business-runtime-rollout-plan.v1", "operation": operation, "agent_tls_materials": {"File": "/transport-component-model", "SHA256": "d" * 64}, "deployments": plan}))
    unknown = directory / "runtime-rollout-hermes-runtime.send-unknown.json"
    unknown.write_bytes(b"original send intent retained after lost response")

    class NativeTransport:
        mutations = 0

        def k(self, *args):
            resource = args[args.index("get") + 1]
            if resource == "deployments":
                items = [v for (kind, _), v in objects.items() if kind == "deployment"]
            elif resource == "pods":
                selector = dict(v.split("=", 1) for v in args[args.index("-l") + 1].split(","))
                items = [v for (kind, _), v in objects.items() if kind == "pod" and all(v["metadata"]["labels"].get(k) == value for k, value in selector.items())]
            else:
                raise AssertionError("unexpected native read")
            return QueryModule.encoded({"items": items})

    class Stages:
        def get(self, kind, name):
            return copy.deepcopy(objects[(kind, name)])

        def retain(self, name, value):
            path, raw = directory / name, QueryModule.encoded(value)
            if path.exists():
                QueryModule.need(path.read_bytes() == raw, "original_retained_result_changed")
            else:
                path.write_bytes(raw)
            return QueryModule.pin(path)

        def kubectl(self, *_):
            transport.mutations += 1
            raise AssertionError("unknown patch must never be resent")

    transport, stages = NativeTransport(), Stages()
    stages.directory, stages.operation = directory, operation
    module = SimpleNamespace(**{name: getattr(QueryModule, name) for name in ("NS", "MARKER", "need", "encoded", "digest", "decode", "read", "pin", "pinned", "write", "image_id", "only_controller")})
    module.NoRedirect = runtime.urllib.request.HTTPRedirectHandler
    module.DeploymentStages = lambda _: stages
    return transport, module, objects, unknown


class RuntimeQueryContinuationTests(unittest.TestCase):
    def test_successful_original_query_allows_next_guard_without_fabricating_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            transport, module, objects, unknown = lost_patch_reply_fixture(directory)
            original_intent = unknown.read_bytes()
            with patch.object(runtime, "load_deployment", return_value=module), patch.object(runtime.BusinessRuntimeStages, "agent_tls_materials", side_effect=tls_transport_model), patch.object(runtime.BusinessRuntimeStages, "verify_agent_tls", return_value=[]):
                stages = runtime.BusinessRuntimeStages(transport)
                result = stages.rollout(query=True)
                continued = runtime.verify_current(transport)
                replay = stages.rollout(query=False)
            self.assertEqual(result["deployments"], continued["deployments"])
            self.assertEqual(replay["operation"], "original-operation")
            self.assertTrue((Path(directory) / "runtime-rollout.confirmed.json").exists())
            self.assertFalse((Path(directory) / "runtime-rollout.result.json").exists())
            self.assertEqual(original_intent, unknown.read_bytes())
            self.assertFalse(list(Path(directory).glob("*.readback.json")))
            self.assertEqual(transport.mutations, 0)

    def test_confirmed_query_cannot_continue_with_replacement_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            transport, module, objects, _ = lost_patch_reply_fixture(directory)
            with patch.object(runtime, "load_deployment", return_value=module), patch.object(runtime.BusinessRuntimeStages, "agent_tls_materials", side_effect=tls_transport_model), patch.object(runtime.BusinessRuntimeStages, "verify_agent_tls", return_value=[]):
                runtime.BusinessRuntimeStages(transport).rollout(query=True)
                objects[("pod", "hermes-actual-pod")]["metadata"]["uid"] = "replacement-pod"
                with self.assertRaises(Refused):
                    runtime.verify_current(transport)
            self.assertEqual(transport.mutations, 0)

    def test_non_token_secret_and_startup_mount_are_refused(self):
        for mount in (True, False):
            value = original()
            c = value["spec"]["template"]["spec"]["containers"][0]
            if mount:
                c["volumeMounts"].append({"name": "original", "mountPath": "/opt/node/bin"})
            else:
                c["env"].append({"name": "RUNTIME_WORKSPACE_ROOT", "valueFrom": {"secretKeyRef": {"name": "other", "key": "workspace"}}})
            with self.assertRaises(Refused):
                runtime.desired_spec(value, "operation", Module)

    def test_token_alias_reference_conflict_is_refused(self):
        value = original("hermes")
        env = value["spec"]["template"]["spec"]["containers"][0]["env"]
        next(e for e in env if e["name"] == "CLAWMANAGER_AGENT_REPORT_TOKEN")["valueFrom"]["secretKeyRef"]["key"] = "foreign-report"
        with self.assertRaises(Refused):
            runtime.desired_spec(value, "operation", Module)

    def test_public_template_has_no_token_values_or_secret_locators(self):
        value = original()
        _, value["spec"] = runtime.desired_spec(value, "operation", Module)
        public = runtime.public_template(value, Module)
        text = json.dumps(public)
        self.assertNotIn("original-agent-token", text)
        self.assertNotIn("original-gateway-token", text)
        self.assertIn("secretKeyRef", text)
        self.assertEqual(public["spec_sha256"], Module.digest(Module.encoded(value["spec"])))

    def test_mutable_image_and_environment_expansion_are_refused(self):
        for expansion in (True, False):
            value = original()
            c = value["spec"]["template"]["spec"]["containers"][0]
            if expansion:
                c["env"].append({"name": "RUNTIME_WORKSPACE_ROOT", "value": "$(UNKNOWN)"})
            else:
                c["image"] = "10.130.14.23:5000/openclaw-lite:latest"
            with self.assertRaises(Refused):
                runtime.desired_spec(value, "operation", Module)


class OriginalTemplateCompatibilityTests(unittest.TestCase):
    def test_original_missing_future_identity_fields_are_explicitly_completed(self):
        for kind in runtime.IMAGES:
            value = original(kind)
            c = value["spec"]["template"]["spec"]["containers"][0]
            c["env"] = [e for e in c["env"] if e["name"] not in ("CLAWMANAGER_DEPLOYMENT_NAME", "CLAWMANAGER_RUNTIME_IMAGE_DIGEST")]
            before = copy.deepcopy(value)
            _, desired = runtime.desired_spec(value, "operation", Module)
            self.assertEqual(value, before)
            final = copy.deepcopy(value)
            final["spec"] = desired
            runtime.finite_template(final, Module, final=True)
            env = {e["name"]: e for e in desired["template"]["spec"]["containers"][0]["env"]}
            self.assertEqual(env["CLAWMANAGER_DEPLOYMENT_NAME"]["value"], kind + "-runtime")
            self.assertEqual(env["CLAWMANAGER_RUNTIME_IMAGE_DIGEST"]["value"], "sha256:" + runtime.IMAGES[kind]["manifest"])

    def test_actual_original_tag_requires_registry_bytes_and_current_cri_join(self):
        config_raw = QueryModule.encoded({"os": "linux", "architecture": "amd64", "model": "original config bytes"})
        config_sha = QueryModule.digest(config_raw)
        manifest_raw = QueryModule.encoded({"schemaVersion": 2, "config": {"digest": "sha256:" + config_sha}, "layers": []})
        manifest_sha = QueryModule.digest(manifest_raw)
        profile = {**runtime.IMAGES["hermes"], "base": manifest_sha, "selected": manifest_sha}

        class Response(io.BytesIO):
            status = 200

            def __init__(self, raw):
                super().__init__(raw)
                self.headers = {"Docker-Content-Digest": "sha256:" + QueryModule.digest(raw)}

        with tempfile.TemporaryDirectory() as directory, patch.dict(runtime.IMAGES, {"hermes": profile}), patch.dict(runtime.BASE_CONFIG, {"hermes": config_sha}):
            transport, module, objects, _ = lost_patch_reply_fixture(directory)
            legacy = original("hermes")
            tag = "10.130.14.23:5000/hermes-lite:2026.7.1"
            c = legacy["spec"]["template"]["spec"]["containers"][0]
            c["image"] = tag
            c["env"] = [e for e in c["env"] if e["name"] not in ("CLAWMANAGER_DEPLOYMENT_NAME", "CLAWMANAGER_RUNTIME_IMAGE_DIGEST")]
            next(e for e in c["env"] if e["name"] == "CLAWMANAGER_RUNTIME_IMAGE_REF")["value"] = tag
            objects[("deployment", "hermes-runtime")]["spec"] = copy.deepcopy(legacy["spec"])
            pod = objects[("pod", "hermes-actual-pod")]
            pod["spec"] = {**copy.deepcopy(legacy["spec"]["template"]["spec"]), "nodeName": "actual-node"}
            config_file = Path(directory) / "original-base-config.json"
            config_file.write_bytes(config_raw)
            startup = Path(directory) / "original-startup-inputs.json"
            startup.write_bytes(QueryModule.encoded({"Version": "original-runtime-startup-image-inputs.v1", "Images": [{"BaseConfig": QueryModule.pin(config_file)}]}))
            image_file = Path(directory) / "runtime-images.result.json"
            images = QueryModule.decode(image_file.read_bytes())
            images["startup_images"] = QueryModule.pin(startup)
            image_file.write_bytes(QueryModule.encoded(images))
            with self.assertRaises(Refused):
                runtime.finite_template(legacy, Module)
            opener = SimpleNamespace(open=lambda *_args, **_kwargs: Response(manifest_raw))
            with patch.object(runtime, "load_deployment", return_value=module), patch.object(runtime.urllib.request, "build_opener", return_value=opener):
                stages = runtime.BusinessRuntimeStages(transport)
                pod["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "f" * 64
                with self.assertRaises(Refused):
                    stages.original_image_proof(legacy)
                pod["status"]["containerStatuses"][0]["imageID"] = "sha256:" + config_sha
                proof = stages.original_image_proof(legacy)
                _, desired = runtime.desired_spec(legacy, "operation", Module, original_image=proof)
                self.assertEqual(desired["template"]["spec"]["containers"][0]["image"], runtime.reference("hermes"))
                with patch.object(opener, "open", return_value=Response(b'{"schemaVersion":2,"unreviewed":true}')):
                    with self.assertRaises(Refused):
                        stages.original_image_proof(legacy)
            self.assertEqual(transport.mutations, 0)




class RuntimeTLSTemplateTests(unittest.TestCase):
    def target(self, deployment):
        return {"Deployment": deployment["metadata"]["name"], "DeploymentUID": deployment["metadata"]["uid"], "SecretName": "sbk-original-tls"}

    def test_tls_rollout_keeps_original_tokens_and_workspace(self):
        deployment = original()
        target = self.target(deployment)
        _, desired = runtime.desired_spec(deployment, "original-operation", Module, agent_tls=target)
        final = copy.deepcopy(deployment)
        final["spec"] = desired
        runtime.validate_agent_tls_template(final, target, Module)
        before = deployment["spec"]["template"]["spec"]["containers"][0]
        after = desired["template"]["spec"]["containers"][0]
        for env in before["env"]:
            if "TOKEN" in env["name"]:
                self.assertIn(env, after["env"])
        self.assertEqual(after["volumeMounts"][0], before["volumeMounts"][0])
        self.assertEqual(desired["strategy"], {"type": "Recreate"})

    def test_tls_mount_collision_is_rejected_before_patch(self):
        for path in ("/run", "/run/clawmanager-agent-tls", "/run/clawmanager-agent-tls/tls.key"):
            deployment = original()
            deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append({"name": "foreign", "mountPath": path})
            with self.assertRaises(Refused):
                runtime.desired_spec(deployment, "original-operation", Module, agent_tls=self.target(deployment))

    def test_tls_final_template_rejects_changed_secret_or_key_file(self):
        for change in ("secret", "key", "writable", "deployment"):
            deployment = original()
            target = self.target(deployment)
            _, desired = runtime.desired_spec(deployment, "original-operation", Module, agent_tls=target)
            deployment["spec"] = desired
            pod = desired["template"]["spec"]
            if change == "secret":
                pod["volumes"][-1]["secret"]["secretName"] = "foreign-tls"
            elif change == "key":
                next(e for e in pod["containers"][0]["env"] if e["name"] == "RUNTIME_AGENT_TLS_KEY_FILE")["value"] = "/other/key"
            elif change == "writable":
                pod["containers"][0]["volumeMounts"][-1]["readOnly"] = False
            else:
                deployment["metadata"]["uid"] = "foreign-deployment"
            with self.assertRaises(Refused):
                runtime.validate_agent_tls_template(deployment, target, Module)


if __name__ == "__main__":
    unittest.main()
