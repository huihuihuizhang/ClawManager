"""Real immutable Runtime publication and same-Deployment guarded rollout."""
import copy
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import re
import secrets
import sys
import time
import urllib.request

DEPLOYMENT_SHA = "b69327c689f6fa15d08ee5d07eed266a79c2166e55a584b96523d0c1fcf235be"
LAYER_SHA = "f08a23b661afacff2634c151ba87f266a8697da8944a19e6c80a8f0f6a29100a"
COLLECTOR_SHA = "0014156ccd9954f7f03dd54581c7049ad9639d8f37fefe8f061455140d47d151"
BUNDLE_SHA = "9875b8ef307c2b59250ca8659756f224882933639a6506a566357226a04cc9cf"
IMAGES = {
    "openclaw": {"repository": "openclaw-lite", "base": "37c43ba05ff7fd4f0949f274fc67c3e9825f6d3d0f9124b5fc45dc8366c39cee", "selected": "730758ed3025b5a1c7fd91b14214eea1d5a50950ef3fd56012a5efb48f345769", "manifest": "5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140"},
    "hermes": {"repository": "hermes-lite", "base": "6688834a944161d8dada995cdffd90781533b24ab1e75bb2182c46eaee3fb52c", "selected": "5fe79507129002540c2fbc25fc49bbd10326cb65dbc752885cfc845b2860731d", "manifest": "a2473da0cf375ed128116af3083eccd3276665adac4ae2722edcbff6cc277353"},
}
LABEL = "clawmanager.io/runtime-type"
BASE_CONFIG = {"openclaw": "c9798a575acf6d1c832a268fa53a057c3d1bb42ce7bdb06f887cddf7d00fb90a", "hermes": "4a36a2cda56406be6c4183eca5c58ac91dcceb36cb3342b7520b315c564a6c92"}
PROTECTED = ("/init", "/command", "/package", "/etc/services.d", "/etc/s6-overlay", "/etc/cont-init.d", "/etc/cont-finish.d", "/custom-cont-init.d", "/custom-services.d", "/run/s6", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/lib", "/usr/lib", "/opt/node/bin", "/lsiopy/bin", "/docker-mods", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/config", "/root", "/home")


def register_arguments(parser):
    parser.add_argument("--runtime-agent-bundle-file", type=Path)
    parser.add_argument("--runtime-registry-credentials-file", type=Path)


def load_deployment():
    path = Path(__file__).resolve().with_name("system-backup-operator-deployment.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != DEPLOYMENT_SHA:
        raise RuntimeError("reviewed_deployment_module_changed")
    spec = importlib.util.spec_from_file_location("business_runtime_deployment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def overlap(a, b):
    return a == b or a == "/" or a.startswith(b + "/") or b.startswith(a + "/")


def reference(kind):
    value = IMAGES[kind]
    return "10.130.14.23:5000/" + value["repository"] + "@sha256:" + value["manifest"]


def finite_template(deployment, module, original_image=None, final=False):
    """Conservative preflight only; original Go decoder/native hold still rule."""
    need = module.need
    metadata, spec = deployment["metadata"], deployment["spec"]
    kind = metadata.get("labels", {}).get(LABEL)
    need(kind in IMAGES and metadata.get("uid") and metadata.get("resourceVersion") and not metadata.get("deletionTimestamp"), "actual_original_runtime_deployment_required")
    need(not metadata.get("labels", {}).get("clawmanager.io/runtime-layout") and not spec["template"].get("metadata", {}).get("labels", {}).get("clawmanager.io/runtime-layout"), "native_pool_slot_runtime_not_supported_by_finite_decoder")
    pod = spec["template"]["spec"]
    need(len(pod.get("containers", [])) == 1 and not pod.get("initContainers") and not pod.get("ephemeralContainers"), "finite_shared_runtime_container_shape_required")
    c = pod["containers"][0]
    need(c["name"] == "runtime" and not c.get("envFrom") and not c.get("volumeDevices") and not c.get("args") and c.get("command", []) in ([], ["/usr/local/bin/clawmanager-agent"]) and c.get("workingDir", "") in ("", "/"), "finite_shared_runtime_startup_override_unsupported")
    original = IMAGES[kind]
    allowed = {"10.130.14.23:5000/" + original["repository"] + "@sha256:" + value for value in (original["base"], original["selected"], original["manifest"])}
    if final:
        need(c["image"] == reference(kind), "final_runtime_exact_reviewed_immutable_candidate_required")
    elif c["image"] not in allowed:
        need(original_image is not None and original_image["reference"] == c["image"] and
             original_image["deployment_uid"] == metadata["uid"] and original_image["pods"] and
             original_image["selected_manifest"] in ("sha256:" + original["selected"], "sha256:" + original["manifest"]),
             "original_runtime_tag_requires_actual_registry_and_pod_identity")
    env, references, names = {}, {}, set()
    fieldrefs = {"POD_NAME": "metadata.name", "POD_NAMESPACE": "metadata.namespace", "POD_IP": "status.podIP", "POD_UID": "metadata.uid", "NODE_NAME": "spec.nodeName"}
    specials = {"HERMES_TUI_DIR", "PATH", "S6_STAGE2_HOOK", "S6_KEEP_ENV", "MODMANAGER_MODONLY", "OPENCLAW_GATEWAY_TOKEN"}
    sensitive = {"RUNTIME_AGENT_CONTROL_TOKEN", "RUNTIME_AGENT_REPORT_TOKEN", "CLAWMANAGER_AGENT_CONTROL_TOKEN", "CLAWMANAGER_AGENT_REPORT_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
    for item in c.get("env", []):
        name = item["name"]
        need(name not in names and (name.startswith(("RUNTIME_", "CLAWMANAGER_")) or name in fieldrefs or name in specials), "runtime_unknown_or_duplicate_environment")
        names.add(name)
        if "valueFrom" in item:
            source = item["valueFrom"]
            if name in sensitive and set(source) == {"secretKeyRef"}:
                secret = source["secretKeyRef"]
                need(set(secret) <= {"name", "key", "optional"} and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", secret.get("name", "")) and re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", secret.get("key", "")) and secret.get("optional", False) is False, "original_runtime_required_secret_reference_shape")
                references[name] = (secret["name"], secret["key"])
            else:
                need(name in fieldrefs and set(source) == {"fieldRef"} and source["fieldRef"].get("fieldPath") == fieldrefs[name] and source["fieldRef"].get("apiVersion", "v1") == "v1", "runtime_other_startup_selector_unsupported")
        else:
            value = item.get("value", "")
            need(isinstance(value, str) and "$(" not in value and "\x00" not in value, "runtime_environment_expansion_unsupported")
            env[name] = value
    for suffix in ("CONTROL", "REPORT"):
        canonical, alias = "RUNTIME_AGENT_" + suffix + "_TOKEN", "CLAWMANAGER_AGENT_" + suffix + "_TOKEN"
        if canonical in references:
            need(alias not in env and (alias not in names or references.get(alias) == references[canonical]), "original_runtime_token_alias_reference_mismatch")
        else:
            value = env.get(canonical, "")
            need(alias not in references and 32 <= len(value.encode()) <= 8192 and not any(c.isspace() for c in value) and env.get(alias, value) == value, "complete_original_runtime_token_source_required")
    need(env.get("CLAWMANAGER_RUNTIME_TYPE") == kind and
         any(env.get(name) == metadata["name"] for name in ("CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME", "RUNTIME_DEPLOYMENT_NAME")), "runtime_deployment_identity_environment_mismatch")
    for name in ("CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME", "RUNTIME_DEPLOYMENT_NAME", "CLAWMANAGER_DEPLOYMENT_NAME"):
        need(name not in names or env.get(name) == metadata["name"], "conflicting_original_runtime_deployment_identity")
    need(env.get("CLAWMANAGER_RUNTIME_IMAGE_REF") == c["image"], "original_runtime_image_environment_mismatch")
    if final:
        need(env.get("CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME") == metadata["name"] and env.get("CLAWMANAGER_DEPLOYMENT_NAME") == metadata["name"] and env.get("CLAWMANAGER_RUNTIME_IMAGE_DIGEST") == "sha256:" + original["manifest"], "final_runtime_identity_environment_incomplete")
    elif "CLAWMANAGER_RUNTIME_IMAGE_DIGEST" in names:
        expected = {c["image"].split("@", 1)[1]} if "@" in c["image"] else {"", original_image["root_digest"], original_image["selected_manifest"], original_image["config_digest"]}
        need(env.get("CLAWMANAGER_RUNTIME_IMAGE_DIGEST") in expected, "conflicting_original_runtime_image_identity")
    need(env.get("MODMANAGER_MODONLY", "") == "" and env.get("S6_STAGE2_HOOK", "") in ("", "/docker-mods") and env.get("S6_KEEP_ENV", "") in ("", "0"), "runtime_custom_startup_hook_unsupported")
    # PATH is left for the content-authenticated Go decoder; an explicit
    # override is refused by this deliberately smaller preflight branch.
    need("PATH" not in names, "runtime_explicit_path_requires_original_decoder_qualification")
    for mount in c.get("volumeMounts", []):
        path = mount["mountPath"]
        need(PurePosixPath(path).is_absolute() and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts and not any(overlap(path, root) for root in PROTECTED), "runtime_mount_overlaps_original_startup")
    selector = spec["selector"]
    need(selector.get("matchLabels") and not selector.get("matchExpressions") and all(spec["template"]["metadata"]["labels"].get(k) == v for k, v in selector["matchLabels"].items()), "finite_original_runtime_selector_required")
    replicas = spec.get("replicas", 1)
    need(type(replicas) is int and 0 <= replicas <= 32 and not spec.get("paused"), "finite_original_runtime_replica_policy_required")
    return kind


def desired_spec(deployment, operation, module, original_image=None, agent_tls=None):
    kind = finite_template(deployment, module, original_image=original_image)
    desired = copy.deepcopy(deployment["spec"])
    container = desired["template"]["spec"]["containers"][0]
    container["image"] = reference(kind)
    for name, value in {"CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME": deployment["metadata"]["name"],
                        "CLAWMANAGER_DEPLOYMENT_NAME": deployment["metadata"]["name"],
                        "CLAWMANAGER_RUNTIME_IMAGE_REF": reference(kind),
                        "CLAWMANAGER_RUNTIME_IMAGE_DIGEST": "sha256:" + IMAGES[kind]["manifest"]}.items():
        existing = next((item for item in container["env"] if item["name"] == name), None)
        if existing is None:
            container["env"].append({"name": name, "value": value})
        else:
            existing.clear()
            existing.update({"name": name, "value": value})
    if not any(item["name"] == "POD_UID" for item in container["env"]):
        container["env"].append({"name": "POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}})
    if agent_tls is not None:
        need = module.need
        tls_root, volume_name = "/run/clawmanager-agent-tls", "sbk-shared-agent-tls"
        need(agent_tls["DeploymentUID"] == deployment["metadata"]["uid"] and agent_tls["Deployment"] == deployment["metadata"]["name"], "actual_same_deployment_tls_material_required")
        need(not any(module.overlap(m["mountPath"], tls_root) for m in container.get("volumeMounts", [])), "new_agent_tls_mount_collision")
        need(not any(v["name"] == volume_name for v in desired["template"]["spec"].get("volumes", [])), "new_agent_tls_volume_collision")
        for name, value in {"RUNTIME_AGENT_TLS_CERT_FILE": tls_root + "/tls.crt", "RUNTIME_AGENT_TLS_KEY_FILE": tls_root + "/tls.key"}.items():
            existing = next((item for item in container["env"] if item["name"] == name), None)
            need(existing is None, "original_runtime_tls_input_requires_explicit_reconciliation")
            container["env"].append({"name": name, "value": value})
        container.setdefault("volumeMounts", []).append({"name": volume_name, "mountPath": tls_root, "readOnly": True})
        desired["template"]["spec"].setdefault("volumes", []).append({"name": volume_name, "secret": {"secretName": agent_tls["SecretName"], "defaultMode": 256, "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}})
    desired["template"].setdefault("metadata", {}).setdefault("annotations", {})[module.MARKER] = operation
    # No overlapping old/new runtime processes against the original workspace.
    desired["strategy"] = {"type": "Recreate"}
    final = copy.deepcopy(deployment)
    final["spec"] = desired
    finite_template(final, module, final=True)
    if agent_tls is not None:
        validate_agent_tls_template(final, agent_tls, module)
    return kind, desired



def validate_agent_tls_template(deployment, target, module):
    need = module.need
    need(deployment["metadata"]["name"] == target["Deployment"] and deployment["metadata"]["uid"] == target["DeploymentUID"], "runtime_tls_deployment_identity")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {entry["name"]: entry for entry in container["env"]}
    for name, path in {"RUNTIME_AGENT_TLS_CERT_FILE": "/run/clawmanager-agent-tls/tls.crt", "RUNTIME_AGENT_TLS_KEY_FILE": "/run/clawmanager-agent-tls/tls.key"}.items():
        need(env.get(name) == {"name": name, "value": path}, "actual_literal_agent_tls_file_required")
    mounts = [mount for mount in container.get("volumeMounts", []) if module.overlap(mount["mountPath"], "/run/clawmanager-agent-tls")]
    need(mounts == [{"name": "sbk-shared-agent-tls", "mountPath": "/run/clawmanager-agent-tls", "readOnly": True}], "exact_readonly_agent_tls_mount_required")
    volumes = [volume for volume in pod.get("volumes", []) if volume["name"] == "sbk-shared-agent-tls"]
    need(volumes == [{"name": "sbk-shared-agent-tls", "secret": {"secretName": target["SecretName"], "defaultMode": 256, "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}}], "actual_immutable_agent_tls_secret_projection_required")


def public_template(deployment, module):
    kind = finite_template(deployment, module, final=True)
    c = deployment["spec"]["template"]["spec"]["containers"][0]
    return {"runtime": kind, "namespace": deployment["metadata"]["namespace"], "name": deployment["metadata"]["name"], "uid": deployment["metadata"]["uid"],
            "spec_sha256": module.digest(module.encoded(deployment["spec"])), "image": c["image"], "replicas": deployment["spec"].get("replicas", 1),
            "containers": [{"name": c["name"], "command": c.get("command", []), "args": c.get("args", []), "working_directory": c.get("workingDir", ""),
                            "environment": [{"name": e["name"], "source": next(iter(e["valueFrom"])) if "valueFrom" in e else "literal"} for e in c.get("env", [])],
                            "mounts": [{k: v for k, v in m.items() if k in ("name", "mountPath", "subPath", "readOnly")} for m in c.get("volumeMounts", [])]}]}


class BusinessRuntimeStages:
    def __init__(self, operator):
        self.op = operator
        self.m = load_deployment()
        self.stages = self.m.DeploymentStages(operator)

    def original_image_proof(self, deployment):
        """Registry bytes AND actual owner/CRI join; a tag supplies no digest."""
        m, stages = self.m, self.stages
        kind = deployment["metadata"].get("labels", {}).get(LABEL)
        m.need(kind in IMAGES, "known_original_runtime_kind_required")
        profile = IMAGES[kind]
        c = deployment["spec"]["template"]["spec"]["containers"][0]
        match = re.fullmatch(r"10\.130\.14\.23:5000/" + re.escape(profile["repository"]) + r":([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})", c["image"])
        m.need(match is not None, "unreviewed_original_runtime_reference")
        images = m.decode(m.read(stages.directory / "runtime-images.result.json"))
        definition = m.decode(m.pinned(images["startup_images"]))
        inputs = [value for value in definition["Images"] if value["BaseConfig"]["SHA256"] == BASE_CONFIG[kind]]
        m.need(len(inputs) == 1, "actual_original_runtime_base_config_input_required")
        m.pinned(inputs[0]["BaseConfig"])
        manifests = []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), m.NoRedirect())

        def fetch(selected, expected=None):
            url = "http://10.130.14.23:5000/v2/" + profile["repository"] + "/manifests/" + selected
            request = urllib.request.Request(url, headers={"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
            with opener.open(request, timeout=30) as response:
                raw = response.read((4 << 20) + 1)
                m.need(response.status == 200 and 0 < len(raw) <= 4 << 20 and response.read(1) == b"", "original_runtime_registry_manifest_incomplete")
                digest = "sha256:" + m.digest(raw)
                m.need(expected is None or digest == expected, "original_runtime_manifest_descriptor_mismatch")
                header = response.headers.get("Docker-Content-Digest")
                m.need(header is None or header == digest, "original_runtime_manifest_header_mismatch")
            path = stages.directory / ("runtime-original-" + deployment["metadata"]["uid"] + "-" + digest[7:] + ".manifest.json")
            if path.exists():
                m.need(m.read(path) == raw, "original_runtime_manifest_retained_bytes_changed")
                pin = m.pin(path)
            else:
                pin = m.write(path, raw)
            manifests.append(pin)
            return m.decode(raw), digest

        root, root_digest = fetch(match[1])
        m.need(root_digest in {"sha256:" + profile[k] for k in ("base", "selected", "manifest")}, "mutable_runtime_tag_does_not_resolve_to_reviewed_original_content")
        selected, selected_digest = root, root_digest
        if "manifests" in root:
            eligible = [entry for entry in root["manifests"] if entry.get("platform", {}).get("os") == "linux" and entry.get("platform", {}).get("architecture") == "amd64"]
            m.need(len(eligible) == 1 and eligible[0]["digest"] == "sha256:" + profile["selected"], "unique_original_linux_amd64_runtime_required")
            selected, selected_digest = fetch(eligible[0]["digest"], eligible[0]["digest"])
        m.need(selected_digest in ("sha256:" + profile["selected"], "sha256:" + profile["manifest"]) and selected.get("schemaVersion") == 2 and "manifests" not in selected, "reviewed_original_runtime_manifest_required")
        config = selected["config"]["digest"]
        expected_config = "sha256:" + BASE_CONFIG[kind] if selected_digest == "sha256:" + profile["selected"] else images["images"][kind]["config"]
        m.need(config == expected_config, "original_runtime_manifest_config_mismatch")
        selector = deployment["spec"]["selector"]
        m.need(selector.get("matchLabels") and not selector.get("matchExpressions"), "finite_original_runtime_selector_required")
        selector_text = ",".join(k + "=" + v for k, v in sorted(selector["matchLabels"].items()))
        pods = m.decode(self.op.k("-n", m.NS, "get", "pods", "-l", selector_text, "-o", "json"))["items"]
        m.need(len(pods) == deployment["spec"].get("replicas", 1) and len(pods) > 0, "original_tagged_runtime_requires_actual_current_pods")
        actors = []
        for pod in pods:
            m.need(not pod["metadata"].get("deletionTimestamp") and len(pod["spec"].get("containers", [])) == 1 and pod["spec"]["containers"][0]["image"] == c["image"], "original_runtime_tag_pod_template_mismatch")
            owner = m.only_controller(pod, "ReplicaSet")
            rs = stages.get("replicaset", owner["name"])
            parent = m.only_controller(rs, "Deployment")
            statuses = pod.get("status", {}).get("containerStatuses", [])
            m.need(rs["metadata"]["uid"] == owner["uid"] and parent["uid"] == deployment["metadata"]["uid"] and len(statuses) == 1 and statuses[0].get("name") == c["name"] and statuses[0].get("containerID") and "running" in statuses[0].get("state", {}) and m.image_id(statuses[0]["imageID"]) in (root_digest, selected_digest, config), "original_runtime_tag_actual_cri_or_owner_mismatch")
            actors.append({"pod": pod["metadata"]["name"], "uid": pod["metadata"]["uid"], "container_id": statuses[0]["containerID"], "image_id": statuses[0]["imageID"], "replicaset_uid": rs["metadata"]["uid"]})
        current = stages.get("deployment", deployment["metadata"]["name"])
        m.need(current["metadata"]["uid"] == deployment["metadata"]["uid"] and current["spec"] == deployment["spec"], "original_tagged_runtime_template_changed_during_readback")
        proof = {"reference": c["image"], "deployment_uid": deployment["metadata"]["uid"], "root_digest": root_digest, "selected_manifest": selected_digest, "config_digest": config, "manifests": manifests, "pods": actors}
        stages.retain("runtime-original-image-" + deployment["metadata"]["uid"] + ".json", proof)
        return proof

    def inventory(self, final=False):
        items = self.m.decode(self.op.k("-n", self.m.NS, "get", "deployments", "-l", LABEL, "-o", "json"))["items"]
        self.m.need(items and len(items) <= 64, "actual_business_runtime_universe_required")
        self.original_images = {}
        for item in items:
            c = item["spec"]["template"]["spec"]["containers"][0]
            proof = None
            if not final and "@sha256:" not in c["image"]:
                proof = self.original_image_proof(item)
                self.original_images[item["metadata"]["name"]] = proof
            finite_template(item, self.m, original_image=proof, final=final)
        self.m.need({item["metadata"].get("labels", {}).get(LABEL) for item in items} == set(IMAGES), "both_original_openclaw_hermes_runtime_deployments_required")
        return sorted(items, key=lambda x: x["metadata"]["name"])

    def images(self):
        self.op.upgraded_released()
        root, stages, m = self.op.root, self.stages, self.m
        m.need(self.op.a.runtime_registry_credentials_file is None, "startup_collector_authorization_adapter_required_for_private_registry")
        bundle = self.op.a.runtime_agent_bundle_file or root / "agent-prebuilt-shared-native-236d56d85fea-linux-amd64.tar.gz"
        m.read(bundle, BUNDLE_SHA, limit=64 << 20, private=False)
        helper = root / "scripts/system-backup-agent-runtime-layer/agent_runtime_layer.py"
        m.read(helper, LAYER_SHA, private=False)
        images = {}
        for kind in IMAGES:
            argv = [sys.executable, "-B", helper, "--runtime", kind, "--bundle", bundle, "--shared-private-agent-data-dir", "--push", "--max-seconds", "1200"]
            if kind == "openclaw":
                argv += ["--openclaw-shared-service-gate"]
            value, pin = stages.call("runtime-image-" + kind, argv)
            m.need(value["status"] == "image-pushed" and value["immutable_reference"] == reference(kind) and value["manifest_digest"] == "sha256:" + IMAGES[kind]["manifest"] and re.fullmatch(r"sha256:[a-f0-9]{64}", value["config_digest"]) and value["tag_written"] is False and value["workload_mutated"] is False, "actual_runtime_immutable_publication_required")
            m.need(kind != "openclaw" or value.get("openclaw_shared_service_gate") is True, "original_openclaw_fixed_shared_gate_required")
            m.need(value.get("shared_agent_data_directory") == {"path": "/var/lib/openclaw-agent" if kind == "openclaw" else "/var/lib/clawmanager-agent", "uid": 0, "gid": 0, "mode": "0700"}, "actual_managed_private_agent_directory_required")
            images[kind] = {"reference": value["immutable_reference"], "manifest": value["manifest_digest"], "config": value["config_digest"], "native_receipt": pin}
        collector = root / "scripts/system-backup-runtime-startup-inputs.py"
        m.read(collector, COLLECTOR_SHA, private=False)
        argv = [sys.executable, "-B", collector, "--output-directory", stages.directory / "runtime-startup-images"]
        for kind in IMAGES:
            argv += ["--image", kind + "=" + images[kind]["reference"]]
        # Anonymous original registry is already the reviewed producer default.
        # Distinct credential encodings are never converted or leaked here.
        collected, receipt = stages.call("runtime-startup-images-collect", argv)
        definition = {"File": collected["file"], "SHA256": collected["sha256"]}
        m.pinned(definition)
        result = {"version": "operator-business-runtime-images.v1", "images": images, "startup_images": definition, "collector_receipt": receipt, "native_qualified": False, "backup_ready": False}
        stages.retain("runtime-images.result.json", result)
        return result

    def final_pods(self, deployment, desired, image):
        m, stages = self.m, self.stages
        name, uid = deployment["metadata"]["name"], deployment["metadata"]["uid"]
        selector = ",".join(k + "=" + v for k, v in sorted(desired["selector"]["matchLabels"].items()))
        replicas = desired.get("replicas", 1)
        for _ in range(120):
            current = stages.get("deployment", name)
            m.need(current["metadata"]["uid"] == uid and current["spec"] == desired, "original_runtime_deployment_drift_during_rollout")
            pods = m.decode(self.op.k("-n", m.NS, "get", "pods", "-l", selector, "-o", "json"))["items"]
            status = current.get("status", {})
            stable = len(pods) == replicas and status.get("observedGeneration", 0) >= current["metadata"]["generation"] and status.get("updatedReplicas", 0) == replicas and status.get("availableReplicas", 0) == replicas
            if stable:
                final = []
                for pod in pods:
                    m.need(not pod["metadata"].get("deletionTimestamp") and len(pod["spec"].get("containers", [])) == 1 and not pod["spec"].get("initContainers") and not pod["spec"].get("ephemeralContainers"), "final_runtime_pod_shape_unconfirmed")
                    owner = m.only_controller(pod, "ReplicaSet")
                    rs = stages.get("replicaset", owner["name"])
                    parent = m.only_controller(rs, "Deployment")
                    m.need(rs["metadata"]["uid"] == owner["uid"] and parent["uid"] == uid and pod["spec"]["containers"][0]["image"] == image["reference"], "final_runtime_original_owner_or_image_mismatch")
                    actual_container, expected_container = pod["spec"]["containers"][0], desired["template"]["spec"]["containers"][0]
                    m.need(all(actual_container.get(key, [] if key != "workingDir" else "") == expected_container.get(key, [] if key != "workingDir" else "") for key in ("command", "args", "workingDir", "env", "envFrom")), "runtime_admission_changed_original_startup_or_secret_references")
                    comparison = copy.deepcopy(current)
                    comparison["spec"]["template"] = {"metadata": pod["metadata"], "spec": pod["spec"]}
                    finite_template(comparison, m, final=True)
                    statuses = pod.get("status", {}).get("containerStatuses", [])
                    m.need(len(statuses) == 1 and statuses[0].get("ready") and "running" in statuses[0].get("state", {}) and statuses[0].get("containerID") and m.image_id(statuses[0]["imageID"]) in (image["manifest"], image["config"]), "final_runtime_real_cri_image_not_confirmed")
                    pod_pin = stages.retain("runtime-final-" + pod["metadata"]["uid"] + "-" + m.digest(m.encoded(pod))[:12] + ".pod.private.json", pod)
                    final.append({"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"], "replicaset_uid": rs["metadata"]["uid"], "container_id": statuses[0]["containerID"], "image_id": statuses[0]["imageID"], "node": pod["spec"]["nodeName"], "pod_spec_sha256": m.digest(m.encoded(pod["spec"])), "private_snapshot": pod_pin})
                return current, final
            time.sleep(2)
        m.need(False, "runtime_rollout_unknown_read_original_no_resend")

    def agent_tls_materials(self, universe, query=False):
        m, stages = self.m, self.stages
        path = stages.directory / "runtime-agent-tls.result.json"
        if not path.exists():
            m.need(not query, "original_runtime_agent_tls_result_required_no_reissue")
            definition = stages.retain("runtime-agent-tls.definition.json", {"Version": "original-shared-agent-tls-definition.v1", "SecretPrefix": stages.prefix + "-agent-tls", "ValiditySeconds": 86400})
            directory = stages.directory / "runtime-agent-tls"
            directory.mkdir(mode=0o700, exist_ok=True)
            material, receipt = stages.cli("runtime-agent-tls-materials", "system-backup-observer-deployment-materials", ["--mode", "shared-agent-tls", "--definition-file", definition["File"], "--definition-sha256", definition["SHA256"], "--output-directory", directory])
            m.need(material["Version"] == "original-shared-agent-tls-materials.v1" and material["Status"] == "materialized_uninstalled_no_native_source_proof" and material["Namespace"] == m.NS and material["ServerName"] == "lite-agent.clawmanager.internal", "actual_agent_tls_material_producer_required")
            m.need({(d["metadata"]["name"], d["metadata"]["uid"]) for d in universe} == {(t["Deployment"], t["DeploymentUID"]) for t in material["Targets"]}, "complete_actual_agent_tls_universe_required")
            secrets = []
            for target in material["Targets"]:
                manifest = m.decode(m.pinned(target["SecretManifest"]))
                secret = stages.create_object("runtime-agent-tls-secret-" + m.digest(target["DeploymentUID"].encode())[:16], manifest)
                m.need(secret.get("type") == "kubernetes.io/tls" and secret.get("immutable") is True, "actual_immutable_agent_tls_secret_required")
                secrets.append({"name": target["SecretName"], "uid": secret["metadata"]["uid"], "deployment_uid": target["DeploymentUID"]})
            stages.retain(path.name, {"version": "operator-shared-agent-tls.v1", "operation": stages.operation, "materials_receipt": receipt, "secrets": secrets, "native_qualified": False, "backup_ready": False})
        result = m.decode(m.read(path))
        m.need(result["version"] == "operator-shared-agent-tls.v1" and result["operation"] == stages.operation, "same_original_agent_tls_operation_required")
        material = m.decode(m.pinned(result["materials_receipt"]))
        m.need({(d["metadata"]["name"], d["metadata"]["uid"]) for d in universe} == {(t["Deployment"], t["DeploymentUID"]) for t in material["Targets"]}, "agent_tls_universe_changed")
        m.pinned(material["CA"])
        secrets = {entry["deployment_uid"]: entry for entry in result["secrets"]}
        m.need(set(secrets) == {target["DeploymentUID"] for target in material["Targets"]}, "complete_agent_tls_secret_uid_roster")
        for target in material["Targets"]:
            m.pinned(target["Certificate"]); m.pinned(target["PrivateKey"])
            manifest = m.decode(m.pinned(target["SecretManifest"]))
            current = stages.get("secret", target["SecretName"])
            m.need(current["metadata"]["uid"] == secrets[target["DeploymentUID"]]["uid"] and current.get("immutable") is True and current.get("type") == manifest["type"] and current.get("data") == manifest["data"] and not current["metadata"].get("deletionTimestamp"), "actual_original_agent_tls_secret_changed")
        return result, material

    def verify_agent_tls(self, deployments, material):
        import socket
        m, stages = self.m, self.stages
        m.pinned(material["CA"])
        context = m.ssl.create_default_context(cafile=material["CA"]["File"])
        context.minimum_version = m.ssl.TLSVersion.TLSv1_3
        targets = {target["DeploymentUID"]: target for target in material["Targets"]}
        checks = []
        for binding in deployments:
            target = targets[binding["uid"]]
            deployment = stages.get("deployment", binding["name"])
            validate_agent_tls_template(deployment, target, m)
            for observed in binding["pods"]:
                pod = stages.get("pod", observed["name"])
                m.need(pod["metadata"]["uid"] == observed["uid"] and m.digest(m.encoded(pod["spec"])) == observed["pod_spec_sha256"] and pod["spec"]["nodeName"] == observed["node"], "same_actual_tls_agent_pod_required")
                address = str(m.ipaddress.ip_address(pod["status"]["podIP"]))
                with socket.create_connection((address, 19090), timeout=10) as tcp:
                    with context.wrap_socket(tcp, server_hostname=material["ServerName"]) as tls:
                        uris = [value for kind, value in tls.getpeercert().get("subjectAltName", ()) if kind == "URI"]
                        m.need(tls.version() == "TLSv1.3" and uris == [target["ServerURI"]] and m.digest(tls.getpeercert(binary_form=True)) == target["ServerCertificateDERSHA256"], "actual_agent_tls_leaf_or_deployment_identity_mismatch")
                        checks.append({"deployment_uid": binding["uid"], "pod_uid": observed["uid"], "server_uri": target["ServerURI"], "certificate_der_sha256": target["ServerCertificateDERSHA256"], "tls_version": tls.version()})
        return checks

    def rollout(self, query=False):
        m, stages = self.m, self.stages
        if not query and ((stages.directory / "runtime-rollout.result.json").exists() or (stages.directory / "runtime-rollout.confirmed.json").exists()):
            return verify_current(self.op)
        images = m.decode(m.read(stages.directory / "runtime-images.result.json"))
        for value in images["images"].values():
            m.pinned(value["native_receipt"])
        m.pinned(images["startup_images"])
        universe = self.inventory()
        tls_result, tls_material = self.agent_tls_materials(universe, query=query)
        tls_targets = {target["DeploymentUID"]: target for target in tls_material["Targets"]}
        plan_file = stages.directory / "runtime-rollout.plan.json"
        if plan_file.exists():
            plan = m.decode(m.read(plan_file))
        else:
            m.need(not query, "original_runtime_rollout_plan_required_for_query")
            plan = {"version": "operator-original-business-runtime-rollout-plan.v1", "operation": stages.operation, "agent_tls_materials": tls_result["materials_receipt"], "deployments": []}
            # Build/validate the ENTIRE original universe before the first patch.
            for deployment in universe:
                proof = self.original_images.get(deployment["metadata"]["name"])
                kind, desired = desired_spec(deployment, stages.operation, m, original_image=proof, agent_tls=tls_targets[deployment["metadata"]["uid"]])
                plan["deployments"].append({"runtime": kind, "original": deployment, "desired": desired, "original_image": proof})
            stages.retain(plan_file.name, plan)
        m.need(plan["operation"] == stages.operation and plan.get("agent_tls_materials") == tls_result["materials_receipt"], "same_runtime_rollout_operation_and_tls_material_required")
        current_universe = self.inventory()
        m.need({(d["metadata"]["name"], d["metadata"]["uid"]) for d in current_universe} == {(x["original"]["metadata"]["name"], x["original"]["metadata"]["uid"]) for x in plan["deployments"]}, "original_runtime_universe_changed")
        public, bindings = [], []
        for selected in plan["deployments"]:
            original, desired, kind = selected["original"], selected["desired"], selected["runtime"]
            current = stages.get("deployment", original["metadata"]["name"])
            if not query:
                patch = [{"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": original["metadata"]["resourceVersion"]}, {"op": "test", "path": "/spec", "value": original["spec"]}, {"op": "replace", "path": "/spec", "value": desired}]
                current, _ = stages.kubectl("runtime-rollout-" + original["metadata"]["name"], ["patch", "deployment", original["metadata"]["name"], "--type=json", "--patch-file=/dev/stdin", "-o", "json"], patch)
            m.need(current["metadata"]["uid"] == original["metadata"]["uid"], "original_runtime_deployment_replaced")
            current, pods = self.final_pods(original, desired, images["images"][kind])
            public_item = public_template(current, m)
            public_item["actual_pods"] = [{k: v for k, v in pod.items() if k != "private_snapshot"} for pod in pods]
            public.append(public_item)
            bindings.append({"name": current["metadata"]["name"], "uid": current["metadata"]["uid"], "spec_sha256": m.digest(m.encoded(current["spec"])), "pods": pods})
        suffix = "-query-" + secrets.token_hex(8) if query else ""
        public_pin = stages.retain("runtime-final-templates" + suffix + ".public.json", {"version": "original-runtime-final-template-public.v1", "templates": public, "native_qualified": False})
        loaded = any(e["source"] == "secretKeyRef" for item in public for c in item["containers"] for e in c["environment"])
        tls_checks = self.verify_agent_tls(bindings, tls_material)
        result = {"version": "operator-business-runtime-rollout.v1", "operation": stages.operation, "deployments": bindings, "public_templates": public_pin, "startup_images": images["startup_images"], "configuration_mutated": False, "requires_original_loaded_environment_qualification": loaded, "agent_tls_materials": tls_result["materials_receipt"], "actual_agent_tls_handshakes": tls_checks, "native_qualified": False, "backup_ready": False}
        result_pin = stages.retain("runtime-rollout" + suffix + ".result.json", result)
        if query:
            canonical = stages.directory / "runtime-rollout.result.json"
            confirmation = stages.directory / "runtime-rollout.confirmed.json"
            if canonical.exists() or confirmation.exists():
                # Existing completion cannot move to a replacement Pod or a
                # different operation merely because it has the same image.
                verify_current(self.op)
            else:
                stages.retain(confirmation.name, {"version": "operator-original-runtime-rollout-confirmed.v1",
                    "operation": stages.operation, "plan": m.pin(plan_file), "result": result_pin})
        return result


def dispatch(operator):
    stages = BusinessRuntimeStages(operator)
    if operator.a.action == "runtime-images":
        return stages.images()
    return stages.rollout(query=operator.a.action == "runtime-query")


def verify_current(operator):
    stages = BusinessRuntimeStages(operator)
    canonical = stages.stages.directory / "runtime-rollout.result.json"
    if canonical.exists():
        result = stages.m.decode(stages.m.read(canonical))
    else:
        confirmation = stages.m.decode(stages.m.read(stages.stages.directory / "runtime-rollout.confirmed.json"))
        stages.m.need(confirmation["version"] == "operator-original-runtime-rollout-confirmed.v1" and
                      confirmation["operation"] == stages.stages.operation and
                      confirmation["plan"]["File"] == str(stages.stages.directory / "runtime-rollout.plan.json"),
                      "same_original_runtime_confirmation_required")
        plan = stages.m.decode(stages.m.pinned(confirmation["plan"]))
        stages.m.need(plan["operation"] == confirmation["operation"], "original_runtime_confirmed_plan_changed")
        result = stages.m.decode(stages.m.pinned(confirmation["result"]))
    stages.m.need(result["operation"] == stages.stages.operation and result["version"] == "operator-business-runtime-rollout.v1", "final_business_runtime_rollout_required_before_uid_bound_materials")
    actual = stages.inventory(final=True)
    stages.m.need({(d["metadata"]["name"], d["metadata"]["uid"]) for d in actual} == {(d["name"], d["uid"]) for d in result["deployments"]}, "business_runtime_universe_changed_after_final_rollout")
    for binding in result["deployments"]:
        deployment = stages.stages.get("deployment", binding["name"])
        stages.m.need(stages.m.digest(stages.m.encoded(deployment["spec"])) == binding["spec_sha256"], "business_runtime_template_changed_after_final_rollout")
        for old in binding["pods"]:
            pod = stages.stages.get("pod", old["name"])
            statuses = pod.get("status", {}).get("containerStatuses", [])
            stages.m.need(pod["metadata"]["uid"] == old["uid"] and not pod["metadata"].get("deletionTimestamp") and stages.m.digest(stages.m.encoded(pod["spec"])) == old["pod_spec_sha256"] and len(statuses) == 1 and statuses[0].get("containerID") == old["container_id"] and statuses[0].get("imageID") == old["image_id"] and statuses[0].get("ready"), "business_runtime_actor_changed_recollect_original_facts")
    tls_result, tls_material = stages.agent_tls_materials(actual, query=True)
    stages.m.need(result.get("agent_tls_materials") == tls_result["materials_receipt"], "same_rollout_tls_material_lineage_required")
    stages.verify_agent_tls(result["deployments"], tls_material)
    return result
