#!/usr/bin/env python3
"""Validation-environment first-owner bootstrap preflight.

Read-only census, bootstrap-object rendering and server-side dry-run. It binds
the selected validation enrollment/plan, reuses the existing operator
deployment template constants and shapes, and records the identity chain that
the real objects must exhibit before any final config, certificate or grant is
issued against it.

Two modes:
  preflight  read plan/enrollment/census, render the bootstrap object set and
             run `kubectl apply --dry-run=server` for every object. Nothing is
             created and no credential is printed.
  observe    after the existing operator template created the base observer and
             the controller Pod that waits for controller.env.ready, read the
             Deployment -> ReplicaSet -> Running Pod -> ServiceAccount -> PVC
             UID chain and reject drift.

No SQL password, token, DSN or private key is read or emitted.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

VERSION = "original-validation-bootstrap-preflight.v1"
DEFINITION_VERSION = "original-validation-bootstrap-preflight-definition.v1"
PLAN_VERSION = "system-backup-installation-owner-enrollment-plan.v1"
ENROLLMENT_VERSION = "system-backup-installation-owner-enrollment.v1"
MARKER = "backup.clawreef.io/original-operator"
PLAN_MARKER = "backup.clawreef.io/original-plan-sha256"
RUNTIME_MOUNT = "/run/system-backup"
RUNTIME = RUNTIME_MOUNT + "/runtime"
PRIVATE_MOUNT = "/run/installation-owner-private"
PRIVATE = PRIVATE_MOUNT + "/installer"
STAGING = "/var/lib/system-backup/staging"
CONTROLLER_READY = "/run/system-backup/runtime/controller.env.ready"

# Mirrors DeploymentStages.host_observer in system-backup-operator-deployment.py.
# The controller starts only after the owner materializes the final literal
# environment file and its .ready digest, and backup stays disabled.
LAUNCHER = """set -eu
f=/run/system-backup/runtime/controller.env
while test ! -f "$f.ready"; do sleep 2; done
test ! -L "$f"; test ! -L "$f.ready"
test "$(stat -c %u:%a "$f")" = 65532:600
test "$(sha256sum "$f" | cut -d ' ' -f 1)" = "$(cat "$f.ready")"
while IFS= read -r entry; do
 case $entry in SYSTEM_BACKUP_*=*|DB_*=*|CLAWMANAGER_LEADER_ELECTION=*) export "$entry";; *) exit 41;; esac
done < "$f"
exec /usr/local/bin/system-backup-v2-controller
"""

# Resource names accepted by kubectl for the rendered kinds.
RESOURCES = {
    "ServiceAccount": "serviceaccount",
    "Role": "role",
    "RoleBinding": "rolebinding",
    "ClusterRole": "clusterrole",
    "ClusterRoleBinding": "clusterrolebinding",
    "PersistentVolumeClaim": "persistentvolumeclaim",
    "Deployment": "deployment",
    "Service": "service",
}

DIGEST = re.compile(r"^[a-f0-9]{64}$")
DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
OPERATION = re.compile(r"^[a-f0-9]{32}$")
SIZE = re.compile(r"^[1-9][0-9]{0,3}(?:Gi|Ti)$")


class Refused(Exception):
    """A concrete preflight rejection; the string is the stable reason code."""


def need(value, code):
    if not value:
        raise Refused(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_file(path, limit=4 << 20):
    raw = Path(path).read_bytes()
    need(0 < len(raw) <= limit, "bounded_file_required:" + str(path))
    return raw


def pinned(reader, path, pin, limit=4 << 20):
    need(isinstance(pin, str) and DIGEST.fullmatch(pin), "digest_pin_required:" + str(path))
    raw = reader(path, limit)
    need(isinstance(raw, bytes) and 0 < len(raw) <= limit, "bounded_file_required:" + str(path))
    need(sha256(raw) == pin, "pinned_file_changed:" + str(path))
    return raw


def decode_canonical(raw, code):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Refused(code + ":not_json")
    need(isinstance(value, dict), code + ":not_object")
    need(canonical(value) == raw or canonical(value) == raw.rstrip(b"\n"), code + ":not_canonical")
    return value


def exact(value, keys, code):
    need(isinstance(value, dict) and set(value) == set(keys), code + ":closed_schema")


def bounded_text(value, code, limit=512):
    need(isinstance(value, str) and 0 < len(value) <= limit and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value), code)


def digest_text(value, code):
    need(isinstance(value, str) and DIGEST.fullmatch(value) is not None, code)


def rules(value, code):
    need(isinstance(value, list), code + ":list")
    out = []
    for rule in value:
        need(isinstance(rule, dict), code + ":rule")
        need(set(rule) <= {"apiGroups", "resources", "verbs", "resourceNames"} and {"apiGroups", "resources", "verbs"} <= set(rule), code + ":rule")
        for key in ("apiGroups", "resources", "verbs"):
            need(isinstance(rule[key], list) and rule[key] and all(isinstance(x, str) for x in rule[key]), code + ":" + key)
        need(all(name for name in rule["resources"]) and all(name for name in rule["verbs"]), code + ":resource_and_verb_names")
        if "resourceNames" in rule:
            need(isinstance(rule["resourceNames"], list) and rule["resourceNames"] and all(isinstance(x, str) and x for x in rule["resourceNames"]), code + ":resourceNames")
        out.append({key: list(rule[key]) for key in ("apiGroups", "resources", "verbs", "resourceNames") if key in rule})
    return out


def pvc(name, size, access_mode, storage_class):
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": name, "annotations": {}},
        "spec": {
            "accessModes": [access_mode],
            "volumeMode": "Filesystem",
            "resources": {"requests": {"storage": size}},
            "storageClassName": storage_class,
        },
    }


def role_binding(kind, name, namespace, subject, role_ref):
    obj = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": name},
        "subjects": [{"kind": "ServiceAccount", "name": subject, "namespace": namespace}],
        "roleRef": role_ref,
    }
    if kind == "RoleBinding":
        obj["metadata"]["namespace"] = namespace
    return obj


class Kubectl:
    """Bounded kubectl runner. Only the fixed argv shapes below are issued."""

    def __init__(self, kubeconfig, context=None, timeout="60s", runner=None):
        self.base = ["kubectl", "--kubeconfig", str(kubeconfig), "--request-timeout=" + timeout]
        if context:
            self.base += ["--context", context]
        self.runner = runner or self._subprocess

    @staticmethod
    def _subprocess(argv, data):
        result = subprocess.run(argv, input=data, capture_output=True, timeout=180, check=False)
        return result.returncode, result.stdout, result.stderr

    def _run(self, args, data=None):
        return self.runner([*self.base, *args], data)

    def get(self, kind, name, namespace=None):
        argv = ["get", kind, name, "--ignore-not-found", "-o", "json"]
        if namespace:
            argv += ["-n", namespace]
        code, out, _ = self._run(argv)
        need(code == 0, "kubectl_get_failed:" + kind + "/" + name)
        return json.loads(out) if out.strip() else None

    def list(self, kind, namespace=None, selector=None):
        argv = ["get", kind, "-o", "json"]
        if namespace:
            argv += ["-n", namespace]
        if selector:
            argv += ["-l", selector]
        code, out, err = self._run(argv)
        if code != 0:
            # An absent snapshot CRD is a concrete unconfirmed item, not a crash.
            if b"the server could not find the requested resource" in err or b"doesn't have a resource type" in err:
                return None
            need(False, "kubectl_list_failed:" + kind)
        return json.loads(out).get("items", []) if out.strip() else []

    def apply_dry_run(self, obj, namespace):
        argv = ["apply", "--dry-run=server", "-f", "-", "-o", "json"]
        if obj["kind"] not in ("ClusterRole", "ClusterRoleBinding"):
            argv += ["-n", namespace]
        code, out, err = self._run(argv, canonical(obj))
        need(code == 0, "server_dry_run_rejected:" + obj["kind"] + "/" + obj["metadata"]["name"] + ":" + err.decode(errors="replace")[:160])
        return json.loads(out) if out.strip() else {}

    def config_view(self):
        code, out, _ = self._run(["config", "view", "--minify", "--flatten", "--raw", "-o", "json"])
        need(code == 0, "kubeconfig_view_failed")
        return json.loads(out)


def load_definition(raw):
    d = decode_canonical(raw, "definition")
    exact(d, {
        "Version", "Operation", "Namespace", "Plan", "ControllerServiceAccount", "WorkerServiceAccount",
        "SourcesServiceAccount", "ControllerDeployment", "ControlService", "InputsClaim", "StagingClaim",
        "PrivateClaim", "InputsStorageClass", "StagingStorageClass", "StagingSize", "PrivateSize",
        "AppDeployment", "AppImage", "RuntimeDeployments", "RuntimeImages", "LonghornNamespace",
        "SnapshotClass", "CloneClass", "ControllerRules", "ControllerClusterRules", "WorkerRules",
        "WorkerClusterRules", "SourceRules",
    }, "definition")
    need(d["Version"] == DEFINITION_VERSION, "definition_version")
    need(isinstance(d["Operation"], str) and OPERATION.fullmatch(d["Operation"]), "definition_operation")
    need(isinstance(d["Namespace"], str) and DNS_SUBDOMAIN.fullmatch(d["Namespace"]), "definition_namespace")
    exact(d["Plan"], {"InstallationID", "NamespaceUID", "ClusterID", "ServerUUID", "Database"}, "definition_plan")
    for key in ("InstallationID", "NamespaceUID", "ClusterID", "ServerUUID", "Database"):
        bounded_text(d["Plan"][key], "definition_plan_" + key.lower())
    for key in ("ControllerServiceAccount", "WorkerServiceAccount", "SourcesServiceAccount", "ControllerDeployment",
                "ControlService", "InputsClaim", "StagingClaim", "PrivateClaim", "InputsStorageClass",
                "StagingStorageClass", "AppDeployment", "LonghornNamespace", "SnapshotClass", "CloneClass"):
        need(isinstance(d[key], str) and DNS_SUBDOMAIN.fullmatch(d[key]) is not None, "definition_name:" + key)
    for key in ("StagingSize", "PrivateSize"):
        need(isinstance(d[key], str) and SIZE.fullmatch(d[key]) is not None, "definition_size:" + key)
    need(isinstance(d["AppImage"], str) and re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}", d["AppImage"]), "definition_app_image")
    need(isinstance(d["RuntimeDeployments"], dict) and set(d["RuntimeDeployments"]) <= {"hermes", "openclaw"} and d["RuntimeDeployments"], "definition_runtime_deployments")
    need(isinstance(d["RuntimeImages"], dict) and set(d["RuntimeImages"]) <= set(d["RuntimeDeployments"]), "definition_runtime_images")
    for value in d["RuntimeDeployments"].values():
        need(isinstance(value, str) and DNS_SUBDOMAIN.fullmatch(value) is not None, "definition_runtime_deployment_name")
    for value in d["RuntimeImages"].values():
        need(isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value), "definition_runtime_image")
    for key in ("ControllerRules", "ControllerClusterRules", "WorkerRules", "WorkerClusterRules", "SourceRules"):
        d[key] = rules(d[key], "definition_" + key)
    need(len(d["ControllerClusterRules"]) == 0 or d["ControllerRules"], "definition_controller_rules_shape")
    return d


def load_plan(raw):
    d = decode_canonical(raw, "plan")
    exact(d, {
        "SchemaVersion", "EnrollmentName", "EnrollmentID", "IssuerID", "EnrollmentRevision", "Target",
        "InstallerDatabaseAccount", "LocalAdminUsername", "OwnerUsername", "OwnerUID", "OwnerGroups",
        "IssuerPublicKeySHA256", "KubernetesAPI", "KubernetesCASHA256", "DatabaseCASHA256",
        "DatabaseTLSServerName",
    }, "plan")
    need(d.get("SchemaVersion") == PLAN_VERSION, "plan_version")
    need(isinstance(d.get("Target"), dict), "plan_target")
    for key in ("InstallationID", "ServerUUID", "Database", "DatabaseAccount", "ClusterID", "Namespace", "NamespaceUID"):
        bounded_text(d["Target"].get(key), "plan_target_" + key.lower())
    need(isinstance(d.get("EnrollmentName"), str) and DNS_SUBDOMAIN.fullmatch(d["EnrollmentName"]) is not None, "plan_enrollment_name")
    digest_text(d.get("IssuerPublicKeySHA256"), "plan_issuer_public")
    return d


def verify_enrollment(kubectl, plan, pin, issuer_public):
    exact(pin, {"ConfigMapUID", "DocumentSHA256"}, "enrollment_pin")
    bounded_text(pin["ConfigMapUID"], "enrollment_pin_uid")
    digest_text(pin["DocumentSHA256"], "enrollment_pin_document")
    namespace = plan["Target"]["Namespace"]
    cm = kubectl.get("configmap", plan["EnrollmentName"], namespace)
    need(cm is not None, "enrollment_configmap_absent")
    need(cm["metadata"].get("uid") == pin["ConfigMapUID"], "enrollment_configmap_uid_changed")
    need(not cm["metadata"].get("deletionTimestamp"), "enrollment_configmap_deleting")
    need(cm.get("immutable") is True, "enrollment_configmap_not_immutable")
    data = cm.get("data") or {}
    need(set(data) == {"enrollment.json"} and not cm.get("binaryData"), "enrollment_configmap_shape")
    raw = data["enrollment.json"].encode()
    need(sha256(raw) == pin["DocumentSHA256"], "enrollment_document_changed")
    document = json.loads(raw)
    need(document.get("SchemaVersion") == ENROLLMENT_VERSION, "enrollment_document_version")
    need(document.get("Plan") == plan, "enrollment_plan_mismatch")
    need(isinstance(document.get("AdminUserID"), int) and document["AdminUserID"] > 0, "enrollment_admin")
    if issuer_public is not None:
        need(base64.b64decode(document.get("Issuer", "")) == issuer_public, "enrollment_issuer_public_mismatch")
    return {"ConfigMapUID": pin["ConfigMapUID"], "DocumentSHA256": pin["DocumentSHA256"], "Namespace": namespace}


def verify_target(kubectl, plan, definition):
    target = plan["Target"]
    need(target["Namespace"] == definition["Namespace"], "definition_namespace_mismatch")
    for key in ("InstallationID", "NamespaceUID", "ClusterID", "ServerUUID", "Database"):
        need(target[key] == definition["Plan"][key], "definition_target_mismatch:" + key)
    namespace = kubectl.get("namespace", target["Namespace"])
    need(namespace is not None, "target_namespace_absent")
    need(namespace["metadata"].get("uid") == target["NamespaceUID"], "target_namespace_uid_changed")
    need(not namespace["metadata"].get("deletionTimestamp"), "target_namespace_deleting")
    return {"NamespaceUID": target["NamespaceUID"], "ClusterID": target["ClusterID"]}


def pod_images(pod):
    return {state.get("name"): state.get("imageID", "") for state in pod.get("status", {}).get("containerStatuses", [])}


def digest_suffix(image_id):
    index = image_id.find("@sha256:")
    return image_id[index + 1:] if index >= 0 else ""


def deployment_pods(kubectl, namespace, deployment):
    selector = deployment["spec"].get("selector", {}).get("matchLabels") or {}
    need(selector and not deployment["spec"]["selector"].get("matchExpressions"), "deployment_selector_required")
    query = ",".join(key + "=" + value for key, value in sorted(selector.items()))
    items = kubectl.list("pods", namespace, query)
    need(items is not None, "pods_list_unavailable")
    return [pod for pod in items if not pod["metadata"].get("deletionTimestamp")]


def census_app(kubectl, definition):
    namespace = definition["Namespace"]
    deployment = kubectl.get("deployment", definition["AppDeployment"], namespace)
    need(deployment is not None and deployment["metadata"].get("uid"), "app_deployment_absent")
    need(not deployment["metadata"].get("deletionTimestamp"), "app_deployment_deleting")
    containers = deployment["spec"]["template"]["spec"].get("containers") or []
    need(containers, "app_deployment_container_required")
    pods = deployment_pods(kubectl, namespace, deployment)
    need(pods, "app_deployment_has_no_pods")
    images = []
    for pod in pods:
        for name, image_id in pod_images(pod).items():
            images.append({"pod": pod["metadata"]["name"], "pod_uid": pod["metadata"]["uid"], "container": name, "image_id": image_id})
    images.sort(key=lambda item: (item["pod"], item["container"]))
    unconfirmed = []
    released = any(digest_suffix(item["image_id"]) == definition["AppImage"].split("@", 1)[1] for item in images)
    if not released:
        # The bootstrap Pod can be admitted with the final reference before the
        # business rollout; the callback records the missing release digest for
        # the reviewed disposition instead of silently claiming it is current.
        unconfirmed.append("app_release_image_not_yet_rolled_out")
    return {
        "Name": definition["AppDeployment"],
        "UID": deployment["metadata"]["uid"],
        "Image": definition["AppImage"],
        "Pods": images,
    }, unconfirmed


def census_runtime(kubectl, definition):
    namespace = definition["Namespace"]
    out, unconfirmed = {}, []
    for runtime, name in sorted(definition["RuntimeDeployments"].items()):
        deployment = kubectl.get("deployment", name, namespace)
        need(deployment is not None and deployment["metadata"].get("uid"), "runtime_deployment_absent:" + runtime)
        need(not deployment["metadata"].get("deletionTimestamp"), "runtime_deployment_deleting:" + runtime)
        pods = deployment_pods(kubectl, namespace, deployment)
        need(pods, "runtime_deployment_has_no_pods:" + runtime)
        images = []
        for pod in pods:
            for container, image_id in pod_images(pod).items():
                images.append({"pod": pod["metadata"]["name"], "pod_uid": pod["metadata"]["uid"], "container": container, "image_id": image_id})
        expected = definition["RuntimeImages"].get(runtime)
        if expected:
            need(any(digest_suffix(item["image_id"]) == expected for item in images), "runtime_pod_image_mismatch:" + runtime)
        else:
            unconfirmed.append("runtime_image_pin_required:" + runtime)
        out[runtime] = {"Deployment": name, "UID": deployment["metadata"]["uid"], "Pods": images}
    return out, unconfirmed


def census_platform(kubectl, definition):
    namespace = definition["Namespace"]
    nodes = kubectl.list("nodes")
    need(nodes, "nodes_absent")
    node_view = []
    for node in nodes:
        need(not node["metadata"].get("deletionTimestamp"), "node_deleting")
        info = node.get("status", {}).get("nodeInfo", {})
        node_view.append({
            "Name": node["metadata"]["name"],
            "UID": node["metadata"]["uid"],
            "KubeletVersion": info.get("kubeletVersion"),
            "ContainerRuntimeVersion": info.get("containerRuntimeVersion"),
            "OS": info.get("operatingSystem"),
        })
    need(all(item["UID"] for item in node_view), "node_uid_required")
    node_view.sort(key=lambda item: item["Name"])

    inputs = kubectl.get("storageclass", definition["InputsStorageClass"])
    need(inputs is not None, "inputs_storage_class_absent")
    need(inputs.get("provisioner") == "driver.longhorn.io", "inputs_storage_class_not_longhorn")
    need(inputs["metadata"].get("uid"), "inputs_storage_class_uid_required")
    staging = kubectl.get("storageclass", definition["StagingStorageClass"])
    need(staging is not None, "staging_storage_class_absent")
    need(staging.get("provisioner") != "kubernetes.io/no-provisioner", "staging_storage_class_not_dynamic")

    classes = kubectl.list("volumesnapshotclasses")
    unconfirmed = []
    snapshot = None
    if classes is None:
        unconfirmed.append("snapshot_crd_absent")
    else:
        for item in classes:
            if item["metadata"]["name"] == definition["SnapshotClass"]:
                snapshot = item
        if snapshot is None:
            unconfirmed.append("snapshot_class_absent")
        else:
            need(snapshot.get("driver") == "driver.longhorn.io", "snapshot_class_not_longhorn")
    clone = kubectl.get("storageclass", definition["CloneClass"])
    if clone is None:
        unconfirmed.append("clone_class_absent")

    longhorn = kubectl.get("namespace", definition["LonghornNamespace"])
    need(longhorn is not None and longhorn["metadata"].get("uid"), "longhorn_namespace_absent")

    app_ns = kubectl.get("namespace", namespace)
    pv_names = sorted({claim["spec"].get("volumeName") for claim in (kubectl.list("persistentvolumeclaims", namespace) or []) if claim["spec"].get("volumeName")})
    return {
        "NamespaceUID": app_ns["metadata"]["uid"],
        "Nodes": node_view,
        "InputsStorageClass": {"Name": inputs["metadata"]["name"], "UID": inputs["metadata"]["uid"], "Provisioner": inputs.get("provisioner"), "VolumeBindingMode": inputs.get("volumeBindingMode"), "ReclaimPolicy": inputs.get("reclaimPolicy"), "AllowVolumeExpansion": inputs.get("allowVolumeExpansion")},
        "StagingStorageClass": {"Name": staging["metadata"]["name"], "UID": staging["metadata"]["uid"], "Provisioner": staging.get("provisioner")},
        "SnapshotClass": None if snapshot is None else {"Name": snapshot["metadata"]["name"], "UID": snapshot["metadata"]["uid"], "Driver": snapshot.get("driver")},
        "CloneClass": None if clone is None else {"Name": clone["metadata"]["name"], "Provisioner": clone.get("provisioner")},
        "LonghornNamespace": {"Name": longhorn["metadata"]["name"], "UID": longhorn["metadata"]["uid"]},
        "BoundPVCVolumeNames": pv_names,
    }, unconfirmed


def controller_deployment(definition, census):
    namespace = definition["Namespace"]
    node = census["Nodes"][0]["Name"]
    containers = [
        {
            "name": "controller",
            "image": definition["AppImage"],
            "command": ["/bin/sh", "-ec", LAUNCHER],
            "env": [
                {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                {"name": "K8S_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                {"name": "SYSTEM_BACKUP_ENABLED", "value": "false"},
                {"name": "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "value": "public-v1"},
                {"name": "CLAWMANAGER_LEADER_ELECTION", "value": "true"},
            ],
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [
                {"name": "inputs", "mountPath": RUNTIME_MOUNT, "readOnly": True},
                {"name": "staging", "mountPath": STAGING},
            ],
        },
        {
            "name": "installation-owner",
            "image": definition["AppImage"],
            "command": ["/bin/sh", "-ec", "umask 077; for d in " + RUNTIME + " " + PRIVATE + "; do if test ! -e \"$d\"; then mkdir -m 700 \"$d\"; fi; test ! -L \"$d\"; test \"$(stat -c %u:%a \"$d\")\" = 65532:700; done; while :; do sleep 3600; done"],
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [
                {"name": "inputs", "mountPath": RUNTIME_MOUNT},
                {"name": "private", "mountPath": PRIVATE_MOUNT},
            ],
        },
    ]
    pod_spec = {
        "serviceAccountName": definition["ControllerServiceAccount"],
        "automountServiceAccountToken": True,
        "nodeSelector": {"kubernetes.io/hostname": node},
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": containers,
        "volumes": [
            {"name": "inputs", "persistentVolumeClaim": {"claimName": definition["InputsClaim"]}},
            {"name": "staging", "persistentVolumeClaim": {"claimName": definition["StagingClaim"]}},
            {"name": "private", "persistentVolumeClaim": {"claimName": definition["PrivateClaim"]}},
        ],
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": definition["ControllerDeployment"], "annotations": {}},
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app.kubernetes.io/name": definition["ControllerDeployment"]}},
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": definition["ControllerDeployment"]}, "annotations": {}},
                "spec": pod_spec,
            },
        },
    }


def render_bootstrap(definition, plan_sha, census):
    namespace = definition["Namespace"]
    operation = definition["Operation"]
    objects = []

    def own(obj, key, value):
        obj["metadata"].setdefault("annotations", {})[key] = value
        return obj

    for account in (definition["ControllerServiceAccount"], definition["WorkerServiceAccount"], definition["SourcesServiceAccount"]):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account, "namespace": namespace}, "automountServiceAccountToken": False}
        objects.append(own(sa, PLAN_MARKER, plan_sha))

    def rbac(account, namespaced, cluster):
        if namespaced:
            role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": account, "namespace": namespace}, "rules": namespaced}
            objects.append(own(role, MARKER, operation))
            objects.append(own(role_binding("RoleBinding", account, namespace, account, {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": account}), MARKER, operation))
        if cluster:
            role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": account}, "rules": cluster}
            objects.append(own(role, MARKER, operation))
            objects.append(own(role_binding("ClusterRoleBinding", account, namespace, account, {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": account}), MARKER, operation))

    rbac(definition["ControllerServiceAccount"], definition["ControllerRules"], definition["ControllerClusterRules"])
    rbac(definition["WorkerServiceAccount"], definition["WorkerRules"], definition["WorkerClusterRules"])

    source_namespaced = []
    source_cluster = []
    for rule in definition["SourceRules"]:
        if rule["resources"] in (["namespaces"], ["nodes"], ["persistentvolumes"]):
            need("resourceNames" not in rule, "source_cluster_rule_must_not_prebind_resource_names")
            source_cluster.append(rule)
        else:
            source_namespaced.append(rule)
    source_account = definition["SourcesServiceAccount"]
    if source_namespaced:
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": source_account, "namespace": namespace}, "rules": source_namespaced}
        objects.append(own(role, MARKER, operation))
        objects.append(own(role_binding("RoleBinding", source_account, namespace, source_account, {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": source_account}), MARKER, operation))
    concrete = []
    for rule in source_cluster:
        if rule["resources"] == ["namespaces"]:
            concrete.append({**rule, "resourceNames": [namespace]})
        elif rule["resources"] == ["nodes"]:
            concrete.append({**rule, "resourceNames": [node["Name"] for node in census["Nodes"]]})
        elif census["BoundPVCVolumeNames"]:
            concrete.append({**rule, "resourceNames": list(census["BoundPVCVolumeNames"])})
    if concrete:
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": source_account}, "rules": concrete}
        objects.append(own(role, MARKER, operation))
        objects.append(own(role_binding("ClusterRoleBinding", source_account, namespace, source_account, {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": source_account}), MARKER, operation))

    objects.append(own(pvc(definition["InputsClaim"], "1Gi", "ReadWriteMany", definition["InputsStorageClass"]), MARKER, operation))
    objects.append(own(pvc(definition["StagingClaim"], definition["StagingSize"], "ReadWriteOnce", definition["StagingStorageClass"]), MARKER, operation))
    objects.append(own(pvc(definition["PrivateClaim"], definition["PrivateSize"], "ReadWriteOnce", definition["StagingStorageClass"]), MARKER, operation))

    deployment = own(controller_deployment(definition, census), MARKER, operation)
    deployment["spec"]["template"]["metadata"]["annotations"][MARKER] = operation
    objects.append(deployment)

    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": definition["ControlService"], "namespace": namespace},
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/name": definition["ControllerDeployment"]},
            "ports": [{"name": "control-mtls", "port": 9443, "targetPort": 9443, "protocol": "TCP"}],
        },
    }
    objects.append(own(service, MARKER, operation))
    for obj in objects:
        if obj["kind"] not in ("ClusterRole", "ClusterRoleBinding"):
            obj["metadata"].setdefault("namespace", namespace)
    return objects


def contains(actual, desired):
    """True when every desired field is present in actual. Lists are exact."""
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value) for key, value in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(contains(a, d) for a, d in zip(actual, desired))
    return actual == desired


def has_entries(actual, desired):
    """True when every desired entry is present somewhere in the actual list."""
    return isinstance(actual, list) and all(any(contains(item, want) for item in actual) for want in desired)


def ownership(definition, plan_sha):
    return {
        "ServiceAccount": (PLAN_MARKER, plan_sha),
        "Deployment": (MARKER, definition["Operation"]),
        "Service": (MARKER, definition["Operation"]),
        "PersistentVolumeClaim": (MARKER, definition["Operation"]),
        "Role": (MARKER, definition["Operation"]),
        "RoleBinding": (MARKER, definition["Operation"]),
        "ClusterRole": (MARKER, definition["Operation"]),
        "ClusterRoleBinding": (MARKER, definition["Operation"]),
    }


def classify_existing(kubectl, definition, plan_sha, obj, expected_uids):
    kind, name = obj["kind"], obj["metadata"]["name"]
    namespace = obj["metadata"].get("namespace")
    actual = kubectl.get(RESOURCES[kind], name, namespace)
    if actual is None:
        return "absent"
    key = kind + "/" + name
    if expected_uids and key in expected_uids:
        need(actual["metadata"].get("uid") == expected_uids[key], "existing_object_uid_drift:" + key)
    marker, value = ownership(definition, plan_sha)[kind]
    need((actual["metadata"].get("annotations") or {}).get(marker) == value, "existing_object_ownership_conflict:" + key)
    fields = {
        "ServiceAccount": ("automountServiceAccountToken",),
        "Deployment": ("spec",),
        "Service": ("spec",),
        "PersistentVolumeClaim": ("spec",),
        "Role": ("rules",),
        "ClusterRole": ("rules",),
        "RoleBinding": ("subjects", "roleRef"),
        "ClusterRoleBinding": ("subjects", "roleRef"),
    }[kind]
    need(all(contains(actual.get(field), obj.get(field)) for field in fields), "existing_object_spec_drift:" + key)
    return "owned_replay"


def check_kubeconfig(kubectl, plan):
    view = kubectl.config_view()
    need(len(view.get("clusters", [])) == 1, "one_kubeconfig_cluster_required")
    server = view["clusters"][0]["cluster"].get("server", "")
    parts = urlsplit(server)
    need(parts.scheme == "https" and parts.hostname and not parts.username and parts.path in ("", "/") and not parts.query and not parts.fragment, "kubeconfig_endpoint_shape")
    need(server.rstrip("/") == plan["KubernetesAPI"].rstrip("/"), "kubeconfig_endpoint_mismatch")
    return {"Server": server}


def preflight(kubectl, definition, census, unconfirmed, plan_sha, expected_uids=None):
    objects = render_bootstrap(definition, plan_sha, census)
    results = []
    for obj in objects:
        existing = classify_existing(kubectl, definition, plan_sha, obj, expected_uids)
        kubectl.apply_dry_run(obj, definition["Namespace"])
        results.append({
            "Kind": obj["kind"],
            "Name": obj["metadata"]["name"],
            "Namespace": obj["metadata"].get("namespace", ""),
            "Existing": existing,
            "DryRun": "server_admitted",
        })
    # A finite source ClusterRole must not silently omit PV resource names.
    source_cluster = [r for r in definition["SourceRules"] if "persistentvolumes" in r["resources"]]
    if source_cluster and not census["BoundPVCVolumeNames"]:
        unconfirmed.append("source_cluster_pv_resource_names_required")
    return results


def observe(kubectl, plan, definition, expected_uids=None):
    namespace = definition["Namespace"]
    deployment = kubectl.get("deployment", definition["ControllerDeployment"], namespace)
    need(deployment is not None and deployment["metadata"].get("uid"), "observe_deployment_absent")
    need(deployment["spec"]["template"]["spec"].get("serviceAccountName") == definition["ControllerServiceAccount"], "observe_controller_account_mismatch")
    containers = {c["name"]: c for c in deployment["spec"]["template"]["spec"].get("containers", [])}
    need(set(containers) == {"controller", "installation-owner"}, "observe_controller_containers")
    need(has_entries(containers["controller"].get("env"), [{"name": "SYSTEM_BACKUP_ENABLED", "value": "false"}]), "observe_controller_enabled")
    need(has_entries(containers["controller"].get("env"), [{"name": "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "value": "public-v1"}]), "observe_controller_protocol")
    need(has_entries(containers["controller"].get("env"), [{"name": "CLAWMANAGER_LEADER_ELECTION", "value": "true"}]), "observe_controller_leader_election")
    need(containers["controller"]["command"][-1] == LAUNCHER, "observe_controller_launcher")
    for name in ("inputs", "staging", "private"):
        need(any(volume["name"] == name for volume in deployment["spec"]["template"]["spec"].get("volumes", [])), "observe_volume_absent:" + name)

    pods = deployment_pods(kubectl, namespace, deployment)
    need(len(pods) == 1, "observe_single_running_pod_required")
    pod = pods[0]
    need(pod.get("status", {}).get("phase") == "Running", "observe_pod_not_running")
    refs = pod["metadata"].get("ownerReferences") or []
    need(len(refs) == 1 and refs[0].get("kind") == "ReplicaSet" and refs[0].get("uid"), "observe_pod_replicaset_owner")
    rs = kubectl.get("replicaset", refs[0]["name"], namespace)
    need(rs is not None and rs["metadata"].get("uid") == refs[0]["uid"], "observe_pod_replicaset_identity")
    need(any(owner.get("uid") == deployment["metadata"]["uid"] for owner in rs["metadata"].get("ownerReferences", [])), "observe_replicaset_deployment_owner")
    need(not rs["metadata"].get("deletionTimestamp"), "observe_replicaset_deleting")
    need(pod["spec"].get("serviceAccountName") == definition["ControllerServiceAccount"], "observe_pod_account_mismatch")
    states = {state.get("name"): state for state in pod.get("status", {}).get("containerStatuses", [])}
    need(set(states) == {"controller", "installation-owner"}, "observe_pod_containers")
    # The bootstrap controller intentionally waits for controller.env.ready, so
    # it is Running but not Ready until the owner delivers the final literal
    # environment. The installation-owner container must be Ready now.
    need("running" in states["installation-owner"].get("state", {}) and states["installation-owner"].get("ready"), "observe_installation_owner_not_ready")
    need("running" in states["controller"].get("state", {}), "observe_controller_not_running")
    account = kubectl.get("serviceaccount", pod["spec"].get("serviceAccountName"), namespace)
    need(account is not None and account["metadata"].get("uid"), "observe_service_account_absent")

    claims = {}
    for name in (definition["InputsClaim"], definition["StagingClaim"], definition["PrivateClaim"]):
        claim = kubectl.get("persistentvolumeclaim", name, namespace)
        need(claim is not None and claim["metadata"].get("uid"), "observe_claim_absent:" + name)
        need(not claim["metadata"].get("deletionTimestamp"), "observe_claim_deleting:" + name)
        claims[name] = claim["metadata"]["uid"]

    chain = {
        "NamespaceUID": plan["Target"]["NamespaceUID"],
        "ServiceAccount": account["metadata"]["name"],
        "ServiceAccountUID": account["metadata"]["uid"],
        "Deployment": deployment["metadata"]["name"],
        "DeploymentUID": deployment["metadata"]["uid"],
        "DeploymentSpecSHA256": sha256(canonical(deployment["spec"])),
        "ReplicaSet": rs["metadata"]["name"],
        "ReplicaSetUID": rs["metadata"]["uid"],
        "Pod": pod["metadata"]["name"],
        "PodUID": pod["metadata"]["uid"],
        "PodSpecSHA256": sha256(canonical(pod["spec"])),
        "PVC": claims,
        "Containers": {name: {"ContainerID": state.get("containerID"), "ImageID": state.get("imageID")} for name, state in states.items()},
    }
    if expected_uids:
        for key, value in expected_uids.items():
            if key.startswith("Deployment/"):
                need(chain["DeploymentUID"] == value, "observe_deployment_uid_drift")
    need(all(state.get("imageID") for state in states.values()), "observe_image_ids_required")
    return chain


def write_private_report(directory, name, value):
    path = Path(directory)
    # The operator creates the private output directory (umask 077) before the
    # run; this action never creates parents or widens an existing directory.
    need(path.is_dir(), "output_directory_required")
    need(stat_private(path), "output_directory_private")
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode() + b"\n"
    target = path / name
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise Refused("report_already_exists:" + str(name))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    return str(target), sha256(raw)


def stat_private(path):
    if os.name == "nt":
        # Windows ACLs, not POSIX mode bits, carry the private boundary.
        return path.is_dir()
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return False
    return mode & 0o077 == 0


def main(argv, runner=None, filereader=None, reportwriter=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("preflight", "observe"), default="preflight")
    parser.add_argument("--plan-file", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--issuer-public-file")
    parser.add_argument("--issuer-public-sha256")
    parser.add_argument("--enrollment-pin-file", required=True)
    parser.add_argument("--enrollment-pin-sha256", required=True)
    parser.add_argument("--kubeconfig-file", required=True)
    parser.add_argument("--kubeconfig-sha256", required=True)
    parser.add_argument("--definition-file", required=True)
    parser.add_argument("--definition-sha256", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--context")
    args = parser.parse_args(argv)

    read = filereader or (lambda path, limit=4 << 20: read_file(path, limit))
    write_report = reportwriter or write_private_report

    plan_raw = pinned(read, args.plan_file, args.plan_sha256)
    plan = load_plan(plan_raw)
    definition = load_definition(pinned(read, args.definition_file, args.definition_sha256))
    pin_raw = pinned(read, args.enrollment_pin_file, args.enrollment_pin_sha256, 16384)
    try:
        pin = json.loads(pin_raw)
    except ValueError:
        raise Refused("enrollment_pin_not_json")
    issuer = None
    if args.issuer_public_file or args.issuer_public_sha256:
        need(args.issuer_public_file and args.issuer_public_sha256, "issuer_public_pin_pair")
        raw = pinned(read, args.issuer_public_file, args.issuer_public_sha256, 32)
        need(len(raw) == 32, "issuer_public_size")
        issuer = raw
    pinned(read, args.kubeconfig_file, args.kubeconfig_sha256)

    kubectl = Kubectl(args.kubeconfig_file, args.context, runner=runner)
    enrollment = verify_enrollment(kubectl, plan, pin, issuer)
    target = verify_target(kubectl, plan, definition)
    kube = check_kubeconfig(kubectl, plan)

    sources = {
        "Plan": {"File": str(Path(args.plan_file).resolve()), "SHA256": args.plan_sha256},
        "Definition": {"File": str(Path(args.definition_file).resolve()), "SHA256": args.definition_sha256},
        "EnrollmentPin": {"File": str(Path(args.enrollment_pin_file).resolve()), "SHA256": args.enrollment_pin_sha256},
        "Kubeconfig": {"File": str(Path(args.kubeconfig_file).resolve()), "SHA256": args.kubeconfig_sha256},
        "IssuerPublic": None if issuer is None else {"File": str(Path(args.issuer_public_file).resolve()), "SHA256": args.issuer_public_sha256},
    }
    base = {
        "version": VERSION,
        "mode": args.mode,
        "operation": definition["Operation"],
        "plan": {"InstallationID": plan["Target"]["InstallationID"], "Namespace": plan["Target"]["Namespace"], "NamespaceUID": plan["Target"]["NamespaceUID"], "ClusterID": plan["Target"]["ClusterID"], "ServerUUID": plan["Target"]["ServerUUID"], "Database": plan["Target"]["Database"]},
        "enrollment": enrollment,
        "target": target,
        "kube": kube,
        "sources": sources,
        "created": False,
        "configuration_enabled": False,
        "backup_enabled": False,
        "pending": [
            "sql_control_and_source_identity_readback",
            "source_api_bound_token_and_tokenreview",
            "observer_mtls_handshake",
            "final_config_certificate_and_grant_binding_to_uid_chain",
        ],
    }

    if args.mode == "observe":
        chain = observe(kubectl, plan, definition)
        base.update({"state": "bootstrap_identity_chain_observed_not_yet_authorized", "uid_chain": chain, "unconfirmed": [], "objects": []})
        name = "bootstrap-identity.result.json"
    else:
        census = {"app": None, "platform": None, "runtime": None}
        app, app_unconfirmed = census_app(kubectl, definition)
        platform, platform_unconfirmed = census_platform(kubectl, definition)
        runtime, runtime_unconfirmed = census_runtime(kubectl, definition)
        census["app"], census["platform"], census["runtime"] = app, platform, runtime
        unconfirmed = [*app_unconfirmed, *platform_unconfirmed, *runtime_unconfirmed]
        if issuer is None:
            unconfirmed.append("issuer_public_pin_required")
        if not definition["ControllerRules"] and not definition["ControllerClusterRules"]:
            unconfirmed.append("controller_rbac_rules_required")
        if not definition["WorkerRules"] and not definition["WorkerClusterRules"]:
            unconfirmed.append("worker_rbac_rules_required")
        results = preflight(kubectl, definition, platform, unconfirmed, args.plan_sha256)
        base.update({
            "state": "read_only_preflight_and_server_dry_run_passed" if not unconfirmed else "read_only_preflight_passed_with_unconfirmed_items",
            "census": census,
            "objects": results,
            "unconfirmed": sorted(set(unconfirmed)),
            "uid_chain": None,
            "next": "apply the reviewed bootstrap template, then run --mode observe to record the real UID chain",
        })
        name = "bootstrap-preflight.result.json"

    path, digest = write_report(args.output_directory, name, base)
    print(json.dumps({"Report": {"File": path, "SHA256": digest}, "State": base["state"], "Unconfirmed": base["unconfirmed"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refused as error:
        print(json.dumps({"state": "refused", "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
