#!/usr/bin/env python3
"""Operator-run persistent Vault installation. Never run by the coding agent.

Root/unseal/TLS private material stays in an operator-owned 0700 directory.
No root/unseal token is put in a Pod, Kubernetes Secret, argv, log or report.
Only installation-owned named resources in the fixed namespace are mutable.
The JWT smoke is infrastructure evidence, not production task admission.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONTEXT = "kubernetes-admin@kubernetes"
NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
IMAGE = None  # Mandatory verified image input; never inherit the image's dev CMD.
IMAGE_DIGESTS = set()
LABEL = "backup.clawmanager.io/transit-install"
AUDIENCE = "clawmanager-backup-worker"
CLI = "/bin/vault"
VERSION = None
NODES = {"k8s-master": "bc1fb478-0388-4f53-96b4-8d186301f6af", "node1": "fe1cc275-6fa1-484e-8bf6-7b21193daffd"}
UUID = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
PHASE = "arguments"


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def run(argv, data=None, timeout=40, allowed=(0,)):
    try:
        result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("tool_unavailable_or_timeout") from None
    require(result.returncode in allowed and len(result.stdout) <= 2097152, "tool_failed_or_output_limit")
    return result.stdout


def kube(*args, data=None, timeout=40):
    return run(["kubectl", "--context=" + CONTEXT, "--request-timeout=25s", *args], data, timeout)


def get(resource, name):
    raw = kube("-n", NAMESPACE, "get", resource, name, "--ignore-not-found", "-o", "json")
    return json.loads(raw) if raw.strip() else None


def guard():
    item = json.loads(kube("get", "namespace", NAMESPACE, "-o", "json"))
    meta = item.get("metadata", {})
    require(item.get("kind") == "Namespace" and item.get("apiVersion") == "v1" and meta.get("name") == NAMESPACE and meta.get("uid") == NAMESPACE_UID and not meta.get("deletionTimestamp"), "namespace_identity_changed")


class Owner:
    def __init__(self, directory, new=False):
        require(os.name == "posix" and directory.is_absolute(), "linux_absolute_private_directory_required")
        self.directory = directory
        if new:
            require(not directory.exists() and not directory.is_symlink(), "new_private_directory_required")
            directory.mkdir(mode=0o700)  # Parent is chosen/owned by the operator.
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "private_directory_ownership_or_mode")
        self.state = None if new else self.read("state.json")

    def write(self, name, value, replace=False):
        require(re.fullmatch(r"[a-z0-9_.-]{1,100}", name), "private_file_name")
        path = self.directory / name
        raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        target = self.directory / (name + ".new-" + secrets.token_hex(4)) if replace else path
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            require(path.is_file() and not path.is_symlink(), "original_private_file_missing")
            os.replace(target, path)
        return path

    def read(self, name, json_value=True):
        path = self.directory / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 2097152, "private_file_ownership_or_mode")
            raw = stream.read(2097153)
        return json.loads(raw) if json_value else raw

    def save(self):
        self.write("state.json", self.state, replace=(self.directory / "state.json").exists())

    def create(self, obj, resource):
        guard()
        name = obj["metadata"]["name"]
        require(name.startswith(self.state["prefix"]), "resource_outside_install_prefix")
        key = resource + "/" + name
        known = self.state["resources"].get(key)
        if known:
            actual = get(resource, name)
            if actual is None and name.startswith(self.state["prefix"] + "-smoke-"):
                del self.state["resources"][key]
                self.save()
                known = None
            else:
                require(actual and actual["metadata"]["uid"] == known and actual["metadata"].get("labels", {}).get(LABEL) == self.state["run"], "owned_resource_identity_changed")
                return actual
        require(get(resource, name) is None, "resource_name_already_exists")
        require(self.state.get("pending") is None, "original_operation_unknown_do_not_retry")
        obj["metadata"].setdefault("labels", {})[LABEL] = self.state["run"]
        obj["metadata"]["namespace"] = NAMESPACE
        self.state["pending"] = "create/" + key
        self.save()
        raw = kube("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", data=json.dumps(obj).encode())
        uid = raw.decode().strip()
        require(UUID.fullmatch(uid), "created_uid_missing")
        self.state["resources"][key] = uid
        self.state["pending"] = None
        self.save()
        return get(resource, name)

    def delete(self, resource, name, group="api/v1"):
        guard()
        key = resource + "/" + name
        uid = self.state["resources"].get(key)
        require(uid is not None, "deletion_not_owned")
        actual = get(resource, name)
        if actual is None:
            return
        require(actual["metadata"]["uid"] == uid and actual["metadata"].get("labels", {}).get(LABEL) == self.state["run"], "deletion_uid_or_owner_changed")
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"}
        # --raw -f - sends this exact UID precondition in the DELETE body.
        kube("delete", "--raw=/" + group + "/namespaces/" + NAMESPACE + "/" + resource + "/" + name, "-f", "-", data=json.dumps(options).encode())


def certificate(owner):
    prefix = owner.state["prefix"]
    dns = prefix + "." + NAMESPACE + ".svc"
    ca_key = owner.directory / "ca-key.pem"
    ca = owner.directory / "ca.pem"
    key = owner.directory / "server-key.pem"
    csr = owner.directory / "server.csr"
    cert = owner.directory / "server.pem"
    for path in (ca_key, ca, key, csr, cert):
        require(not path.exists(), "tls_material_already_exists")
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "365", "-subj", "/CN=" + prefix + "-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca)], timeout=90)
    run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=" + dns, "-keyout", str(key), "-out", str(csr)], timeout=90)
    extension = owner.write("server-ext.txt", ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + dns + ",DNS:" + dns + ".cluster.local,DNS:localhost,IP:127.0.0.1\n").encode())
    run(["openssl", "x509", "-req", "-sha256", "-days", "365", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-set_serial", str(int(secrets.token_hex(16), 16)), "-extfile", str(extension), "-out", str(cert)])
    for path in (ca_key, ca, key, csr, cert):
        os.chmod(path, 0o600)
    run(["openssl", "verify", "-CAfile", str(ca), "-verify_hostname", dns, str(cert)])


def provider_data_initializer():
    # Vault opens its FSM before creating the configured Raft directory.
    # The Pod's original non-root UID/GID/fsGroup applies to this container.
    return {"name": "prepare-raft-directory", "image": IMAGE, "imagePullPolicy": "Never", "command": ["/bin/sh", "-ec", "umask 077; mkdir -p /data/raft; test -d /data/raft; test -w /data/raft"], "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}, "resources": {"requests": {"cpu": "25m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}}, "volumeMounts": [{"name": "data", "mountPath": "/data"}]}


def manifests(owner, storage_class):
    name = owner.state["prefix"]
    server = name + "." + NAMESPACE + ".svc"
    config = {"ui": False, "disable_mlock": True, "api_addr": "https://" + server + ":8200", "cluster_addr": "https://127.0.0.1:8201", "storage": {"raft": {"path": "/data/raft", "node_id": name}}, "listener": {"tcp": {"address": "0.0.0.0:8200", "cluster_address": "0.0.0.0:8201", "tls_cert_file": "/tls/server.pem", "tls_key_file": "/tls/server-key.pem", "tls_min_version": "tls12"}}}
    labels = {LABEL: owner.state["run"], "app.kubernetes.io/name": name}
    pod = {"nodeName": owner.state["node"], "serviceAccountName": name, "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "vault", "image": IMAGE, "imagePullPolicy": "Never", "command": [CLI, "server", "-config=/config/server.json"], "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}, "ports": [{"name": "https", "containerPort": 8200}], "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}}, "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "tls", "mountPath": "/tls", "readOnly": True}, {"name": "config", "mountPath": "/config", "readOnly": True}, {"name": "tmp", "mountPath": "/tmp"}], "readinessProbe": {"exec": {"command": [CLI, "status", "-address=https://127.0.0.1:8200", "-ca-cert=/tls/ca.pem"]}, "periodSeconds": 5, "timeoutSeconds": 3}, "livenessProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 10, "initialDelaySeconds": 20}}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": name + "-data"}}, {"name": "tls", "secret": {"secretName": name + "-tls", "defaultMode": 0o440}}, {"name": "config", "configMap": {"name": name + "-config"}}, {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}}]}
    pod["initContainers"] = [provider_data_initializer()]
    return [
        ("serviceaccounts", {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}, "automountServiceAccountToken": False}),
        ("persistentvolumeclaims", {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name + "-data"}, "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": storage_class, "resources": {"requests": {"storage": "2Gi"}}}}),
        ("secrets", {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name + "-tls"}, "immutable": True, "type": "Opaque", "data": {key: base64.b64encode(owner.read(key, False)).decode() for key in ("ca.pem", "server-key.pem", "server.pem")}}),
        ("configmaps", {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name + "-config"}, "immutable": True, "data": {"server.json": json.dumps(config)}}),
        ("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": {"type": "ClusterIP", "selector": labels, "ports": [{"name": "https", "port": 8200, "targetPort": "https"}]}}),
        ("networkpolicies", {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name}, "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"], "ingress": [{"from": [{"podSelector": {}}], "ports": [{"protocol": "TCP", "port": 8200}]}], "egress": []}}),
        ("deployments", {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name}, "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": pod}}}),
    ]


def provider_pod(owner, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guard()
        obj = json.loads(kube("-n", NAMESPACE, "get", "pods", "-l", LABEL + "=" + owner.state["run"], "-o", "json"))
        candidates = [item for item in obj.get("items", []) if item.get("metadata", {}).get("name", "").startswith(owner.state["prefix"] + "-") and any(c.get("name") == "vault" for c in item.get("spec", {}).get("containers", [])) and not item.get("metadata", {}).get("deletionTimestamp")]
        require(len(candidates) <= 1, "provider_pod_ambiguous")
        if candidates:
            pod = candidates[0]
            statuses = [c for c in pod.get("status", {}).get("containerStatuses", []) if c.get("name") == "vault"]
            if len(statuses) == 1 and "running" in statuses[0].get("state", {}):
                require(any(statuses[0].get("imageID", "").endswith(digest) for digest in IMAGE_DIGESTS), "running_image_digest_mismatch")
                return pod
        time.sleep(2)
    raise Refused("provider_start_timeout_pvc_or_image")


class API:
    def __init__(self, owner):
        self.owner = owner
        pod = provider_pod(owner)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.process = subprocess.Popen(["kubectl", "--context=" + CONTEXT, "--request-timeout=25s", "-n", NAMESPACE, "port-forward", "--address=127.0.0.1", "pod/" + pod["metadata"]["name"], str(self.port) + ":8200"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.create_default_context(cafile=str(owner.directory / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        for _ in range(30):
            require(self.process.poll() is None, "port_forward_exited")
            try:
                initial = self.call("GET", "sys/seal-status")
                require(initial.get("version") == VERSION, "provider_binary_version_mismatch")
                return
            except Refused:
                time.sleep(0.5)
        self.close()
        raise Refused("provider_tls_or_forward_timeout")

    def close(self):
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def call(self, method, path, body=None, token=None, expected=(200, 204)):
        require(re.fullmatch(r"[A-Za-z0-9_./-]{1,256}", path) and ".." not in path, "provider_path")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request("https://127.0.0.1:" + str(self.port) + "/v1/" + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                status, raw = response.status, response.read(1048577)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(1048577)
        except Exception:
            raise Refused("provider_tls_or_transport_unknown") from None
        require(status in expected and len(raw) <= 1048576, "provider_http_or_output_rejected")
        return json.loads(raw) if raw.strip() else {}


def der_length(value):
    return bytes([value]) if value < 128 else bytes([0x80 | ((value.bit_length() + 7) // 8)]) + value.to_bytes((value.bit_length() + 7) // 8, "big")


def der(tag, data):
    return bytes([tag]) + der_length(len(data)) + data


def public_keys():
    discovery = json.loads(kube("get", "--raw=/.well-known/openid-configuration"))
    jwks = json.loads(kube("get", "--raw=/openid/v1/jwks"))
    require(type(discovery.get("issuer")) is str and discovery["issuer"].startswith("https://") and 1 <= len(jwks.get("keys", [])) <= 16, "kubernetes_public_jwt_material_missing")
    require(discovery["issuer"] == "https://kubernetes.default.svc.cluster.local" and hashlib.sha256(json.dumps(jwks, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == "578fa8fb65ec23d3b3ff2319a87ff58e97aa36975895da91dc31d25120847ec4", "original_jwt_issuer_or_jwks_changed")
    result = []
    for key in jwks["keys"]:
        require(key.get("kty") == "RSA" and key.get("alg", "RS256") == "RS256", "jwt_rsa_rs256_required")
        integers = []
        for name in ("n", "e"):
            raw = base64.urlsafe_b64decode(key[name] + "=" * (-len(key[name]) % 4)).lstrip(b"\0")
            require(raw, "invalid_public_jwk")
            integers.append(der(2, (b"\0" if raw[0] & 0x80 else b"") + raw))
        pkcs1 = der(0x30, b"".join(integers))
        spki = der(0x30, bytes.fromhex("300d06092a864886f70d0101010500") + der(3, b"\0" + pkcs1))
        encoded = base64.b64encode(spki).decode()
        result.append("-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + "\n-----END PUBLIC KEY-----\n")
    return discovery["issuer"], result


def initialize(owner, api):
    status = api.call("GET", "sys/init")
    require(not status.get("initialized"), "already_initialized_never_reinitialize")
    owner.state["pending"] = "provider-init"
    owner.save()
    material = api.call("POST", "sys/init", {"secret_shares": 3, "secret_threshold": 2})
    require(len(material.get("keys_base64", [])) == 3 and material.get("root_token"), "initialization_material_shape")
    owner.write("init-material.json", material)
    owner.state["pending"] = None
    owner.save()
    unseal(owner, api)


def unseal(owner, api):
    material = owner.read("init-material.json")
    for key in material["keys_base64"][:2]:
        status = api.call("GET", "sys/seal-status")
        if not status.get("sealed"):
            break
        api.call("POST", "sys/unseal", {"key": key})
    status = api.call("GET", "sys/seal-status")
    require(status.get("sealed") is False and status.get("cluster_id"), "unseal_not_confirmed")
    if owner.state.get("cluster_id"):
        require(status["cluster_id"] == owner.state["cluster_id"], "provider_cluster_identity_changed")
    owner.state["cluster_id"] = status["cluster_id"]
    owner.save()


def configure(owner, api):
    root = owner.read("init-material.json")["root_token"]
    name = owner.state["prefix"]
    api.call("POST", "sys/audit/" + name, {"type": "file", "options": {"file_path": "/data/audit.jsonl", "log_raw": "false"}}, root)
    api.call("POST", "sys/mounts/transit", {"type": "transit"}, root)
    api.call("POST", "transit/keys/" + name + "-kek", {"type": "aes256-gcm96", "derived": True, "exportable": False, "allow_plaintext_backup": False}, root)
    signing = {}
    for purpose in ("capture", "acceptance", "catalog"):
        key = name + "-" + purpose
        api.call("POST", "transit/keys/" + key, {"type": "ed25519", "exportable": False, "allow_plaintext_backup": False}, root)
        value = api.call("GET", "transit/keys/" + key, token=root)["data"]
        signing[purpose] = {"key_name": key, "provider_version": "1", "public_key": value["keys"]["1"]["public_key"]}
    issuer, keys = public_keys()
    mount = name + "-jwt"
    api.call("POST", "sys/auth/" + mount, {"type": "jwt"}, root)
    api.call("POST", "auth/" + mount + "/config", {"jwt_validation_pubkeys": keys, "bound_issuer": issuer, "jwt_supported_algs": ["RS256"]}, root)
    owner.state["jwt_mount"], owner.state["jwt_issuer"] = mount, issuer
    owner.state["signing"] = signing
    owner.state["configured"] = True
    owner.save()


def bind_identity(owner, api, action, pod, sa, context64):
    root = owner.read("init-material.json")["root_token"]
    sa_obj, pod_obj = get("serviceaccounts", sa), get("pods", pod)
    require(sa_obj and pod_obj and pod_obj["spec"].get("serviceAccountName") == sa and pod_obj["metadata"].get("labels", {}).get(LABEL) == owner.state["run"], "smoke_workload_identity_changed")
    name = owner.state["prefix"] + "-" + action
    key = owner.state["prefix"] + "-kek"
    parameters = {"context": [context64]}
    path = "transit/datakey/plaintext/" + key if action == "generate" else "transit/decrypt/" + key
    if action == "generate":
        parameters.update({"bits": ["256"], "key_version": ["1"]})
    else:
        parameters["ciphertext"] = ["vault:v1:*"]
    policy = json.dumps({"path": {path: {"capabilities": ["update"], "allowed_parameters": parameters}}})
    api.call("PUT", "sys/policies/acl/" + name, {"policy": policy}, root)
    claims = {"/kubernetes.io/namespace": NAMESPACE, "/kubernetes.io/serviceaccount/uid": sa_obj["metadata"]["uid"], "/kubernetes.io/pod/uid": pod_obj["metadata"]["uid"]}
    api.call("POST", "auth/" + owner.state["jwt_mount"] + "/role/" + name, {"role_type": "jwt", "bound_audiences": [AUDIENCE], "bound_subject": "system:serviceaccount:" + NAMESPACE + ":" + sa, "bound_claims": claims, "claim_mappings": {key: value for key, value in zip(claims, ("namespace", "service_account_uid", "pod_uid"))}, "user_claim": "sub", "token_type": "batch", "token_no_default_policy": True, "token_policies": [name], "token_ttl": "20s", "token_max_ttl": "20s", "token_explicit_max_ttl": "20s", "clock_skew_leeway": -1, "expiration_leeway": -1, "not_before_leeway": -1}, root)
    jwt = kube("-n", NAMESPACE, "create", "token", sa, "--audience=" + AUDIENCE, "--duration=600s", "--bound-object-kind=Pod", "--bound-object-name=" + pod, "--bound-object-uid=" + pod_obj["metadata"]["uid"]).decode().strip()
    result = api.call("POST", "auth/" + owner.state["jwt_mount"] + "/login", {"role": name, "jwt": jwt})["auth"]
    require(result.get("token_type") == "batch" and result.get("renewable") is False and result.get("policies") == [name] and 1 <= result.get("lease_duration", 0) <= 20, "jwt_token_profile_rejected")
    metadata = result.get("metadata", {})
    require(all(metadata.get(key) == value for key, value in {"role": name, "namespace": NAMESPACE, "service_account_uid": sa_obj["metadata"]["uid"], "pod_uid": pod_obj["metadata"]["uid"]}.items()), "jwt_identity_metadata_rejected")
    return result["client_token"]


def smoke(owner, api):
    name = owner.state["prefix"]
    created = []
    try:
        smoke_config = {"ui": False, "disable_mlock": True, "api_addr": "https://127.0.0.1:8200", "storage": {"inmem": {}}, "listener": {"tcp": {"address": "127.0.0.1:8200", "tls_cert_file": "/tls/server.pem", "tls_key_file": "/tls/server-key.pem"}}}
        owner.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name + "-smoke-config"}, "immutable": True, "data": {"server.json": json.dumps(smoke_config)}}, "configmaps")
        for action in ("generate", "unwrap"):
            sa, pod = name + "-smoke-" + action, name + "-smoke-" + action
            owner.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}, "automountServiceAccountToken": False}, "serviceaccounts")
            owner.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod}, "spec": {"nodeName": owner.state["node"], "serviceAccountName": sa, "automountServiceAccountToken": False, "restartPolicy": "Never", "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "smoke", "image": IMAGE, "imagePullPolicy": "Never", "command": [CLI, "server", "-config=/config/server.json"], "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}, "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True}, {"name": "tls", "mountPath": "/tls", "readOnly": True}, {"name": "tmp", "mountPath": "/tmp"}], "resources": {"requests": {"cpu": "25m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}}}], "volumes": [{"name": "config", "configMap": {"name": name + "-smoke-config"}}, {"name": "tls", "secret": {"secretName": name + "-tls", "defaultMode": 0o440}}, {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}]}}, "pods")
            created.append((sa, pod))
            kube("-n", NAMESPACE, "wait", "pod/" + pod, "--for=condition=Ready", "--timeout=120s", timeout=130)
        context64 = base64.b64encode(("clawmanager.transit.bootstrap-smoke.v1\x00" + owner.state["run"]).encode()).decode()
        generate = bind_identity(owner, api, "generate", created[0][1], created[0][0], context64)
        unwrap = bind_identity(owner, api, "unwrap", created[1][1], created[1][0], context64)
        key = name + "-kek"
        if (owner.directory / "persistence-check.json").exists():
            original = owner.read("persistence-check.json")
            old_plain = api.call("POST", "transit/decrypt/" + key, {"context": original["context"], "ciphertext": original["ciphertext"]}, unwrap)["data"]["plaintext"]
            require(hashlib.sha256(base64.b64decode(old_plain, validate=True)).hexdigest() == original["plaintext_sha256"], "original_persisted_ciphertext_did_not_unwrap")
            owner.state["original_ciphertext_readback_passed"] = True
        wrapped = api.call("POST", "transit/datakey/plaintext/" + key, {"context": context64, "bits": "256", "key_version": "1"}, generate)["data"]
        require(len(base64.b64decode(wrapped["plaintext"], validate=True)) == 32 and wrapped["ciphertext"].startswith("vault:v1:"), "real_datakey_shape")
        opened = api.call("POST", "transit/decrypt/" + key, {"context": context64, "ciphertext": wrapped["ciphertext"]}, unwrap)["data"]
        require(opened["plaintext"] == wrapped["plaintext"], "real_unwrap_mismatch")
        if not (owner.directory / "persistence-check.json").exists():
            owner.write("persistence-check.json", {"context": context64, "ciphertext": wrapped["ciphertext"], "plaintext_sha256": hashlib.sha256(base64.b64decode(wrapped["plaintext"], validate=True)).hexdigest()})
        api.call("POST", "transit/decrypt/" + key, {"context": context64, "ciphertext": wrapped["ciphertext"]}, generate, expected=(403,))
        api.call("POST", "transit/datakey/plaintext/" + key, {"context": context64, "bits": "256", "key_version": "1"}, unwrap, expected=(403,))
        api.call("POST", "transit/decrypt/" + key, {"context": base64.b64encode(b"wrong-context").decode(), "ciphertext": wrapped["ciphertext"]}, unwrap, expected=(400, 403))
        owner.state["jwt_smoke_passed"] = True
        owner.save()
    finally:
        cleanup_failed = False
        root = owner.read("init-material.json")["root_token"]
        for action in ("generate", "unwrap"):
            scoped = name + "-" + action
            try:
                api.call("DELETE", "auth/" + owner.state["jwt_mount"] + "/role/" + scoped, token=root, expected=(204,))
                api.call("DELETE", "sys/policies/acl/" + scoped, token=root, expected=(204,))
            except Exception:
                cleanup_failed = True
        for sa, pod in reversed(created):
            try:
                owner.delete("pods", pod)
                kube("-n", NAMESPACE, "wait", "--for=delete", "pod/" + pod, "--timeout=60s", timeout=70)
                owner.delete("serviceaccounts", sa)
            except Exception:
                cleanup_failed = True
        try:
            owner.delete("configmaps", name + "-smoke-config")
        except Exception:
            cleanup_failed = True
        require(not cleanup_failed, "owned_smoke_cleanup_incomplete")


def pvc_binding(owner):
    name = owner.state["prefix"] + "-data"
    claim = get("persistentvolumeclaims", name)
    require(claim and claim["metadata"]["uid"] == owner.state["resources"]["persistentvolumeclaims/" + name] and claim.get("status", {}).get("phase") == "Bound" and claim["spec"].get("storageClassName") == owner.state["storage_class"], "owned_data_claim_not_bound")
    pv = get("persistentvolumes", claim["spec"]["volumeName"])
    ref = pv.get("spec", {}).get("claimRef", {}) if pv else {}
    require(pv and not pv["metadata"].get("deletionTimestamp") and ref.get("uid") == claim["metadata"]["uid"] and ref.get("name") == name and ref.get("namespace") == NAMESPACE, "owned_data_pv_binding_changed")
    binding = {"claim_uid": claim["metadata"]["uid"], "pv": pv["metadata"]["name"], "pv_uid": pv["metadata"]["uid"], "pv_spec_sha256": hashlib.sha256(json.dumps(pv["spec"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    if owner.state.get("pvc_binding"):
        require(owner.state["pvc_binding"] == binding, "original_persistent_volume_changed")
    else:
        owner.state["pvc_binding"] = binding
        owner.save()


def persistence(owner, api):
    name = owner.state["prefix"]
    pvc_binding(owner)
    old = provider_pod(owner)
    uid = owner.state["resources"]["deployments/" + name]
    owner.state["persistence_restart_started"] = True
    owner.save()
    for replicas in (0, 1):
        guard()
        patch = [{"op": "test", "path": "/metadata/uid", "value": uid}, {"op": "replace", "path": "/spec/replicas", "value": replicas}]
        kube("-n", NAMESPACE, "patch", "deployment", name, "--type=json", "-p", json.dumps(patch))
        if replicas == 0:
            kube("-n", NAMESPACE, "wait", "--for=delete", "pod/" + old["metadata"]["name"], "--timeout=120s", timeout=130)
            api.close()
    restarted = API(owner)
    try:
        current = provider_pod(owner)
        require(current["metadata"]["uid"] != old["metadata"]["uid"], "provider_restart_not_observed")
        unseal(owner, restarted)
        pvc_binding(owner)
        root = owner.read("init-material.json")["root_token"]
        for original in owner.state["signing"].values():
            actual = restarted.call("GET", "transit/keys/" + original["key_name"], token=root)["data"]
            require(actual["keys"]["1"]["public_key"] == original["public_key"], "original_signing_key_changed_after_restart")
        smoke(owner, restarted)
        require(owner.state.get("original_ciphertext_readback_passed"), "persistent_ciphertext_readback_missing")
        owner.state["persistence_restart_verified"] = True
        owner.save()
        return restarted
    except BaseException:
        restarted.close()
        raise


def resume_install_owner(owner):
    """Authenticate this exact pre-initialization install; never adopt or create."""
    state = owner.state
    require(state.get("schema_version") == "d-transit-owned-install.v1" and state.get("context") == CONTEXT and state.get("namespace") == NAMESPACE and state.get("namespace_uid") == NAMESPACE_UID and state.get("pending") is None, "original_install_state_unknown")
    require(re.fullmatch(r"[a-f0-9]{16}", state.get("run", "")) and state.get("prefix") == "sbk-transit-zh-" + state["run"][:8], "original_install_owner_changed")
    require(not (owner.directory / "init-material.json").exists() and not (owner.directory / "init-material.json").is_symlink() and not state.get("cluster_id") and not state.get("configured") and not state.get("jwt_mount"), "initialization_already_started_do_not_repeat")
    require(state.get("node") in NODES and state.get("node_uid") == NODES[state["node"]] and state.get("image") == IMAGE, "original_install_node_or_image_changed")
    node = json.loads(kube("get", "node", state["node"], "-o", "json"))
    require(node["metadata"].get("uid") == state["node_uid"] and node.get("status", {}).get("nodeInfo", {}).get("architecture") == "amd64" and not node["metadata"].get("deletionTimestamp"), "original_scheduling_node_changed")
    require(type(state.get("storage_class")) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", state["storage_class"]), "original_storage_class_missing")
    storage = json.loads(kube("get", "storageclass", state["storage_class"], "-o", "json"))
    require(not storage["metadata"].get("deletionTimestamp") and "nfs" not in storage.get("provisioner", "").lower(), "original_storage_class_rejected")
    expected = manifests(owner, state["storage_class"])
    require(set(state.get("resources", {})) == {resource + "/" + obj["metadata"]["name"] for resource, obj in expected}, "original_seven_resource_set_changed")
    observed = {}
    for resource, obj in expected:
        guard()
        name = obj["metadata"]["name"]
        actual = get(resource, name)
        uid = state["resources"][resource + "/" + name]
        require(UUID.fullmatch(uid) and actual and actual.get("apiVersion") == obj["apiVersion"] and actual.get("kind") == obj["kind"] and actual.get("metadata", {}).get("uid") == uid and actual["metadata"].get("namespace") == NAMESPACE and actual["metadata"].get("labels", {}).get(LABEL) == state["run"] and not actual["metadata"].get("deletionTimestamp"), "original_owned_resource_changed")
        observed[resource] = actual
        if resource in ("secrets", "configmaps"):
            require(actual.get("immutable") is True and actual.get("data") == obj["data"], "original_tls_or_server_config_changed")
    pod = observed["deployments"]["spec"]["template"]["spec"]
    containers = pod.get("containers", [])
    require(pod.get("nodeName") == state["node"] and pod.get("serviceAccountName") == state["prefix"] and pod.get("automountServiceAccountToken") is False and len(containers) == 1 and containers[0].get("name") == "vault" and containers[0].get("image") == IMAGE and containers[0].get("imagePullPolicy") == "Never" and containers[0].get("command") == [CLI, "server", "-config=/config/server.json"], "original_provider_deployment_changed")
    claim = observed["persistentvolumeclaims"]
    require(claim.get("spec", {}).get("storageClassName") == state["storage_class"] and claim["spec"].get("accessModes") == ["ReadWriteOnce"] and claim["spec"].get("resources", {}).get("requests", {}).get("storage") == "2Gi", "original_data_claim_changed")
    pvc_binding(owner)
    ensure_provider_data_initializer(owner, observed["deployments"])


def ensure_provider_data_initializer(owner, deployment):
    """Patch only the original provider template, retaining all data/material."""
    spec = deployment["spec"]["template"]["spec"]
    security = spec.get("securityContext", {})
    require(security.get("runAsNonRoot") is True and security.get("runAsUser") == 65532 and security.get("runAsGroup") == 65532 and security.get("fsGroup") == 65532, "original_provider_nonroot_identity_changed")
    data = [volume for volume in spec.get("volumes", []) if volume.get("name") == "data"]
    require(data == [{"name": "data", "persistentVolumeClaim": {"claimName": owner.state["prefix"] + "-data"}}], "original_provider_data_mount_changed")
    expected = [provider_data_initializer()]
    if "initContainers" in spec:
        require(spec["initContainers"] == expected, "original_provider_init_containers_changed")
        return
    metadata = deployment["metadata"]
    require(metadata.get("uid") == owner.state["resources"]["deployments/" + owner.state["prefix"]] and type(metadata.get("resourceVersion")) is str and metadata["resourceVersion"], "original_provider_patch_identity_missing")
    guard()
    patch = [{"op": "test", "path": "/metadata/uid", "value": metadata["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]}, {"op": "add", "path": "/spec/template/spec/initContainers", "value": expected}]
    kube("-n", NAMESPACE, "patch", "deployment", owner.state["prefix"], "--type=json", "-p", json.dumps(patch), "-o", "jsonpath={.metadata.uid}")


def main():
    global PHASE, IMAGE, IMAGE_DIGESTS, CLI, VERSION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("install", "resume-install", "unseal", "smoke", "uninstall"))
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--storage-class")
    parser.add_argument("--image-input", type=Path)
    parser.add_argument("--image-input-sha256")
    parser.add_argument("--node", choices=tuple(NODES), default="k8s-master")
    args = parser.parse_args()
    os.umask(0o077)
    api = None
    try:
        PHASE = "namespace"
        guard()
        if args.operation == "install":
            require(args.image_input and args.image_input_sha256, "reviewed_offline_image_input_required")
            image_raw = args.image_input.read_bytes()
            require(len(image_raw) <= 16384 and hashlib.sha256(image_raw).hexdigest() == args.image_input_sha256, "image_input_digest_mismatch")
            image_input = json.loads(image_raw)
            require(image_input.get("schema_version") == "d-transit-image-input.v1" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}", image_input.get("image", "")) and image_input.get("entrypoint") == "/bin/vault" and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", image_input.get("version", "")) and type(image_input.get("image_id_digests")) is list and image_input["image_id_digests"] and all(re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in image_input["image_id_digests"]), "offline_image_input_shape")
            IMAGE, IMAGE_DIGESTS, CLI, VERSION = image_input["image"], set(image_input["image_id_digests"]), image_input["entrypoint"], image_input["version"]
            node = json.loads(kube("get", "node", args.node, "-o", "json"))
            require(node["metadata"]["uid"] == NODES[args.node] and node["status"]["nodeInfo"]["architecture"] == "amd64" and not node["metadata"].get("deletionTimestamp"), "original_scheduling_node_changed")
            require(args.storage_class and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", args.storage_class), "explicit_storage_class_required")
            for tool in ("kubectl", "openssl"):
                require(shutil.which(tool), "required_tool_missing")
            storage = json.loads(kube("get", "storageclass", args.storage_class, "-o", "json"))
            require(not storage["metadata"].get("deletionTimestamp") and "nfs" not in storage.get("provisioner", "").lower(), "persistent_raft_storage_class_rejected")
            owner = Owner(args.state_dir, new=True)
            nonce = secrets.token_hex(8)
            owner.state = {"schema_version": "d-transit-owned-install.v1", "context": CONTEXT, "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID, "run": nonce, "prefix": "sbk-transit-zh-" + nonce[:8], "image": IMAGE, "image_input": image_input, "node": args.node, "node_uid": NODES[args.node], "storage_class": args.storage_class, "resources": {}, "pending": None}
            owner.save()
            PHASE = "tls-material"
            certificate(owner)
            PHASE = "owned-resources"
            for resource, obj in manifests(owner, args.storage_class):
                owner.create(obj, resource)
            PHASE = "provider-start"
            api = API(owner)
            PHASE = "initialize"
            initialize(owner, api)
            PHASE = "configure"
            configure(owner, api)
            PHASE = "jwt-smoke"
            smoke(owner, api)
            PHASE = "persistent-restart-readback"
            api = persistence(owner, api)
        else:
            owner = Owner(args.state_dir)
            saved_image = owner.state["image_input"]
            IMAGE, IMAGE_DIGESTS, CLI, VERSION = saved_image["image"], set(saved_image["image_id_digests"]), saved_image["entrypoint"], saved_image["version"]
            require(owner.state.get("context") == CONTEXT and owner.state.get("namespace_uid") == NAMESPACE_UID and owner.state.get("image") == IMAGE and owner.state.get("pending") is None, "original_install_state_unknown")
            if args.operation == "resume-install":
                PHASE = "resume-original-install-identities"
                resume_install_owner(owner)
                PHASE = "provider-start"
                api = API(owner)
                require(api.call("GET", "sys/init").get("initialized") is False, "already_initialized_never_reinitialize")
                PHASE = "initialize"
                initialize(owner, api)
                PHASE = "configure"
                configure(owner, api)
                PHASE = "jwt-smoke"
                smoke(owner, api)
                PHASE = "persistent-restart-readback"
                api = persistence(owner, api)
            elif args.operation == "uninstall":
                PHASE = "owned-uninstall-retaining-keys"
                name = owner.state["prefix"]
                for resource, item, group in (("deployments", name, "apis/apps/v1"), ("networkpolicies", name, "apis/networking.k8s.io/v1"), ("services", name, "api/v1"), ("configmaps", name + "-config", "api/v1"), ("secrets", name + "-tls", "api/v1"), ("serviceaccounts", name, "api/v1")):
                    owner.delete(resource, item, group)
                owner.state["uninstalled_data_retained"] = True
                owner.save()
            else:
                api = API(owner)
                PHASE = args.operation
                unseal(owner, api)
                if args.operation == "smoke":
                    smoke(owner, api)
        PHASE = "final-identities"
        guard()
        report = {"schema_version": "d-transit-install-report.v1", "status": "completed", "operation": args.operation, "context": CONTEXT, "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID, "provider_cluster_id": owner.state.get("cluster_id"), "image": IMAGE, "endpoint": "https://" + owner.state["prefix"] + "." + NAMESPACE + ".svc:8200", "key_name": owner.state["prefix"] + "-kek", "provider_version": "1", "jwt_mount": owner.state.get("jwt_mount"), "jwt_smoke_passed": owner.state.get("jwt_smoke_passed", False), "persistence_restart_verified": owner.state.get("persistence_restart_verified", False), "storage_class": owner.state["storage_class"], "data_pvc": owner.state["prefix"] + "-data", "pvc_binding": owner.state.get("pvc_binding"), "ca_sha256": hashlib.sha256(owner.read("ca.pem", False)).hexdigest(), "signing": owner.state.get("signing"), "persistent_data_deleted": False, "owner_material_exported": False, "production_owner_mapping_registered": False, "source_independent_verified": False, "backup_target_classified": False}
        owner.write("public-report.json", report, replace=(owner.directory / "public-report.json").exists())
        print(json.dumps(report, sort_keys=True))
        return 0
    except Refused as error:
        print(json.dumps({"schema_version": "d-transit-install-report.v1", "status": "refused", "stage": PHASE, "reason": error.reason, "raw_diagnostics_withheld": True}))
        return 1
    except Exception:
        print(json.dumps({"schema_version": "d-transit-install-report.v1", "status": "refused", "stage": PHASE, "reason": "private_error_details_withheld"}))
        return 1
    finally:
        if api is not None:
            api.close()


if __name__ == "__main__":
    sys.exit(main())
