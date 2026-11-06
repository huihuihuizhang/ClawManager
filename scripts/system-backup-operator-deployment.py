#!/usr/bin/env python3
"""Deployment stages for the existing original-operation Linux operator.

Imported by the operator, never an alternate authority or arbitrary command runner.
All native sends retain an intent before dispatch and are never silently retried.
"""
import base64
import copy
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import ssl
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import zlib

NS = "clawmanager-zhanghui08-system"
REGISTRY = "http://10.130.14.23:5000"
MARKER = "backup.clawreef.io/original-operator"
CRI_SHA = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"
RUNTIME_MOUNT = "/run/system-backup"
RUNTIME = RUNTIME_MOUNT + "/runtime"
PRIVATE_MOUNT = "/run/installation-owner-private"
PRIVATE = PRIVATE_MOUNT + "/installer"
STAGING = "/var/lib/system-backup/staging"
PASSWORD = Path("/root/.clawmanager-backup-install/admin-password")
ROUTES = {"whole": (19443, "/observation/v1"), "gateway": (19444, "/gateway-observation/v1"), "stopped-pro": (19445, "/stopped-pro-observation/v1"), "shared": (19446, "/shared-runtime-lifecycle/v1")}


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    # Every Go definition consumer uses RFC8785 canonical bytes, including
    # exact EOF. These finite DTOs have integer counters, never float claims.
    def ordered(item):
        if isinstance(item, dict):
            need(all(isinstance(k, str) for k in item), "json_string_keys_required")
            return {k: ordered(item[k]) for k in sorted(item, key=lambda s: s.encode("utf-16-be"))}
        if isinstance(item, list):
            return [ordered(v) for v in item]
        need(not isinstance(item, float), "floating_input_not_in_finite_definition_protocol")
        if isinstance(item, int):
            need(abs(item) <= 9007199254740991, "json_exact_integer_limit")
        return item
    return json.dumps(ordered(value), separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, pin=None, limit=4 << 20, private=True):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "canonical_original_file_required")
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "file_kind_or_size")
    if private and os.name == "posix":
        need(before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0, "private_operator_file_required")
    with path.open("rb") as f:
        opened = os.fstat(f.fileno())
        raw = f.read(limit + 1)
        after = os.fstat(f.fileno())
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(raw) == before.st_size,
         "file_changed")
    need(pin is None or digest(raw) == pin, "producer_file_pin_changed")
    return raw


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("json_constant")))


def sync(directory):
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write(path, raw):
    with Path(path).open("xb") as f:
        os.chmod(path, 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    sync(Path(path).parent)
    return {"File": str(path), "SHA256": digest(raw)}


def pin(path, private=True, limit=4 << 20):
    raw = read(path, private=private, limit=limit)
    return {"File": str(path), "SHA256": digest(raw)}


def pinned(value, private=True, limit=4 << 20):
    return read(value["File"], value["SHA256"], private=private, limit=limit)


def register_arguments(parser):
    parser.add_argument("--deployment-app-image")
    parser.add_argument("--deployment-worker-image")
    parser.add_argument("--deployment-storage-class")
    parser.add_argument("--deployment-inputs-storage-class", default="longhorn-rwx")
    parser.add_argument("--deployment-staging-size")
    parser.add_argument("--deployment-ssh-key-file", type=Path)
    parser.add_argument("--deployment-known-hosts-file", type=Path)
    parser.add_argument("--deployment-crictl-file", type=Path)
    parser.add_argument("--deployment-source-selection-file", type=Path)
    parser.add_argument("--deployment-source-selection-sha256")
    parser.add_argument("--deployment-writer-selection-file", type=Path)
    parser.add_argument("--deployment-writer-selection-sha256")
    parser.add_argument("--deployment-minio-options-file", type=Path)
    parser.add_argument("--deployment-minio-options-sha256")
    parser.add_argument("--deployment-vault-state-directory", type=Path)
    parser.add_argument("--deployment-vault-owner-material-file", type=Path, default=Path("/root/sbk-vault-owner-20261102-01/init-material.json"))
    parser.add_argument("--deployment-signing-until")


def upsert(env, name, value):
    need(len([e for e in env if e["name"] == name]) <= 1, "duplicate_environment_name")
    env[:] = [e for e in env if e["name"] != name]
    env.append({"name": name, "value": value})


def overlap(a, b):
    return a == b or a == "/" or b == "/" or a.startswith(b + "/") or b.startswith(a + "/")


def only_controller(obj, kind):
    owners = [r for r in obj["metadata"].get("ownerReferences", []) if r.get("controller") is True]
    need(len(owners) == 1 and owners[0]["kind"] == kind and owners[0]["apiVersion"] == "apps/v1", "actual_single_controller_owner_required")
    return owners[0]


def image_id(value):
    for prefix in ("docker-pullable://", "docker://", "containerd://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if "@sha256:" in value:
        return "sha256:" + value.rsplit("@sha256:", 1)[1]
    return value


def merge_material_patches(original, patches):
    """Merge only additive mount/init arrays emitted by the real producers.

    Individual resourceVersions are point-in-time producer guards. The single
    native send uses the final current RV AND the complete unchanged base spec.
    """
    desired = copy.deepcopy(original["spec"])
    for patch in patches:
        need(isinstance(patch, list), "native_material_patch_array_required")
        tested_uid = tested_rv = False
        for op in patch:
            action, path, value = op["op"], op["path"], op.get("value")
            if action == "test":
                if path == "/metadata/uid":
                    need(value == original["metadata"]["uid"], "material_patch_foreign_controller")
                    tested_uid = True
                elif path == "/metadata/resourceVersion":
                    need(isinstance(value, str) and value, "material_patch_original_rv_required")
                    tested_rv = True
                else:
                    match = re.fullmatch(r"/spec/template/spec/containers/([0-9]+)/name", path)
                    need(match is not None and original["spec"]["template"]["spec"]["containers"][int(match[1])]["name"] == value, "material_patch_container_test")
                continue
            need(action == "add" and tested_uid and tested_rv, "only_original_additive_material_patch_supported")
            match = re.fullmatch(r"/spec/template/spec/(volumes|initContainers)(/-)?", path)
            if match:
                target = desired["template"]["spec"].setdefault(match[1], [])
                entries = [value] if match[2] else value
            else:
                match = re.fullmatch(r"/spec/template/spec/containers/([0-9]+)/volumeMounts(/-)?", path)
                need(match is not None, "unexpected_material_patch_path")
                target = desired["template"]["spec"]["containers"][int(match[1])].setdefault("volumeMounts", [])
                entries = [value] if match[2] else value
            need(isinstance(entries, list) and all(isinstance(e, dict) and e.get("name") for e in entries), "material_patch_named_array_required")
            for entry in entries:
                need(not any(e["name"] == entry["name"] for e in target), "material_patch_duplicate_name")
                if "mountPath" in entry:
                    need(not any(overlap(e["mountPath"], entry["mountPath"]) for e in target), "material_patch_mount_overlap")
                target.append(copy.deepcopy(entry))
        need(tested_uid and tested_rv, "material_patch_identity_guard_required")
    return desired


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("registry_redirect_refused")


def registry_image(reference, built, commit):
    match = re.fullmatch(r"10\.130\.14\.23:5000/([a-z0-9][a-z0-9._/-]*)@sha256:([a-f0-9]{64})", reference or "")
    need(match is not None and ".." not in match[1].split("/"), "actual_immutable_original_registry_image_required")
    repo, manifest_sha = match.groups()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def response(kind, value):
        req = urllib.request.Request(REGISTRY + "/v2/" + repo + "/" + kind + "/sha256:" + value,
                                     headers={"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
        r = client.open(req, timeout=30)
        need(r.status == 200, "registry_actual_content_unavailable")
        return r

    def small(kind, value):
        with response(kind, value) as r:
            raw = r.read((4 << 20) + 1)
        need(0 < len(raw) <= 4 << 20 and digest(raw) == value, "registry_content_digest_mismatch")
        return raw

    manifest_raw = small("manifests", manifest_sha)
    manifest = decode(manifest_raw)
    need(manifest.get("schemaVersion") == 2 and "manifests" not in manifest and isinstance(manifest.get("layers"), list), "single_actual_image_manifest_required")
    config_descriptor = manifest["config"]
    need(config_descriptor["digest"] == built["config_digest"], "registry_image_not_from_same_release")
    config_raw = small("blobs", config_descriptor["digest"].removeprefix("sha256:"))
    need(len(config_raw) == config_descriptor["size"], "registry_config_size")
    config = decode(config_raw)
    need(config.get("os") == "linux" and config.get("architecture") == "amd64" and
         config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") == commit,
         "same_source_linux_amd64_image_required")
    diffs = config["rootfs"]["diff_ids"]
    need(config["rootfs"]["type"] == "layers" and len(diffs) == len(manifest["layers"]) and 0 < len(diffs) <= 128, "image_layer_roster")
    layers = []
    for descriptor, expected_diff in zip(manifest["layers"], diffs):
        need(re.fullmatch(r"sha256:[a-f0-9]{64}", descriptor["digest"]) and 0 < descriptor["size"] <= 8 << 30, "image_layer_descriptor")
        media = descriptor["mediaType"]
        need(media in ("application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar"), "image_layer_media_type")
        decoder = zlib.decompressobj(31) if media.endswith("gzip") else None
        compressed, plain = hashlib.sha256(), hashlib.sha256()
        count = plain_count = 0
        with response("blobs", descriptor["digest"][7:]) as stream:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                count += len(block)
                need(count <= descriptor["size"], "image_layer_overrun")
                compressed.update(block)
                if decoder:
                    while block:
                        data = decoder.decompress(block, 1 << 20)
                        plain_count += len(data)
                        need(plain_count <= 32 << 30, "image_plain_layer_limit")
                        plain.update(data)
                        block = decoder.unconsumed_tail
                    need(not decoder.unused_data, "image_layer_multistream_or_trailing_bytes")
                else:
                    plain_count += len(block)
                    plain.update(block)
        need(count == descriptor["size"] and compressed.hexdigest() == descriptor["digest"][7:], "image_actual_layer_digest")
        need(decoder is None or decoder.eof, "image_layer_incomplete_gzip")
        need("sha256:" + plain.hexdigest() == expected_diff, "image_actual_layer_diffid")
        layers.append({"digest": descriptor["digest"], "size": count, "diff_id": expected_diff})
    return {"reference": reference, "manifest_sha256": manifest_sha, "config_digest": config_descriptor["digest"], "commit": commit, "layers": layers}


class DeploymentStages:
    def __init__(self, operator):
        self.op = operator
        self.a = operator.a
        self.root, self.run = operator.root, operator.run
        self.scope = operator.open()
        self.operation = decode(read(self.run / "operation.json"))["operation"]
        need(re.fullmatch(r"[a-f0-9]{32}", self.operation), "original_operation_required")
        self.directory = self.run / "deployment"
        if not self.directory.exists():
            self.directory.mkdir(mode=0o700)
            sync(self.run)
        need(self.directory.resolve(strict=True) == self.directory, "deployment_directory_link")
        self.prefix = "sbk-" + self.operation[:12]

    def get(self, resource, name):
        return decode(self.op.k("-n", NS, "get", resource, name, "-o", "json"))

    def retain(self, name, value):
        path, raw = self.directory / name, encoded(value)
        if path.exists():
            need(read(path) == raw, "retained_operation_data_changed")
            return pin(path)
        return write(path, raw)

    def completed(self, stage):
        item = self.op.completed(stage)
        return decode(read(item["stdout"], item["stdout_sha256"]))

    def common(self):
        wrapper = self.completed("sql-enroll")
        enrolled = decode(read(wrapper["receipt_file"], wrapper["receipt_sha256"]))
        need(enrolled["Version"] == "original-native-enrollment-produced.v1", "actual_original_enrollment_required")
        plan = decode(pinned(enrolled["Plan"]))
        for key in ("IssuerPublic", "Enrollment"):
            pinned(enrolled[key])
        materials = decode(read(self.run / "sql-accounts/sql-accounts-materials.public.json"))
        need(materials["server_uuid"] == plan["Target"]["ServerUUID"] and materials["database"] == plan["Target"]["Database"], "same_sql_material_identity")
        installer = materials["files"]["mysql-installer.dsn"]
        pinned(installer)
        args = ["--plan-file", enrolled["Plan"]["File"], "--plan-sha256", enrolled["Plan"]["SHA256"],
                "--issuer-public-file", enrolled["IssuerPublic"]["File"], "--issuer-public-sha256", enrolled["IssuerPublic"]["SHA256"],
                "--enrollment-pin-file", enrolled["Enrollment"]["File"], "--enrollment-pin-sha256", enrolled["Enrollment"]["SHA256"],
                "--kubeconfig-file", self.op.kube, "--kubeconfig-sha256", digest(read(self.op.kube)),
                "--dsn-file", installer["File"], "--database-ca-file", materials["source_tls"]["ca_file"],
                "--local-admin-password-file", PASSWORD]
        return args, enrolled, plan, materials

    def binary(self, name):
        receipt = decode(read(self.root / "build-receipt.json", private=False))
        path = self.root / "bin" / name
        raw = read(path, receipt["binaries"][name], limit=128 << 20, private=False)
        need(raw[:6] == b"\x7fELF\x02\x01" and raw[18:20] == b"\x3e\x00", "release_linux_binary_required")
        return path

    def call(self, stage, argv, data=None, json_output=True):
        name = self.directory / (stage + ".send-unknown.json")
        if name.exists():
            intent = decode(read(name))
            need(intent["argv"] == [str(x) for x in argv] and intent["operation"] == self.operation and
                 (intent["input"] is None if data is None else intent["input"] is not None and intent["input"]["SHA256"] == digest(data)),
                 "original_native_intent_changed")
            if intent["input"] is not None:
                pinned(intent["input"], limit=200 << 20)
            completed = self.directory / (stage + ".readback.json")
            need(completed.exists(), "send_already_recorded_use_deployment_query_no_resend")
            receipt = decode(read(completed))
            raw = pinned(receipt["stdout"], limit=64 << 20)
            return (decode(raw) if json_output else None), receipt["stdout"]
        input_pin = write(self.directory / (stage + ".stdin.private"), data) if data is not None else None
        self.retain(stage + ".send-unknown.json", {"stage": stage, "argv": [str(x) for x in argv], "input": input_pin, "operation": self.operation})
        stdout, stderr = self.directory / (stage + ".stdout.private"), self.directory / (stage + ".stderr.private")
        with stdout.open("xb") as out, stderr.open("xb") as err:
            os.chmod(stdout, 0o600); os.chmod(stderr, 0o600)
            result = subprocess.run([str(x) for x in argv], input=data, stdout=out, stderr=err, timeout=1800, check=False)
            out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
        sync(self.directory)
        need(result.returncode == 0, "native_send_unknown_retain_original_intent")
        raw = read(stdout, limit=64 << 20)
        value = decode(raw) if json_output else None
        self.retain(stage + ".readback.json", {"stage": stage, "stdout": pin(stdout, limit=64 << 20), "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(), "exit_code": result.returncode})
        return value, pin(stdout, limit=64 << 20)

    def kubectl(self, stage, args, obj=None):
        argv = ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", self.op.kube,
                "--request-timeout=60s", "-n", NS, *args]
        return self.call(stage, argv, encoded(obj) if obj is not None else None)

    def create_object(self, stage, obj):
        obj.setdefault("metadata", {}).setdefault("annotations", {})[MARKER] = self.operation
        retained = self.kubectl(stage, ["create", "-f", "-", "-o", "json"], obj)[0]
        current = self.get(obj["kind"], obj["metadata"]["name"])
        need(current["metadata"]["uid"] == retained["metadata"]["uid"] and current["metadata"].get("annotations", {}).get(MARKER) == self.operation and
             all(current.get(k) == retained.get(k) for k in ("spec", "data", "binaryData", "immutable")), "created_object_drift")
        return current

    def cli(self, stage, binary, flags):
        common, _, _, _ = self.common()
        return self.call(stage, [self.binary(binary), *common, *flags])

    def preinstall_api_runtime_mount(self, desired):
        # Same ORIGINAL input PVC as controller, no owner-private PVC. Mount
        # the directory so the later signed projection appears without a roll.
        pod = desired["template"]["spec"]
        need(len(pod["containers"]) == 1, "one_original_api_container_required")
        container = pod["containers"][0]
        volume = {"name": "sbk-original-runtime-inputs", "persistentVolumeClaim": {"claimName": self.prefix + "-inputs", "readOnly": True}}
        mount = {"name": volume["name"], "mountPath": RUNTIME_MOUNT, "readOnly": True}
        volumes = [v for v in pod.get("volumes", []) if v["name"] == volume["name"]]
        mounts = [v for v in container.get("volumeMounts", []) if overlap(v["mountPath"], RUNTIME_MOUNT)]
        need((not volumes and not mounts) or volumes == [volume] and mounts == [mount], "original_api_runtime_mount_collision")
        if not volumes:
            pod.setdefault("volumes", []).append(volume)
            container.setdefault("volumeMounts", []).append(mount)

    def verify_api_minio_recovery_file(self, selected):
        pinned(selected)
        app = self.get("deployment", "clawmanager-app")
        need(app["metadata"]["uid"] == self.scope["app_deployment_uid"] and app["spec"].get("replicas") == 1, "same_original_running_api_required")
        expected = copy.deepcopy(app["spec"])
        self.preinstall_api_runtime_mount(expected)
        need(expected == app["spec"], "api_runtime_mount_not_preinstalled_before_original_source_signing")
        host = self.host_result()
        claim = self.get("pvc", self.prefix + "-inputs")
        need(claim["metadata"]["uid"] == host["pvc_uids"]["inputs"], "api_and_controller_must_mount_same_original_input_pvc")
        labels = app["spec"]["selector"]["matchLabels"]
        pods = decode(self.op.k("-n", NS, "get", "pods", "-l", ",".join(k+"="+v for k,v in sorted(labels.items())), "-o", "json"))["items"]
        need(len(pods) == 1 and not pods[0]["metadata"].get("deletionTimestamp"), "one_actual_api_pod_required")
        pod = pods[0]
        owner = [v for v in pod["metadata"]["ownerReferences"] if v.get("controller") and v["kind"] == "ReplicaSet"]
        need(len(owner) == 1, "actual_api_replica_owner_required")
        replica = self.get("replicaset", owner[0]["name"])
        need(replica["metadata"]["uid"] == owner[0]["uid"] and any(v.get("controller") and v["uid"] == app["metadata"]["uid"] for v in replica["metadata"]["ownerReferences"]), "same_original_api_controller_graph_required")
        container = app["spec"]["template"]["spec"]["containers"][0]["name"]
        result = self.op.k("-n", NS, "exec", pod["metadata"]["name"], "-c", container, "--", "/bin/sh", "-ec", 'test ! -w "$1"; sha256sum -- "$1"', "sh", selected["File"])
        need(result.decode("ascii").split() == [selected["SHA256"], selected["File"]], "actual_api_uid_cannot_read_original_readonly_recovery_file")
        again = self.get("pod", pod["metadata"]["name"])
        need(again["metadata"]["uid"] == pod["metadata"]["uid"] and again["spec"] == pod["spec"] and again["status"]["containerStatuses"] == pod["status"]["containerStatuses"], "api_actor_changed_during_recovery_file_readback")
        return {"PodUID": pod["metadata"]["uid"], "File": selected, "PVCUID": claim["metadata"]["uid"], "ReadOnly": True}

    def new_image(self):
        if (self.directory / "new-image.result.json").exists():
            result = decode(read(self.directory / "new-image.result.json"))
            inputs_pvc = self.prepare_inputs_pvc()
            need(not result.get("inputs_pvc") or result["inputs_pvc"]["UID"] == inputs_pvc["metadata"]["uid"], "installed_input_pvc_uid_drift")
            actual = self.get("deployment", result["app"]["Name"])
            need(actual["metadata"]["uid"] == result["app"]["UID"] and digest(encoded(actual["spec"])) == result["app"]["SpecSHA256"], "installed_app_template_drift")
            return result
        self.op.upgraded_released()
        self.common()
        inputs_pvc = self.prepare_inputs_pvc()
        tls = self.completed("tls-apply")
        need(tls["OperatorSQLTLSVerified"] is True, "actual_tls_producer_required")
        tls_plan = decode(read(tls["PlanFile"], tls["PlanSHA256"]))
        ca = read(tls["CAFile"], tls["CASHA256"], limit=65536)
        source_tls = decode(read(tls["SourceTLSFile"], tls["SourceTLSSHA256"]))
        need(source_tls["ca_file"] == tls["CAFile"] and source_tls["ca_sha256"] == tls["CASHA256"] and
             source_tls["server_name"] in tls_plan["DNSNames"], "actual_database_tls_tuple")
        build = decode(read(self.root / "build-receipt.json", private=False))
        images = {"app": registry_image(self.a.deployment_app_image, build["images"]["app"], build["commit"]),
                  "worker": registry_image(self.a.deployment_worker_image, build["images"]["worker"], build["commit"])}
        self.retain("images.actual.json", images)
        original = self.get("deployment", "clawmanager-app")
        need(original["metadata"]["uid"] == self.scope["app_deployment_uid"] and original["spec"].get("replicas", 1) == 0, "original_app_stopped_required")
        desired = copy.deepcopy(original["spec"])
        pod = desired["template"]["spec"]
        need(len(pod["containers"]) == 1, "one_original_business_app_container_required")
        container = pod["containers"][0]
        # Preserve original main-app credentials, config mounts and all business
        # service settings. A2's limited mysql-business identity is never used.
        original_db = {k: copy.deepcopy(container.get(k)) for k in ("env", "envFrom", "volumeMounts")}
        need(not any(overlap(m["mountPath"], "/etc/clawmanager-business-mysql-ca") for m in container.get("volumeMounts", [])), "new_mysql_ca_mount_collision")
        need(not any(v["name"] == "sbk-business-mysql-ca" for v in pod.get("volumes", [])), "new_mysql_ca_volume_collision")
        cm_name = self.prefix + "-mysql-ca"
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cm_name, "namespace": NS}, "immutable": True, "data": {"ca.crt": ca.decode("ascii")}}
        cm_actual = self.create_object("new-image-ca-create", cm)
        container["image"] = images["app"]["reference"]
        env = container.setdefault("env", [])
        for name, value in {"DB_TLS_CA_FILE": "/etc/clawmanager-business-mysql-ca/ca.crt", "DB_TLS_CA_SHA256": tls["CASHA256"],
                            "DB_TLS_SERVER_NAME": source_tls["server_name"], "SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED": "false",
                            "SYSTEM_BACKUP_READ_LIVE_ENABLED": "false", "SYSTEM_BACKUP_V2_EXECUTION_ENABLED": "false",
                            "SYSTEM_BACKUP_CONTROLLER_ENABLED": "false", "SYSTEM_BACKUP_ENABLED": "false"}.items():
            upsert(env, name, value)
        pod.setdefault("volumes", []).append({"name": "sbk-business-mysql-ca", "configMap": {"name": cm_name, "defaultMode": 292}})
        # A subPath file is a regular bind mount inside the container. Mounting
        # the projection directory would expose symlinks to the strict reader.
        container.setdefault("volumeMounts", []).append({"name": "sbk-business-mysql-ca", "mountPath": "/etc/clawmanager-business-mysql-ca/ca.crt", "subPath": "ca.crt", "readOnly": True})
        self.preinstall_api_runtime_mount(desired)
        desired.setdefault("template", {}).setdefault("metadata", {}).setdefault("annotations", {})[MARKER] = self.operation
        self.retain("new-image.plan.json", {"version": "original-app-complete-tls-template.v1", "operation": self.operation,
                     "original_uid": original["metadata"]["uid"], "original_resource_version": original["metadata"]["resourceVersion"],
                     "original_spec": original["spec"], "desired_spec": desired, "images": images, "ca_uid": cm_actual["metadata"]["uid"],
                     "preserved_business_inputs_sha256": digest(encoded(original_db)), "inputs_pvc_uid": inputs_pvc["metadata"]["uid"], "configuration_enabled": False})
        patch = [{"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": original["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/spec", "value": original["spec"]}, {"op": "replace", "path": "/spec", "value": desired}]
        changed, _ = self.kubectl("new-image-app-patch", ["patch", "deployment", "clawmanager-app", "--type=json", "--patch-file=/dev/stdin", "-o", "json"], patch)
        need(changed["metadata"]["uid"] == original["metadata"]["uid"] and changed["spec"] == desired, "app_template_readback_mismatch")
        app, business_pods = self.business_rollout(images)
        result = {"version": "operator-new-image-result.v1", "state": "actual_full_business_mysql_tls_template_and_same_release_rollout_verified",
                  "app": {"Name": "clawmanager-app", "UID": changed["metadata"]["uid"], "SpecSHA256": digest(encoded(app["spec"]))}, "business_pods": business_pods,
                  "images": images, "inputs_pvc": {"Name": inputs_pvc["metadata"]["name"], "UID": inputs_pvc["metadata"]["uid"]},
                  "plan": pin(self.directory / "new-image.plan.json"), "configuration_enabled": False}
        self.retain("new-image.result.json", result)
        return result

    def ssh(self, stage, address, script, data=None):
        ipaddress.ip_address(address)
        key, known = self.a.deployment_ssh_key_file, self.a.deployment_known_hosts_file
        need(key is not None and known is not None, "existing_pinned_ssh_key_and_known_hosts_required")
        read(key, limit=65536)
        read(known, limit=4 << 20, private=False)
        target = "root@" + ("[" + address + "]" if ":" in address else address)
        # All remote script text is generated here; never supplied by a request.
        argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                "-o", "UserKnownHostsFile=" + str(known), "-i", key, target, "sh -ceu " + shlex.quote(script)]
        return self.call(stage, argv, data=data, json_output=False)

    def node_probe(self, node):
        addresses = [a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"]
        need(len(addresses) == 1, "unambiguous_actual_node_internal_ip_required")
        address = str(ipaddress.ip_address(addresses[0]))
        script = """test \"$(id -u)\" = 0
test \"$(uname -s)\" = Linux
test \"$(uname -m)\" = x86_64
machine=$(cat /etc/machine-id); boot=$(cat /proc/sys/kernel/random/boot_id)
case $machine$boot in ''|*[!0-9a-f-]*) exit 20;; esac
socket=; count=0
for path in /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock; do
  if test -S \"$path\" && test ! -L \"$path\"; then socket=$path; count=$((count+1)); fi
done
test \"$count\" = 1
printf '{\"machine_id\":\"%s\",\"boot_id\":\"%s\",\"cri_endpoint\":\"unix://%s\"}\\n' \"$machine\" \"$boot\" \"$socket\"
"""
        _, receipt = self.ssh("node-probe-" + digest(node["metadata"]["uid"].encode())[:16], address, script)
        value = decode(pinned(receipt))
        info = node["status"]["nodeInfo"]
        need(value["machine_id"] == info["machineID"] and value["boot_id"] == info["bootID"], "actual_ssh_node_identity_not_kubernetes_node")
        return address, value

    def account(self, suffix):
        definition = self.retain(suffix + "-sa.definition.json", {"Version": "original-observer-service-account.v1", "Name": self.prefix + "-" + suffix, "ExistingUID": ""})
        value, output = self.cli(suffix + "-sa", "system-backup-observer-deployment-materials", ["--mode", "service-account", "--definition-file", definition["File"], "--definition-sha256", definition["SHA256"]])
        need(value["Namespace"] == NS and value["Name"] == self.prefix + "-" + suffix and value["Created"] is True, "actual_created_service_account_required")
        return value, output

    def pvc_definition(self, name, size, storage_class):
        obj = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": self.prefix + "-" + name, "namespace": NS},
               "spec": {"storageClassName": storage_class, "accessModes": ["ReadWriteOnce"], "volumeMode": "Filesystem", "resources": {"requests": {"storage": size}}}}
        return obj

    def provision(self, name, size, storage_class):
        return self.create_object("host-pvc-" + name, self.pvc_definition(name, size, storage_class))

    def prepare_inputs_pvc(self):
        # new-image consumes this SAME original create-only PVC before any
        # app Pod references it. Pending is valid for WaitForFirstConsumer;
        # actual business_rollout still owns Pod Ready/TLS/image verification.
        need(self.a.deployment_inputs_storage_class, "select_actual_shared_inputs_storage_class")
        storage = decode(self.op.k("get", "storageclass", self.a.deployment_inputs_storage_class, "-o", "json"))
        need(storage["metadata"]["name"] == self.a.deployment_inputs_storage_class and
             not storage["metadata"].get("deletionTimestamp") and storage["provisioner"] == "driver.longhorn.io",
             "actual_longhorn_shared_inputs_storage_class_required")
        need(storage["metadata"].get("uid"), "actual_inputs_storage_class_uid_required")
        fields = ("provisioner", "parameters", "volumeBindingMode", "reclaimPolicy", "allowVolumeExpansion", "mountOptions", "allowedTopologies")
        self.retain("inputs-storage-class.selection.json", {"Name": storage["metadata"]["name"], "UID": storage["metadata"]["uid"],
                    "Configuration": {key: storage[key] for key in fields if key in storage}})
        obj = self.pvc_definition("inputs", "1Gi", storage["metadata"]["name"])
        obj["spec"]["accessModes"] = ["ReadWriteMany"]
        obj["metadata"].setdefault("annotations", {})[MARKER] = self.operation
        # SAME historic host-pvc-inputs stage/receipt, not a second create.
        # call() refuses unknown sends and reuses only its exact recorded reply.
        retained = self.kubectl("host-pvc-inputs", ["create", "-f", "-", "-o", "json"], obj)[0]
        current = self.get("pvc", obj["metadata"]["name"])
        for actual in (retained, current):
            configured = {k: v for k, v in actual["spec"].items() if k != "volumeName"}
            need(actual["metadata"]["name"] == obj["metadata"]["name"] and actual["metadata"]["namespace"] == NS and
                 actual["metadata"].get("uid") and not actual["metadata"].get("deletionTimestamp") and
                 actual["metadata"].get("annotations", {}).get(MARKER) == self.operation and configured == obj["spec"] and
                 actual.get("status", {}).get("phase") in (None, "Pending", "Bound"), "original_inputs_pvc_spec_or_owner_drift")
        need(current["metadata"]["uid"] == retained["metadata"]["uid"] and
             (not retained["spec"].get("volumeName") or current["spec"].get("volumeName") == retained["spec"]["volumeName"]),
             "original_inputs_pvc_uid_or_binding_drift")
        if current["spec"].get("volumeName"):
            self.retain("inputs-pvc-native-binding.json", {"UID": current["metadata"]["uid"], "VolumeName": current["spec"]["volumeName"]})
        return current

    def host_observer(self):
        image_result = decode(read(self.directory / "new-image.result.json"))
        common, enrolled, plan, sql = self.common()
        need(self.a.deployment_storage_class, "select_actual_dynamic_storage_class_for_new_operator_pvcs")
        need(re.fullmatch(r"[1-9][0-9]{0,3}(?:Gi|Ti)", self.a.deployment_staging_size or ""), "actual_staging_capacity_selection_required")
        storage = decode(self.op.k("get", "storageclass", self.a.deployment_storage_class, "-o", "json"))
        need(storage["provisioner"] != "kubernetes.io/no-provisioner", "actual_dynamic_storage_class_required")
        cri_file = self.a.deployment_crictl_file
        need(cri_file is not None, "reviewed_offline_crictl_elf_required")
        cri = pin(cri_file, private=False, limit=64 << 20)
        need(cri["SHA256"] == CRI_SHA, "reviewed_crictl_release_changed")
        controller, controller_receipt = self.account("controller")
        worker, worker_receipt = self.account("worker")
        sources, sources_receipt = self.account("sources")
        pods = decode(self.op.k("-n", NS, "get", "pods", "-o", "json"))["items"]
        node_names = sorted({p["spec"]["nodeName"] for p in pods if p["status"].get("phase") in ("Running", "Pending") and p["spec"].get("nodeName") and not p["metadata"].get("deletionTimestamp")})
        need(0 < len(node_names) <= 16, "actual_current_namespace_node_roster_required")
        nodes, selections, probes = {}, [], {}
        for name in node_names:
            node = decode(self.op.k("get", "node", name, "-o", "json"))
            need(node["status"]["nodeInfo"]["operatingSystem"] == "linux" and node["status"]["nodeInfo"]["architecture"] == "amd64", "finite_host_linux_amd64_only")
            address, native = self.node_probe(node)
            nodes[name], probes[name] = node, {"address": address, **native}
            host = "[" + address + "]" if ":" in address else address
            selections.append({"name": name, "uid": node["metadata"]["uid"], "endpoints": {kind: "https://" + host + ":" + str(port) + route for kind, (port, route) in ROUTES.items()}})
        definition = self.retain("observer-pki.definition.json", {"schema_version": "original-observer-pki-definition.v1", "trust_domain": "clawmanager.local", "service_account": controller["Name"], "service_account_uid": controller["UID"], "validity_seconds": 86400, "nodes": selections})
        output_dir = self.directory / "observer-pki"
        output_dir.mkdir(mode=0o700, exist_ok=True)
        pki, pki_receipt = self.call("observer-pki", [self.binary("system-backup-original-observer-pki"), *common,
            "--definition-file", definition["File"], "--definition-sha256", definition["SHA256"], "--output-directory", output_dir])
        need(pki["Status"] == "materialized_uninstalled_not_task_authority", "actual_original_pki_producer_result")
        build = decode(read(self.root / "build-receipt.json", private=False))
        agent_binaries = build.get("shared_agent_binaries", {})
        need(set(agent_binaries) == {"openclaw", "hermes"}, "sealed_release_actual_shared_agent_elf_roster_required")
        need(all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,80}", name) for name in agent_binaries.values()), "finite_sealed_release_agent_binary_name")
        shared_agents = {runtime: pin(self.binary(name), private=False, limit=64 << 20) for runtime, name in sorted(agent_binaries.items())}
        shared_owner_directory = "/var/lib/clawmanager-system-backup/" + self.prefix + "/shared-owner"
        host_definition = self.retain("observer-host.definition.json", {"Version": "original-observer-host-deployment.v1", "PKIDefinition": definition, "PKIReceipt": pki_receipt,
            "Binaries": {kind: pin(self.binary(binary), private=False, limit=64 << 20) for kind, binary in {"whole": "backup-node-observer", "gateway": "backup-gateway-node-observer", "stopped-pro": "backup-stopped-pro-node-observer", "shared": "backup-shared-runtime-node-owner"}.items()},
            "BinaryDirectory": "/usr/local/libexec/" + self.prefix, "MaterialDirectory": "/etc/clawmanager-system-backup/" + self.prefix,
            "SharedRuntime": {"OwnerDirectory": shared_owner_directory, "CgroupMount": "/sys/fs/cgroup", "AgentExecutables": shared_agents},
            "CRI": [{"Node": name, "NodeUID": nodes[name]["metadata"]["uid"], "Binary": "/usr/local/libexec/" + self.prefix + "/crictl", "BinarySHA256": CRI_SHA, "Endpoint": probes[name]["cri_endpoint"], "ReleaseBinary": cri} for name in node_names]})
        bundles_dir = self.directory / "observer-host"
        bundles_dir.mkdir(mode=0o700, exist_ok=True)
        host_materials, host_materials_receipt = self.call("observer-host-materials", [self.binary("system-backup-observer-deployment-materials"), *common, "--mode", "host-materials", "--definition-file", host_definition["File"], "--definition-sha256", host_definition["SHA256"], "--output-directory", bundles_dir])
        for name, bundle in sorted(host_materials["NodeBundles"].items()):
            raw = pinned(bundle, limit=200 << 20)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = archive.getmembers()
                need(all(m.isfile() and "/" not in m.name and m.name not in ("", ".", "..") for m in members), "exact_producer_flat_host_bundle_required")
                need(len({m.name for m in members}) == len(members) and any(m.name == "install.sh" for m in members), "host_bundle_roster")
            remote = "/root/.clawmanager-backup-install/" + self.prefix + "-" + digest(nodes[name]["metadata"]["uid"].encode())[:16]
            script = "umask 077; mkdir -m 700 -- " + shlex.quote(remote) + "; cd -- " + shlex.quote(remote) + "; cat > bundle.private.tar; test \"$(sha256sum bundle.private.tar | cut -d ' ' -f 1)\" = " + shlex.quote(bundle["SHA256"]) + "; tar -xf bundle.private.tar; bash ./install.sh --apply"
            self.ssh("observer-install-" + digest(nodes[name]["metadata"]["uid"].encode())[:16], probes[name]["address"], script, raw)
        # This validates actual mTLS identities/handshake only. The authentic
        # native proof request remains the real original writer factory's job.
        tls_context = ssl.create_default_context(cafile=pki["CA"]["File"])
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        pinned(pki["CA"]); pinned(pki["ClientCertificate"]); pinned(pki["ClientKey"])
        tls_context.load_cert_chain(pki["ClientCertificate"]["File"], pki["ClientKey"]["File"])
        import socket
        tls_checks = []
        for endpoint in pki["Endpoints"]:
            from urllib.parse import urlsplit
            u = urlsplit(endpoint["Endpoint"]["URL"])
            with socket.create_connection((u.hostname, u.port), timeout=10) as tcp:
                with tls_context.wrap_socket(tcp, server_hostname=u.hostname) as tls_socket:
                    uris = [v for kind, v in tls_socket.getpeercert().get("subjectAltName", ()) if kind == "URI"]
                    need(uris == [endpoint["Endpoint"]["ServerURI"]] and tls_socket.version() == "TLSv1.3", "actual_observer_tls_identity")
                    tls_checks.append({"node": endpoint["Node"], "kind": endpoint["Kind"], "server_uri": uris[0], "server_certificate_sha256": digest(tls_socket.getpeercert(binary_form=True))})
        inputs_pvc = self.prepare_inputs_pvc()
        need(not image_result.get("inputs_pvc") or image_result["inputs_pvc"]["UID"] == inputs_pvc["metadata"]["uid"], "api_controller_original_inputs_pvc_uid_mismatch")
        pvcs = {"inputs": inputs_pvc, **{name: self.provision(name, size, storage["metadata"]["name"]) for name, size in (("staging", self.a.deployment_staging_size), ("private", "1Gi"))}}
        # The controller's final image, account, node and ALL producer mounts
        # exist before UID-bound issuance. Startup imports only private literal
        # environment lines; never eval/source shell code or patch PodTemplate.
        launcher = """set -eu
f=/run/system-backup/runtime/controller.env
while test ! -f \"$f.ready\"; do sleep 2; done
test ! -L \"$f\"; test ! -L \"$f.ready\"
test \"$(stat -c %u:%a \"$f\")\" = 65532:600
test \"$(sha256sum \"$f\" | cut -d ' ' -f 1)\" = \"$(cat \"$f.ready\")\"
while IFS= read -r entry; do
 case $entry in SYSTEM_BACKUP_*=*|DB_*=*|CLAWMANAGER_LEADER_ELECTION=*) export \"$entry\";; *) exit 41;; esac
done < \"$f\"
exec /usr/local/bin/system-backup-v2-controller
"""
        host_name = self.prefix + "-controller"
        pod_env = [{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}, {"name": "K8S_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                   {"name": "SYSTEM_BACKUP_ENABLED", "value": "false"}, {"name": "SYSTEM_BACKUP_EXECUTION_PROTOCOL", "value": "public-v1"}, {"name": "CLAWMANAGER_LEADER_ELECTION", "value": "true"}]
        pod_spec = {"serviceAccountName": controller["Name"], "automountServiceAccountToken": True, "nodeSelector": {"kubernetes.io/hostname": node_names[0]},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [
                {"name": "controller", "image": image_result["images"]["app"]["reference"], "command": ["/bin/sh", "-ec", launcher], "env": pod_env,
                 "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                 "volumeMounts": [{"name": "inputs", "mountPath": RUNTIME_MOUNT, "readOnly": True}, {"name": "staging", "mountPath": STAGING}]},
                {"name": "installation-owner", "image": image_result["images"]["app"]["reference"], "command": ["/bin/sh", "-ec", "umask 077; for d in " + RUNTIME + " " + PRIVATE + "; do if test ! -e \"$d\"; then mkdir -m 700 \"$d\"; fi; test ! -L \"$d\"; test \"$(stat -c %u:%a \"$d\")\" = 65532:700; done; while :; do sleep 3600; done"],
                 "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                 "volumeMounts": [{"name": "inputs", "mountPath": RUNTIME_MOUNT}, {"name": "private", "mountPath": PRIVATE_MOUNT}]}],
            "volumes": [{"name": name, "persistentVolumeClaim": {"claimName": obj["metadata"]["name"]}} for name, obj in pvcs.items()]}
        self.op.nonce_mount_profile(pod_spec)
        deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": host_name, "namespace": NS}, "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app.kubernetes.io/name": host_name}}, "template": {"metadata": {"labels": {"app.kubernetes.io/name": host_name}, "annotations": {MARKER: self.operation}}, "spec": pod_spec}}}
        actual = self.create_object("host-deployment-create", deployment)
        service = self.create_object("host-control-service-create", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": host_name, "namespace": NS},
            "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": host_name}, "ports": [{"name": "control-mtls", "port": 9443, "targetPort": 9443, "protocol": "TCP"}]}})
        identity = self.wait_host(actual, image_result["images"]["app"])
        self.op.verify_nonce_readable(self, identity)
        need(identity["ServiceAccountUID"] == controller["UID"], "original_controller_account_replaced")
        credentials = {"plan.json": enrolled["Plan"], "issuer-public.key": enrolled["IssuerPublic"], "enrollment-pin.json": enrolled["Enrollment"],
                       "installer.dsn": sql["files"]["mysql-installer.dsn"], "database-ca.pem": pin(Path(sql["source_tls"]["ca_file"])), "operator.kubeconfig.json": pin(self.op.kube), "admin-password": pin(PASSWORD)}
        for name, source in credentials.items():
            self.host_file(identity, "private-" + name.replace(".", "-"), PRIVATE + "/" + name, pinned(source))
        mirror = self.runtime_mirror()
        agent_tls_result = decode(read(self.directory / "runtime-agent-tls.result.json"))
        need(agent_tls_result["version"] == "operator-shared-agent-tls.v1" and agent_tls_result["operation"] == self.operation, "actual_same_operation_agent_tls_materials_required")
        agent_tls_material = decode(pinned(agent_tls_result["materials_receipt"]))
        need(agent_tls_material["Version"] == "original-shared-agent-tls-materials.v1" and agent_tls_material["ServerName"] == "lite-agent.clawmanager.internal" and agent_tls_material["Namespace"] == NS, "actual_agent_tls_ca_source_required")
        pinned(agent_tls_material["CA"])
        runtime_sources = {"runtime-agent-ca.pem": agent_tls_material["CA"], "observer-ca.pem": pki["CA"], "observer-client.pem": pki["ClientCertificate"], "observer-client-key.pem": pki["ClientKey"],
                           "database-ca.pem": pin(Path(sql["source_tls"]["ca_file"]))}
        for name, source in sql["files"].items():
            if name.startswith(("mysql-source", "mysql-runtime", "mysql-control_sql", "mysql-business")):
                runtime_sources[name] = source
        runtime_pins = {}
        for name, source in runtime_sources.items():
            raw = pinned(source)
            target = mirror / name
            if target.exists():
                need(read(target) == raw, "original_mirrored_runtime_bytes_changed")
                runtime_pins[name] = pin(target)
            else:
                runtime_pins[name] = write(target, raw)
            self.host_file(identity, "runtime-" + name.replace(".", "-"), str(target), raw)
        result = {"version": "operator-host-observer-result.v1", "state": "actual_final_host_waiting_and_native_observer_services_installed",
            "host": identity, "accounts": {"controller": controller, "worker": worker, "sources": sources}, "pvc_uids": {name: p["metadata"]["uid"] for name, p in pvcs.items()},
            "pki_definition": definition, "pki_receipt": pki_receipt, "host_materials_receipt": host_materials_receipt,
            "shared_runtime": {"protocol": "shared-container-freeze.v1", "owner_directory": shared_owner_directory, "cgroup_mount": "/sys/fs/cgroup", "agent_executables": shared_agents, "host_definition": host_definition, "agent_tls_materials": agent_tls_result["materials_receipt"]}, "actual_tls_handshakes": tls_checks,
            "installer_common_args": ["--plan-file", PRIVATE + "/plan.json", "--plan-sha256", enrolled["Plan"]["SHA256"], "--issuer-public-file", PRIVATE + "/issuer-public.key", "--issuer-public-sha256", enrolled["IssuerPublic"]["SHA256"], "--enrollment-pin-file", PRIVATE + "/enrollment-pin.json", "--enrollment-pin-sha256", enrolled["Enrollment"]["SHA256"], "--kubeconfig-file", PRIVATE + "/operator.kubeconfig.json", "--kubeconfig-sha256", digest(read(self.op.kube)), "--dsn-file", PRIVATE + "/installer.dsn", "--database-ca-file", PRIVATE + "/database-ca.pem", "--local-admin-password-file", PRIVATE + "/admin-password"],
            "runtime_output_directory": RUNTIME, "controller_process_started": False, "native_writer_proof_issued": False, "backup_ready": False}
        result["runtime_input_pins"] = runtime_pins
        result["sql_runtime_profile"] = "original_six_role_runtime_is_legacy14_not_full_public_controller"
        result["control_service"] = {"Name": service["metadata"]["name"], "UID": service["metadata"]["uid"], "ClusterIP": service["spec"]["clusterIP"],
                                     "SelectedURL": "https://" + host_name + "." + NS + ".svc:9443", "TLSListenerObserved": False}
        self.retain("host-observer.result.json", result)
        return result

    def wait_host(self, deployment, image):
        for _ in range(120):
            current = self.get("deployment", deployment["metadata"]["name"])
            need(current["metadata"]["uid"] == deployment["metadata"]["uid"] and current["spec"] == deployment["spec"], "final_host_spec_drift")
            pods = decode(self.op.k("-n", NS, "get", "pods", "-l", "app.kubernetes.io/name=" + deployment["metadata"]["name"], "-o", "json"))["items"]
            pods = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
            if len(pods) == 1 and pods[0]["status"].get("phase") == "Running":
                pod = pods[0]
                owner = only_controller(pod, "ReplicaSet")
                rs = self.get("replicaset", owner["name"])
                parent = only_controller(rs, "Deployment")
                need(rs["metadata"]["uid"] == owner["uid"] and parent["uid"] == deployment["metadata"]["uid"], "actual_host_owner_chain")
                states = {s["name"]: s for s in pod["status"].get("containerStatuses", [])}
                if set(states) == {"controller", "installation-owner"} and all(s.get("containerID") and "running" in s.get("state", {}) and s.get("ready") for s in states.values()):
                    need(all(image_id(s["imageID"]) in ("sha256:" + image["manifest_sha256"], image["config_digest"]) for s in states.values()), "actual_host_same_release_image")
                    sa = self.get("serviceaccount", pod["spec"]["serviceAccountName"])
                    return {"Deployment": deployment["metadata"]["name"], "DeploymentUID": deployment["metadata"]["uid"], "DeploymentSpecSHA256": digest(encoded(current["spec"])), "ReplicaSet": rs["metadata"]["name"], "ReplicaSetUID": rs["metadata"]["uid"], "Pod": pod["metadata"]["name"], "PodUID": pod["metadata"]["uid"], "PodSpecSHA256": digest(encoded(pod["spec"])), "ServiceAccount": sa["metadata"]["name"], "ServiceAccountUID": sa["metadata"]["uid"], "Containers": {name: {"ContainerID": state["containerID"], "ImageID": state["imageID"]} for name, state in states.items()}}
            time.sleep(2)
        raise Refused("host_rollout_unconfirmed_use_deployment_query")

    def check_host(self, identity):
        dep, pod = self.get("deployment", identity["Deployment"]), self.get("pod", identity["Pod"])
        need(dep["metadata"]["uid"] == identity["DeploymentUID"] and digest(encoded(dep["spec"])) == identity["DeploymentSpecSHA256"] and
             pod["metadata"]["uid"] == identity["PodUID"] and digest(encoded(pod["spec"])) == identity["PodSpecSHA256"] and pod["status"]["phase"] == "Running" and not pod["metadata"].get("deletionTimestamp"), "same_final_host_identity_required")
        states = {s["name"]: s for s in pod["status"].get("containerStatuses", [])}
        for name, expected in identity["Containers"].items():
            need(states[name]["containerID"] == expected["ContainerID"] and states[name]["imageID"] == expected["ImageID"] and "running" in states[name]["state"], "same_host_container_required")
        return pod

    def host_file(self, identity, stage, destination, raw):
        self.check_host(identity)
        need(destination.startswith((RUNTIME + "/", PRIVATE + "/")) and re.fullmatch(r"/[A-Za-z0-9_./-]+", destination) and ".." not in Path(destination).parts, "fixed_producer_destination_required")
        expected = digest(raw)
        script = "umask 077; test ! -e \"$1\"; test ! -L \"$1\"; cat > \"$1\"; test \"$(stat -c %u:%a \"$1\")\" = 65532:600; test \"$(sha256sum \"$1\" | cut -d ' ' -f 1)\" = \"$2\"; printf '{\"delivered\":true}\\n'"
        result, receipt = self.call(stage, ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", self.op.kube, "-n", NS, "exec", "-i", identity["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-ec", script, "sh", destination, expected], raw)
        self.check_host(identity)
        need(result == {"delivered": True}, "actual_file_delivery_unconfirmed")
        actual = self.op.k("-n", NS, "exec", identity["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-ec",
                           "test ! -L \"$1\"; test \"$(stat -c %u:%a \"$1\")\" = 65532:600; sha256sum \"$1\"", "sh", destination).decode("ascii").split()
        need(actual and actual[0] == expected, "current_host_file_readback_mismatch")
        self.check_host(identity)
        return {"File": destination, "SHA256": expected, "Readback": receipt}

    def host_exec(self, stage, binary, flags, common=True):
        selected = self.host_result()
        identity = selected["host"]
        self.check_host(identity)
        self.binary(binary)
        argv = ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", self.op.kube, "-n", NS, "exec", identity["Pod"], "-c", "installation-owner", "--", "/usr/local/bin/" + binary]
        if common:
            argv += selected["installer_common_args"]
        value, receipt = self.call(stage, [*argv, *flags])
        self.check_host(identity)
        return value, receipt

    def host_result(self):
        result = self.directory / "materials.result.json"
        if result.exists():
            material = decode(read(result))
            initial = decode(read(self.directory / "host-observer.result.json"))
            return {**initial, "host": material["host"]}
        return decode(read(self.directory / "host-observer.result.json"))

    def runtime_mirror(self):
        # Real production delivery files, not temporary test/build artifacts.
        parent = Path(RUNTIME_MOUNT)
        if not parent.exists():
            parent.mkdir(mode=0o700)
        need(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid() and parent.stat().st_mode & 0o022 == 0,
             "private_actual_operator_runtime_parent_required")
        directory = Path(RUNTIME)
        if not directory.exists():
            directory.mkdir(mode=0o700)
            write(directory / "operator-owner.json", encoded({"operation": self.operation, "run": str(self.run)}))
        need(directory.resolve(strict=True) == directory and decode(read(directory / "operator-owner.json")) == {"operation": self.operation, "run": str(self.run)}, "existing_runtime_directory_not_this_operation")
        return directory

    def deliver_runtime_tree(self, identity):
        directory = self.runtime_mirror()
        delivered = []
        for source in sorted(directory.rglob("*")):
            need(not source.is_symlink(), "runtime_delivery_link_refused")
            if source.is_dir():
                continue
            if source == directory/"registration-capacity.current.json":
                # This continuously sampled native report is atomically
                # transported by its original process, never sealed/replayed
                # by the immutable runtime material delivery pass.
                info = source.stat()
                need(info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_mode & 0o077 == 0 and
                     (self.run/"production-adoption/actual-capacity-collector-process.json").is_file(), "original_dynamic_capacity_report_owner_required")
                continue
            raw = read(source, limit=64 << 20)
            destination = str(source)
            relative = source.relative_to(directory)
            need(re.fullmatch(r"[A-Za-z0-9_./-]+", relative.as_posix()) and ".." not in relative.parts, "runtime_file_name_required")
            parent = str(source.parent)
            if parent != RUNTIME:
                self.check_host(identity)
                # Every selected path is a fixed descendant of the actual
                # private mirror; no caller command text is interpolated.
                self.op.k("-n", NS, "exec", identity["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-ec", "umask 077; mkdir -p -- \"$1\"; test ! -L \"$1\"; test \"$(stat -c %u:%a \"$1\")\" = 65532:700", "sh", parent)
            stage = "runtime-copy-" + digest((identity["PodUID"]+"/"+relative.as_posix()).encode())[:24]
            current = self.op.k("-n", NS, "exec", identity["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c",
                                'if test -e "$1"; then test -f "$1"; test ! -L "$1"; test "$(stat -c %u:%a "$1")" = 65532:600; sha256sum -- "$1"; else printf ABSENT; fi', "sh", destination).decode().split()
            if current == ["ABSENT"]:
                delivered.append(self.host_file(identity, stage, destination, raw))
            else:
                need(current and current[0] == digest(raw), "existing_original_runtime_file_changed_no_overwrite")
                self.check_host(identity)
                delivered.append({"File": destination, "SHA256": digest(raw)})
        return delivered

    def materials(self):
        initial = decode(read(self.directory / "host-observer.result.json"))
        self.check_host(initial["host"])
        common, _, _, _ = self.common()
        need(self.a.deployment_source_selection_file is not None and self.a.deployment_source_selection_sha256 and
             self.a.deployment_writer_selection_file is not None and self.a.deployment_writer_selection_sha256 and
             self.a.deployment_minio_options_file is not None and self.a.deployment_minio_options_sha256,
             "actual_source_writer_and_original_minio_producer_pins_required")
        selection = {"File": str(self.a.deployment_source_selection_file), "SHA256": self.a.deployment_source_selection_sha256}
        writer = {"File": str(self.a.deployment_writer_selection_file), "SHA256": self.a.deployment_writer_selection_sha256}
        options = {"File": str(self.a.deployment_minio_options_file), "SHA256": self.a.deployment_minio_options_sha256}
        selected, writers = decode(pinned(selection)), decode(pinned(writer))
        pinned(options)
        need(selected["Controller"]["PodUID"] == initial["host"]["PodUID"] and selected["Controller"]["DeploymentUID"] == initial["host"]["DeploymentUID"], "actual_initial_material_controller_required")
        config = decode(pinned(selected["Deployment"]))
        need(not config.get("publication_signers") and not config.get("publisher_verifier"), "uid_bound_publication_must_be_issued_after_material_rollout")
        base = self.get("deployment", initial["host"]["Deployment"])
        root = self.runtime_mirror()
        receipts, patches, objects = [], [], []
        actions = []
        if writers.get("RedisReadKeepers"):
            actions.append("prepare-redis-materials")
        if writers.get("PreAdoptionVaultDependencies"):
            actions.append("prepare-provider-materials")
        if writers.get("StoppedPro"):
            actions.append("prepare-observer-materials")
        actions.append("prepare-minio-materials")
        original_minio_receipt = None
        for action in actions:
            output = root / action
            output.mkdir(mode=0o700, exist_ok=True)
            flags = ["--source-selection-file", selection["File"], "--source-selection-sha256", selection["SHA256"], "--writer-selection-file", writer["File"], "--writer-selection-sha256", writer["SHA256"], "--controller-container", "controller", "--output-directory", output]
            if action == "prepare-minio-materials":
                flags += ["--definition-file", options["File"], "--definition-sha256", options["SHA256"]]
            result, result_pin = self.call(action, [self.binary("system-backup-source-registries"), action, *common, *flags])
            need(all(k in result for k in ("Deployment", "MaterialsTemplate", "SourceSelection", "DeploymentPatch")), "actual_native_material_receipt_shape")
            for key in ("Deployment", "MaterialsTemplate", "SourceSelection", "DeploymentPatch"):
                pinned(result[key])
            selection = result["SourceSelection"]
            if "WriterSelection" in result:
                pinned(result["WriterSelection"])
                writer = result["WriterSelection"]
            secret_pin = result.get("SecretManifests", result.get("SecretManifest"))
            manifest = decode(pinned(secret_pin))
            candidates = manifest["items"] if manifest.get("kind") == "List" else [manifest]
            need(all(o.get("kind") == "Secret" and o.get("immutable") is True and o["metadata"]["namespace"] == NS for o in candidates), "actual_immutable_material_secrets_required")
            objects += candidates
            patches.append(decode(pinned(result["DeploymentPatch"])))
            receipts.append({"action": action, "receipt": result_pin})
            if action == "prepare-minio-materials":
                need(result["Version"] == "formal-minio-material-delivery.v1", "actual_minio_delivery_receipt_required")
                original_minio_receipt = result_pin
        current = self.get("deployment", initial["host"]["Deployment"])
        need(current["metadata"]["uid"] == base["metadata"]["uid"] and current["spec"] == base["spec"], "material_controller_spec_changed_before_commit")
        desired = merge_material_patches(base, patches)
        for index, obj in enumerate(objects):
            self.create_object("material-secret-" + str(index), copy.deepcopy(obj))
        combined = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
                    {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                    {"op": "test", "path": "/spec", "value": base["spec"]}, {"op": "replace", "path": "/spec", "value": desired}]
        self.retain("material-final-rollout.plan.json", {"original": base, "desired_spec": desired, "producer_receipts": receipts, "original_minio_receipt": original_minio_receipt, "source_selection": selection, "writer_selection": writer})
        changed, _ = self.kubectl("material-final-rollout", ["patch", "deployment", current["metadata"]["name"], "--type=json", "--patch-file=/dev/stdin", "-o", "json"], combined)
        images = decode(read(self.directory / "new-image.result.json"))["images"]
        identity = self.wait_host(changed, images["app"])
        need(identity["ServiceAccountUID"] == initial["host"]["ServiceAccountUID"], "material_rollout_service_account_changed")
        # Refresh comparison DATA from the actual final graph. This is not a
        # facts receipt. D1 runs the real create-only facts producer AFTER all
        # native signing-role metadata has been issued in this final Pod.
        selected = decode(pinned(selection))
        selected["Controller"] = {"Namespace": NS, "NamespaceUID": initial["accounts"]["controller"]["NamespaceUID"], **{k: identity[k] for k in ("Deployment", "DeploymentUID", "ReplicaSet", "ReplicaSetUID", "Pod", "PodUID", "ServiceAccount", "ServiceAccountUID")}}
        final_selection = write(root / "source-selection.final-controller.json", encoded(selected))
        self.check_host(identity)
        delivered = self.deliver_runtime_tree(identity)
        result = {"version": "operator-materials-result.v1", "state": "actual_native_materials_delivered_final_controller_observed_before_uid_bound_issuance",
            "host": identity, "original_minio_delivery_receipt": original_minio_receipt, "SourceSelection": final_selection, "WriterSelection": writer,
            "Deployment": selected["Deployment"], "producer_receipts": receipts, "final_source_facts_produced": False,
            "delivered_file_pins": delivered, "runtime_directory": str(root), "uid_bound_publication_issued": False, "backup_ready": False}
        self.retain("materials.result.json", result)
        return result

    def publish_controller_environment(self, environment, producer_pins):
        """Called by D1 after concrete composition/issuer receipts exist.

        Values are literal environment data assembled by that owner workflow.
        This function adds no grant/config and does not submit a backup task.
        """
        host = self.host_result()["host"]
        self.check_host(host)
        need(isinstance(environment, dict) and environment and isinstance(producer_pins, list) and producer_pins, "actual_controller_environment_and_producer_pins_required")
        # Independently trusted ORIGINAL locator for the actual old/new
        # Forward reader. Never obtain this path or hash from metadata/task
        # JSON, the recovery projection or the newly issued v2 grant.
        forward = decode(read(self.directory / "initial-forward.result.json"))
        need(forward["version"] == "operator-initial-forward.v1" and forward["host"] == host, "same_original_forward_producer_and_host_required")
        original_forward = forward["grant"]
        native = decode(pinned(forward["native_receipt"]))
        need(native["Version"] == "original-runtime-execution-result.v1" and native["Grant"] == original_forward and native["ControllerPodUID"] == host["PodUID"], "actual_original_forward_native_receipt_required")
        pinned(original_forward, limit=65536)
        need(Path(original_forward["File"]).is_relative_to(self.runtime_mirror()), "original_forward_must_use_existing_readonly_runtime_mount")
        environment, producer_pins = dict(environment), list(producer_pins)
        for name, value in (("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE", original_forward["File"]), ("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256", original_forward["SHA256"])):
            need(name not in environment or environment[name] == value, "original_forward_trusted_locator_changed")
            environment[name] = value
        old_pins = [p for p in producer_pins if p["File"] == original_forward["File"]]
        need(len(old_pins) <= 1 and (not old_pins or old_pins[0]["SHA256"] == original_forward["SHA256"]), "original_forward_producer_pin_changed")
        if not old_pins:
            producer_pins.append(original_forward)
        # This descriptor was owner-authored and delivered BEFORE the actual
        # whole-cold dispatch. Its future file is now the original A-signed
        # projection, not an operator-created current-health statement.
        recovery = decode(read(self.op.run / "production-adoption/minio-recovery-preinstalled.json"))
        need(recovery["Version"] == "operator-original-minio-recovery-preinstall.v1" and recovery["Host"] == host and recovery["BackupReady"] is False, "same_original_pre_cold_recovery_descriptor_required")
        original_descriptor = recovery["Descriptor"]
        descriptor = decode(pinned(original_descriptor))
        descriptor_receipt = decode(pinned(recovery["NativeDescriptorReceipt"]))
        need(descriptor_receipt["Version"] == "original-minio-whole-cold-resource-locator.v1" and descriptor_receipt["State"] == "actual_original_sql_actor_pinned_future_projection_not_issued" and descriptor_receipt["Descriptor"] == original_descriptor, "actual_original_descriptor_native_receipt_required")
        terminal = decode(pinned(recovery["Terminal"]))
        need(terminal["RecoverySource"] == original_descriptor, "enable_terminal_and_controller_must_select_same_descriptor")
        dispatched = self.op.completed("adopt")
        actual_adoption = decode(read(Path(dispatched["stdout"]), dispatched["stdout_sha256"]))
        projection_receipt = actual_adoption["MinIORecoveryProjection"]
        need(actual_adoption["Version"] == "original-first-adoption-production.v1" and actual_adoption["State"] == "original_adoption_committed_sources_recovered_disabled_v1_dependencies_unverified" and projection_receipt["Version"] == "original-minio-whole-cold-resource-succession.v1" and projection_receipt["State"] == "original_whole_cold_history_projection_exact_readback_not_current_health", "actual_completed_original_whole_cold_recovery_required")
        projection = projection_receipt["Projection"]
        pinned(projection)
        need(descriptor["Version"] == "original-minio-whole-cold-resource-locator.v1" and descriptor["ProjectionFile"] == recovery["ProjectionFile"] == projection["File"] and Path(original_descriptor["File"]).is_relative_to(self.runtime_mirror()) and Path(projection["File"]).is_relative_to(self.runtime_mirror()), "same_preinstalled_projection_path_on_original_runtime_mount_required")
        for name, value in (("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_FILE", original_descriptor["File"]), ("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_SHA256", original_descriptor["SHA256"])):
            need(name not in environment or environment[name] == value, "original_minio_recovery_trusted_locator_changed")
            environment[name] = value
        for selected in (original_descriptor, projection):
            old = [p for p in producer_pins if p["File"] == selected["File"]]
            need(len(old) <= 1 and (not old or old[0] == selected), "original_minio_recovery_producer_pin_changed")
            if not old:
                producer_pins.append(selected)
        metadata = decode(read(self.op.run / "production-adoption/actual-minio-runtime-consent-selection.json"))
        need(metadata["Host"] == host and metadata["Descriptor"] == original_descriptor, "same_original_runtime_metadata_consent_source_required")
        actual_metadata = decode(pinned(metadata["NativeReceipt"]))
        consent = metadata["Consent"]
        need(actual_metadata["State"] == "original_runtime_metadata_consent_exact_readback_sql_enrollment_not_proven" and actual_metadata["Consent"] == consent, "actual_owner_runtime_metadata_consent_receipt_required")
        pinned(consent)
        need(Path(consent["File"]).is_relative_to(self.runtime_mirror()), "runtime_metadata_consent_original_readonly_mount_required")
        for name, value in (("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_FILE",consent["File"]),("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_SHA256",consent["SHA256"])):
            need(name not in environment or environment[name] == value, "original_runtime_metadata_consent_locator_changed")
            environment[name] = value
        selected_metadata = [v for v in producer_pins if v["File"] == consent["File"]]
        need(len(selected_metadata) <= 1 and (not selected_metadata or selected_metadata[0] == consent), "runtime_metadata_consent_producer_pin_changed")
        if not selected_metadata:
            producer_pins.append(consent)
        enabled = decode(read(self.op.run / "production-adoption/actual-enabled-publication-runtime-selection.json"))
        need(enabled["Host"] == host and enabled["OriginalForward"] == original_forward, "same_original_controller_and_forward_enabled_sources_required")
        native_enabled = decode(pinned(enabled["NativeReceipt"]))
        need(native_enabled["State"] == "enabled_owner_publication_materials_generated_original_sources_preserved" and native_enabled["Signers"] == enabled["Signers"] and native_enabled["Verifier"] == enabled["Verifier"], "actual_native_enabled_material_producer_required")
        for prefix, selected in (("SYSTEM_BACKUP_FORWARD_GRANT",enabled["Forward"]),("SYSTEM_BACKUP_VERIFIER_MATERIALS",enabled["Formal"]),("SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS",enabled["Signers"]),("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS",enabled["Verifier"])):
            pinned(selected)
            need(Path(selected["File"]).is_relative_to(self.runtime_mirror()), "actual_enabled_sources_original_readonly_runtime_mount_required")
            environment[prefix+"_FILE"] = selected["File"]
            environment[prefix+"_SHA256"] = selected["SHA256"]
            matching = [v for v in producer_pins if v["File"] == selected["File"]]
            need(len(matching)<=1 and (not matching or matching[0]==selected), "enabled_source_pin_changed")
            if not matching:
                producer_pins.append(selected)
        need(environment.get("SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE") and environment.get("SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_SHA256"), "actual_native_normal_relay_handover_binding_required")
        needed = {"SYSTEM_BACKUP_PUBLIC_CONFIG_FILE", "SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256", "SYSTEM_BACKUP_FORWARD_GRANT_SHA256",
                  "SYSTEM_BACKUP_RECOVERY_GRANT_SHA256", "SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE", "SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256",
                  "SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256", "SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE",
                  "SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256", "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256",
                  "SYSTEM_BACKUP_PUBLICATION_TARGET_FILE", "SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256", "SYSTEM_BACKUP_READINESS_MINIO_SOURCE_FILE",
                  "SYSTEM_BACKUP_READINESS_MINIO_SOURCE_SHA256", "SYSTEM_BACKUP_READINESS_MINIO_PROFILE", "SYSTEM_BACKUP_ENABLED", "DB_USER", "DB_PASSWORD",
                  "DB_HOST", "DB_PORT", "DB_NAME", "DB_TLS_CA_FILE", "DB_TLS_CA_SHA256", "DB_TLS_SERVER_NAME",
                  "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE", "SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256",
                  "SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_FILE", "SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_SHA256",
                  "SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_FILE", "SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_SHA256", "SYSTEM_BACKUP_FORWARD_GRANT_FILE",
                  "SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE", "SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_SHA256"}
        need(needed.issubset(environment) and all(environment[n] for n in needed), "complete_public_controller_environment_required")
        need(environment["SYSTEM_BACKUP_ENABLED"] == "true" and environment["SYSTEM_BACKUP_READINESS_MINIO_PROFILE"] in
             ("minio-2025-04-22-builtin-flat.v1", "minio-2025-09-07-builtin-flat.v1", "minio-2026-11-05-delete-compat-builtin-flat.v1"), "exact_controller_and_readiness_profile_required")
        files = {p["File"]: p for p in producer_pins}
        need(len(files) == len(producer_pins), "duplicate_controller_producer_file")
        for value in producer_pins:
            pinned(value, limit=64 << 20)
        for name in needed:
            if name.endswith("_FILE"):
                value = environment[name]
                need(value in files, "controller_runtime_file_without_actual_producer_pin")
                corresponding = name[:-5] + "_SHA256"
                if corresponding in environment:
                    need(environment[corresponding] == files[value]["SHA256"], "controller_environment_pin_not_producer_bytes")
        lines = []
        for name, value in sorted(environment.items()):
            need(re.fullmatch(r"(?:SYSTEM_BACKUP_[A-Z0-9_]+|DB_[A-Z0-9_]+|CLAWMANAGER_LEADER_ELECTION)", name) and
                 isinstance(value, str) and not any(c in value for c in "\r\n\x00"), "literal_controller_environment_required")
            lines.append(name + "=" + value)
        delivered = self.deliver_runtime_tree(host)
        for source in producer_pins:
            self.remote_pin(host, source)
        raw = ("\n".join(lines) + "\n").encode()
        env_file = self.host_file(host, "controller-environment", RUNTIME + "/controller.env", raw)
        self.retain("controller-activation-inputs.json", {"environment_sha256": digest(raw), "producer_pins": producer_pins, "host": host, "runtime_delivery": delivered})
        self.host_file(host, "controller-activation", RUNTIME + "/controller.env.ready", digest(raw).encode())
        self.check_host(host)
        result = {"state": "controller_start_signal_delivered_to_same_pod_no_readiness_claim", "host": host, "environment_file": env_file, "backup_ready": False}
        self.retain("controller-activation.result.json", result)
        return result

    def issuer_private(self):
        _, enrolled, _, _ = self.common()
        private = Path(enrolled["Plan"]["File"]).with_name("issuer.private")
        need(len(read(private, limit=64)) == 64, "original_enrolled_private_issuer_required")
        # The actual Go owner independently matches this key to its pinned Plan.
        return private

    def signing_material(self):
        material_result = decode(read(self.directory / "materials.result.json"))
        identity = material_result["host"]
        self.check_host(identity)
        state_directory = self.a.deployment_vault_state_directory or self.a.deployment_vault_owner_material_file.parent
        need(self.a.deployment_signing_until, "original_signing_deadline_required")
        state = decode(read(state_directory / "state.json"))
        report_pin = pin(state_directory / "public-report.json")
        report = decode(pinned(report_pin))
        _, _, plan, _ = self.common()
        need(report["schema_version"] == "d-transit-install-report.v1" and report["namespace"] == NS and
             report["namespace_uid"] == plan["Target"]["NamespaceUID"] and state["namespace_uid"] == report["namespace_uid"] and
             state["cluster_id"] == report["provider_cluster_id"] and state["jwt_mount"] == report["jwt_mount"] and
             report["endpoint"] == "https://" + state["prefix"] + "." + NS + ".svc:8200", "actual_original_vault_install_identity_required")
        owner_material = pin(self.a.deployment_vault_owner_material_file)
        ca = read(state_directory / "ca.pem", report["ca_sha256"], limit=65536)
        mirror = self.runtime_mirror()
        ca_file = mirror / "signing-provider-ca.pem"
        if not ca_file.exists():
            write(ca_file, ca)
        need(read(ca_file) == ca, "actual_original_vault_ca_mirror_changed")
        signing = report["signing"]
        need(set(signing) == {"capture", "acceptance", "catalog"}, "actual_three_existing_signing_keys_required")
        output = mirror / "original-signing"
        output.mkdir(mode=0o700, exist_ok=True)
        common, _, _, _ = self.common()
        flags = ["issue-signing-material", *common, "--source-issuer-private-file", self.issuer_private(),
                 "--controller-deployment", identity["Deployment"], "--controller-pod-name", identity["Pod"], "--output-directory", output,
                 "--vault-endpoint", report["endpoint"], "--vault-cluster-id", report["provider_cluster_id"], "--vault-jwt-mount", report["jwt_mount"],
                 "--capture-key", signing["capture"]["key_name"], "--acceptance-key", signing["acceptance"]["key_name"], "--catalog-key", signing["catalog"]["key_name"],
                 "--vault-ca-file", ca_file, "--vault-ca-sha256", report["ca_sha256"], "--vault-owner-material-file", owner_material["File"],
                 "--vault-owner-material-sha256", owner_material["SHA256"], "--vault-owner-material-is-init-json=true", "--until", self.a.deployment_signing_until]
        receipt, receipt_pin = self.call("original-signing-material", [self.binary("system-backup-first-install-materials"), *flags])
        self.check_host(identity)
        for name in ("Material", "RecordPin", "ResourceObserver", "CaptureObserver"):
            pinned(receipt[name])
        delivered = self.deliver_runtime_tree(identity)
        result = {"version": "operator-signing-material-result.v1", "state": "actual_original_signing_producer_completed_same_final_controller",
                  "host": identity, "original_signing_receipt": receipt_pin, "actual_producer_output": receipt, "vault_install_report": report_pin,
                  "delivered_runtime_files": delivered, "runtime_sql_owner_or_publisher_grant_issued": False, "backup_ready": False}
        self.retain("signing-material.result.json", result)
        return result

    def publication_authorization(self, core, config, forward_grant_sha256, runtime_dsn, request_files):
        """Use A r2's exact original first-install request/prebootstrap path.

        All authority, actual SQL row, original head and expiry checks remain in
        A's real existing CLI. Arguments select actual producer files only.
        """
        initial = decode(read(self.directory / "signing-material.result.json"))
        identity = initial["host"]
        self.check_host(identity)
        for value in (core, config, runtime_dsn, request_files):
            pinned(value)
        receipt = decode(pinned(initial["original_signing_receipt"]))
        signing_material = receipt["Material"]
        pinned(signing_material)
        output = self.runtime_mirror() / "publication-authorization"
        output.mkdir(mode=0o700, exist_ok=True)
        common, _, _, _ = self.common()
        _, _, _, sql_materials = self.common()
        action = "issue-initial-publication-authorization-minio-metadata" if sql_materials.get("runtime_profile") == "public-runtime-c1-minio-metadata-read.v1" else "issue-publication-authorization"
        value, output_pin = self.call("publication-authorization", [self.binary("system-backup-first-install-materials"), action, *common,
            "--source-issuer-private-file", self.issuer_private(), "--controller-deployment", identity["Deployment"], "--controller-pod-name", identity["Pod"],
            "--output-directory", output, "--runtime-dsn-file", runtime_dsn["File"], "--core-file", core["File"], "--core-sha256", core["SHA256"],
            "--request-files-file", request_files["File"], "--request-files-sha256", request_files["SHA256"],
            "--config-file", config["File"], "--config-sha256", config["SHA256"], "--forward-grant-sha256", forward_grant_sha256,
            "--signing-material-file", signing_material["File"], "--signing-material-sha256", signing_material["SHA256"]])
        self.check_host(identity)
        self.deliver_runtime_tree(identity)
        result = {"version": "operator-publication-authorization-result.v1", "state": "actual_original_publication_authorization_producer_completed",
                  "host": identity, "receipt": output_pin, "actual_producer_output": value, "configuration_enabled_by_this_action": False, "backup_ready": False}
        self.retain("publication-authorization.result.json", result)
        return result

    def remote_pin(self, identity, selected):
        need(selected["File"].startswith(RUNTIME + "/") and re.fullmatch(r"/[A-Za-z0-9_./-]+", selected["File"]) and ".." not in Path(selected["File"]).parts and re.fullmatch(r"[a-f0-9]{64}", selected["SHA256"]), "producer_runtime_file_pin_required")
        self.check_host(identity)
        observed = self.op.k("-n", NS, "exec", identity["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-ec",
            "test ! -L \"$1\"; test -f \"$1\"; test \"$(stat -c %u:%a \"$1\")\" = 65532:600; sha256sum \"$1\"", "sh", selected["File"]).decode("ascii").split()
        need(observed and observed[0] == selected["SHA256"], "actual_producer_runtime_bytes_changed")
        self.check_host(identity)

    def business_rollout(self, images, verify_only=False):
        app_plan = decode(read(self.directory / "new-image.plan.json"))
        app = self.get("deployment", "clawmanager-app")
        operation = decode(read(self.run / "operation.json"))
        replicas = operation["scope"]["app_replicas"]
        need(isinstance(replicas, int) and 1 <= replicas <= 16 and app["metadata"]["uid"] == app_plan["original_uid"], "actual_original_business_replica_policy_required")
        expected = copy.deepcopy(app_plan["desired_spec"])
        if app["spec"].get("replicas", 1) == 0:
            need(not verify_only, "original_business_app_stopped_no_readonly_restart")
            need(app["spec"] == expected, "complete_business_tls_template_required_before_start")
            patch = [{"op": "test", "path": "/metadata/uid", "value": app["metadata"]["uid"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": app["metadata"]["resourceVersion"]},
                     {"op": "test", "path": "/spec", "value": expected}, {"op": "replace", "path": "/spec/replicas", "value": replicas}]
            self.kubectl("business-app-start", ["patch", "deployment", "clawmanager-app", "--type=json", "--patch-file=/dev/stdin", "-o", "json"], patch)
        expected["replicas"] = replicas
        actual_pods = None
        for _ in range(120):
            app = self.get("deployment", "clawmanager-app")
            need(app["metadata"]["uid"] == app_plan["original_uid"] and app["spec"] == expected, "business_template_changed_during_rollout")
            selector = expected["selector"].get("matchLabels")
            need(selector and not expected["selector"].get("matchExpressions"), "finite_business_selector_required")
            pods = decode(self.op.k("-n", NS, "get", "pods", "-l", ",".join(k + "=" + v for k, v in sorted(selector.items())), "-o", "json"))["items"]
            live = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
            statuses = app.get("status", {})
            stable = len(live) == replicas and statuses.get("observedGeneration", 0) >= app["metadata"]["generation"] and statuses.get("updatedReplicas", 0) == replicas and statuses.get("availableReplicas", 0) == replicas
            if stable:
                actual_pods = []
                for pod in live:
                    owner = only_controller(pod, "ReplicaSet")
                    rs = self.get("replicaset", owner["name"])
                    parent = only_controller(rs, "Deployment")
                    need(rs["metadata"]["uid"] == owner["uid"] and parent["uid"] == app["metadata"]["uid"] and len(pod["spec"]["containers"]) == 1, "business_actual_owner_chain")
                    state = pod["status"].get("containerStatuses", [])
                    need(len(state) == 1 and state[0].get("ready") and "running" in state[0].get("state", {}) and state[0].get("containerID") and image_id(state[0]["imageID"]) in ("sha256:" + images["app"]["manifest_sha256"], images["app"]["config_digest"]), "business_actual_same_release_container")
                    # Native EOF hash inside the actual business container checks
                    # the real regular subPath CA file, not a ConfigMap claim.
                    observed = self.op.k("-n", NS, "exec", pod["metadata"]["name"], "-c", state[0]["name"], "--", "/bin/sh", "-ec",
                        "test ! -L /etc/clawmanager-business-mysql-ca/ca.crt; test -f /etc/clawmanager-business-mysql-ca/ca.crt; sha256sum /etc/clawmanager-business-mysql-ca/ca.crt").decode("ascii").split()
                    expected_ca = next(e["value"] for e in expected["template"]["spec"]["containers"][0]["env"] if e["name"] == "DB_TLS_CA_SHA256")
                    need(observed and observed[0] == expected_ca, "actual_business_ca_file_readback")
                    current = self.get("pod", pod["metadata"]["name"])
                    need(current["metadata"]["uid"] == pod["metadata"]["uid"] and current["status"]["containerStatuses"][0]["containerID"] == state[0]["containerID"], "business_actor_changed_during_readback")
                    actual_pods.append({"Pod": pod["metadata"]["name"], "PodUID": pod["metadata"]["uid"], "ReplicaSetUID": rs["metadata"]["uid"], "ContainerID": state[0]["containerID"], "ImageID": state[0]["imageID"], "CAFileSHA256": expected_ca})
                break
            need(not verify_only, "original_business_app_not_ready_no_readonly_wait_or_restart")
            time.sleep(2)
        need(actual_pods is not None, "business_rollout_unconfirmed_use_deployment_query")
        return app, actual_pods

    def query(self):
        # Read-only native query. It does not infer completion from a retained
        # intent, delete resources, roll out a Pod or resend an unknown action.
        app = self.get("deployment", "clawmanager-app")
        out = {"version": "operator-deployment-query.v1", "state": "actual_objects_read_no_native_resend", "operation": self.operation,
               "app": {"UID": app["metadata"]["uid"], "SpecSHA256": digest(encoded(app["spec"])), "replicas": app["spec"].get("replicas", 1)}, "unknown_sends": [], "backup_ready": False}
        for intent in sorted(self.directory.glob("*.send-unknown.json")):
            result = intent.with_name(intent.name.replace(".send-unknown.json", ".readback.json"))
            if not result.exists():
                out["unknown_sends"].append(intent.name)
        if (self.directory / "host-observer.result.json").exists():
            host = decode(read(self.directory / "host-observer.result.json"))
            self.check_host(host["host"])
            out["host"] = host["host"]
        self.retain("query-" + secrets.token_hex(8) + ".json", out)
        return out


def dispatch(operator, action):
    stages = DeploymentStages(operator)
    if action == "new-image":
        return stages.new_image()
    if action == "host-observer":
        return stages.host_observer()
    if action == "materials":
        return stages.materials()
    if action == "materials-signing":
        return stages.signing_material()
    if action == "deployment-query":
        return stages.query()
    raise Refused("unknown_owned_deployment_action")
