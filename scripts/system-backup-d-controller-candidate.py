#!/usr/bin/env python3
"""Offline paused controller candidate. No kubectl, credentials issuance or activation.

Checks byte pins and explicit mounted references only. It does not authenticate
owner review, grant signatures, SQL permissions, TLS or live Kubernetes UIDs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

VERSION = "system-backup-controller-candidate.v1"
PAIRS = (
    ("SYSTEM_BACKUP_PUBLIC_CONFIG_FILE", "SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256"),
    ("SYSTEM_BACKUP_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_VERIFIER_MATERIALS_SHA256"),
    ("SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_FILE", "SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS_SHA256"),
    ("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE", "SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256"),
    ("SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE", "SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256"),
    ("SYSTEM_BACKUP_PUBLICATION_TARGET_FILE", "SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256"),
)
READINESS_PAIR = ("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_FILE", "SYSTEM_BACKUP_READINESS_MINIO_SOURCE_SHA256")
READINESS_PROFILE_ENV = "SYSTEM_BACKUP_READINESS_MINIO_PROFILE"
# Closed compatibility declarations from systembackupminioauthority.NativeProfile;
# selecting one never proves native version, current permissions or readiness.
READINESS_SOURCES = {
    "minio-2025-04-22-builtin-flat.v1": "minio-publication-effective-permission-source.v2",
    "minio-2025-09-07-builtin-flat.v1": "minio-publication-september-effective-permission-source.v1",
    "minio-2026-11-05-delete-compat-builtin-flat.v1": "minio-publication-delete-compat-effective-permission-source.v1",
}
PUBLICATION_POLICY_PROTOCOL = "system-backup-original-publication-policy.v1"


def require(value):
    if not value:
        raise ValueError("candidate_rejected")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def image(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[0-9a-f]{64}", value)


def absolute(value):
    require(isinstance(value, str) and value.startswith("/") and str(PurePosixPath(value)) == value)
    require(".." not in PurePosixPath(value).parts and "\\" not in value and not any(ord(c) < 32 for c in value))
    return value


def local_bytes(root, item):
    require(set(item) >= {"file", "sha256"} and pin(item["sha256"]))
    relative = Path(item["file"])
    require(not relative.is_absolute() and ".." not in relative.parts)
    source = root / relative
    require(not source.is_symlink())
    resolved = source.resolve(strict=True)
    require(root in resolved.parents and resolved.is_file() and resolved.stat().st_size <= 16 * 1024 * 1024)
    raw = resolved.read_bytes()
    require(sha(raw) == item["sha256"])
    return raw


def mounted_refs(pod, container, destination):
    result = []
    volumes = {v["name"]: v for v in pod.get("volumes", [])}
    require(len(volumes) == len(pod.get("volumes", [])))
    for mount in container.get("volumeMounts", []):
        prefix = absolute(mount["mountPath"])
        # This narrow entry consumes directory mounts; no file subPath ambiguity.
        if not destination.startswith(prefix.rstrip("/") + "/"):
            continue
        require(mount.get("readOnly") is True and not mount.get("subPath") and not mount.get("subPathExpr"))
        relative = destination[len(prefix.rstrip("/")) + 1:]
        volume = volumes[mount["name"]]
        sources = volume.get("projected", {}).get("sources", [volume])
        for source in sources:
            for kind, field, name_field in (("Secret", "secret", "name"), ("ConfigMap", "configMap", "name")):
                ref = source.get(field)
                if ref is None:
                    continue
                require(not ref.get("optional", False))
                # Non-projected Secret volumes use secretName.
                name = ref.get(name_field, ref.get("secretName"))
                items = ref.get("items")
                if items is None:
                    if "/" not in relative:
                        result.append((kind, name, relative))
                else:
                    for item in items:
                        if item["path"] == relative:
                            result.append((kind, name, item["key"]))
    return result


def prepare(plan_path):
    root = plan_path.resolve(strict=True).parent
    require(plan_path.stat().st_size <= 1024 * 1024)
    plan = decode(plan_path.read_bytes())
    require(set(plan) == {"schema_version", "release_commit", "namespace", "namespace_uid", "app_image", "worker_image", "service_account", "deployment", "files"})
    require(plan["schema_version"] == VERSION and re.fullmatch(r"[0-9a-f]{40}", plan["release_commit"]))
    require(image(plan["app_image"]) and image(plan["worker_image"]))
    require(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", plan["namespace"]))
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", plan["namespace_uid"]))
    require(set(plan["deployment"]) == {"file", "sha256"})
    manifest = decode(local_bytes(root, plan["deployment"]))
    require(manifest["apiVersion"] == "apps/v1" and manifest["kind"] == "Deployment")
    require(manifest["metadata"]["namespace"] == plan["namespace"])
    require(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", manifest["metadata"]["name"]))
    spec = manifest["spec"]
    require(type(spec["replicas"]) is int and spec["replicas"] == 0)
    selector = spec["selector"]["matchLabels"]
    require(selector and all(spec["template"]["metadata"]["labels"].get(k) == v for k, v in selector.items()))
    pod = spec["template"]["spec"]
    require(set(plan["service_account"]) == {"name", "uid"} and plan["service_account"]["uid"])
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", plan["service_account"]["uid"]))
    require(pod["serviceAccountName"] == plan["service_account"]["name"])
    require(len(pod["containers"]) == 1 and not pod.get("initContainers"))
    container = pod["containers"][0]
    require(container["image"] == plan["app_image"])
    require(container["command"] == ["/usr/local/bin/system-backup-v2-controller"] and not container.get("args"))
    require(not container.get("envFrom"))
    env = {e["name"]: e for e in container["env"]}
    require(len(env) == len(container["env"]))
    require(env["SYSTEM_BACKUP_EXECUTION_PROTOCOL"].get("value") == "public-v1")
    require(env["SYSTEM_BACKUP_ENABLED"].get("value") == "false")
    pod_name_source = env["POD_NAME"].get("valueFrom")
    require(isinstance(pod_name_source, dict) and set(pod_name_source) == {"fieldRef"})
    pod_name_field = pod_name_source["fieldRef"]
    require(isinstance(pod_name_field, dict) and set(pod_name_field) in ({"fieldPath"}, {"apiVersion", "fieldPath"}))
    require(pod_name_field["fieldPath"] == "metadata.name" and pod_name_field.get("apiVersion", "v1") == "v1")
    require(env["CLAWMANAGER_LEADER_ELECTION"].get("value") == "true")
    # Actual DB credentials must remain existing secret refs, never inline bytes.
    for name in ("DB_USER", "DB_PASSWORD"):
        require(set(env[name]) == {"name", "valueFrom"})
        ref = env[name]["valueFrom"]["secretKeyRef"]
        require(ref.get("name") and ref.get("key") and not ref.get("optional", False))
    require(isinstance(plan["files"], list) and 1 <= len(plan["files"]) <= 256)
    materials = {}
    for item in plan["files"]:
        require(set(item) == {"file", "sha256", "mount_path", "kind", "name", "key"})
        destination = absolute(item["mount_path"])
        require(destination not in materials and item["kind"] in ("Secret", "ConfigMap") and item["name"] and item["key"])
        require(mounted_refs(pod, container, destination) == [(item["kind"], item["name"], item["key"])])
        materials[destination] = (item, local_bytes(root, item))
    # Runtime requires an explicit profile and independent permission-source
    # pin even though this candidate remains paused/recovery-only. No default,
    # envFrom or projected environment value is an independently reviewed pin.
    for name in (*READINESS_PAIR, READINESS_PROFILE_ENV):
        require(name in env and set(env[name]) == {"name", "value"})
        require(isinstance(env[name]["value"], str) and env[name]["value"])
    profile = env[READINESS_PROFILE_ENV]["value"]
    require(profile in READINESS_SOURCES)
    for file_env, hash_env in PAIRS + (READINESS_PAIR,):
        destination = env[file_env]["value"]
        absolute(destination)
        require(pin(env[hash_env]["value"]) and destination in materials
                and env[hash_env]["value"] == materials[destination][0]["sha256"])
    readiness = decode(materials[env[READINESS_PAIR[0]]["value"]][1])
    require(isinstance(readiness, dict) and readiness.get("Version") == READINESS_SOURCES[profile])
    config = decode(materials[env[PAIRS[0][0]]["value"]][1])
    require(config["schema_version"] == "system-backup-public-deployment.v1" and config["capture_scope"] == "six-part")
    require(config["namespace"] == plan["namespace"] and config["namespace_uid"] == plan["namespace_uid"])
    require(config["worker_image"] == plan["worker_image"])
    for field, pair in zip(("formal_verifier", "publication_signers", "publisher_verifier", "capture_modules", "publication_target"), PAIRS[1:]):
        require(config[field]["path"] == env[pair[0]]["value"])
    capture = decode(materials[env[PAIRS[4][0]]["value"]][1])
    require(isinstance(capture, dict) and capture.get("Version") == "original-six-part-capture-materials.v1")
    discovery = capture.get("Discovery")
    require(isinstance(discovery, dict))
    policy = discovery.get("PublicationPolicy")
    require(isinstance(policy, dict) and set(policy) == {"Protocol", "Path", "SHA256"})
    require(policy["Protocol"] == PUBLICATION_POLICY_PROTOCOL and pin(policy["SHA256"]))
    policy_path = absolute(policy["Path"])
    # Every materials entry was already matched to exactly one actual readonly
    # Secret/ConfigMap projection above, and its local bytes checked by SHA.
    require(policy_path in materials and materials[policy_path][0]["sha256"] == policy["SHA256"])
    policy_body = decode(materials[policy_path][1])
    require(isinstance(policy_body, dict) and policy_body.get("schema_version") == PUBLICATION_POLICY_PROTOCOL)
    for field in ("profile_file", "capacity_file", "source_dsn_file", "server_certificate", "server_key", "issuer_certificate", "issuer_key"):
        require(config[field] in materials)
    for field, hash_env in (("forward_grant", "SYSTEM_BACKUP_FORWARD_GRANT_SHA256"), ("recovery_grant", "SYSTEM_BACKUP_RECOVERY_GRANT_SHA256")):
        destination = config[field]["path"]
        require(destination in materials and env[hash_env]["value"] == materials[destination][0]["sha256"])
    key_directory = absolute(config["key_directory"])
    require(any(path.startswith(key_directory.rstrip("/") + "/") for path in materials))
    report = {"schema_version": VERSION, "scope": "offline byte-pins and mounted-reference checks only", "replicas": 0,
              "forward_enabled": False, "namespace": plan["namespace"], "namespace_uid": plan["namespace_uid"],
              "release_commit": plan["release_commit"], "deployment_sha256": plan["deployment"]["sha256"],
              "files_checked": len(materials), "cluster_contacted": False, "authorization_verified": False,
              "live_resources_verified": False, "full_acceptance": False}
    return manifest, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True, help="private reviewed plan JSON; local file paths relative to its directory")
    parser.add_argument("--output", type=Path, help="new private directory for candidate JSON and report; no apply")
    args = parser.parse_args()
    manifest, report = prepare(args.plan)
    if args.output:
        # Validation finishes before creating any output; never overwrite a bundle.
        args.output.mkdir(mode=0o700)
        for filename, value in (("controller.paused.json", manifest), ("report.json", report)):
            target = args.output / filename
            with target.open("x", encoding="utf-8") as stream:
                os.chmod(target, 0o600)
                json.dump(value, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("Controller candidate rejected; check reviewed inputs, file pins and mounts. Private contents withheld; no cluster contacted.")
