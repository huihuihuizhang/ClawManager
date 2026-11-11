#!/usr/bin/env python3
"""Renew validation runtime TLS, apply guarded rollout, and read back TLS."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone

NS = "clawmanager-sbk-validation-system"
ROOT = Path("/root/sbk/p2-runtime-rollout.us14OMgn")
WORK = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
ENR = WORK / "fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native"
KUBE = WORK / "operator.kubeconfig.yaml"
EXPECTED = {
    "hermes-runtime": ("de547f9b-b21a-45b3-9d74-c77ce35ab0d4", "hermes", "a2473da0cf375ed128116af3083eccd3276665adac4ae2722edcbff6cc277353"),
    "openclaw-runtime": ("baf19cae-4476-4d1c-a9c8-884fd13077d2", "openclaw", "5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140"),
}
CONFIG_DIGESTS = {
    "hermes-runtime": "e5ff8986745359feab85ab53d6299e6e4026b8bfc7adeee72e34747a36b529ee",
    "openclaw-runtime": "942dd8a82d877b0953308bb2e80f6631a1697b7f06eac5caab36b5572a0d2bb2",
}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def save(path, value):
    with path.open("x", encoding="utf-8") as file:
        json.dump(value, file, sort_keys=True)
        file.write("\n")


def pinned(pin):
    raw = Path(pin["File"]).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == pin["SHA256"], "material pin mismatch")
    return raw


def call(label, argv, data=None):
    result = subprocess.run([str(x) for x in argv], input=data, capture_output=True, text=True)
    with (ROOT / (label + ".stdout.private")).open("a", encoding="utf-8") as out:
        out.write(result.stdout)
    with (ROOT / (label + ".stderr.private")).open("a", encoding="utf-8") as out:
        out.write(result.stderr)
    need(result.returncode == 0, label + " failed; inspect its private stderr log")
    return result.stdout


def kube(label, *args, data=None):
    return call(label, ["kubectl", "--kubeconfig", KUBE, "--request-timeout=20s", "-n", NS, *args], data)


def get(kind, name):
    return json.loads(kube("read-" + kind + "-" + name, "get", kind, name, "-o", "json"))


def main():
    os.umask(0o077)
    need(ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_mode & 0o077 == 0, "private rollout directory required")
    print("Rollout records", ROOT, flush=True)
    plan_file = ROOT / "runtime-tls-rollout.plan.private.json"
    receipt_file = ROOT / "runtime-agent-tls.receipt.private.json"
    if not plan_file.exists():
        originals = {d["metadata"]["name"]: d for d in json.loads((ROOT / "runtime-deployments.private.json").read_bytes())["items"]}
        need(set(originals) == set(EXPECTED), "original deployment roster mismatch")
        for name, (uid, kind, digest) in EXPECTED.items():
            current = get("deployment", name)
            need(current["metadata"]["uid"] == uid and current["spec"] == originals[name]["spec"], "original deployment changed: " + name)
        if not receipt_file.exists():
            definition = {"Version": "original-shared-agent-tls-definition.v1", "SecretPrefix": "sbk-p2-" + hashlib.sha256(str(ROOT).encode()).hexdigest()[:12], "ValiditySeconds": 86400}
            definition_file = ROOT / "runtime-agent-tls.definition.canonical.json"
            definition_raw = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if definition_file.exists():
                need(definition_file.read_bytes() == definition_raw, "TLS definition changed")
            else:
                with definition_file.open("xb") as file:
                    file.write(definition_raw)
            directory = ROOT / "runtime-agent-tls"
            directory.mkdir(mode=0o700, exist_ok=True)
            args = ["/root/sbk/bin/system-backup-observer-deployment-materials", "--mode", "shared-agent-tls"]
            pins = [
                ("plan", ENR / "original-enrollment-plan.json", "a0aa44b5a12a453c352a402e73c4f4d42a675b2430d2cb69972a29df1f859752"),
                ("issuer-public", ENR / "issuer.public", "8a2df27b26737198ba78e49f5291bb53ad283e42099d228e1ba5762c6d318ac6"),
                ("enrollment-pin", ENR / "original-enrollment-pin.json", "ba649013288b0b62fb111e74ce151f344ad76169b8c9206da47fa1580b086256"),
                ("kubeconfig", KUBE, "152d2049f8b1c3e9e043ed024bae24cf2253aa3b8da19bf1c67f9fa9a9979bde"),
            ]
            for flag, path, digest in pins:
                pinned({"File": str(path), "SHA256": digest})
                args += ["--" + flag + "-file", path, "--" + flag + "-sha256", digest]
            args += ["--dsn-file", WORK / "fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn",
                     "--database-ca-file", WORK / "mysql-source-ca.pem", "--local-admin-password-file", WORK / "fresh-backup-bootstrap/admin-password",
                     "--definition-file", definition_file, "--definition-sha256", hashlib.sha256(definition_file.read_bytes()).hexdigest(), "--output-directory", directory]
            print("Issuing runtime TLS materials", flush=True)
            save(receipt_file, json.loads(call("issue-runtime-agent-tls", args)))
        receipt = json.loads(receipt_file.read_bytes())
        need(receipt["Version"] == "original-shared-agent-tls-materials.v1" and receipt["Status"] == "materialized_uninstalled_no_native_source_proof" and receipt["Namespace"] == NS, "unexpected TLS receipt")
        targets = {t["Deployment"]: t for t in receipt["Targets"]}
        need(set(targets) == set(EXPECTED), "TLS target roster mismatch")
        plans = []
        for name, (uid, kind, digest) in EXPECTED.items():
            original = originals[name]
            target = targets[name]
            need(target["DeploymentUID"] == uid and target["DeploymentGeneration"] == original["metadata"]["generation"], "TLS target identity mismatch")
            desired = copy.deepcopy(original["spec"])
            pod = desired["template"]["spec"]
            need(len(pod["containers"]) == 1 and pod["containers"][0]["name"] == "runtime" and not pod.get("initContainers"), "runtime shape changed")
            container = pod["containers"][0]
            image = "10.130.14.23:5000/" + kind + "-lite@sha256:" + digest
            container["image"] = image
            values = {"CLAWMANAGER_RUNTIME_DEPLOYMENT_NAME": name, "CLAWMANAGER_DEPLOYMENT_NAME": name,
                      "CLAWMANAGER_RUNTIME_IMAGE_REF": image, "CLAWMANAGER_RUNTIME_IMAGE_DIGEST": "sha256:" + digest,
                      "RUNTIME_AGENT_TLS_CERT_FILE": "/run/clawmanager-agent-tls/tls.crt", "RUNTIME_AGENT_TLS_KEY_FILE": "/run/clawmanager-agent-tls/tls.key"}
            env = container.setdefault("env", [])
            need(len({e["name"] for e in env}) == len(env), "duplicate runtime environment")
            need(not any(e["name"].startswith("RUNTIME_AGENT_TLS_") for e in env), "existing runtime TLS requires reconciliation")
            for key, value in values.items():
                env[:] = [e for e in env if e["name"] != key]
                env.append({"name": key, "value": value})
            if not any(e["name"] == "POD_UID" for e in env):
                env.append({"name": "POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}})
            mount_root = "/run/clawmanager-agent-tls"
            for mount in container.get("volumeMounts", []):
                path = mount["mountPath"].rstrip("/") or "/"
                need(path != "/" and path != mount_root and not path.startswith(mount_root + "/") and not mount_root.startswith(path + "/"), "TLS mount collision")
            need(not any(v["name"] == "sbk-shared-agent-tls" for v in pod.get("volumes", [])), "TLS volume collision")
            container.setdefault("volumeMounts", []).append({"name": "sbk-shared-agent-tls", "mountPath": mount_root, "readOnly": True})
            pod.setdefault("volumes", []).append({"name": "sbk-shared-agent-tls", "secret": {"secretName": target["SecretName"], "defaultMode": 256,
                "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}})
            desired["strategy"] = {"type": "Recreate"}
            plans.append({"name": name, "uid": uid, "original": original["spec"], "desired": desired, "target": target})
        save(plan_file, {"receipt": receipt, "deployments": plans})
    plan = json.loads(plan_file.read_bytes())
    receipt = plan["receipt"]
    need(datetime.fromisoformat(receipt["NotAfter"].replace("Z", "+00:00")) > datetime.now(timezone.utc), "runtime TLS expired; reconcile this plan before issuing again")
    pinned(receipt["CA"])
    readbacks = []
    for entry in plan["deployments"]:
        name = entry["name"]
        current = get("deployment", name)
        need(current["metadata"]["uid"] == entry["uid"] and current["spec"] in (entry["original"], entry["desired"]), "deployment drift: " + name)
        target = entry["target"]
        pinned(target["Certificate"])
        pinned(target["PrivateKey"])
        manifest = json.loads(pinned(target["SecretManifest"]))
        existing = kube("find-secret-" + name, "get", "secret", target["SecretName"], "--ignore-not-found", "-o", "json")
        secret = json.loads(existing) if existing.strip() else json.loads(kube("create-secret-" + name, "create", "-f", "-", "-o", "json", data=json.dumps(manifest)))
        need(secret.get("immutable") is True and secret.get("type") == manifest["type"] and secret["data"] == manifest["data"] and not secret["metadata"].get("deletionTimestamp"), "TLS Secret mismatch")
    for entry in plan["deployments"]:
        name = entry["name"]
        current = get("deployment", name)
        need(current["metadata"]["uid"] == entry["uid"], "deployment replaced")
        if current["spec"] != entry["desired"]:
            need(current["spec"] == entry["original"], "deployment drift: " + name)
            patch = [{"op": "test", "path": "/metadata/uid", "value": entry["uid"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                     {"op": "test", "path": "/spec", "value": entry["original"]},
                     {"op": "replace", "path": "/spec", "value": entry["desired"]}]
            kube("dry-run-" + name, "patch", "deployment", name, "--type=json", "--patch-file=/dev/stdin", "--dry-run=server", "-o", "json", data=json.dumps(patch))
            print("Rolling out", name, "with Recreate", flush=True)
            kube("patch-" + name, "patch", "deployment", name, "--type=json", "--patch-file=/dev/stdin", "-o", "json", data=json.dumps(patch))
        call("wait-" + name, ["kubectl", "--kubeconfig", KUBE, "--request-timeout=20s", "-n", NS, "rollout", "status", "deployment/" + name, "--timeout=240s"])
        current = get("deployment", name)
        need(current["metadata"]["uid"] == entry["uid"] and current["spec"] == entry["desired"], "post-rollout deployment drift")
        selector = ",".join(k + "=" + v for k, v in current["spec"]["selector"]["matchLabels"].items())
        pods = json.loads(kube("pods-" + name, "get", "pods", "-l", selector, "-o", "json"))["items"]
        active = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
        need(len(active) == current["spec"].get("replicas", 1), "runtime Pod roster mismatch")
        for pod in active:
            statuses = pod["status"].get("containerStatuses", [])
            need(pod["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"), "runtime Pod not ready")
            owner = next(o for o in pod["metadata"]["ownerReferences"] if o.get("controller"))
            need(owner["kind"] == "ReplicaSet", "runtime Pod owner mismatch")
            rs = get("replicaset", owner["name"])
            need(rs["metadata"]["uid"] == owner["uid"] and any(o.get("controller") and o["kind"] == "Deployment" and o["uid"] == entry["uid"] for o in rs["metadata"]["ownerReferences"]), "runtime ReplicaSet owner mismatch")
            need(pod["spec"]["containers"][0]["image"] == entry["desired"]["template"]["spec"]["containers"][0]["image"], "runtime Pod image mismatch")
            actual_container = pod["spec"]["containers"][0]
            desired_container = entry["desired"]["template"]["spec"]["containers"][0]
            need(all(actual_container.get(key) == desired_container.get(key) for key in ("command", "args", "env", "envFrom", "workingDir")), "runtime admission changed startup")
            image_id = statuses[0]["imageID"]
            allowed = ["sha256:" + EXPECTED[name][2], "sha256:" + CONFIG_DIGESTS[name]]
            need(any(image_id == value or image_id.endswith("@" + value) or image_id == "containerd://" + value or image_id == "docker://" + value for value in allowed), "loaded runtime image digest mismatch")
            context = ssl.create_default_context(cafile=receipt["CA"]["File"])
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((pod["status"]["podIP"], 19090), timeout=15) as tcp:
                with context.wrap_socket(tcp, server_hostname=receipt["ServerName"]) as tls:
                    uris = [value for kind, value in tls.getpeercert().get("subjectAltName", ()) if kind == "URI"]
                    need(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() == entry["target"]["ServerCertificateDERSHA256"] and uris == [entry["target"]["ServerURI"]], "runtime TLS identity mismatch")
            print("RUNTIME_TLS_OK", name, pod["metadata"]["name"], pod["metadata"]["uid"], statuses[0]["imageID"], flush=True)
            readbacks.append({"deployment": name, "deployment_uid": entry["uid"], "pod": pod["metadata"]["name"], "pod_uid": pod["metadata"]["uid"], "image_id": image_id, "certificate_der_sha256": entry["target"]["ServerCertificateDERSHA256"]})
    save(ROOT / ("runtime-tls-readback-" + str(time.time_ns()) + ".json"), {"namespace": NS, "ca": receipt["CA"], "not_after": receipt["NotAfter"], "runtimes": readbacks})
    print("RUNTIME_ROLLOUT_TLS_PASSED", ROOT, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ROLLOUT_UNCONFIRMED", str(error), "records", ROOT, flush=True)
        raise SystemExit(1)
