#!/usr/bin/env python3
"""Inspect the pinned Hermes candidate in a disposable, credential-free Pod."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

KUBE = "/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml"
NS = "clawmanager-sbk-validation-system"
DIGEST = "sha256:47729188347a01d249d5a929e474b3bb9959a138c138031a84ec39a7c6412cc7"
IMAGE = "10.130.14.23:5000/hermes-lite@" + DIGEST
PROBE = r'''
import hashlib, json, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path("/usr/local/share/hermes-lite")
result = {"files": {}}
for name in ("start-hermes-lite-runtime", "start-hermes-lite-backend", "hermes-lite-entrypoint", "clawmanager-agent"):
    path = pathlib.Path("/usr/local/bin") / name
    result["files"][name] = {"exists": path.is_file(), "executable": os.access(path, os.X_OK)}
    if path.is_file():
        result["files"][name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
for name in ("source-lock.json", "release.json"):
    path = root / name
    if path.is_file():
        data = json.loads(path.read_bytes())
        result[name] = {key: data.get(key) for key in (
            "schema_version", "tag", "commit", "package_version", "hermes_ref", "hermes_commit",
            "backend_mode", "rpc_protocol", "payload_sha256", "desktop_web_accepted") if key in data}
result["release_verification_exit_code"] = None
if (root / "verify_lite_release.py").is_file() and (root / "source-lock.json").is_file():
    completed = subprocess.run([sys.executable, "-B", str(root / "verify_lite_release.py"),
        "--lock", str(root / "source-lock.json"), "--verify-release"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=90)
    result["release_verification_exit_code"] = completed.returncode
    # The image-owned verifier reports managed paths/hashes, without business credentials.
    result["release_verification_output"] = completed.stdout[-3000:]
with tempfile.TemporaryDirectory(prefix="sbk-hermes-help-") as directory:
    env = dict(os.environ, HOME=directory, HERMES_HOME=directory + "/.hermes", PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run(["hermes", "serve", "--help"], env=env, cwd=directory,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=30)
    output = completed.stdout.lower()
    result["serve_help"] = {"exit_code": completed.returncode,
        "has_isolated_option": "--isolated" in output, "has_host_option": "--host" in output,
        "has_port_option": "--port" in output}
result["startup_files_and_cli_verified"] = (
    all(item["exists"] and item["executable"] for item in result["files"].values())
    and result["release_verification_exit_code"] == 0
    and result["serve_help"]["exit_code"] == 0
    and all(result["serve_help"][key] for key in ("has_isolated_option", "has_host_option", "has_port_option")))
print(json.dumps(result, ensure_ascii=False))
'''


def main():
    os.umask(0o077)
    records = Path(tempfile.mkdtemp(prefix="p2-hermes-candidate.", dir="/root/sbk"))
    name = "sbk-hermes-check-" + records.name.rsplit(".", 1)[1].replace("_", "-")
    print("CANDIDATE_RECORDS", records, flush=True)
    base = ["kubectl", "--kubeconfig", KUBE, "--request-timeout=20s", "-n", NS]

    def call(label, *args, data=None, timeout=60):
        completed = subprocess.run(base + list(args), input=data, text=True, capture_output=True, timeout=timeout)
        (records / (label + ".stdout.private")).write_text(completed.stdout, encoding="utf-8")
        (records / (label + ".stderr.private")).write_text(completed.stderr, encoding="utf-8")
        if completed.returncode:
            raise RuntimeError(label + " failed; inspect its private log")
        return completed.stdout

    request = urllib.request.Request("http://10.130.14.23:5000/v2/hermes-lite/manifests/" + DIGEST,
        headers={"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024 or "sha256:" + hashlib.sha256(raw).hexdigest() != DIGEST:
        raise RuntimeError("candidate manifest identity mismatch")
    manifest = json.loads(raw)
    (records / "candidate.manifest.json").write_bytes(raw)
    config_digest = manifest["config"]["digest"]
    with urllib.request.urlopen("http://10.130.14.23:5000/v2/hermes-lite/blobs/" + config_digest, timeout=20) as response:
        config_raw = response.read(4 * 1024 * 1024 + 1)
    if len(config_raw) > 4 * 1024 * 1024 or "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_digest:
        raise RuntimeError("candidate config identity mismatch")
    config = json.loads(config_raw)
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise RuntimeError("candidate platform mismatch")
    (records / "candidate.config.private.json").write_bytes(config_raw)
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS}, "spec": {
        "automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 900,
        "terminationGracePeriodSeconds": 5, "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "containers": [{"name": "inspect", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["/bin/sh", "-c", "sleep 800"],
            "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
            "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "1Gi"}}}]}}
    uid = None
    try:
        actual = json.loads(call("create", "create", "-f", "-", "-o", "json", data=json.dumps(pod)))
        uid = actual["metadata"]["uid"]
        spec = actual["spec"]
        container = spec["containers"][0]
        if (len(spec["containers"]) != 1 or spec.get("initContainers") or spec.get("volumes")
                or spec.get("automountServiceAccountToken") is not False or spec.get("hostNetwork")
                or spec.get("hostPID") or container.get("envFrom") or container.get("volumeMounts")
                or container.get("command") != pod["spec"]["containers"][0]["command"]
                or container.get("env") != pod["spec"]["containers"][0]["env"]
                or container.get("args") or container["image"] != IMAGE):
            raise RuntimeError("candidate Pod admission changed the isolated inspection spec")
        print("WAITING_FOR_CANDIDATE", name, flush=True)
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            actual = json.loads(call("pod", "get", "pod", name, "-o", "json"))
            statuses = actual.get("status", {}).get("containerStatuses", [])
            if actual["metadata"]["uid"] != uid:
                raise RuntimeError("candidate Pod identity changed")
            if len(statuses) == 1 and statuses[0].get("ready"):
                break
            if actual.get("status", {}).get("phase") in ("Failed", "Succeeded"):
                raise RuntimeError("candidate inspection container terminated")
            time.sleep(3)
        else:
            raise RuntimeError("candidate Pod not ready within 360 seconds")
        image_id = statuses[0].get("imageID", "")
        if not any(image_id == value or image_id.endswith("@" + value) or image_id in (
                "containerd://" + value, "docker://" + value) for value in (DIGEST, config_digest)):
            raise RuntimeError("loaded candidate image identity mismatch")
        result = json.loads(call("probe", "exec", "-i", name, "-c", "inspect", "--", "python3", "-B", "-", data=PROBE, timeout=160))
        result.update(image=IMAGE, image_id=image_id, pod_uid=uid)
        (records / "candidate-inspection.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False), flush=True)
        print("CANDIDATE_INSPECTED_NOT_DEPLOYED", records, flush=True)
        return records, result
    finally:
        if uid is not None:
            # A UID precondition prevents deletion of a replacement Pod with the same name.
            body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "gracePeriodSeconds": 0}
            call("delete", "delete", "--raw", "/api/v1/namespaces/" + NS + "/pods/" + name, "-f", "-", data=json.dumps(body))
            call("wait-delete", "--request-timeout=70s", "wait", "--for=delete", "pod/" + name, "--timeout=60s", timeout=80)
            print("CANDIDATE_TEST_POD_DELETED", name, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit("CANDIDATE_INSPECTION_UNCONFIRMED " + str(exc))
