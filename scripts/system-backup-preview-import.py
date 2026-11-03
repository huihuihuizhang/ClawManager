#!/usr/bin/env python3
"""Inspect the pinned field target or import preview images. Never deploys workloads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

CONTEXT = "kubernetes-admin@kubernetes"
NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
APP_UID = "ed2c80de-9d24-4ca6-8f9c-877a990ac933"
REGISTRY = "10.130.14.23:5000"
ACCEPT = ", ".join(("application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json"))
DIRECT_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, timeout=90):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, check=False)
    if p.returncode or len(p.stdout) > 8 * 1024 * 1024:
        raise RuntimeError("command failed: " + Path(args[0]).name)
    return p.stdout


def kubectl(*args):
    return json.loads(run(["kubectl", "--context", CONTEXT, "-n", NAMESPACE,
                           *args, "-o", "json"]))


def target():
    ns = kubectl("get", "namespace", NAMESPACE)
    if ns["metadata"]["uid"] != NAMESPACE_UID:
        raise RuntimeError("namespace identity changed")
    app = kubectl("get", "deployment", "clawmanager-app")
    if app["metadata"]["uid"] != APP_UID:
        raise RuntimeError("application deployment identity changed")
    return {"context": CONTEXT, "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID,
            "deployment_uid": APP_UID, "images": [c["image"] for c in
            app["spec"]["template"]["spec"]["containers"]],
            "replicas": app["spec"].get("replicas"),
            "ready_replicas": app.get("status", {}).get("readyReplicas", 0)}


def sha_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(repo, reference, missing=False):
    url = "http://" + REGISTRY + "/v2/" + repo + "/manifests/" + reference
    try:
        with DIRECT_HTTP.open(urllib.request.Request(url, headers={"Accept": ACCEPT}),
                              timeout=30) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            header = response.headers.get("Docker-Content-Digest")
    except urllib.error.HTTPError as e:
        if missing and e.code == 404:
            return None
        raise RuntimeError("registry manifest request failed") from None
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("registry manifest too large")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if header != digest or reference.startswith("sha256:") and reference != digest:
        raise RuntimeError("registry manifest digest mismatch")
    doc = json.loads(raw)
    if "manifests" in doc:
        entries = [x for x in doc["manifests"]
                   if x.get("platform", {}).get("os") == "linux"
                   and x.get("platform", {}).get("architecture") == "amd64"]
        if len(entries) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", entries[0]["digest"]):
            raise RuntimeError("one exact Linux amd64 image required")
        return manifest(repo, entries[0]["digest"])
    config = doc.get("config", {}).get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config):
        raise RuntimeError("registry config digest missing")
    return {"reference": REGISTRY + "/" + repo + "@" + digest,
            "manifest_digest": digest, "config_digest": config}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("inspect", "import-images"))
    p.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    directory = args.directory.resolve(strict=True)
    observed = target()
    result = {"status": "NOT_PAGE_READY_FIRST_ADOPTION_PRODUCER_MISSING",
              "target": observed, "workload_mutated": False,
              "backup_task_created": False, "full_acceptance": False,
              "dr_qualified": False}
    if args.action == "inspect":
        print(json.dumps(result, sort_keys=True))
        return
    build = json.loads((directory / "build-receipt.json").read_text(encoding="utf-8-sig"))
    archive = directory / "images.tar"
    if sha_file(archive) != build["archive_sha256"]:
        raise RuntimeError("image archive checksum mismatch")
    version = build["version"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,80}", version):
        raise RuntimeError("invalid exact release version")
    expected = {}
    for role, repo in (("app", "clawmanager"), ("worker", "clawmanager-backup-worker")):
        local = build["images"][role]
        if not re.fullmatch(r"[a-z0-9-]+:[a-z0-9_.-]+", local["tag"]) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", local["id"]) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", local["config_digest"]):
            raise RuntimeError("invalid local image binding")
        remote = manifest(repo, version, missing=True)
        if remote is not None and remote["config_digest"] != local["config_digest"]:
            raise RuntimeError("remote tag already belongs to different image; no overwrite")
        expected[role] = (repo, local, remote)
    print(json.dumps({"stage": "loading-verified-images", "archive_bytes": archive.stat().st_size,
                      "workload_mutated": False}), flush=True)
    run(["nerdctl", "--namespace", "k8s.io", "load", "--input", str(archive)], timeout=900)
    references = {}
    pushed = []
    for role, (repo, local, remote) in expected.items():
        if remote is None:
            tag = REGISTRY + "/" + repo + ":" + version
            print(json.dumps({"stage": "pushing-image", "role": role, "tag": tag}), flush=True)
            run(["nerdctl", "--namespace", "k8s.io", "tag", local["tag"], tag])
            run(["nerdctl", "--namespace", "k8s.io", "--insecure-registry", "push", tag],
                timeout=900)
            pushed.append(role)
            remote = manifest(repo, version)
        if remote["config_digest"] != local["config_digest"]:
            raise RuntimeError("pushed registry image differs from exact local config digest")
        references[role] = remote
    result.update({"source_commit": build["commit"], "images": references,
                   "images_imported": True, "images_pushed": bool(pushed),
                   "pushed_roles": pushed, "images_available": True,
                   "next": "Actual migration, original material issuance and first adoption remain; image import is not deployment or page acceptance."})
    receipt = directory / "image-references.json"
    raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    try:
        with receipt.open("xb") as f:
            f.write(raw)
    except FileExistsError:
        old = json.loads(receipt.read_bytes())
        if old.get("source_commit") != result["source_commit"] or old.get("images") != references:
            raise RuntimeError("existing different import receipt preserved") from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.TimeoutExpired, urllib.error.URLError) as e:
        print(json.dumps({"status": "refused", "reason": str(e),
                          "workload_mutated": False, "full_acceptance": False}), file=sys.stderr)
        sys.exit(1)
