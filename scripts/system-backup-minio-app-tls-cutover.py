#!/usr/bin/env python3
"""Original business app MinIO CA/scheme cutover; no backup config prerequisite."""
import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
FIRST_HOP_SHA = "04dde0494f5af89df363929b86a661a555a6a57696eb7bd25f132bdf7f479714"  # exact frozen first-hop source
MOUNT = "/run/system-backup-business-minio-ca"


def load_helper(path):
    if hashlib.sha256(path.read_bytes()).hexdigest() != FIRST_HOP_SHA:
        raise RuntimeError("exact reviewed first-hop helper required")
    spec = importlib.util.spec_from_file_location("original_minio_first_hop", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def app_source(source, deployment):
    dep = source.get("deployment", deployment)
    selector = dep["spec"]["selector"]
    if selector.get("matchExpressions") or not selector.get("matchLabels") or dep["metadata"].get("deletionTimestamp"):
        raise RuntimeError("actual original app selector required")
    replicas = dep["spec"].get("replicas", 1)
    if replicas < 1 or dep.get("status", {}).get("observedGeneration", 0) < dep["metadata"].get("generation", 1) or dep.get("status", {}).get("updatedReplicas", 0) != replicas or dep.get("status", {}).get("availableReplicas", 0) != replicas:
        raise m.Refused("actual original app rollout not stable")
    pods = json.loads(source.kube("get", "pods", "-l", ",".join(k + "=" + v for k, v in sorted(selector["matchLabels"].items())), "-o", "json"))["items"]
    actual = []
    for pod in pods:
        if pod["metadata"].get("deletionTimestamp"):
            continue
        pod_owner = m.controller(pod, "ReplicaSet")
        rs = source.get("replicaset", pod_owner["name"])
        owner = m.controller(rs, "Deployment")
        if rs["metadata"]["uid"] != pod_owner["uid"] or owner["uid"] != dep["metadata"]["uid"] or len(pod["spec"]["containers"]) != 1:
            raise m.Refused("actual app owner/container differs")
        c = pod["spec"]["containers"][0]
        selected = dep["spec"]["template"]["spec"]["containers"][0]
        if any(c.get(k) != selected.get(k) for k in ("name", "image", "command", "args")):
            raise m.Refused("actual app launch differs from selected original template")
        states = [s for s in pod.get("status", {}).get("containerStatuses", []) if s["name"] == c["name"]]
        if len(states) != 1 or not states[0].get("containerID") or not states[0].get("ready") or "running" not in states[0].get("state", {}):
            raise m.Refused("actual ready app instance required")
        actual.append((pod, c, states[0]))
    if not actual or len(actual) != dep["spec"].get("replicas", 1):
        raise m.Refused("complete stable original app roster required")
    return dep, sorted(actual, key=lambda x: x[0]["metadata"]["uid"])


def app_exec(source, actor, *command):
    pod, container, status = actor
    value = source.kube("exec", pod["metadata"]["name"], "-c", container["name"], "--", *command)
    back = source.get("pod", pod["metadata"]["name"])
    states = [s for s in back["status"]["containerStatuses"] if s["name"] == container["name"]]
    if back["metadata"]["uid"] != pod["metadata"]["uid"] or len(states) != 1 or states[0]["containerID"] != status["containerID"]:
        raise m.Refused("original app changed during selected read")
    return value


def prepare(source, args):
    tls = m.load(source, args.minio_state_directory, args.minio_plan_sha256)
    dep, actors = app_source(source, args.app_deployment)
    if not source.plan.get("LocalAdminUsername"):
        raise m.Refused("actual installation-plan local admin username required")
    m.read_private(args.local_admin_password_file)
    business_download(source, actors[0], args.local_admin_password_file, login_only=True)
    if len(dep["spec"]["template"]["spec"]["containers"]) != 1:
        raise m.Refused("one selected business app container required")
    # Only the public root bundle path is queried, never process env/passwords.
    roots = []
    for actor in actors:
        path = app_exec(source, actor, "/bin/sh", "-ceu", 'printf "%s" "${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"').decode()
        if not path.startswith("/") or any(c in path for c in "\x00\r\n"):
            raise m.Refused("original trust bundle path unresolved")
        bundle = app_exec(source, actor, "/bin/cat", path)
        if b"PRIVATE KEY" in bundle or b"BEGIN CERTIFICATE" not in bundle or len(bundle) > 4 << 20:
            raise m.Refused("original public system trust bundle required")
        roots.append(bundle)
    if any(bundle != roots[0] for bundle in roots):
        raise m.Refused("original app roots differ between replicas")
    ca = m.read_private(args.minio_state_directory / "ca.pem", tls["ca_sha256"])
    combined = roots[0].rstrip() + b"\n" + ca
    directory = args.state_directory
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = "sbk-app-minio-ca-" + tls["operation"][:16]
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": source.ns, "annotations": {m.MARKER: tls["operation"]}}, "immutable": True, "data": {"roots.pem": combined.decode("ascii"), "minio-ca.pem": ca.decode("ascii")}}
    desired = copy.deepcopy(dep["spec"])
    pod = desired["template"]["spec"]
    c = pod["containers"][0]
    if any(v["name"] == name for v in pod.get("volumes", [])) or any(v["mountPath"] == MOUNT for v in c.get("volumeMounts", [])):
        raise m.Refused("selected app trust mount already exists")
    pod.setdefault("volumes", []).append({"name": name, "configMap": {"name": name}})
    c.setdefault("volumeMounts", []).append({"name": name, "mountPath": MOUNT, "readOnly": True})
    updates = {"OBJECT_STORAGE_ENDPOINT": args.service + "." + source.ns + ".svc:9000", "OBJECT_STORAGE_USE_SSL": "true", "SSL_CERT_FILE": MOUNT + "/roots.pem", "OBJECT_STORAGE_TLS_CA_FILE": MOUNT + "/minio-ca.pem", "OBJECT_STORAGE_TLS_CA_SHA256": tls["ca_sha256"]}
    c["env"] = [e for e in c.get("env", []) if e["name"] not in updates] + [{"name": k, "value": v} for k, v in updates.items()]
    desired["template"].setdefault("metadata", {}).setdefault("annotations", {})[m.MARKER] = tls["operation"]
    desired = m.source_patch(source, dep, desired, dry=True)["spec"]
    source.authority()
    if source.get("deployment", args.app_deployment)["spec"] != dep["spec"]:
        raise m.Refused("original business app changed during prepare")
    plan = {"version": "original-minio-business-app-cutover.v1", "operation": tls["operation"], "installation_plan_sha256": args.installation_plan_sha256, "namespace": source.ns, "deployment": dep, "desired_spec": desired, "ca_object": obj, "minio_plan_sha256": args.minio_plan_sha256, "original_roots_sha256": m.sha(roots[0]), "combined_roots_sha256": m.sha(combined)}
    m.durable(directory / "plan.json", m.raw(plan))
    return {"state": "business_cutover_prepared_only", "plan_sha256": m.sha(m.raw(plan)), "minio_operation": tls["operation"], "original_app_image_preserved": True}


def business_download(source, actor, password_file, login_only=False):
    # Existing real route calls DownloadSkill -> storage.GetObject; this is
    # a business SDK read, not an anonymous MinIO liveness substitute.
    username = source.plan.get("LocalAdminUsername")
    if not username:
        raise m.Refused("actual original plan local admin username missing")
    password = m.read_private(password_file).decode().rstrip("\r\n")
    with socket.socket() as pick:
        pick.bind(("127.0.0.1", 0))
        port = pick.getsockname()[1]
    process = subprocess.Popen(source.prefix + ["port-forward", "--address=127.0.0.1", "pod/" + actor[0]["metadata"]["name"], str(port) + ":9001"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=m.native_env())
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), 1):
                    break
            except OSError:
                if process.poll() is not None:
                    raise m.Refused("original app forwarding refused")
                time.sleep(.05)
        else:
            raise m.Refused("original app forwarding unavailable")
        def request(method, path, body=None, token=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            try:
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = "Bearer " + token
                conn.request(method, path, m.raw(body) if body is not None else None, headers)
                response = conn.getresponse()
                value = response.read((64 << 20) + 1)
                if response.status != 200 or len(value) > 64 << 20:
                    raise m.Refused("actual app business request refused; secret response suppressed")
                return value
            finally:
                conn.close()
        auth = json.loads(request("POST", "/api/v1/auth/login", {"username": username, "password": password}))
        token = auth["data"]["access_token"]
        # This administrative route performs the actual existing role check.
        # No claimed role/unsigned token payload is accepted as that check.
        listing = json.loads(request("GET", "/api/v1/admin/skills", token=token))["data"]
        def same_actor():
            back = source.get("pod", actor[0]["metadata"]["name"])
            states = [s for s in back["status"]["containerStatuses"] if s["name"] == actor[1]["name"]]
            if back["metadata"]["uid"] != actor[0]["metadata"]["uid"] or len(states) != 1 or states[0]["containerID"] != actor[2]["containerID"]:
                raise m.Refused("actual business instance changed during request")
        if login_only:
            same_actor()
            return {"state": "actual_original_admin_session_verified"}
        candidates = [s for s in listing if s.get("source_type") == "uploaded" and s.get("current_version_id") and re.fullmatch(r"[a-f0-9]{64}", s.get("archive_hash") or "")]
        if not candidates:
            raise m.Refused("no existing archived business object; actual SDK read remains unverified")
        item = sorted(candidates, key=lambda s: s["id"])[0]
        value = request("GET", "/api/v1/skills/" + str(int(item["id"])) + "/download", token=token)
        if m.sha(value) != item["archive_hash"]:
            raise m.Refused("actual app SDK object differs from original archive hash")
        same_actor()
        return {"state": "actual_business_sdk_read_verified", "bytes": len(value), "archive_sha256": m.sha(value)}
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def apply(source, args, plan):
    directory = args.state_directory
    if (directory / "rollback.sent.json").exists():
        raise m.Refused("original app operation already entered recovery")
    tls = m.load(source, args.minio_state_directory, args.minio_plan_sha256)
    m.apply(source, args.minio_state_directory, tls, query_only=True)
    obj = plan["ca_object"]
    def read_cm():
        values = json.loads(source.kube("get", "configmap", "--field-selector=metadata.name=" + obj["metadata"]["name"], "-o", "json"))["items"]
        if not values:
            return None
        if len(values) != 1 or values[0].get("data") != obj["data"] or not values[0].get("immutable") or values[0]["metadata"].get("annotations", {}).get(m.MARKER) != plan["operation"]:
            raise m.Refused("original app trust object differs")
        return {"uid": values[0]["metadata"]["uid"], "sha256": m.sha(m.raw(obj))}
    if args.action == "query" and not (directory / "ca.sent.json").exists():
        raise m.Refused("query cannot start app installation")
    m.step(directory, "ca", {"sha256": m.sha(m.raw(obj))}, lambda: source.kube("create", "-f", "-", "-o", "json", data=m.raw(obj)), read_cm)
    current = m.current_deployment(source, plan)
    if not (directory / "deployment.sent.json").exists() and (args.action == "query" or current["spec"] != plan["deployment"]["spec"]):
        raise m.Refused("original app pre-send state differs or query-only")
    def read_dep():
        actual = m.current_deployment(source, plan)
        return {"uid": actual["metadata"]["uid"], "spec_sha256": m.sha(m.raw(actual["spec"]))} if actual["spec"] == plan["desired_spec"] else None
    m.step(directory, "deployment", {"uid": current["metadata"]["uid"], "spec_sha256": m.sha(m.raw(plan["desired_spec"]))}, lambda: m.source_patch(source, current, plan["desired_spec"]), read_dep)
    source.kube("rollout", "status", "deployment/" + args.app_deployment, "--timeout=120s", timeout=130)
    dep, actors = app_source(source, args.app_deployment)
    if dep["metadata"]["uid"] != plan["deployment"]["metadata"]["uid"] or dep["spec"] != plan["desired_spec"]:
        raise m.Refused("actual rolled app differs")
    verified = [business_download(source, actor, args.local_admin_password_file) for actor in actors]
    source.authority()
    return {"state": "actual_business_app_object_reads_verified", "replicas": len(verified), "backup_authorized": False, "operation": plan["operation"]}


def main():
    global m
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "apply", "query", "rollback", "verify-business"))
    for key in ("first-hop-helper", "kubeconfig-file", "installation-plan-file", "state-directory", "minio-state-directory", "local-admin-password-file"):
        parser.add_argument("--" + key, type=Path, required=True)
    for key in ("kubeconfig-sha256", "installation-plan-sha256", "minio-plan-sha256"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--service", default="minio")
    parser.add_argument("--app-deployment", default="clawmanager-app")
    args = parser.parse_args()
    m = load_helper(args.first_hop_helper)
    if os.name != "posix" or not args.state_directory.is_absolute() or args.state_directory.resolve() != args.state_directory or args.state_directory.exists() and args.state_directory.stat().st_mode & 0o077:
        raise m.Refused("original Linux private directory required")
    source = m.Source(args)
    if args.action == "prepare":
        result = prepare(source, args)
    else:
        if not re.fullmatch(r"[a-f0-9]{64}", args.plan_sha256 or ""):
            raise m.Refused("exact original app plan SHA required")
        plan = json.loads(m.read_private(args.state_directory / "plan.json", args.plan_sha256))
        if plan["version"] != "original-minio-business-app-cutover.v1" or plan["installation_plan_sha256"] != args.installation_plan_sha256 or plan["namespace"] != source.ns or plan["minio_plan_sha256"] != args.minio_plan_sha256 or plan["deployment"]["metadata"]["name"] != args.app_deployment:
            raise m.Refused("original business cutover identity differs")
        if args.action == "rollback":
            result = m.rollback(source, args.state_directory, plan)
        elif args.action == "verify-business":
            dep, actors = app_source(source, args.app_deployment)
            if dep["metadata"]["uid"] != plan["deployment"]["metadata"]["uid"] or dep["spec"] not in (plan["deployment"]["spec"], plan["desired_spec"]):
                raise m.Refused("actual original business instance differs")
            for actor in actors:
                business_download(source, actor, args.local_admin_password_file)
            source.authority()
            result = {"state": "actual_business_sdk_reads_verified", "replicas": len(actors), "original_spec_restored": dep["spec"] == plan["deployment"]["spec"], "backup_authorized": False}
        else:
            result = apply(source, args, plan)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"state": "business_cutover_unconfirmed_preserve_plan", "error_type": type(error).__name__, "automatic_replay": False}), file=sys.stderr)
        sys.exit(1)
