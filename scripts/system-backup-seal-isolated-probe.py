#!/usr/bin/env python3
"""Disposable storage capability probe. Never qualifies a production deployment."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile
import time
import uuid


def node_capacity_inventory(kubectl, context):
    def read(kind):
        args = [kubectl, "--context", context, "--request-timeout=30s", "get", kind]
        if kind == "pods":
            args.append("--all-namespaces")
        p = subprocess.run(args + ["-o", "json"], text=True, capture_output=True, timeout=60)
        if p.returncode:
            raise RuntimeError("node inventory failed: " + p.stderr[-1000:])
        return json.loads(p.stdout)["items"]
    nodes, pods = read("nodes"), read("pods")
    rows = []
    for node in nodes:
        name = node["metadata"]["name"]
        bound = [p for p in pods if p.get("spec", {}).get("nodeName") == name]
        active = [p for p in bound if p.get("status", {}).get("phase") not in ("Succeeded", "Failed")]
        limit = int(node["status"].get("allocatable", {}).get("pods", 0))
        rows.append({"name": name, "uid": node["metadata"]["uid"],
            "ready": any(c.get("type") == "Ready" and c.get("status") == "True" for c in node["status"].get("conditions", [])),
            "unschedulable": node.get("spec", {}).get("unschedulable", False),
            "taints": node.get("spec", {}).get("taints", []),
            "allocatable_pods": limit, "active_pods": len(active), "total_bound_pods": len(bound),
            "estimated_free_pods": max(0, limit - len(active))})
    return {"read_only": True, "capacity_is_advisory": True, "nodes": rows}


def wait_controller_ready(get, uid, timeout=300):
    deadline = time.monotonic() + timeout
    while True:
        pod = get("pod", "controller", True)
        if pod["metadata"]["uid"] != uid or pod["metadata"].get("deletionTimestamp"):
            raise ValueError("controller replaced or deleting during startup")
        status = pod.get("status", {})
        if status.get("phase") in ("Failed", "Succeeded"):
            raise RuntimeError("controller terminated before Ready: " + status.get("reason", "") + ": " + status.get("message", "")[:1000])
        if any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])):
            return pod
        if time.monotonic() >= deadline:
            raise RuntimeError("controller readiness timeout after 300 seconds")
        time.sleep(2)


def startup_diagnostics(command, get, namespace, uid):
    if get("namespace", namespace)["metadata"]["uid"] != uid:
        raise ValueError("diagnostic namespace identity changed")
    resources = json.loads(command(["-n", namespace, "get", "pod,pvc", "-o", "json"]))
    result = {"resources": [{"kind": r["kind"], "name": r["metadata"]["name"],
        "uid": r["metadata"]["uid"], "status": r.get("status", {}),
        "node": r.get("spec", {}).get("nodeName"), "volume": r.get("spec", {}).get("volumeName")}
        for r in resources.get("items", [])]}
    try:
        events = json.loads(command(["-n", namespace, "get", "events", "-o", "json"]))
        result["events"] = [{"reason": e.get("reason"), "message": e.get("message", "")[:1500],
            "object": e.get("involvedObject"), "count": e.get("count"),
            "lastTimestamp": e.get("lastTimestamp")} for e in events.get("items", [])[-40:]]
    except Exception as exc:
        result["events_error"] = str(exc)[:500]
    if get("namespace", namespace)["metadata"]["uid"] != uid:
        raise ValueError("diagnostic namespace replaced")
    return result


def run(a):
    if getattr(a, "inventory_nodes", False):
        print(json.dumps(node_capacity_inventory(a.kubectl, a.context), indent=2))
        return
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", a.image or "") or a.controller_node == a.worker_node:
        raise ValueError("digest-pinned image and two distinct nodes required")
    name = "seal-capability-" + uuid.uuid4().hex[:16]
    report = {"namespace": name, "scope": "disposable-storage-capability",
              "production_accepted": False, "passed": False, "cleaned": False}
    if not a.execute:
        print(json.dumps({**report, "execute": False, "storage_class": a.storage_class,
                          "image": a.image, "nodes": [a.controller_node, a.worker_node]}))
        return
    base = [a.kubectl, "--context", a.context, "--request-timeout=30s"]

    def command(args, body=None, timeout=90):
        p = subprocess.run(base + args, input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError("kubectl failed: " + p.stderr[-1500:])
        return p.stdout

    def get(kind, obj, ns=False):
        return json.loads(command((["-n", name] if ns else []) + ["get", kind, obj, "-o", "json"]))

    def create(obj):
        return json.loads(command(["create", "-f", "-", "-o", "json"], obj))

    nodes = {n: get("node", n) for n in [a.controller_node, a.worker_node]}
    for n in nodes.values():
        if n["status"]["nodeInfo"]["operatingSystem"] != "linux" or n["status"]["nodeInfo"]["architecture"] != "amd64":
            raise ValueError("probe image requires Linux/amd64")
    sc = get("storageclass", a.storage_class)
    if sc.get("reclaimPolicy", "Delete") != "Delete":
        raise ValueError("disposable probe requires a Delete reclaim policy")
    if sc.get("volumeBindingMode", "Immediate") != "Immediate":
        raise ValueError("node-pinned probe requires Immediate volume binding")
    report["storage_class_uid"] = sc["metadata"]["uid"]
    uid, pvs, attempted = None, {}, False
    print(json.dumps({"started": report}), flush=True)
    stage = "create-namespace"
    try:
        attempted = True
        ns = create({"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": name, "labels": {"seal-capability-run": name}}})
        uid = ns["metadata"]["uid"]
        report["namespace_uid"] = uid
        stage = "create-storage"
        for claim in ["staging", "source"]:
            create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {
                "name": claim, "namespace": name}, "spec": {"accessModes": ["ReadWriteMany"],
                "storageClassName": a.storage_class, "resources": {"requests": {"storage": "1Gi"}}}})
        create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
            "name": "probe", "namespace": name}, "automountServiceAccountToken": False})
        stage = "create-controller"
        created = create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "controller", "namespace": name},
                "spec": {"nodeName": a.controller_node, "serviceAccountName": "probe",
                    "automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 900,
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "controller", "image": a.image, "command": ["/bin/sleep", "900"],
                        "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"], "add": ["DAC_READ_SEARCH"]}},
                        "resources": {"requests": {"cpu": "100m", "memory": "64Mi"},
                                      "limits": {"cpu": "1", "memory": "256Mi"}},
                        "volumeMounts": [{"name": "staging", "mountPath": "/staging"},
                                         {"name": "source", "mountPath": "/source"}]}],
                    "volumes": [{"name": c, "persistentVolumeClaim": {"claimName": c}} for c in ["staging", "source"]]}})
        report["controller_uid"] = created["metadata"]["uid"]
        stage = "wait-controller-ready"
        pod = wait_controller_ready(get, report["controller_uid"])
        stage = "verify-volume-bindings"
        if len(pod["spec"]["containers"]) != 1 or pod["spec"].get("initContainers"):
            raise ValueError("unexpected controller injection")
        volumes = []
        for claim in ["staging", "source"]:
            pvc = get("pvc", claim, True)
            pv = get("pv", pvc["spec"]["volumeName"])
            if pv["spec"].get("persistentVolumeReclaimPolicy") != "Delete":
                raise ValueError("unexpected PV retention policy")
            if pv["spec"]["claimRef"]["uid"] != pvc["metadata"]["uid"]:
                raise ValueError("PVC binding changed")
            pvs[pv["metadata"]["name"]] = pv["metadata"]["uid"]
            volumes.append({"Kind": "PersistentVolumeClaim", "Name": claim, "UID": pvc["metadata"]["uid"],
                            "PVName": pv["metadata"]["name"], "PVUID": pv["metadata"]["uid"]})
        report["volumes"] = volumes
        cfg = {"namespace": name, "namespace_uid": uid, "staging_claim": "staging",
               "staging_directory": "/staging", "worker_image": a.image,
               "workspace": {"claim": "source", "node": a.worker_node},
               "worker_security": {"ServiceAccountName": "probe",
                   "ServiceAccountUID": get("serviceaccount", "probe", True)["metadata"]["uid"],
                   "node_uids": {n: v["metadata"]["uid"] for n, v in nodes.items()}, "volumes": volumes}}
        spec = importlib.util.spec_from_file_location("seal_probe", pathlib.Path(__file__).with_name("system-backup-seal-custody-probe.py"))
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        stage = "run-storage-probe"
        with tempfile.TemporaryDirectory(prefix="seal-capability-") as tmp:
            path = pathlib.Path(tmp) / "probe-config.json"
            raw = json.dumps(cfg).encode()
            path.write_bytes(raw)
            probe.run(argparse.Namespace(config=str(path), config_sha256=hashlib.sha256(raw).hexdigest(),
                context=a.context, controller_pod="controller", controller_uid=pod["metadata"]["uid"],
                controller_image_id=pod["status"]["containerStatuses"][0]["imageID"], container="controller",
                worker_node=a.worker_node, kubectl=a.kubectl, execute=True))
        report["passed"] = True
    except Exception as exc:
        report["failure_stage"] = stage
        report["failure"] = str(exc)[:1500]
        if uid is not None:
            try:
                report["diagnostics"] = startup_diagnostics(command, get, name, uid)
            except Exception as diagnostic_error:
                report["diagnostic_error"] = str(diagnostic_error)[:500]
        raise
    finally:
        try:
            if attempted and uid is None:
                recovered = get("namespace", name)
                if recovered["metadata"].get("labels", {}).get("seal-capability-run") != name:
                    raise ValueError("namespace ownership unknown")
                uid = recovered["metadata"]["uid"]
            if uid:
                # Capture late-bound PVs before deleting only our exact namespace.
                for pvc in json.loads(command(["-n", name, "get", "pvc", "-o", "json"]))["items"]:
                    if pvc["spec"].get("volumeName"):
                        pv = get("pv", pvc["spec"]["volumeName"])
                        if pv["spec"]["claimRef"]["uid"] != pvc["metadata"]["uid"]:
                            raise ValueError("unexpected PV binding during cleanup")
                        pvs[pv["metadata"]["name"]] = pv["metadata"]["uid"]
                command(["delete", "--raw", "/api/v1/namespaces/" + name, "-f", "-"],
                        {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})
                command(["wait", "--for=delete", "namespace/" + name, "--timeout=60s"])
                for pvname in pvs:
                    command(["wait", "--for=delete", "pv/" + pvname, "--timeout=60s"])
                report["cleaned"] = True
        except Exception as exc:
            report["cleanup_error"] = str(exc)
        print(json.dumps(report), flush=True)
        if not report["cleaned"]:
            raise RuntimeError("cleanup incomplete; retain namespace/PV identities")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--context", required=True)
    p.add_argument("--image")
    p.add_argument("--inventory-nodes", action="store_true", help="read-only node Pod capacity inventory; creates no resources")
    p.add_argument("--storage-class", default="longhorn-rwx")
    p.add_argument("--controller-node", default="k8s-master")
    p.add_argument("--worker-node", default="node1")
    p.add_argument("--kubectl", default="kubectl")
    p.add_argument("--execute", action="store_true")
    run(p.parse_args())
