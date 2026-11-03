#!/usr/bin/env python3
"""Read-only namespace writer/mount observations. Never a physical stop proof."""
import argparse
import datetime
import json
import subprocess
import sys

RESOURCES = ("deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs", "pods", "persistentvolumeclaims")


class Refused(ValueError):
    pass


def metadata(value):
    m = value.get("metadata", {})
    return {key: m.get(key) for key in ("namespace", "name", "uid", "generation", "resourceVersion", "deletionTimestamp")}


def owners(value):
    return [{key: row.get(key) for key in ("apiVersion", "kind", "name", "uid", "controller")} for row in value.get("metadata", {}).get("ownerReferences", [])]


def volume_source(volume):
    if "persistentVolumeClaim" in volume:
        return {"kind": "pvc", "claim": volume["persistentVolumeClaim"].get("claimName"), "read_only": volume["persistentVolumeClaim"].get("readOnly", False)}
    if "hostPath" in volume:
        return {"kind": "hostpath", **{k: volume["hostPath"].get(k) for k in ("path", "type")}}
    if "nfs" in volume:
        return {"kind": "nfs", **{k: volume["nfs"].get(k) for k in ("server", "path", "readOnly")}}
    for key in ("emptyDir", "configMap", "secret", "projected", "downwardAPI"):
        if key in volume:
            # No projected tokens, Secret names/data or config bodies escape.
            return {"kind": key, "instance_persistent_data": False}
    return {"kind": "unsupported_or_unknown", "requires_owner_review": True}


def container(container, statuses):
    status = next((v for v in statuses if v.get("name") == container.get("name")), {})
    state = status.get("state", {})
    state_kind = next((v for v in ("running", "terminated", "waiting") if v in state), "unknown")
    detail = state.get(state_kind, {})
    return {
        "name": container.get("name"), "image": container.get("image"), "image_id": status.get("imageID"),
        "container_id": status.get("containerID"), "ready": status.get("ready"), "restart_count": status.get("restartCount"),
        "state": state_kind, "started_at": detail.get("startedAt"), "finished_at": detail.get("finishedAt"), "exit_code": detail.get("exitCode"),
        "mounts": [{k: m.get(k) for k in ("name", "mountPath", "subPath", "subPathExpr", "readOnly", "mountPropagation")} for m in container.get("volumeMounts", [])],
        "block_devices": [{k: m.get(k) for k in ("name", "devicePath")} for m in container.get("volumeDevices", [])],
    }


def project(resource, item):
    spec, status = item.get("spec", {}), item.get("status", {})
    row = {"resource": resource, "identity": metadata(item), "owners": owners(item)}
    if resource == "pods":
        row.update(node=spec.get("nodeName"), phase=status.get("phase"), service_account=spec.get("serviceAccountName"),
                   volumes=[{"name": v.get("name"), **volume_source(v)} for v in spec.get("volumes", [])],
                   containers=[container(c, status.get("containerStatuses", [])) for c in spec.get("containers", [])],
                   init_containers=[container(c, status.get("initContainerStatuses", [])) for c in spec.get("initContainers", [])],
                   ephemeral_container_names=[c.get("name") for c in spec.get("ephemeralContainers", [])])
    elif resource == "persistentvolumeclaims":
        row.update(phase=status.get("phase"), pv=spec.get("volumeName"), storage_class=spec.get("storageClassName"), access_modes=spec.get("accessModes"), volume_mode=spec.get("volumeMode"))
    else:
        row.update(desired_replicas=spec.get("replicas"), suspend=spec.get("suspend"),
                   ready_replicas=status.get("readyReplicas"), available_replicas=status.get("availableReplicas"),
                   desired_scheduled=status.get("desiredNumberScheduled"), active=status.get("active"), succeeded=status.get("succeeded"), failed=status.get("failed"),
                   template_mounts=[{"container": c.get("name"), "mounts": [{k: m.get(k) for k in ("name", "mountPath", "subPath", "subPathExpr", "readOnly")} for m in c.get("volumeMounts", [])]} for c in spec.get("template", {}).get("spec", {}).get("containers", [])])
    return row


class Kubectl:
    def __init__(self, context):
        self.prefix = ["kubectl", "--context", context, "--request-timeout=20s"]

    def get(self, resource, namespace=None, name=None):
        args = self.prefix + (["-n", namespace] if namespace else []) + ["get", resource]
        args += [name] if name else ["--chunk-size=200"]
        try:
            result = subprocess.run(args + ["-o", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            if result.returncode != 0 or len(result.stdout) > 16 << 20:
                raise Refused("resource_read_failed")
            return json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise Refused("resource_read_failed") from None


def collect(api, namespace, namespace_uid):
    def check_namespace():
        item = api.get("namespace", name=namespace)
        if item.get("metadata", {}).get("uid") != namespace_uid or item.get("metadata", {}).get("deletionTimestamp"):
            raise Refused("namespace_identity_changed")
    def lists():
        out = []
        for resource in RESOURCES:
            value = api.get(resource, namespace=namespace)
            if type(value.get("items")) is not list or len(value["items"]) > 5000 or value.get("metadata", {}).get("continue"):
                raise Refused("incomplete_or_unbounded_list")
            seen = set()
            for item in value["items"]:
                m = item.get("metadata", {})
                if m.get("namespace") != namespace or not m.get("name") or not m.get("uid") or not m.get("resourceVersion") or m["name"] in seen:
                    raise Refused("invalid_resource_identity")
                seen.add(m["name"])
                out.append(project(resource, item))
        return sorted(out, key=lambda r: (r["resource"], r["identity"]["name"]))
    check_namespace()
    first = lists()
    nodes = []
    for name in sorted({v["node"] for v in first if v["resource"] == "pods" and v.get("node")}):
        item = api.get("node", name=name)
        if item.get("metadata", {}).get("name") != name or not item.get("metadata", {}).get("uid"):
            raise Refused("node_identity_missing")
        nodes.append({"identity": metadata(item), "os": item.get("status", {}).get("nodeInfo", {}).get("operatingSystem"), "architecture": item.get("status", {}).get("nodeInfo", {}).get("architecture")})
    pvs = []
    for name in sorted({v["pv"] for v in first if v["resource"] == "persistentvolumeclaims" and v.get("pv")}):
        item = api.get("pv", name=name)
        spec = item.get("spec", {})
        if item.get("metadata", {}).get("name") != name or not item.get("metadata", {}).get("uid"):
            raise Refused("pv_identity_missing")
        pvs.append({"identity": metadata(item), "claim_ref": {k: spec.get("claimRef", {}).get(k) for k in ("namespace", "name", "uid")}, "storage": volume_source(spec), "csi_driver": spec.get("csi", {}).get("driver"), "local_path": spec.get("local", {}).get("path"), "access_modes": spec.get("accessModes")})
    last = lists()
    check_namespace()
    first_map = {(v["resource"], v["identity"]["name"]): v for v in first}
    last_map = {(v["resource"], v["identity"]["name"]): v for v in last}
    changed = [{"resource": k[0], "name": k[1]} for k in sorted(first_map.keys() | last_map.keys()) if first_map.get(k) != last_map.get(k)]
    return {"schema_version": "b-writer-mount-observation.v1", "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "namespace": namespace, "namespace_uid": namespace_uid, "read_only": True,
            "status": "observed_drift" if changed else "observed", "changed_resources": changed,
            "physical_fence_proven": False, "complete_writer_inventory_proven": False, "first_adoption_authorized": False,
            "resources": last, "nodes": nodes, "persistent_volumes": pvs,
            "unobserved": ["SQL instance ownership and original stopped identities", "Runtime Agent child/tool process trees", "embedded skill-backfill/skill-materialize and Teams workers", "external NFS/S3/SQL writers and accepted in-flight operations", "stop/drain/current recovery capability"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("context", "namespace", "namespace-uid"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    try:
        result = collect(Kubectl(args.context), args.namespace, args.namespace_uid)
    except Refused as error:
        print(json.dumps({"status": "refused", "code": str(error), "physical_fence_proven": False}))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
