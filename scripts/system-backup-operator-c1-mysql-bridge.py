"""Original operator transport: one complete Go invocation on MySQL's node.

Call invoke_complete(operator, actual_complete_cli_argv) before C1 starts.
It invokes one fixed built ELF in one private mount namespace, preserving all
original host input paths and the SAME Go process/context/source objects.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

NS = "clawmanager-zhanghui08-system"
NS_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
MYSQL_UID = "27916932-fc61-432c-b515-081f18db34a8"
PVC_UID = "e3c297bd-a00a-4a60-bce7-7368a69e8fd2"
PV_UID = "2661bbff-e182-4189-9a09-3c23d5c71050"
HOST_SOURCE = "/data/clawmanager-zhanghui08/system/mysql"
DATADIR = "/var/lib/mysql"
NATIVE_SHA = "fa5aff4df941e9854937b3ea41ad2c46afd38cf1e1019a64f0d618a099209e9d"
BRIDGE_HELPER_SHA = "b617a6736a8fb8c1389eaf29729b0f6cc953f66ca9c100218232b270aea97f1f"
CRI_SHA = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"


def need(value, code):
    if not value:
        raise RuntimeError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)+"\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def controller(obj, kind):
    refs = [ref for ref in obj["metadata"].get("ownerReferences", []) if ref.get("controller")]
    need(len(refs) == 1 and refs[0]["kind"] == kind, "exact_original_mysql_owner_chain_required")
    return refs[0]


def snapshot(operator):
    def get(resource, name, namespace=True):
        args = ["-n", NS] if namespace else []
        return json.loads(operator.k(*args, "get", resource, name, "-o", "json"))
    namespace = get("namespace", NS, False)
    deployment = get("deployment", "mysql")
    pvc = get("pvc", "mysql-data")
    pv = get("pv", pvc["spec"]["volumeName"], False)
    need(namespace["metadata"]["uid"] == NS_UID and deployment["metadata"]["uid"] == MYSQL_UID and deployment["spec"].get("replicas", 1) == 1, "original_mysql_namespace_and_deployment_required")
    need(pvc["metadata"]["uid"] == PVC_UID and pvc["status"]["phase"] == "Bound" and pvc["spec"].get("volumeMode", "Filesystem") == "Filesystem" and pv["metadata"]["uid"] == PV_UID and pv["spec"]["claimRef"]["uid"] == PVC_UID and pv["spec"]["claimRef"]["namespace"] == NS and pv["spec"]["claimRef"]["name"] == "mysql-data" and pv["spec"].get("hostPath", {}).get("path") == HOST_SOURCE and "ReadWriteOnce" in pvc["spec"]["accessModes"], "exact_original_mysql_pvc_pv_hostpath_required")
    pods = json.loads(operator.k("-n", NS, "get", "pods", "-o", "json"))["items"]
    selected = []
    for pod in pods:
        refs = [ref for ref in pod["metadata"].get("ownerReferences", []) if ref.get("controller")]
        if len(refs) != 1 or refs[0]["kind"] != "ReplicaSet":
            continue
        rs = get("replicaset", refs[0]["name"])
        parent = controller(rs, "Deployment")
        need(rs["metadata"]["uid"] == refs[0]["uid"], "original_mysql_replicaset_replaced")
        if parent["uid"] == MYSQL_UID:
            selected.append((pod, rs))
    need(len(selected) == 1, "unique_actual_original_mysql_pod_required")
    pod, rs = selected[0]
    need(pod["spec"].get("dnsPolicy", "ClusterFirst") == "ClusterFirst", "actual_original_mysql_clusterfirst_dns_required")
    need(pod["status"]["phase"] == "Running" and not pod["metadata"].get("deletionTimestamp") and not pod["spec"].get("hostNetwork") and len(pod["spec"]["containers"]) == 1 and not pod["spec"].get("ephemeralContainers"), "original_running_mysql_pod_profile_required")
    container = pod["spec"]["containers"][0]
    mounts = [mount for mount in container.get("volumeMounts", []) if mount["mountPath"] == DATADIR]
    need(len(mounts) == 1 and not any(mounts[0].get(key) for key in ("subPath", "subPathExpr", "mountPropagation", "readOnly")), "original_mysql_whole_writable_datadir_mount_required")
    volumes = [v for v in pod["spec"]["volumes"] if v["name"] == mounts[0]["name"]]
    need(len(volumes) == 1 and volumes[0].get("persistentVolumeClaim", {}).get("claimName") == "mysql-data" and not volumes[0]["persistentVolumeClaim"].get("readOnly"), "original_mysql_datadir_must_be_exact_original_pvc")
    statuses = [s for s in pod["status"]["containerStatuses"] if s["name"] == container["name"]]
    need(len(statuses) == 1 and statuses[0].get("ready") and "running" in statuses[0].get("state", {}) and re.fullmatch(r"containerd://[a-f0-9]{64}", statuses[0].get("containerID", "")), "actual_running_mysql_cri_identity_required")
    current = statuses[0]
    image = current["imageID"].removeprefix("docker-pullable://").rsplit("@", 1)[-1]
    need(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "actual_mysql_immutable_image_digest_required")
    node = get("node", pod["spec"]["nodeName"], False)
    need(node["status"]["nodeInfo"]["operatingSystem"] == "linux" and node["status"]["nodeInfo"]["architecture"] == "amd64" and any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]), "original_mysql_node_ready_linux_amd64_required")
    info = node["status"]["nodeInfo"]
    services = json.loads(operator.k("-n", NS, "get", "services", "-o", "json"))["items"]
    dns_services = []
    for service in services:
        if service["spec"].get("type") == "ExternalName" or service["spec"].get("clusterIP") in (None, "", "None"):
            continue
        ips = service["spec"].get("clusterIPs") or [service["spec"]["clusterIP"]]
        dns_services.append({"name": service["metadata"]["name"], "uid": service["metadata"]["uid"], "cluster_ips": sorted({str(ipaddress.ip_address(ip)) for ip in ips})})
    need(0 < len(dns_services) <= 64 and any(service["name"] == "mysql" for service in dns_services), "actual_original_mysql_and_provider_clusterip_service_roster_required")
    dns_services.sort(key=lambda service: service["name"])
    return {"node": {"name": node["metadata"]["name"], "uid": node["metadata"]["uid"], "machine_id": info["machineID"], "boot_id": info["bootID"]},
            "dns_services": dns_services,
            "mysql": {"namespace_uid": NS_UID, "deployment_uid": MYSQL_UID, "deployment_spec_sha256": sha(canonical(deployment["spec"])), "replicaset_uid": rs["metadata"]["uid"], "pvc_uid": PVC_UID, "pvc_spec_sha256": sha(canonical(pvc["spec"])), "pv_uid": PV_UID, "pv_spec_sha256": sha(canonical(pv["spec"])), "pod_spec_sha256": sha(canonical(pod["spec"])), "mount": mounts[0],
                      "native_container": {"namespace": NS, "node": node["metadata"]["name"], "pod": pod["metadata"]["name"], "pod_uid": pod["metadata"]["uid"], "container_id": current["containerID"], "image_digest": image}}}


def original_nonce_files(operator):
    relative = "scripts/system-backup-operator-nonce.py"
    path = operator.root/relative
    need(sha(path.read_bytes()) == operator.pins["files"][relative], "sealed_original_nonce_operator_required")
    spec = importlib.util.spec_from_file_location("original_nonce_for_single_c1_transport", path)
    nonce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nonce)
    issued = nonce.material(operator)
    bound = json.loads(Path(operator.completed("nonce-bind")["stdout"]).read_bytes())
    need(bound["Version"] == "original-nonce-file-mount-result.v1" and bound["State"] == "original-signed-current-native-readonly-mount-verified", "original_current_nonce_bind_required_before_complete_caller")
    pins = [issued[key] for key in ("Source", "Descriptor", "Material")]+[bound[key] for key in ("Binding", "OwnerMaterial")]
    for pin in pins:
        operator.pin_value(pin)
    # No path is relocated or edited. Go revalidates the original signatures,
    # native resources, actual current actor and the original32B key itself.
    return pins


def prepare(operator, argv=None):
    operator.open()
    need(os.geteuid() == 0 and sys.platform == "linux", "original_linux_root_mysql_node_transport_required")
    actual = snapshot(operator)
    need(Path("/etc/machine-id").read_text().strip() == actual["node"]["machine_id"] and Path("/proc/sys/kernel/random/boot_id").read_text().strip() == actual["node"]["boot_id"], "run_complete_caller_on_actual_original_mysql_node_not_a_different_host")
    cri = operator.a.deployment_crictl_file
    need(cri is not None and Path(cri).is_absolute() and Path(cri).resolve(strict=True) == Path(cri) and sha(Path(cri).read_bytes()) == CRI_SHA, "original_official_crictl_required_for_capacity_bridge")
    sockets = [path for path in (Path("/run/containerd/containerd.sock"), Path("/run/k3s/containerd/containerd.sock")) if path.exists() and stat.S_ISSOCK(path.stat().st_mode) and not path.is_symlink()]
    need(len(sockets) == 1, "one_actual_original_mysql_cri_socket_required")
    native = operator.root/"scripts/system-backup-workspace-native.py"
    need(operator.pins["files"].get("scripts/system-backup-workspace-native.py") == NATIVE_SHA and sha(native.read_bytes()) == NATIVE_SHA, "selected_actual_native_identity_helper_required")
    helper = operator.root/"scripts/system-backup-c1-host-mysql-bridge.py"
    need(operator.pins["files"].get("scripts/system-backup-c1-host-mysql-bridge.py") == BRIDGE_HELPER_SHA == sha(helper.read_bytes()), "sealed_actual_mysql_mount_bridge_helper_required")
    caller = operator.root/"bin/system-backup-first-adoption"
    need(argv is None or isinstance(argv, (list, tuple)) and argv and str(argv[0]) == str(caller), "one_actual_full_adoption_cli_only_no_arbitrary_command")
    receipt = json.loads((operator.root/"build-receipt.json").read_bytes())
    digest = receipt["binaries"][caller.name]
    need(operator.pins["files"].get("bin/"+caller.name) == digest and sha(caller.read_bytes()) == digest, "same_root_built_original_complete_adoption_elf_required")
    enrollment = operator.enrollment()
    plan = json.loads(operator.pin_value(enrollment["Plan"]).read_bytes())
    original = json.loads((operator.run/"operation.json").read_bytes())
    suffix = secrets.token_hex(8)
    output = operator.run/("c1-mysql-mount-bridge-"+suffix)
    output.mkdir(mode=0o700)
    record = {"version": "original-c1-host-mysql-private-mount.v1", "operation": original["operation"], "action": "probe" if argv is None else "invoke-complete", "receipt_directory": str(output), "host_source": HOST_SOURCE, "datadir": DATADIR, "server_uuid": plan["Target"]["ServerUUID"], **actual,
              "original_nonce_files": original_nonce_files(operator), "cri": {"File": str(cri), "SHA256": CRI_SHA, "Endpoint": "unix://"+str(sockets[0])}, "native_helper": {"File": str(native), "SHA256": NATIVE_SHA}, "caller": {"File": str(caller), "SHA256": digest}, "argv": [] if argv is None else [str(arg) for arg in argv]}
    need(snapshot(operator) == actual, "original_mysql_kubernetes_graph_changed_before_single_caller")
    module = operator.source_helpers()
    plan_file = operator.run/("c1-mysql-mount-bridge-"+suffix+".plan.json")
    # Same create-only durable writer as the operator's original dispatch.
    raw = canonical(record)
    with plan_file.open("xb") as target:
        os.chmod(plan_file, 0o600)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    module.sync_dir(operator.run)
    return [sys.executable, "-I", "-B", helper, "--plan-file", plan_file, "--plan-sha256", sha(raw)]


def probe(operator):
    """Actual readonly mount qualification only, never SQL/backup readiness."""
    value, out = operator.invoke("c1-mysql-mount-probe", prepare(operator), repeat=True)
    return {**value, "private_receipt": str(out), "backup_ready": False, "DR": False}


def invoke_complete(operator, actual_complete_cli_argv):
    """Exactly one actual Go invocation; no JSON source/context boundary."""
    argv = prepare(operator, actual_complete_cli_argv)
    # Preserve the existing original adopt.send-unknown.json custody contract.
    # A repeated unknown adopt still refuses; original query/recovery is next.
    return operator.invoke("adopt", argv)
