"""Original-operation same-PVC workspace migration and guarded reverse path.

Imported by the real operator. No SQL edits, data copy, backup success flag,
arbitrary command, guessed PVC, or native-result DTO is accepted.
"""
import copy
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import secrets
import select
import shlex
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NATIVE_SHA = "fa5aff4df941e9854937b3ea41ad2c46afd38cf1e1019a64f0d618a099209e9d"
BUSINESS_SHA = "28cf34ee4121648551b05c5aa5c452cc1be9d755f26a9fa7fde26fde071ab5ae"
PROFILE = "backup.clawreef.io/shared-runtime-source-profile"
CLAIM = "clawmanager-workspaces"
ROOT = "/data/clawmanager-zhanghui08/system/workspaces"
EXPORT = "/exports/workspaces"
CLIENTS = {"clawmanager-app", "openclaw-runtime", "hermes-runtime"}


def load_business():
    path = Path(__file__).resolve().with_name("system-backup-business-runtime.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != BUSINESS_SHA:
        raise RuntimeError("reviewed_business_runtime_module_changed")
    spec = importlib.util.spec_from_file_location("workspace_original_business_runtime", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_exact_script(destination, digest, mode, pending):
    """Fixed generated paths, root custody, create-only final install."""
    parent = str(Path(destination).parent)
    ancestors = list(reversed(Path(parent).parents)) + [Path(parent)]
    lines = ["umask 077", "set -C"]
    for directory in ancestors:
        name = shlex.quote(str(directory))
        lines += ["test ! -L " + name,
                  "if test ! -d " + name + "; then mkdir -m 700 -- " + name + "; fi",
                  "test \"$(stat -c %u " + name + ")\" = 0",
                  "test $((0$(stat -c %a " + name + ") & 022)) = 0"]
    p, d = shlex.quote(pending), shlex.quote(destination)
    lines += ["cat > " + p, "test \"$(sha256sum " + p + " | cut -d ' ' -f 1)\" = " + shlex.quote(digest),
              "chmod " + mode + " -- " + p,
              "if test -e " + d + "; then test ! -L " + d + "; test -f " + d + "; test \"$(stat -c %u " + d + ")\" = 0; test $((0$(stat -c %a " + d + ") & 022)) = 0; cmp -- " + p + " " + d + "; else ln -- " + p + " " + d + "; fi",
              "sync -f " + d, "sync -f " + shlex.quote(parent), "rm -- " + p]
    return "\n".join(lines)


class NativeSession:
    """Only this live original SSH exchange supplies its native observations."""
    def __init__(self, owner, node, definition, attach_only=False):
        self.owner, self.m, self.node = owner, owner.m, node
        self.definition = definition
        self.sequence = 0
        self.connection = secrets.token_hex(8)
        m, stages = self.m, owner.stages
        helper = Path(__file__).resolve().with_name("system-backup-workspace-native.py")
        raw = m.read(helper, NATIVE_SHA, private=False)
        addresses = [entry["address"] for entry in node["status"]["addresses"] if entry["type"] == "InternalIP"]
        m.need(len(addresses) == 1, "workspace_each_node_direct_pinned_ssh_address_required")
        address = str(ipaddress.ip_address(addresses[0]))
        probe_script = "\n".join([
            'test "$(id -u)" = 0', 'test "$(uname -s)" = Linux', 'test "$(uname -m)" = x86_64',
            'machine=$(cat /etc/machine-id); boot=$(cat /proc/sys/kernel/random/boot_id)',
            "case $machine$boot in ''|*[!0-9a-f-]*) exit 20;; esac",
            'socket=; count=0',
            'for path in /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock; do',
            ' if test -S "$path" && test ! -L "$path"; then socket=$path; count=$((count+1)); fi',
            'done', 'test "$count" = 1',
            'printf \'{"machine_id":"%s","boot_id":"%s","cri_endpoint":"unix://%s"}\\n\' "$machine" "$boot" "$socket"'])
        _, probe_pin = stages.ssh("workspace-node-probe-" + definition["session"], address, probe_script)
        probe = m.decode(m.pinned(probe_pin))
        m.need(probe["machine_id"] == node["status"]["nodeInfo"]["machineID"] and probe["boot_id"] == node["status"]["nodeInfo"]["bootID"], "workspace_direct_ssh_actual_node_identity_changed")
        definition["node"] = {"name": node["metadata"]["name"], "uid": node["metadata"]["uid"],
                              "machine_id": probe["machine_id"], "boot_id": probe["boot_id"]}
        definition["cri_endpoint"] = probe["cri_endpoint"]
        destination = "/root/.clawmanager-backup-install/" + stages.prefix + "-workspace-native-" + NATIVE_SHA[:16]
        binary = "/usr/local/libexec/" + stages.prefix + "/crictl"
        definition["cri_binary"] = binary
        cri = owner.op.a.deployment_crictl_file
        m.need(cri is not None and m.digest(m.read(cri, private=False, limit=64 << 20)) == m.CRI_SHA, "reviewed_original_crictl_release_required")
        # Existing exact files are only verified, never replaced. Generated
        # shell is fixed here and receives public reviewed source/ELF bytes.
        script = install_exact_script(destination + "/native.py", NATIVE_SHA, "600", destination + "/native-" + definition["session"] + ".pending")
        if not attach_only:
            stages.ssh("workspace-native-source-" + definition["session"], address, script, raw)
        script = install_exact_script(binary, m.CRI_SHA, "755", str(Path(binary).parent / ("crictl-" + definition["session"] + ".pending")))
        if not attach_only:
            stages.ssh("workspace-native-crictl-" + definition["session"], address, script, m.read(cri, private=False, limit=64 << 20))
        key, known = owner.op.a.deployment_ssh_key_file, owner.op.a.deployment_known_hosts_file
        m.read(key, limit=65536)
        m.read(known, private=False)
        target = "root@" + ("[" + address + "]" if ":" in address else address)
        remote = "test \"$(id -u)\" = 0; test \"$(sha256sum " + shlex.quote(destination + "/native.py") + " | cut -d ' ' -f 1)\" = " + shlex.quote(NATIVE_SHA) + "; exec python3 -I -B " + shlex.quote(destination + "/native.py")
        if attach_only:
            remote += " --attach-only"
        argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + str(known), "-i", str(key), target, "sh -ceu " + shlex.quote(remote)]
        stages.retain("workspace-native-definition-"+definition["session"]+".json",definition)
        stages.retain("workspace-native-connection-" + definition["session"] + "-" + self.connection + ".send-unknown.json", {"argv": argv, "definition": definition, "operation": stages.operation})
        self.stderr = (stages.directory / ("workspace-native-" + definition["session"] + "-" + self.connection + ".stderr.private")).open("xb")
        os.chmod(self.stderr.name, 0o600)
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
        self.received = bytearray()
        self.write_all(m.encoded(definition) + b"\n")
        self.process.stdin.flush()
        self.rpc("probe")

    def write_all(self,raw):
        pending=memoryview(raw)
        while pending:
            count=self.process.stdin.write(pending)
            self.m.need(count is not None and count > 0,"original_native_pipe_short_write_unknown")
            pending=pending[count:]

    def rpc(self, action, original_request=None):
        m, stages = self.m, self.owner.stages
        self.sequence += 1
        nonce = secrets.token_hex(32)
        request = original_request or {"operation": stages.operation, "action": action, "nonce": nonce}
        m.need(request["operation"] == stages.operation and request["action"] == action, "original_request_reconnect_identity_changed")
        name = "workspace-native-" + self.definition["session"] + "-" + self.connection + "-" + str(self.sequence)
        stages.retain(name + ".send-unknown.json", request)
        self.write_all(m.encoded(request) + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 1200
        while b"\n" not in self.received:
            m.need(time.monotonic() < deadline, "original_native_session_unknown_retain_journal")
            ready, _, _ = select.select([self.process.stdout], [], [], min(15, deadline - time.monotonic()))
            if ready:
                block = os.read(self.process.stdout.fileno(), 65536)
                m.need(block, "original_native_session_eof_unknown")
                self.received.extend(block)
                m.need(len(self.received) <= 4 << 20, "original_native_reply_limit")
        raw, _, remaining = self.received.partition(b"\n")
        self.received = bytearray(remaining)
        response = m.decode(bytes(raw))
        m.need(response.get("version") == self.definition["version"] and all(response.get(key) == value for key, value in request.items()), "original_native_reply_identity_unconfirmed")
        if "error" in response:
            stages.retain(name + ".actual-refusal.json",response)
            raise m.Refused("native_refused:"+response["error"])
        m.need(response["node"] == self.definition["node"] and response["session"] == self.definition["session"], "original_native_reply_unconfirmed")
        stages.retain(name + ".actual-observation.json", response)
        return response["data"]

    def close(self):
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
        self.stderr.close()


def direct_spec(original, master, claim, module):
    """Same original volume name, PVC UID and bytes; no new storage object."""
    desired = copy.deepcopy(original)
    pod = desired["template"]["spec"]
    module.need(not master["spec"].get("unschedulable") and any(condition.get("type") == "Ready" and condition.get("status") == "True" for condition in master.get("status",{}).get("conditions",[])),"original_data_node_must_be_ready_and_schedulable_before_source_stop")
    for volume in pod.get("volumes",[]):
        if volume["name"] != "workspaces":
            kinds=set(volume)-{"name"}
            module.need(len(kinds) == 1 and kinds <= {"configMap","secret","projected","downwardAPI","emptyDir"},"moving_original_source_node_with_other_persistent_volume_requires_its_native_bridge")
    module.need(not pod.get("initContainers") and not pod.get("ephemeralContainers") and not pod.get("hostNetwork") and not pod.get("hostPID"),"bounded_single_source_client_move_required")
    module.need(not pod.get("nodeName") and not pod.get("affinity") and not pod.get("topologySpreadConstraints"), "explicit_local_workspace_scheduling_profile_required")
    selected = pod.setdefault("nodeSelector", {})
    selected["kubernetes.io/hostname"] = master["metadata"]["labels"]["kubernetes.io/hostname"]
    module.need(all(master["metadata"]["labels"].get(key) == value for key, value in selected.items()), "original_master_node_selector_conflict")
    for taint in master["spec"].get("taints", []):
        if taint["effect"] not in ("NoSchedule", "NoExecute"):
            continue
        module.need(taint["key"] in ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master") and not taint.get("value"), "unreviewed_master_node_taint")
        toleration = {"key": taint["key"], "operator": "Exists", "effect": taint["effect"]}
        if toleration not in pod.setdefault("tolerations", []):
            pod["tolerations"].append(toleration)
    volumes = [volume for volume in pod.get("volumes", []) if volume["name"] == "workspaces"]
    module.need(len(volumes) == 1 and set(volumes[0]) == {"name", "nfs"} and volumes[0]["nfs"]["path"] == "/" and not volumes[0]["nfs"].get("readOnly"), "original_single_nfs_workspace_required")
    volumes[0].clear()
    volumes[0].update({"name": "workspaces", "persistentVolumeClaim": {"claimName": claim}})
    desired["strategy"] = {"type": "Recreate"}
    return desired


class WorkspaceLocalization:
    def __init__(self, operator):
        self.business = load_business()
        self.runtime = self.business.BusinessRuntimeStages(operator)
        self.op, self.m, self.stages = operator, self.runtime.m, self.runtime.stages
        self.sessions = []

    def object(self, resource, name):
        return self.stages.get(resource, name)

    def list(self, resource, namespace=True):
        args = ["-n", self.m.NS] if namespace else ["-A"]
        return self.m.decode(self.op.k("get", resource, *args, "-o", "json"))["items"]

    def deployment_for(self, pod):
        owner = self.m.only_controller(pod, "ReplicaSet")
        rs = self.object("replicaset", owner["name"])
        parent = self.m.only_controller(rs, "Deployment")
        self.m.need(rs["metadata"]["uid"] == owner["uid"], "original_workspace_rs_identity")
        deployment = self.object("deployment", parent["name"])
        self.m.need(deployment["metadata"]["uid"] == parent["uid"], "original_workspace_deployment_identity")
        return deployment

    def inventory(self):
        m = self.m
        namespace = m.decode(self.op.k("get", "namespace", m.NS, "-o", "json"))
        service = self.object("service", "workspace-store")
        server_ip = str(ipaddress.ip_address(service["spec"]["clusterIP"]))
        claim = self.object("pvc", CLAIM)
        pv = m.decode(self.op.k("get", "pv", claim["spec"]["volumeName"], "-o", "json"))
        m.need(claim["status"]["phase"] == "Bound" and pv["spec"]["claimRef"]["uid"] == claim["metadata"]["uid"] and pv["spec"]["claimRef"]["namespace"] == m.NS and pv["spec"].get("hostPath", {}).get("path") == ROOT and claim["spec"].get("volumeMode", "Filesystem") == "Filesystem", "exact_original_workspace_pvc_pv_required")
        all_pods = self.list("pods", namespace=False)
        clients, server = [], None
        deployments = {}
        for pod in all_pods:
            volumes = pod["spec"].get("volumes", [])
            uses_nfs = [volume for volume in volumes if volume.get("nfs", {}).get("server") == server_ip]
            uses_claim = [volume for volume in volumes if volume.get("persistentVolumeClaim", {}).get("claimName") == CLAIM and pod["metadata"]["namespace"] == m.NS]
            if not uses_nfs and not uses_claim:
                continue
            m.need(pod["metadata"]["namespace"] == m.NS and not pod["metadata"].get("deletionTimestamp") and pod["status"]["phase"] == "Running" and not pod["spec"].get("hostNetwork") and not pod["spec"].get("hostPID") and len(pod["spec"]["containers"]) == 1, "complete_owned_workspace_pod_profile_required")
            deployment = self.deployment_for(pod)
            name = deployment["metadata"]["name"]
            deployments[name] = deployment
            statuses = pod["status"].get("containerStatuses", [])
            m.need(len(statuses) == 1 and statuses[0].get("ready") and statuses[0].get("state", {}).get("running") is not None and statuses[0].get("containerID"), "actual_workspace_container_required")
            descriptor = {"namespace": m.NS, "node": pod["spec"]["nodeName"], "pod": pod["metadata"]["name"], "pod_uid": pod["metadata"]["uid"], "container_id": statuses[0]["containerID"], "nfs_server": server_ip,
                          "pod_ip":pod["status"]["podIP"],
                          "image_digest":m.image_id(statuses[0]["imageID"]),
                          "role": "application" if name == "clawmanager-app" else "agent"}
            if uses_nfs:
                m.need(name in CLIENTS and len(uses_nfs) == 1 and uses_nfs[0]["name"] == "workspaces" and uses_nfs[0]["nfs"]["path"] == "/" and not uses_nfs[0]["nfs"].get("readOnly"), "complete_finite_original_nfs_client_universe")
                mounts = [mount for mount in pod["spec"]["containers"][0].get("volumeMounts", []) if mount["name"] == "workspaces"]
                m.need(len(mounts) == 1 and mounts[0]["mountPath"] == "/workspaces" and not mounts[0].get("subPath") and not mounts[0].get("subPathExpr") and not mounts[0].get("readOnly"), "original_nfs_root_alias_profile")
                clients.append(descriptor)
            else:
                m.need(name == "workspace-store" and server is None and len(uses_claim) == 1, "single_original_pvc_export_server_required")
                server = descriptor
        m.need(server is not None and {self.deployment_for(next(pod for pod in all_pods if pod["metadata"]["uid"] == item["pod_uid"]))["metadata"]["name"] for item in clients} == CLIENTS and set(deployments) == CLIENTS | {"workspace-store"}, "complete_original_workspace_actor_roster_required")
        for client in clients:
            client["nfs_backend"]=server["pod_ip"]
        server["nfs_backend"]=server["pod_ip"]
        # A zero-replica controller is still a possible future writer. Its
        # absent Pod is not permission to omit it from the source universe.
        for deployment in self.list("deployments"):
            volumes=deployment["spec"]["template"]["spec"].get("volumes",[])
            if any(volume.get("nfs",{}).get("server") == server_ip or volume.get("persistentVolumeClaim",{}).get("claimName") == CLAIM for volume in volumes):
                name=deployment["metadata"]["name"]
                m.need(name in deployments and deployment["metadata"]["uid"] == deployments[name]["metadata"]["uid"] and deployment["spec"] == deployments[name]["spec"],"unmapped_zero_or_live_deployment_workspace_writer")
        # Current Service routing must name exactly the original server Pod.
        endpoints = self.object("endpoints", service["metadata"]["name"])
        addresses = [address for subset in endpoints.get("subsets", []) for address in subset.get("addresses", [])]
        m.need(len(addresses) == 1 and addresses[0].get("targetRef", {}).get("uid") == server["pod_uid"] and addresses[0].get("targetRef", {}).get("namespace") == m.NS, "actual_nfs_service_endpoint_original_server")
        for kind in ("statefulsets", "daemonsets", "jobs", "cronjobs"):
            for resource in self.list(kind):
                template = resource.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}) if kind == "cronjobs" else resource.get("spec", {}).get("template", {})
                m.need(not any(v.get("nfs", {}).get("server") == server_ip or v.get("persistentVolumeClaim", {}).get("claimName") == CLAIM for v in template.get("spec", {}).get("volumes", [])), "unmapped_future_workspace_writer")
        for hpa in self.list("hpa"):
            m.need(hpa["spec"]["scaleTargetRef"]["name"] not in deployments, "workspace_autoscaler_requires_explicit_native_fence")
        master = m.decode(self.op.k("get", "node", server["node"], "-o", "json"))
        nodes=m.decode(self.op.k("get","nodes","-o","json"))["items"]
        terms=pv["spec"].get("nodeAffinity",{}).get("required",{}).get("nodeSelectorTerms",[])
        def matches(node):
            for term in terms:
                rules=term.get("matchExpressions",[])
                m.need(rules and not term.get("matchFields"),"explicit_original_pv_node_affinity_profile_required")
                m.need(all(rule["operator"] in ("In","Exists") and (bool(rule.get("values")) if rule["operator"] == "In" else not rule.get("values")) for rule in rules),"reviewed_original_pv_node_affinity_required")
                if all(node["metadata"].get("labels",{}).get(rule["key"]) in rule["values"] if rule["operator"] == "In" else rule["key"] in node["metadata"].get("labels",{}) for rule in rules):
                    return True
            return False
        m.need(terms and [node["metadata"]["uid"] for node in nodes if matches(node)] == [master["metadata"]["uid"]],"same_original_pv_unique_actual_server_node_required")
        return {"namespace_uid": namespace["metadata"]["uid"], "service": service, "endpoints": endpoints, "pvc": claim, "pv": pv, "clients": clients, "server": server, "deployments": deployments, "master": master}

    def patch(self, stage, name, before, desired):
        current = self.object("deployment", name)
        self.m.need(current["metadata"]["uid"] == before["metadata"]["uid"] and current["spec"] == before["spec"], "original_workspace_guarded_spec_changed")
        patch = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}, {"op": "test", "path": "/spec", "value": before["spec"]}, {"op": "replace", "path": "/spec", "value": desired}]
        self.stages.kubectl(stage, ["patch", "deployment", name, "--type=json", "--patch-file=/dev/stdin", "-o", "json"], patch)
        actual = self.object("deployment", name)
        self.m.need(actual["metadata"]["uid"] == before["metadata"]["uid"] and actual["spec"] == desired, "actual_workspace_patch_readback_changed")
        return actual

    def stopped(self, stage, original):
        desired = copy.deepcopy(original["spec"])
        desired["replicas"] = 0
        return self.patch(stage, original["metadata"]["name"], original, desired)

    def native_sessions(self, inventory, direction):
        by_node = {item["node"] for item in inventory["clients"]}
        if inventory.get("server"):
            by_node.add(inventory["server"]["node"])
        sessions = {}
        for name in sorted(by_node):
            node = self.m.decode(self.op.k("get", "node", name, "-o", "json"))
            definition = {"version": "original-workspace-localization-native.v1", "operation": self.stages.operation, "session": secrets.token_hex(16), "direction": direction,
                          "node": None, "cri_binary": "", "cri_endpoint": "", "containers": [item for item in inventory["clients"] if item["node"] == name],
                          "server": inventory.get("server") if (inventory.get("server") or {}).get("node") == name else None}
            session = NativeSession(self, node, definition)
            self.sessions.append(session)
            sessions[name] = session
        return sessions

    def runtime_materials(self, stage, baseline=None, ca=None, require_shared=False):
        definition = {"Version": "original-workspace-runtime-observation.v1", "Operation": self.stages.operation, "Baseline": baseline or {"File": "", "SHA256": ""}, "AgentCA": ca or {"File": "", "SHA256": ""}, "RequireShared": require_shared}
        pin = self.stages.retain(stage + ".definition.json", definition)
        directory = self.stages.directory / stage
        directory.mkdir(mode=0o700, exist_ok=True)
        return self.stages.cli(stage, "system-backup-observer-deployment-materials", ["--mode", "workspace-runtime-readback" if baseline else "workspace-runtime-baseline", "--definition-file", pin["File"], "--definition-sha256", pin["SHA256"], "--output-directory", directory])

    def stop_original_gateways(self, baseline, baseline_pin, ca=None, suffix="forward"):
        m = self.m
        _,_,installation,_=self.stages.common()
        for agent in baseline["Agents"]:
            for gateway in agent["Gateways"]:
                name = "workspace-gateway-stop-" + suffix + "-" + str(gateway["instance_id"])
                definition = self.stages.retain(name + ".definition.json", {"Version":"original-workspace-gateway-stop.v1", "Operation":self.stages.operation, "PodUID":agent["PodUID"], "GatewayID":gateway["gateway_id"], "Baseline":baseline_pin, "AgentCA":ca or {"File":"", "SHA256":""}})
                directory=Path("/var/lib/clawmanager-system-backup/workspace-gateway-stops")/m.digest(installation["Target"]["InstallationID"].encode())[:24]/self.stages.operation/m.digest((agent["PodUID"]+":"+gateway["gateway_id"]).encode())[:32]
                for parent in reversed([directory,*directory.parents][:-1]):
                    if parent.exists() or parent.is_symlink():
                        info=parent.lstat()
                        m.need(stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and info.st_uid == 0 and info.st_mode&0o022 == 0,"fixed_original_gateway_custody_parent_rejected")
                    else:
                        parent.mkdir(mode=0o700)
                        m.sync(parent.parent)
                m.need(stat.S_IMODE(directory.stat().st_mode) == 0o700,"fixed_original_gateway_custody_must_be_private")
                self.stages.retain(name+".custody.json",{"operation":self.stages.operation,"definition":definition,"directory":str(directory),"pod_uid":agent["PodUID"],"gateway_id":gateway["gateway_id"]})
                self.stages.cli(name, "system-backup-observer-deployment-materials", ["--mode","workspace-runtime-stop","--definition-file",definition["File"],"--definition-sha256",definition["SHA256"],"--output-directory",directory])

    def wait_absent(self, sessions, action):
        deadline = time.monotonic() + 180
        # Native read-only exit queries may repeat; original mutations never do.
        pending = set(sessions)
        while pending:
            self.m.need(time.monotonic() < deadline, "original_workspace_process_exit_unconfirmed")
            for name in list(pending):
                try:
                    sessions[name].rpc(action)
                    pending.remove(name)
                except self.m.Refused as error:
                    self.m.need(str(error).startswith("native_refused:"),"native_transport_unknown_reconnect_original_session_required")
                    time.sleep(1)

    def wait_pods_gone(self, uids):
        deadline = time.monotonic() + 180
        while True:
            current = {pod["metadata"]["uid"] for pod in self.list("pods")}
            if not current.intersection(uids):
                return
            self.m.need(time.monotonic() < deadline, "original_workspace_pods_not_removed_after_fd_close")
            time.sleep(1)

    def app_tls_trust(self, desired, tls_material):
        m, stages = self.m, self.stages
        stages.preinstall_api_runtime_mount(desired)
        body = m.pinned(tls_material["CA"])
        name = stages.prefix + "-runtime-agent-ca"
        cm = stages.create_object("workspace-app-agent-ca", {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": m.NS}, "immutable": True, "data": {"ca.crt": body.decode("ascii")}})
        pod = desired["template"]["spec"]
        container = pod["containers"][0]
        m.need(not any(m.overlap(mount["mountPath"], "/etc/clawmanager-runtime-agent-ca") for mount in container.get("volumeMounts", [])), "original_business_agent_ca_mount_collision")
        m.need(not any(volume["name"] == "sbk-runtime-agent-ca" for volume in pod.get("volumes", [])), "original_business_agent_ca_volume_collision")
        for key, value in {"RUNTIME_AGENT_CA_FILE": "/etc/clawmanager-runtime-agent-ca/ca.crt", "RUNTIME_AGENT_CA_SHA256": tls_material["CA"]["SHA256"], "RUNTIME_WORKSPACE_PVC_CLAIM": CLAIM}.items():
            m.upsert(container.setdefault("env", []), key, value)
        pod.setdefault("volumes", []).append({"name": "sbk-runtime-agent-ca", "configMap": {"name": name, "defaultMode": 292}})
        container.setdefault("volumeMounts", []).append({"name": "sbk-runtime-agent-ca", "mountPath": "/etc/clawmanager-runtime-agent-ca/ca.crt", "subPath": "ca.crt", "readOnly": True})
        return {"Name": name, "UID": cm["metadata"]["uid"], "CA": tls_material["CA"]}

    def app_readback(self,plan,direct=True):
        m=self.m
        spec=plan["desired"]["clawmanager-app"] if direct else plan["reverse_specs"]["clawmanager-app"]
        original=plan["original"]["deployments"]["clawmanager-app"]
        pods=self.wait_deployment("clawmanager-app",spec,original["metadata"]["uid"])
        image_result=m.decode(m.read(self.stages.directory/"new-image.result.json"))
        m.need(image_result["app"]["UID"] == original["metadata"]["uid"] and image_result["app"]["SpecSHA256"] == m.digest(m.encoded(original["spec"])),"workspace_app_overlay_original_release_lineage_changed")
        expected_image=image_result["images"]["app"]
        env={item["name"]:item.get("value") for item in spec["template"]["spec"]["containers"][0].get("env",[])}
        paths=[("/etc/clawmanager-business-mysql-ca/ca.crt",env["DB_TLS_CA_SHA256"])]
        if direct:
            cm=self.object("configmap",plan["app_agent_ca"]["Name"])
            m.need(cm["metadata"]["uid"] == plan["app_agent_ca"]["UID"] and cm.get("immutable") is True and cm.get("data",{}) == {"ca.crt":m.pinned(plan["app_agent_ca"]["CA"]).decode("ascii")},"workspace_actual_app_agent_ca_object_changed")
            paths.append(("/etc/clawmanager-runtime-agent-ca/ca.crt",env["RUNTIME_AGENT_CA_SHA256"]))
        script="\n".join("test ! -L "+shlex.quote(path)+"; test -f "+shlex.quote(path)+"; sha256sum "+shlex.quote(path) for path,_ in paths)
        observations=[]
        for pod in pods:
            state=pod["status"]["containerStatuses"][0]
            m.need(m.image_id(state["imageID"]) in ("sha256:"+expected_image["manifest_sha256"],expected_image["config_digest"]),"workspace_app_actual_original_release_image_changed")
            raw=self.op.k("-n",m.NS,"exec",pod["metadata"]["name"],"-c",state["name"],"--","/bin/sh","-ec",script)
            lines=raw.decode("ascii").splitlines()
            m.need(len(lines) == len(paths) and all(line.split() == [digest,path] for line,(path,digest) in zip(lines,paths)),"actual_business_ca_regular_file_eof_readback_failed")
            again=self.object("pod",pod["metadata"]["name"])
            m.need(again["metadata"]["uid"] == pod["metadata"]["uid"] and again["spec"] == pod["spec"] and again["status"]["containerStatuses"][0]["containerID"] == state["containerID"] and again["status"]["containerStatuses"][0]["imageID"] == state["imageID"],"workspace_app_actor_changed_during_ca_readback")
            observations.append({"pod_uid":pod["metadata"]["uid"],"container_id":state["containerID"],"image_id":state["imageID"],"files":[{"path":path,"sha256":digest} for path,digest in paths]})
        return {"original_new_image_result":m.pin(self.stages.directory/"new-image.result.json"),"actual_spec_sha256":m.digest(m.encoded(spec)),"observations":observations}

    def nfs_client_boundary(self,sessions,inventory,label):
        """Only original actual source-node addresses can own NFSD states."""
        nodes={item["node"] for item in inventory["clients"]}
        networks={name:sessions[name].rpc("source-node-network") for name in sorted(nodes)}
        owners={}
        for name,result in networks.items():
            self.m.need(result["node"] == sessions[name].definition["node"],"same_original_native_node_network_reply_required")
            for interface in result["ipv4_interfaces"]:
                owners.setdefault(interface["address"],set()).add(name)
        server=sessions[inventory["server"]["node"]]
        census=server.rpc("source-nfs-client-census")
        self.m.need(census["server"] == inventory["server"] and census["node"] == server.definition["node"],"same_original_server_native_client_reply_required")
        for client in census["clients"]:
            self.m.need(len(owners.get(client["address"],set())) == 1,"unknown_or_ambiguous_original_nfs_v4_client_or_delegation_owner")
            self.m.need(all(kind in ("open","lock","deleg") for kind in client["state_kinds"]),"unknown_original_nfs_v4_state_or_delegation_kind")
        result={"version":"original-nfs-v4-client-boundary-data.v1","operation":self.stages.operation,"source_node_networks":networks,"actual_server_clients":census,"delegation_flush_proved":False,"network_admission_fence_proved":False,"backup_ready":False}
        cohort=self.m.digest(self.m.encoded({name:session.definition["session"] for name,session in sessions.items()}))[:16]
        self.stages.retain(label+"-"+cohort+".json",result)
        return result

    def forward(self, probe_only=False):
        m, stages = self.m, self.stages
        self.op.workspace_upgrade_released()
        stages.common()
        inventory = self.inventory()
        image_path=stages.directory/"new-image.result.json"
        m.need(image_path.exists(),"actual_completed_original_business_release_required_before_workspace_migration")
        business_image=m.decode(m.read(image_path))
        original_app=inventory["deployments"]["clawmanager-app"]
        m.need(business_image["app"]["UID"] == original_app["metadata"]["uid"] and business_image["app"]["SpecSHA256"] == m.digest(m.encoded(original_app["spec"])),"original_business_release_template_changed_before_workspace_migration")
        suffix = "probe-"+secrets.token_hex(8) if probe_only else "before"
        snapshot, snapshot_pin = self.runtime_materials("workspace-runtime-"+suffix)
        inventory["runtime_before"] = snapshot_pin
        stages.retain("workspace-localization."+suffix+".json" if probe_only else "workspace-localization.original.json", inventory)
        sessions = self.native_sessions(inventory, "probe" if probe_only else "to-local")
        self.nfs_client_boundary(sessions,inventory,"workspace-nfs-clients-before-tree-read")
        for session in sessions.values():
            session.rpc("preflight-tree-profile")
            session.rpc("source-mount-census")
        clients_before=self.nfs_client_boundary(sessions,inventory,"workspace-nfs-clients-before-source-stop")
        if probe_only:
            for session in sessions.values():
                session.rpc("abort-before-mutation")
                session.rpc("retire-owner")
            return {"version": "original-workspace-localization-probe.v1", "state": "actual_native_inputs_observed_no_source_changed", "operation": stages.operation, "backup_ready": False}
        images = m.decode(m.read(stages.directory / "runtime-images.result.json"))
        m.pinned(images["startup_images"])
        universe = self.runtime.inventory()
        m.need({item["metadata"]["uid"] for item in universe} == {inventory["deployments"][name]["metadata"]["uid"] for name in CLIENTS-{"clawmanager-app"}},"complete_same_original_runtime_roster_required")
        tls_result, tls_material = self.runtime.agent_tls_materials(universe)
        targets = {target["DeploymentUID"]: target for target in tls_material["Targets"]}
        desired = {}
        runtime_plan = []
        for original in universe:
            proof=self.runtime.original_images.get(original["metadata"]["name"])
            kind, spec = self.business.desired_spec(original, stages.operation, m, original_image=proof, agent_tls=targets[original["metadata"]["uid"]])
            spec = direct_spec(spec, inventory["master"], CLAIM, m)
            spec["template"].setdefault("metadata", {}).setdefault("annotations", {})[PROFILE] = "shared-container-freeze.v1"
            desired[original["metadata"]["name"]] = spec
            runtime_plan.append({"runtime": kind, "original": original, "desired": spec,"original_image":proof})
        desired["clawmanager-app"] = direct_spec(inventory["deployments"]["clawmanager-app"]["spec"], inventory["master"], CLAIM, m)
        app_ca = self.app_tls_trust(desired["clawmanager-app"], tls_material)
        reverse_specs={name:copy.deepcopy(value["spec"]) for name,value in inventory["deployments"].items()}
        for original in universe:
            proof=self.runtime.original_images.get(original["metadata"]["name"])
            if proof:
                container=reverse_specs[original["metadata"]["name"]]["template"]["spec"]["containers"][0]
                container["image"]=container["image"].rsplit(":",1)[0]+"@"+proof["selected_manifest"]
        server_original_pod=next(pod for pod in self.list("pods") if pod["metadata"]["uid"] == inventory["server"]["pod_uid"])
        server_image=server_original_pod["status"]["containerStatuses"][0]["imageID"].removeprefix("docker-pullable://")
        m.need("@sha256:" in server_image,"original_server_pullable_immutable_image_identity_required")
        reverse_specs["workspace-store"]["template"]["spec"]["containers"][0]["image"]=server_image
        plan = {"version": "original-workspace-localization-plan.v1", "operation": stages.operation, "original": inventory, "desired": desired,"reverse_specs":reverse_specs, "native_definitions":[session.definition for session in sessions.values()], "agent_tls_materials": tls_result["materials_receipt"], "app_agent_ca": app_ca}
        stages.retain("workspace-localization.plan.json", plan)
        # Stop backend first so SDK deletes cannot change original SQL desired
        # states to stopped. Actual original app process exit is checked natively.
        stopped = {"clawmanager-app": self.stopped("workspace-stop-app", inventory["deployments"]["clawmanager-app"])}
        self.wait_absent(sessions, "confirm-application-exit")
        self.stop_original_gateways(snapshot, snapshot_pin)
        for name in sorted(CLIENTS - {"clawmanager-app"}):
            stopped[name] = self.stopped("workspace-stop-" + name, inventory["deployments"][name])
        self.wait_absent(sessions, "confirm-client-exit")
        mount_census={name:session.rpc("source-mount-census") for name,session in sessions.items()}
        # Each original node's real FD/COMMIT observation is required, even if
        # the server is on another node. A caller boolean is never substituted.
        commits = {name: session.rpc("sync-clients") for name, session in sessions.items()}
        clients_at_commit=self.nfs_client_boundary(sessions,inventory,"workspace-nfs-clients-after-original-commit")
        server_session = sessions[inventory["server"]["node"]]
        isolated = server_session.rpc("isolate-server")
        m.need(all(item["tree"] == isolated["tree"] for result in commits.values() for item in result), "all_original_clients_server_full_tree_mismatch")
        for session in sessions.values():
            session.rpc("close-client-fds")
        self.wait_pods_gone({item["pod_uid"] for item in inventory["clients"]})
        self.stopped("workspace-stop-nfs-server", inventory["deployments"]["workspace-store"])
        self.wait_absent({inventory["server"]["node"]:server_session}, "confirm-server-exit")
        final_server = server_session.rpc("finalize-server-stop")
        m.need(final_server["tree"] == isolated["tree"], "original_server_tree_drift_after_cold_stop")
        server_session.rpc("close-server-fds")
        self.wait_pods_gone({inventory["server"]["pod_uid"]})
        for name in sorted(CLIENTS):
            self.patch("workspace-direct-template-" + name, name, stopped[name], desired[name])
        # A positive deployment observation only; the genuine original backup
        # factory must subsequently prepare/hold this actual source universe.
        stages.retain("workspace-localization.native-cut.json", {"version": "original-workspace-localization-native-cut.v1", "operation": stages.operation,"nfs_clients_before":clients_before,"nfs_clients_at_commit":clients_at_commit,"node_mount_census":mount_census, "commits": commits, "server": final_server, "pvc_uid": inventory["pvc"]["metadata"]["uid"], "pv_uid": inventory["pv"]["metadata"]["uid"], "backup_ready": False})
        stages.retain("runtime-rollout.plan.json", {"version": "operator-original-business-runtime-rollout-plan.v1", "operation": stages.operation, "agent_tls_materials": tls_result["materials_receipt"], "deployments": runtime_plan})
        self.runtime.rollout(query=True)
        app_observation=self.app_readback(plan)
        recovered, recovered_pin = self.runtime_materials("workspace-runtime-after", baseline=snapshot_pin, ca=tls_material["CA"], require_shared=True)
        result = {"version": "original-workspace-localization-result.v1", "operation": stages.operation, "state": "actual_same_pvc_native_cut_and_original_business_readback_complete", "original": m.pin(stages.directory / "workspace-localization.original.json"), "plan": m.pin(stages.directory / "workspace-localization.plan.json"), "native_cut": m.pin(stages.directory / "workspace-localization.native-cut.json"), "business_readback": recovered_pin,
                  "source_instances": len(recovered["Instances"]),"app_overlay_readback":app_observation, "pvc_uid": inventory["pvc"]["metadata"]["uid"], "pv_uid": inventory["pv"]["metadata"]["uid"], "backup_ready": False, "DR": False}
        stages.retain("workspace-localization.result.json", result)
        return result

    def guarded_transition(self, name, target, plan, stage):
        """A fresh exact read can resolve a lost Kubernetes response."""
        current=self.object("deployment",name)
        original=plan["original"]["deployments"][name]
        self.m.need(current["metadata"]["uid"] == original["metadata"]["uid"],"workspace_reversal_original_deployment_replaced")
        allowed=[original["spec"],plan["reverse_specs"][name]]
        if name in plan["desired"]:
            allowed.append(plan["desired"][name])
        allowed += [dict(value,replicas=0) for value in list(allowed)]
        self.m.need(current["spec"] in allowed,"workspace_reversal_unowned_template_change")
        if current["spec"] == target:
            return current
        return self.patch(stage+"-"+self.m.digest(self.m.encoded(target))[:16],name,current,target)

    def once(self, session, action):
        status=session.rpc("session-status")
        prior=status["replies"].get(action)
        if prior is not None:
            self.m.need("data" in prior,"original_native_action_unconfirmed_no_replay:"+action)
            return prior["data"]
        return session.rpc(action)

    def descriptor(self,pod,name,server_ip):
        self.m.need(pod["metadata"]["namespace"] == self.m.NS and len(pod["spec"]["containers"]) == 1 and not pod["spec"].get("hostNetwork") and not pod["spec"].get("hostPID"),"finite_owned_reverse_pod_required")
        states=pod["status"].get("containerStatuses",[])
        self.m.need(len(states) == 1 and states[0].get("containerID") and states[0].get("state",{}).get("running") is not None,"actual_reverse_running_container_required")
        return {"namespace":self.m.NS,"node":pod["spec"]["nodeName"],"pod":pod["metadata"]["name"],"pod_uid":pod["metadata"]["uid"],"container_id":states[0]["containerID"],"image_digest":self.m.image_id(states[0]["imageID"]),"nfs_server":server_ip,"role":"application" if name == "clawmanager-app" else "agent"}

    def new_reverse_clients(self,plan):
        original=plan["original"]
        known={item["pod_uid"] for item in original["clients"]}
        clients=[]
        server_ip=original["service"]["spec"]["clusterIP"]
        for pod in self.list("pods",namespace=False):
            volumes=pod["spec"].get("volumes",[])
            roots=[v for v in volumes if v.get("nfs",{}).get("server") == server_ip or pod["metadata"]["namespace"] == self.m.NS and v.get("persistentVolumeClaim",{}).get("claimName") == CLAIM]
            if not roots:
                continue
            self.m.need(pod["metadata"]["namespace"] == self.m.NS,"foreign_writer_appeared_during_workspace_reversal")
            dep=self.deployment_for(pod)
            name=dep["metadata"]["name"]
            self.m.need(name in plan["original"]["deployments"] and dep["metadata"]["uid"] == original["deployments"][name]["metadata"]["uid"],"unmapped_writer_appeared_during_workspace_reversal")
            if name == "workspace-store" or pod["metadata"]["uid"] in known:
                continue
            states=pod["status"].get("containerStatuses",[])
            if pod["status"]["phase"] == "Pending" and all(not state.get("containerID") and state.get("restartCount",0) == 0 for state in states):
                continue
            self.m.need(len(roots) == 1 and roots[0]["name"] == "workspaces","reverse_source_alias_unknown")
            mounts=[item for item in pod["spec"]["containers"][0].get("volumeMounts",[]) if item["name"] == "workspaces"]
            self.m.need(len(mounts) == 1 and mounts[0]["mountPath"] == "/workspaces" and not mounts[0].get("subPath") and not mounts[0].get("subPathExpr"),"reverse_original_workspace_root_required")
            clients.append(self.descriptor(pod,name,server_ip))
        return {"clients":clients,"server":None}

    def wait_deployment(self,name,spec,uid):
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            deployment=self.object("deployment",name)
            self.m.need(deployment["metadata"]["uid"] == uid and deployment["spec"] == spec,"restored_deployment_identity_or_template_changed")
            pods=[]
            selector=spec["selector"]
            self.m.need(selector.get("matchLabels") and not selector.get("matchExpressions"),"finite_restored_deployment_selector_required")
            for pod in self.list("pods"):
                if all(pod["metadata"].get("labels",{}).get(key) == value for key,value in selector["matchLabels"].items()):
                    owner=self.deployment_for(pod)
                    self.m.need(owner["metadata"]["uid"] == uid,"restored_deployment_selector_alias")
                    pods.append(pod)
            count=spec.get("replicas",1)
            if len(pods) == count and deployment.get("status",{}).get("observedGeneration",0)>=deployment["metadata"]["generation"] and all(not pod["metadata"].get("deletionTimestamp") and pod["status"]["phase"] == "Running" and len(pod["status"].get("containerStatuses",[])) == 1 and pod["status"]["containerStatuses"][0].get("ready") for pod in pods):
                return pods
            time.sleep(2)
        raise self.m.Refused("actual_restored_deployment_readiness_unconfirmed:"+name)

    def restored_server_observer(self,server):
        """Resume the same read-only bridge after a lost SSH response.

        Definitions are retained BEFORE the first connection. Only actual
        positive handle-release responses allow ignoring a retired observer;
        original transition/client owners always remain strictly attach-only.
        """
        m,stages=self.m,self.stages
        selected=None
        for path in sorted(stages.directory.glob("workspace-native-definition-*.json")):
            definition=m.decode(m.read(path))
            if definition.get("direction") != "observe-restored-server":
                continue
            m.need(definition["operation"] == stages.operation and not definition["containers"],"same_original_read_only_server_observer_required")
            records=stages.directory.glob("workspace-native-"+definition["session"]+"-*.actual-observation.json")
            released=any((lambda r:r.get("operation") == stages.operation and r.get("session") == definition["session"] and r.get("action") in ("release-restored-observation","abort-before-mutation") and "data" in r)(m.decode(m.read(record))) for record in records)
            if released:
                continue
            node=m.decode(self.op.k("get","node",definition["node"]["name"],"-o","json"))
            session=NativeSession(self,node,copy.deepcopy(definition),attach_only=True)
            self.sessions.append(session)
            status=session.rpc("session-status")
            if status["server_closed"] and status["clients_closed"]:
                session.rpc("retire-owner")
                continue
            same=definition["server"]["pod_uid"] == server["pod_uid"] and definition["server"]["container_id"] == server["container_id"]
            if same and selected is None:
                selected=session
            else:
                # This role cannot unexport, stop, sync clients or modify the
                # source. Its abandoned observation handles are safe to close.
                if not status["server_closed"]:
                    self.once(session,"abort-before-mutation")
                session.rpc("retire-owner")
        if selected is None:
            sessions=self.native_sessions({"clients":[],"server":server},"observe-restored-server")
            selected=sessions[server["node"]]
        return selected

    def reverse(self):
        """Restore the SAME original PVC and original business desired states.

        This is also the recovery entry after an interrupted forward command.
        Old owners must remain alive; a missing owner is never re-prepared.
        Full-tree migration failure is retained, not relabelled as integrity
        proof. Same-inode operational restoration has its own exact outcome.
        """
        m,stages=self.m,self.stages
        if (stages.directory/"workspace-reversal.result.json").exists():
            return self.query()
        self.op.workspace_upgrade_released()
        stages.common()
        plan=m.decode(m.read(stages.directory/"workspace-localization.plan.json"))
        m.need(plan["version"] == "original-workspace-localization-plan.v1" and plan["operation"] == stages.operation,"same_original_workspace_reversal_plan_required")
        original=plan["original"]
        namespace=m.decode(self.op.k("get","namespace",m.NS,"-o","json"))
        claim=self.object("pvc",CLAIM)
        pv=m.decode(self.op.k("get","pv",original["pv"]["metadata"]["name"],"-o","json"))
        m.need(namespace["metadata"]["uid"] == original["namespace_uid"] and claim["metadata"]["uid"] == original["pvc"]["metadata"]["uid"] and claim["spec"] == original["pvc"]["spec"] and pv["metadata"]["uid"] == original["pv"]["metadata"]["uid"] and pv["spec"] == original["pv"]["spec"],"original_workspace_pvc_pv_changed_cannot_reverse")
        old={}
        for definition in plan["native_definitions"]:
            node=m.decode(self.op.k("get","node",definition["node"]["name"],"-o","json"))
            session=NativeSession(self,node,copy.deepcopy(definition),attach_only=True)
            self.sessions.append(session)
            old[node["metadata"]["name"]]=session
        old_server=old[original["server"]["node"]]
        fresh_inventory=self.new_reverse_clients(plan)
        reverse_plan_path=stages.directory/"workspace-reversal.plan.json"
        if reverse_plan_path.exists():
            reverse_plan=m.decode(m.read(reverse_plan_path))
            m.need(reverse_plan["operation"] == stages.operation and reverse_plan["forward_plan"] == m.pin(stages.directory/"workspace-localization.plan.json"),"same_original_workspace_reverse_operation_required")
            fresh={}
            for definition in reverse_plan["native_definitions"]:
                node=m.decode(self.op.k("get","node",definition["node"]["name"],"-o","json"))
                session=NativeSession(self,node,copy.deepcopy(definition),attach_only=True)
                self.sessions.append(session)
                fresh[definition["session"]]=session
        else:
            fresh=self.native_sessions(fresh_inventory,"to-nfs")
            reverse_plan={"version":"original-workspace-reversal-plan.v1","operation":stages.operation,"forward_plan":m.pin(stages.directory/"workspace-localization.plan.json"),"native_definitions":[s.definition for s in fresh.values()],"fresh_clients":fresh_inventory["clients"]}
            stages.retain(reverse_plan_path.name,reverse_plan)
        reverse_clients=list(reverse_plan["fresh_clients"])
        for path in sorted(stages.directory.glob("workspace-reversal-round-*.json")):
            round_plan=m.decode(m.read(path))
            m.need(round_plan["operation"] == stages.operation and round_plan["reverse_plan"] == m.pin(reverse_plan_path),"same_original_reversal_round_required")
            reverse_clients.extend(round_plan["clients"])
            for definition in round_plan["native_definitions"]:
                node=m.decode(self.op.k("get","node",definition["node"]["name"],"-o","json"))
                session=NativeSession(self,node,copy.deepcopy(definition),attach_only=True)
                self.sessions.append(session)
                fresh[definition["session"]]=session
        captured={item["pod_uid"] for item in reverse_clients}
        additional=[item for item in fresh_inventory["clients"] if item["pod_uid"] not in captured]
        if additional:
            extra=self.native_sessions({"clients":additional,"server":None},"to-nfs")
            round_plan={"version":"original-workspace-reversal-round.v1","operation":stages.operation,"reverse_plan":m.pin(reverse_plan_path),"clients":additional,"native_definitions":[session.definition for session in extra.values()]}
            stages.retain("workspace-reversal-round-"+secrets.token_hex(8)+".json",round_plan)
            reverse_clients.extend(additional)
            fresh.update({session.definition["session"]:session for session in extra.values()})
        sessions=list(old.values())+list(fresh.values())
        indexed={str(index):session for index,session in enumerate(sessions)}
        for name in ["clawmanager-app"]:
            current=self.object("deployment",name)
            self.guarded_transition(name,dict(current["spec"],replicas=0),plan,"workspace-reverse-stop-"+name)
        for session in sessions:
            self.once(session,"stop-original-application")
        self.wait_absent(indexed,"confirm-application-exit")
        for name in sorted(CLIENTS-{"clawmanager-app"}):
            current=self.object("deployment",name)
            self.guarded_transition(name,dict(current["spec"],replicas=0),plan,"workspace-reverse-stop-"+name)
        for session in sessions:
            self.once(session,"stop-original-clients")
        self.wait_absent(indexed,"confirm-client-exit")
        current_server_pods=[pod for pod in self.list("pods") if pod["metadata"]["uid"] == original["server"]["pod_uid"]]
        server_dep=self.object("deployment","workspace-store")
        server_states=current_server_pods[0]["status"].get("containerStatuses",[]) if current_server_pods else []
        original_server_running=bool(len(server_states) == 1 and server_states[0].get("containerID") == original["server"]["container_id"] and server_states[0].get("state",{}).get("running") is not None)
        keep_original_server=bool(original_server_running and not current_server_pods[0]["metadata"].get("deletionTimestamp") and server_dep["spec"].get("replicas",1)>0)
        server_status=old_server.rpc("session-status")
        if not server_status["server_closed"] and original_server_running:
            try:
                self.once(old_server,"restore-original-server")
            except m.Refused as error:
                m.need(str(error).startswith(("native_refused:","original_native_action_unconfirmed_no_replay:")),"same_original_server_owner_transport_unknown")
                # A real same-owner refusal is not restoration. The guarded
                # cold path below must independently prove all original netns
                # users absent and actual NFSD/export shutdown before restart.
                keep_original_server=False
        fresh_server=None
        if keep_original_server:
            restored=old_server.rpc("verify-server-restored")
        else:
            # Re-establish the real original server BEFORE flushing held NFS
            # client FDs. Flushing an original NFS mount against a dead server
            # cannot succeed. Original client scopes are already absent; their
            # actual FDs remain in their SAME persistent owners throughout.
            server_status=old_server.rpc("session-status")
            if not server_status["server_closed"]:
                current=self.object("deployment","workspace-store")
                self.guarded_transition("workspace-store",dict(current["spec"],replicas=0),plan,"workspace-reverse-stop-server")
                self.once(old_server,"stop-original-server")
                self.wait_absent({"server":old_server},"confirm-server-exit")
                self.once(old_server,"close-dead-server-for-recovery")
            else:
                self.wait_absent({"server":old_server},"confirm-server-exit")
            self.wait_pods_gone({original["server"]["pod_uid"]})
            self.guarded_transition("workspace-store",plan["reverse_specs"]["workspace-store"],plan,"workspace-reverse-start-server")
            pods=self.wait_deployment("workspace-store",plan["reverse_specs"]["workspace-store"],original["deployments"]["workspace-store"]["metadata"]["uid"])
            m.need(len(pods) == 1 and pods[0]["metadata"]["uid"] != original["server"]["pod_uid"],"fresh_restored_server_incarnation_required")
            server=self.descriptor(pods[0],"workspace-store",original["service"]["spec"]["clusterIP"])
            m.need(server["node"] == original["server"]["node"] and server["image_digest"] == original["server"]["image_digest"],"restored_server_original_node_and_image_required")
            fresh_server=self.restored_server_observer(server)
            restored=fresh_server.rpc("verify-server-restored")
            original_probe=old_server.rpc("session-status")["replies"]["probe"]["data"]["server"]
            m.need(restored["exports"] == original_probe["exports"] and restored["pin"]["device"] == original_probe["pin"]["device"] and restored["pin"]["inode"] == original_probe["pin"]["inode"],"restored_server_original_export_and_pvc_inode_bridge_required")
            endpoints=self.object("endpoints",original["service"]["metadata"]["name"])
            addresses=[address for subset in endpoints.get("subsets",[]) for address in subset.get("addresses",[])]
            m.need(len(addresses) == 1 and addresses[0].get("targetRef",{}).get("uid") == server["pod_uid"],"fresh_restored_server_service_route_unconfirmed")
        syncs=[]
        for session in sessions:
            status=session.rpc("session-status")
            if not status["clients_closed"]:
                syncs.append(self.once(session,"sync-clients-for-recovery"))
                self.once(session,"close-recovery-client-fds")
        self.wait_pods_gone({item["pod_uid"] for item in original["clients"]+reverse_clients})
        if keep_original_server:
            self.once(old_server,"release-restored-observation")
        else:
            self.once(fresh_server,"release-restored-observation")
            fresh_server.rpc("retire-owner")
        for name in sorted(CLIENTS):
            self.guarded_transition(name,plan["reverse_specs"][name],plan,"workspace-reverse-template-"+name)
        observed={}
        for name in sorted(CLIENTS):
            observed[name]=self.wait_deployment(name,plan["reverse_specs"][name],original["deployments"][name]["metadata"]["uid"])
        app_observation=self.app_readback(plan,direct=False)
        recovered,recovered_pin=self.runtime_materials("workspace-runtime-reversed",baseline=original["runtime_before"])
        result={"version":"original-workspace-reversal-result.v1","operation":stages.operation,"state":"actual_original_nfs_source_and_business_states_restored","forward_plan":m.pin(stages.directory/"workspace-localization.plan.json"),"reverse_plan":m.pin(reverse_plan_path),"same_pvc_uid":claim["metadata"]["uid"],"same_pv_uid":pv["metadata"]["uid"],"server_observation":restored,"server_spec":self.object("deployment","workspace-store")["spec"],"original_mount_syncs":syncs,"business_readback":recovered_pin,"app_readback":app_observation,"source_instances":len(recovered["Instances"]),"original_image_tags_replaced_by_exact_original_digest":True,"full_tree_integrity_proved":False,"backup_ready":False,"DR":False}
        stages.retain("workspace-reversal.result.json",result)
        # Keep old owners alive until every actual source has been read back.
        # A failure earlier deliberately leaves the original recovery handles.
        for session in sessions:
            session.rpc("retire-owner")
        return result

    def query(self,abort_probe=False):
        """Read actual original owners; never repeat an uncertain mutation."""
        m,stages=self.m,self.stages
        stages.common()
        statuses=[]
        completed_reverse=(stages.directory/"workspace-reversal.result.json").exists()
        plan_path=stages.directory/"workspace-localization.plan.json"
        if abort_probe:
            m.need(not plan_path.exists(),"reviewed_forward_plan_exists_use_workspace_restore_nfs")
        if not completed_reverse:
            for path in sorted(stages.directory.glob("workspace-native-definition-*.json")):
                definition=m.decode(m.read(path))
                m.need(definition["operation"] == stages.operation,"same_original_native_definition_required")
                replies=stages.directory.glob("workspace-native-"+definition["session"]+"-*.actual-observation.json")
                retired=any((lambda r:r.get("action") == "retire-owner" and r.get("operation") == stages.operation and r.get("session") == definition["session"] and r.get("data",{}).get("all_original_fds_released") is True)(m.decode(m.read(reply))) for reply in replies)
                if retired:
                    continue
                node=m.decode(self.op.k("get","node",definition["node"]["name"],"-o","json"))
                session=NativeSession(self,node,copy.deepcopy(definition),attach_only=True)
                self.sessions.append(session)
                status=session.rpc("session-status")
                statuses.append({"definition":m.pin(path),"actual_status":status})
                if abort_probe:
                    self.once(session,"abort-before-mutation")
                    session.rpc("retire-owner")
        result={"version":"original-workspace-query.v1","operation":stages.operation,"state":"actual_original_owner_states_read_unconfirmed_deployment","owners":statuses,"backup_ready":False,"DR":False}
        if plan_path.exists() and not abort_probe:
            plan=m.decode(m.read(plan_path))
            original=plan["original"]
            if completed_reverse:
                saved=m.decode(m.read(stages.directory/"workspace-reversal.result.json"))
                m.need(saved["operation"] == stages.operation and saved["forward_plan"] == m.pin(plan_path),"same_original_completed_reversal_required")
                m.need(self.object("deployment","workspace-store")["spec"] == saved["server_spec"],"restored_nfs_server_template_changed")
                result["app_readback"]=self.app_readback(plan,direct=False)
                _,result["business_readback"]=self.runtime_materials("workspace-runtime-reverse-query-"+secrets.token_hex(8),baseline=original["runtime_before"])
                result["state"]="actual_restored_original_business_states_read"
            elif (stages.directory/"workspace-localization.result.json").exists() and not (stages.directory/"workspace-reversal.plan.json").exists():
                server=self.object("deployment","workspace-store")
                m.need(server["metadata"]["uid"] == original["deployments"]["workspace-store"]["metadata"]["uid"] and server["spec"] == dict(original["deployments"]["workspace-store"]["spec"],replicas=0),"original_server_cold_deployment_changed")
                self.business.verify_current(self.op)
                material=m.decode(m.pinned(plan["agent_tls_materials"]))
                result["app_readback"]=self.app_readback(plan)
                _,result["business_readback"]=self.runtime_materials("workspace-runtime-direct-query-"+secrets.token_hex(8),baseline=original["runtime_before"],ca=material["CA"],require_shared=True)
                result["state"]="actual_localized_original_business_states_read"
        if abort_probe:
            result["state"]="actual_unmutated_probe_handles_released"
        return result

    def close(self):
        for session in self.sessions:
            session.close()


def dispatch(operator):
    owner = WorkspaceLocalization(operator)
    try:
        if operator.a.action == "workspace-localization-probe":
            return owner.forward(probe_only=True)
        if operator.a.action == "workspace-localize":
            return owner.forward()
        if operator.a.action == "workspace-restore-nfs":
            return owner.reverse()
        if operator.a.action == "workspace-query":
            return owner.query()
        if operator.a.action == "workspace-abort-probe":
            return owner.query(abort_probe=True)
        raise owner.m.Refused("workspace_reverse_coordinator_not_frozen")
    finally:
        owner.close()


def verify_localized(operator):
    """Main-operator guard before host/materials/adoption, never a hold proof."""
    owner=WorkspaceLocalization(operator)
    try:
        result=owner.query()
        owner.m.need(result["state"] == "actual_localized_original_business_states_read","original_workspace_localization_and_business_readback_required")
        return result
    finally:
        owner.close()


def verify_app_overlay(operator):
    """Explicit lineage for a repeated new-image query; original stays sealed."""
    observation=verify_localized(operator)
    owner=WorkspaceLocalization(operator)
    original=owner.m.decode(owner.m.read(owner.stages.directory/"new-image.result.json"))
    result=copy.deepcopy(original)
    result["workspace_overlay"]={"plan":owner.m.pin(owner.stages.directory/"workspace-localization.plan.json"),"result":owner.m.pin(owner.stages.directory/"workspace-localization.result.json"),"actual_readback":observation["app_readback"],"backup_ready":False}
    return result
