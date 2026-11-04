#!/usr/bin/env python3
"""Original Kubernetes-authorized MinIO TLS only. Run with python3 -B.

No MinIO admin/account operation, app image, task grant or enabled config is
required. Interrupted sends are queried, never replayed. Recovery retains the
original private plan and TLS objects; it restores only the selected spec.
"""
import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time

sys.dont_write_bytecode = True
UTILITY_SHA = "3c83146283440b73ec518c505d7e6bfbccb94c5651ba9c0e3e3d764767d14421"
IMAGE = "10.130.14.23:5000/minio@sha256:52dfd5c0bbd38d3219f2058c7af216d9f9a27a994b7b5baad09bbd38866015ff"
MARKER = "system-backup.clawmanager.io/minio-first-hop"
MOUNT = "/run/system-backup-first-hop-tls"


class Refused(Exception):
    pass


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def durable(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_private(path, pin=None, private=True):
    st = path.lstat()
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or st.st_size > 8 << 20 or os.name != "nt" and st.st_mode & (0o077 if private else 0o022):
        raise Refused("private input type/mode/size")
    value = path.read_bytes()
    if pin is not None and sha(value) != pin:
        raise Refused("private input pin changed")
    return value


def native_env():
    env = dict(os.environ)
    for name in list(env):
        if name.lower() in ("http_proxy", "https_proxy", "all_proxy", "kubeconfig", "openssl_conf", "openssl_engines", "openssl_modules"):
            del env[name]
    env["NO_PROXY"] = "*"
    return env


def command(argv, data=None, timeout=45):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_env(), timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 16 << 20:
        raise Refused("native command unconfirmed; inspect original operation")
    return result.stdout


def utility(path):
    if sha(path.read_bytes()) != UTILITY_SHA:
        raise Refused("reviewed TLS utility pin differs")
    spec = importlib.util.spec_from_file_location("reviewed_original_tls_utility", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.Refused = Refused
    module.run = command  # same reviewed openssl/file helper, fixed direct native transport
    return module


class Source:
    def __init__(self, args):
        self.args = args
        self.plan = json.loads(read_private(args.installation_plan_file, args.installation_plan_sha256))
        if self.plan.get("SchemaVersion") != "system-backup-installation-owner-enrollment-plan.v1":
            raise Refused("original installation plan required")
        self.ns = self.plan["Target"]["Namespace"]
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", self.ns) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", args.service):
            raise Refused("namespace/service selector invalid")
        self.prefix = ["kubectl", "--kubeconfig", str(args.kubeconfig_file), "--namespace", self.ns, "--request-timeout=20s"]
        cfg = json.loads(self.kube("config", "view", "--raw", "--minify", "--flatten", "-o", "json"))
        if len(cfg.get("clusters", [])) != 1 or len(cfg.get("users", [])) != 1:
            raise Refused("one original static Kubernetes credential required")
        cluster, user = cfg["clusters"][0]["cluster"], cfg["users"][0]["user"]
        ca = base64.b64decode(cluster.get("certificate-authority-data", ""), validate=True)
        if cluster.get("server") != self.plan["KubernetesAPI"] or not cluster.get("server", "").startswith("https://") or cluster.get("insecure-skip-tls-verify") or cluster.get("proxy-url") or not ca or sha(ca) != self.plan["KubernetesCASHA256"]:
            raise Refused("original verified Kubernetes TLS binding differs")
        allowed = {"token", "client-certificate-data", "client-key-data"}
        if set(user) - allowed or bool(user.get("client-certificate-data")) != bool(user.get("client-key-data")) or bool(user.get("token")) == bool(user.get("client-certificate-data") and user.get("client-key-data")):
            raise Refused("static original credential only; no plugin/proxy/impersonation")
        self.authority()

    def kube(self, *argv, data=None, timeout=45):
        read_private(self.args.kubeconfig_file, self.args.kubeconfig_sha256)
        return command(self.prefix + list(argv), data, timeout)

    def get(self, kind, name):
        return json.loads(self.kube("get", kind, name, "-o", "json"))

    def authority(self):
        # Same original subject/group/namespace/cluster rules as the reviewed
        # native installation channel; Kubernetes performs actual RBAC checks.
        review = {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
        who = json.loads(self.kube("create", "-f", "-", "-o", "json", data=raw(review)))["status"]["userInfo"]
        if who.get("username") != self.plan["OwnerUsername"] or who.get("uid", "") != self.plan["OwnerUID"] or sorted(who.get("groups", [])) != self.plan["OwnerGroups"]:
            raise Refused("actual original installer identity differs")
        for name, expected in (("kube-system", self.plan["Target"]["ClusterID"]), (self.ns, self.plan["Target"]["NamespaceUID"])):
            obj = self.get("namespace", name)
            if obj["metadata"]["uid"] != expected or obj["metadata"].get("deletionTimestamp"):
                raise Refused("original cluster/namespace changed")
        for group, resource, verb in (("", "secrets", "create"), ("", "configmaps", "create"), ("apps", "deployments", "patch"), ("", "pods/portforward", "create")):
            resource, _, sub = resource.partition("/")
            attrs = {"namespace": self.ns, "verb": verb, "group": group, "resource": resource}
            if sub:
                attrs["subresource"] = sub
            review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": {"resourceAttributes": attrs}}
            status = json.loads(self.kube("create", "-f", "-", "-o", "json", data=raw(review)))["status"]
            if status.get("allowed") is not True or status.get("denied") or status.get("evaluationError"):
                raise Refused("original installer access refused")

    def graph(self):
        service = self.get("service", self.args.service)
        if service["metadata"].get("deletionTimestamp") or not service["spec"].get("selector") or service["spec"].get("type", "ClusterIP") != "ClusterIP" or not any(p["port"] == 9000 and p.get("protocol", "TCP") == "TCP" for p in service["spec"]["ports"]):
            raise Refused("original single MinIO API Service required")
        slices = json.loads(self.kube("get", "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name=" + self.args.service, "-o", "json"))["items"]
        refs, addresses = {}, []
        for page in slices:
            if not any(o.get("uid") == service["metadata"]["uid"] and o.get("kind") == "Service" for o in page["metadata"].get("ownerReferences", [])) or not any(p.get("port") == 9000 and p.get("protocol", "TCP") == "TCP" for p in page.get("ports", [])):
                raise Refused("actual Service endpoint binding differs")
            for endpoint in page.get("endpoints", []):
                ref = endpoint.get("targetRef", {})
                if ref.get("kind") != "Pod" or ref.get("namespace") != self.ns or endpoint.get("conditions", {}).get("ready") is not True:
                    raise Refused("actual ready Pod endpoint required")
                refs[ref["uid"]] = ref["name"]
                addresses.extend(endpoint.get("addresses", []))
        if len(refs) != 1:
            raise Refused("one actual MinIO endpoint required")
        uid, name = next(iter(refs.items()))
        pod = self.get("pod", name)
        if pod["metadata"]["uid"] != uid or pod["metadata"].get("deletionTimestamp"):
            raise Refused("actual Pod identity changed")
        pod_ips = {p["ip"] for p in pod.get("status", {}).get("podIPs", [])}
        if pod.get("status", {}).get("podIP"):
            pod_ips.add(pod["status"]["podIP"])
        if not addresses or not set(addresses).issubset(pod_ips):
            raise Refused("actual Service addresses do not select original Pod IP")
        owner = controller(pod, "ReplicaSet")
        rs = self.get("replicaset", owner["name"])
        if rs["metadata"]["uid"] != owner["uid"]:
            raise Refused("actual ReplicaSet identity changed")
        owner = controller(rs, "Deployment")
        dep = self.get("deployment", owner["name"])
        if dep["metadata"]["uid"] != owner["uid"] or dep["metadata"].get("deletionTimestamp") or dep["spec"].get("replicas", 1) != 1:
            raise Refused("actual single MinIO Deployment required")
        containers = pod["spec"]["containers"]
        if len(containers) != 1 or len(dep["spec"]["template"]["spec"]["containers"]) != 1:
            raise Refused("unclassified MinIO sidecar")
        c = containers[0]
        states = [x for x in pod.get("status", {}).get("containerStatuses", []) if x["name"] == c["name"]]
        if len(states) != 1 or states[0].get("imageID") != IMAGE or not states[0].get("containerID") or not states[0].get("ready") or "running" not in states[0].get("state", {}):
            raise Refused("original immutable MinIO process differs")
        return {"service": service, "pod": pod, "replicaset": rs, "deployment": dep, "status": states[0]}


def controller(obj, kind):
    owners = [o for o in obj["metadata"].get("ownerReferences", []) if o.get("controller")]
    if len(owners) != 1 or owners[0].get("kind") != kind:
        raise Refused("actual workload owner binding required")
    return owners[0]


def forwarded_health(source, graph, ca=None, leaf=None):
    pod = graph["pod"]
    with socket.socket() as pick:
        pick.bind(("127.0.0.1", 0))
        port = pick.getsockname()[1]
    argv = source.prefix + ["port-forward", "--address=127.0.0.1", "pod/" + pod["metadata"]["name"], str(port) + ":9000"]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=native_env())
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise Refused("original Kubernetes forwarding refused")
            try:
                channel = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                time.sleep(.05)
        else:
            raise Refused("original Kubernetes forwarding unavailable")
        try:
            host = source.args.service + "." + source.ns + ".svc"
            if ca is not None:
                trust = ssl.create_default_context(cafile=str(ca))
                trust.minimum_version = ssl.TLSVersion.TLSv1_3
                channel = trust.wrap_socket(channel, server_hostname=host)
                if leaf is not None and channel.getpeercert(binary_form=True) != ssl.PEM_cert_to_DER_cert(leaf.decode()):
                    raise Refused("actual installed TLS leaf differs")
            channel.sendall(("GET /minio/health/live HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode())
            response = http.client.HTTPResponse(channel)
            response.begin()
            if response.status != 200:
                raise Refused("transport not confirmed; existing TLS/unknown is not plaintext authorization")
        finally:
            channel.close()
        current = source.get("pod", pod["metadata"]["name"])
        if current["metadata"]["uid"] != pod["metadata"]["uid"] or current["status"]["containerStatuses"] != pod["status"]["containerStatuses"]:
            raise Refused("original native endpoint changed during transport read")
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def prepare(source, directory, util):
    source.authority()
    graph = source.graph()
    dep = graph["deployment"]
    c = dep["spec"]["template"]["spec"]["containers"][0]
    if c.get("command", []) not in ([], ["minio"], ["/usr/bin/minio"], ["/usr/local/bin/minio"]) or not c.get("args") or c["args"][0] != "server" or any("certs-dir" in a for a in c["args"]) or any(e["name"] == "MINIO_CERTS_DIR" for e in c.get("env", [])):
        raise Refused("existing TLS/unknown actual launch; preserve and use its original CA")
    forwarded_health(source, graph)  # anonymous actual plaintext health, no admin secret
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    operation = secrets.token_hex(16)
    name = "sbk-minio-first-tls-" + operation[:16]
    host = source.args.service + "." + source.ns + ".svc"
    addresses = graph["service"]["spec"].get("clusterIPs", [graph["service"]["spec"]["clusterIP"]])
    ips = [str(ipaddress.ip_address(address)) for address in addresses]
    config = "[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN=" + host + "\n[ext]\nsubjectAltName=DNS:" + source.args.service + ",DNS:" + host + ",DNS:" + host + ".cluster.local" + "".join(",IP:" + ip for ip in ips) + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
    durable(directory / "server.cnf", config.encode())
    for output in ("ca.key", "private.key"):
        util.openssl(directory, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(directory / output))
    util.openssl(directory, "req", "-x509", "-new", "-key", str(directory / "ca.key"), "-sha256", "-days", "30", "-subj", "/CN=Original MinIO first hop " + operation, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(directory / "ca.pem"))
    util.openssl(directory, "req", "-new", "-key", str(directory / "private.key"), "-config", str(directory / "server.cnf"), "-out", str(directory / "server.csr"))
    util.openssl(directory, "x509", "-req", "-in", str(directory / "server.csr"), "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca.key"), "-set_serial", str(secrets.randbits(120) + 1), "-days", "14", "-sha256", "-extfile", str(directory / "server.cnf"), "-extensions", "ext", "-out", str(directory / "public.crt"))
    util.openssl(directory, "verify", "-CAfile", str(directory / "ca.pem"), "-verify_hostname", host, str(directory / "public.crt"))
    spki = command(["openssl", "pkey", "-pubin", "-outform", "DER"], util.openssl(directory, "x509", "-in", str(directory / "public.crt"), "-pubkey", "-noout"))
    (directory / "ca.key").unlink()
    (directory / "server.csr").unlink()
    for path in directory.iterdir():
        path.chmod(0o600)
        with path.open("rb") as file:
            os.fsync(file.fileno())
    ca, cert, key = (read_private(directory / p) for p in ("ca.pem", "public.crt", "private.key"))
    metadata = {"name": name, "namespace": source.ns, "annotations": {MARKER: operation}}
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": metadata, "immutable": True, "type": "Opaque", "data": {"public.crt": base64.b64encode(cert).decode(), "private.key": base64.b64encode(key).decode()}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "immutable": True, "data": {"ca.pem": ca.decode()}}
    desired = copy.deepcopy(dep["spec"])
    desired["strategy"] = {"type": "Recreate"}
    template = desired["template"]
    template.setdefault("metadata", {}).setdefault("annotations", {})[MARKER] = operation
    util.add_volume(desired, name, {"secret": {"secretName": name, "defaultMode": 292}}, MOUNT)
    template["spec"]["containers"][0]["args"].extend(["--certs-dir", MOUNT])
    container = template["spec"]["containers"][0]
    port_names = {p.get("name") for p in container.get("ports", []) if p.get("containerPort") == 9000}
    for name in ("readinessProbe", "livenessProbe", "startupProbe"):
        probe = container.get(name, {})
        if probe.get("exec"):
            raise Refused("actual exec probe needs its original TLS-aware decoder")
        if "httpGet" in probe:
            get = probe["httpGet"]
            if get.get("port") != 9000 and get.get("port") not in port_names or get.get("path") not in ("/minio/health/live", "/minio/health/ready", "/minio/health/cluster", "/minio/health/cluster/read") or get.get("host"):
                raise Refused("actual HTTP probe is not the selected native health endpoint")
            get["scheme"] = "HTTPS"
    # The server's real dry-run defaults are persisted before ANY real send.
    desired = source_patch(source, dep, desired, dry=True)["spec"]
    plan = {"version": "original-minio-first-hop-tls.v1", "operation": operation, "installation_plan_sha256": source.args.installation_plan_sha256, "kubeconfig_sha256": source.args.kubeconfig_sha256, "namespace": source.ns, "service": source.args.service, "service_uid": graph["service"]["metadata"]["uid"], "service_spec": graph["service"]["spec"], "deployment": dep, "desired_spec": desired, "secret": secret, "ca_object": cm, "ca_sha256": sha(ca), "spki_sha256": sha(spki), "leaf_sha256": sha(ssl.PEM_cert_to_DER_cert(cert.decode())), "prepared_at": datetime.now(timezone.utc).isoformat()}
    source.authority()
    last = source.graph()
    if last["deployment"]["metadata"]["uid"] != dep["metadata"]["uid"] or last["deployment"]["spec"] != dep["spec"] or last["service"]["metadata"]["uid"] != graph["service"]["metadata"]["uid"] or last["service"]["spec"] != graph["service"]["spec"]:
        raise Refused("original source changed during preparation")
    durable(directory / "plan.json", raw(plan))
    return {"state": "prepared_local_only", "operation": operation, "plan_sha256": sha(raw(plan)), "ca_file": str(directory / "ca.pem"), "ca_sha256": sha(ca), "cluster_mutated": False}


def source_patch(source, before, spec, dry=False, cancel=None):
    patch = [{"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": before["metadata"]["resourceVersion"]}, {"op": "replace", "path": "/spec", "value": spec}]
    if cancel is not None:
        annotations = dict(before["metadata"].get("annotations", {}))
        annotations[MARKER] = "rollback-" + cancel
        patch.append({"op": "add", "path": "/metadata/annotations", "value": annotations})
    extra = ["--dry-run=server"] if dry else []
    return json.loads(source.kube("patch", "deployment", before["metadata"]["name"], "--type=json", "--patch-file=/dev/stdin", "-o", "json", *extra, data=raw(patch)))


def step(directory, name, intended, send, query):
    sent, confirmed = directory / (name + ".sent.json"), directory / (name + ".confirmed.json")
    if confirmed.exists():
        value = query()
        if value is None or json.loads(read_private(confirmed)) != value:
            raise Refused("confirmed original operation drifted")
        return value
    if sent.exists():
        if json.loads(read_private(sent)) != intended:
            raise Refused("original pending intent differs")
        value = query()
        if value is None:
            raise Refused("original send unknown; query only, no replay")
    else:
        durable(sent, raw(intended))
        # If this throws, the durable pending intent survives, and the next
        # call can only query. An absent query is not permission to resend.
        send()
        value = query()
        if value is None:
            raise Refused("original send unconfirmed; retain operation")
    durable(confirmed, raw(value))
    return value


def load(source, directory, pin):
    plan = json.loads(read_private(directory / "plan.json", pin))
    if plan["version"] != "original-minio-first-hop-tls.v1" or plan["installation_plan_sha256"] != source.args.installation_plan_sha256 or source.args.action != "rollback" and plan["kubeconfig_sha256"] != source.args.kubeconfig_sha256 or plan["namespace"] != source.ns or plan["service"] != source.args.service:
        raise Refused("original prepared installation scope differs")
    if source.args.action != "rollback":
        certificate = read_private(directory / "public.crt")
        if sha(read_private(directory / "ca.pem")) != plan["ca_sha256"] or sha(ssl.PEM_cert_to_DER_cert(certificate.decode())) != plan["leaf_sha256"]:
            raise Refused("original prepared TLS files changed")
        command(["openssl", "verify", "-CAfile", str(directory / "ca.pem"), "-verify_hostname", source.args.service + "." + source.ns + ".svc", str(directory / "public.crt")])
        command(["openssl", "x509", "-in", str(directory / "public.crt"), "-checkend", "300", "-noout"])
    source.authority()  # fresh original RBAC on every install/query/recovery
    service = source.get("service", source.args.service)
    if service["metadata"]["uid"] != plan["service_uid"] or service["spec"] != plan["service_spec"]:
        raise Refused("original Service replaced")
    return plan


def current_deployment(source, plan):
    before = plan["deployment"]
    current = source.get("deployment", before["metadata"]["name"])
    if current["metadata"]["uid"] != before["metadata"]["uid"] or current["metadata"].get("deletionTimestamp"):
        raise Refused("original Deployment replaced")
    return current


def binding_receipt(source, graph):
    pod = graph["pod"]
    account = source.get("serviceaccount", pod["spec"].get("serviceAccountName") or "default")
    node = source.get("node", pod["spec"]["nodeName"])
    objects = dict(graph)
    objects["service_account"], objects["node"] = account, node
    return {name: {"name": value["metadata"]["name"], "uid": value["metadata"]["uid"]} for name, value in objects.items() if name != "status"}


def apply(source, directory, plan, query_only=False):
    if (directory / "rollback.sent.json").exists():
        raise Refused("original operation entered recovery; install cannot resume")
    for key, kind in (("secret", "secret"), ("ca_object", "configmap")):
        intended = plan[key]
        def query(obj=intended, resource=kind):
            # Listing a unique intended name yields real absence without
            # treating command/network errors as NotFound.
            values = json.loads(source.kube("get", resource, "--field-selector=metadata.name=" + obj["metadata"]["name"], "-o", "json"))["items"]
            if not values:
                return None
            if len(values) != 1:
                raise Refused("original TLS object ambiguous")
            actual = values[0]
            for field in ("data", "immutable"):
                if actual.get(field) != obj.get(field):
                    raise Refused("original TLS object differs")
            if actual["metadata"].get("annotations", {}).get(MARKER) != plan["operation"]:
                raise Refused("original TLS object ownership differs")
            return {"uid": actual["metadata"]["uid"], "sha256": sha(raw(obj))}
        if query_only and not (directory / (key + ".sent.json")).exists():
            raise Refused("operation not sent; query does not install")
        step(directory, key, {"sha256": sha(raw(intended))}, lambda obj=intended: source.kube("create", "-f", "-", "-o", "json", data=raw(obj)), query)
    def query_deployment():
        actual = current_deployment(source, plan)
        return {"uid": actual["metadata"]["uid"], "spec_sha256": sha(raw(actual["spec"]))} if actual["spec"] == plan["desired_spec"] else None
    current = current_deployment(source, plan)
    if not (directory / "deployment.sent.json").exists() and (query_only or current["spec"] != plan["deployment"]["spec"]):
        raise Refused("original pre-send spec changed or query-only")
    step(directory, "deployment", {"uid": plan["deployment"]["metadata"]["uid"], "spec_sha256": sha(raw(plan["desired_spec"]))}, lambda: source_patch(source, current, plan["desired_spec"]), query_deployment)
    source.kube("rollout", "status", "deployment/" + current["metadata"]["name"], "--timeout=90s", timeout=100)
    graph = source.graph()
    if graph["deployment"]["metadata"]["uid"] != current["metadata"]["uid"] or graph["deployment"]["spec"] != plan["desired_spec"]:
        raise Refused("actual installed native binding differs")
    forwarded_health(source, graph, directory / "ca.pem", read_private(directory / "public.crt"))
    source.authority()
    return {"state": "actual_tls_verified", "operation": plan["operation"], "endpoint": "https://" + source.args.service + "." + source.ns + ".svc:9000", "server_name": source.args.service + "." + source.ns + ".svc", "ca_file": str(directory / "ca.pem"), "ca_sha256": plan["ca_sha256"], "spki_sha256": plan["spki_sha256"], "leaf_sha256": plan["leaf_sha256"], "objects": binding_receipt(source, graph), "container": graph["status"]["name"], "container_id": graph["status"]["containerID"], "image_id": graph["status"]["imageID"], "permission_gate_or_adoption": False}


def rollback(source, directory, plan):
    current = current_deployment(source, plan)
    before, desired = plan["deployment"]["spec"], plan["desired_spec"]
    if current["spec"] not in (before, desired):
        raise Refused("foreign spec change; preserve original recovery custody")
    def query():
        actual = current_deployment(source, plan)
        if actual["spec"] == before and actual["metadata"].get("annotations", {}).get(MARKER) == "rollback-" + plan["operation"]:
            return {"uid": actual["metadata"]["uid"], "restored_spec_sha256": sha(raw(before)), "late_original_cas_fenced": True}
        return None
    # Even a pending send whose query still sees the old spec is fenced with
    # a real metadata RV change. Its late old-RV patch can no longer commit.
    step(directory, "rollback", {"operation": plan["operation"], "restore_sha256": sha(raw(before))}, lambda: source_patch(source, current, before, cancel=plan["operation"]), query)
    source.kube("rollout", "status", "deployment/" + current["metadata"]["name"], "--timeout=90s", timeout=100)
    source.authority()
    return {"state": "original_spec_restored_late_install_fenced", "tls_objects_retained": True, "account_or_data_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "prepare", "apply", "query", "rollback", "probe-existing"))
    for name in ("kubeconfig-file", "installation-plan-file", "state-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("kubeconfig-sha256", "installation-plan-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--service", default="minio")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--existing-ca-file", type=Path)
    parser.add_argument("--existing-ca-sha256")
    parser.add_argument("--reviewed-utility", type=Path, default=Path(__file__).with_name("system-backup-first-page-tls-only.py"))
    args = parser.parse_args()
    directory = args.state_directory
    if os.name != "posix" or not directory.is_absolute() or directory.resolve() != directory or directory.exists() and (directory.is_symlink() or directory.stat().st_mode & 0o077):
        raise Refused("original Linux operator private absolute state directory required")
    source = Source(args)
    if args.action == "inspect":
        graph = source.graph()
        c = graph["pod"]["spec"]["containers"][0]
        result = {"state": "actual_kubernetes_binding_only", "objects": binding_receipt(source, graph), "image_id": graph["status"]["imageID"], "explicit_certs_dir_arg": any("certs-dir" in a for a in c.get("args", [])), "native_tls_or_plaintext_verified": False, "cluster_mutated": False}
    elif args.action == "prepare":
        result = prepare(source, directory, utility(args.reviewed_utility))
    elif args.action == "probe-existing":
        if not args.existing_ca_file or not args.existing_ca_sha256:
            raise Refused("actual existing CA file/pin required; no inferred HTTP state")
        read_private(args.existing_ca_file, args.existing_ca_sha256, private=False)
        forwarded_health(source, source.graph(), args.existing_ca_file)
        result = {"state": "existing_tls_verified_no_mutation", "ca_sha256": args.existing_ca_sha256}
    else:
        if not re.fullmatch(r"[a-f0-9]{64}", args.plan_sha256 or ""):
            raise Refused("exact original private plan pin required")
        plan = load(source, directory, args.plan_sha256)
        result = rollback(source, directory, plan) if args.action == "rollback" else apply(source, directory, plan, args.action == "query")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, http.client.HTTPException) as error:
        print(json.dumps({"state": "unconfirmed_preserve_original_plan", "reason": str(error) if isinstance(error, Refused) else type(error).__name__, "retry_send": False}), file=sys.stderr)
        sys.exit(1)
