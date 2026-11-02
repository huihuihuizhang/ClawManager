#!/usr/bin/env python3
"""Owned Kubernetes TLS1.3 MySQL fixture for A's precompiled Linux runner.

No host Go/Node/Docker/mysql/openssl. Startup-only needs no native bundle.
Kubernetes operations are confined to one new namespace.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

DIGEST = "5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977"
MYSQL_IMAGE = "10.130.14.23:5000/mysql@sha256:" + DIGEST
LABEL = "clawmanager.io/diagnostic-owner"
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
TLS_INIT = r"""set -eu
command -v openssl >/dev/null
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Owned diagnostic CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout /private/ca.key -out /tls/ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' -keyout /tls/server.key -out /private/server.csr >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' >/private/server.ext
openssl x509 -req -days 1 -in /private/server.csr -CA /tls/ca.crt -CAkey /private/ca.key -CAcreateserial -extfile /private/server.ext -out /tls/server.crt >/dev/null 2>&1
chmod 755 /tls
chmod 444 /tls/ca.crt /tls/server.crt /tls/server.key
"""


class Refused(Exception):
    pass


class Interrupted(Exception):
    def __init__(self, code):
        self.code = code


def require(value):
    if not value:
        raise Refused()


class Fixture:
    def __init__(self, args):
        self.args = args
        self.owner = secrets.token_hex(16)
        self.namespace = "sbk-apermit-" + self.owner[:20]
        self.uid = None
        self.pod_uid = None
        self.server_version = None
        self.server_uuid = None
        self.session_tls = {}
        self.image_ids = {}
        self.password = None
        self.last_command_error = None
        self.diagnostics_exit_code = 0
        self.attempted = False
        self.work = None
        self.logs = args.logs
        self.logs_created = False
        self.forward = None
        self.runner = None
        self.forward_stream = None
        self.stage = "preflight"
        self.residuals = []
        self.kube = ["kubectl", "--context=" + args.context, "--request-timeout=25s"]
        self.stream_kube = ["kubectl", "--context=" + args.context, "--request-timeout=0"]

    def checkpoint(self):
        # Non-secret receipt exists before the first create, including ACK loss.
        (self.logs / "ownership.json").write_text(json.dumps({"namespace": self.namespace, "namespace_uid": self.uid,
            "pod_uid": self.pod_uid, "owner": self.owner, "stage": self.stage,
            "server_version": self.server_version, "observed_image_ids": self.image_ids,
            "server_uuid": self.server_uuid, "session_tls": self.session_tls,
            "port_forward_pid": self.forward.pid if self.forward else None,
            "runner_pid": self.runner.pid if self.runner else None}, indent=2) + "\n")

    def command(self, args, data=None, timeout=45, stream=False):
        try:
            result = subprocess.run((self.stream_kube if stream else self.kube) + args, input=None if data is None else json.dumps(data).encode(),
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.last_command_error = {"stage": self.stage, "exit_code": None, "message": "kubectl subprocess timeout"}
            raise Refused() from None
        if result.returncode != 0:
            # API error bodies can contain a full rejected Pod/Secret. Never save them.
            self.last_command_error = {"stage": self.stage, "exit_code": result.returncode,
                                       "message": "kubectl failed; raw error body withheld"}
            raise Refused()
        return result.stdout

    def scrub(self, value, limit=512):
        text = str(value)
        if self.password:
            for secret in (self.password, base64.b64encode(self.password.encode()).decode()):
                text = text.replace(secret, "[redacted]")
        text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[private key withheld]", text, flags=re.S)
        text = re.sub(r"(?i)(password|mysql_pwd|token|access_key|secret_key)([\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)", r"\1\2[redacted]", text)
        text = re.sub(r"(?i)\b(?:mysql|postgres|postgresql)://\S+", "[credential URI withheld]", text)
        text = re.sub(r"(?im)^.*\b(?:SELECT\s|INSERT\s|UPDATE\s|DELETE\s+FROM|REPLACE\s+INTO|CREATE\s|GRANT\s|ALTER\s|DROP\s|TRUNCATE\s|SET\s+PASSWORD).*$", "[SQL text withheld]", text)
        if '"spec"' in text or '"data"' in text or '"env"' in text:
            text = "[structured error body withheld]"
        text = "".join(c if c in "\n\t" or ord(c) >= 32 else "?" for c in text)
        return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")

    def collect_startup_diagnostics(self):
        """Best effort, <=35s and <=64KiB. Does not affect the original result."""
        if not self.logs_created or not self.attempted:
            return
        deadline = time.monotonic() + 35
        summary = {"scope": "owned fixture startup summary", "namespace": self.namespace, "namespace_uid": self.uid, "owner": self.owner,
                   "pod_uid": self.pod_uid, "last_command_error": self.last_command_error,
                   "pod": None, "events": [], "notes": [], "log_tails": {}}
        def read(args):
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            return self.command(args, timeout=min(10, remaining))
        def owned_pod(pod):
            meta = pod["metadata"]
            require(meta["name"] == "mysql" and meta.get("namespace") == self.namespace and meta.get("labels", {}).get(LABEL) == self.owner)
            require(UUID.fullmatch(meta["uid"]) and (self.pod_uid is None or meta["uid"] == self.pod_uid))
            self.pod_uid = meta["uid"]
        def state(value):
            result = {}
            for kind in ("waiting", "running", "terminated"):
                if kind not in value:
                    continue
                item = value[kind]
                result["state"] = kind
                for key in ("reason", "message", "startedAt", "finishedAt"):
                    if key in item: result[key] = self.scrub(item[key], 512 if key == "message" else 128)
                for key in ("exitCode", "signal"):
                    if type(item.get(key)) is int: result[key] = item[key]
            return result
        try:
            raw = read(["get", "namespace", self.namespace, "--ignore-not-found", "-o", "json"])
            require(raw.strip())
            meta = json.loads(raw)["metadata"]
            require(meta["name"] == self.namespace and meta.get("labels", {}).get(LABEL) == self.owner)
            require(UUID.fullmatch(meta["uid"]) and (self.uid is None or meta["uid"] == self.uid))
            self.uid = meta["uid"]
            summary["namespace_uid"] = self.uid
        except Exception:
            self.diagnostics_exit_code = 1
            summary["notes"].append("namespace_identity_unavailable_or_changed")
            (self.logs / "startup-diagnostics.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
            return
        pod_owned = False
        try:
            pod = json.loads(read(["-n", self.namespace, "get", "pod", "mysql", "-o", "json"]))
            owned_pod(pod)
            pod_owned = True
            summary["pod_uid"] = self.pod_uid
            status = pod.get("status", {})
            view = {"phase": self.scrub(status.get("phase", "unknown"), 32),
                    "reason": self.scrub(status.get("reason", ""), 128), "message": self.scrub(status.get("message", "")),
                    "conditions": [], "containers": [], "init_containers": []}
            for condition in status.get("conditions", [])[:8]:
                view["conditions"].append({key: self.scrub(condition.get(key, ""), 512 if key == "message" else 128)
                                           for key in ("type", "status", "reason", "message", "lastTransitionTime")})
            for field, target, expected in (("containerStatuses", "containers", "mysql"), ("initContainerStatuses", "init_containers", "tls")):
                for item in status.get(field, [])[:8]:
                    if item.get("name") != expected:
                        continue
                    image_id = item.get("imageID", "")
                    # Preserve only runtime digest identifiers, not arbitrary status text.
                    if image_id and not re.fullmatch(r"(?:docker-pullable://|docker://|containerd://|cri-o://)?(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[a-f0-9]{64}", image_id):
                        image_id = "unavailable_or_invalid"
                    view[target].append({"name": expected, "ready": item.get("ready") is True,
                                         "restart_count": item.get("restartCount") if type(item.get("restartCount")) is int else None,
                                         "image_id": image_id, "current": state(item.get("state", {})), "previous": state(item.get("lastState", {}))})
            summary["pod"] = view
        except Exception:
            self.diagnostics_exit_code = 1
            summary["notes"].append("owned_pod_status_unavailable_or_changed")
        if self.pod_uid:
            try:
                query = urlencode({"fieldSelector": "involvedObject.uid=" + self.pod_uid, "limit": "24"})
                events = json.loads(read(["get", "--raw=/api/v1/namespaces/" + self.namespace + "/events?" + query]))
                for event in events.get("items", [])[:24]:
                    involved = event.get("involvedObject", {})
                    if involved.get("uid") != self.pod_uid or involved.get("name") != "mysql" or involved.get("kind") != "Pod" or involved.get("namespace") != self.namespace:
                        continue
                    summary["events"].append({"type": self.scrub(event.get("type", ""), 32), "reason": self.scrub(event.get("reason", ""), 128),
                                              "message": self.scrub(event.get("message", "")),
                                              "count": event.get("count") if type(event.get("count")) is int else None,
                                              "last_timestamp": self.scrub(event.get("lastTimestamp", event.get("eventTime", "")), 64)})
                summary["events_more_available"] = bool(events.get("metadata", {}).get("continue"))
            except Exception:
                self.diagnostics_exit_code = 1
                summary["notes"].append("exact_pod_events_unavailable")
        containers = ("mysql", "tls") if self.args.include_container_logs else (("tls",) if self.args.include_init_logs else ())
        if pod_owned:
            for container in containers:
                try:
                    owned_pod(json.loads(read(["-n", self.namespace, "get", "pod", "mysql", "-o", "json"])))
                    logs = read(["-n", self.namespace, "logs", "mysql", "-c", container, "--tail=40", "--limit-bytes=4096", "--timestamps=true"])
                    # Redact this run's password/base64 and private keys BEFORE our byte cap.
                    summary["log_tails"][container] = self.scrub(logs.decode(errors="replace"), 4096)
                except Exception:
                    self.diagnostics_exit_code = 1
                    summary["notes"].append("owned_" + container + "_log_tail_unavailable")
        encoded = json.dumps(summary, ensure_ascii=False, indent=2)
        if len(encoded.encode()) > 65536:
            summary["log_tails"] = {}
            summary["events"] = summary["events"][:8]
            summary["notes"].append("summary_truncated")
            encoded = json.dumps(summary, ensure_ascii=False, indent=2)
        require(len(encoded.encode()) <= 65536)
        (self.logs / "startup-diagnostics.json").write_text(encoded + "\n")

    def get_namespace(self):
        raw = self.command(["get", "namespace", self.namespace, "--ignore-not-found", "-o", "json"])
        return json.loads(raw) if raw.strip() else None

    def namespace_identity(self, recover=False):
        item = self.get_namespace()
        if item is None:
            return False
        metadata = item["metadata"]
        require(metadata["name"] == self.namespace and metadata.get("labels", {}).get(LABEL) == self.owner)
        require(UUID.fullmatch(metadata["uid"]))
        if self.uid is None:
            require(recover and self.attempted)
            self.uid = metadata["uid"]
        require(metadata["uid"] == self.uid)
        return True

    def pod_identity(self):
        require(self.namespace_identity())
        pod = json.loads(self.command(["-n", self.namespace, "get", "pod", "mysql", "-o", "json"]))
        require(pod["metadata"].get("labels", {}).get(LABEL) == self.owner)
        uid = pod["metadata"]["uid"]
        require(UUID.fullmatch(uid))
        if self.pod_uid is None:
            self.pod_uid = uid
        require(uid == self.pod_uid)
        spec = pod["spec"]
        require(spec.get("automountServiceAccountToken") is False)
        require(not spec.get("hostNetwork") and not spec.get("hostPID") and not spec.get("hostIPC") and not spec.get("imagePullSecrets"))
        require(len(spec["containers"]) == 1 and len(spec.get("initContainers", [])) == 1)
        for container in spec["containers"] + spec["initContainers"]:
            require(container["image"] == self.args.mysql_image)
            require(container.get("securityContext", {}).get("privileged") is False)
            require(container.get("securityContext", {}).get("allowPrivilegeEscalation") is False)
            require(not container.get("envFrom"))
        for volume in spec.get("volumes", []):
            require(not any(key in volume for key in ("hostPath", "persistentVolumeClaim", "projected")))
            require("emptyDir" in volume or volume.get("secret", {}).get("secretName") == "mysql-password")
        for status in pod.get("status", {}).get("containerStatuses", []) + pod.get("status", {}).get("initContainerStatuses", []):
            if status["name"] in ("mysql", "tls") and status.get("imageID"):
                observed = status["imageID"]
                require(re.fullmatch(r"(?:docker-pullable://|docker://|containerd://|cri-o://)?(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[a-f0-9]{64}", observed))
                self.image_ids[status["name"]] = observed
        return pod

    def exec_pod(self, command):
        self.pod_identity()
        return self.command(["-n", self.namespace, "exec", "mysql", "-c", "mysql", "--"] + command)

    def resources(self, password):
        metadata = {"namespace": self.namespace, "labels": {LABEL: self.owner}}
        secret = {"apiVersion": "v1", "kind": "Secret", "metadata": dict(metadata, name="mysql-password"),
                  "type": "Opaque", "data": {"password": base64.b64encode(password.encode()).decode()}}
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": dict(metadata, name="deny-all"),
                  "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}}
        security = {"privileged": False, "allowPrivilegeEscalation": False, "seccompProfile": {"type": "RuntimeDefault"}}
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": dict(metadata, name="mysql"), "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never", "terminationGracePeriodSeconds": 25,
            "hostNetwork": False, "hostPID": False, "hostIPC": False,
            "nodeSelector": {"kubernetes.io/os": "linux"},
            "initContainers": [{"name": "tls", "image": self.args.mysql_image, "imagePullPolicy": "IfNotPresent",
                                "command": ["/bin/sh", "-c", TLS_INIT], "securityContext": security,
                                "volumeMounts": [{"name": "tls", "mountPath": "/tls"}, {"name": "tls-private", "mountPath": "/private"}]}],
            "containers": [{"name": "mysql", "image": self.args.mysql_image, "imagePullPolicy": "IfNotPresent",
                "securityContext": security,
                "args": ["--ssl-ca=/run/fixture-tls/ca.crt", "--ssl-cert=/run/fixture-tls/server.crt",
                         "--ssl-key=/run/fixture-tls/server.key", "--require-secure-transport=ON", "--tls-version=TLSv1.3"],
                "env": [{"name": "MYSQL_ROOT_PASSWORD_FILE", "value": "/run/fixture-password/password"}, {"name": "MYSQL_ROOT_HOST", "value": "%"}],
                "ports": [{"name": "mysql", "containerPort": 3306}],
                "readinessProbe": {"tcpSocket": {"port": "mysql"}, "periodSeconds": 2, "failureThreshold": 90},
                "resources": {"requests": {"cpu": "1", "memory": "1Gi"}, "limits": {"memory": "3Gi"}},
                "volumeMounts": [{"name": "data", "mountPath": "/var/lib/mysql"},
                                 {"name": "tls", "mountPath": "/run/fixture-tls", "readOnly": True},
                                 {"name": "password", "mountPath": "/run/fixture-password", "readOnly": True}]}],
            "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "16Gi"}}, {"name": "tls", "emptyDir": {}},
                        {"name": "tls-private", "emptyDir": {}},
                        {"name": "password", "secret": {"secretName": "mysql-password", "defaultMode": 292}}]}}
        return secret, policy, pod

    def run(self):
        self.logs.mkdir(mode=0o700)
        self.logs_created = True
        self.work = Path(tempfile.mkdtemp(prefix="d-kube-mysql-", dir=self.args.scratch)).resolve()
        password = secrets.token_hex(32)
        self.password = password
        self.stage = "namespace-create"
        self.checkpoint()
        self.attempted = True
        self.command(["create", "-f", "-", "-o", "json"], {"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": self.namespace, "labels": {LABEL: self.owner, "clawmanager.io/diagnostic-kind": "a-permit-data"}}})
        require(self.namespace_identity(recover=True))
        self.checkpoint()
        secret, policy, pod = self.resources(password)
        for stage, resource in (("secret-create", secret), ("policy-create", policy), ("pod-create", pod)):
            self.stage = stage
            require(self.namespace_identity())
            self.command(["-n", self.namespace, "create", "-f", "-"], resource)
        self.pod_identity()
        self.checkpoint()
        self.stage = "pod-ready-openssl-tls"
        self.command(["-n", self.namespace, "wait", "--for=condition=Ready", "pod/mysql", "--timeout=240s"], timeout=260, stream=True)
        self.pod_identity()
        require(set(self.image_ids) == {"mysql", "tls"})
        self.stage = "uuid-and-server-tls"
        sql = 'MYSQL_PWD="$(cat /run/fixture-password/password)"; export MYSQL_PWD; exec mysql --user=root --protocol=TCP --host=127.0.0.1 --ssl-mode=VERIFY_IDENTITY --ssl-ca=/run/fixture-tls/ca.crt --tls-version=TLSv1.3 --batch --skip-column-names -e "SELECT VERSION(),@@server_uuid,@@tls_version,@@require_secure_transport; SHOW SESSION STATUS WHERE Variable_name IN (\'Ssl_version\',\'Ssl_cipher\')"'
        values = self.exec_pod(["/bin/sh", "-ec", sql]).decode().strip().split()
        require(len(values) == 8)
        version = re.fullmatch(r"(\d{1,2})\.(\d{1,2})\.(\d{1,3})(?:[-+._A-Za-z0-9]{0,96})", values[0])
        require(version is not None)
        self.server_version = values[0]
        self.stage = "server-version-capability"
        self.checkpoint()
        major, minor, patch = map(int, version.group(1, 2, 3))
        # Conservative diagnostic branches, not a blanket migration compatibility claim.
        require(major == 8 and ((minor == 0 and patch >= 16) or minor == 4))
        require(UUID.fullmatch(values[1]) and values[2] == "TLSv1.3" and values[3] in ("1", "ON"))
        server_uuid = values[1]
        self.server_uuid = server_uuid
        tls = dict(zip(values[4::2], values[5::2]))
        require(set(tls) == {"Ssl_version", "Ssl_cipher"} and tls["Ssl_version"] == "TLSv1.3")
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tls["Ssl_cipher"]))
        self.session_tls = tls
        self.checkpoint()
        ca = self.exec_pod(["cat", "/run/fixture-tls/ca.crt"])
        require(ca.startswith(b"-----BEGIN CERTIFICATE-----") and len(ca) < 32768)
        ca_file = self.work / "ca.crt"
        ca_file.write_bytes(ca)
        self.stage = "loopback-port-forward"
        self.forward_stream = (self.work / "port-forward.log").open("wb")
        mapping = (str(self.args.port) if self.args.port else "") + ":3306"
        self.forward = subprocess.Popen(self.stream_kube + ["-n", self.namespace, "port-forward", "--address=127.0.0.1", "pod/mysql", mapping],
                                        stdout=self.forward_stream, stderr=subprocess.STDOUT)
        self.checkpoint()
        deadline = time.monotonic() + 30
        port = None
        while time.monotonic() < deadline:
            require(self.forward.poll() is None)
            text = (self.work / "port-forward.log").read_text(errors="replace")
            match = re.search(r"Forwarding from 127\.0\.0\.1:([0-9]+) -> 3306", text)
            if match:
                port = int(match[1])
                require(1023 < port < 65536 and port != 3306 and (not self.args.port or port == self.args.port))
                break
            time.sleep(0.1)
        require(port is not None)
        self.pod_identity()
        if self.args.startup_only:
            self.stage = "startup-verified"
            self.checkpoint()
            return 0
        credentials = self.work / "credentials.json"
        credentials.write_text(json.dumps({"Host": "127.0.0.1", "Port": port, "User": "root", "Password": password,
            "CAFile": str(ca_file), "TLSServerName": "localhost", "ServerUUID": server_uuid}))
        credentials.chmod(0o600)
        del password
        self.stage = "a-native-diagnostic"
        env = dict(os.environ, A_PERMIT_NATIVE_SCRATCH=str(self.work))
        self.runner = subprocess.Popen(["bash", str(self.args.bundle / "run-diagnostic.sh"), str(credentials), server_uuid, str(self.logs / "diagnostic")],
                                       env=env, start_new_session=True)
        self.checkpoint()
        code = self.runner.wait(timeout=1080)
        if code == 0:
            require(self.forward.poll() is None)
        self.stage = "diagnostic-finished"
        return code if code >= 0 else 128 - code

    def stop(self, process, group=False):
        if process is None or process.poll() is not None:
            return
        # Popen owns the unreaped child PID. No name/prefix based process search.
        if group:
            require(os.getpgid(process.pid) == process.pid)
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if group:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=10)

    def cleanup(self):
        rc = 0
        for name, process, group in (("runner-process", self.runner, True), ("port-forward-process", self.forward, False)):
            try:
                self.stop(process, group)
            except Exception:
                self.residuals.append(name + ":" + str(process.pid if process else "unknown"))
                rc = 1
        if self.forward_stream:
            try:
                self.forward_stream.close()
            except Exception:
                rc = 1
        if self.attempted:
            try:
                if self.namespace_identity(recover=True):
                    require(self.uid is not None)
                    # GET owner check PLUS atomic UID precondition; never delete by prefix.
                    delete = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": self.uid}, "propagationPolicy": "Foreground"}
                    self.command(["delete", "--raw=/api/v1/namespaces/" + self.namespace, "-f", "-"], delete)
                    deadline = time.monotonic() + self.args.cleanup_timeout
                    while self.get_namespace() is not None:
                        require(time.monotonic() < deadline)
                        time.sleep(1)
            except Exception:
                self.residuals.append("namespace:" + self.namespace + ":uid=" + str(self.uid) + ":owner=" + self.owner)
                rc = 1
        # Namespace / process failures do not skip erasure of local credentials.
        if self.work is not None:
            try:
                require(not self.work.is_symlink() and self.work.resolve() == self.work and self.work.parent == self.args.scratch)
                require(self.work.name.startswith("d-kube-mysql-"))
                shutil.rmtree(self.work)
                require(not self.work.exists())
            except Exception:
                self.residuals.append("private-work:" + str(self.work))
                rc = 1
        return rc

    def finish(self, original):
        try:
            self.collect_startup_diagnostics()
        except Exception:
            # Diagnostic collection/file errors must never prevent cleanup or replace rc.
            self.diagnostics_exit_code = 1
        cleanup = self.cleanup()
        self.password = None
        report = {"scope": "isolated fixture DATA; not page or production acceptance", "stage": self.stage,
                  "mode": "startup-only" if self.args.startup_only else "native-diagnostic", "native_started": self.runner is not None,
                  "namespace": self.namespace, "namespace_uid": self.uid, "owner": self.owner,
                  "server_version": self.server_version, "observed_image_ids": self.image_ids,
                  "server_uuid": self.server_uuid, "session_tls": self.session_tls, "diagnostics_exit_code": self.diagnostics_exit_code,
                  "original_exit_code": original, "cleanup_exit_code": cleanup, "residuals": self.residuals,
                  "full_acceptance": False}
        if self.logs_created:
            try:
                (self.logs / "fixture.json").write_text(json.dumps(report, indent=2) + "\n")
            except Exception:
                cleanup = 1
                report["cleanup_exit_code"] = 1
                report["residuals"].append("fixture-report-write")
        try:
            print(json.dumps(report), flush=True)
        except Exception:
            cleanup = 1
            print("Fixture report write failed; cleanup was attempted. Original test exit retained.", file=sys.stderr)
        return original if original else cleanup


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="required except with --startup-only")
    parser.add_argument("--startup-only", action="store_true", help="only create/check/clean the isolated TLS MySQL; no bundle or native runner")
    parser.add_argument("--include-init-logs", action="store_true", help="save sanitized bounded logs from this run's tls init only")
    parser.add_argument("--include-container-logs", action="store_true", help="save sanitized bounded logs from this run's mysql and tls containers")
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--logs", required=True, type=Path)
    parser.add_argument("--context", default="kubernetes-admin@kubernetes")
    parser.add_argument("--mysql-image", default=MYSQL_IMAGE)
    parser.add_argument("--port", type=int, default=0, help="0 uses kubectl-selected free loopback port; never 3306")
    parser.add_argument("--cleanup-timeout", type=int, default=90)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.uname().machine == "x86_64")
    require(all(path.is_absolute() for path in (args.scratch, args.logs)))
    args.scratch = args.scratch.resolve(strict=True)
    require(args.scratch.is_dir() and not args.logs.exists() and not args.logs.is_symlink())
    require(args.logs.parent.resolve(strict=True) == args.logs.parent)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:" + DIGEST, args.mysql_image))
    require(args.port == 0 or (1023 < args.port < 65536 and args.port != 3306))
    require(1 <= args.cleanup_timeout <= 300 and args.context and not args.context.startswith("-"))
    tools = ("bash", "kubectl") if args.startup_only else ("bash", "kubectl", "sha256sum", "stat", "mktemp", "cp", "chmod", "tee", "grep", "rm", "uname", "mkdir")
    for tool in tools:
        require(shutil.which(tool))
    if not args.startup_only:
        require(args.bundle is not None and args.bundle.is_absolute())
        args.bundle = args.bundle.resolve(strict=True)
        require((args.bundle / "run-diagnostic.sh").is_file() and (args.bundle / "SHA256SUMS").is_file())
        # Verify the existing A bundle before creating any Kubernetes resources.
        result = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=args.bundle, capture_output=True)
        require(result.returncode == 0)
    return args


def main():
    os.umask(0o077)
    fixture = Fixture(parse())
    def interrupted(signum, _frame):
        raise Interrupted(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    original = 1
    try:
        original = fixture.run()
    except Interrupted as error:
        original = error.code
    except Exception:
        # Do not print kubectl/SQL/credential-bearing exception text or Pod logs.
        original = 1
    finally:
        # A second signal must not abort the bounded cleanup midway.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    return fixture.finish(original)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit("Fixture preflight/report failed; private error details withheld. Check exact residual resources if a run started.")
