#!/usr/bin/env python3
"""Install the validation runtime CA in App and observe instance recovery."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

NS = "clawmanager-sbk-validation-system"
WORK = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
KUBE = WORK / "operator.kubeconfig.yaml"
EXPECTED_CA = "c99ddcf7198d4e8cc0445a141ddef69e6998ec213c007955b38bb37efda394f3"


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    os.umask(0o077)
    records = Path(tempfile.mkdtemp(prefix="p2-app-ca.", dir="/root/sbk"))
    print("APP_CA_RECORDS", records, flush=True)
    base = ["kubectl", "--kubeconfig", str(KUBE), "--request-timeout=20s", "-n", NS]

    def call(label, args, data=None):
        result = subprocess.run(base + args, input=data, capture_output=True, text=True)
        (records / (label + ".stdout.private")).write_text(result.stdout, encoding="utf-8")
        (records / (label + ".stderr.private")).write_text(result.stderr, encoding="utf-8")
        need(result.returncode == 0, label + " failed; see private logs in " + str(records))
        return result.stdout

    def get(kind, name):
        return json.loads(call("read-" + kind + "-" + name, ["get", kind, name, "-o", "json"]))

    receipt = json.loads(Path("/root/sbk/p2-runtime-rollout.us14OMgn/runtime-agent-tls.receipt.private.json").read_bytes())
    need(receipt["Namespace"] == NS and receipt["CA"]["SHA256"] == EXPECTED_CA, "unexpected runtime CA receipt")
    ca = Path(receipt["CA"]["File"]).read_bytes()
    need(hashlib.sha256(ca).hexdigest() == EXPECTED_CA, "runtime CA bytes changed")
    app = get("deployment", "clawmanager-app")
    (records / "original-app.private.json").write_text(json.dumps(app), encoding="utf-8")
    desired = copy.deepcopy(app["spec"])
    pod = desired["template"]["spec"]
    need(len(pod["containers"]) == 1, "unexpected App container roster")
    container = pod["containers"][0]
    cm_name = "sbk-runtime-agent-ca-" + EXPECTED_CA[:16]
    volume_name = "sbk-runtime-agent-ca"
    mount_root = "/run/clawmanager-agent-ca"
    volume = {"name": volume_name, "configMap": {"name": cm_name, "defaultMode": 292, "items": [{"key": "ca.pem", "path": "ca.pem"}]}}
    mount = {"name": volume_name, "mountPath": mount_root, "readOnly": True}
    volumes = pod.setdefault("volumes", [])
    mounts = container.setdefault("volumeMounts", [])
    existing_volumes = [item for item in volumes if item["name"] == volume_name]
    existing_mounts = [item for item in mounts if item["name"] == volume_name]
    need(not existing_volumes or existing_volumes == [volume], "App CA volume needs reconciliation")
    need(not existing_mounts or existing_mounts == [mount], "App CA mount needs reconciliation")
    for item in mounts:
        if item["name"] == volume_name:
            continue
        path = item["mountPath"].rstrip("/") or "/"
        need(path != "/" and path != mount_root and not path.startswith(mount_root + "/") and not mount_root.startswith(path + "/"), "App CA mount path collision")
    if not existing_volumes:
        volumes.append(volume)
    if not existing_mounts:
        mounts.append(mount)
    env = container.setdefault("env", [])
    need(len({item["name"] for item in env}) == len(env), "duplicate App environment")
    for key, value in {"RUNTIME_AGENT_CA_FILE": mount_root + "/ca.pem", "RUNTIME_AGENT_CA_SHA256": EXPECTED_CA}.items():
        matches = [item for item in env if item["name"] == key]
        if matches:
            matches[0].clear()
            matches[0].update({"name": key, "value": value})
        else:
            env.append({"name": key, "value": value})
    configmap = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cm_name, "namespace": NS}, "immutable": True, "data": {"ca.pem": ca.decode("utf-8")}}
    existing = call("find-ca-configmap", ["get", "configmap", cm_name, "--ignore-not-found", "-o", "json"])
    current_cm = json.loads(existing) if existing.strip() else json.loads(call("create-ca-configmap", ["create", "-f", "-", "-o", "json"], json.dumps(configmap)))
    need(current_cm.get("immutable") is True and current_cm.get("data") == configmap["data"] and not current_cm["metadata"].get("deletionTimestamp"), "App CA ConfigMap mismatch")
    if desired != app["spec"]:
        patch = [{"op": "test", "path": "/metadata/uid", "value": app["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": app["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/spec", "value": app["spec"]},
                 {"op": "replace", "path": "/spec", "value": desired}]
        raw = json.dumps(patch)
        (records / "app-ca.patch.private.json").write_text(raw, encoding="utf-8")
        call("dry-run-app-ca", ["patch", "deployment", "clawmanager-app", "--type=json", "--patch-file=/dev/stdin", "--dry-run=server", "-o", "json"], raw)
        print("Rolling out App with the pinned runtime CA", flush=True)
        call("patch-app-ca", ["patch", "deployment", "clawmanager-app", "--type=json", "--patch-file=/dev/stdin", "-o", "json"], raw)
    call("wait-app", ["rollout", "status", "deployment/clawmanager-app", "--timeout=240s"])
    current = get("deployment", "clawmanager-app")
    need(current["metadata"]["uid"] == app["metadata"]["uid"] and current["spec"] == desired, "App deployment drift after rollout")
    selector = ",".join(key + "=" + value for key, value in desired["selector"]["matchLabels"].items())
    pods = json.loads(call("app-pods", ["get", "pods", "-l", selector, "-o", "json"]))["items"]
    active = [item for item in pods if not item["metadata"].get("deletionTimestamp")]
    need(len(active) == desired.get("replicas", 1), "App Pod count not settled")
    for item in active:
        statuses = item["status"].get("containerStatuses", [])
        need(item["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"), "App Pod not ready")
        actual = item["spec"]["containers"][0]
        need(actual["env"] == container["env"], "App admission changed environment")
        value = call("verify-ca-" + item["metadata"]["name"], ["exec", item["metadata"]["name"], "-c", container["name"], "--", "sh", "-c", 'sha256sum "$RUNTIME_AGENT_CA_FILE"; printf "PIN=%s\\n" "$RUNTIME_AGENT_CA_SHA256"'])
        need(value.split()[0] == EXPECTED_CA and "PIN=" + EXPECTED_CA in value, "App mounted CA mismatch")
        print("APP_AGENT_CA_OK", item["metadata"]["name"], EXPECTED_CA, flush=True)
    dsn = (WORK / "fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn").read_text().strip()
    credentials, separator, address = dsn.rpartition("@tcp(")
    user, colon, password = credentials.partition(":")
    _, database_separator, database_part = address.partition(")/")
    database = database_part.split("?", 1)[0]
    need(separator and colon and database_separator and user and database and not any(c in password for c in "\r\n\x00"), "unsupported installer DSN")
    query = "SELECT JSON_OBJECT('ID',id,'Status',status,'ErrorCode',COALESCE(runtime_error_code,''),'ErrorMessage',COALESCE(runtime_error_message,'')) FROM instances ORDER BY id"
    remote = 'IFS= read -r MYSQL_PWD || exit 1; export MYSQL_PWD; exec mysql --protocol=TCP --ssl-mode=REQUIRED -h 127.0.0.1 -P 3306 -u "$1" "$2" -N -B --raw -e "$3"'
    for attempt in range(7):
        rows = [json.loads(line) for line in call("instance-recovery", ["exec", "-i", "deployment/mysql", "-c", "mysql", "--", "sh", "-c", remote, "sbk-readonly", user, database, query], password + "\n").splitlines() if line.strip()]
        running = [row["ID"] for row in rows if row["Status"] == "running"]
        print("RUNNING_IDS", running, flush=True)
        if running == [1, 2, 3, 7, 8]:
            print("APP_CA_AND_RUNNING_ROSTER_RECOVERED", records, flush=True)
            return
        if attempt < 6:
            time.sleep(10)
    for row in rows:
        print(json.dumps(row, ensure_ascii=False), flush=True)
    print("APP_CA_READY_INSTANCE_RECOVERY_PENDING", records, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("APP_CA_UNCONFIRMED", str(error), flush=True)
        raise SystemExit(1)
