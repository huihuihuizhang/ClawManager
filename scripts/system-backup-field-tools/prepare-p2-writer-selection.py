#!/usr/bin/env python3
"""Use retained P2 coordinates and loaded credentials to author a base selection.

This calls the existing prepare-selection owner, not a stop/adoption operation.
Credentials are retained only in the private output directory and never printed.
"""
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import posixpath
import subprocess
import tempfile

BIN = Path("/root/sbk/p2-hermes-1dd1ae71")
WORK = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
KUBE = WORK / "operator.kubeconfig.yaml"
ENR = WORK / "fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native"
DATA = Path("/root/sbk/p2-materials-1dd1ae71.lVSEBfl2")
NS = "clawmanager-sbk-validation-system"
PINS = {
    "coordinates": (DATA / "coordinates/initial-source-coordinates.json", "4fe0083a3546c7a41c302861c65b805eea9ef981f9862e86f4bae043724b7980"),
    "snapshot": (DATA / "coordinates/initial-source-kubernetes.private.json", "2dc4ce78540b2194c6c94679908fadd83340cee95e4e8e5afd472fed75b0577a"),
    "startup": (DATA / "runtime-startup-images/runtime-startup-images.json", "28e979483e004141f3452f13609057fc0cde5bb82e4ca1d34e299cb536087068"),
    "plan": (ENR / "original-enrollment-plan.json", "a0aa44b5a12a453c352a402e73c4f4d42a675b2430d2cb69972a29df1f859752"),
    "observer_definition": (WORK / "fresh-backup-bootstrap/observer-pki.definition.json", "47de353412f9811338a87dfefffae3e328557269e41d486a11fd71b6b385733b"),
    "observer_receipt": (WORK / "fresh-backup-bootstrap/observer-pki.receipt.json", "b0749959fb6ae25eef2ef7568b571e895cdab8daa619dd2894764e99481815b9"),
}
EXPECTED_IMAGES = {
    "10.130.14.23:5000/openclaw-lite@sha256:5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140",
    "10.130.14.23:5000/hermes-lite@sha256:279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254",
}
CA_SHA = "c99ddcf7198d4e8cc0445a141ddef69e6998ec213c007955b38bb37efda394f3"
ADOPTION_SHA = "130a12944ed7faa4655234107d006875859d7152b1d7952a3232b14f1d601b41"


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(path, digest, limit=8 << 20):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and path.is_file(), "pinned input path changed")
    need(0 < path.stat().st_size <= limit and path.stat().st_mode & 0o077 == 0, "pinned input must remain private and bounded")
    raw = path.read_bytes()
    need(sha(raw) == digest, "pinned input bytes changed: " + path.name)
    return raw


def source_config(data, scope, workspace, credential, ca):
    need(data.get("Version") == "original-initial-source-coordinates.v1" and data.get("Namespace") == NS,
         "unexpected source coordinates")
    need(scope and len(scope) <= 128 and scope in data.get("ApplicationScopes", []), "loaded App scope is absent from original SQL coordinates")
    need(workspace == "/workspaces" and posixpath.normpath(workspace) == workspace, "unexpected loaded workspace root")
    test_scope = data.get("RuntimeTestScope")
    need(isinstance(test_scope, dict) and test_scope.get("Version") in (
        "explicit-running-only-runtime-test-scope.v2", "explicit-running-tenant-runtime-test-scope.v3"), "original runtime scope missing")
    rows = data["Instances"]
    need([row["ID"] for row in rows] == list(range(1, 9))
         and [row["ID"] for row in test_scope["Deferred"]] == [4, 5, 6]
         and [row["ID"] for row in rows if row["ID"] not in (4, 5, 6)] == [1, 2, 3, 7, 8]
         and all(row["Status"] == "running" for row in rows if row["ID"] not in (4, 5, 6)), "approved runtime roster changed")
    need(test_scope["InstallationID"] == data["InstallationID"] and test_scope["NamespaceUID"] == data["NamespaceUID"], "runtime scope target changed")
    return {"installation_id": data["InstallationID"], "namespace": data["Namespace"], "namespace_uid": data["NamespaceUID"],
        "application_scope": scope, "runtime_sources": {"shared_runtime_protocol": "shared-container-freeze.v1",
            "workspace_root": workspace, "agent_token_file": str(credential), "agent_ca_file": ca["File"], "agent_ca_sha256": ca["SHA256"],
            "current_stopped_pro_layouts": copy.deepcopy(data.get("StoppedProLayouts", [])), "runtime_test_scope": copy.deepcopy(test_scope)}}


def main():
    os.umask(0o077)
    records = Path(tempfile.mkdtemp(prefix="p2-writer-selection.", dir="/root/sbk"))
    print("WRITER_SELECTION_RECORDS", records, flush=True)
    material = {name: pinned(path, digest) for name, (path, digest) in PINS.items()}
    data, snapshot, plan = (json.loads(material[name]) for name in ("coordinates", "snapshot", "plan"))
    target = plan["Target"]
    need(all(data[key] == target[key] for key in ("InstallationID", "Namespace", "NamespaceUID")), "enrolled source target changed")
    need((BIN / "SOURCE_REVISION").read_text().strip() == "1dd1ae7179520223c944401a2cc38fb738e09540", "wrong CLI source revision")
    need(sha((BIN / "system-backup-first-adoption").read_bytes()) == ADOPTION_SHA, "wrong prepare-selection executable")
    base = ["kubectl", "--kubeconfig", str(KUBE), "--request-timeout=20s", "-n", NS]
    sequence = 0

    def kube(label, args, private_stdout=True):
        nonlocal sequence
        sequence += 1
        prefix = str(sequence) + "-" + label
        result = subprocess.run(base + args, capture_output=True, timeout=40)
        (records / (prefix + ".stderr.private")).write_bytes(result.stderr)
        if private_stdout:
            (records / (prefix + ".stdout.private")).write_bytes(result.stdout)
        need(result.returncode == 0, label + " failed; inspect its private log")
        return result.stdout

    def get(kind, name):
        return json.loads(kube("get-" + kind + "-" + name, ["get", kind, name, "-o", "json"]))

    def loaded(captured):
        name = captured["metadata"]["name"]

        def check(current):
            need(current["metadata"]["uid"] == captured["metadata"]["uid"]
                 and not current["metadata"].get("deletionTimestamp") and current["status"].get("phase") == "Running"
                 and len(current["spec"]["containers"]) == len(captured["spec"]["containers"]) == 1
                 and current["spec"]["containers"][0]["name"] == captured["spec"]["containers"][0]["name"]
                 and current["spec"]["containers"][0]["image"] == captured["spec"]["containers"][0]["image"]
                 and len(current["spec"].get("initContainers", [])) == len(captured["spec"].get("initContainers", []))
                 and len(current["spec"].get("ephemeralContainers", [])) == len(captured["spec"].get("ephemeralContainers", [])),
                 "captured Pod changed: " + name)
            actual_status = current["status"].get("containerStatuses", [])
            old_status = captured["status"].get("containerStatuses", [])
            need(len(actual_status) == len(old_status) == 1 and actual_status[0].get("ready")
                 and actual_status[0].get("containerID") and actual_status[0]["containerID"] == old_status[0].get("containerID"),
                 "captured container restarted: " + name)

        check(get("pod", name))
        command = r'printf "%s\000%s\000%s" "$SYSTEM_BACKUP_SQL_GATE_SCOPE" "$RUNTIME_AGENT_CONTROL_TOKEN" "$RUNTIME_WORKSPACE_ROOT"'
        raw = kube("loaded-source-inputs-" + name, ["exec", name, "-c", captured["spec"]["containers"][0]["name"],
            "--", "sh", "-c", command], private_stdout=False)
        check(get("pod", name))
        fields = raw.split(b"\0")
        need(len(fields) == 3, "loaded environment transport failed")
        return fields

    pods = [pod for pod in snapshot["Pods"] if pod["metadata"].get("namespace") == NS and not pod["metadata"].get("deletionTimestamp")]
    app_snapshot = next(dep for dep in snapshot["Deployments"] if dep["metadata"]["name"] == "clawmanager-app")
    app = get("deployment", "clawmanager-app")
    need(app["metadata"]["uid"] == app_snapshot["metadata"]["uid"]
         and app["metadata"]["generation"] == app_snapshot["metadata"]["generation"], "App changed since source coordinates")
    selector = app["spec"]["selector"]["matchLabels"]
    app_pods = [pod for pod in pods if all(pod["metadata"].get("labels", {}).get(key) == value for key, value in selector.items())]
    need(len(app_pods) == app["spec"].get("replicas", 1), "complete ready App cohort required")
    app_values = [loaded(pod) for pod in app_pods]
    scopes = {value[0].decode("utf-8").strip() for value in app_values}
    need(len(scopes) == 1, "App replicas have different loaded gate scopes")
    scope = scopes.pop()
    control = app_values[0][1]
    need(32 <= len(control) <= 8192 and not any(chr(value).isspace() for value in control), "actual App control credential unavailable")
    need(all(hmac.compare_digest(value[1], control) for value in app_values), "App replicas have different control credentials")
    runtime_pods = [pod for pod in pods if len(pod["spec"]["containers"]) == 1 and pod["spec"]["containers"][0]["image"] in EXPECTED_IMAGES]
    need(len(runtime_pods) == 2 and {pod["spec"]["containers"][0]["image"] for pod in runtime_pods} == EXPECTED_IMAGES,
         "both pinned Runtime Pods required")
    roots = set()
    for pod in runtime_pods:
        _, token, root = loaded(pod)
        need(hmac.compare_digest(token, control), "App and Runtime control credentials differ")
        roots.add(root.decode("utf-8"))
    need(len(roots) == 1, "Runtime workspace roots differ")
    workspace = roots.pop()
    need(all(not value[2] or value[2].decode("utf-8") == workspace for value in app_values), "App and Runtime workspace roots differ")
    after = get("deployment", "clawmanager-app")
    need(after["metadata"]["uid"] == app["metadata"]["uid"]
         and after["metadata"]["generation"] == app["metadata"]["generation"], "App changed while reading source inputs")
    tls = json.loads(Path("/root/sbk/p2-runtime-rollout.us14OMgn/runtime-agent-tls.receipt.private.json").read_bytes())
    need(tls["Version"] == "original-shared-agent-tls-materials.v1" and tls["Namespace"] == NS and tls["CA"]["SHA256"] == CA_SHA,
         "unexpected runtime TLS materials")
    pinned(tls["CA"]["File"], CA_SHA)
    credential = records / "agent-control-token.private"
    with credential.open("xb") as output:
        output.write(control)
    config = source_config(data, scope, workspace, credential, tls["CA"])
    config_file = records / "source-config.json"
    raw = (json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    config_file.write_bytes(raw)
    (records / "source-config.lineage.json").write_text(json.dumps({"version": "operator-actual-writer-source-config.v2",
        "coordinates": {"File": str(PINS["coordinates"][0]), "SHA256": PINS["coordinates"][1]},
        "config": {"File": str(config_file), "SHA256": sha(raw)}, "source_qualified": False, "backup_ready": False}), encoding="utf-8")
    print("SOURCE_CONFIG_READY", str(config_file), sha(raw), "scope", scope, flush=True)
    selection, journal = records / "selection", records / "journal"
    selection.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    argv = [str(BIN / "system-backup-first-adoption"), "--action", "prepare-selection",
        "--plan-file", str(PINS["plan"][0]), "--plan-sha256", PINS["plan"][1],
        "--issuer-public-file", str(ENR / "issuer.public"), "--issuer-public-sha256", "8a2df27b26737198ba78e49f5291bb53ad283e42099d228e1ba5762c6d318ac6",
        "--enrollment-pin-file", str(ENR / "original-enrollment-pin.json"), "--enrollment-pin-sha256", "ba649013288b0b62fb111e74ce151f344ad76169b8c9206da47fa1580b086256",
        "--kubeconfig-file", str(KUBE), "--kubeconfig-sha256", "152d2049f8b1c3e9e043ed024bae24cf2253aa3b8da19bf1c67f9fa9a9979bde",
        "--dsn-file", str(WORK / "fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn"),
        "--database-ca-file", str(WORK / "mysql-source-ca.pem"), "--local-admin-password-file", str(WORK / "fresh-backup-bootstrap/admin-password"),
        "--source-config-file", str(config_file), "--source-config-sha256", sha(raw),
        "--runtime-startup-images-file", str(PINS["startup"][0]), "--runtime-startup-images-sha256", PINS["startup"][1],
        "--observer-definition-file", str(PINS["observer_definition"][0]), "--observer-definition-sha256", PINS["observer_definition"][1],
        "--observer-receipt-file", str(PINS["observer_receipt"][0]), "--observer-receipt-sha256", PINS["observer_receipt"][1],
        "--selection-output-directory", str(selection), "--journal-directory", str(journal)]
    print("Preparing writer selection through the original owner", flush=True)
    result = subprocess.run(argv, capture_output=True, timeout=160)
    (records / "prepare-selection.stdout.private").write_bytes(result.stdout)
    (records / "prepare-selection.stderr.private").write_bytes(result.stderr)
    if result.stdout:
        print(result.stdout.decode("utf-8", errors="replace").strip(), flush=True)
    need(result.returncode == 0, "prepare-selection refused; retain this directory and its private stderr")
    receipt = json.loads(result.stdout)
    need(receipt["Version"] == "original-writer-selection-materials.v1", "unexpected writer selection receipt")
    for field in ("Selection", "SourceCoordinates"):
        pinned(receipt[field]["File"], receipt[field]["SHA256"])
    (records / "writer-selection.receipt.json").write_bytes(result.stdout)
    print("P2_WRITER_SELECTION_AUTHORED", records, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("P2_WRITER_SELECTION_UNCONFIRMED " + str(error))
