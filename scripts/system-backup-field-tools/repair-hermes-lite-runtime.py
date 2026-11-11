#!/usr/bin/env python3
"""Publish, inspect and roll out only the validation Hermes runtime."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request

WORK = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
KUBE = WORK / "operator.kubeconfig.yaml"
NS = "clawmanager-sbk-validation-system"
DEPLOYMENT = "hermes-runtime"
DEPLOYMENT_UID = "de547f9b-b21a-45b3-9d74-c77ce35ab0d4"
OLD_IMAGE = "10.130.14.23:5000/hermes-lite@sha256:a2473da0cf375ed128116af3083eccd3276665adac4ae2722edcbff6cc277353"
REPAIRED_DIGEST = "sha256:279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254"
CA_SHA = "c99ddcf7198d4e8cc0445a141ddef69e6998ec213c007955b38bb37efda394f3"
DEPENDENCIES = {
    "publish-hermes-lite-native.py": "c1db2bdcb5c7529fd7d46d1b46d67c79e801651e11d49c49ad5652e926989b8c",
    "inspect-hermes-lite-candidate.py": "d6f893a632fb4b7becf22ef1ba37f19562bd6a1ff5f800c610a664de317b5f10",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise RuntimeError("App API redirect refused")


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def load(directory, filename, name):
    path = directory / filename
    need(hashlib.sha256(path.read_bytes()).hexdigest() == DEPENDENCIES[filename], "repair dependency source changed: " + filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_container(container):
    result = copy.deepcopy(container)
    for item in result.get("env", []):
        # EnvVar.Value is omitted by Kubernetes JSON serialization when empty.
        # No valueFrom, nonempty value, entry order or other field is ignored.
        if item.get("value") == "" and "valueFrom" not in item:
            item.pop("value")
    return result


def canonical_spec(spec):
    result = copy.deepcopy(spec)
    pod = result["template"]["spec"]
    pod["containers"] = [canonical_container(item) for item in pod["containers"]]
    return result


def difference_paths(expected, actual, prefix=""):
    if type(expected) is not type(actual):
        return [prefix or "/"]
    if isinstance(expected, dict):
        differences = []
        for key in sorted(set(expected) | set(actual)):
            path = prefix + "/" + str(key).replace("~", "~0").replace("/", "~1")
            differences.extend([path] if key not in expected or key not in actual
                               else difference_paths(expected[key], actual[key], path))
        return differences
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [prefix + "/length"]
        return [path for index, pair in enumerate(zip(expected, actual))
                for path in difference_paths(pair[0], pair[1], prefix + "/" + str(index))]
    return [] if expected == actual else [prefix or "/"]


def runtime_admission_container(expected_pod, actual_pod, expected_container):
    need(len(actual_pod.get("containers", [])) == 1 and not actual_pod.get("initContainers"),
         "runtime admission added a container")
    actual = canonical_container(actual_pod["containers"][0])
    expected = canonical_container(expected_container)
    critical = ("image", "command", "args", "workingDir", "env", "envFrom", "volumeMounts")
    comparison = lambda value: {key: value.get(key) for key in critical}
    print("POD_STARTUP_DIFFERENCE_PATHS", json.dumps(difference_paths(comparison(expected), comparison(actual))), flush=True)
    expected_mounts = expected.get("volumeMounts", [])
    actual_mounts = actual.get("volumeMounts", [])
    expected_names = {item["name"] for item in expected_mounts}
    added = [item for item in actual_mounts if item["name"] not in expected_names]
    if added:
        # ServiceAccount admission adds this read-only, Pod-local credential
        # projection. It does not appear in the Deployment container template.
        need(len(added) == 1 and expected_pod.get("automountServiceAccountToken") is not False,
             "runtime admission added unexpected mounts")
        mount = added[0]
        need(mount == {"name": mount["name"], "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True}
             and mount["name"].startswith("kube-api-access-"), "unexpected ServiceAccount mount shape")
        need(actual_pod.get("serviceAccountName", "default") == expected_pod.get("serviceAccountName", "default"),
             "runtime admission changed the ServiceAccount")
        volume = next((item for item in actual_pod.get("volumes", []) if item["name"] == mount["name"]), None)
        need(volume is not None and set(volume) == {"name", "projected"}, "ServiceAccount mount is not a projected volume")
        projected = volume["projected"]
        need(set(projected) == {"defaultMode", "sources"} and projected["defaultMode"] == 0o644
             and len(projected["sources"]) == 3, "unexpected ServiceAccount projection shape")
        by_type = {}
        for source in projected["sources"]:
            need(len(source) == 1, "unexpected mixed ServiceAccount projection source")
            key = next(iter(source))
            need(key not in by_type, "duplicate ServiceAccount projection source")
            by_type[key] = source[key]
        need(set(by_type) == {"serviceAccountToken", "configMap", "downwardAPI"}, "unexpected ServiceAccount projection sources")
        token = by_type["serviceAccountToken"]
        need(set(token) <= {"path", "expirationSeconds", "audience"} and token.get("path") == "token"
             and not token.get("audience") and isinstance(token.get("expirationSeconds"), int)
             and 600 <= token["expirationSeconds"] <= 86400, "unexpected ServiceAccount token projection")
        ca = by_type["configMap"]
        need(set(ca) <= {"name", "items", "optional"} and ca.get("name") == "kube-root-ca.crt"
             and not ca.get("optional") and ca.get("items") == [{"key": "ca.crt", "path": "ca.crt"}],
             "unexpected ServiceAccount CA projection")
        need(by_type["downwardAPI"] == {"items": [{"path": "namespace", "fieldRef": {
            "apiVersion": "v1", "fieldPath": "metadata.namespace"}}]}, "unexpected ServiceAccount namespace projection")
        actual["volumeMounts"] = [item for item in actual_mounts if item["name"] != mount["name"]]
        print("STANDARD_SERVICEACCOUNT_PROJECTION_CONFIRMED", flush=True)
    need(comparison(actual) == comparison(expected), "runtime admission changed the inspected startup")
    # Preserve every declared business/TLS volume and allow only the validated
    # extra projection. No injected Secret, hostPath or workspace replacement.
    expected_volumes = {item["name"]: item for item in expected_pod.get("volumes", [])}
    actual_volumes = {item["name"]: item for item in actual_pod.get("volumes", [])}
    allowed_extra = {added[0]["name"]} if added else set()
    need(set(actual_volumes) == set(expected_volumes) | allowed_extra
         and all(actual_volumes[name] == value for name, value in expected_volumes.items()),
         "runtime admission changed a business/TLS volume")
    return actual


def main(resume_records=None):
    os.umask(0o077)
    directory = Path(__file__).resolve().parent
    records = Path(tempfile.mkdtemp(prefix="p2-hermes-resume." if resume_records else "p2-hermes-repair.", dir="/root/sbk"))
    print("HERMES_REPAIR_RECORDS", records, flush=True)
    base = ["kubectl", "--kubeconfig", str(KUBE), "--request-timeout=20s", "-n", NS]

    def call(label, args, data=None, timeout=60, private_output=True):
        result = subprocess.run(base + args, input=data, capture_output=True, text=True, timeout=timeout)
        if private_output:
            (records / (label + ".stdout.private")).write_text(result.stdout, encoding="utf-8")
        (records / (label + ".stderr.private")).write_text(result.stderr, encoding="utf-8")
        need(result.returncode == 0, label + " failed; inspect private logs in " + str(records))
        return result.stdout

    def get(kind, name):
        return json.loads(call("get-" + kind + "-" + name, ["get", kind, name, "-o", "json"]))

    def pinned(pin):
        raw = Path(pin["File"]).read_bytes()
        need(hashlib.sha256(raw).hexdigest() == pin["SHA256"], "pinned material bytes changed")
        return raw

    receipt = json.loads(Path("/root/sbk/p2-runtime-rollout.us14OMgn/runtime-agent-tls.receipt.private.json").read_bytes())
    need(receipt["Namespace"] == NS and receipt["CA"]["SHA256"] == CA_SHA, "unexpected runtime CA receipt")
    pinned(receipt["CA"])
    need(datetime.fromisoformat(receipt["NotAfter"].replace("Z", "+00:00")) > datetime.now(timezone.utc), "existing runtime TLS expired")
    target = next(item for item in receipt["Targets"] if item["Deployment"] == DEPLOYMENT)
    need(target["DeploymentUID"] == DEPLOYMENT_UID, "TLS deployment identity mismatch")
    pinned(target["Certificate"])
    pinned(target["PrivateKey"])
    original = get("deployment", DEPLOYMENT)
    need(original["metadata"]["uid"] == DEPLOYMENT_UID, "Hermes deployment replaced")
    need(original["spec"].get("replicas", 1) == 1 and original["spec"]["strategy"]["type"] == "Recreate", "unexpected Hermes rollout shape")
    pod_spec = original["spec"]["template"]["spec"]
    need(len(pod_spec["containers"]) == 1 and not pod_spec.get("initContainers"), "unexpected runtime container shape")
    old_container = pod_spec["containers"][0]
    need(old_container["name"] == "runtime" and not old_container.get("command") and not old_container.get("args"), "unexpected runtime startup override")
    need(len({item["name"] for item in old_container.get("env", [])}) == len(old_container.get("env", [])), "duplicate runtime environment")
    values = {item["name"]: item.get("value") for item in old_container.get("env", [])}
    need(values.get("RUNTIME_AGENT_TLS_CERT_FILE") == "/run/clawmanager-agent-tls/tls.crt"
         and values.get("RUNTIME_AGENT_TLS_KEY_FILE") == "/run/clawmanager-agent-tls/tls.key", "unexpected existing TLS mount configuration")
    manifest_secret = json.loads(pinned(target["SecretManifest"]))
    actual_secret = get("secret", target["SecretName"])
    need(actual_secret.get("immutable") is True and actual_secret["data"] == manifest_secret["data"], "existing runtime TLS Secret changed")
    publisher = load(directory, "publish-hermes-lite-native.py", "sbk_hermes_publisher")
    if resume_records:
        resume_records = Path(resume_records)
        need(resume_records.is_absolute() and resume_records.resolve(strict=True) == resume_records
             and resume_records.is_dir() and resume_records.stat().st_mode & 0o077 == 0, "private original repair records required")
        saved = json.loads((resume_records / "rollout-plan.private.json").read_bytes())
        publication_directory = resume_records / "image"
        need(saved["deployment_uid"] == DEPLOYMENT_UID
             and Path(saved["image_publication"]) == publication_directory / "publication.receipt.json", "unexpected saved repair plan")
        publication = json.loads((publication_directory / "publication.receipt.json").read_bytes())
        need(publication["manifest_digest"] == REPAIRED_DIGEST and publication["base_digest"] == publisher.BASE
             and publication["agent_sha256"] == publisher.AGENT
             and publication["image"] == "10.130.14.23:5000/hermes-lite@" + REPAIRED_DIGEST, "unexpected saved image publication")
        for pin in publication["pins"].values():
            need(Path(pin["File"]).resolve(strict=True).parent == publication_directory, "saved image input path escaped its private directory")
            pinned(pin)
        need(publication["pins"]["manifest.json"]["SHA256"] == REPAIRED_DIGEST.removeprefix("sha256:")
             and publication["config_digest"] == "sha256:" + publication["pins"]["config.private.json"]["SHA256"], "saved image descriptor identity mismatch")
        raw_paths = difference_paths(saved["desired"], original["spec"])
        remaining = difference_paths(canonical_spec(saved["desired"]), canonical_spec(original["spec"]))
        print("DEPLOYMENT_DIFFERENCE_PATHS", json.dumps(raw_paths), flush=True)
        need(not remaining, "deployment changed beyond empty literal env serialization: " + json.dumps(remaining))
        print("DEPLOYMENT_MATCHES_AFTER_EMPTY_ENV_NORMALIZATION", flush=True)
        inspection_directory = Path(saved["inspection"])
        inspection = json.loads((inspection_directory / "candidate-inspection.json").read_bytes())
        print("REUSING_PUBLISHED_IMAGE_AND_COMPLETED_INSPECTION", publication["image"], flush=True)
    else:
        publication_directory = records / "image"
        publication_directory.mkdir(mode=0o700)
        publication = publisher.publish(directory, publication_directory)
        inspector = load(directory, "inspect-hermes-lite-candidate.py", "sbk_hermes_inspector")
        inspector.DIGEST = publication["manifest_digest"]
        inspector.IMAGE = publication["image"]
        inspection_directory, inspection = inspector.main()
    need(old_container["image"] in (OLD_IMAGE, publication["image"]), "unexpected current Hermes image")
    need(inspection["image"] == publication["image"] and inspection["startup_files_and_cli_verified"]
         and inspection["files"]["clawmanager-agent"]["sha256"] == publisher.AGENT
         and inspection["release.json"]["payload_sha256"] == publication["payload_sha256"]
         and inspection["release.json"]["desktop_web_accepted"] is False, "new image inspection did not confirm the expected payload")
    print("NEW_HERMES_IMAGE", publication["image"], flush=True)
    print("NEW_BASE_CONFIG", publication["pins"]["base-config.private.json"]["SHA256"], flush=True)
    print("NEW_RELEASE_SHA256", publication["release_sha256"], flush=True)
    desired = copy.deepcopy(original["spec"])
    container = desired["template"]["spec"]["containers"][0]
    if not resume_records:
        container["image"] = publication["image"]
        changes = {"CLAWMANAGER_RUNTIME_IMAGE_REF": publication["image"],
                   "CLAWMANAGER_RUNTIME_IMAGE_DIGEST": publication["manifest_digest"],
                   "CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED": "true", "CLAWMANAGER_HERMES_BACKEND_MODE": "serve",
                   "RUNTIME_GATEWAY_COMMAND": "start-hermes-lite-runtime", "RUNTIME_AGENT_ROLE": "",
                   "RUNTIME_AGENT_DATA_DIR": "/var/lib/clawmanager-agent"}
        container["env"] = [item for item in container.get("env", []) if item["name"] not in changes and item["name"] != "HERMES_TUI_DIR"]
        container["env"].extend({"name": key, "value": value} for key, value in changes.items())
    desired = canonical_spec(desired)
    container = desired["template"]["spec"]["containers"][0]
    plan = {"deployment_uid": DEPLOYMENT_UID, "original": original["spec"], "desired": desired,
            "image_publication": str(publication_directory / "publication.receipt.json"), "inspection": str(inspection_directory)}
    (records / "rollout-plan.private.json").write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def apply_spec(expected, replacement, label):
        current = get("deployment", DEPLOYMENT)
        need(current["metadata"]["uid"] == DEPLOYMENT_UID and canonical_spec(current["spec"]) == canonical_spec(expected), "Hermes deployment drift; no overwrite")
        patch = [{"op": "test", "path": "/metadata/uid", "value": DEPLOYMENT_UID},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/spec", "value": current["spec"]},
                 {"op": "replace", "path": "/spec", "value": canonical_spec(replacement)}]
        text = json.dumps(patch)
        call(label + "-dry-run", ["patch", "deployment", DEPLOYMENT, "--type=json", "--patch-file=/dev/stdin", "--dry-run=server", "-o", "json"], text)
        call(label, ["patch", "deployment", DEPLOYMENT, "--type=json", "--patch-file=/dev/stdin", "-o", "json"], text)

    def wait_rollout(label):
        call(label, ["--request-timeout=260s", "rollout", "status", "deployment/" + DEPLOYMENT, "--timeout=240s"], timeout=280)

    changed = False
    try:
        if canonical_spec(desired) != canonical_spec(original["spec"]):
            need(not resume_records, "resume mode refuses deployment mutation")
            print("Rolling out only Hermes with the existing TLS Secret", flush=True)
            # Arm recovery before the mutation: a lost API response can still mean it applied.
            changed = True
            apply_spec(original["spec"], desired, "rollout-hermes")
        wait_rollout("wait-hermes")
        current = get("deployment", DEPLOYMENT)
        need(current["metadata"]["uid"] == DEPLOYMENT_UID and canonical_spec(current["spec"]) == canonical_spec(desired), "Hermes deployment changed after rollout")
        selector = ",".join(key + "=" + value for key, value in desired["selector"]["matchLabels"].items())
        pods = json.loads(call("runtime-pods", ["get", "pods", "-l", selector, "-o", "json"]))["items"]
        pods = [item for item in pods if not item["metadata"].get("deletionTimestamp")]
        need(len(pods) == 1, "Hermes active Pod count did not settle")
        pod = pods[0]
        actual_container = runtime_admission_container(desired["template"]["spec"], pod["spec"], container)
        statuses = pod["status"].get("containerStatuses", [])
        need(pod["status"]["phase"] == "Running" and len(statuses) == 1 and statuses[0].get("ready"), "Hermes Pod not ready")
        image_id = statuses[0].get("imageID", "")
        need(any(image_id == value or image_id.endswith("@" + value) or image_id in ("containerd://" + value, "docker://" + value)
                 for value in (publication["manifest_digest"], publication["config_digest"])), "loaded Hermes image identity mismatch")
        binary = call("runtime-agent-sha", ["exec", pod["metadata"]["name"], "-c", "runtime", "--", "sha256sum", "/usr/local/bin/clawmanager-agent"])
        need(binary.split()[0] == publisher.AGENT, "loaded runtime Agent bytes mismatch")
        token = call("runtime-control-token", ["exec", pod["metadata"]["name"], "-c", "runtime", "--", "sh", "-c", 'printf "%s" "$RUNTIME_AGENT_CONTROL_TOKEN"'], private_output=False)
        need(token and not any(character.isspace() for character in token), "invalid loaded runtime control credential")
        context = ssl.create_default_context(cafile=receipt["CA"]["File"])
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        def control(path, authorized):
            connection = http.client.HTTPConnection(pod["status"]["podIP"], 19090, timeout=15)
            try:
                tcp = socket.create_connection((pod["status"]["podIP"], 19090), timeout=15)
                connection.sock = context.wrap_socket(tcp, server_hostname=receipt["ServerName"])
                need(hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() == target["ServerCertificateDERSHA256"], "runtime TLS leaf identity mismatch")
                uris = [value for kind, value in connection.sock.getpeercert().get("subjectAltName", ()) if kind == "URI"]
                need(uris == [target["ServerURI"]], "runtime TLS URI identity mismatch")
                connection.request("GET", path, headers={"X-ClawManager-Control-Token": token} if authorized else {})
                response = connection.getresponse()
                return response.status, response.read((1 << 20) + 1)
            finally:
                connection.close()

        status, _ = control("/v1/shared-backup/capabilities", False)
        need(status == 401, "runtime control authentication boundary changed")
        status, raw = control("/v1/shared-backup/capabilities", True)
        need(status == 200 and len(raw) <= 1 << 20, "shared backup capability request failed")
        capability = json.loads(raw)
        (records / "shared-backup-capabilities.json").write_bytes(raw)
        print("SHARED_BACKUP_CAPABILITY", json.dumps({key: capability.get(key) for key in (
            "Protocol", "Supported", "DurableReservation", "Namespace", "PodUID", "Deployment")}), flush=True)
        need(capability.get("Protocol") == "shared-container-freeze.v1" and capability.get("Supported") is True
             and capability.get("DurableReservation") is True and capability.get("Namespace") == NS
             and capability.get("PodUID") == pod["metadata"]["uid"] and capability.get("Deployment") == DEPLOYMENT,
             "runtime native capability identity mismatch")
        status, _ = control("/v1/health", True)
        need(status == 200, "runtime health request failed")
        print("HERMES_TLS_AND_SHARED_BACKUP_CAPABILITY_OK", pod["metadata"]["name"], publication["image"], flush=True)
    except Exception:
        if changed:
            try:
                current = get("deployment", DEPLOYMENT)
                if canonical_spec(current["spec"]) == canonical_spec(desired):
                    apply_spec(desired, original["spec"], "rollback-hermes")
                    wait_rollout("wait-rollback")
                    print("HERMES_INFRASTRUCTURE_CHECK_FAILED_ORIGINAL_SPEC_RESTORED", records, flush=True)
                else:
                    need(canonical_spec(current["spec"]) == canonical_spec(original["spec"]), "deployment drift prevents automatic rollback")
            except Exception as recovery_error:
                print("HERMES_ROLLBACK_UNCONFIRMED", str(recovery_error), records, flush=True)
        raise

    # Recover the failed instance only through the normal authenticated App API.
    app = get("deployment", "clawmanager-app")
    app_selector = ",".join(key + "=" + value for key, value in app["spec"]["selector"]["matchLabels"].items())
    app_pods = json.loads(call("app-pods", ["get", "pods", "-l", app_selector, "-o", "json"]))["items"]
    ready = [item for item in app_pods if not item["metadata"].get("deletionTimestamp")
             and item.get("status", {}).get("phase") == "Running"
             and item["status"].get("containerStatuses")
             and all(status.get("ready") for status in item["status"]["containerStatuses"])]
    need(ready, "no ready App Pod for normal instance recovery")
    log_path = records / "app-port-forward.private.log"
    with log_path.open("w", encoding="utf-8") as log:
        forward = subprocess.Popen(base + ["--request-timeout=0", "port-forward", "pod/" + ready[0]["metadata"]["name"],
            ":9001", "--address=127.0.0.1"], stdout=log, stderr=subprocess.STDOUT)
    try:
        port = None
        for _ in range(100):
            match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+) -> 9001", log_path.read_text())
            if match:
                port = int(match.group(1))
                break
            need(forward.poll() is None, "App port-forward failed; inspect its private log")
            time.sleep(0.2)
        need(port is not None, "App port-forward did not become ready")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def api(method, path, payload=None, bearer=None):
            headers = {"Content-Type": "application/json"}
            if bearer:
                headers["Authorization"] = "Bearer " + bearer
            request = urllib.request.Request("http://127.0.0.1:" + str(port) + path,
                data=json.dumps(payload).encode() if payload is not None else None, headers=headers, method=method)
            with opener.open(request, timeout=20) as response:
                need(response.status == 200, "App API request did not succeed")
                raw = response.read((4 << 20) + 1)
            need(len(raw) <= 4 << 20, "App response too large")
            return json.loads(raw)

        enrollment = WORK / "fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native/original-enrollment-plan.json"
        plan = json.loads(enrollment.read_bytes())
        password = (WORK / "fresh-backup-bootstrap/admin-password").read_text().rstrip("\r\n")
        login = api("POST", "/api/v1/auth/login", {"username": plan["LocalAdminUsername"], "password": password})
        bearer = login["data"]["access_token"]
        before = api("GET", "/api/v1/instances/3", bearer=bearer)["data"]["instance"]
        need(before["id"] == 3 and before.get("type") == "hermes" and before.get("runtime_type") == "gateway"
             and before.get("instance_mode") == "lite", "unexpected instance 3 identity")
        print("HERMES_INSTANCE_BEFORE", before.get("status"), "generation", before.get("runtime_generation"), flush=True)
        if before.get("status") in ("error", "stopped") and not resume_records:
            api("POST", "/api/v1/instances/3/start", payload={}, bearer=bearer)
            print("HERMES_NORMAL_API_START_ACCEPTED", flush=True)
        previous = None
        for _ in range(46):
            instance = api("GET", "/api/v1/instances/3", bearer=bearer)["data"]["instance"]
            state = {key: instance.get(key) for key in ("id", "status", "runtime_generation", "runtime_error_code", "runtime_error_message")}
            if state != previous:
                print("HERMES_INSTANCE_STATUS", json.dumps(state, ensure_ascii=False), flush=True)
                previous = state
            (records / "instance-recovery.json").write_text(json.dumps(state, ensure_ascii=False) + "\n", encoding="utf-8")
            if state["status"] == "running":
                print("HERMES_RUNNING_P2_STARTUP_INPUTS_UPDATE_REQUIRED", records, flush=True)
                return
            if state["status"] == "error":
                break
            time.sleep(2)
        print("HERMES_RUNTIME_READY_INSTANCE_RECOVERY_PENDING", records, flush=True)
        raise RuntimeError("Hermes instance did not become running; retain the verified runtime for diagnosis")
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()
            forward.wait(timeout=5)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--resume-records", type=Path, help="verify an already applied repair; no publication, test Pod, rollout or instance start")
        args = parser.parse_args()
        main(args.resume_records)
    except Exception as error:
        raise SystemExit("HERMES_REPAIR_UNCONFIRMED " + str(error))
