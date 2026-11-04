#!/usr/bin/env python3
"""Observe actual Pod identity and normal HTTPS config/readiness routes.

No authorization is generated. pin creates a comparison receipt, NOT source
authority. verify never enables config. Its optional PUT body is always {} and
cannot pass DecodeConfigMutationRequest. Credentials are prompted, not saved.
"""
import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX = 4 * 1024 * 1024
CONFIG = "/api/v1/admin/system-backup-config"
OVERVIEW = "/api/v1/admin/system-backup-overview"


class Refused(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate_json_member")
        value[key] = item
    return value


def decode(raw):
    require(len(raw) <= MAX, "response_too_large")
    return json.loads(raw, object_pairs_hook=unique)


def kube(args, kind, name):
    proc = subprocess.run(["kubectl", "--context", args.context, "--namespace", args.namespace,
                           "--request-timeout=15s", "get", kind, name, "-o", "json"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    require(proc.returncode == 0, "kubernetes_observation_failed")
    return decode(proc.stdout)


def metadata(obj):
    m = obj["metadata"]
    require(m.get("uid") and m.get("resourceVersion") and not m.get("deletionTimestamp"),
            "object_identity_unavailable")
    return {key: m.get(key) for key in ("name", "namespace", "uid", "resourceVersion", "generation")}


def pod_identity(args, name):
    pod = kube(args, "pod", name)
    m = metadata(pod)
    require(m["namespace"] == args.namespace, "pod_namespace_changed")
    status = pod["status"]
    require(status.get("phase") == "Running" and any(c.get("type") == "Ready" and
            c.get("status") == "True" for c in status.get("conditions", [])), "pod_not_ready")
    containers = status.get("containerStatuses", [])
    require(len(containers) == len(pod["spec"]["containers"]) and containers, "container_set_unknown")
    for c in containers:
        require(c.get("ready") is True and c.get("containerID") and c.get("imageID") and
                c.get("state", {}).get("running", {}).get("startedAt"), "container_not_running")
    owners = [o for o in pod["metadata"].get("ownerReferences", []) if o.get("controller")]
    require(len(owners) == 1 and owners[0]["kind"] == "ReplicaSet", "expected_deployment_pod")
    rs = kube(args, "replicaset", owners[0]["name"])
    require(rs["metadata"]["uid"] == owners[0]["uid"], "replicaset_identity_changed")
    parents = [o for o in rs["metadata"].get("ownerReferences", []) if o.get("controller")]
    require(len(parents) == 1 and parents[0]["kind"] == "Deployment", "deployment_owner_unknown")
    deploy = kube(args, "deployment", parents[0]["name"])
    require(deploy["metadata"]["uid"] == parents[0]["uid"], "deployment_identity_changed")
    sa = kube(args, "serviceaccount", pod["spec"].get("serviceAccountName", "default"))
    return {"pod": m, "pod_spec_sha256": sha(canonical(pod["spec"])),
            "containers": sorted([{k: c.get(k) for k in ("name", "containerID", "imageID", "restartCount", "state")}
                                  for c in containers], key=lambda c: c["name"]),
            "replicaset": metadata(rs), "deployment": metadata(deploy),
            "deployment_spec_sha256": sha(canonical(deploy["spec"])), "serviceaccount": metadata(sa)}


def identity(args):
    ns = kube(args, "namespace", args.namespace)
    require(ns["metadata"]["uid"] == args.namespace_uid, "namespace_identity_changed")
    return {"context": args.context, "namespace": args.namespace, "namespace_uid": args.namespace_uid,
            "app": pod_identity(args, args.app_pod), "controller": pod_identity(args, args.controller_pod)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, origin, ca, ca_sha, token):
        url = urllib.parse.urlsplit(origin)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and url.path in ("", "/") and not url.query and not url.fragment, "https_origin_required")
        raw = ca.read_bytes()
        require(sha(raw) == ca_sha, "independent_ca_pin_mismatch")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cadata=raw.decode("ascii"))
        require(token and not any(c.isspace() for c in token), "session_token_invalid")
        self.origin, self.token = origin.rstrip("/"), token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                 urllib.request.HTTPSHandler(context=ctx))

    def request(self, path, method="GET"):
        # This body is deliberately unchangeable, with no config/version/proof.
        require(method in ("GET", "PUT") and (method != "PUT" or path == CONFIG), "probe_scope_invalid")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if method == "PUT":
            headers.update({"Content-Type": "application/json", "Idempotency-Key": "d-route-probe-" + os.urandom(16).hex()})
        req = urllib.request.Request(self.origin + path, data=b"{}" if method == "PUT" else None,
                                     headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.headers.get_content_type() == "application/json", "api_json_required")
            body = decode(response.read(MAX + 1))
            require(isinstance(body, dict), "api_object_required")
            return response.code, response.headers, body


def active_config(api, installation):
    status, headers, body = api.request(CONFIG)
    require(status == 200 and headers.get("X-System-Backup-Data-Source") == "live", "active_config_not_live")
    require(body.get("schema_version") == "system-backup-config.v1" and
            body.get("origin_installation_id") == installation and body.get("active") is True and
            type(body.get("version")) is int and body["version"] > 0 and
            type(body.get("row_version")) is int and body["row_version"] > 0 and
            isinstance(body.get("config"), dict) and type(body["config"].get("enabled")) is bool and
            type(body.get("effective_enabled")) is bool, "active_config_identity_invalid")
    return body


def readiness(api, installation, version):
    status, _, body = api.request(OVERVIEW)
    require(status == 200, "readiness_endpoint_unavailable")
    require(body.get("schema_version") == "system-backup-overview.v1" and
            body.get("origin_installation_id") == installation and body.get("config_version") == version,
            "readiness_identity_mismatch")
    stamp = dt.datetime.fromisoformat(body["observed_at"].replace("Z", "+00:00"))
    require(stamp.tzinfo is not None and -5 <= (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds() <= 60,
            "readiness_observation_stale")
    require(body.get("effective_enabled") is True and body.get("backup_recovery_readiness") is True and
            body.get("source_writer_state") == "clean" and
            all(body.get(k) == "healthy" for k in ("controller_health", "database_health",
                "artifact_target_health", "evidence_store_health", "catalog_health")), "readiness_not_healthy")
    return {"observed_at": body["observed_at"], "config_version": version, "backup_recovery_readiness": True}


def verify_api(api, installation, probe):
    first = active_config(api, installation)
    route = "not_probed"
    if probe:
        status, _, body = api.request(CONFIG, "PUT")
        require(status == 400 and body.get("code") == "validation_failed", "mutation_route_probe_failed")
        route = "invalid_body_rejected_400"
    require(first["config"]["enabled"] is True and first["effective_enabled"] is True, "config_not_enabled")
    observed = readiness(api, installation, first["version"])
    last = active_config(api, installation)
    require(first == last, "config_changed_during_readback")
    return {"config_version": first["version"], "mutation_route": route, "readiness": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("pin", "verify"))
    for name in ("context", "namespace", "namespace-uid", "app-pod", "controller-pod"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256")
    parser.add_argument("--origin")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--ca-sha256")
    parser.add_argument("--installation")
    parser.add_argument("--probe-mutation", action="store_true")
    args = parser.parse_args()
    report = {"schema_version": "d-field-enable-readback.v1", "status": "BLOCKED",
              "authorization_issued": False, "configuration_mutated": False,
              "browser_path_verified": False, "source_authority_proved": False}
    try:
        if args.action == "pin":
            before = identity(args)
            require(identity(args) == before, "identity_changed_during_pin")
            raw = canonical({"schema_version": "d-field-pod-comparison.v1", "identity": before})
            fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            report.update(status="COMPARISON_PINNED_NOT_AUTHORITY", receipt_sha256=sha(raw))
        else:
            require(all((args.receipt_sha256, args.origin, args.ca_file, args.ca_sha256, args.installation)),
                    "verification_inputs_missing")
            raw = args.receipt.read_bytes()
            require(sha(raw) == args.receipt_sha256, "receipt_pin_mismatch")
            receipt = decode(raw)
            require(receipt["schema_version"] == "d-field-pod-comparison.v1", "receipt_schema_invalid")
            require(identity(args) == receipt["identity"], "identity_changed_reissue_required")
            api = API(args.origin, args.ca_file, args.ca_sha256, getpass.getpass("Existing normal login bearer token (hidden): "))
            try:
                report.update(verify_api(api, args.installation, args.probe_mutation))
            finally:
                require(identity(args) == receipt["identity"], "identity_changed_during_readback")
            report["status"] = "API_READBACK_VERIFIED_BROWSER_AND_OWNER_ACCEPTANCE_STILL_REQUIRED"
    except Refused as error:
        report["reason"] = str(error)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, subprocess.SubprocessError, urllib.error.URLError):
        # Never print provider/kubectl responses, private paths or tokens.
        report["reason"] = "observation_unavailable"
    print(json.dumps(report, sort_keys=True))
    return 2 if report["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
