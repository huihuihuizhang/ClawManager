#!/usr/bin/env python3
"""No-argument, public-only collection for the explicitly selected field scope."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
CONTEXT = "kubernetes-admin@kubernetes"
NAMESPACE = "clawmanager-zhanghui08-system"
NAMESPACE_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
PINS = {
    "system-backup-first-page-inputs.py": "af8600aa44dd2e9db3835779a0bb438c4b172db8041d1a68aab49ffb1278c42e",
    "system-backup-d-first-install-inputs.py": "dbd5f6af63a29318f2106a64b12c5bdf0cbe564af9b3cccd07e5e17fd967b3be",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name):
    path = Path(__file__).absolute().with_name(name)
    if path.is_symlink() or not path.is_file():
        raise ValueError("pinned_dependency_required")
    raw = path.read_bytes()
    if len(raw) > 262144 or sha(raw) != PINS[name]:
        raise ValueError("dependency_pin_changed")
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_kubectl(arguments):
    result = subprocess.run(["kubectl", "--context=" + CONTEXT, "--request-timeout=15s", *arguments],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False)
    if result.returncode != 0 or len(result.stdout) > 262144:
        raise ValueError("public_scope_read_unavailable")
    return result.stdout


def service_endpoint(inventory, role):
    candidates = []
    for service in inventory["public_objects"].get("services", {}).get("items", []):
        name = service["name"].lower()
        labels = [str(value).lower() for value in service.get("selector", {}).values()]
        names = {role, "clawmanager-" + role}
        if name in names or role in labels or "clawmanager-" + role in labels:
            candidates.append(service)
    if len(candidates) != 1:
        return {"status": "not_selected", "reason": "missing_or_ambiguous_service", "candidates": [s["name"] for s in candidates]}
    service = candidates[0]
    address = service.get("cluster_ip", "")
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError("not_original_cluster_ip")
    except ValueError:
        return {"status": "not_selected", "reason": "no_finite_cluster_ip", "service": service["name"], "service_uid": service["uid"]}
    ports = [p for p in service.get("ports", []) if isinstance(p.get("port"), int) and 1 <= p["port"] <= 65535]
    preferred = ({"mysql", "mysql-tcp"} if role == "mysql" else {"api", "s3", "minio", "http", "https", "http-api", "minio-api"})
    selected = [p for p in ports if p.get("name", "").lower() in preferred]
    if len(selected) != 1:
        selected = ports if len(ports) == 1 else []
    if len(selected) != 1:
        return {"status": "not_selected", "reason": "api_port_ambiguous", "service": service["name"], "service_uid": service["uid"], "ports": ports}
    return {"status": "selected_from_actual_service_metadata", "service": service["name"], "service_uid": service["uid"],
            "cluster_ip": address, "port": selected[0]["port"], "port_name": selected[0].get("name", ""),
            "scheme_or_tls_inferred_from_port": False}


def main():
    if len(sys.argv) != 1:
        raise ValueError("this_fixed_scope_entry_takes_no_arguments")
    field = load("system-backup-first-page-inputs.py")
    public = load("system-backup-d-first-install-inputs.py")
    # First enforce the independently selected namespace UID, before any other
    # observation. whoami below is only a same-run consistency binding.
    uid = public_kubectl(["get", "namespace", NAMESPACE, "-o=jsonpath={.metadata.uid}"]).decode("ascii").strip()
    if uid != NAMESPACE_UID:
        raise ValueError("original_namespace_uid_changed")
    subject = json.loads(public_kubectl(["auth", "whoami", "-o=json"]))
    if subject.get("kind") != "SelfSubjectReview" or subject.get("apiVersion") != "authentication.k8s.io/v1":
        raise ValueError("self_subject_review_shape")
    info = subject.get("status", {}).get("userInfo", {})
    groups = info.get("groups", [])
    if not isinstance(groups, list) or not groups or not all(isinstance(g, str) for g in groups):
        raise ValueError("self_subject_groups")
    groups_sha = sha(json.dumps(sorted(groups), separators=(",", ":"), ensure_ascii=False).encode())
    args = SimpleNamespace(context=CONTEXT, namespace=NAMESPACE, namespace_uid=NAMESPACE_UID,
                           owner_subject=info.get("username"), owner_uid=info.get("uid", ""),
                           owner_groups_sha256=groups_sha, mode="inventory", mysql_host=None, mysql_port=3306,
                           mysql_server_name=None, mysql_ca_file=None, minio_url=None, minio_ca_file=None)
    observer = public.Inventory(args)
    inventory = observer.collect()
    inventory.pop("pending_sources", None)
    topology = field.metadata_extension(observer, public, inventory)
    mysql_selected = service_endpoint(inventory, "mysql")
    minio_selected = service_endpoint(inventory, "minio")
    if mysql_selected["status"] == "selected_from_actual_service_metadata":
        args.mysql_host, args.mysql_port = mysql_selected["cluster_ip"], mysql_selected["port"]
        args.mysql_server_name = mysql_selected["service"] + "." + NAMESPACE + ".svc"
    mysql = field.observe_or_missing(lambda: field.mysql_tls(args))
    minio_observations = {}
    if minio_selected["status"] == "selected_from_actual_service_metadata":
        host = minio_selected["cluster_ip"]
        host = "[" + host + "]" if ":" in host else host
        for scheme in ("http", "https"):
            # Explicitly try both public health transports. No scheme is
            # inferred from port or promoted to authenticated provider state.
            args.minio_url = scheme + "://" + host + ":" + str(minio_selected["port"])
            minio_observations[scheme] = field.observe_or_missing(lambda: field.minio_endpoint(args))
    observer.namespace()
    if observer.owner() != inventory["owner"]:
        raise ValueError("same_run_subject_changed")
    output_directory = tempfile.mkdtemp(prefix="system-backup-first-page-public-")
    full = {"schema_version": "system-backup-first-page-once-public.v1", "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "context": CONTEXT, "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID,
            "identity_trust": "current_whoami_same_run_observation_only_not_independent_installation_authorization",
            "inventory": inventory, "topology": topology, "mysql_service": mysql_selected, "mysql_tls": mysql,
            "minio_service": minio_selected, "minio_public_transport_observations": minio_observations,
            "independent_mysql_CA": "not_provided", "independent_minio_CA": "not_provided", "KEK_and_owner_exports": "not_provided",
            "secret_values_read": False, "SQL_or_container_exec_sent": False, "cluster_mutated": False,
            "source_authority_issued": False, "backup_readiness_proved": False, "page_task_created": False}
    receipt = public.write_public(output_directory, "first-page-once-public.json", full)
    deployments = [{"name": d["name"], "uid": d["uid"], "replicas": d.get("desired_replicas"),
                    "service_account": d.get("service_account"), "containers": [{"name": c["name"], "image": c["image"], "mounts": c["mounts"]} for c in d.get("containers", [])]}
                   for d in inventory["public_objects"].get("deployments", {}).get("items", [])]
    pods = [{"name": p["name"], "uid": p["uid"], "owners": p["owners"], "node": p.get("node"), "phase": p.get("phase"),
             "service_account": p.get("service_account"), "containers": p.get("container_statuses", [])}
            for p in inventory["public_objects"].get("pods", {}).get("items", [])]
    report = {"status": "PUBLIC_FIELD_OBSERVATIONS_ONLY_INSTALLATION_GAPS_REMAIN", "observed_at": full["observed_at"],
              "scope": {"context": CONTEXT, "namespace": NAMESPACE, "namespace_uid": NAMESPACE_UID},
              "identity_trust": full["identity_trust"], "observed_subject": inventory["owner"],
              "mysql_service": mysql_selected, "mysql_TLS_handshake_no_auth_no_SQL": mysql,
              "minio_service": minio_selected, "minio_public_HTTP_and_TLS_health_only": minio_observations,
              "deployments": deployments, "pods": pods, "storage_and_nodes": topology,
              "bound_PV_identity_and_backend": inventory["bound_persistentvolumes"],
              "public_collection_gaps": inventory["public_input_blockers"],
              "installation_gaps": ["independent_original_owner_plan_and_enrollment_authorization_not_derived_from_whoami",
                                    "production_mysql_independent_CA_SAN_auth_UUID_finite_grants_and_census",
                                    "MinIO_independent_CA_SPKI_exact_release_commit_six_principal_current_permission_and_bucket_state",
                                    "actual_original_KEK_provider_export_and_authenticated_owner_native_host_mappings",
                                    "complete_actual_owners_legal_enabling_and_unchanged_source_recovery_publication_readback"],
              "receipt": receipt, "source_authority_issued": False, "backup_readiness_proved": False,
              "secret_values_read": False, "SQL_or_container_exec_sent": False, "cluster_mutated": False}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({"status": "PUBLIC_COLLECTION_REFUSED", "scope": NAMESPACE,
                          "reason": "dependency_tool_or_selected_namespace_identity_unavailable",
                          "source_authority_issued": False, "cluster_mutated": False}))
        sys.exit(2)
