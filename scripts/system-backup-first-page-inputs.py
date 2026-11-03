#!/usr/bin/env python3
"""One bounded public field collection; no Secret read, exec, SQL or mutation."""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
SHA = re.compile(r"[a-f0-9]{64}")
HELPER_SHA256 = "dbd5f6af63a29318f2106a64b12c5bdf0cbe564af9b3cccd07e5e17fd967b3be"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path, limit):
    path = Path(path)
    before = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("regular_file_required")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("file_identity_changed")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > limit or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("file_changed")
    return raw


def certificate(tls):
    der = tls.getpeercert(binary_form=True)
    result = {"leaf_sha256": digest(der), "tls_version": tls.version(),
              "cipher": tls.cipher()[0], "chain_and_hostname_verified": tls.context.verify_mode == ssl.CERT_REQUIRED}
    verified = tls.getpeercert()
    if verified:
        result["verified_leaf_SAN"] = verified.get("subjectAltName", [])
        result["not_before"] = verified.get("notBefore")
        result["not_after"] = verified.get("notAfter")
    # Public certificate only; no raw server response or credential is printed.
    try:
        parsed = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
                                input=der, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
        if parsed.returncode == 0 and len(parsed.stdout) <= 16384:
            result["public_certificate"] = parsed.stdout.decode("utf-8", "strict").splitlines()
        else:
            result["san_decode"] = "unavailable"
    except (OSError, subprocess.SubprocessError, UnicodeError):
        result["san_decode"] = "unavailable"
    return result


def tls_context(ca_file):
    if ca_file:
        raw = regular_bytes(ca_file, 1 << 20)
        context = ssl.create_default_context(cadata=raw.decode("ascii"))
        ca = {"selected_ca_sha256": digest(raw), "ca_source": "operator_selected_public_file"}
    else:
        # Discovery only: absence of independent trust stays a hard missing item.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ca = {"ca_source": "not_provided", "chain_and_hostname_verified": False}
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context, ca


def read_exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise ValueError("short_mysql_handshake")
        result += part
    return result


def mysql_tls(args):
    if not args.mysql_host:
        return {"status": "not_selected", "authenticated_server_uuid_and_account": "not_checked"}
    context, ca = tls_context(args.mysql_ca_file)
    # MySQL protocol SSLRequest only. No username/password/auth packet or SQL.
    with socket.create_connection((args.mysql_host, args.mysql_port), timeout=7) as raw:
        raw.settimeout(7)
        header = read_exact(raw, 4)
        size = int.from_bytes(header[:3], "little")
        if header[3] != 0 or not 30 <= size <= 65536:
            raise ValueError("mysql_greeting_rejected")
        greeting = read_exact(raw, size)
        if greeting[0] != 10:
            raise ValueError("mysql_protocol_rejected")
        version_end = greeting.find(b"\0", 1)
        lower_at = version_end + 1 + 4 + 8 + 1
        if version_end < 2 or lower_at + 2 > len(greeting):
            raise ValueError("mysql_greeting_shape")
        capabilities = int.from_bytes(greeting[lower_at:lower_at + 2], "little")
        if not capabilities & 0x0800 or not capabilities & 0x0200:
            return {"status": "server_did_not_advertise_tls", **ca,
                    "authenticated_server_uuid_and_account": "not_checked"}
        upper_at = lower_at + 5
        if upper_at + 2 <= len(greeting):
            capabilities |= int.from_bytes(greeting[upper_at:upper_at + 2], "little") << 16
        flags = capabilities & (0x0200 | 0x0800 | 0x8000 | 0x20000 | 0x80000)
        payload = struct.pack("<IIB23s", flags, 16 << 20, 45, b"\0" * 23)
        raw.sendall(len(payload).to_bytes(3, "little") + b"\x01" + payload)
        with context.wrap_socket(raw, server_hostname=args.mysql_server_name or args.mysql_host) as tls:
            return {"status": "tls_handshake_only", "endpoint": args.mysql_host,
                    "port": args.mysql_port, "selected_server_name": args.mysql_server_name or args.mysql_host,
                    **ca, **certificate(tls), "authenticated_server_uuid_and_account": "not_checked",
                    "business_grants_and_schema_census": "not_checked", "sql_sent": False}


def minio_endpoint(args):
    if not args.minio_url:
        return {"status": "not_selected", "six_principal_permissions": "not_checked"}
    endpoint = urlsplit(args.minio_url)
    if endpoint.scheme not in ("http", "https") or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment:
        raise ValueError("selected_minio_origin_required")
    port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
    result = {"endpoint": args.minio_url, "selected_scheme": endpoint.scheme,
              "six_principal_permissions": "not_checked", "authenticated_release_and_commit": "not_checked"}
    if endpoint.scheme == "https":
        context, ca = tls_context(args.minio_ca_file)
        connection = http.client.HTTPSConnection(endpoint.hostname, port, timeout=7, context=context)
        connection.connect()
        result.update(ca)
        result.update(certificate(connection.sock))
    else:
        connection = http.client.HTTPConnection(endpoint.hostname, port, timeout=7)
        result.update({"tls": "not_configured_on_selected_http_origin", "chain_and_hostname_verified": False})
    try:
        connection.request("GET", "/minio/health/live", headers={"Connection": "close"})
        response = connection.getresponse()
        result["health_http_status"] = response.status
        response.read(1024)  # Discard body. Health is not a permission observation.
        result["status"] = "public_health_only"
    finally:
        connection.close()
    return result


def metadata_extension(observer, module, inventory):
    q, boolean = module.quoted, module.boolean
    node_fields = module.identity_fields()
    node_fields.update({"architecture": q(".status.nodeInfo.architecture"), "os": q(".status.nodeInfo.operatingSystem"),
                        "runtime": q(".status.nodeInfo.containerRuntimeVersion"), "unschedulable": boolean(".spec.unschedulable"),
                        "conditions": module.array_template(".status.conditions", module.object_template({"type": q(".type"), "status": q(".status")})),
                        "labels": '{ {{$first := true}}{{range $key,$value := .metadata.labels}}{{if not $first}},{{end}}{{$first = false}}{{printf "%q:%q" $key $value}}{{end}} }'})
    nodes = sorted({p["node"] for p in inventory["public_objects"].get("pods", {}).get("items", []) if p.get("node")})
    observed_nodes, failures = [], []
    for name in nodes:
        try:
            observed_nodes.append(json.loads(observer.command(["get", "node", name, "-o=go-template=" + module.object_template(node_fields)])))
        except module.Refused:
            failures.append("node_public_metadata:" + name)
    volumes = []
    for pv in inventory["bound_persistentvolumes"]:
        fields = module.identity_fields()
        requirement = module.object_template({"key": q(".key"), "operator": q(".operator"),
                                               "values": module.array_template(".values", '{{printf "%q" .}}')})
        term = module.object_template({"match_expressions": module.array_template(".matchExpressions", requirement),
                                       "match_fields": module.array_template(".matchFields", requirement)})
        fields.update({"node_affinity_required_terms": module.array_template(".spec.nodeAffinity.required.nodeSelectorTerms", term),
                       "access_modes": module.array_template(".spec.accessModes", '{{printf "%q" .}}'), "volume_mode": q(".spec.volumeMode"),
                       "storage_class": q(".spec.storageClassName"), "phase": q(".status.phase")})
        try:
            current = json.loads(observer.command(["get", "pv", pv["name"], "-o=go-template=" + module.object_template(fields)]))
            if current["uid"] != pv["uid"]:
                raise module.Refused("pv_replaced")
            volumes.append(current)
        except module.Refused:
            failures.append("pv_topology:" + pv["name"])
    return {"nodes": observed_nodes, "persistentvolume_topology": volumes, "missing": failures}


# Only known public outputs from the real KEK exporter are read. Never inspect
# or fingerprint provider credentials or either private issuer key.
KEK_FILES = ("installation-authority.record.json", "installation-authority.signature",
             "installation-authority.public-key", "generate.capability.json", "unwrap.capability.json", "original-source-pins.json")
OWNER_FILES = ("bootstrap-original.record.json", "bootstrap-original.signature", "bootstrap-original.sha256",
               "bootstrap-native-hosts.record.json", "bootstrap-native-hosts.signature", "bootstrap-native-hosts.sha256")


def exported_kek(directory):
    if not directory:
        return {"status": "not_provided", "files": [], "original_mapping_and_capabilities_verified": False}
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("original_export_directory_required")
    files, missing = [], []
    for name in KEK_FILES:
        try:
            raw = regular_bytes(root / name, 262144)
            files.append({"name": name, "sha256": digest(raw), "bytes": len(raw)})
        except (OSError, ValueError):
            missing.append(name)
    return {"status": "public_export_files_present" if not missing else "incomplete_public_export",
            "files": files, "missing": missing, "original_mapping_and_capabilities_verified": False,
            "note": "Presence/pins only. Original consumers must authenticate signatures, source authority, windows and current revocation."}


def exported_owners(directory):
    if not directory:
        return {"status": "not_provided", "files": [], "authenticated": False}
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("original_owner_export_directory_required")
    files, missing = [], []
    for name in OWNER_FILES:
        try:
            raw = regular_bytes(root / name, 262144)
            files.append({"name": name, "sha256": digest(raw), "bytes": len(raw)})
        except (OSError, ValueError):
            missing.append(name)
    return {"status": "public_mapping_files_present" if not missing else "incomplete_public_mapping",
            "files": files, "missing": missing, "authenticated": False}


def observe_or_missing(action):
    try:
        return action()
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException, subprocess.SubprocessError):
        return {"status": "unavailable_or_rejected", "details": "withheld; verify selected original endpoint/CA and connectivity"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--namespace-uid", required=True)
    parser.add_argument("--owner-subject", required=True)
    parser.add_argument("--owner-uid", default="")
    parser.add_argument("--owner-groups-sha256", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--mysql-host")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-server-name")
    parser.add_argument("--mysql-ca-file")
    parser.add_argument("--minio-url")
    parser.add_argument("--minio-ca-file")
    parser.add_argument("--kek-export-directory")
    parser.add_argument("--owner-mapping-directory")
    args = parser.parse_args()
    if not SHA.fullmatch(args.owner_groups_sha256) or not 1 <= args.mysql_port <= 65535:
        raise ValueError("selected_input_rejected")
    dependency = Path(__file__).with_name("system-backup-d-first-install-inputs.py")
    if digest(regular_bytes(dependency.absolute(), 262144)) != HELPER_SHA256:
        raise ValueError("public_projection_helper_pin_changed")
    spec = importlib.util.spec_from_file_location("public_first_install", dependency)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args.mode = "inventory"
    observer = module.Inventory(args)
    inventory = observer.collect()
    # The original helper's historical missing-owner count is not current
    # admission state. Keep its actual projections, use this report's gaps.
    inventory.pop("pending_sources", None)
    topology = metadata_extension(observer, module, inventory)
    mysql = observe_or_missing(lambda: mysql_tls(args))
    minio = observe_or_missing(lambda: minio_endpoint(args))
    kek = observe_or_missing(lambda: exported_kek(args.kek_export_directory))
    owners = observe_or_missing(lambda: exported_owners(args.owner_mapping_directory))
    # Re-pin the original namespace/subject after the endpoint observations.
    observer.namespace()
    if observer.owner() != inventory["owner"]:
        raise ValueError("owner_changed")
    missing = list(inventory["public_input_blockers"]) + topology["missing"]
    if not mysql.get("chain_and_hostname_verified"):
        missing.append("production_mysql_independent_CA_SAN_TLS13")
    missing.extend(["authenticated_production_mysql_server_UUID_finite_account_and_census",
                    "current_minio_six_principal_owner_native_permissions_release_commit_and_bucket_state",
                    "original_owner_mapping_and_native_host_mapping_authenticated_consumption",
                    "status_relay_original_current_source_owner", "authorized_config_enabling"])
    if minio.get("selected_scheme") != "https" or not minio.get("chain_and_hostname_verified"):
        missing.append("actual_minio_TLS_CA_SAN_or_explicit_original_endpoint_change_plan")
    if kek.get("status") != "public_export_files_present":
        missing.append("actual_original_KEK_export")
    missing.append("current_KEK_mapping_capabilities_and_revocation_authentication")
    if owners.get("status") != "public_mapping_files_present":
        missing.append("actual_original_owner_and_native_host_mapping_export")
    result = {"schema_version": "system-backup-first-page-field-inputs.v1", "status": "COLLECTED_WITH_EXPLICIT_INSTALLATION_GAPS",
              "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "inventory": inventory,
              "topology": topology, "mysql": mysql, "minio": minio, "kek_public_export": kek,
              "owner_mapping_public_export": owners,
              "required_minio_principals": ["artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append", "observer"],
              "installation_gaps": sorted(set(missing)), "secret_api_requested": False,
              "container_exec_or_env_values_read": False, "SQL_sent": False, "cluster_mutated": False,
              "source_authority_issued": False, "page_task_created": False, "performance_probe_run": False}
    receipt = module.write_public(args.output_directory, "first-page-field-inputs.json", result)
    print(json.dumps({"status": result["status"], **receipt, "installation_gaps": result["installation_gaps"]}))
    return 2 if missing else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # No command stderr, network body, file body or exception string escapes.
        print(json.dumps({"status": "COLLECTION_REFUSED", "reason": "original_public_field_selection_or_scope_unavailable",
                          "cluster_mutated": False, "page_task_created": False}))
        sys.exit(2)
