"""Finite original source DATA adapters; no authorization or native success.

The caller supplies the existing operator module (m), DeploymentStages, and
the r3 original_app_environment resolver. These helpers do not invoke binaries,
acquire a hold, write a complete SourceSelection, or issue any grant.
"""
import base64
from pathlib import Path
import re
from urllib.parse import urlsplit


def retain(m, path, raw):
    path = Path(path)
    m.need(not path.is_symlink(), "provider_output_symlink_refused")
    if path.exists():
        m.need(m.read(path) == raw, "original_provider_bytes_changed_no_replacement")
        return m.pin(path)
    return m.write(path, raw)


def https(m, endpoint):
    u = urlsplit(endpoint)
    m.need(u.scheme == "https" and u.hostname and u.port and not u.username and
           not u.password and not u.path and not u.query and not u.fragment,
           "original_provider_https_authority_required")
    return u


def minio_fragment(m, stages, tls_receipt_pin, environment):
    """Use original first-hop query/apply receipt, never prepare-only intent.

    Caller runs the original query immediately before this helper. Existing-TLS
    installations without that receipt need a real equivalent owner exporter;
    neither a caller bool nor an inferred CA is accepted as a substitute here.
    """
    tls = m.decode(m.pinned(tls_receipt_pin))
    m.need(tls.get("state") == "actual_tls_verified" and
           tls.get("permission_gate_or_adoption") is False,
           "actual_original_minio_tls_query_receipt_required")
    u = https(m, tls["endpoint"])
    m.need(tls["server_name"] == u.hostname and
           all(re.fullmatch(r"[a-f0-9]{64}", tls[k]) for k in
               ("ca_sha256", "spki_sha256", "leaf_sha256")),
           "original_minio_tls_identity_required")
    _, _, plan, _ = stages.common()
    target = plan["Target"]
    objects = tls["objects"]
    m.need(u.hostname == objects["service"]["name"] + "." + target["Namespace"] + ".svc",
           "same_original_minio_service_namespace_required")
    deployment = stages.get("deployment", objects["deployment"]["name"])
    pod = stages.get("pod", objects["pod"]["name"])
    service = stages.get("service", objects["service"]["name"])
    for kind, obj in (("deployment", deployment), ("pod", pod), ("service", service)):
        m.need(obj["metadata"]["uid"] == objects[kind]["uid"] and
               obj["metadata"]["namespace"] == target["Namespace"] and
               not obj["metadata"].get("deletionTimestamp"),
               "same_original_minio_tls_object_required")
    states = [s for s in pod["status"]["containerStatuses"] if s["name"] == tls["container"]]
    m.need(len(states) == 1 and states[0].get("ready") and "running" in states[0]["state"] and
           states[0]["containerID"] == tls["container_id"] and states[0]["imageID"] == tls["image_id"],
           "same_original_minio_tls_container_required")
    user = environment(m, stages, deployment, "MINIO_ROOT_USER")
    secret = environment(m, stages, deployment, "MINIO_ROOT_PASSWORD")
    m.need(0 < len(user) <= 1024 and 0 < len(secret) <= 4096 and
           not any(c in user or c in secret for c in (b"\x00", b"\r", b"\n")),
           "bounded_actual_original_minio_credential_required")
    ca = {"File": tls["ca_file"], "SHA256": tls["ca_sha256"]}
    ca_raw = m.pinned(ca)
    m.need(b"BEGIN CERTIFICATE" in ca_raw and b"PRIVATE KEY" not in ca_raw,
           "original_public_minio_ca_required")
    again = stages.get("deployment", deployment["metadata"]["name"])
    m.need(again["metadata"]["uid"] == deployment["metadata"]["uid"] and again["spec"] == deployment["spec"] and
           environment(m, stages, again, "MINIO_ROOT_USER") == user and
           environment(m, stages, again, "MINIO_ROOT_PASSWORD") == secret,
           "original_minio_credential_source_changed")
    root = stages.runtime_mirror()
    ca = retain(m, root / "initial-source-minio-ca.pem", ca_raw)
    credential = retain(m, root / "initial-source-minio-credential.private.json", m.encoded({
        "access_key": user.decode("utf-8"), "secret_key": base64.b64encode(secret).decode("ascii")}))
    connection = {"Purpose": "source_objects", "Endpoint": tls["endpoint"], "Account": user.decode("utf-8"),
                  "ServerUUID": "", "Database": "", "CA": ca, "Credential": credential,
                  "IdentitySHA256": "", "ScopeSHA256": ""}
    # This is a PARTIAL ordinary template; grants/issuer/finite object scope
    # must come from the existing real producers. It is not FormalSourceMount.
    template = {"CredentialFile": credential["File"], "CredentialSHA256": credential["SHA256"],
                "Objects": {"Address": u.netloc, "ServerName": u.hostname,
                            "CAFile": ca["File"], "CASHA256": ca["SHA256"]}}
    return {"Connection": connection, "MaterialsObjectsData": template,
            "OriginalTLSReceipt": tls_receipt_pin, "SPKISHA256": tls["spki_sha256"],
            "LeafSHA256": tls["leaf_sha256"]}


def vault_options_fragment(m, stages, state_pin, report_pin, ca_pin, init_pin):
    """Decode original owner files locally at runtime, for provider-materials.

    Root is extracted only to the original-owner-readonly pre-adoption path.
    It must never be mounted as evidence_write/KMS task credential. The existing
    Go owner repeats live Vault/Kube/SQL observation and authentication.
    """
    state, report = m.decode(m.pinned(state_pin)), m.decode(m.pinned(report_pin))
    _, _, plan, _ = stages.common()
    target = plan["Target"]
    m.need(state.get("schema_version") == "d-transit-owned-install.v1" and
           state.get("configured") is True and state.get("pending") is None and
           state.get("namespace") == target["Namespace"] and state.get("namespace_uid") == target["NamespaceUID"] and
           report.get("schema_version") == "d-transit-install-report.v1" and report.get("status") == "completed" and
           report.get("provider_cluster_id") == state["cluster_id"] and report.get("jwt_mount") == state["jwt_mount"] and
           report.get("namespace_uid") == target["NamespaceUID"] and
           report.get("ca_sha256") == ca_pin["SHA256"], "same_original_vault_owner_report_required")
    prefix = state["prefix"]
    endpoint = "https://" + prefix + "." + target["Namespace"] + ".svc:8200"
    https(m, endpoint)
    m.need(report["endpoint"] == endpoint and report["key_name"] == prefix + "-kek" and
           report["provider_version"] == "1" and report["data_pvc"] == prefix + "-data",
           "original_vault_installer_key_coordinates_required")
    for kind, resource, name in (("deployment", "deployments", prefix), ("service", "services", prefix),
                                 ("pvc", "persistentvolumeclaims", report["data_pvc"])):
        obj = stages.get(kind, name)
        m.need(obj["metadata"]["uid"] == state["resources"][resource + "/" + name] and
               obj["metadata"]["namespace"] == target["Namespace"] and
               not obj["metadata"].get("deletionTimestamp"), "same_original_vault_resource_required")
    ca_raw = m.pinned(ca_pin)
    m.need(b"BEGIN CERTIFICATE" in ca_raw and b"PRIVATE KEY" not in ca_raw, "original_public_vault_ca_required")
    original = m.decode(m.pinned(init_pin))
    token = original.get("root_token", "").encode("utf-8")
    m.need(0 < len(token) <= 16384 and not any(chr(c).isspace() for c in token),
           "original_vault_init_root_token_required_for_owner_only")
    root = stages.runtime_mirror()
    ca = retain(m, root / "initial-provider-vault-ca.pem", ca_raw)
    owner = retain(m, root / "initial-provider-vault-owner-token.private", token)
    return {"Deployment": prefix, "Service": prefix, "Claim": report["data_pvc"], "DataMountPath": "",
            "Endpoint": endpoint, "ClusterID": state["cluster_id"], "TransitMount": "transit",
            "KeyName": report["key_name"], "KeyVersion": report["provider_version"], "JWTMount": state["jwt_mount"],
            "CA": ca, "OwnerToken": owner}
