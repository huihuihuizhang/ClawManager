"""Earliest typed provider topology and functional profile DATA, before grants.

No permission definition, target credential, ConfigSHA256 or signature is an
input or output. No imports perform IO. No native success is manufactured.
"""
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class FilePin:
    File: str
    SHA256: str


@dataclass(frozen=True)
class ObjectIdentity:
    Kind: str
    Name: str
    UID: str


@dataclass(frozen=True)
class MinIOProviderTopology:
    Version: str
    InstallationID: str
    Namespace: str
    NamespaceUID: str
    Endpoint: str
    ServerName: str
    CA: FilePin
    SPKISHA256: str
    LeafSHA256: str
    OriginalTLSReceipt: FilePin
    Objects: list
    Container: str
    ContainerID: str
    ImageID: str
    Storage: list


def object_identity(m, obj, kind, expected_name=None, expected_uid=None):
    meta = obj["metadata"]
    m.need(meta.get("name") and meta.get("uid") and not meta.get("deletionTimestamp") and
           (expected_name is None or meta["name"] == expected_name) and
           (expected_uid is None or meta["uid"] == expected_uid), "same_original_topology_object_required")
    return asdict(ObjectIdentity(kind, meta["name"], meta["uid"]))


def controller(m, obj, kind):
    refs = [r for r in obj["metadata"].get("ownerReferences", []) if r.get("controller")]
    m.need(len(refs) == 1 and refs[0]["kind"] == kind, "original_topology_controller_required")
    return refs[0]


def snapshot(m, stages, actual, target):
    refs = actual["objects"]
    objects, live = [], {}
    for resource, key, kind in (("deployment", "deployment", "Deployment"), ("replicaset", "replicaset", "ReplicaSet"),
        ("pod", "pod", "Pod"), ("service", "service", "Service"), ("serviceaccount", "service_account", "ServiceAccount"),
        ("node", "node", "Node")):
        expected = refs[key]
        obj = stages.get(resource, expected["name"])
        objects.append(object_identity(m, obj, kind, expected["name"], expected["uid"]))
        if kind != "Node":
            m.need(obj["metadata"].get("namespace") == target["Namespace"], "same_original_topology_namespace_required")
        live[key] = obj
    dep, rs, pod = live["deployment"], live["replicaset"], live["pod"]
    parent, grandparent = controller(m, pod, "ReplicaSet"), controller(m, rs, "Deployment")
    m.need(parent["uid"] == rs["metadata"]["uid"] and grandparent["uid"] == dep["metadata"]["uid"] and
           pod["spec"]["nodeName"] == live["node"]["metadata"]["name"] and
           pod["spec"].get("serviceAccountName", "default") == live["service_account"]["metadata"]["name"] and
           len(pod["spec"]["containers"]) == 1 and len(dep["spec"]["template"]["spec"]["containers"]) == 1,
           "actual_original_topology_owner_chain_required")
    c = pod["spec"]["containers"][0]
    current = [s for s in pod["status"].get("containerStatuses", []) if s["name"] == actual["container"]]
    m.need(c["name"] == actual["container"] and len(current) == 1 and current[0].get("ready") and
           "running" in current[0].get("state", {}) and current[0]["containerID"] == actual["container_id"] and
           current[0]["imageID"] == actual["image_id"], "same_original_topology_cri_required")
    selector = live["service"]["spec"].get("selector", {})
    m.need(selector and all(pod["metadata"].get("labels", {}).get(k) == v for k, v in selector.items()),
           "actual_original_topology_service_selector_required")
    volumes = {v["name"]: v for v in pod["spec"].get("volumes", [])}
    storage = []
    for mount in c.get("volumeMounts", []):
        volume = volumes.get(mount["name"], {})
        if "persistentVolumeClaim" in volume:
            claim = stages.get("pvc", volume["persistentVolumeClaim"]["claimName"])
            pvc_ref = object_identity(m, claim, "PersistentVolumeClaim")
            m.need(claim["metadata"]["namespace"] == target["Namespace"] and claim.get("status", {}).get("phase") == "Bound" and
                   claim["spec"].get("volumeName"), "actual_original_target_bound_claim_required")
            pv = m.decode(stages.op.k("get", "pv", claim["spec"]["volumeName"], "-o", "json"))
            pv_ref = object_identity(m, pv, "PersistentVolume")
            bound = pv["spec"].get("claimRef", {})
            m.need(bound.get("uid") == claim["metadata"]["uid"] and bound.get("namespace") == target["Namespace"] and
                   bound.get("name") == claim["metadata"]["name"], "actual_original_target_pv_claim_binding_required")
            storage.append({"Kind": "pvc", "Volume": mount["name"], "MountPath": mount["mountPath"],
                "SubPath": mount.get("subPath", ""), "ReadOnly": mount.get("readOnly", False), "Claim": pvc_ref, "PV": pv_ref})
        elif "hostPath" in volume:
            path = volume["hostPath"]["path"]
            m.need(path.startswith("/") and path != "/" and ".." not in Path(path).parts,
                   "actual_original_target_hostpath_required")
            storage.append({"Kind": "hostpath", "Volume": mount["name"], "MountPath": mount["mountPath"],
                "SubPath": mount.get("subPath", ""), "ReadOnly": mount.get("readOnly", False),
                "Path": path, "Node": objects[-1]})
    m.need(storage and any(not s["ReadOnly"] for s in storage), "actual_original_persistent_minio_target_required")
    return objects, sorted(storage, key=lambda x: (x["Volume"], x["MountPath"]))


def author_topology(m, stages, finalized_tls_pin):
    _, _, plan, _ = stages.common()
    target = plan["Target"]
    final = m.decode(m.pinned(finalized_tls_pin))
    receipt = final["TLS"]
    actual = m.decode(m.pinned(receipt))
    m.need(actual.get("state") == "actual_tls_verified" and actual.get("permission_gate_or_adoption") is False,
           "actual_original_finalized_minio_tls_receipt_required")
    u = urlsplit(actual["endpoint"])
    m.need(u.scheme == "https" and u.hostname and u.port == 9000 and not u.username and not u.password and
           not u.path and not u.query and not u.fragment and u.hostname == actual["server_name"] and
           u.hostname == actual["objects"]["service"]["name"] + "." + target["Namespace"] + ".svc" and
           all(re.fullmatch(r"[a-f0-9]{64}", actual[k]) for k in ("ca_sha256", "spki_sha256", "leaf_sha256")),
           "actual_original_topology_https_ca_spki_required")
    ca = FilePin(actual["ca_file"], actual["ca_sha256"])
    ca_raw = m.pinned(asdict(ca))
    m.need(b"BEGIN CERTIFICATE" in ca_raw and b"PRIVATE KEY" not in ca_raw, "original_topology_public_ca_bytes_required")
    ns = m.decode(stages.op.k("get", "namespace", target["Namespace"], "-o", "json"))
    object_identity(m, ns, "Namespace", target["Namespace"], target["NamespaceUID"])
    first = snapshot(m, stages, actual, target)
    last = snapshot(m, stages, actual, target)
    m.need(first == last, "original_provider_topology_changed_during_authoring")
    data = MinIOProviderTopology("original-minio-provider-topology-data.v1", target["InstallationID"], target["Namespace"],
        target["NamespaceUID"], actual["endpoint"], actual["server_name"], ca, actual["spki_sha256"], actual["leaf_sha256"],
        FilePin(receipt["File"], receipt["SHA256"]), first[0], actual["container"], actual["container_id"], actual["image_id"], first[1])
    # m.retain is RFC8785 DATA; no Grant/ConfigSHA256/principal placeholders.
    return stages.retain("initial-provider-topology.data.json", asdict(data))


def author_profile(m, stages, lifecycle, finalized_tls_pin):
    topology_pin = author_topology(m, stages, finalized_tls_pin)
    topology = m.decode(m.pinned(topology_pin))
    _, _, plan, _ = stages.common()
    target = plan["Target"]
    final = m.decode(m.pinned(finalized_tls_pin))
    m.need(lifecycle.current_app_roster(m, stages) == final["CurrentAppRoster"],
           "profile_requires_actual_post_tls_app_roster")
    cluster = m.decode(stages.op.k("get", "namespace", "kube-system", "-o", "json"))
    object_identity(m, cluster, "Namespace", "kube-system")
    nodes = m.decode(stages.op.k("get", "nodes", "-o", "json"))["items"]
    m.need(nodes and all(n["metadata"].get("uid") for n in nodes), "actual_profile_nodes_required")
    kinds = {"k3s" if "k3s" in n["status"]["nodeInfo"]["kubeletVersion"] else "kubernetes" for n in nodes}
    m.need(len(kinds) == 1, "one_actual_profile_orchestrator_required")
    domain = "cluster:" + cluster["metadata"]["uid"]
    m.need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", domain), "actual_profile_domain_required")
    identity = stages.retain("initial-functional-domain-identity.json", {"KubernetesAPI": plan["KubernetesAPI"],
        "KubernetesCASHA256": plan["KubernetesCASHA256"], "KubeSystemUID": cluster["metadata"]["uid"]})
    failure = stages.retain("initial-functional-failure-domains.json", {"schema_version": "system-backup-original-failure-domains.v1",
        "origin_installation_id": target["InstallationID"], "registry_version": "initial-functional-domains-v1", "history": [{
        "sequence": 1, "domain_id": domain, "identity_sha256": identity["SHA256"], "state": "active", "previous_sha256": ""}]})
    risks = sorted(["attestation_missing", "same_failure_domain", "source_overlap", "artifact_credential_source_dependent",
                    "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent"])
    ref = "isolated-policy-" + m.digest(target["InstallationID"].encode())[:24]
    # This is actual, newly written deployment configuration, not observed
    # restore evidence. No target is created and no source privilege is used.
    policy = stages.retain("initial-functional-restore-target-policy.json", {
        "schema_version": "original-functional-restore-target-policy.v1", "installation_id": target["InstallationID"],
        "reference": ref, "source_namespace": target["Namespace"], "source_namespace_uid": target["NamespaceUID"],
        "source_database": target["Database"], "source_database_server_uuid": target["ServerUUID"],
        "target_namespace_prefix": "cm-drill-", "target_database_prefix": "cm_drill_", "target_kind": "isolated_drill",
        "admin_policy": "replace_bootstrap_with_source_admin", "start_policy": "stopped_tasks_disabled",
        "source_namespace_reuse": "forbidden", "source_database_reuse": "forbidden", "source_volume_reuse": "forbidden",
        "required_observation_schema": "system-backup-b-restore-target.v1", "owned_target_topology": topology_pin,
        "failure_domain_identity": identity})
    profile_data = {"installation_id": target["InstallationID"], "revision": "initial-functional-v1",
        "source_orchestrator": next(iter(kinds)), "source_profile": "cluster", "target_class": "same-cluster-copy",
        "target_risks": risks, "target_failure_domain_id": domain, "restore_target_ref": ref, "restore_target_sha256": policy["SHA256"]}
    # Go ExecutionProfile.CanonicalIdentity uses this struct field order.
    raw = json.dumps(profile_data, ensure_ascii=False, separators=(",", ":")).encode()
    path = stages.directory / "initial-execution-profile.json"
    if path.exists():
        m.need(m.read(path) == raw, "profile_bytes_changed_requires_new_original_operation")
        profile = m.pin(path)
    else:
        profile = m.write(path, raw)
    m.need(lifecycle.current_app_roster(m, stages) == final["CurrentAppRoster"], "post_tls_app_changed_during_profile_authoring")
    return stages.retain("initial-functional-profile-data.result.json", {"ExecutionProfile": profile,
        "RestoreTargetPolicy": policy, "FailureDomains": failure, "DomainIdentity": identity,
        "ProviderTopology": topology_pin, "ActualTLSFinalization": finalized_tls_pin,
        "ClassificationData": {"SchemaVersion": "system-backup-original-functional-classification.v1", "Profile": "functional-backup.non-dr.v1",
        "TaskPurpose": "functional_test", "TargetClass": "same-cluster-copy", "TargetFailureDomain": domain,
        "RecoveryEvidenceStatus": "not_provided", "SourceDomains": [domain], "TargetRisks": risks,
        "FailureRegistryFile": failure["File"], "FailureRegistrySHA256": failure["SHA256"]}})
