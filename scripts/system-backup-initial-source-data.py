"""Actual original source coordinates and API transport, never source proof."""
from pathlib import Path
import base64
import datetime
import json
import time
from urllib.parse import urlsplit


def retained_coordinate_readback(m, stages, stage, argv):
    intent_file = stages.directory / (stage + ".send-unknown.json")
    receipt_file = stages.directory / (stage + ".readback.json")
    m.need(intent_file.is_file() and receipt_file.is_file(), "original_coordinate_intent_and_readback_required_for_query")
    expected = {"stage": stage, "argv": [str(x) for x in argv], "input": None, "operation": stages.operation}
    m.need(m.decode(m.read(intent_file)) == expected, "original_coordinate_query_intent_changed")
    receipt = m.decode(m.read(receipt_file))
    stdout = receipt["stdout"]
    m.need(receipt.get("stage") == stage and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0 and
           stdout["File"] == str(stages.directory / (stage + ".stdout.private")), "original_coordinate_query_readback_changed")
    stages.op.pin_value({"File": str(stages.directory / (stage + ".stderr.private")), "SHA256": receipt["stderr_sha256"]})
    return m.decode(m.pinned(stdout, limit=64 << 20)), stdout


def coordinates(m, stages, query_only=False):
    common, _, plan, _ = stages.common()
    running_only = getattr(stages.a, "running_only_runtime_test", False)
    stage = "initial-source-coordinates"
    if query_only:
        m.need(running_only, "explicit_running_only_runtime_test_option_required")
        mirror = Path(m.RUNTIME)
        m.need(m.decode(m.read(mirror / "operator-owner.json")) == {"operation": stages.operation, "run": str(stages.run)},
               "existing_runtime_directory_not_this_operation")
    else:
        mirror = stages.runtime_mirror()
    directory = mirror / stage
    if not query_only:
        directory.mkdir(mode=0o700, exist_ok=True)
    options = ["--running-only-runtime-test", running_only] if running_only else []
    argv = [stages.binary("system-backup-first-install-materials"), "author-initial-source-coordinates", *common,
            "--output-directory", directory, *options]
    if query_only:
        native, receipt_pin = retained_coordinate_readback(m, stages, stage, argv)
        m.need(native["Coordinates"]["File"] == str(directory / "initial-source-coordinates.json") and
               native["KubernetesSnapshot"]["File"] == str(directory / "initial-source-kubernetes.private.json"),
               "original_coordinate_query_native_output_paths_changed")
    else:
        native, receipt_pin = stages.call(stage, argv)
    m.need(native["Version"] == "original-initial-source-data-authored.v1" and native["WriterQualified"] is False and native["BackupReady"] is False,
           "actual_original_authenticated_source_data_author_required")
    result = m.decode(m.pinned(native["Coordinates"], limit=8 << 20))
    m.pinned(native["KubernetesSnapshot"], limit=8 << 20)
    target = plan["Target"]
    m.need(result["Version"] == "original-initial-source-coordinates.v1" and
           result["InstallationID"] == target["InstallationID"] and result["Namespace"] == target["Namespace"] and
           result["NamespaceUID"] == target["NamespaceUID"] and len(result["Instances"]) == native["InstanceCount"],
           "same_complete_original_source_coordinates_required")
    scope = result.get("RuntimeTestScope")
    if running_only:
        m.need(scope is not None and scope["Version"] == "explicit-running-only-runtime-test-scope.v2" and
               scope["InstallationID"] == target["InstallationID"] and scope["ServerUUID"] == target["ServerUUID"] and
               scope["Database"] == target["Database"] and scope["NamespaceUID"] == target["NamespaceUID"] and
               scope["OriginalInstancesSHA256"] == m.digest(m.encoded(result["Instances"])),
               "actual_running_only_scope_from_same_original_SQL_snapshot_required")
        deferred = {row["ID"] for row in scope["Deferred"]}
        active_ids = ",".join(str(row["ID"]) for row in result["Instances"] if row["ID"] not in deferred)
        deferred_ids = ",".join(str(row["ID"]) for row in scope["Deferred"])
        m.need(running_only == active_ids + ":" + deferred_ids, "same_explicit_approved_runtime_test_roster_required")
    else:
        m.need(scope is None, "explicit_running_only_runtime_test_option_required")
    result_name = "initial-source-coordinates.result.json"
    retained = {"version": "operator-original-source-data.v1", "coordinates": native["Coordinates"],
        "kubernetes_snapshot": native["KubernetesSnapshot"], "native_receipt": receipt_pin, "writer_qualified": False, "backup_ready": False}
    if query_only:
        path = stages.directory / result_name
        if path.exists() or path.is_symlink():
            m.need(m.decode(m.read(path)) == retained, "original_coordinate_query_retained_result_changed")
    else:
        stages.retain(result_name, retained)
    return result, native["Coordinates"], receipt_pin


def retain_bytes(m, path, raw):
    if path.exists():
        m.need(m.read(path) == raw, "original_source_transport_changed_no_replacement")
        return m.pin(path)
    return m.write(path, raw)


def writer_source_inputs(m, stages, assembly):
    data, data_pin, receipt_pin = coordinates(m, stages)
    app = stages.get("deployment", "clawmanager-app")
    m.need(app["metadata"]["uid"] == stages.scope["app_deployment_uid"], "same_original_app_required_for_initial_source")
    # This must be the original effective app gate scope, not an invented
    # namespace/UID string that would select an empty participant registry.
    scope = assembly.original_app_environment(m, stages, app, "SYSTEM_BACKUP_SQL_GATE_SCOPE").decode("utf-8").strip()
    m.need(scope and scope in data.get("ApplicationScopes", []) and len(scope) <= 128, "actual_original_app_gate_scope_and_SQL_registry_required")
    existing = assembly.optional_pin(m, stages.a, "writer_source_config")
    if existing is not None:
        value = m.decode(m.pinned(existing))
        m.need(value["application_scope"] == scope and value.get("runtime_sources", {}).get("runtime_test_scope") == data.get("RuntimeTestScope"),
               "writer_source_config_must_use_actual_original_app_gate_and_runtime_scope")
        return existing
    token = assembly.original_app_environment(m, stages, app, "RUNTIME_AGENT_CONTROL_TOKEN")
    m.need(32 <= len(token) <= 8192 and not any(chr(v).isspace() for v in token), "actual_original_agent_token_required")
    workspace = assembly.original_app_environment(m, stages, app, "RUNTIME_WORKSPACE_ROOT").decode("utf-8")
    m.need(workspace.startswith("/") and workspace != "/" and str(Path(workspace)) == workspace, "actual_original_workspace_root_required")
    tls = m.decode(m.read(stages.directory / "runtime-agent-tls.result.json"))
    m.need(tls["version"] == "operator-shared-agent-tls.v1" and tls["operation"] == stages.operation, "same_original_agent_tls_receipt_required")
    material = m.decode(m.pinned(tls["materials_receipt"]))
    m.need(material["Version"] == "original-shared-agent-tls-materials.v1" and material["Namespace"] == data["Namespace"], "actual_original_agent_tls_material_required")
    m.pinned(material["CA"])
    after = stages.get("deployment", "clawmanager-app")
    m.need(after["metadata"]["uid"] == app["metadata"]["uid"] and after["spec"] == app["spec"] and
           assembly.original_app_environment(m, stages, after, "RUNTIME_AGENT_CONTROL_TOKEN") == token and
           assembly.original_app_environment(m, stages, after, "SYSTEM_BACKUP_SQL_GATE_SCOPE").decode().strip() == scope,
           "original_app_source_configuration_changed")
    credential = retain_bytes(m, stages.runtime_mirror() / "original-agent-control-token", token)
    config = {"installation_id": data["InstallationID"], "namespace": data["Namespace"], "namespace_uid": data["NamespaceUID"], "application_scope": scope,
        "runtime_sources": {"shared_runtime_protocol": "shared-container-freeze.v1", "workspace_root": workspace,
            "agent_token_file": credential["File"], "agent_ca_file": material["CA"]["File"], "agent_ca_sha256": material["CA"]["SHA256"],
            "current_stopped_pro_layouts": data.get("StoppedProLayouts", [])}}
    if data.get("RuntimeTestScope") is not None:
        config["runtime_sources"]["runtime_test_scope"] = data["RuntimeTestScope"]
    selected = stages.retain("initial-writer-source-config.v2.json", config)
    assembly.bind(m, stages.a, "writer_source_config", selected)
    stages.retain("initial-writer-source-config.v2.lineage.json", {"version": "operator-actual-writer-source-config.v2", "source_coordinates": data_pin,
        "native_source_receipt": receipt_pin, "config": selected, "source_qualified": False, "backup_ready": False})
    return selected


def source_token_pod(m, stages, data, account, host, phase):
    # Kubernetes requires TokenRequest's service account to match the bound Pod.
    # A dedicated source reader keeps the original limited sources role separate
    # from the controller. No token, Secret, PVC or host path enters this Pod.
    current = stages.get("pod", host["Pod"])
    m.need(current["metadata"]["uid"] == host["PodUID"] and current["spec"]["serviceAccountName"] == host["ServiceAccount"], "same_original_controller_for_source_reader_image_required")
    images = {x["image"] for x in current["spec"]["containers"]}
    m.need(len(images) == 1, "one_original_release_image_for_source_reader_required")
    image = images.pop()
    m.need("@sha256:" in image and len(image.rsplit("@sha256:", 1)[1]) == 64, "immutable_original_release_image_required")
    name = stages.prefix + "-sources-" + phase
    spec = {"serviceAccountName": account["metadata"]["name"], "automountServiceAccountToken": False,
        "restartPolicy": "Always", "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "source-token-anchor", "image": image,
            "command": ["/bin/sh", "-ec", "while :; do sleep 3600; done"],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}}}]}
    created = stages.create_object(phase + "-source-token-anchor", {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": data["Namespace"],
        "labels": {"app.kubernetes.io/name": name}, "annotations": {m.MARKER: stages.operation}}, "spec": spec})
    for _ in range(60):
        pod = stages.get("pod", name)
        m.need(pod["metadata"]["uid"] == created["metadata"]["uid"] and not pod["metadata"].get("deletionTimestamp") and
            pod["spec"]["serviceAccountName"] == account["metadata"]["name"] and pod["spec"].get("automountServiceAccountToken") is False and
            not pod["spec"].get("volumes") and not pod["spec"].get("initContainers") and not pod["spec"].get("ephemeralContainers") and
            len(pod["spec"]["containers"]) == 1 and pod["spec"]["containers"][0]["image"] == image and
            pod["spec"]["containers"][0]["command"] == spec["containers"][0]["command"], "actual_sources_SA_anchor_pod_changed")
        states = pod.get("status", {}).get("containerStatuses", [])
        if pod.get("status", {}).get("phase") == "Running" and len(states) == 1 and states[0].get("ready") and "running" in states[0].get("state", {}):
            return {"Name": name, "UID": pod["metadata"]["uid"], "Namespace": data["Namespace"], "ServiceAccount": account["metadata"]["name"], "ServiceAccountUID": account["metadata"]["uid"],
                "Image": image, "ContainerID": states[0]["containerID"], "ImageID": states[0]["imageID"]}
        time.sleep(2)
    m.need(False, "actual_sources_SA_anchor_pod_not_ready")


def source_api_inputs(m, stages, phase="initial"):
    m.need(phase in ("initial", "final"), "bounded_original_source_api_phase_required")
    data, data_pin, writer_receipt = coordinates(m, stages)
    observed = m.decode(m.read(stages.directory / "host-observer.result.json"))
    host = observed["host"] if phase == "initial" else m.decode(m.read(stages.directory / "materials.result.json"))["host"]
    stages.check_host(host)
    source_account = observed["accounts"]["sources"]
    account = stages.get("serviceaccount", source_account["Name"])
    m.need(account["metadata"]["uid"] == source_account["UID"], "same_original_sources_serviceaccount_required")
    namespace = m.decode(stages.op.k("get", "namespace", data["Namespace"], "-o", "json"))
    m.need(namespace["metadata"]["uid"] == data["NamespaceUID"], "same_original_source_namespace_required")
    definition = m.decode(m.pinned(observed["pki_definition"]))
    nodes = sorted({node["name"] for node in definition["nodes"]})
    pvs = sorted({volume["PVName"] for volume in data["Volumes"]})
    m.need(nodes and pvs and all(nodes) and all(pvs), "complete_original_node_and_volume_names_required")
    # These are read privileges for the namespace's complete source metadata.
    # Task mutation, provider access, signer grants and source writes are absent.
    rules = [
        {"apiGroups": [""], "resources": ["pods", "services", "serviceaccounts", "configmaps", "secrets", "persistentvolumeclaims", "endpoints"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["apps"], "resources": ["deployments", "replicasets", "statefulsets", "daemonsets"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["batch"], "resources": ["jobs", "cronjobs"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["networking.k8s.io"], "resources": ["ingresses", "networkpolicies"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles", "rolebindings"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get", "list", "watch"]},
    ]
    name = stages.prefix + "-sources-read"
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": name, "namespace": data["Namespace"]}, "rules": rules}
    actual_role = stages.create_object("initial-source-api-role", role)
    m.need(actual_role["rules"] == rules, "actual_original_source_read_role_rules_required")
    subjects = [{"kind": "ServiceAccount", "name": account["metadata"]["name"], "namespace": data["Namespace"]}]
    role_ref = {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}
    binding = stages.create_object("initial-source-api-rolebinding", {"apiVersion": role["apiVersion"], "kind": "RoleBinding", "metadata": {"name": name, "namespace": data["Namespace"]}, "subjects": subjects, "roleRef": role_ref})
    m.need(binding["subjects"] == subjects and binding["roleRef"] == role_ref, "actual_original_source_read_binding_required")
    cluster_rules = [
        {"apiGroups": [""], "resources": ["namespaces"], "resourceNames": [data["Namespace"]], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["nodes"], "resourceNames": nodes, "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["persistentvolumes"], "resourceNames": pvs, "verbs": ["get"]},
    ]
    cluster_role = stages.create_object("initial-source-api-clusterrole", {"apiVersion": role["apiVersion"], "kind": "ClusterRole", "metadata": {"name": name}, "rules": cluster_rules})
    m.need(cluster_role["rules"] == cluster_rules, "actual_finite_original_source_cluster_read_rules_required")
    cluster_ref = {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": name}
    cluster_binding = stages.create_object("initial-source-api-clusterbinding", {"apiVersion": role["apiVersion"], "kind": "ClusterRoleBinding", "metadata": {"name": name}, "subjects": subjects, "roleRef": cluster_ref})
    m.need(cluster_binding["subjects"] == subjects and cluster_binding["roleRef"] == cluster_ref, "actual_finite_original_source_cluster_binding_required")
    config = m.decode(stages.op.k("config", "view", "--minify", "--flatten", "--raw", "-o", "json"))
    m.need(len(config["clusters"]) == 1, "one_original_operator_cluster_required")
    cluster = config["clusters"][0]["cluster"]
    endpoint = cluster["server"]
    parsed = urlsplit(endpoint)
    m.need(parsed.scheme == "https" and parsed.hostname and not parsed.username and parsed.path in ("", "/") and not parsed.query and not parsed.fragment and
           not cluster.get("insecure-skip-tls-verify", False) and cluster.get("tls-server-name", parsed.hostname) == parsed.hostname and
           not cluster.get("proxy-url"), "actual_original_verified_kubernetes_endpoint_required")
    endpoint = endpoint.rstrip("/")
    ca = base64.b64decode(cluster["certificate-authority-data"], validate=True)
    m.need(0 < len(ca) <= 65536 and b"BEGIN CERTIFICATE" in ca and b"PRIVATE KEY" not in ca, "actual_original_apiserver_ca_required")
    root = stages.runtime_mirror()
    ca_pin = retain_bytes(m, root / "original-source-api-ca.pem", ca)
    command = ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", stages.op.kube, "--request-timeout=30s", "-n", data["Namespace"]]
    token_pod = source_token_pod(m, stages, data, account, host, phase)
    token_stage = phase + "-source-api-bound-token-" + m.digest(token_pod["UID"].encode())[:16]
    _, token_pin = stages.call(token_stage, [*command, "create", "token", account["metadata"]["name"], "--duration=86400s",
        "--bound-object-kind=Pod", "--bound-object-name=" + token_pod["Name"], "--bound-object-uid=" + token_pod["UID"]], json_output=False)
    token = m.pinned(token_pin).strip()
    m.need(32 <= len(token) <= 16384 and not any(chr(v).isspace() for v in token), "actual_original_source_api_token_required")
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token.decode("ascii")}}
    review, review_pin = stages.call(phase + "-source-api-token-review-" + m.digest(token_pod["UID"].encode())[:16], [*command, "create", "--raw=/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-"], m.encoded(body))
    status = review["status"]
    m.need(status.get("authenticated") is True and not status.get("error") and status["user"]["username"] == "system:serviceaccount:" + data["Namespace"] + ":" + account["metadata"]["name"] and
           status["user"]["uid"] == account["metadata"]["uid"], "actual_original_source_api_token_review_required")
    extra = status["user"].get("extra", {})
    m.need(extra.get("authentication.kubernetes.io/pod-uid") == [token_pod["UID"]] and extra.get("authentication.kubernetes.io/pod-name") == [token_pod["Name"]], "actual_original_source_api_token_pod_binding_required")
    claims = json.loads(base64.urlsafe_b64decode(token.split(b".")[1] + b"=" * (-len(token.split(b".")[1]) % 4)))
    m.need(isinstance(claims["exp"], int) and claims["exp"] > int(datetime.datetime.now(datetime.timezone.utc).timestamp()), "original_source_api_token_expired")
    jwt = retain_bytes(m, root / (phase + "-source-api-" + m.digest(token_pod["UID"].encode())[:16] + ".jwt"), token)
    stages.check_host(host)
    m.need(stages.get("serviceaccount", account["metadata"]["name"])["metadata"]["uid"] == account["metadata"]["uid"], "original_source_api_account_replaced")
    connection = {"Purpose": "source_api", "Endpoint": endpoint, "Account": account["metadata"]["uid"], "ServerUUID": "", "Database": "",
        "CA": ca_pin, "Credential": jwt, "IdentitySHA256": "", "ScopeSHA256": ""}
    scope = {"Namespace": data["Namespace"], "NamespaceUID": data["NamespaceUID"], "ServiceAccount": account["metadata"]["name"], "ServiceAccountUID": account["metadata"]["uid"],
        "RoleUID": actual_role["metadata"]["uid"], "RoleBindingUID": binding["metadata"]["uid"], "ClusterRoleUID": cluster_role["metadata"]["uid"],
        "ClusterBindingUID": cluster_binding["metadata"]["uid"], "Rules": rules, "ClusterRules": cluster_rules}
    return stages.retain(phase + "-source-api-inputs.result.json", {"version": "operator-original-source-api-inputs.v1", "phase": phase, "host": host, "token_pod": token_pod, "scope": scope, "connection": connection,
        "original_source_coordinates": data_pin, "original_writer_receipt": writer_receipt, "token_review": review_pin,
        "token_expires_unix": claims["exp"], "native_source_qualified": False, "backup_ready": False})


def source_api_successor(m, stages):
    destination = stages.directory / "materials.source-api-successor.result.json"
    parent_pin = m.pin(stages.directory / "materials.result.json")
    parent = m.decode(m.pinned(parent_pin))
    m.need(parent["version"] == "operator-materials-result.v1" and parent["final_source_facts_produced"] is False, "original_materials_before_source_facts_required")
    stages.check_host(parent["host"])
    if destination.exists():
        result = m.decode(m.read(destination))
        m.need(result["source_api_successor"]["ParentMaterials"] == parent_pin and result["host"] == parent["host"], "same_original_source_api_successor_required")
        m.pinned(result["SourceSelection"])
        m.pinned(result["source_api_successor"]["NativeReceipt"])
        return result
    m.need(not (stages.directory / "initial-forward.result.json").exists() and not (stages.run / "final-rollout-binding.json").exists(),
           "final_source_api_successor_must_precede_original_grants_and_facts")
    selected = m.decode(m.pinned(parent["SourceSelection"]))
    for field in ("PartsFile", "SourceWritersFile", "RedisSourcesFile"):
        m.need(not selected.get(field) or not Path(selected[field]).exists(), "source_api_successor_before_create_only_source_facts_required")
    initial = m.decode(m.read(stages.directory / "initial-source-api-inputs.result.json"))
    final_pin = source_api_inputs(m, stages, phase="final")
    final = m.decode(m.pinned(final_pin))
    m.need(final["scope"] == initial["scope"], "same_original_source_api_scope_no_privilege_change_required")
    previous = selected["Connections"][1]
    connection = final["connection"]
    m.need(previous["Purpose"] == connection["Purpose"] == "source_api" and previous["Endpoint"] == connection["Endpoint"] and
           previous["Account"] == connection["Account"] and previous["CA"] == connection["CA"], "same_original_source_api_transport_owner_required")
    until = datetime.datetime.fromtimestamp(final["token_expires_unix"], datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    inputs = stages.retain("final-source-api-successor.inputs.json", {"Version": "original-source-api-successor-inputs.v1", "SourceSelection": parent["SourceSelection"],
        "Connection": connection, "TokenNotAfter": until})
    directory = stages.runtime_mirror() / "final-source-api-successor"
    directory.mkdir(mode=0o700, exist_ok=True)
    common, _, _, _ = stages.common()
    native, native_pin = stages.call("final-source-api-successor", [stages.binary("system-backup-first-install-materials"), "refresh-initial-source-api", *common,
        "--definition-file", inputs["File"], "--definition-sha256", inputs["SHA256"], "--output-directory", directory])
    m.need(native["Version"] == "original-source-api-successor-authored.v1" and native["ParentSelection"] == parent["SourceSelection"] and native["Deployment"] == parent["Deployment"] and
           native["NativeSourceQualified"] is False and native["GrantsIssued"] is False and native["BackupReady"] is False, "actual_original_source_api_successor_author_required")
    m.pinned(native["SourceSelection"])
    m.pinned(native["MaterialsTemplate"])
    stages.check_host(parent["host"])
    delivered = stages.deliver_runtime_tree(parent["host"])
    result = {**parent, "SourceSelection": native["SourceSelection"], "delivered_file_pins": delivered,
        "source_api_successor": {"ParentMaterials": parent_pin, "ParentSelection": parent["SourceSelection"], "FinalSourceAPI": final_pin,
            "NativeReceipt": native_pin, "MaterialsTemplate": native["MaterialsTemplate"], "SameOriginalScope": True}, "backup_ready": False}
    stages.retain(destination.name, result)
    return result
