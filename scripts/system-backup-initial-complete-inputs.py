"""Original initial provider lifecycle and complete operational source DATA.

No imports perform IO. Native owners authenticate and reread all selected DATA.
Unknown release schemas, source images and physical layouts remain refusals.
"""
import base64
import datetime
import importlib.util
from pathlib import Path, PurePosixPath
import re


def sealed(m, stages, name):
    relative = "scripts/" + name
    expected = stages.op.pins["files"].get(relative)
    m.need(expected is not None, "sealed_original_initial_tool_required:" + name)
    path = stages.root / relative
    m.read(path, expected, private=False)
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def provider_action(m, stages, assembly, action):
    providers = sealed(m, stages, "system-backup-initial-provider-fragments.py")
    lifecycle = sealed(m, stages, "system-backup-initial-provider-lifecycle.py")
    tls = lifecycle.OriginalTLSLifecycle(m, stages)
    plans_path = stages.directory / "initial-provider-tls.plans.json"
    if action == "prepare":
        m.need(not (stages.run / "original-writer-selection").exists(), "initial_provider_TLS_must_precede_original_writer_census")
        return tls.prepare()
    plans = m.pin(plans_path)
    if action == "apply":
        m.need(not (stages.run / "original-writer-selection").exists(), "do_not_roll_TLS_after_original_writer_census")
        return tls.apply(plans)
    if action == "query":
        prefix = "initial-provider-query-fresh-"
        count = sum(1 for _ in stages.directory.glob(prefix + "*.result.json"))
        value = tls.query(plans, "-fresh-" + str(count))
        return stages.retain(prefix + str(count) + ".result.json", value)
    m.need(action == "finalize", "original_provider_lifecycle_action_required")
    return tls.finalize(plans, providers, assembly.original_app_environment)


def vault(m, stages, providers, lifecycle, writer):
    root = stages.a.deployment_vault_state_directory or stages.a.deployment_vault_owner_material_file.parent
    report = m.pin(root / "public-report.json")
    report_data = m.decode(m.pinned(report))
    ca = m.pin(root / "ca.pem")
    m.need(ca["SHA256"] == report_data["ca_sha256"], "actual_original_vault_CA_required")
    options = lifecycle.vault_prepare(m, stages, providers, m.pin(root / "state.json"), report, ca, m.pin(stages.a.deployment_vault_owner_material_file))
    # Each stage authenticates the original same pre-provider base selection.
    # Only the final native output supplies the dependency-bearing successor.
    for phase in ("apply", "query", "finalize"):
        selected = lifecycle.vault_observe(m, stages, options, writer, phase)
    result = m.decode(m.pinned(selected))
    m.pinned(result["WriterSelection"]); m.pinned(result["InstalledObserver"])
    return result


def relay_pki(m, stages, host, until):
    # Reuse the ONE actual original PKI owner/selector. Do not issue a second
    # CA/key set in the source author and then sign Core for a different relay.
    selected = stages.op.prepare_relay_runtime_trust()
    result = stages.op.c1_authors_module().actual_pki(stages.op)
    m.need(selected["PKI"]["Manifest"] == result["Manifest"] and
           selected["PKI"]["Signature"] == result["Signature"] and
           result["DeploymentUID"] == host["DeploymentUID"], "same_original_relay_owner_before_core_required")
    stages.check_host(host)
    return result


def env_names(m, stages, app):
    container = app["spec"]["template"]["spec"]["containers"][0]
    names = {e["name"] for e in container.get("env", [])}
    for source in container.get("envFrom", []):
        key = "secretRef" if "secretRef" in source else "configMapRef"
        m.need(key in source and not source[key].get("optional", False), "required_original_environment_source")
        obj = stages.get("secret" if key == "secretRef" else "configmap", source[key]["name"])
        names.update(source.get("prefix", "") + k for k in obj.get("data", {}))
    return names


def effective_app_config(m, stages):
    lifecycle = sealed(m, stages, "system-backup-initial-provider-lifecycle.py")
    before = lifecycle.current_app_roster(m, stages)
    m.need(before["DeploymentUID"] == stages.scope["app_deployment_uid"] and before["Actors"], "actual_original_app_roster_required_for_config_DATA")
    prefix = "initial-effective-app-config-read-"
    counter = sum(1 for _ in stages.directory.glob(prefix + "*.send-unknown.json"))
    outputs, reads = [], []
    for index, actor in enumerate(before["Actors"]):
        for repeat in (0, 1):
            _, pin = stages.call(prefix + str(counter) + "-" + str(index) + "-" + str(repeat),
                ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", stages.op.kube, "--request-timeout=30s", "-n", m.NS,
                    "exec", actor["Pod"], "-c", actor["Container"], "--", "/usr/local/bin/clawreef-server", "--system-backup-source-config-data"], json_output=False)
            raw = m.pinned(pin).splitlines()
            m.need(raw and all(line.startswith(b"Loading k8s config from: ") for line in raw[:-1]), "original_app_config_DATA_output_protocol_required")
            data = m.decode(raw[-1])
            m.need(data["Version"] == "original-application-config-coordinates.v1" and data["RuntimeQualified"] is False and data["BackupReady"] is False,
                "actual_original_app_config_DATA_mode_required")
            outputs.append(data); reads.append(pin)
    m.need(all(value == outputs[0] for value in outputs) and lifecycle.current_app_roster(m, stages) == before, "actual_original_app_config_or_roster_changed")
    value = {"version": "operator-original-effective-app-config.v1", "data": outputs[0], "app_roster": before, "native_reads": reads, "runtime_qualified": False, "backup_ready": False}
    path = stages.directory / "initial-effective-app-config.result.json"
    if path.exists():
        previous = m.decode(m.read(path))
        m.need(previous["data"] == value["data"] and previous["app_roster"] == before, "original_effective_app_config_changed_no_replacement")
        stages.retain(prefix + str(counter) + ".recheck.json", value)
        return previous
    stages.retain(path.name, value)
    return value



def object_scope(m, stages, assembly, app):
    names = env_names(m, stages, app)
    # These are the production config.go defaults only when its original env
    # key is absent. A file-based config has its own source owner; never guess.
    container = app["spec"]["template"]["spec"]["containers"][0]
    m.need(not any(x in (container.get("args", []) + container.get("command", [])) for x in ("--config", "-config")), "original_file_config_object_scope_producer_required")
    effective = effective_app_config(m, stages)["data"]
    values = {"OBJECT_STORAGE_BUCKET": effective["ObjectBucket"], "OBJECT_STORAGE_BASE_PATH": effective["ObjectPrefix"]}
    for name in values:
        m.need(values[name] != "", "original_effective_object_scope_nonempty_required:" + name)
        if name in names:
            environment = assembly.original_app_environment(m, stages, app, name).decode()
            m.need(environment == values[name], "original_config_LOAD_environment_scope_mismatch:" + name)
    bucket, prefix = values["OBJECT_STORAGE_BUCKET"], values["OBJECT_STORAGE_BASE_PATH"].strip("/")
    m.need(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) and prefix and PurePosixPath(prefix).as_posix() == prefix and ".." not in PurePosixPath(prefix).parts, "actual_finite_original_object_scope_required")
    return bucket, prefix


def inline_nfs_workspace(m, stages, coordinates, root, subpath, source, worker_node):
    """Populate the EXISTING signed Core; no source proof or storage mutation."""
    def get(kind, name, namespace=None):
        args = (["-n", namespace] if namespace else []) + ["get", kind, name, "-o", "json"]
        return m.decode(stages.op.k(*args))
    services = m.decode(stages.op.k("get", "services", "-A", "-o", "json"))["items"]
    selected = [s for s in services if s["spec"].get("clusterIP") == source["server"]]
    m.need(len(selected) == 1, "original_inline_NFS_Service_must_be_unique")
    service = selected[0]
    ns, name = service["metadata"]["namespace"], service["metadata"]["name"]
    namespace = get("namespace", ns)
    endpoints = get("endpoints", name, ns)
    addresses = [a for s in endpoints.get("subsets", []) for a in s.get("addresses", [])]
    m.need(not any(s.get("notReadyAddresses") for s in endpoints.get("subsets", [])) and len(addresses) == 1,
           "one_actual_inline_NFS_backend_required")
    ref = addresses[0].get("targetRef", {})
    m.need(ref.get("kind") == "Pod" and ref.get("namespace") == ns and ref.get("uid"), "actual_inline_NFS_endpoint_Pod_UID_required")
    pod = get("pod", ref["name"], ns)
    m.need(pod["metadata"]["uid"] == ref["uid"] and pod["status"].get("podIP") == addresses[0]["ip"] and
           not pod["metadata"].get("deletionTimestamp") and service["spec"].get("selector") and
           all(pod["metadata"].get("labels", {}).get(k) == v for k,v in service["spec"]["selector"].items()),
           "original_inline_NFS_Service_backend_changed")
    candidates = [(v, mount) for v in pod["spec"].get("volumes", []) if "persistentVolumeClaim" in v
                  for c in pod["spec"]["containers"] for mount in c.get("volumeMounts", []) if mount["name"] == v["name"]]
    m.need(len(candidates) == 1 and not candidates[0][1].get("subPath") and not candidates[0][1].get("subPathExpr"),
           "one_actual_provider_PVC_mount_locator_required_no_export_proof_created")
    volume, export_mount = candidates[0]
    claim = get("pvc", volume["persistentVolumeClaim"]["claimName"], ns)
    pv = get("pv", claim["spec"]["volumeName"])
    m.need(claim["status"]["phase"] == "Bound" and pv["spec"]["claimRef"]["uid"] == claim["metadata"]["uid"] and
           pv["spec"]["claimRef"]["namespace"] == ns and pv["spec"]["claimRef"]["name"] == claim["metadata"]["name"],
           "original_inline_NFS_provider_PVC_PV_UID_binding_required")
    node = get("node", pod["spec"]["nodeName"])
    scope = coordinates.get("RuntimeTestScope")
    deferred = {r["ID"] for r in scope["Deferred"]} if scope is not None else set()
    paths = []
    for row in coordinates["Instances"]:
        if row["ID"] in deferred:
            continue
        data_path = row["Workspace"]
        m.need(row["ID"] > 0 and row["UserID"] > 0 and row["Generation"] > 0 and data_path.startswith(root + "/") and
               str(PurePosixPath(data_path)) == data_path and ".." not in PurePosixPath(data_path).parts,
               "original_SQL_instance_workspace_path_required_for_inline_NFS")
        relative = "/".join(v for v in (subpath, data_path[len(root)+1:]) if v)
        m.need(relative and not relative.startswith("/") and ".." not in PurePosixPath(relative).parts,
               "whole_shared_NFS_root_is_not_an_instance_source")
        paths.append({"InstanceID": row["ID"], "UserID": row["UserID"], "Generation": row["Generation"], "SubPath": relative})
    paths.sort(key=lambda v: v["InstanceID"])
    m.need(paths and len({v["InstanceID"] for v in paths}) == len(paths), "complete_original_SQL_NFS_path_set_required")
    provider = {"Namespace": ns, "NamespaceUID": namespace["metadata"]["uid"], "Service": name, "ServiceUID": service["metadata"]["uid"],
                "EndpointsUID": endpoints["metadata"]["uid"], "Pod": pod["metadata"]["name"], "PodUID": pod["metadata"]["uid"],
                "Claim": claim["metadata"]["name"], "ClaimUID": claim["metadata"]["uid"], "PV": pv["metadata"]["name"], "PVUID": pv["metadata"]["uid"],
                "PVSpec": pv["spec"], "Node": node["metadata"]["name"], "NodeUID": node["metadata"]["uid"], "ExportMountPath": export_mount["mountPath"]}
    stages.retain("initial-original-inline-NFS-selection.json", {"version": "original-inline-NFS-input-selection.v1", "provider": provider,
                  "original_paths": paths, "physical_export_mapping_proven": False, "writers_fenced": False, "backup_ready": False})
    # Only staging is a consumer-namespace PVC. Never replace the actual source
    # with an unused same-name claim, copy files or stop the shared provider.
    return {"claim": "", "nfs": {"server": source["server"], "export": source["path"], "original_paths": paths, "provider": provider},
            "sub_path": subpath, "node": worker_node, "max_files": 1000000, "max_file_bytes": 1 << 30,
            "max_archive_bytes": 8 << 30, "max_compressed_bytes": 8 << 30}


def workspace(m, stages, assembly, app, host, coordinates):
    root = assembly.original_app_environment(m, stages, app, "RUNTIME_WORKSPACE_ROOT").decode()
    container = app["spec"]["template"]["spec"]["containers"][0]
    mounts = [x for x in container.get("volumeMounts", []) if root == x["mountPath"] or root.startswith(x["mountPath"] + "/")]
    m.need(len(mounts) == 1 and not mounts[0].get("subPathExpr"), "one_actual_original_workspace_mount_required")
    mount = mounts[0]
    volumes = [v for v in app["spec"]["template"]["spec"]["volumes"] if v["name"] == mount["name"]]
    m.need(len(volumes) == 1 and sum(k in volumes[0] for k in ("persistentVolumeClaim", "nfs", "hostPath")) == 1,
           "one_actual_original_workspace_volume_source_required")
    selector = app["spec"]["selector"]
    m.need(selector.get("matchLabels") and not selector.get("matchExpressions"), "finite_original_app_selector_required")
    pods = m.decode(stages.op.k("-n", coordinates["Namespace"], "get", "pods", "-l", ",".join(k+"="+v for k,v in sorted(selector["matchLabels"].items())), "-o", "json"))["items"]
    pods = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    m.need(len(pods) == 1 and pods[0]["spec"]["nodeName"] in coordinates["NodeUIDs"], "actual_original_app_workspace_node_required")
    suffix = root[len(mount["mountPath"]):].lstrip("/")
    subpath = "/".join(x for x in (mount.get("subPath", ""), suffix) if x)
    m.need(not subpath or not subpath.startswith("/") and ".." not in PurePosixPath(subpath).parts, "finite_original_workspace_subpath_required")
    if "nfs" in volumes[0]:
        # Worker placement is the original signed staging node; the actual
        # runtime Pod may be elsewhere when reading a shared NFS source.
        host_pod = stages.get("pod", host["Pod"])
        m.need(host_pod["metadata"]["uid"] == host["PodUID"], "same_original_staging_controller_Pod_UID_required")
        worker_node = host_pod["spec"]["nodeName"]
        m.need(worker_node in coordinates["NodeUIDs"], "original_staging_node_UID_required")
        return root, inline_nfs_workspace(m, stages, coordinates, root, subpath, volumes[0]["nfs"], worker_node), None
    m.need("persistentVolumeClaim" in volumes[0], "unsupported_original_workspace_source_requires_actual_adapter")
    claim_name = volumes[0]["persistentVolumeClaim"]["claimName"]
    actual = stages.get("pvc", claim_name)
    pins = [v for v in coordinates["Volumes"] if v["ClaimName"] == claim_name and v["ClaimUID"] == actual["metadata"]["uid"]]
    m.need(len(pins) == 1 and actual["status"]["phase"] == "Bound", "same_original_workspace_PVC_identity_required")
    return root, {"claim": claim_name, "sub_path": subpath, "node": pods[0]["spec"]["nodeName"],
        "max_files": 1000000, "max_file_bytes": 1 << 30, "max_archive_bytes": 8 << 30, "max_compressed_bytes": 8 << 30}, pins[0]


def actor(m, stages, part):
    name = stages.prefix + "-" + {"deployment_resources": "resources", "secret_bundle": "secrets"}[part]
    value = stages.create_object("initial-source-actor-" + part, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": m.NS}, "automountServiceAccountToken": False})
    m.need(value["metadata"]["uid"] and value.get("automountServiceAccountToken") is False, "actual_original_source_actor_required")
    return {"Name": name, "UID": value["metadata"]["uid"]}


def source_core(m, stages, assembly, data, writer, profile, relay, public):
    common, _, plan, sql = stages.common()
    target = plan["Target"]
    host_result = m.decode(m.read(stages.directory / "host-observer.result.json")); host = host_result["host"]
    stages.check_host(host)
    app = stages.get("deployment", "clawmanager-app")
    m.need(app["metadata"]["uid"] == stages.scope["app_deployment_uid"], "same_original_app_required")
    workspace_root, work, workspace_pin = workspace(m, stages, assembly, app, host, data)
    stage_claim = stages.get("pvc", stages.prefix + "-staging")
    staging_pins = [v for v in data["Volumes"] if v["ClaimName"] == stage_claim["metadata"]["name"] and v["ClaimUID"] == host_result["pvc_uids"]["staging"]]
    m.need(len(staging_pins) == 1, "actual_staging_volume_pin_required")
    worker = host_result["accounts"]["worker"]
    images = m.decode(m.read(stages.directory / "new-image.result.json"))["images"]
    source = stages.op.sql_role_inputs()["roles"]["source"]
    mirror = stages.runtime_mirror(); directory = mirror / "initial-source-inputs"
    # Numeric values here are finite configured caps, never source measurements.
    def volume_pin(pin, name):
        return {"Volume": name, "Kind": "PersistentVolumeClaim", "Name": pin["ClaimName"], "UID": pin["ClaimUID"], "PVName": pin["PVName"], "PVUID": pin["PVUID"], "SHA256": pin["PVSpecSHA256"]}
    observers = {"CAFile": writer["ObserverCA"]["File"], "CASHA256": writer["ObserverCA"]["SHA256"], "CertificateFile": writer["ObserverCertificate"]["File"], "CertificateSHA256": writer["ObserverCertificate"]["SHA256"], "KeyFile": writer["ObserverKey"]["File"], "KeySHA256": writer["ObserverKey"]["SHA256"]}
    source_dsn = host_result["runtime_input_pins"]["mysql-source.dsn"]
    m.need(source_dsn["SHA256"] == source["dsn"]["SHA256"], "same_original_readonly_source_dsn_required")
    runtime = {"shared_runtime_protocol": writer["SharedRuntimeProtocol"], "shared_runtime_observer": {**observers, "Endpoints": writer["SharedRuntimeEndpoints"], "WholeNodeEndpoints": writer["WholePodEndpoints"], "Nodes": data.get("SharedNodes", [])},
        "stopped_pro_observer": {**observers, "Endpoints": writer["StoppedProEndpoints"], "NodeUIDs": {k: data["NodeUIDs"][k] for k in writer["StoppedProEndpoints"]}},
        "current_stopped_pro_layouts": [{k:r[k] for k in ("InstanceID", "ControllerName", "Mounts")} for r in data.get("StoppedProLayouts", [])], "supported": [], "namespaces": [target["Namespace"]],
        "agent_token_file": writer["AgentCredential"]["File"], "agent_ca_file": writer["AgentCA"]["File"], "agent_ca_sha256": writer["AgentCA"]["SHA256"], "gateway_originals": [],
        "lease_participants": [p["ID"] for p in writer["Participants"]], "deployments": [{"namespace": target["Namespace"], "name": d["Name"], "uid": d["UID"]} for d in writer["Deployments"] if d["Role"] == "agent"], "workspace_root": workspace_root}
    seen = set()
    scope = data.get("RuntimeTestScope")
    if scope is not None:
        runtime["runtime_test_scope"] = scope
    deferred_ids = {row["ID"] for row in scope["Deferred"]} if scope is not None else set()
    for source_row in data["Instances"]:
        if source_row["ID"] in deferred_ids:
            continue
        key = tuple(source_row[k] for k in ("Type", "Mode", "Variant", "OS"))
        if key not in seen:
            seen.add(key); runtime["supported"].append(dict(zip(("Type", "Mode", "Variant", "OS"), key)))
    m.need(runtime["lease_participants"] and runtime["shared_runtime_observer"]["Nodes"], "actual_original_participants_and_shared_native_paths_required")
    config = {"schema_version": "system-backup-public-deployment.v1", "capture_scope": "six-part", "installation_id": target["InstallationID"], "controller_owner": host["DeploymentUID"],
        "application_scope": writer["ApplicationScope"], "namespace": target["Namespace"], "namespace_uid": target["NamespaceUID"], "trust_domain": "clawmanager.invalid",
        "forward_grant": {"path": str(directory / "forward.grant.json"), "public_key_base64": public}, "recovery_grant": {"path": str(directory / "recovery.grant.json"), "public_key_base64": public},
        "key_directory": str(mirror / "execution-keys"), "profile_file": str(directory / "execution-profile.json"), "capacity_file": str(mirror / "registration-capacity.current.json"),
        "source_dsn_file": source_dsn["File"], "source_user": source["username"], "source_database": target["Database"], "source_server_uuid": target["ServerUUID"], "source_tls": sql["source_tls"],
        "staging_directory": m.STAGING, "seal_custody_max_bytes": 1 << 30, "staging_claim": stage_claim["metadata"]["name"], "worker_image": images["worker"]["reference"],
        "worker_security": {"node_uids": data["NodeUIDs"], "volumes": ([volume_pin(workspace_pin, "workspace")] if workspace_pin is not None else []) + [volume_pin(staging_pins[0], "staging")], "ServiceAccountName": worker["Name"], "ServiceAccountUID": worker["UID"]},
        "control_url": host_result["control_service"]["SelectedURL"], "listen": ":9443", "server_certificate": relay["ServerCertificate"]["File"], "server_key": relay["ServerKey"]["File"],
        "issuer_certificate": relay["CA"]["File"], "issuer_certificate_sha256": relay["CA"]["SHA256"], "issuer_key": relay["IssuerKey"]["File"],
        "platform_writers": [{"namespace": target["Namespace"], "name": d["Name"], "uid": d["UID"]} for d in writer["Deployments"] if d["Role"] == "writer"], "workspace": work,
        "acquire_seconds": int(writer["Policy"]["AcquisitionTimeout"] / 1000000000), "hold_seconds": int(writer["Policy"]["MaxHold"] / 1000000000), "runtime_sources": runtime, "formal_verifier": {"protocol": "controller-verifier-materials.v1", "path": str(directory / "formal-verifier.json")},
        "capture_modules": {"protocol": "original-six-part-capture-materials.v1", "path": str(directory / "capture-materials.json")}, "redis_read_keepers": writer.get("RedisReadKeepers", [])}
    # Consume actual R30 enrolled trust in the NEW value, before any source
    # author writes/hashes the Core and before Forward1 is ever issued.
    trust = stages.op.prepare_relay_runtime_trust()
    m.need(trust["PKI"]["Manifest"] == relay["Manifest"], "original_core_relay_PKI_selection_changed")
    fields = trust["CoreFields"]
    config.update({"original_relay_enrollment": fields["original_relay_enrollment"],
                   "control_url": fields["control_url"], **fields["tls"],
                   "issuer_certificate_sha256": trust["PKI"]["CA"]["SHA256"]})
    return config, directory, host, app

def runtime_policies(m, stages, data):
    images = m.decode(m.read(stages.directory / "runtime-images.result.json"))["images"]
    policies, references, seen = [], {}, set()
    storage = {r["InstanceID"]: r for r in data["Storage"]}
    scope = data.get("RuntimeTestScope")
    deferred_ids = {row["ID"] for row in scope["Deferred"]} if scope is not None else set()
    for source in data["Instances"]:
        if source["ID"] in deferred_ids:
            continue
        kind = source["Type"]
        m.need(kind in ("openclaw", "hermes") and source["OS"] == "linux", "original_release_runtime_schema_producer_required:" + str(source["ID"]))
        image = images[kind]["reference"]
        if source["Mode"] == "pro":
            # A Pro source does not inherit the shared Agent image by brand.
            # Retain its actual current Pod/controller immutable source image.
            layouts = [x for x in data["Layouts"] if x["Source"]["ID"] == source["ID"]]
            m.need(len(layouts) == 1, "one_actual_Pro_source_layout_required")
            layout = layouts[0]
            if layout["CurrentPod"]:
                pod = stages.get("pod", layout["CurrentPod"])
                m.need(pod["metadata"]["uid"] == layout["CurrentPodUID"] and pod["metadata"]["namespace"] == layout["CurrentNamespace"], "same_actual_Pro_source_Pod_required")
                containers = pod["spec"]["containers"]
            else:
                stopped = [x for x in data.get("StoppedProLayouts", []) if x["InstanceID"] == source["ID"]]
                m.need(len(stopped) == 1 and stopped[0]["ControllerName"], "actual_stopped_Pro_immutable_image_owner_required")
                deployment = stages.get("deployment", stopped[0]["ControllerName"])
                pin = [x for x in data["Census"]["Deployments"] if x["Name"] == deployment["metadata"]["name"]]
                m.need(len(pin) == 1 and pin[0]["UID"] == deployment["metadata"]["uid"] and deployment["spec"].get("replicas", 1) == 0, "same_actual_current_stopped_Pro_controller_required")
                containers = deployment["spec"]["template"]["spec"]["containers"]
            m.need(len(containers) == 1 and re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", containers[0]["image"]), "actual_Pro_image_manifest_producer_required_no_shared_image_substitution")
            image = containers[0]["image"]
        # The actual original owner deliberately selects the already published,
        # immutable and startup-authenticated release. Native readers must still
        # match this explicit SQL descriptor and actual loaded source image.
        descriptor = storage[source["ID"]]["RuntimeImageReference"]
        if descriptor in references:
            m.need(references[descriptor] == image, "ambiguous_original_runtime_image_reference")
        references[descriptor] = image
        runtime = {k.lower(): source[k] for k in ("Type", "Mode", "Backend", "Variant", "OS")}
        identity = (kind, source["Mode"], source["Backend"], source["Variant"], source["OS"], image)
        if identity in seen:
            continue
        seen.add(identity)
        prefix = "home/" if source["Mode"] == "lite" else ""
        fields = []
        def rules(action, *paths):
            fields.extend({"Path": p.split("."), "Action": action, "Required": False} for p in paths)
        if kind == "openclaw":
            filename, fmt = prefix + ".openclaw/openclaw.json", "json"
            rules("preserve", "meta.lastTouchedVersion", "meta.lastTouchedAt", "wizard.lastRunAt", "wizard.lastRunVersion", "wizard.lastRunCommand", "wizard.lastRunMode",
                "agents.defaults.model.primary", "agents.defaults.model.fallbacks.*", "agents.defaults.models.*.alias", "agents.defaults.workspace", "agents.defaults.compaction.mode",
                "agents.defaults.maxConcurrent", "agents.defaults.subagents.maxConcurrent", "agents.defaults.subagents.model", "agents.defaults.timeoutSeconds", "agents.defaults.contextTokens",
                "agents.list.*.id", "agents.list.*.name", "agents.list.*.workspace", "agents.list.*.model", "auth.profiles.*.provider", "auth.profiles.*.mode",
                "models.mode", "models.providers.*.api", "models.providers.*.models.*.id", "models.providers.*.models.*.name", "models.providers.*.models.*.reasoning",
                "models.providers.*.models.*.input.*", "models.providers.*.models.*.contextWindow", "models.providers.*.models.*.maxTokens", "models.providers.*.models.*.cost.input",
                "models.providers.*.models.*.cost.output", "models.providers.*.models.*.cost.cacheRead", "models.providers.*.models.*.cost.cacheWrite",
                "gateway.port", "gateway.mode", "gateway.bind", "gateway.auth.mode", "gateway.controlUi.allowedOrigins.*", "messages.ackReactionScope", "commands.native", "commands.nativeSkills",
                "commands.restart", "session.dmScope", "skills.install.nodeManager", "plugins.allow.*", "browser.defaultProfile", "browser.executablePath")
            rules("stub", "auth.profiles.*.token", "auth.profiles.*.key", "auth.profiles.*.apiKey", "models.providers.*.apiKey", "models.providers.*.baseUrl", "gateway.auth.token", "gateway.auth.password",
                "skills.entries.*.apiKey", "skills.entries.*.env.*")
            rules("disable", "gateway.controlUi.enabled", "gateway.controlUi.allowInsecureAuth", "gateway.controlUi.dangerouslyDisableDeviceAuth", "hooks.enabled", "hooks.internal.enabled",
                "hooks.internal.entries.*.enabled", "skills.entries.*.enabled", "plugins.entries.*.enabled", "browser.enabled", "cron.enabled")
            for channel in ("telegram", "discord", "slack", "feishu", "wecom", "dingtalk", "qq", "whatsapp", "signal", "imessage", "matrix", "msteams", "webchat"):
                rules("disable", "channels." + channel + ".enabled")
                for key in ("token", "botToken", "appToken", "appSecret", "clientSecret", "secret", "webhookUrl", "baseUrl"):
                    rules("stub", "channels." + channel + "." + key)
                for key in ("dmPolicy", "groupPolicy", "streamMode", "streaming", "allowFrom.*", "groups.*.requireMention", "groups.*.enabled"):
                    rules("preserve", "channels." + channel + "." + key)
        else:
            filename, fmt = prefix + ".hermes/config.yaml", "yaml"
            rules("preserve", "model", "provider", "max_turns", "reasoning_effort", "max_tokens", "temperature", "context_length", "default_model", "default_provider",
                "agent.max_turns", "agent.max_tokens", "agent.reasoning_effort", "agent.temperature", "terminal.backend", "terminal.timeout", "terminal.working_dir",
                "display.show_reasoning", "display.tool_progress", "display.show_cost", "compression.enabled", "compression.threshold", "memory.memory_enabled", "memory.user_profile_enabled",
                "memory.memory_char_limit", "memory.user_profile_char_limit", "session.idle_timeout", "session.max_age", "skills_path", "toolsets.*")
            rules("stub", "api_key", "base_url", "model.api_key", "model.base_url", "gateway.token", "gateway.password", "telegram.bot_token", "discord.bot_token", "slack.bot_token")
            rules("disable", "gateway.enabled", "telegram.enabled", "discord.enabled", "slack.enabled", "cron.enabled", "auto_update.enabled")
        policies.append({"Version": "original-" + kind + "-finite-schema.v1", "Image": image, "Runtime": runtime,
            "Files": [{"path": filename, "format": fmt, "required": True, "fields": fields}]})
    # No rule automatically preserves an unknown field. Native normalization
    # rejects added/ambiguous leaves and missing actual required files.
    return policies, references


def team_writer_images(m, stages, app, namespace):
    """Expectations come from the retained native release, never current drift."""
    result_pin = m.pin(stages.directory / "new-image.result.json")
    result = m.decode(m.pinned(result_pin))
    images_pin = m.pin(stages.directory / "images.actual.json")
    images = m.decode(m.pinned(images_pin))
    plan = m.decode(m.pinned(result["plan"]))
    m.need(result["version"] == "operator-new-image-result.v1" and
        result["state"] == "actual_full_business_mysql_tls_template_and_same_release_rollout_verified" and
        result["images"] == images == plan["images"], "original_business_release_receipts_required")
    m.need(app["metadata"]["name"] == result["app"]["Name"] and app["metadata"]["namespace"] == namespace and
        app["metadata"]["uid"] == result["app"]["UID"] == plan["original_uid"] and
        m.digest(m.encoded(app["spec"])) == result["app"]["SpecSHA256"] and
        app["spec"]["template"] == plan["desired_spec"]["template"], "original_business_release_template_required")
    pod = plan["desired_spec"]["template"]["spec"]
    # The current native release producer attests one app container. Future
    # sidecars need their own native release receipt; the Go consumer supports
    # distinct images/builds per ordinary/init container without worker reuse.
    m.need(len(pod["containers"]) == 1 and not pod.get("initContainers") and not pod.get("ephemeralContainers"),
        "each_business_container_needs_original_release_receipt")
    image = images["app"]; container = pod["containers"][0]
    m.need(re.fullmatch(r"[0-9a-f]{64}", image["manifest_sha256"]) and
        re.fullmatch(r"sha256:[0-9a-f]{64}", image["config_digest"]) and
        re.fullmatch(r"[0-9a-f]{40}", image["commit"]) and
        image["reference"].endswith("@sha256:" + image["manifest_sha256"]) and
        container["image"] == image["reference"] and container["name"], "original_business_immutable_image_required")
    observed = result["business_pods"]
    m.need(0 < len(observed) <= 16 and len({p["PodUID"] for p in observed}) == len(observed) and
        all(p["PodUID"] and p["ReplicaSetUID"] and p["ContainerID"] and
            m.image_id(p["ImageID"]) in ("sha256:" + image["manifest_sha256"], image["config_digest"]) for p in observed),
        "original_business_pod_release_readback_required")
    # Pin reads again before returning; no network/mutation or new signer here.
    m.pinned(result_pin); m.pinned(images_pin); m.pinned(result["plan"])
    return {"deployment/" + namespace + "/" + app["metadata"]["name"]: [{
        "Container": container["name"], "Image": image["reference"],
        "ConfigDigest": image["config_digest"], "BuildCommit": image["commit"]}]}


def material_template(m, stages, assembly, core, directory, host, app, data, redis, minio, source_api, source_public, sql_operation):
    policies, image_references = runtime_policies(m, stages, data)
    bucket, prefix = object_scope(m, stages, assembly, app)
    objects = {"GrantFile": str(directory / "objects-source.grant.json"), "GrantSHA256": "", "Issuer": source_public,
        **minio["MaterialsObjectsData"], "ObjectPrefixes": [{"Bucket": bucket, "Prefix": prefix + "/"}]}
    redis_mount = dict(redis["source_mount"]); redis_mount["GrantFile"] = str(directory / "redis-source.grant.json")
    api = source_api["connection"]
    actors = {part: actor(m, stages, part) for part in ("deployment_resources", "secret_bundle")}
    m.need(len({x["UID"] for x in actors.values()} | {api["Account"]}) == 3, "independent_actual_original_source_actors_required")
    team_units = ["team.pending_deletions", "team.event_projection", "team.maintenance_sweep", "northbound.operation", "northbound.lifecycle_action", "team.workspace_http"]
    discovery = {"GrantFile": str(directory / "source-metadata.grant.json"), "GrantSHA256": "", "Issuer": source_public,
        "ControllerDeployment": host["Deployment"], "ControllerDeploymentUID": host["DeploymentUID"], "ControllerServiceAccount": host["ServiceAccount"], "ControllerServiceAccountUID": host["ServiceAccountUID"],
        "SourceAPI": {"Server": api["Endpoint"], "CAFile": api["CA"]["File"], "CASHA256": api["CA"]["SHA256"], "TokenFile": api["Credential"]["File"]},
        "SourceAPITokenSHA256": api["Credential"]["SHA256"], "SourceAPIServiceAccount": source_api["scope"]["ServiceAccount"], "SourceAPIServiceAccountUID": api["Account"],
        "Redis": redis["capture_policy"], "RuntimePolicies": policies, "RuntimeImageReferences": image_references, "ResourceActors": actors,
        "TeamPlatformUnits": {"deployment/" + data["Namespace"] + "/" + app["metadata"]["name"]: team_units},
        "TeamWriterImages": team_writer_images(m, stages, app, data["Namespace"])}
    operations = {}
    names = ("capture-database", "capture-workspace", "capture-source-redis", "capture-team-objects", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle")
    for name in names:
        request = {"version": "users-instances-worker.v1alpha1", "operation": name, "artifact_name": name + ".encrypted", "max_archive_bytes": 32 << 20, "max_compressed_bytes": 32 << 20}
        if name == "capture-workspace":
            request.update({"max_files": core["workspace"]["max_files"], "max_file_bytes": core["workspace"]["max_file_bytes"],
                "max_archive_bytes": core["workspace"]["max_archive_bytes"], "max_compressed_bytes": core["workspace"]["max_compressed_bytes"]})
        if name == "capture-database":
            tls = core["source_tls"]
            request["database"] = {"source_scope": "reviewed-business-tables.v1", "schema_census": sql_operation["Census"], "address": sql_operation["Address"], "name": core["source_database"],
                "server_uuid": core["source_server_uuid"], "tls_server_name": tls["server_name"], "root_ca": base64.b64encode(m.read(tls["ca_file"], tls["ca_sha256"])).decode(), "max_rows": 100000, "max_memory_bytes": 32 << 20}
        # These are finite pre-grant templates. Native installation mapping
        # issuance supplies provider/permit/mount bindings later; no signed
        # ConfigSHA256, task identity, observed source or fake grant is inserted.
        operations[name] = {"Request": request, "Formal": {"schema_version": "public-c-stream-job.v1alpha1", "envelope_name": name + ".envelope", "max_frames": 65536},
            "Workload": {"Identity": {"Namespace": data["Namespace"]}, "Image": core["worker_image"], "ServiceAccount": core["worker_security"]["ServiceAccountName"],
                "Source": ({"name": "source", "nfs": {"server": core["workspace"]["nfs"]["server"], "path": core["workspace"]["nfs"]["export"], "readOnly": True}}
                           if core["workspace"].get("nfs") else {"name": "source", "persistentVolumeClaim": {"claimName": core["workspace"]["claim"], "readOnly": True}}), "SourceSubPath": core["workspace"]["sub_path"],
                "StagingClaim": core["staging_claim"], "NodeName": core["workspace"]["node"], "DeadlineSeconds": 300,
                "WorkerControl": {"URL": core["control_url"], "BoundPodIdentity": True}}}
    resources = [{"Part": "deployment_resources", "Group": group, "Version": version, "Resource": resource, "LabelSelector": ""}
        for group, version, resource in (("apps", "v1", "deployments"), ("apps", "v1", "replicasets"), ("", "v1", "pods"), ("", "v1", "services"), ("", "v1", "configmaps"), ("", "v1", "persistentvolumeclaims"),
            ("rbac.authorization.k8s.io", "v1", "roles"), ("rbac.authorization.k8s.io", "v1", "rolebindings"), ("", "v1", "serviceaccounts"), ("networking.k8s.io", "v1", "networkpolicies"))]
    resources.append({"Part": "secret_bundle", "Group": "", "Version": "v1", "Resource": "secrets", "LabelSelector": ""})
    return {"Version": "original-six-part-capture-materials.v1", "Revision": "original-first-source.v1", "InstallationID": core["installation_id"], "ControllerOwner": core["controller_owner"],
        "DeploymentConfigSHA256": "", "CaptureGrantSHA256": "", "Operations": operations, "Redis": redis_mount, "Objects": objects, "SkillBucket": bucket, "SkillPrefix": prefix,
        "UserMetadataAllowlist": [], "MaxObjects": 10000, "MaxObjectBytes": 16 << 20, "MaxObjectTotalBytes": 64 << 20, "ResourceTypes": resources, "Discovery": discovery}


def original_runtime_test_scope(m, stages, data, data_pin, query_only=False):
    """Consume ONLY R34's actual authenticated native issue/query receipt.

    Local DATA does not grant a scoped task. The existing signed core plus
    source-writers registry/config/request must commit it before runtime use.
    """
    common, _, plan, _ = stages.common()
    target = plan["Target"]
    directory = stages.runtime_mirror() / "runtime-test-scope"
    directory.mkdir(mode=0o700, exist_ok=True)
    base = [stages.binary("system-backup-c1-native-inputs"), "runtime-test-scope", *common, "--output-directory", directory]
    issued = None
    issue = "initial-runtime-test-scope"
    sent = stages.directory / (issue + ".send-unknown.json")
    completed = stages.directory / (issue + ".readback.json")
    if not query_only and (not sent.exists() or completed.exists()):
        issued, _ = stages.call(issue, [*base, "--mode", "issue"])
    # Even a cached issue is followed by a NEW authenticated query. An unknown
    # issue is never replayed: query requires the original exact on-disk file.
    prefix = "initial-runtime-test-scope-query-"
    sequence = sum(1 for _ in stages.directory.glob(prefix + "*.send-unknown.json"))
    observed, observed_pin = stages.call(prefix + str(sequence), [*base, "--mode", "query"])
    m.need(observed["Version"] == "original-runtime-test-scope-result.v1" and
        observed["State"] == "exact_original_two_error_lite_runtime_scope_DATA_not_signed_or_admitted",
        "actual_original_R34_runtime_test_scope_receipt_required")
    if issued is not None:
        m.need(issued["Version"] == observed["Version"] and issued["Scope"] == observed["Scope"] and issued["RuntimeTestScope"] == observed["RuntimeTestScope"],
            "same_original_scope_issue_and_fresh_query_required")
    scope = m.decode(m.pinned(observed["Scope"]))
    m.need(scope == observed["RuntimeTestScope"] and scope["Version"] == "explicit-known-error-lite-runtime-test-scope.v1" and
        scope["InstallationID"] == target["InstallationID"] == data["InstallationID"] and scope["ServerUUID"] == target["ServerUUID"] and
        scope["Database"] == target["Database"] and scope["NamespaceUID"] == target["NamespaceUID"] == data["NamespaceUID"] and
        scope["OriginalInstancesSHA256"] == m.digest(m.encoded(data["Instances"])), "same_complete_raw_original_SQL_snapshot_required_for_scope")
    deferred = scope["Deferred"]
    originals = {row["ID"]: row for row in data["Instances"]}
    m.need(len(data["Instances"]) == len(originals) == 6 and len(deferred) == 2 and len({row["ID"] for row in deferred}) == 2 and
        {row["Type"] for row in deferred} == {"opencode", "deepseek-harness"} and
        all(row["Mode"] == "lite" and row["Status"] == "error" and row["OS"] == "linux" and row["Generation"] >= 0 and originals.get(row["ID"]) == row for row in deferred),
        "only_exact_original_two_known_error_Lite_rows_may_defer_runtime")
    binding = {"version": "operator-original-runtime-test-scope.v1", "Scope": observed["Scope"], "RuntimeTestScope": scope,
        "OriginalSourceCoordinates": data_pin, "OriginalInstancesSHA256": scope["OriginalInstancesSHA256"], "Deferred": deferred,
        "SQLInstanceCount": len(data["Instances"]), "PlannedRuntimeInstanceCount": len(data["Instances"]) - len(deferred),
        "FullRuntimeCoverage": False, "SQLRowsPreserved": True, "OriginalTaskPurpose": "functional_test",
        "ScopeSignedOrAdmitted": False, "backup_ready": False}
    original = stages.directory / "initial-runtime-test-scope.binding-data.json"
    if original.exists():
        m.need(m.decode(m.read(original)) == binding, "original_runtime_test_scope_binding_changed_no_replacement")
    else:
        stages.retain(original.name, binding)
    stages.retain(prefix + str(sequence) + ".result.json", {"Binding": m.pin(original), "NativeReceipt": observed_pin,
        "Scope": observed["Scope"], "FullRuntimeCoverage": False, "backup_ready": False})
    return binding


def running_only_scope_binding(m, stages, data, data_pin, query_only=False):
    scope = data["RuntimeTestScope"]
    rows = data["Instances"]
    deferred = scope["Deferred"]
    by_id = {row["ID"]: row for row in rows}
    deferred_ids = {row["ID"] for row in deferred}
    active = [row for row in rows if row["ID"] not in deferred_ids]
    stopped = [row for row in deferred if (row["Type"], row["Mode"], row["Status"], row["OS"]) == ("openclaw", "pro", "stopped", "linux")]
    errors = [row for row in deferred if (row["Mode"], row["Status"], row["OS"]) == ("lite", "error", "linux")]
    m.need(scope["Version"] == "explicit-running-only-runtime-test-scope.v2" and len(rows) == len(by_id) == 6 and
           len(deferred) == len(deferred_ids) == 3 and len(stopped) == 1 and len(errors) == 2 and
           {row["Type"] for row in errors} == {"opencode", "deepseek-harness"} and
           all(by_id.get(row["ID"]) == row for row in deferred) and len(active) == 3 and
           all((row["Mode"], row["Status"], row["OS"]) == ("lite", "running", "linux") for row in active) and
           scope["OriginalInstancesSHA256"] == m.digest(m.encoded(rows)), "exact_original_running_only_scope_required")
    binding = {"version": "operator-original-runtime-test-scope.v2", "RuntimeTestScope": scope,
        "OriginalSourceCoordinates": data_pin, "OriginalInstancesSHA256": scope["OriginalInstancesSHA256"],
        "Deferred": deferred, "SQLInstanceCount": len(rows), "PlannedRuntimeInstanceCount": len(active),
        "FullRuntimeCoverage": False, "SQLRowsPreserved": True, "OriginalTaskPurpose": "functional_test",
        "ScopeSignedOrAdmitted": False, "backup_ready": False}
    name = "initial-runtime-test-scope.binding-data.json"
    if query_only:
        path = stages.directory / name
        if path.exists() or path.is_symlink():
            m.need(m.decode(m.read(path)) == binding, "original_runtime_test_scope_binding_changed_no_replacement")
    else:
        stages.retain(name, binding)
    return binding


def runtime_test_scope_action(m, stages, sources, query_only=False):
    if getattr(stages.a, "running_only_runtime_test", False):
        data, data_pin, _ = sources.coordinates(m, stages, query_only=query_only)
        return running_only_scope_binding(m, stages, data, data_pin, query_only=query_only)
    data, data_pin, _ = sources.coordinates(m, stages)
    m.need(query_only or getattr(stages.a, "defer_known_error_runtime", False), "explicit_user_runtime_test_scope_opt_in_required")
    return original_runtime_test_scope(m, stages, data, data_pin, query_only)


def prepare(m, stages, assembly):
    # Every required file below belongs to an existing real producer; a missing
    # native definition is a named stop, never a request for handwritten facts.
    providers = sealed(m, stages, "system-backup-initial-provider-fragments.py")
    lifecycle = sealed(m, stages, "system-backup-initial-provider-lifecycle.py")
    topology = sealed(m, stages, "system-backup-initial-provider-topology.py")
    sources = sealed(m, stages, "system-backup-initial-source-data.py")
    redis_owner = sealed(m, stages, "system-backup-initial-redis-sources.py")
    tls_pin = m.pin(stages.directory / "initial-provider-tls.finalized.json")
    tls = m.decode(m.pinned(tls_pin))
    profile_pin = topology.author_profile(m, stages, lifecycle, tls_pin)
    profile_result = m.decode(m.pinned(profile_pin)); profile = m.decode(m.pinned(profile_result["ExecutionProfile"]))
    stages.op.bind_writer_selection_argument()
    redis = redis_owner.prepare(m, stages, assembly)
    base_writer = redis["writer_selection"]
    vault_result = vault(m, stages, providers, lifecycle, base_writer)
    writer_pin = vault_result["WriterSelection"]; writer = m.decode(m.pinned(writer_pin))
    # The exact source input is a successor, not a mutation of the base writer.
    stages.a.deployment_writer_selection_file = Path(writer_pin["File"]); stages.a.deployment_writer_selection_sha256 = writer_pin["SHA256"]
    data, data_pin, coordinate_receipt = sources.coordinates(m, stages)
    m.need(len(data.get("Layouts", [])) == len(data["Instances"]), "every_original_source_layout_required_including_nonrunning")
    scope_binding = None
    if getattr(stages.a, "running_only_runtime_test", False):
        m.need(profile["target_class"] == "same-cluster-copy" and profile_result["ClassificationData"]["TaskPurpose"] == "functional_test" and
               writer.get("RuntimeTestScope") == data["RuntimeTestScope"], "same_original_running_only_scope_writer_and_functional_test_profile_required")
        scope_binding = running_only_scope_binding(m, stages, data, data_pin)
    elif getattr(stages.a, "defer_known_error_runtime", False):
        m.need(profile["target_class"] == "same-cluster-copy" and profile_result["ClassificationData"]["TaskPurpose"] == "functional_test",
            "explicit_runtime_deferral_only_for_original_functional_test_profile")
        scope_binding = original_runtime_test_scope(m, stages, data, data_pin)
        data = {**data, "RuntimeTestScope": scope_binding["RuntimeTestScope"]}

    source_api_pin = sources.source_api_inputs(m, stages); source_api = m.decode(m.pinned(source_api_pin))
    until_value = stages.a.deployment_signing_until
    m.need(until_value is not None, "original_explicit_installation_until_required")
    until = datetime.datetime.fromisoformat(until_value.replace("Z", "+00:00"))
    until = min(until, datetime.datetime.fromtimestamp(source_api["token_expires_unix"], datetime.timezone.utc))
    until_text = until.isoformat().replace("+00:00", "Z")
    common, enrolled, plan, sql = stages.common()
    host = m.decode(m.read(stages.directory / "host-observer.result.json"))["host"]
    relay = relay_pki(m, stages, host, until_text)
    issuer_result = sealed(m, stages, "system-backup-runtime-issuers.py").prepare(stages.op)
    envelope = m.decode(m.pinned(issuer_result["material"]))
    issuer_material = m.decode(base64.b64decode(envelope["Record"], validate=True))
    forward_key = issuer_material["Issuers"]["forward_execution"]["PublicKey"]
    public = base64.b64encode(m.pinned(forward_key)).decode()
    source_public = base64.b64encode(m.pinned(enrolled["IssuerPublic"])).decode()
    core, directory, host, app = source_core(m, stages, assembly, data, writer, profile, relay, public)
    # Use the exact mirrored public CA accessible to the actual runtime host.
    host_inputs = m.decode(m.read(stages.directory / "host-observer.result.json"))["runtime_input_pins"]
    ca = host_inputs["database-ca.pem"]; m.pinned(ca)
    core["source_tls"] = {**sql["source_tls"], "ca_file": ca["File"], "ca_sha256": ca["SHA256"]}
    prepared = stages.completed("sql-prepare")
    operation = m.decode(m.pinned({"File": prepared["operation_file"], "SHA256": prepared["operation_sha256"]}))
    actual = {x["Role"]: x for x in operation["Accounts"]}
    m.need("control_sql" in actual and "source" in actual, "actual_original_control_and_source_SQL_roles_required")
    connections = []
    for role, purpose in (("control_sql", "control_sql"), ("source", "source_sql")):
        credential = host_inputs["mysql-" + role + ".dsn"]; m.pinned(credential)
        account = actual[role]
        connections.append({"Purpose": purpose, "Endpoint": "mysql+tls://" + operation["Address"], "Account": account["User"] + "@" + account["Host"],
            "ServerUUID": operation["ServerUUID"], "Database": operation["Database"], "CA": ca, "Credential": credential, "IdentitySHA256": "", "ScopeSHA256": ""})
    material = material_template(m, stages, assembly, core, directory, host, app, data, redis, tls["MinIOFragment"], source_api, source_public, operation)
    controller = {"Namespace": data["Namespace"], "NamespaceUID": data["NamespaceUID"], **{k: host[k] for k in ("Deployment", "DeploymentUID", "ReplicaSet", "ReplicaSetUID", "Pod", "PodUID", "ServiceAccount", "ServiceAccountUID")}}
    inputs = {"Version": "original-initial-source-author-inputs.v1", "Deployment": core, "Materials": material, "Profile": profile, "Controller": controller,
        "Connections": [connections[0], source_api["connection"], tls["MinIOFragment"]["Connection"], redis["connection"], connections[1]],
        "RuntimeAgent": {"Operations": ["backup_capabilities_read", "gateway_state_read"], "ScopeSHA256": "", "CA": writer["AgentCA"], "Credential": writer["AgentCredential"]},
        "PartsVersion": "original-first-source.v1", "SourceWritersVersion": "original-first-source.v1", "RedisSourcesVersion": "original-first-source.v1",
        "NotBefore": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)).isoformat().replace("+00:00", "Z"), "Until": until_text}
    definition_path = stages.directory / "initial-complete-source.inputs.json"
    if definition_path.exists():
        previous = m.decode(m.read(definition_path))
        m.need({k:v for k,v in previous.items() if k != "NotBefore"} == {k:v for k,v in inputs.items() if k != "NotBefore"}, "original_complete_source_definition_changed_no_replacement")
        inputs = previous
    definition = stages.retain(definition_path.name, inputs)
    directory.mkdir(mode=0o700, exist_ok=True)
    native, receipt = stages.call("initial-complete-source-author", [stages.binary("system-backup-first-install-materials"), "author-initial-source-inputs", *common,
        "--definition-file", definition["File"], "--definition-sha256", definition["SHA256"], "--output-directory", directory])
    m.need(native["Version"] == "original-initial-source-inputs-authored.v1" and native["NativeSourceQualified"] is False and native["GrantsIssued"] is False and native["BackupReady"] is False, "actual_original_initial_source_DATA_author_required")
    for key in ("Deployment", "MaterialsTemplate", "ExecutionProfile", "SourceSelection"):
        m.pinned(native[key])
    assembly.bind(m, stages.a, "deployment_source_selection", native["SourceSelection"])
    assembly.bind(m, stages.a, "owner_core", native["Deployment"])
    return stages.retain("initial-complete-source.result.json", {"version": "operator-initial-complete-source-data.v1", **native, "WriterSelection": writer_pin,
        "actual_native_receipt": receipt, "source_coordinates": data_pin, "coordinate_receipt": coordinate_receipt, "original_Vault": vault_result,
        "profile_data": profile_pin, "ProviderTopology": profile_result["ProviderTopology"], "RuntimeTestScopeBinding": scope_binding, "TLS_lifecycle": tls_pin, "relay_pki": relay["Manifest"], "SourceFactDependencies": data.get("Dependencies", []),
        "formal_worker_mapping_issued": False, "source_facts_produced": False, "backup_ready": False})
