"""Reuse original native outputs as operational locations, never authorization.

The existing Go issuer still authenticates the complete request and live owner.
No key, grant, signature, scope, config, or native success is manufactured here.
"""
from pathlib import Path
import base64
import re


def optional_pin(m, args, prefix):
    path = getattr(args, prefix + "_file", None)
    sha = getattr(args, prefix + "_sha256", None)
    m.need((path is None) == (sha is None), "complete_original_input_pin_required:" + prefix)
    if path is None:
        return None
    m.need(re.fullmatch(r"[a-f0-9]{64}", sha or ""), "original_input_sha_required:" + prefix)
    pin = {"File": str(path), "SHA256": sha}
    m.pinned(pin)
    return pin


def bind(m, args, prefix, pin):
    m.pinned(pin)
    existing = optional_pin(m, args, prefix)
    m.need(existing is None or existing == pin, "original_input_selector_conflict:" + prefix)
    setattr(args, prefix + "_file", Path(pin["File"]))
    setattr(args, prefix + "_sha256", pin["SHA256"])


def prepare_core_input(m, stages):
    """Bind only core before SQL-role validation; no request write or issuer."""
    core = optional_pin(m, stages.a, "owner_core")
    if core is None:
        material = m.decode(m.read(stages.directory / "materials.result.json"))
        m.need(material["version"] == "operator-materials-result.v1", "actual_materials_result_required_for_core")
        stages.check_host(material["host"])
        selected = m.decode(m.pinned(material["SourceSelection"]))
        m.need(material["Deployment"] == selected["Deployment"], "material_core_selection_mismatch")
        core = material["Deployment"]
        m.pinned(core)
    bind(m, stages.a, "owner_core", core)
    return core


def original_app_environment(m, stages, app, name):
    """Resolve only this original app key; never emit credential values."""
    containers = app["spec"]["template"]["spec"]["containers"]
    m.need(len(containers) == 1, "one_original_app_container_required")
    container = containers[0]
    candidates = [entry for entry in container.get("env", []) if entry["name"] == name]
    m.need(len(candidates) <= 1, "duplicate_original_app_environment")
    if candidates:
        entry = candidates[0]
        if "value" in entry:
            value = entry["value"].encode()
        else:
            selector = entry["valueFrom"]
            m.need(len(selector) == 1, "finite_original_app_environment_selector_required")
            kind = "secret" if "secretKeyRef" in selector else "configmap"
            ref = selector.get("secretKeyRef", selector.get("configMapKeyRef"))
            m.need(ref is not None and not ref.get("optional", False), "required_original_app_environment_selector")
            obj = stages.get(kind, ref["name"])
            value = base64.b64decode(obj["data"][ref["key"]], validate=True) if kind == "secret" else obj["data"][ref["key"]].encode()
    else:
        found = []
        for entry in container.get("envFrom", []):
            prefix = entry.get("prefix", "")
            if not name.startswith(prefix):
                continue
            key = name[len(prefix):]
            kind = "secret" if "secretRef" in entry else "configmap"
            ref = entry.get("secretRef", entry.get("configMapRef"))
            m.need(ref is not None and not ref.get("optional", False), "required_original_app_envfrom_selector")
            obj = stages.get(kind, ref["name"])
            if key in obj.get("data", {}):
                found.append(base64.b64decode(obj["data"][key], validate=True) if kind == "secret" else obj["data"][key].encode())
        # Ambiguous envFrom shadowing needs explicit review of original config;
        # no precedence guess becomes a different source credential.
        m.need(len(found) == 1, "one_actual_original_app_environment_source_required:" + name)
        value = found[0]
    m.need(value and b"\x00" not in value and b"$(" not in value, "literal_original_app_environment_required")
    return value


def prepare_writer_source_input(m, stages):
    """Actual earliest finite projection for the existing native writer owner.

    This file is intentionally NOT bound as owner_core: it is not a complete
    DeploymentConfig and cannot stand in for one in later source capture.
    The native owner repeats an unfiltered SQL/Kube census, including stopped
    instances; an unprovided stopped layout is rejected, never omitted.
    """
    existing = optional_pin(m, stages.a, "writer_source_config")
    if existing is not None:
        return existing
    _, _, plan, _ = stages.common()
    app = stages.get("deployment", "clawmanager-app")
    m.need(app["metadata"]["uid"] == stages.scope["app_deployment_uid"], "same_original_app_required_for_source_author")
    app_spec = app["spec"]
    token = original_app_environment(m, stages, app, "RUNTIME_AGENT_CONTROL_TOKEN")
    m.need(32 <= len(token) <= 8192 and not any(chr(v).isspace() for v in token), "actual_original_agent_control_token_required")
    workspace = original_app_environment(m, stages, app, "RUNTIME_WORKSPACE_ROOT").decode("utf-8")
    m.need(workspace.startswith("/") and str(Path(workspace)) == workspace and workspace != "/", "original_absolute_workspace_root_required")
    tls = m.decode(m.read(stages.directory / "runtime-agent-tls.result.json"))
    m.need(tls["version"] == "operator-shared-agent-tls.v1" and tls["operation"] == stages.operation, "actual_agent_tls_producer_required_for_source_author")
    material = m.decode(m.pinned(tls["materials_receipt"]))
    m.need(material["Version"] == "original-shared-agent-tls-materials.v1" and material["Namespace"] == plan["Target"]["Namespace"], "same_actual_agent_tls_namespace_required")
    m.pinned(material["CA"])
    # Compare the actual app source again before retaining the finite config.
    again = stages.get("deployment", "clawmanager-app")
    m.need(again["metadata"]["uid"] == app["metadata"]["uid"] and again["spec"] == app_spec and
           original_app_environment(m, stages, again, "RUNTIME_AGENT_CONTROL_TOKEN") == token,
           "original_app_source_changed_during_authoring")
    root = stages.runtime_mirror()
    credential_path = root / "original-agent-control-token"
    if credential_path.exists():
        m.need(m.read(credential_path) == token, "original_agent_credential_changed_no_replacement")
        credential = m.pin(credential_path)
    else:
        credential = m.write(credential_path, token)
    target = plan["Target"]
    config = {"installation_id": target["InstallationID"], "namespace": target["Namespace"], "namespace_uid": target["NamespaceUID"],
              "application_scope": target["Namespace"] + ":" + stages.scope["app_deployment_uid"],
              "runtime_sources": {"shared_runtime_protocol": "shared-container-freeze.v1", "workspace_root": workspace,
                  "agent_token_file": credential["File"], "agent_ca_file": material["CA"]["File"], "agent_ca_sha256": material["CA"]["SHA256"],
                  "current_stopped_pro_layouts": []}}
    selected = stages.retain("initial-writer-source-config.json", config)
    bind(m, stages.a, "writer_source_config", selected)
    return selected


REGISTRY_KINDS = ("parts", "redis_sources", "failure_domains", "disaster_identity_mapping", "source_writers", "rbac_bindings", "secret_allowlist", "strong_auth_issuers", "provider_proof_issuers")
REFERENCE_PURPOSES = ("artifact_write", "artifact_read", "artifact_delete", "artifact_upload_issuer", "artifact_ca", "evidence_store", "evidence_write", "evidence_read", "evidence_delete", "evidence_ca", "evidence_kek", "kek", "capture_signing", "acceptance_signing", "catalog_signing", "catalog_read", "catalog_append", "catalog_snapshot", "nonce_hmac", "status_relay")


def original_selectors(value, registries, references):
    """Project real record selectors only; never assert they are authenticated."""
    if isinstance(value, list):
        for item in value:
            original_selectors(item, registries, references)
    elif isinstance(value, dict):
        if set(value) == {"registry_kind", "version", "sha256"} and value["registry_kind"] in REGISTRY_KINDS:
            registries.add((value["registry_kind"], value["version"], value["sha256"]))
        if set(value) == {"purpose", "version", "identity_hash"} and value["purpose"] in REFERENCE_PURPOSES:
            references.add((value["purpose"], value["version"], value["identity_hash"]))
        for child in value.values():
            original_selectors(child, registries, references)
        if set(value) == {"Record", "Signature"} and isinstance(value["Record"], str):
            import json
            decoded = base64.b64decode(value["Record"], validate=True)
            if decoded.startswith(b"{"):
                original_selectors(json.loads(decoded), registries, references)


def retain_original_bytes(m, path, raw):
    if path.exists():
        m.need(m.read(path) == raw, "original_source_bytes_changed_no_replacement")
        return m.pin(path)
    return m.write(path, raw)


def prepare_initial_minio_options(m, stages):
    """Run the existing original MinIO producer before material delivery.

    Read root credentials from the real original MinIO workload, not the
    not-yet-created material options. Existing Go owners authenticate the full
    source selection, enrollment, Kube graph, TLS/server, all buckets and native
    accounts. No final_binding/materials receipt is required at this step.
    """
    existing = optional_pin(m, stages.a, "deployment_minio_options")
    if existing is not None:
        return existing
    source = optional_pin(m, stages.a, "deployment_source_selection")
    writer_pin = optional_pin(m, stages.a, "deployment_writer_selection")
    terminal_pin = optional_pin(m, stages.a, "compose_minio_input")
    m.need(source is not None and writer_pin is not None and terminal_pin is not None,
           "actual_initial_source_writer_and_original_minio_owner_inputs_required")
    m.pinned(source)
    writer = m.decode(m.pinned(writer_pin))
    terminal = m.decode(m.pinned(terminal_pin))
    definition_pin = {"File": terminal["DefinitionFile"], "SHA256": terminal["DefinitionSHA256"]}
    definition = m.decode(m.pinned(definition_pin))
    common, _, plan, _ = stages.common()
    grant = definition["Grant"]
    target = plan["Target"]
    m.need(grant["Installation"] == target["InstallationID"] and grant["Namespace"] == target["Namespace"] and
           grant["NamespaceUID"] == target["NamespaceUID"], "same_actual_original_minio_owner_target_required")
    provider = grant["Provider"]
    workload = stages.get("deployment", provider["Deployment"]["Name"])
    m.need(workload["metadata"]["uid"] == provider["Deployment"]["UID"], "same_original_minio_workload_required")
    user = original_app_environment(m, stages, workload, "MINIO_ROOT_USER")
    password = original_app_environment(m, stages, workload, "MINIO_ROOT_PASSWORD")
    m.need(0 < len(user) <= 1024 and 0 < len(password) <= 4096 and
           not any(byte in user or byte in password for byte in (b"\x00", b"\r", b"\n")), "bounded_original_minio_root_source_required")
    again = stages.get("deployment", provider["Deployment"]["Name"])
    m.need(again["metadata"]["uid"] == workload["metadata"]["uid"] and again["spec"] == workload["spec"] and
           original_app_environment(m, stages, again, "MINIO_ROOT_USER") == user and
           original_app_environment(m, stages, again, "MINIO_ROOT_PASSWORD") == password, "original_minio_root_source_changed")
    root = stages.runtime_mirror()
    user_pin = retain_original_bytes(m, root / "original-minio-root-user", user)
    password_pin = retain_original_bytes(m, root / "original-minio-root-password", password)
    del password, user
    provider_pin = stages.retain("initial-minio-provider.json", {"Version": "original-minio-source-provider-input.v1", "Installation": grant["Installation"],
        "Namespace": grant["Namespace"], "NamespaceUID": grant["NamespaceUID"], "Provider": provider})
    mc = getattr(stages.a, "adoption_mc_file", None) or stages.root / "tools/mc"
    mc_pin = m.pin(mc, private=False, limit=128 << 20)
    mc_sha = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
    m.need(mc_pin["SHA256"] == mc_sha and stages.op.pins["files"].get("tools/mc") == mc_sha, "actual_sealed_original_mc_required")
    directory = root / "initial-minio-read-materials"
    directory.mkdir(mode=0o700, exist_ok=True)
    inputs = stages.retain("initial-minio-read-materials.inputs.json", {"Version": "original-minio-whole-history-setup-inputs.v1", "SourceSelection": source,
        "Provider": provider_pin, "OutputDirectory": str(directory), "Policy": writer["Policy"], "Admin": {
            "UserFile": user_pin["File"], "PasswordFile": password_pin["File"], "MCFile": str(mc), "MCSHA256": mc_sha}})
    setup, setup_pin = stages.call("initial-minio-read-materials", [stages.binary("system-backup-first-adoption-production"), "--action", "prepare-minio-history",
        *common, "--inputs-file", inputs["File"], "--inputs-sha256", inputs["SHA256"]])
    m.need(setup["Version"] == "original-minio-source-setup-receipt.v1" and setup["State"] == "accounts_installed_not_held" and
           setup["Stage"] == "native_installed_requires_gate_preflight" and setup["NativeWritesAttempted"] is True,
           "actual_original_minio_account_installer_receipt_required")
    material_pin = {"File": setup["MaterialsFile"], "SHA256": setup["MaterialsSHA256"]}
    material = m.decode(m.pinned(material_pin))
    m.need(material["Version"] == "original-minio-source-read-materials.v1" and material["SourceSelectionSHA256"] == source["SHA256"] and
           material["ProviderDefinitionSHA256"] == provider_pin["SHA256"], "same_original_minio_material_lineage_required")
    output = root / "initial-minio-options"
    output.mkdir(mode=0o700, exist_ok=True)
    actual, options_receipt = stages.call("initial-minio-options-author", [stages.binary("system-backup-first-install-materials"), "author-initial-minio-options", *common,
        "--setup-receipt-file", setup_pin["File"], "--setup-receipt-sha256", setup_pin["SHA256"],
        "--history-definition-file", definition_pin["File"], "--history-definition-sha256", definition_pin["SHA256"], "--output-directory", output])
    m.need(actual["Version"] == "original-initial-minio-options-authored.v1" and actual["BackupReady"] is False and
           actual["NativeSetupReceipt"] == setup_pin and actual["HistoryDefinition"] == definition_pin,
           "actual_original_minio_options_author_receipt_required")
    options = actual["Options"]
    m.pinned(options)
    stages.retain("initial-minio-options-author.result.json", {"version": "operator-initial-minio-options-author.v1", "source_selection": source,
        "writer_selection": writer_pin, "original_minio_owner": terminal_pin, "native_setup_receipt": setup_pin,
        "native_options_receipt": options_receipt, "options": options, "backup_ready": False})
    bind(m, stages.a, "deployment_minio_options", options)
    return options


def prepare_disabled_config(m, stages):
    """Build complete disabled ConfigValues from existing native owner outputs.

    Refuse absent/ambiguous purposes instead of using an empty reference, a
    synthetic identity, the newest file, or an unmeasured source-size claim.
    """
    directories = []
    for prefix in ("compose_registry_directory", "compose_mapping_directory", "compose_source_registry_directory",
                   "compose_status_relay_directory", "compose_six_reference_directory", "compose_kek_window_directory"):
        path = getattr(stages.a, prefix, None)
        if path is not None:
            path = Path(path)
            m.need(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(), "actual_original_owner_output_directory_required")
            directories.append(path)
    # These are this operation's original producer directories, never a repo
    # or machine-wide search. No credential bytes are returned or logged.
    directories.extend(p for p in (stages.run / "production-adoption", stages.runtime_mirror()) if p.exists())
    registries, references, source_pins = set(), set(), []
    paths = set()
    for directory in directories:
        for path in directory.rglob("*.json"):
            m.need(not path.is_symlink() and path.resolve(strict=True) == path, "owner_source_link_refused")
            if path in paths:
                continue
            paths.add(path)
            m.need(len(paths) <= 10000, "bounded_original_owner_output_roster_required")
            if path.stat().st_size > 8 << 20:
                continue
            value = m.decode(m.read(path, limit=8 << 20))
            original_selectors(value, registries, references)
            relative = path.relative_to(directory).parts
            if len(relative) >= 3 and relative[-3] in REGISTRY_KINDS and re.fullmatch(r"[a-f0-9]{64}\.json", relative[-1]):
                actual = m.pin(path)
                m.need(actual["SHA256"] == path.stem, "original_content_addressed_registry_bytes_changed")
                registries.add((relative[-3], relative[-2], path.stem))
            source_pins.append(m.pin(path, limit=8 << 20))
    selected_registries, selected_references = [], []
    for kind in REGISTRY_KINDS:
        options = [r for r in registries if r[0] == kind]
        m.need(len(options) == 1, "actual_unique_original_registry_required:" + kind)
        _, version, digest = options[0]
        selected_registries.append({"registry_kind": kind, "version": version, "sha256": digest})
    for purpose in REFERENCE_PURPOSES:
        options = [r for r in references if r[0] == purpose]
        m.need(len(options) == 1, "actual_unique_original_reference_required:" + purpose)
        _, version, identity = options[0]
        selected_references.append({"purpose": purpose, "version": version, "identity_hash": identity})
    host = m.decode(m.read(stages.directory / "materials.result.json"))
    stages.check_host(host["host"])
    original_host = m.decode(m.read(stages.directory / "host-observer.result.json"))
    pvc = stages.get("pvc", stages.prefix + "-staging")
    m.need(pvc["metadata"]["uid"] == original_host["pvc_uids"]["staging"] and pvc["status"]["phase"] == "Bound", "same_actual_staging_capacity_source_required")
    quantity = pvc["status"]["capacity"]["storage"]
    match = re.fullmatch(r"([1-9][0-9]*)(Ki|Mi|Gi|Ti)?", quantity)
    m.need(match is not None, "finite_actual_staging_quantity_required")
    scale = {None: 1, "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40}[match[2]]
    selection = stages.retain("initial-disabled-config.selections.json", {"Version": "original-disabled-config-selections.v1",
        "Registries": selected_registries, "References": selected_references, "StagingBytes": int(match[1]) * scale})
    target = stages.runtime_mirror() / "original-disabled-config.json"
    result, receipt = stages.call("initial-disabled-config-author", [stages.binary("system-backup-first-install-materials"), "author-disabled-config",
        "--definition-file", selection["File"], "--definition-sha256", selection["SHA256"], "--output-file", target])
    m.need(result["Version"] == "original-disabled-config-authored.v1" and result["AuthorityIssued"] is False and
           result["CapacityVerified"] is False and result["BackupReady"] is False, "actual_disabled_config_data_author_required")
    config = result["Config"]
    m.pinned(config)
    stages.retain("initial-disabled-config-author.result.json", {"version": "operator-disabled-config-data-author.v1", "config": config,
        "native_receipt": receipt, "original_owner_source_pins": source_pins, "source_size_measured": False, "backup_ready": False})
    return config


def prepare_initial_runtime_inputs(m, stages):
    """Called before initial-forward/provider stages; all files are original.

    An explicit complete pair wins. Automatic request assembly requires the
    already selected bootstrap config/grant and native signing output. It cannot
    bootstrap the earlier missing source configuration/material selection.
    """
    args = stages.a
    core = prepare_core_input(m, stages)
    request = optional_pin(m, args, "owner_request_files")
    if request is not None:
        return
    if request is None:
        config = optional_pin(m, args, "owner_config")
        compose_config = optional_pin(m, args, "compose_config")
        m.need(config is None or compose_config is None or config == compose_config,
               "original_bootstrap_config_selectors_conflict")
        config = config or compose_config
        if config is None:
            config = prepare_disabled_config(m, stages)
            bind(m, args, "owner_config", config)
            bind(m, args, "compose_config", config)
        grant = optional_pin(m, args, "compose_bootstrap_grant")
        m.need(config is not None, "missing_complete_original_bootstrap_config_producer_output")
        signing = m.decode(m.read(stages.directory / "signing-material.result.json"))
        m.need(signing["version"] == "operator-signing-material-result.v1", "actual_signing_result_required_for_request")
        stages.check_host(signing["host"])
        receipt = m.decode(m.pinned(signing["original_signing_receipt"]))
        m.need(receipt["Version"] == "original-publication-signing-material-result.v1" and
               receipt == signing["actual_producer_output"], "original_signing_receipt_changed")
        observer = receipt["CaptureObserver"]
        m.pinned(observer)
        if grant is None:
            core_value = m.decode(m.pinned(core))
            profile = m.decode(m.read(Path(core_value["profile_file"])))
            matrices = {("kubernetes", "cluster"): "k8s-cluster", ("kubernetes", "single-node"): "k8s-single-node",
                        ("k3s", "cluster"): "k3s-cluster", ("k3s", "single-node"): "k3s-single-node"}
            matrix = matrices.get((profile.get("source_orchestrator"), profile.get("source_profile")))
            m.need(matrix is not None and args.deployment_signing_until, "actual_original_profile_and_request_deadline_required")
            directory = stages.runtime_mirror() / "original-request-author"
            directory.mkdir(mode=0o700, exist_ok=True)
            common, _, _, _ = stages.common()
            actual, native_pin = stages.call("initial-request-author", [stages.binary("system-backup-first-install-materials"),
                "prepare-initial-request", *common, "--config-file", config["File"], "--config-sha256", config["SHA256"],
                "--signing-material-file", receipt["Material"]["File"], "--signing-material-sha256", receipt["Material"]["SHA256"],
                "--matrix-key", matrix, "--change-reason", "Original administrator requested initial complete system backup installation",
                "--until", args.deployment_signing_until, "--output-directory", directory])
            m.need(actual["Version"] == "original-initial-request-authored.v1" and actual["Config"] == config and
                   actual["ConfigurationMutated"] is False and actual["GrantsInstalled"] is False and actual["BackupReady"] is False,
                   "actual_original_authenticated_request_author_receipt_required")
            grant = actual["Grant"]
            m.pinned(grant)
            request = actual["RequestFiles"]
            authored = m.decode(m.pinned(request))
            m.need(authored == actual["Request"] and authored["ObserverFile"] == observer["File"] and
                   authored["ObserverFileSHA256"] == observer["SHA256"], "same_original_request_observer_required")
            stages.retain("initial-request-author.result.json", {"version": "operator-initial-request-author.v1", "native_receipt": native_pin,
                "core": core, "config": config, "grant": grant, "request_files": request, "backup_ready": False})
            bind(m, args, "compose_bootstrap_grant", grant)
            bind(m, args, "owner_core", core)
            bind(m, args, "owner_request_files", request)
            return
        value = {"ConfigFile": config["File"], "ConfigFileSHA256": config["SHA256"],
                 "GrantFile": grant["File"], "GrantFileSHA256": grant["SHA256"],
                 "ObserverFile": observer["File"], "ObserverFileSHA256": observer["SHA256"]}
        path = stages.runtime_mirror() / "original-request-files.json"
        raw = m.encoded(value)
        if path.exists():
            m.need(m.read(path) == raw, "original_request_files_changed_no_replacement")
            request = m.pin(path)
        else:
            request = m.write(path, raw)
    bind(m, args, "owner_core", core)
    bind(m, args, "owner_request_files", request)
