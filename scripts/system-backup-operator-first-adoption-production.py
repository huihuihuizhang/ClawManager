"""Actual owner-authored inputs and ONE same-process first-adoption run.

Preparation files contain producer locations, never source/coverage/control
DTOs. The sealed Go production CLI creates opaque C1/B/C/A objects itself.
"""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

BINARY = "system-backup-first-adoption-production"
PREPARE = {"adopt-prepare-minio-history": "prepare-minio-history", "adopt-prepare-native-plan": "prepare-native-plan", "adopt-prepare-inputs": "prepare-inputs"}
PREPARE["adopt-prepare-recovery-descriptor"] = "prepare-recovery-descriptor"
SUCCESS = "original_adoption_committed_sources_recovered_disabled_v1_dependencies_unverified"


def register_arguments(parser):
    for name in ("c1-invocation", "archive-template", "minio-history-inputs", "provider-inputs"):
        parser.add_argument("--adoption-"+name+"-file", type=Path)
        parser.add_argument("--adoption-"+name+"-sha256")
    parser.add_argument("--adoption-capture-seconds", type=int, default=120)
    parser.add_argument("--adoption-recovery-seconds", type=int, default=180)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def helpers(operator):
    return operator.source_helpers()


def selected(operator, name):
    m = helpers(operator)
    path = getattr(operator.a, "adoption_"+name.replace("-", "_")+"_file")
    sha = getattr(operator.a, "adoption_"+name.replace("-", "_")+"_sha256")
    if name == "c1-invocation" and path is None and sha is None:
        return operator.c1_authors_module().invocation(operator)
    if name == "archive-template" and path is None and sha is None:
        return operator.archive_inputs_module().template(operator, SimpleNamespace(ensure_directory=ensure_directory, save_selection=save_selection))
    m.require(path is not None and sha is not None, "actual_adoption_"+name.replace("-", "_")+"_producer_pin_required")
    pin = {"File": str(path), "SHA256": sha}
    operator.pin_value(pin)
    return pin


def retained(operator, stage):
    receipt = operator.completed(stage)
    path = Path(receipt["stdout"])
    return helpers(operator).load(path), {"File": str(path), "SHA256": receipt["stdout_sha256"]}


def ensure_directory(operator, path):
    if not path.exists():
        path.mkdir(mode=0o700)
        helpers(operator).sync_dir(path.parent)
    m = helpers(operator)
    info = path.stat()
    m.require(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0 and (os.name != "posix" or info.st_uid == os.geteuid()), "original_private_adoption_directory_required")
    return path


def save_selection(operator, name, value):
    directory = ensure_directory(operator, operator.run/"production-adoption")
    path = directory/name
    # The owner uses decodeExact for typed provider inputs: no final newline,
    # omitted exported fields, or noncanonical timestamp representation.
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    m = helpers(operator)
    if path.exists():
        m.require(path.read_bytes() == raw, "original_adoption_input_selection_changed_do_not_replace")
    else:
        with path.open("xb") as target:
            path.chmod(0o600)
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        m.sync_dir(directory)
    return {"File": str(path), "SHA256": hashlib.sha256(raw).hexdigest()}


def common(operator):
    flags = operator.owner_common()
    stages = operator.deployment_stages()
    binary = stages.binary(BINARY)
    m = helpers(operator)
    m.require(operator.pins["files"].get("bin/"+BINARY) == digest(binary), "sealed_actual_production_adoption_elf_required")
    return binary, flags, stages


def original_provider_inputs(operator, initial_runtime):
    supplied = operator.a.adoption_provider_inputs_file
    supplied_sha = operator.a.adoption_provider_inputs_sha256
    helpers(operator).require((supplied is None) == (supplied_sha is None), "provider_input_file_and_pin_must_be_selected_together")
    if supplied is not None:
        return selected(operator, "provider-inputs")
    # Reuse actual owner-issued Forward/publication/issuer/core/Request and
    # current controller graph. This never calls legacy provider SQL install.
    owner = initial_runtime.InitialRuntimeStages(operator)
    forward, publication = owner.previous_publication()
    m = owner.m
    file, pin = operator.a.initial_provider_file, operator.a.initial_provider_sha256
    m.need(file is not None and pin is not None, "actual_original_native_provider_observer_input_required")
    provider = {"File": str(file), "SHA256": pin}
    m.pinned(provider)
    identity = operator.a.initial_worker_jwt_identity_file
    m.need(isinstance(identity, str) and identity.startswith("/") and ".." not in Path(identity).parts, "actual_original_worker_projected_jwt_identity_required")
    output = ensure_directory(operator, owner.stages.runtime_mirror()/"initial-provider-authorities")
    until = operator.a.deployment_signing_until
    m.need(isinstance(until, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{0,8}[1-9])?Z", until), "retain_exact_original_canonical_utc_issuance_until_required")
    value = {"C1": None, "Issuers": owner.material, "Core": owner.core_pin, "Forward": forward["grant"], "Provider": provider, "PublicationOwnerInputs": publication["owner_inputs"], "Request": m.decode(m.pinned(owner.request_pin)), "ControllerDeployment": owner.host["Deployment"], "ControllerPodName": owner.host["Pod"], "WorkerJWTIdentityFile": identity, "OutputDirectory": str(output), "Until": until}
    return save_selection(operator, "actual-provider-location-inputs.json", value)


def original_minio_history_inputs(operator):
    file = operator.a.adoption_minio_history_inputs_file
    sha = operator.a.adoption_minio_history_inputs_sha256
    helpers(operator).require((file is None) == (sha is None), "minio_history_input_file_and_pin_must_be_selected_together")
    if file is not None:
        return selected(operator, "minio-history-inputs")
    return operator.adoption_locations_module().minio_history_inputs(operator, SimpleNamespace(ensure_directory=ensure_directory, save_selection=save_selection))


def prepare_selections(operator, initial_runtime, stages):
    m = helpers(operator)
    m.require(1 <= operator.a.adoption_capture_seconds <= 600 and 1 <= operator.a.adoption_recovery_seconds <= 600, "bounded_original_adoption_contexts_required")
    base = ensure_directory(operator, operator.run/"production-adoption")
    for name in ("input-owner", "history", "head1", "warm"):
        ensure_directory(operator, base/name)
    _, _, _, sql = stages.common()
    runtime = sql["files"]["mysql-runtime.dsn"]
    operator.pin_value(runtime)
    ca = {"File": sql["source_tls"]["ca_file"], "SHA256": sql["source_tls"]["ca_sha256"]}
    operator.pin_value(ca)
    writer, _ = retained(operator, "writer-selection")
    m.require(writer["Version"] == "original-writer-selection-materials.v1" and writer["State"] == "actual_original_complete_base_selection_materialized_no_hold", "actual_complete_writer_selection_required")
    operator.pin_value(writer["Selection"])
    c1_writer = operator.c1_inputs_module().writer_selection(operator)
    operator.pin_value(c1_writer)
    issuer, _ = retained(operator, "adopt-prepare-issuers")
    operator.pin_value(issuer)
    history, _ = retained(operator, "adopt-prepare-minio-history")
    m.require(history["Version"] == "original-minio-source-setup-receipt.v1" and history["State"] == "accounts_installed_not_held", "actual_whole_minio_history_owner_materials_required")
    material = {"File": history["MaterialsFile"], "SHA256": history["MaterialsSHA256"]}
    operator.pin_value(material)
    native, native_receipt = retained(operator, "adopt-prepare-native-plan")
    operator.pin_value({"File": native["PlanFile"], "SHA256": native["PlanSHA256"]})
    reader = stages.binary("system-backup-original-archive-reader")
    value = {"Version": "original-first-adoption-input-selections.v1", "ProviderInputs": original_provider_inputs(operator, initial_runtime), "C1Invocation": selected(operator, "c1-invocation"), "NativePlanReceipt": native_receipt, "RuntimeDSN": runtime, "RuntimeCA": ca, "WriterSelection": writer["Selection"], "MinIOWholeHistoryMaterial": material, "BusinessSourceSelection": operator.final_binding()["source_selection"], "AdoptionIssuers": issuer, "ArchiveTemplate": selected(operator, "archive-template"), "CustodyReader": {"File": str(reader), "SHA256": digest(reader)}, "OutputDirectory": str(base/"input-owner"), "HistoryDirectory": str(base/"history"), "Head1Directory": str(base/"head1"), "WarmDirectory": str(base/"warm"), "CaptureSeconds": operator.a.adoption_capture_seconds, "RecoverySeconds": operator.a.adoption_recovery_seconds}
    value["MinIORecoveryDescriptor"] = operator.minio_recovery_module().input_descriptor(operator)
    value["WriterSelection"] = c1_writer
    return save_selection(operator, "actual-owner-input-selections.json", value)


def prepare(operator, action, initial_runtime):
    m = helpers(operator)
    m.require(action in PREPARE and not (operator.run/"adopt.send-unknown.json").exists(), "original_full_adoption_dispatched_no_new_preparation")
    m.require(not list((operator.run/"deployment").glob("initial-provider-authorities.send-unknown.json")), "legacy_provider_install_dispatched_cannot_reinstall_first_mixed_rows")
    if action == "adopt-prepare-recovery-descriptor":
        return operator.minio_recovery_module().prepare_descriptor(operator, SimpleNamespace(ensure_directory=ensure_directory, save_selection=save_selection))
    binary, flags, stages = common(operator)
    if action == "adopt-prepare-minio-history":
        source = original_minio_history_inputs(operator)
        setup = m.load(operator.pin_value(source))
        m.require(setup["Version"] == "original-minio-whole-history-setup-inputs.v1", "actual_owner_whole_history_setup_locations_required")
        binding = operator.final_binding()
        m.require(setup["SourceSelection"] == binding["source_selection"], "whole_history_source_must_be_original_final_selection")
    elif action == "adopt-prepare-native-plan":
        sockets = [path for path in (Path("/run/containerd/containerd.sock"), Path("/run/k3s/containerd/containerd.sock")) if path.exists() and stat.S_ISSOCK(path.stat().st_mode) and not path.is_symlink()]
        m.require(len(sockets) == 1, "actual_local_original_minio_cri_socket_required")
        output = ensure_directory(operator, ensure_directory(operator, operator.run/"production-adoption")/"native-plan")
        # D1 r10 validates and executes the same pinned native inode through
        # /proc/self/fd. Pass the independently selected official ELF location;
        # never depend on global PATH or substitute a crictl installation.
        cri = operator.a.deployment_crictl_file
        m.require(cri is not None and cri.is_absolute() and cri.resolve(strict=True) == cri, "exact_original_official_crictl_file_required")
        info = cri.stat()
        cri_sha = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"
        m.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_mode & 0o111 and (os.name != "posix" or info.st_uid == 0) and digest(cri) == cri_sha, "exact_root_owned_official_crictl_bytes_required")
        source = save_selection(operator, "actual-native-plan-inputs.json", {"Version": "original-minio-history-native-plan-inputs.v1", "ArchiveTemplate": selected(operator, "archive-template"), "CRI": {"File": str(cri), "SHA256": cri_sha}, "CRIEndpoint": "unix://"+str(sockets[0]), "OutputDirectory": str(output)})
    else:
        source = prepare_selections(operator, initial_runtime, stages)
    value, out = operator.invoke(action, [binary, "--action", PREPARE[action], *flags, "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"]])
    if action == "adopt-prepare-inputs":
        m.require(value["Version"] == "original-first-adoption-input-receipt.v1" and value["State"] == "actual_producer_locations_bound_not_adopted_not_enabled" and value["AdoptionCommitted"] is False and value["ConfigurationEnabled"] is False and value["PageBackupCompleted"] is False, "actual_owner_input_author_receipt_required")
        operator.pin_value(value["Inputs"])
        operator.pin_value(value["DisabledInitializationQuery"])
        operator.pin_value(value["MinIORecoveryQuery"])
    return {"state": value.get("State", "actual_original_native_plan_produced"), "actual_producer_output": value, "private_receipt": str(out), "backup_ready": False, "page_backup_completed": False}


def validate_adoption(operator, value):
    m = helpers(operator)
    m.require(value.get("Version") == "original-first-adoption-production.v1" and value.get("State") == SUCCESS and value.get("HoldVerified") is True and value.get("AdoptionCommitted") is True and value.get("SourceRecoveryVerified") is True and value.get("Adoption", {}).get("Operation") and value.get("CurrentReferencesQualified") is False and value.get("ConfigurationEnabled") is False and value.get("PageBackupCompleted") is False and value.get("DisabledInitializationVerified") is True, "actual_same_process_production_adoption_and_source_recovery_required")
    initialized = value.get("DisabledInitialization")
    validate_initialization(operator, initialized)
    m.require(initialized["Epoch"] == value["Adoption"]["ExpectedEpoch"], "disabled_initialization_must_retain_original_adopted_epoch")
    material = m.load(operator.pin_value(value["ProviderResultFile"]))
    m.require(material == value.get("ProviderResult") and material.get("SQLMetadataReceipt") == value.get("RuntimeMetadata"), "actual_queried_provider_material_copy_required")


def validate_initialization(operator, value):
    helpers(operator).require(isinstance(value, dict) and value.get("State") == "disabled_v1_committed_exact_readback_dependencies_unverified" and value.get("CurrentHealth") == "unknown" and value.get("KEKAdmission") == "absent" and value.get("Result", {}).get("version") == 1 and value.get("Result", {}).get("operation_public_id"), "actual_disabled_v1_owner_readback_required_dependencies_unverified")


def query(operator):
    m = helpers(operator)
    m.require((operator.run/"adopt.send-unknown.json").exists(), "no_original_adoption_dispatch_to_query")
    binary, flags, _ = common(operator)
    issued, _ = retained(operator, "adopt-prepare-inputs")
    m.require(issued.get("Version") == "original-first-adoption-input-receipt.v1", "original_owner_authored_query_input_required")
    source = issued["DisabledInitializationQuery"]
    operator.pin_value(source)
    value, out = operator.invoke("adopt-query", [binary, "--action", "query-disabled-initialization", *flags, "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"]], repeat=True)
    validate_initialization(operator, value)
    return {"state": value["State"], "private_receipt": str(out), "source_recovery_verified": False, "backup_ready": False, "page_backup_completed": False, "resubmit_allowed": False}


def runtime_continuation(operator, initial_runtime):
    """Hand actual retained material locations to the existing runtime issuer.

    No provider reinstallation or pure-C1 E-table query after initialization.
    The existing runtime issuer still authenticates actual material and actors.
    """
    value, adoption_receipt = retained(operator, "adopt")
    validate_adoption(operator, value)
    owner = initial_runtime.InitialRuntimeStages(operator)
    m, stages = owner.m, owner.stages
    forward, publication = owner.previous_publication()
    inputs_receipt, _ = retained(operator, "adopt-prepare-inputs")
    inputs = m.decode(m.pinned(inputs_receipt["Inputs"]))
    provider = inputs["Provider"]
    m.need(provider["Core"] == owner.core_pin and provider["Forward"] == forward["grant"] and provider["Issuers"] == owner.material and provider["PublicationOwnerInputs"] == publication["owner_inputs"] and provider["Request"] == m.decode(m.pinned(owner.request_pin)) and provider["ControllerDeployment"] == owner.host["Deployment"] and provider["ControllerPodName"] == owner.host["Pod"], "actual_production_runtime_material_scope_changed")
    actual = m.decode(m.pinned(value["ProviderResultFile"]))
    initial_runtime.provider_pins(m, actual)
    original = m.decode(base64.b64decode(m.decode(m.pinned(owner.material))["Record"], validate=True))
    source = original["Issuers"]["provider_permit_delivery"]["PrivateKey"]
    m.need(actual["PermitSigningKeyFile"] == source["File"], "actual_original_delegated_permit_key_locator_required")
    raw = m.pinned(source, limit=64)
    m.need(len(raw) == 64 and base64.b64encode(raw[32:]).decode() == actual["DeliveryPin"]["issuer_public_key"], "actual_delegated_permit_signer_mismatch")
    delegated = initial_runtime.retain_bytes(m, stages.runtime_mirror()/"provider-permit-delivery.private", raw)
    stages.check_host(owner.host)
    delivered = stages.deliver_runtime_tree(owner.host)
    result = {"version": "operator-initial-provider-authorities.v1", "host": owner.host, "core": owner.core_pin, "forward": forward["grant"], "provider_source": provider["Provider"], "owner_inputs": publication["owner_inputs"], "native_receipt": value["ProviderResultFile"], "actual_producer_output": actual, "permit_signing_key": delegated, "delivered_runtime_files": delivered, "original_full_adoption": adoption_receipt, "backup_ready": False}
    # A later replay can observe different delivery diagnostics. Compare the
    # original durable material/lineage rather than rewriting its result.
    target = stages.directory/"initial-provider.result.json"
    if target.exists():
        previous = m.decode(m.read(target))
        m.need({k: v for k, v in previous.items() if k != "delivered_runtime_files"} == {k: v for k, v in result.items() if k != "delivered_runtime_files"}, "original_production_runtime_continuation_changed")
        initial_runtime.read_provider_result(m, previous)
        return previous
    stages.retain(target.name, result)
    return result


def verify_original_controller_after_adoption(operator, original):
    # Source recovery can legitimately replace business Pods. Controller-bound
    # grants still require the exact original controller full identity.
    m = helpers(operator)
    selected = m.load(operator.pin_value(original["source_selection"]))
    web, _ = operator.web_modules()
    args = operator.actual_pods(selected)
    after = operator.with_original_kube(lambda: web.r.identity(args))
    m.require(after["controller"] == original["identity"]["controller"], "controller_changed_reissue_uid_bound_grants")
    target = operator.run/"post-adoption-pod-comparison.json"
    if target.exists():
        operator.pin_value({"File": str(target), "SHA256": digest(target)})
        m.require(m.load(target) == after, "actual_post_adoption_graph_changed_retain_original_comparison")
    else:
        raw = (json.dumps(after, sort_keys=True, indent=2)+"\n").encode()
        with target.open("xb") as out:
            target.chmod(0o600)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        m.sync_dir(operator.run)


def adopt(operator):
    value, out = run(operator)
    return {"state": value["State"], "private_receipt": str(out), "page_backup_completed": False}


def run(operator):
    m = helpers(operator)
    m.require(not (operator.run/"adopt.send-unknown.json").exists(), "original_full_adoption_already_dispatched_no_resubmission")
    m.require(not (operator.run/"deployment/initial-provider-authorities.send-unknown.json").exists(), "legacy_provider_install_dispatched_cannot_reinstall_first_mixed_rows")
    original = operator.final_binding()
    operator.check_final_identity(original)
    binary, flags, stages = common(operator)
    issued, _ = retained(operator, "adopt-prepare-inputs")
    m.require(issued["Version"] == "original-first-adoption-input-receipt.v1" and issued["State"] == "actual_producer_locations_bound_not_adopted_not_enabled", "actual_owner_authored_production_input_required")
    inputs = issued["Inputs"]
    operator.pin_value(inputs)
    operator.minio_recovery_module().check_before_dispatch(operator, m.load(operator.pin_value(inputs)))
    stages.verify_api_minio_recovery_file(operator.minio_recovery_module().input_descriptor(operator))
    private = stages.issuer_private()
    operator.pin_value({"File": str(private), "SHA256": digest(private)})
    _, _, _, sql_materials = stages.common()
    action = "run-minio-metadata" if sql_materials.get("runtime_profile") == "public-runtime-c1-minio-metadata-read.v1" else "run"
    argv = [binary, "--action", action, *flags, "--issuer-private-file", private, "--issuer-private-sha256", digest(private), "--inputs-file", inputs["File"], "--inputs-sha256", inputs["SHA256"]]
    value, out = operator.invoke_complete_adoption(argv)
    validate_adoption(operator, value)
    verify_original_controller_after_adoption(operator, original)
    operator.minio_recovery_module().deliver(operator, SimpleNamespace(validate_adoption=validate_adoption), value)
    stages.verify_api_minio_recovery_file(value["MinIORecoveryProjection"]["Projection"])
    return value, out
