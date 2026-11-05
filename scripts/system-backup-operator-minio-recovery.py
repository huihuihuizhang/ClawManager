"""Actual owner descriptor preparation and readonly original recovery delivery.

The descriptor/terminal files are location DATA. Actor and SQL declarations
come from D1's authenticated actual producer; only A verifies authority.
"""
import hashlib
import json
from pathlib import Path

BINARY = "system-backup-first-adoption-production"
DESCRIPTOR_VERSION = "original-minio-whole-cold-resource-locator.v1"
DESCRIPTOR_STATE = "actual_original_sql_actor_pinned_future_projection_not_issued"
PROJECTION_VERSION = "original-minio-whole-cold-resource-succession.v1"
PROJECTION_STATE = "original_whole_cold_history_projection_exact_readback_not_current_health"
ACTIONS = ("adopt-preinstall-minio-recovery", "adopt-query-minio-recovery", "adopt-deliver-minio-recovery")


def register_arguments(parser):
    parser.add_argument("--adoption-minio-terminal-file", type=Path)
    parser.add_argument("--adoption-minio-terminal-sha256")


def h(op):
    return op.source_helpers()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pinned(op, value):
    return op.pin_value(value)


def read_stage(op, name):
    receipt = op.completed(name)
    pin = {"File": receipt["stdout"], "SHA256": receipt["stdout_sha256"]}
    return h(op).load(pinned(op, pin)), pin


def producer(op):
    stages = op.deployment_stages()
    binary = stages.binary(BINARY)
    h(op).require(op.pins["files"]["bin/"+BINARY] == digest(binary), "sealed_original_minio_descriptor_owner_elf_required")
    return binary, op.owner_common(), stages


def prepared_selection(op):
    path = op.run/"production-adoption/actual-minio-recovery-selection.json"
    return h(op).load(pinned(op, {"File": str(path), "SHA256": digest(path)}))


def terminal_pin(op):
    file, sha = op.a.adoption_minio_terminal_file, op.a.adoption_minio_terminal_sha256
    h(op).require((file is None) == (sha is None), "original_minio_terminal_file_pin_pair_required")
    if file is None:
        file, sha = op.a.compose_minio_input_file, op.a.compose_minio_input_sha256
    h(op).require(file is not None and sha is not None, "actual_original_minio_terminal_producer_file_required")
    value = {"File": str(file), "SHA256": sha}
    pinned(op, value)
    return value


def prepare_descriptor(op, production):
    m = h(op)
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "minio_locator_must_be_preinstalled_before_original_adoption_dispatch")
    original_pin = terminal_pin(op)
    original = m.load(pinned(op, original_pin))
    m.require(original.get("RecoverySource") is None and isinstance(original.get("Pin"), dict), "actual_original_terminal_without_recovery_locator_required")
    permission = original["PermissionSource"]
    pinned(op, permission)
    _, _, stages = producer(op)
    directory = production.ensure_directory(op, stages.runtime_mirror()/"minio-recovery")
    # Copy only actual native producer DATA. The Go owner authenticates this
    # exact SQL trust pin and independently obtains g.Actor/definition/profile.
    sql_pin = production.save_selection(op, "actual-minio-original-sql-trust-pin.json", original["Pin"])
    inputs = production.save_selection(op, "actual-minio-recovery-descriptor-inputs.json", {"Version": "original-minio-recovery-descriptor-inputs.v1", "SQLTrustPin": sql_pin, "PermissionSource": permission, "OutputDirectory": str(directory), "ProjectionFile": str(directory/"original-minio-recovery.signed.json")})
    production.save_selection(op, "actual-minio-recovery-selection.json", {"OriginalTerminal": original_pin, "Inputs": inputs})
    binary, flags, _ = producer(op)
    value, out = op.invoke("adopt-prepare-recovery-descriptor", [binary, "--action", "prepare-recovery-descriptor", *flags, "--inputs-file", inputs["File"], "--inputs-sha256", inputs["SHA256"]])
    m.require(value.get("Version") == DESCRIPTOR_VERSION and value.get("State") == DESCRIPTOR_STATE, "actual_owner_sql_actor_descriptor_receipt_required")
    pinned(op, value["Descriptor"])
    installed = preinstall(op, production)
    return {"state": DESCRIPTOR_STATE, "private_receipt": str(out), "preinstall": installed, "backup_ready": False, "page_backup_completed": False}


def preinstall(op, production):
    m = h(op)
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "minio_locator_cannot_be_added_after_original_adoption_dispatch")
    selection = prepared_selection(op)
    original = m.load(pinned(op, selection["OriginalTerminal"]))
    issued, native_receipt = read_stage(op, "adopt-prepare-recovery-descriptor")
    m.require(issued.get("Version") == DESCRIPTOR_VERSION and issued.get("State") == DESCRIPTOR_STATE, "actual_original_descriptor_owner_receipt_required")
    descriptor_pin = issued["Descriptor"]
    descriptor = m.load(pinned(op, descriptor_pin))
    inputs = m.load(pinned(op, selection["Inputs"]))
    actor = descriptor.get("Actor", {})
    m.require(descriptor["Version"] == DESCRIPTOR_VERSION and descriptor["Pin"] == original["Pin"] and descriptor["DefinitionSHA256"] == original["DefinitionSHA256"] and descriptor["PermissionSourceFile"] == original["PermissionSource"]["File"] and descriptor["PermissionSourceSHA256"] == original["PermissionSource"]["SHA256"] and descriptor["ProjectionFile"] == inputs["ProjectionFile"] and actor.get("LocalAdminUserID", 0) > 0 and actor.get("LocalAdminUsername") and actor.get("InstallerDatabaseAccount"), "actual_original_sql_actor_and_terminal_descriptor_locations_required")
    m.require(not Path(descriptor["ProjectionFile"]).exists(), "future_original_minio_projection_must_not_be_fabricated_before_cold")
    # A deliberately excludes RecoverySource from the old terminal-binding
    # hash. Add its real descriptor location to a NEW typed DATA input only.
    terminal = dict(original)
    terminal["RecoverySource"] = descriptor_pin
    terminal_output = production.save_selection(op, "original-minio-terminal-with-recovery.json", terminal)
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    root = stages.runtime_mirror()
    m.require(Path(descriptor_pin["File"]).is_relative_to(root) and Path(descriptor["ProjectionFile"]).is_relative_to(root), "minio_recovery_files_must_use_original_readonly_runtime_mount")
    delivered = stages.deliver_runtime_tree(host)
    stages.remote_pin(host, descriptor_pin)
    result = {"Version": "operator-original-minio-recovery-preinstall.v1", "OriginalTerminal": selection["OriginalTerminal"], "Descriptor": descriptor_pin, "Terminal": terminal_output, "NativeDescriptorReceipt": native_receipt, "ProjectionFile": descriptor["ProjectionFile"], "Host": host, "DeliveredRuntimeFiles": delivered, "BackupReady": False}
    pin = production.save_selection(op, "minio-recovery-preinstalled.json", result)
    return {"state": "actual_original_descriptor_delivered_projection_not_issued", "preinstall": pin, "descriptor": descriptor_pin, "terminal": terminal_output, "backup_ready": False}


def installed(op):
    path = op.run/"production-adoption/minio-recovery-preinstalled.json"
    value = h(op).load(pinned(op, {"File": str(path), "SHA256": digest(path)}))
    h(op).require(value.get("Version") == "operator-original-minio-recovery-preinstall.v1" and value.get("BackupReady") is False, "actual_pre_cold_minio_locator_preinstall_required")
    issued = h(op).load(pinned(op, value["NativeDescriptorReceipt"]))
    h(op).require(issued.get("Version") == DESCRIPTOR_VERSION and issued.get("State") == DESCRIPTOR_STATE and issued["Descriptor"] == value["Descriptor"], "original_minio_descriptor_producer_changed")
    pinned(op, value["Descriptor"])
    pinned(op, value["Terminal"])
    return value


def input_descriptor(op):
    return installed(op)["Descriptor"]


def check_before_dispatch(op, inputs):
    value = installed(op)
    h(op).require(inputs["MinIORecoveryDescriptor"] == value["Descriptor"], "production_must_use_preinstalled_original_minio_descriptor")
    descriptor = h(op).load(pinned(op, value["Descriptor"]))
    h(op).require(not Path(descriptor["ProjectionFile"]).exists(), "no_projection_or_second_capture_before_first_original_dispatch")
    stages = op.deployment_stages()
    stages.check_host(value["Host"])
    stages.remote_pin(value["Host"], value["Descriptor"])


def bind_terminal_argument(op):
    value = installed(op)
    file, sha = op.a.compose_minio_input_file, op.a.compose_minio_input_sha256
    if file is not None or sha is not None:
        h(op).require({"File": str(file), "SHA256": sha} in (value["OriginalTerminal"], value["Terminal"]), "same_original_terminal_must_select_preinstalled_descriptor")
    op.a.compose_minio_input_file = Path(value["Terminal"]["File"])
    op.a.compose_minio_input_sha256 = value["Terminal"]["SHA256"]


def deliver(op, production, value=None):
    if value is None:
        value, _ = read_stage(op, "adopt")
    production.validate_adoption(op, value)
    preinstalled = installed(op)
    issued, _ = read_stage(op, "adopt-prepare-inputs")
    inputs = h(op).load(pinned(op, issued["Inputs"]))
    h(op).require(inputs["MinIORecoveryDescriptor"] == preinstalled["Descriptor"], "actual_adoption_used_different_minio_descriptor")
    receipt = value.get("MinIORecoveryProjection")
    h(op).require(isinstance(receipt, dict) and receipt.get("Version") == PROJECTION_VERSION and receipt.get("State") == PROJECTION_STATE, "actual_sealed_whole_cold_owner_projection_required")
    projection = receipt["Projection"]
    h(op).require(projection["File"] == preinstalled["ProjectionFile"], "signed_projection_must_use_preinstalled_original_path")
    pinned(op, projection)
    stages = op.deployment_stages()
    host = preinstalled["Host"]
    stages.check_host(host)
    delivered = stages.deliver_runtime_tree(host)
    stages.remote_pin(host, preinstalled["Descriptor"])
    stages.remote_pin(host, projection)
    return {"state": "actual_original_signed_minio_projection_delivered_not_current_health", "descriptor": preinstalled["Descriptor"], "projection": projection, "delivered_runtime_files": delivered, "backup_ready": False, "page_backup_completed": False}


def query(op):
    h(op).require((op.run/"adopt.send-unknown.json").exists(), "no_original_adoption_dispatch_to_query")
    issued, _ = read_stage(op, "adopt-prepare-inputs")
    source = issued["MinIORecoveryQuery"]
    pinned(op, source)
    binary, flags, _ = producer(op)
    value, out = op.invoke("adopt-query-minio-recovery", [binary, "--action", "query-minio-recovery", *flags, "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"]], repeat=True)
    h(op).require(value.get("Version") == PROJECTION_VERSION and value.get("State") == PROJECTION_STATE, "original_owner_minio_projection_query_required")
    pinned(op, value["Projection"])
    return {"state": value["State"], "private_receipt": str(out), "backup_ready": False, "page_backup_completed": False, "resubmit_allowed": False}


def dispatch(op, action, production):
    if action == "adopt-preinstall-minio-recovery":
        return preinstall(op, production)
    if action == "adopt-query-minio-recovery":
        return query(op)
    h(op).require(action == "adopt-deliver-minio-recovery", "fixed_original_minio_recovery_action_required")
    return deliver(op, production)
