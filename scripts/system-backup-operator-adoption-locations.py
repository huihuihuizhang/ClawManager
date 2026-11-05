"""Author operational DATA from retained original producer bytes.

No census/coverage/observer DTO is emitted. Actual Go owner/native producers
still authenticate every source and perform every live observation themselves.
"""
import base64
import hashlib
import os
from pathlib import Path
import stat

MC_SHA = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"


def register_arguments(parser):
    parser.add_argument("--adoption-mc-file", type=Path)


def h(op):
    return op.source_helpers()


def data(op, pin):
    return h(op).load(op.pin_value(pin))


def private_bytes(op, production, name, raw):
    directory = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"original-minio-admin")
    path = directory/name
    if path.exists():
        op.pin_value({"File": str(path), "SHA256": hashlib.sha256(raw).hexdigest()})
        h(op).require(path.read_bytes() == raw, "original_minio_admin_bytes_changed_no_replacement")
    else:
        with path.open("xb") as target:
            path.chmod(0o600)
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        h(op).sync_dir(directory)
    return {"File": str(path), "SHA256": hashlib.sha256(raw).hexdigest()}


def original_terminal(op):
    # This is an existing original native/SQL MinIO producer input used by
    # composition, not one of the three formerly caller-authored new files.
    file, sha = op.a.compose_minio_input_file, op.a.compose_minio_input_sha256
    h(op).require(file is not None and sha is not None, "actual_original_minio_composition_producer_required")
    pin = {"File": str(file), "SHA256": sha}
    return pin, data(op, pin)


def minio_history_inputs(op, production):
    m = h(op)
    binding = op.final_binding()
    source_selection = binding["source_selection"]
    op.pin_value(source_selection)
    writer = data(op, binding["writer_selection"])
    m.require(isinstance(writer.get("Policy"), dict), "actual_original_writer_gate_policy_required")
    _, terminal = original_terminal(op)
    definition_pin = {"File": terminal["DefinitionFile"], "SHA256": terminal["DefinitionSHA256"]}
    definition = data(op, definition_pin)
    grant = definition["Grant"]
    # Copy the same actual original definition's provider DATA. Go's actual
    # owner/native source compares it to real selection/TLS/Kube/MinIO state.
    provider = {"Version": "original-minio-source-provider-input.v1", "Installation": grant["Installation"], "Namespace": grant["Namespace"], "NamespaceUID": grant["NamespaceUID"], "Provider": grant["Provider"]}
    provider_pin = production.save_selection(op, "actual-minio-whole-history-provider.json", provider)
    file, sha = op.a.deployment_minio_options_file, op.a.deployment_minio_options_sha256
    m.require(file is not None and sha is not None, "actual_original_minio_material_delivery_options_required")
    options_pin = {"File": str(file), "SHA256": sha}
    options = data(op, options_pin)
    m.require(options.get("Version") == "formal-minio-material-delivery-input.v1", "actual_formal_minio_material_options_required")
    material = data(op, options["Materials"])
    m.require(material.get("Version") == "original-minio-source-read-materials.v1", "actual_original_native_root_credential_materials_required")
    root = data(op, material["RootCredential"])
    user, encoded = root["AccessKey"], root["SecretKey"]
    m.require(isinstance(user, str) and isinstance(encoded, str), "actual_original_minio_admin_credential_shape_required")
    secret = base64.b64decode(encoded, validate=True)
    user_raw = user.encode()
    m.require(0 < len(user_raw) <= 1024 and 0 < len(secret) <= 4096, "bounded_actual_original_minio_admin_files_required")
    m.require(not any(byte in user_raw or byte in secret for byte in (b"\x00", b"\r", b"\n")), "native_original_minio_credential_bytes_required")
    # Preserve original bytes only in create-only private files; never put
    # credentials in argv, JSON receipts, public output, environment or logs.
    user_pin = private_bytes(op, production, "original-user.private", user_raw)
    secret_pin = private_bytes(op, production, "original-password.private", secret)
    del secret, encoded, root, material
    mc = op.a.adoption_mc_file or op.root/"tools/mc"
    m.require(mc.is_absolute() and mc.resolve(strict=True) == mc and hashlib.sha256(mc.read_bytes()).hexdigest() == MC_SHA, "exact_original_mc_release_bytes_required")
    info = mc.stat()
    m.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_mode & 0o111 and (os.name != "posix" or info.st_uid == 0), "exact_root_owned_executable_mc_required")
    m.require(op.pins["files"].get("tools/mc") == MC_SHA, "original_mc_must_be_in_sealed_release")
    directory = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"whole-history-materials")
    value = {"Version": "original-minio-whole-history-setup-inputs.v1", "SourceSelection": source_selection, "Provider": provider_pin, "OutputDirectory": str(directory), "Policy": writer["Policy"], "Admin": {"UserFile": user_pin["File"], "PasswordFile": secret_pin["File"], "MCFile": str(mc), "MCSHA256": MC_SHA}}
    pin = production.save_selection(op, "actual-minio-whole-history-setup-inputs.json", value)
    production.save_selection(op, "actual-minio-whole-history-author-lineage.json", {"Definition": definition_pin, "OriginalOptions": options_pin, "SourceSelection": source_selection, "WriterSelection": binding["writer_selection"], "Inputs": pin, "BackupReady": False})
    return pin
