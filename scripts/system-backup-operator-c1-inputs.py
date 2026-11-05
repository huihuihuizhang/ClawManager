"""Real pre-C1 evidence material command and retained operational locations.

These receipts do not authorize archive decrypt or a capture. The real owner
producer authenticates the original enrollment and performs every native write.
"""
import datetime
import hashlib
from pathlib import Path

ACTIONS = ("adopt-prepare-c1-evidence-material", "adopt-query-c1-evidence-material")
VERSION = "original-c1-evidence-material-result.v1"
SUCCESS = "original_dedicated_evidence_materials_issued_not_producer_or_adoption"
QUERY_SUCCESS = "original_dedicated_evidence_materials_current_original_files_verified"


def register_arguments(parser):
    parser.add_argument("--adoption-c1-material-seconds", type=int, default=480)


def data(op, pin):
    return op.source_helpers().load(op.pin_value(pin))


def output_directory(op, production):
    return production.ensure_directory(op, op.deployment_stages().runtime_mirror()/"initial-c1-evidence")


def receipt(op,include_archive=True):
    archive=op.run/"production-adoption/actual-archive-evidence-producer-selection.json"
    if include_archive and archive.exists():
        return op.archive_inputs_module().selected(op)["C1"]
    path = op.run/"production-adoption/actual-c1-evidence-producer-selection.json"
    selected = data(op, {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()})
    value = data(op, selected)
    op.source_helpers().require(value.get("Version") == VERSION and value.get("State") in (SUCCESS, QUERY_SUCCESS), "actual_c1_evidence_native_owner_material_required")
    for name in ("Material", "Signature", "InstalledObserver", "WriterSelection"):
        op.pin_value(value[name])
    return value


def writer_selection(op):
    # Consume the real producer's updated Vault observer. The original writer
    # selection does not include the newly installed dedicated evidence key.
    return receipt(op)["WriterSelection"]


def prepare(op, production, query=False):
    m = op.source_helpers()
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "c1_material_preparation_after_adoption_dispatch_forbidden")
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    binary = stages.binary("system-backup-first-install-materials")
    m.require(op.pins["files"]["bin/system-backup-first-install-materials"] == hashlib.sha256(binary.read_bytes()).hexdigest(), "sealed_original_c1_material_owner_elf_required")
    directory = output_directory(op, production)
    action = "query-initial-c1-evidence-material" if query else "issue-initial-c1-evidence-material"
    args = [binary, action, *op.owner_common(), "--output-directory", directory]
    if query:
        m.require((op.run/(ACTIONS[0]+".send-unknown.json")).exists(), "query_only_original_c1_material_dispatch_required")
    else:
        writer = op.final_binding()["writer_selection"]
        op.pin_value(writer)
        seconds = op.a.adoption_c1_material_seconds
        m.require(1 <= seconds <= 480, "bounded_pre_c1_evidence_material_lifetime_required")
        deadline = datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=seconds)
        # This is only a requested operational deadline. Actual SQL time,
        # enrollment and every original native window are enforced by Go.
        for original in (op.a.deployment_signing_until,):
            m.require(isinstance(original, str) and original.endswith("Z"), "retain_original_c1_source_deadline_required")
            deadline = min(deadline, datetime.datetime.fromisoformat(original[:-1]+"+00:00"))
        until = deadline.isoformat(timespec="microseconds").replace("+00:00", "Z")
        owner = op.a.deployment_vault_owner_material_file
        if owner is None:
            m.require(op.a.deployment_vault_state_directory is not None, "actual_original_vault_owner_directory_required")
            owner = op.a.deployment_vault_state_directory/"init-material.json"
        owner = Path(owner)
        owner_pin = {"File": str(owner), "SHA256": hashlib.sha256(owner.read_bytes()).hexdigest()}
        op.pin_value(owner_pin)
        args += ["--writer-selection-file", writer["File"], "--writer-selection-sha256", writer["SHA256"], "--vault-owner-material-file", owner_pin["File"], "--vault-owner-material-sha256", owner_pin["SHA256"], "--vault-owner-material-is-init-json=true", "--source-issuer-private-file", stages.issuer_private(), "--controller-deployment", host["Deployment"], "--controller-pod-name", host["Pod"], "--until", until]
    value, out = op.invoke(ACTIONS[1] if query else ACTIONS[0], args, repeat=query)
    m.require(value.get("Version") == VERSION and value.get("State") == (QUERY_SUCCESS if query else SUCCESS), "actual_dedicated_evidence_material_native_producer_receipt_required")
    for name in ("Material", "Signature", "InstalledObserver", "WriterSelection"):
        op.pin_value(value[name])
    stages.check_host(host)
    path = op.run/"production-adoption/actual-c1-evidence-producer-selection.json"
    if path.exists():
        original = receipt(op)
        m.require(all(original[name] == value[name] for name in ("Material", "Signature", "InstalledObserver", "WriterSelection", "Key")), "query_must_read_same_original_c1_material_no_replacement")
    else:
        production.save_selection(op, path.name, {"File": str(out), "SHA256": hashlib.sha256(out.read_bytes()).hexdigest()})
    return {"state": value["State"], "actual_producer_output": value, "private_receipt": str(out), "backup_ready": False, "archive_decrypt_qualified": False, "page_backup_completed": False}
