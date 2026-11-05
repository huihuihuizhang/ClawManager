"""Consume actual original S3/relay/archive/capacity owners, then encode C1 DATA.

Every authority remains in the sealed native Go command. No input handfile,
placeholder credential, caller Passed flag or cached native observation is made.
"""
import base64
import datetime
import hashlib
import os
from pathlib import Path
import sys

ACTIONS = ("adopt-prepare-c1-s3", "adopt-query-c1-s3", "adopt-prepare-relay-pki", "adopt-query-relay-pki", "adopt-start-readonly-relay", "adopt-query-readonly-relay", "adopt-prepare-c1-definitions", "adopt-assemble-c1", "adopt-prepare-catalog-checkpoint", "adopt-query-catalog-checkpoint", "adopt-prepare-relay-runtime-trust")
S3_STATE = "original_s3_materials_issued_and_native_reobserved_not_c1_or_adoption"
DEFINITIONS_STATE = "original_native_definitions_authored_not_signed_or_adopted"


def pin(path):
    path = Path(path)
    return {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()}


def data(op, selected):
    return op.source_helpers().load(op.pin_value(selected))


def retained(op, name):
    return data(op, data(op, pin(op.run/"production-adoption"/name)))


def same_receipt(op, production, selector, value, out, fields):
    path = op.run/"production-adoption"/selector
    if path.exists():
        original = retained(op, selector)
        op.source_helpers().require(all(original[k] == value[k] for k in fields), "query_must_retain_same_original_native_material")
    else:
        production.save_selection(op, selector, pin(out))


def actual_s3(op):
    result = retained(op, "actual-c1-s3-producer-selection.json")
    op.source_helpers().require(result.get("Version") == "original-c1-s3-result.v1" and result.get("State") == S3_STATE, "actual_original_s3_native_owner_receipt_required")
    for name in ("Material", "Signature", "S3Profile", "UploadMaterials", "ChannelCredentials", "ChannelMaterial"):
        op.pin_value(result[name])
    return result


def actual_pki(op):
    result = retained(op, "actual-relay-pki-producer-selection.json")
    op.source_helpers().require(result.get("Version") == "original-relay-pki-result.v1" and result.get("State") == "original_relay_pki_material_issued_service_tls_not_yet_verified", "actual_original_relay_pki_owner_receipt_required")
    for name in ("Manifest", "Signature", "CA", "IssuerKey", "ServerCertificate", "ServerKey", "ClientCertificate", "ClientKey"):
        op.pin_value(result[name])
    return result


def definitions(op):
    result = retained(op, "actual-c1-definition-producer-selection.json")
    op.source_helpers().require(result.get("Version") == "original-c1-provider-definition-result.v1" and result.get("State") == DEFINITIONS_STATE, "actual_c1_native_definition_author_required")
    for name in ("Six", "StatusRelay", "Channel", "Store", "Credentials"):
        op.pin_value(result[name])
    return result


def private_bytes(op, production, name, raw):
    directory = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"c1-author-locations")
    target = directory/name
    if target.exists():
        op.pin_value(pin(target))
        op.source_helpers().require(target.read_bytes() == raw, "original_native_material_bytes_changed_no_replacement")
    else:
        with target.open("xb") as output:
            target.chmod(0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        op.source_helpers().sync_dir(directory)
    return pin(target)


def s3(op, production, query=False):
    m = op.source_helpers()
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    binary = stages.binary("system-backup-c1-s3-materials")
    m.require(op.pins["files"].get("bin/"+binary.name) == pin(binary)["SHA256"], "sealed_original_s3_native_owner_elf_required")
    output = production.ensure_directory(op, stages.runtime_mirror()/"original-c1-s3")
    argv = [binary, "query" if query else "issue", *op.owner_common()]
    if query:
        m.require((op.run/(ACTIONS[0]+".send-unknown.json")).exists(), "original_s3_issue_intent_required_no_reissue")
        argv += ["--output-directory", output]
    else:
        # Reuse the actual whole-history location author's provider/root/MC;
        # this writes DATA only and does not perform another native setup.
        history = data(op, production.original_minio_history_inputs(op))
        options_pin = {"File": str(op.a.deployment_minio_options_file), "SHA256": op.a.deployment_minio_options_sha256}
        options = data(op, options_pin)
        root = data(op, options["Materials"])["RootCredential"]
        op.pin_value(root)
        original = m.load(op.run/"operation.json")
        suffix = hashlib.sha256(original["operation"].encode()).hexdigest()[:20]
        until = min(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=9), datetime.datetime.fromisoformat(op.a.deployment_signing_until.replace("Z", "+00:00")))
        inputs = {"Version": "original-c1-s3-inputs.v1", "CreateFreshBuckets": True, "ProviderDefinition": history["Provider"], "RootCredential": root, "MC": {"File": history["Admin"]["MCFile"], "SHA256": history["Admin"]["MCSHA256"]}, "OutputDirectory": str(output), "UploadBucket": "sbk-c1-"+suffix+"-upload", "UploadRoot": "artifacts/", "UploadStagingRoot": "staging/", "EvidenceBucket": "sbk-c1-"+suffix+"-evidence", "EvidenceRoot": "evidence", "Until": until.replace(tzinfo=None).isoformat(timespec="microseconds").rstrip("0").rstrip(".")+"Z"}
        source = production.save_selection(op, "actual-c1-s3-inputs.json", inputs)
        issuer = pin(stages.issuer_private())
        op.pin_value(issuer)
        argv += ["--inputs-file", source["File"], "--inputs-sha256", source["SHA256"], "--issuer-private-file", issuer["File"], "--issuer-private-sha256", issuer["SHA256"]]
    value, out = op.invoke(ACTIONS[1] if query else ACTIONS[0], argv, repeat=query)
    m.require(value.get("Version") == "original-c1-s3-result.v1" and value.get("State") == S3_STATE, "actual_s3_native_positive_negative_and_cleanup_verification_required")
    for name in ("Material", "Signature", "S3Profile", "UploadMaterials", "ChannelCredentials", "ChannelMaterial"):
        op.pin_value(value[name])
    same_receipt(op, production, "actual-c1-s3-producer-selection.json", value, out, ("Material", "Signature", "S3Profile", "UploadMaterials", "ChannelMaterial", "ChannelCredentials", "ChannelPrincipal"))
    stages.check_host(host)
    return {"state": value["State"], "private_receipt": str(out), "backup_ready": False, "page_backup_completed": False}


def prepare_definitions(op, production):
    m = op.source_helpers()
    stages = op.deployment_stages()
    observed = stages.host_result()
    host = observed["host"]
    stages.check_host(host)
    pki = actual_pki(op)
    upstream = actual_s3(op)
    archive = op.archive_inputs_module().selected(op)
    material_result = m.load(stages.directory/"materials.result.json")
    m.require(material_result["host"] == host, "actual_c1_final_controller_required")
    # The actual archive observer contains the native CA bytes. The owner
    # compares this exact pin to Transit.CAPEM again; no new trust is created.
    ca = private_bytes(op, production, "archive-vault-ca.pem", base64.b64decode(archive["Vault"]["Transit"]["CAPEM"], validate=True))
    m.require(ca["SHA256"] == archive["Vault"]["Transit"]["CASHA256"], "actual_archive_vault_ca_required")
    directory = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"c1-definitions")
    value = {"Version": "original-c1-provider-definition-inputs.v1", "ArchiveMaterialDirectory": str(Path(archive["Material"]["File"]).parent), "ControllerDeployment": host["Deployment"], "ControllerPod": host["Pod"], "RelayService": observed["control_service"]["Name"], "RelayContainer": "installation-owner", "RelayEndpoint": pki["Endpoint"], "OutputDirectory": str(directory), "Config": {"File": "", "SHA256": ""}, "Deployment": material_result["Deployment"], "S3Profile": upstream["S3Profile"], "VaultCA": ca, "RelayCA": pki["CA"], "RelayCertificate": pki["ClientCertificate"], "RelayPrivateKey": pki["ClientKey"], "ChannelMaterial": upstream["ChannelMaterial"], "ChannelCredentials": upstream["ChannelCredentials"], "ChannelPrincipal": upstream["ChannelPrincipal"]}
    source = production.save_selection(op, "actual-c1-definition-inputs.json", value)
    binary = stages.binary("system-backup-c1-native-inputs")
    m.require(op.pins["files"].get("bin/"+binary.name) == pin(binary)["SHA256"], "sealed_original_c1_definition_owner_required")
    result, out = op.invoke("adopt-prepare-c1-definitions", [binary, "definitions", *op.owner_common(), "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"]])
    m.require(result.get("Version") == "original-c1-provider-definition-result.v1" and result.get("State") == DEFINITIONS_STATE, "actual_c1_native_definitions_required")
    same_receipt(op, production, "actual-c1-definition-producer-selection.json", result, out, ("Six", "StatusRelay", "Channel", "Store", "Credentials", "SixReferences", "StatusRelayReference"))
    definitions(op)
    stages.check_host(host)
    return {"state": result["State"], "private_receipt": str(out), "SixReferences": result["SixReferences"], "StatusRelayReference": result["StatusRelayReference"], "backup_ready": False}


def invocation(op):
    selected = data(op, pin(op.run/"production-adoption/actual-c1-invocation-selection.json"))
    value = data(op, selected)
    op.source_helpers().require(value.get("Version") == "original-c1-pending-runtime-invocation.v3" and value.get("PreColdHead1Directory") == "", "actual_automatic_pending_v3_input_required")
    return selected


def assemble(op, production, native):
    m = op.source_helpers()
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    refs = definitions(op)
    cap = native.capacity(op)
    c1 = op.c1_inputs_module().receipt(op)
    wrap = production.save_selection(op, "actual-archive-updated-c1-receipt.json", c1)
    signed = m.load(stages.directory/"signing-material.result.json")
    forward = m.load(stages.directory/"initial-forward.result.json")
    m.require(forward.get("version") == "operator-initial-forward.v1" and forward["host"] == signed["host"] == host, "same_final_c1_forward_signing_controller_required")
    request_pin = forward["request_files"]
    request = data(op, request_pin)
    config = data(op, {"File": request["ConfigFile"], "SHA256": request["ConfigFileSHA256"]})
    selected_refs = {r["purpose"]: r for r in config["references"]}
    m.require(all(selected_refs.get(r["purpose"]) == r for r in refs["SixReferences"]+[refs["StatusRelayReference"]]), "final_config_must_bind_real_six_and_status_relay_before_c1")
    _, terminal = op.adoption_locations_module().original_terminal(op)
    nonce = m.load(Path(op.completed("nonce-bind")["stdout"]))
    m.require(nonce.get("Version") == "original-nonce-file-mount-result.v1" and nonce.get("State") == "original-signed-current-native-readonly-mount-verified", "actual_current_nonce_mount_required")
    selected = {"request-files": request_pin, "channel": refs["Channel"], "signing-receipt": signed["original_signing_receipt"], "wrap-receipt": wrap, "materials-result": pin(stages.directory/"materials.result.json"), "store": refs["Store"], "credentials": refs["Credentials"], "capacity-config": cap["CapacityConfig"], "capacity-dsn": cap["CapacityDSN"], "capacity-tls": cap["CapacityTLS"], "six-definition": refs["Six"], "minio-definition": {"File": terminal["DefinitionFile"], "SHA256": terminal["DefinitionSHA256"]}, "status-relay-definition": refs["StatusRelay"], "nonce-binding": nonce["Binding"]}
    # Evidence CA defaults to zero pending locator. The SAME native Go C1
    # call derives it from the actual Six provider CA/Service and original
    # signed Request, then performs actual TLS evidence on its protected channel.
    path, digest = op.a.compose_evidence_ca_binding_file, op.a.compose_evidence_ca_binding_sha256
    m.require((path is None) == (digest is None), "evidence_ca_file_and_sha_must_be_selected_together")
    if path is not None:
        selected["evidence-ca-binding"] = {"File": str(path), "SHA256": digest}
    path, digest = op.a.compose_catalog_location_file, op.a.compose_catalog_location_sha256
    m.require((path is None) == (digest is None), "catalog_location_file_and_sha_must_be_selected_together")
    selected["catalog-checkpoint"] = {"File": str(path), "SHA256": digest} if path is not None else catalog_checkpoint(op, production)
    script = op.root/"scripts/system-backup-original-c1-pending-input.py"
    m.require(op.pins["files"].get("scripts/"+script.name) == pin(script)["SHA256"], "sealed_pending_v3_encoder_required")
    args = [sys.executable, "-I", "-B", script]
    for name, value in selected.items():
        op.pin_value(value)
        args += ["--"+name+"-file", value["File"]]
    args += ["--output-directory", op.run/"production-adoption/c1-pending-runtime"]
    result, out = op.invoke("adopt-assemble-c1", args)
    m.require(result.get("version") == "original-c1-pending-runtime-input-result.v3" and result.get("writer_selection") == c1["WriterSelection"] and result.get("wrap_material") == c1["Material"] and result.get("authority") is False, "actual_pending_v3_receipt_and_original_archive_material_required")
    op.pin_value(result["input"])
    production.save_selection(op, "actual-c1-invocation-selection.json", result["input"])
    stages.check_host(host)
    return {"state": "actual_original_owner_inputs_encoded_pending_v3_not_captured", "private_receipt": str(out), "input": invocation(op), "backup_ready": False, "page_backup_completed": False}


def prepare_relay_runtime_trust(op, production, relay):
    """Call the actual enrolled owner before core authoring or Forward signing.

    This receipt contains public enrollment references and existing PKI paths.
    It grants no authority, starts no receiver and never edits an existing core.
    """
    selector = op.run/"production-adoption/actual-relay-pki-producer-selection.json"
    if not selector.exists():
        # invoke records a create-only original issue intent. Unknown outcomes
        # must use the existing explicit PKI query action, never reissue here.
        result, out = relay.prepare_pki(op, production)
        same_receipt(op, production, selector.name, result, out,
                     ("Manifest", "Signature", "CA", "IssuerKey", "ServerCertificate",
                      "ServerKey", "ClientCertificate", "ClientKey", "DeploymentUID",
                      "ServiceUID", "Endpoint"))
    pki = actual_pki(op)
    # Always call the owner: it rechecks the current host and exact native files.
    fields = relay.prepare_normal_runtime_trust(op, production, pki)
    op.source_helpers().require(set(fields) == {"original_relay_enrollment", "control_url", "tls"},
                                "actual_relay_precore_owner_fields_required")
    value = {"Version": "original-relay-precore-trust-selection.v1",
             "PKI": {key: pki[key] for key in ("Manifest", "Signature", "CA", "IssuerKey",
                       "ServerCertificate", "ServerKey", "DeploymentUID", "ServiceUID", "Endpoint")},
             "CoreFields": fields}
    receipt = production.save_selection(op, "actual-relay-precore-trust.json", value)
    production.save_selection(op, "actual-relay-precore-trust-selection.json", receipt)
    op.a.initial_relay_runtime_trust_file = Path(receipt["File"])
    op.a.initial_relay_runtime_trust_sha256 = receipt["SHA256"]
    return value


def core_relay_fields(op, production, relay):
    """Initial source author calls this while constructing a NEW core value."""
    selected = prepare_relay_runtime_trust(op, production, relay)
    fields = selected["CoreFields"]
    return {"original_relay_enrollment": fields["original_relay_enrollment"],
            "control_url": fields["control_url"], **fields["tls"],
            "issuer_certificate_sha256": selected["PKI"]["CA"]["SHA256"]}


def validate_core_relay_trust(op, selected):
    """Refuse a stale core BEFORE any native Forward/publication invocation."""
    m = op.source_helpers()
    core = data(op, {"File": str(op.a.owner_core_file), "SHA256": op.a.owner_core_sha256})
    fields = selected["CoreFields"]
    m.require(core.get("original_relay_enrollment") == fields["original_relay_enrollment"] and
              core.get("control_url") == fields["control_url"] and
              all(core.get(key) == value for key, value in fields["tls"].items()) and
              core.get("issuer_certificate_sha256") == selected["PKI"]["CA"]["SHA256"],
              "original_core_must_bind_actual_enrolled_relay_trust_before_forward_signing")


def dispatch(op, production, relay, native):
    action = op.a.action
    op.source_helpers().require(action in ACTIONS and not (op.run/"adopt.send-unknown.json").exists(), "c1_authoring_must_precede_original_capture")
    if action == "adopt-prepare-relay-runtime-trust":
        result = prepare_relay_runtime_trust(op, production, relay)
        return {"state": "actual_enrolled_relay_trust_selected_before_core_hashing", "selection": pin(op.run/"production-adoption/actual-relay-precore-trust.json"), "backup_ready": False}
    if action in ("adopt-prepare-catalog-checkpoint", "adopt-query-catalog-checkpoint"):
        selected = catalog_checkpoint(op, production, query=action == "adopt-query-catalog-checkpoint")
        return {"state": "original_catalog_location_selected_native_c1_recheck_required", "location": selected, "backup_ready": False}
    if action in ACTIONS[:2]:
        return s3(op, production, query=action == ACTIONS[1])
    if action in ("adopt-prepare-relay-pki", "adopt-query-relay-pki"):
        query = action == "adopt-query-relay-pki"
        if query:
            op.source_helpers().require((op.run/"adopt-prepare-relay-pki.send-unknown.json").exists(), "original_pki_issue_intent_required_query_only")
        result, out = relay.prepare_pki(op, production, query=query)
        same_receipt(op, production, "actual-relay-pki-producer-selection.json", result, out, ("Manifest", "Signature", "CA", "IssuerKey", "ServerCertificate", "ServerKey", "ClientCertificate", "ClientKey", "DeploymentUID", "ServiceUID", "Endpoint"))
        prepare_relay_runtime_trust(op, production, relay)
        return {"state": result["State"], "private_receipt": str(out), "backup_ready": False}
    if action == "adopt-start-readonly-relay":
        result = relay.start_readonly(op, production, actual_pki(op), native.capacity(op))
        production.save_selection(op, "actual-readonly-relay-start-result.json", result)
        return result
    if action == "adopt-query-readonly-relay":
        return relay.query_readonly(op, production, actual_pki(op))
    if action == "adopt-prepare-c1-definitions":
        return prepare_definitions(op, production)
    return assemble(op, production, native)


def catalog_location(op, selected):
    value = data(op, selected)
    op.source_helpers().require(value.get("Version") == "original-catalog-initial-inventory-location.v1" and value.get("VersionID") not in (None, "", "null", "latest", "current"), "actual_native_initial_catalog_location_required")
    op.pin_value({"File": value["EnvelopeFile"], "SHA256": value["EnvelopeSHA256"]})
    return value


def catalog_checkpoint(op, production, query=False):
    m = op.source_helpers()
    selector = op.run/"production-adoption/actual-catalog-initial-location-selection.json"
    if selector.exists() and not query:
        selected = data(op, pin(selector))
        catalog_location(op, selected)
        return selected
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "initial_catalog_authoring_after_adoption_forbidden")
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    _, terminal = op.adoption_locations_module().original_terminal(op)
    definition = {"File": terminal["DefinitionFile"], "SHA256": terminal["DefinitionSHA256"]}
    op.pin_value(definition)
    binary = stages.binary("system-backup-minio-catalog-initial")
    m.require(op.pins["files"].get("bin/"+binary.name) == pin(binary)["SHA256"], "sealed_actual_catalog_initial_owner_required")
    base = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"catalog-initial-inventory")
    capture_dir = production.ensure_directory(op, base/"capture")
    envelope_selection = op.run/"production-adoption/actual-catalog-initial-envelope-selection.json"
    capture_stage = "adopt-capture-catalog-inventory"
    publish_stage = "adopt-publish-catalog-inventory"
    common = [*op.owner_common(), "--definition-file", definition["File"], "--definition-sha256", definition["SHA256"]]
    if envelope_selection.exists():
        envelope = data(op, pin(envelope_selection))
        op.pin_value(envelope)
    elif (op.run/(capture_stage+".send-unknown.json")).exists():
        # Retain the exact signed ORIGINAL envelope when its stdout was lost.
        # The real native publish/query owner verifies that original signature,
        # target, full definition, native window and actual object readback.
        source = capture_dir/"catalog-initial-inventory.envelope.json"
        m.require(source.is_file(), "catalog_capture_unknown_no_original_signed_envelope_do_not_recapture")
        envelope = pin(source)
        op.pin_value(envelope)
        production.save_selection(op, envelope_selection.name, envelope)
    else:
        m.require(not query, "no_original_catalog_capture_to_query")
        history = data(op, production.original_minio_history_inputs(op))
        original_issuer = stages.issuer_private()
        result, out = op.invoke(capture_stage, [binary, "capture", *common, "--output-directory", capture_dir, "--admin-user-file", history["Admin"]["UserFile"], "--admin-password-file", history["Admin"]["PasswordFile"], "--issuer-private-file", original_issuer])
        m.require(set(result) == {"File", "SHA256"}, "actual_catalog_native_signed_capture_output_required")
        envelope = result
        op.pin_value(envelope)
        production.save_selection(op, envelope_selection.name, envelope)
    if query:
        m.require((op.run/(publish_stage+".send-unknown.json")).exists(), "original_catalog_publish_intent_required_readonly_query")
        import secrets
        output = production.ensure_directory(op, base/("query-"+secrets.token_hex(8)))
        stage, action = "adopt-query-catalog-inventory", "query"
    else:
        m.require(not (op.run/(publish_stage+".send-unknown.json")).exists(), "catalog_publish_unknown_query_original_no_republish")
        output = production.ensure_directory(op, base/"publish")
        stage, action = publish_stage, "publish"
    result, out = op.invoke(stage, [binary, action, *common, "--output-directory", output, "--envelope-file", envelope["File"], "--envelope-sha256", envelope["SHA256"]], repeat=query)
    m.require(set(result) == {"File", "SHA256"}, "actual_catalog_native_versioned_readback_output_required")
    current = catalog_location(op, result)
    m.require(current["DefinitionSHA256"] == definition["SHA256"] and current["EnvelopeFile"] == envelope["File"] and current["EnvelopeSHA256"] == envelope["SHA256"], "same_original_signed_catalog_inventory_required")
    if selector.exists():
        original = data(op, pin(selector))
        m.require(catalog_location(op, original) == current, "query_must_retain_exact_original_catalog_object_version")
        result = original
    else:
        production.save_selection(op, selector.name, result)
    stages.check_host(host)
    return result
