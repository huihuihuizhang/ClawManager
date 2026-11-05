"""Actual normal-enable owner issuers; preserve original sources and windows."""
import base64
import hashlib
import json
import os
import time
import urllib.error
from pathlib import Path

ACTIONS=("enabled-forward","enabled-publication","enabled-runtime-materials","enabled-provider-materials","enabled-provider-query","enabled-activate","enabled-query-relay-stop","enabled-query-runtime")


def pin(path):
    path=Path(path)
    return {"File":str(path),"SHA256":hashlib.sha256(path.read_bytes()).hexdigest()}


def original(op,initial_runtime):
    runtime=initial_runtime.InitialRuntimeStages(op)
    forward,publication=runtime.previous_publication()
    operation=pin(op.run/"enable-journal/operation-response.raw.json")
    op.pin_value(operation)
    return runtime,forward,publication,operation


def trusted_environment(op):
    m=op.source_helpers()
    path=op.run/"production-adoption/actual-minio-runtime-consent-selection.json"
    selected=m.load(op.pin_value(pin(path)))
    native=m.load(op.pin_value(selected["NativeReceipt"]))
    m.require(native.get("State")=="original_runtime_metadata_consent_exact_readback_sql_enrollment_not_proven" and native["Consent"]==selected["Consent"],"actual_original_consent_producer_selection_required")
    original=m.load(op.pin_value(selected["Inputs"]))["Owner"]["OriginalForward"]
    environment=dict(os.environ)
    for prefix,value in (("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE",selected["Consent"]),("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE",selected["Descriptor"]),("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT",original)):
        op.pin_value(value)
        environment[prefix+"_FILE"]=value["File"]
        environment[prefix+"_SHA256"]=value["SHA256"]
    return environment


def retained_data(op, selection):
    m = op.source_helpers()
    return m.load(op.pin_value(m.load(op.pin_value(pin(op.run/"production-adoption"/selection)))))


def enabled_provider_receipt(op):
    m = op.source_helpers()
    receipt = retained_data(op, "actual-enabled-provider-selection.json")
    actual = receipt.get("Provider", {})
    m.require(receipt.get("Version") == "original-enabled-provider-materials-result.v1" and
              receipt.get("State") == "enabled_native_capabilities_committed_readback_verified" and
              receipt.get("ConfigVersion") == 2 and
              actual.get("Version") == "original-enabled-runtime-provider-authorities-result.v1" and
              actual.get("State") == receipt["State"] and
              actual["SQLMetadataReceipt"] == {"File": "", "SHA256": ""},
              "actual_enabled_native_provider_commit_and_readback_required")
    op.pin_value(receipt["Material"])
    for key in ("MappingRecord", "MappingSignature", "GenerateFile", "UnwrapFile", "PublisherUnwrapFile", "FormalGrant", "PermitGrant"):
        op.pin_value({"File": actual[key]["File"], "SHA256": actual[key]["SHA256"]})
    m.require(actual["FormalWorkload"]["ConfigVersion"] == 2 and
              actual["FormalWorkload"]["ConfigSHA256"] == receipt["ConfigSHA256"] and
              actual["PermitWorkload"]["ConfigVersion"] == 2 and
              actual["PermitWorkload"]["ConfigSHA256"] == receipt["ConfigSHA256"] and
              actual["Generate"] != actual["Unwrap"] and actual["Unwrap"] != actual["PublisherUnwrap"],
              "distinct_actual_config2_provider_authorities_required")
    return receipt


def provider_materials(op, production, initial_runtime, query=False):
    m = op.source_helpers()
    runtime, old, _, operation = original(op, initial_runtime)
    stages = runtime.stages
    stages.check_host(runtime.host)
    binary = stages.binary("system-backup-enabled-provider-materials")
    m.require(op.pins["files"].get("bin/"+binary.name) == pin(binary)["SHA256"], "sealed_enabled_provider_owner_binary_required")
    argv = [binary, "query" if query else "issue", "--minio-metadata-profile", *op.owner_common(),
            "--runtime-dsn-file", runtime.runtime_dsn["File"]]
    selection = op.run/"production-adoption/actual-enabled-provider-inputs.json"
    if query:
        # Only the native query can recover original committed rows. No C1
        # metadata receipt or new issue inputs/Until are passed to it.
        m.require((op.run/"enabled-provider-materials.send-unknown.json").exists(), "original_enabled_provider_issue_intent_required_query_only")
        original_send = m.load(op.run/"enabled-provider-materials.send-unknown.json")
        sent = original_send.get("argv", [])
        m.require(original_send.get("stage") == "enabled-provider-materials" and sent[:2] == [str(binary), "issue"] and
                  sent.count("--inputs-file") == 1 and sent.count("--inputs-sha256") == 1, "actual_original_enabled_issue_dispatch_required")
        input_pin = {"File": sent[sent.index("--inputs-file")+1], "SHA256": sent[sent.index("--inputs-sha256")+1]}
        m.require(input_pin["File"] == str(selection), "original_enabled_provider_input_locator_changed")
        inputs = m.load(op.pin_value(input_pin))
        material = pin(Path(inputs["OutputDirectory"])/"enabled-provider.material.json")
        op.pin_value(material)
        argv += ["--material-file", material["File"], "--material-sha256", material["SHA256"]]
    else:
        previous = m.load(Path(stages.directory)/"initial-provider.result.json")
        m.require(previous["host"] == runtime.host and previous["core"] == runtime.core_pin, "same_original_provider_inputs_required")
        op.pin_value(previous["provider_source"])
        issued = op.completed("enabled-forward")
        forward = m.load(op.pin_value({"File": issued["stdout"], "SHA256": issued["stdout_sha256"]}))
        issued = op.completed("enabled-publication")
        publication = m.load(op.pin_value({"File": issued["stdout"], "SHA256": issued["stdout_sha256"]}))
        original_provider = initial_runtime.read_provider_result(runtime.m, previous)
        old_permit = original_provider["PermitGrant"]
        old_envelope = m.load(op.pin_value({"File": old_permit["File"], "SHA256": old_permit["SHA256"]}))
        old_record = json.loads(base64.b64decode(old_envelope["Record"], validate=True))
        worker = old_record["WorkerJWTIdentityFile"]
        m.require(op.a.initial_worker_jwt_identity_file is None or op.a.initial_worker_jwt_identity_file == worker,
                  "enabled_worker_identity_location_must_preserve_original_signed_locator")
        m.require(isinstance(worker, str) and worker.startswith("/") and ".." not in Path(worker).parts,
                  "actual_original_worker_projected_jwt_location_required")
        directory = production.ensure_directory(op, stages.runtime_mirror()/"enabled-provider-authorities")
        inputs = {"Version": "original-enabled-runtime-provider-inputs.v1", "EnableReceipt": operation,
                  "OriginalForward": old["grant"], "Issuers": runtime.material, "Core": runtime.core_pin,
                  "Forward": forward["Grant"], "Provider": previous["provider_source"],
                  "PublicationOwnerInputs": publication["RuntimeOwnerInputs"], "Request": m.load(op.pin_value(runtime.request_pin)),
                  "ControllerDeployment": runtime.host["Deployment"], "ControllerPodName": runtime.host["Pod"],
                  "WorkerJWTIdentityFile": worker, "OutputDirectory": str(directory), "Until": op.a.deployment_signing_until}
        selected = production.save_selection(op, selection.name, inputs)
        argv += ["--inputs-file", selected["File"], "--inputs-sha256", selected["SHA256"]]
    result, out = op.invoke("enabled-provider-query" if query else "enabled-provider-materials", argv,
                            repeat=query, env=trusted_environment(op))
    m.require(result.get("Version") == "original-enabled-provider-materials-result.v1" and
              result.get("State") == "enabled_native_capabilities_committed_readback_verified" and
              result.get("ConfigVersion") == 2, "actual_enabled_native_provider_owner_receipt_required")
    selector = op.run/"production-adoption/actual-enabled-provider-selection.json"
    if selector.exists():
        prior = enabled_provider_receipt(op)
        m.require(prior == result, "query_must_preserve_same_original_enabled_native_material")
    else:
        production.save_selection(op, selector.name, pin(out))
    actual = enabled_provider_receipt(op)
    stages.check_host(runtime.host)
    return {"state": actual["State"], "private_receipt": str(out), "backup_ready": False}


def formal_materials(op, production, initial_runtime, runtime, base):
    m = op.source_helpers()
    receipt = enabled_provider_receipt(op)
    actual = receipt["Provider"]
    previous = m.load(Path(runtime.stages.directory)/"initial-provider.result.json")
    original_provider = initial_runtime.read_provider_result(runtime.m, previous)
    m.require(previous["host"] == runtime.host and previous["core"] == runtime.core_pin and
              actual["Binding"] == original_provider["Binding"] and
              actual["MappingSource"] == original_provider["MappingSource"] and
              actual["InstallationIssuer"] == original_provider["InstallationIssuer"] and
              actual["MappingRecord"]["SHA256"] == original_provider["MappingRecord"]["SHA256"] and
              actual["MappingSignature"]["SHA256"] == original_provider["MappingSignature"]["SHA256"],
              "enabled_provider_must_preserve_original_native_mapping")
    # Reuse original delegated key BYTES, not its old config1 permit grant.
    delegated = previous["permit_signing_key"]
    raw = Path(op.pin_value(delegated)).read_bytes()
    m.require(actual["PermitSigningKeyFile"] == original_provider["PermitSigningKeyFile"] and
              len(raw) == 64 and base64.b64encode(raw[32:]).decode() == actual["DeliveryPin"]["issuer_public_key"],
              "actual_original_delegated_delivery_signer_required")
    old = m.load(op.pin_value(base["formal_verifier"]))
    formal = {"schema_version": "controller-verifier-materials.v1", "database": actual["Database"],
              "binding": actual["Binding"], "generate_capability": actual["Generate"], "unwrap_capability": actual["Unwrap"],
              "installation_issuer": actual["InstallationIssuer"], "ca_file": old["ca_file"], "jwt_file": old["jwt_file"],
              "workload": actual["FormalWorkload"], "grant": actual["FormalGrant"],
              "provider_permits": {"workload": actual["PermitWorkload"], "grant": actual["PermitGrant"],
                                   "signing_key_file": delegated["File"], "delivery_pin": actual["DeliveryPin"]}}
    directory = production.ensure_directory(op, runtime.stages.runtime_mirror()/"enabled-runtime")
    selected = initial_runtime.retain_bytes(runtime.m, directory/"formal-verifier-materials.json", runtime.m.encoded(formal))
    m.require(selected["File"] != base["formal_verifier"]["File"] and
              selected["File"] != runtime.core["formal_verifier"]["path"], "enabled_formal_bundle_must_use_new_independent_path")
    production.save_selection(op, "actual-enabled-formal-selection.json", {"Formal": selected, "ProviderMaterial": receipt["Material"],
                              "ProviderReceipt": m.load(op.pin_value(pin(op.run/"production-adoption/actual-enabled-provider-selection.json"))),
                              "OriginalFormal": base["formal_verifier"], "Host": runtime.host, "Core": runtime.core_pin})
    return selected, actual


def runtime_materials(op,production,initial_runtime):
    m=op.source_helpers()
    runtime,old,_,operation=original(op,initial_runtime)
    stages=runtime.stages
    def actual(stage):
        retained=op.completed(stage)
        return m.load(op.pin_value({"File":retained["stdout"],"SHA256":retained["stdout_sha256"]}))
    forward=actual("enabled-forward")
    publication=actual("enabled-publication")
    owner=m.load(op.pin_value(publication["RuntimeOwnerInputs"]))
    base=m.load(Path(stages.directory)/"publication-runtime.result.json")
    m.require(base["host"]==runtime.host,"same_original_runtime_material_controller_required")
    if not (op.run/"production-adoption/actual-enabled-provider-selection.json").exists():
        provider_materials(op,production,initial_runtime)
    formal,actual_provider=formal_materials(op,production,initial_runtime,runtime,base)
    sources=m.load(op.pin_value(base["runtime_sources"]))
    sources=dict(sources)
    m.require(sources["Binding"]==actual_provider["Binding"] and sources["InstallationIssuer"]==actual_provider["InstallationIssuer"],"enabled_actual_original_provider_mapping_required")
    sources["GenerateCapability"],sources["UnwrapCapability"]=actual_provider["Generate"],actual_provider["PublisherUnwrap"]
    sources["SigningRecord"],sources["SigningPin"]=owner["SigningRecord"],owner["SigningPin"]
    sources["SigningFiles"]=[{"Purpose":v["binding"]["Purpose"],"JWTFile":v["jwt_file"],"CAFile":v["ca_file"]} for v in owner["SigningMounts"]]
    sources["VerifierGrant"]=owner["PublisherGrant"]
    source=op.capture_mapping_module().encode_runtime_sources(op,sources,"enabled")
    output=production.ensure_directory(op,stages.runtime_mirror()/"enabled-publication-runtime")
    args=[stages.binary("system-backup-first-install-materials"),"issue-enabled-runtime-materials",*op.owner_common(),"--runtime-dsn-file",runtime.runtime_dsn["File"],"--source-definition-file",base["SourceDefinition"]["File"],"--source-definition-sha256",base["SourceDefinition"]["SHA256"],"--components-template-file",base["ComponentsTemplate"]["File"],"--components-template-sha256",base["ComponentsTemplate"]["SHA256"],"--runtime-sources-file",source["File"],"--runtime-sources-sha256",source["SHA256"],"--runtime-owner-inputs-file",publication["RuntimeOwnerInputs"]["File"],"--runtime-owner-inputs-sha256",publication["RuntimeOwnerInputs"]["SHA256"],"--enable-operation-file",operation["File"],"--enable-operation-sha256",operation["SHA256"],"--request-files-file",runtime.request_pin["File"],"--request-files-sha256",runtime.request_pin["SHA256"],"--enabled-forward-file",forward["Grant"]["File"],"--enabled-forward-sha256",forward["Grant"]["SHA256"],"--original-forward-file",old["grant"]["File"],"--original-forward-sha256",old["grant"]["SHA256"],"--output-signers-file",output/"publication-signers.json","--output-verifier-file",output/"publisher-verifier.json","--output-definition-file",output/"unused-source-definition.json","--output-components-file",output/"unused-source-components.json"]
    value,out=op.invoke(ACTIONS[2],args,env=trusted_environment(op))
    m.require(value.get("Version")=="original-publication-runtime-materials-result.v1" and value.get("State")=="enabled_owner_publication_materials_generated_original_sources_preserved" and value["SourceDefinition"]==base["SourceDefinition"] and value["ComponentsTemplate"]==base["ComponentsTemplate"],"actual_enabled_publication_material_readback_original_source_preserved_required")
    for name in ("Signers","Verifier"):op.pin_value(value[name])
    stages.check_host(runtime.host)
    production.save_selection(op,"actual-enabled-publication-runtime-selection.json",{"Forward":forward["Grant"],"OriginalForward":old["grant"],"Signers":value["Signers"],"Verifier":value["Verifier"],"OwnerInputs":publication["RuntimeOwnerInputs"],"NativeReceipt":pin(out),"Host":runtime.host,"Formal":formal,"ProviderMaterial":enabled_provider_receipt(op)["Material"]})
    stages.deliver_runtime_tree(runtime.host)
    return {"state":value["State"],"private_receipt":str(out),"backup_ready":False,"page_backup_completed":False}


def prepare(op,production,initial_runtime,publication=False):
    m=op.source_helpers()
    runtime,old,old_publication,operation=original(op,initial_runtime)
    stages=runtime.stages
    stages.check_host(runtime.host)
    binary=stages.binary("system-backup-first-install-materials")
    m.require(op.pins["files"]["bin/system-backup-first-install-materials"]==hashlib.sha256(binary.read_bytes()).hexdigest(),"sealed_actual_enabled_owner_cli_required")
    common=[*op.owner_common(),"--runtime-dsn-file",runtime.runtime_dsn["File"],"--core-file",runtime.core_pin["File"],"--core-sha256",runtime.core_pin["SHA256"],"--request-files-file",runtime.request_pin["File"],"--request-files-sha256",runtime.request_pin["SHA256"],"--enable-operation-file",operation["File"],"--enable-operation-sha256",operation["SHA256"]]
    if not publication:
        # Actual private original forward-purpose issuer stays in owner realm.
        signed=m.load(op.pin_value(runtime.material))
        manifest=json.loads(base64.b64decode(signed["Record"],validate=True))
        key=manifest["Issuers"]["forward_execution"]["PrivateKey"]
        op.pin_value(key)
        directory=production.ensure_directory(op,stages.runtime_mirror()/"enabled-forward")
        argv=[binary,"reissue-enabled-forward",*common,"--forward-grant-sha256",old["grant"]["SHA256"],"--execution-issuer-private-file",key["File"],"--output-directory",directory]
        value,out=op.invoke(ACTIONS[0],argv,env=trusted_environment(op))
        m.require(value.get("ConfigVersion")==2 and value.get("Version")=="original-enabled-forward-result.v1","actual_enabled_forward_owner_receipt_required")
        for name in ("Grant","Config"):op.pin_value(value[name])
    else:
        issued=op.completed(ACTIONS[0]);forward=m.load(op.pin_value({"File":issued["stdout"],"SHA256":issued["stdout_sha256"]}))
        m.require(forward.get("ConfigVersion")==2,"actual_independent_forward2_required")
        signing=m.load(Path(stages.directory)/"signing-material.result.json")
        m.require(signing["host"]==runtime.host,"same_actual_signing_controller_required")
        native=m.load(op.pin_value(signing["original_signing_receipt"]))
        material=native["Material"];op.pin_value(material)
        directory=production.ensure_directory(op,stages.runtime_mirror()/"enabled-publication")
        argv=[binary,"issue-enabled-publication-authorization",*common,"--source-issuer-private-file",stages.issuer_private(),"--controller-deployment",runtime.host["Deployment"],"--controller-pod-name",runtime.host["Pod"],"--config-file",forward["Config"]["File"],"--config-sha256",forward["Config"]["SHA256"],"--forward-grant-sha256",forward["Grant"]["SHA256"],"--enabled-forward-file",forward["Grant"]["File"],"--signing-material-file",material["File"],"--signing-material-sha256",material["SHA256"],"--output-directory",directory]
        value,out=op.invoke(ACTIONS[1],argv,env=trusted_environment(op))
        m.require(value.get("Version")=="original-publication-runtime-authorization-result.v1" and value.get("SigningPin",{}).get("Revision")==3,"actual_enabled_publication_revision3_receipt_required")
        for name in ("RuntimeOwnerInputs","SigningPinFile"):op.pin_value(value[name])
    stages.check_host(runtime.host)
    # Delivery transfers only the genuine newly produced files. It neither
    # changes the core nor starts a second controller or an enabled task.
    stages.deliver_runtime_tree(runtime.host)
    return {"state":"actual_enabled_publication_owner_issued_runtime_not_activated" if publication else "actual_enabled_forward_owner_issued_runtime_not_activated","private_receipt":str(out),"backup_ready":False,"page_backup_completed":False}


def stop_inputs(op, production, initial_runtime, runtime, operation):
    stages = runtime.stages
    production.ensure_directory(op, stages.runtime_mirror()/"normal-runtime-inputs")
    request = runtime.m.decode(runtime.m.pinned(runtime.request_pin))
    for key in ("ConfigFile", "GrantFile", "ObserverFile"):
        selected = {"File": request[key], "SHA256": request[key+"SHA256"]}
        target = initial_runtime.retain_bytes(runtime.m, stages.runtime_mirror()/"normal-runtime-inputs"/(key+".json"),
                                             Path(op.pin_value(selected)).read_bytes())
        request[key] = target["File"]
    response = initial_runtime.retain_bytes(runtime.m, stages.runtime_mirror()/"normal-runtime-inputs/enable-response.json",
                                            Path(op.pin_value(operation)).read_bytes())
    stages.deliver_runtime_tree(runtime.host)
    return request, response


def retain_native_stop(op, production, initial_runtime, runtime, value):
    m = op.source_helpers()
    m.require(value.get("Version") == "original-readonly-relay-handover-result.v1" and
              value.get("State") == "original_readonly_listener_absent_normal_runtime_not_started" and
              value.get("OriginalListenerAbsent") is True and value.get("RuntimeStarted") is False,
              "actual_native_readonly_listener_absence_required")
    for key in ("Result", "Signature"):
        selected = value[key]
        path = Path(selected["File"])
        m.require(path.is_relative_to(runtime.stages.runtime_mirror()), "actual_stop_receipt_runtime_location_required")
        production.ensure_directory(op, path.parent)
        runtime.stages.remote_pin(runtime.host, selected)
        raw = op.k("-n", "clawmanager-zhanghui08-system", "exec", runtime.host["Pod"], "-c", "installation-owner", "--", "/bin/cat", selected["File"])
        m.require(hashlib.sha256(raw).hexdigest() == selected["SHA256"], "native_stop_receipt_bytes_changed")
        saved = initial_runtime.retain_bytes(runtime.m, path, raw)
        m.require(saved == selected, "same_native_signed_stop_material_required")
    return production.save_selection(op, "actual-normal-relay-stop-selection.json", value)


def stop_readonly_for_runtime(op, production, initial_runtime, query=False):
    runtime, _, _, operation = original(op, initial_runtime)
    m = op.source_helpers()
    selected = op.run/"production-adoption/actual-normal-relay-stop-selection.json"
    if selected.exists() and not query:
        return m.load(op.pin_value(pin(selected)))
    request, response = stop_inputs(op, production, initial_runtime, runtime, operation)
    # D1 authenticates actual enabled owner/KEK admission and original process;
    # query verifies absence and never emits another signal.
    relay = op.relay_bootstrap_module()
    pki = op.c1_authors_module().actual_pki(op)
    value, _ = relay.stop_for_normal_runtime(op, production, pki, response, request, query=query)
    retain_native_stop(op, production, initial_runtime, runtime, value)
    runtime.stages.check_host(runtime.host)
    return value


def database_environment(op, production, initial_runtime, runtime):
    m = op.source_helpers()
    selected = op.run/"production-adoption/actual-controller-database-environment-selection.json"
    if selected.exists():
        result = m.load(op.pin_value(pin(selected)))
    else:
        _, enrolled, _, sql = runtime.stages.common()
        tls = dict(sql["source_tls"])
        ca = {"File": tls["ca_file"], "SHA256": tls["ca_sha256"]}
        target = initial_runtime.retain_bytes(runtime.m, runtime.stages.runtime_mirror()/"normal-runtime-database-ca.pem",
                                             Path(op.pin_value(ca)).read_bytes())
        tls["ca_file"] = target["File"]
        tls_pin = production.save_selection(op, "actual-controller-database-tls.json", tls)
        output = op.run/"production-adoption/controller-database.environment.private.json"
        result, _ = op.invoke("controller-database-environment", [runtime.stages.binary("system-backup-first-install-materials"),
                        "runtime-database-environment", "--plan-file", enrolled["Plan"]["File"], "--plan-sha256", enrolled["Plan"]["SHA256"],
                        "--runtime-dsn-file", runtime.runtime_dsn["File"], "--runtime-dsn-sha256", runtime.runtime_dsn["SHA256"],
                        "--tls-file", tls_pin["File"], "--tls-sha256", tls_pin["SHA256"], "--output-file", output])
        op.pin_value(result)
        production.save_selection(op, selected.name, result)
    value = m.load(op.pin_value(result))
    m.require(value.get("Version") == "original-runtime-database-environment.v1", "actual_driver_decoded_runtime_database_environment_required")
    return value["Environment"]


def activation_environment(op, production, initial_runtime, runtime):
    m = op.source_helpers()
    selected = m.load(op.pin_value(pin(op.run/"production-adoption/actual-enabled-publication-runtime-selection.json")))
    formal = m.load(op.pin_value(pin(op.run/"production-adoption/actual-enabled-formal-selection.json")))
    m.require(selected["Host"] == runtime.host and formal["Host"] == runtime.host and selected["Formal"] == formal["Formal"] and
              selected["ProviderMaterial"] == formal["ProviderMaterial"], "same_actual_enabled_native_formal_and_publication_sources_required")
    enabled_provider_receipt(op)
    base = m.load(Path(runtime.stages.directory)/"publication-runtime.result.json")
    recovery = m.load(op.pin_value(pin(op.run/"production-adoption/minio-recovery-preinstalled.json")))
    descriptor = m.load(op.pin_value(recovery["Descriptor"]))
    permission = {"File": descriptor["PermissionSourceFile"], "SHA256": descriptor["PermissionSourceSHA256"]}
    terminal = m.load(op.pin_value(recovery["Terminal"]))
    definition = m.load(op.pin_value({"File": terminal["DefinitionFile"], "SHA256": terminal["DefinitionSHA256"]}))
    target = {"File": definition["TargetFile"], "SHA256": definition["TargetSHA256"]}
    m.require(target["File"] == runtime.core["publication_target"]["path"], "actual_original_formal_publication_target_required")
    environment = database_environment(op, production, initial_runtime, runtime)
    environment.update({"SYSTEM_BACKUP_ENABLED": "true", "SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED": "true",
                        "SYSTEM_BACKUP_EXECUTION_PROTOCOL": "public-v1", "SYSTEM_BACKUP_CONTROLLER_ENABLED": "true",
                        "CLAWMANAGER_LEADER_ELECTION": "true", "SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID": runtime.core["installation_id"],
                        "SYSTEM_BACKUP_READINESS_MINIO_PROFILE": descriptor["PermissionProfile"],
                        "SYSTEM_BACKUP_CAPACITY_REPORT_FILE": "/run/system-backup/runtime/registration-capacity.current.json"})
    m.require(runtime.core["capacity_file"] == environment["SYSTEM_BACKUP_CAPACITY_REPORT_FILE"], "original_core_must_select_live_capacity_report")
    files = {}
    def add(source):
        op.pin_value(source)
        m.require(source["File"] not in files or files[source["File"]] == source, "actual_producer_path_hash_conflict")
        files[source["File"]] = source
    def pair(prefix, source):
        add(source)
        environment[prefix+"_FILE"], environment[prefix+"_SHA256"] = source["File"], source["SHA256"]
    pair("SYSTEM_BACKUP_PUBLIC_CONFIG", runtime.core_pin)
    pair("SYSTEM_BACKUP_FORWARD_GRANT", selected["Forward"])
    pair("SYSTEM_BACKUP_VERIFIER_MATERIALS", selected["Formal"])
    pair("SYSTEM_BACKUP_PUBLICATION_SIGNER_MATERIALS", selected["Signers"])
    pair("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS", selected["Verifier"])
    pair("SYSTEM_BACKUP_PUBLICATION_TARGET", target)
    pair("SYSTEM_BACKUP_READINESS_MINIO_SOURCE", permission)
    # Core fixes these original paths. Native startup validates the actual
    # immutable producer bytes/signatures; these are independent startup pins.
    pair("SYSTEM_BACKUP_CAPTURE_MATERIALS", pin(Path(runtime.core["capture_modules"]["path"])))
    environment["SYSTEM_BACKUP_RECOVERY_GRANT_SHA256"] = pin(Path(runtime.core["recovery_grant"]["path"]))["SHA256"]
    add(pin(Path(runtime.core["recovery_grant"]["path"])))
    add({"File": environment["DB_TLS_CA_FILE"], "SHA256": environment["DB_TLS_CA_SHA256"]})
    return environment, files


def activate_controller(op, production, initial_runtime):
    m = op.source_helpers()
    runtime, _, _, _ = original(op, initial_runtime)
    intent = op.run/"production-adoption/controller-normal-activation-intent.json"
    m.require(not intent.exists(), "normal_activation_already_sent_query_original_runtime_only")
    environment, files = activation_environment(op, production, initial_runtime, runtime)
    # Actual capacity collector remains live throughout real page capture.
    op.live_capacity_module().query(op)
    stopped = stop_readonly_for_runtime(op, production, initial_runtime)
    pki = op.c1_authors_module().actual_pki(op)
    binding = op.relay_bootstrap_module().runtime_handover_binding(op, production, pki, stopped)
    m.require(all(runtime.core.get(key) == value for key, value in binding["tls"].items()), "normal_receiver_TLS_must_equal_original_core")
    # The native handover descriptor is delivered by its actual owner helper.
    native_handover = {"File": binding["env"]["SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE"],
                       "SHA256": binding["env"]["SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_SHA256"]}
    production.ensure_directory(op, Path(native_handover["File"]).parent)
    initial_runtime.retain_bytes(runtime.m, Path(native_handover["File"]), Path(op.pin_value(binding["Inputs"])).read_bytes())
    files[native_handover["File"]] = native_handover
    environment.update(binding["env"])
    production.save_selection(op, intent.name, {"Host": runtime.host, "Stop": stopped["Result"],
                              "Handover": native_handover, "Core": runtime.core_pin, "BackupReady": False})
    # Real existing controller Pod launcher watches this exact env + ready file.
    # This is the actual start call; no new Pod/UID and no task is created here.
    started = runtime.stages.publish_controller_environment(environment, list(files.values()))
    result = query_controller_runtime(op, production, initial_runtime)
    return {"state": result["state"], "activation": started, "normal_handover": result,
            "backup_ready": False, "page_backup_completed": False}


def query_controller_runtime(op, production, initial_runtime):
    m = op.source_helpers()
    runtime, _, _, _ = original(op, initial_runtime)
    intent = m.load(op.pin_value(pin(op.run/"production-adoption/controller-normal-activation-intent.json")))
    m.require(intent["Host"] == runtime.host and intent["Core"] == runtime.core_pin, "same_original_normal_controller_required")
    stopped = m.load(op.pin_value(pin(op.run/"production-adoption/actual-normal-relay-stop-selection.json")))
    pki = op.c1_authors_module().actual_pki(op)
    deadline = time.monotonic()+30
    while True:
        try:
            result = op.relay_bootstrap_module().query_normal_runtime_handover(op, pki, stopped, runtime.host)
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            m.require(time.monotonic() < deadline, "normal_runtime_start_unconfirmed_query_same_identity_only")
            runtime.stages.check_host(runtime.host)
            time.sleep(0.25)
    runtime.stages.check_host(runtime.host)
    return result


def dispatch(op, production, initial_runtime):
    if op.a.action == "enabled-activate":
        return activate_controller(op, production, initial_runtime)
    if op.a.action == "enabled-query-runtime":
        return query_controller_runtime(op, production, initial_runtime)
    if op.a.action == "enabled-query-relay-stop":
        stopped = stop_readonly_for_runtime(op, production, initial_runtime, query=True)
        return {"state": stopped["State"], "backup_ready": False, "page_backup_completed": False}
    if op.a.action in ("enabled-provider-materials", "enabled-provider-query"):
        return provider_materials(op, production, initial_runtime, query=op.a.action == "enabled-provider-query")
    if op.a.action == "enabled-runtime-materials":
        return runtime_materials(op, production, initial_runtime)
    return prepare(op, production, initial_runtime, publication=op.a.action == "enabled-publication")
