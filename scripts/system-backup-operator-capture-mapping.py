"""Concrete original capture DATA/native factory calls; no authority in JSON."""
import hashlib
from pathlib import Path
import urllib.parse

ACTIONS = ("initial-capture-inputs", "initial-capture-mappings")
SCHEMA = "contracts/system-backup/v12/schema-registry.json"
SCHEMA_SHA = "e8670002f637508955e0eb19350fa17abee0976153e6ca8c2c02055808b83a36"


def pin(path):
    path = Path(path)
    return {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()}


def data(op, selected):
    return op.source_helpers().load(op.pin_value(selected))


def completed(op, stage):
    receipt = op.completed(stage)
    selected = {"File": receipt["stdout"], "SHA256": receipt["stdout_sha256"]}
    return data(op, selected), selected


def bind(op, prefix, selected):
    m = op.source_helpers()
    op.pin_value(selected)
    file, sha = getattr(op.a, prefix+"_file", None), getattr(op.a, prefix+"_sha256", None)
    m.require(file is None or str(file) == selected["File"], "original_capture_input_file_selector_conflict")
    m.require(sha is None or sha == selected["SHA256"], "original_capture_input_hash_selector_conflict")
    setattr(op.a, prefix+"_file", Path(selected["File"]))
    setattr(op.a, prefix+"_sha256", selected["SHA256"])


def encode_runtime_sources(op, value, phase):
    m = op.source_helpers()
    m.require(phase in ("initial", "enabled"), "finite_original_runtime_source_phase_required")
    production = op.production_adoption_module()
    stage = phase+"-runtime-source-go-encoding"
    if (op.run/(stage+".readback.json")).exists():
        result, _ = completed(op, stage)
        op.pin_value(result)
        return result
    source = production.save_selection(op, phase+"-runtime-source-encoding-inputs.json", value)
    directory = production.ensure_directory(op, op.deployment_stages().runtime_mirror()/"original-runtime-sources")
    result, _ = op.invoke(stage, [op.deployment_stages().binary("system-backup-first-install-materials"),
        "encode-publication-runtime-sources", "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"],
        "--output-file", directory/(phase+"-runtime-sources.json")])
    op.pin_value(result)
    return result


def prepare_inputs(op, production, initial_runtime):
    m = op.source_helpers()
    selected_file = op.run/"production-adoption/actual-initial-capture-input-selection.json"
    if selected_file.exists():
        selected = data(op, data(op, pin(selected_file)))
        bind(op, "owner_source_definition", selected["SourceDefinition"])
        bind(op, "owner_components", selected["ComponentsTemplate"])
        return selected
    if op.a.owner_source_definition_file is not None or op.a.owner_components_file is not None:
        m.require(op.a.owner_source_definition_file is not None and op.a.owner_source_definition_sha256 and
                  op.a.owner_components_file is not None and op.a.owner_components_sha256,
                  "complete_original_capture_definition_components_pairs_required")
        # Existing independently selected native complete inputs remain valid;
        # this compatibility path does not manufacture future DB/native grants.
        return None
    runtime = initial_runtime.InitialRuntimeStages(op)
    stages = runtime.stages
    previous = m.load(stages.directory/"initial-provider.result.json")
    actual = initial_runtime.read_provider_result(runtime.m, previous)
    m.require(previous["host"] == runtime.host and previous["core"] == runtime.core_pin, "same_original_native_capture_provider_required")
    source_provider = production.save_selection(op, "actual-capture-provider-material-data.json", actual)
    binding = op.final_binding()
    m.require(binding["deployment"] == runtime.core_pin, "same_original_final_source_capture_core_required")
    facts = data(op, binding["facts_receipt"])
    source = data(op, binding["source_selection"])
    template = data(op, source["MaterialsTemplate"])
    directory = Path(runtime.core["capture_modules"]["path"]).parent
    production.ensure_directory(op, directory)
    _, enrolled, _, sql = stages.common()
    source_dsn = sql["files"]["mysql-source.dsn"]
    tls = production.save_selection(op, "actual-capture-source-database-tls.json", sql["source_tls"])
    credential, _ = op.invoke("initial-capture-database-credential", [stages.binary("system-backup-first-install-materials"),
        "runtime-database-environment", "--worker-source-credential", "--plan-file", enrolled["Plan"]["File"],
        "--plan-sha256", enrolled["Plan"]["SHA256"], "--runtime-dsn-file", source_dsn["File"],
        "--runtime-dsn-sha256", source_dsn["SHA256"], "--tls-file", tls["File"], "--tls-sha256", tls["SHA256"],
        "--output-file", directory/"source-database.credential.json"])
    op.pin_value(credential)
    schema_path = op.root/SCHEMA
    raw = schema_path.read_bytes()
    m.require(schema_path.resolve(strict=True) == schema_path and op.pins["files"].get(SCHEMA) == SCHEMA_SHA and
              hashlib.sha256(raw).hexdigest() == SCHEMA_SHA, "sealed_original_v12_schema_registry_asset_required")
    schema = initial_runtime.retain_bytes(runtime.m, directory/"control-schema-registry.json", raw)
    address = template["Operations"]["capture-database"]["Request"]["database"]["address"]
    endpoint = urllib.parse.urlsplit("mysql://"+address)
    m.require(endpoint.hostname and endpoint.port and not endpoint.username and not endpoint.path,
              "actual_original_mysql_Service_endpoint_required")
    service = stages.get("service", endpoint.hostname.split(".")[0])
    role = op.sql_role_inputs()["roles"]["source"]
    forward = runtime.previous_forward()
    inputs = {"Version": "original-capture-operational-input-author.v1", "Core": runtime.core_pin,
              "Forward": forward["grant"], "RequestFiles": runtime.request_pin,
              "SourceSelection": binding["source_selection"], "ProviderResult": source_provider,
              "ProviderObserver": previous["provider_source"], "DatabaseCredential": credential,
              "SchemaRegistry": schema, "PartsRegistry": facts["PartsRegistry"],
              "DatabaseAccount": role["account"], "DatabaseService": service["metadata"]["name"],
              "DatabaseServiceUID": service["metadata"]["uid"], "DatabasePort": endpoint.port,
              "TeamsSource": {}, "TeamsFiles": []}
    selected = production.save_selection(op, "actual-capture-operational-author-inputs.json", inputs)
    result, out = op.invoke("initial-capture-inputs", [stages.binary("system-backup-first-install-materials"),
        "author-capture-operational-inputs", "--inputs-file", selected["File"], "--inputs-sha256", selected["SHA256"]])
    m.require(result.get("Version") == "original-capture-operational-inputs-authored.v1" and
              result.get("GrantsIssued") is False and result.get("NativeMappingsCreated") is False and
              result.get("BackupReady") is False, "actual_original_typed_capture_DATA_author_required")
    for key in ("SourceDefinition", "ComponentsTemplate", "DatabaseIssueDefinition"):
        op.pin_value(result[key])
    production.save_selection(op, selected_file.name, pin(out))
    bind(op, "owner_source_definition", result["SourceDefinition"])
    bind(op, "owner_components", result["ComponentsTemplate"])
    stages.check_host(runtime.host)
    return result


def finalize_mappings(op, production, initial_runtime, publication=None):
    m = op.source_helpers()
    runtime = initial_runtime.InitialRuntimeStages(op)
    stages = runtime.stages
    original = data(op, data(op, pin(op.run/"production-adoption/actual-initial-capture-input-selection.json")))
    publication = publication or m.load(stages.directory/"publication-runtime.result.json")
    m.require(publication["host"] == runtime.host, "same_original_native_publication_runtime_required")
    # This binder only handles the actual native publisher's single unsigned
    # verifier append; all source/window/DB fields remain exact original DATA.
    bridge = production.save_selection(op, "actual-published-capture-database-binding-inputs.json", {
        "Version": "original-published-capture-database-inputs.v1", "OriginalDefinition": original["SourceDefinition"],
        "PublishedDefinition": publication["SourceDefinition"], "OriginalDatabaseIssue": original["DatabaseIssueDefinition"],
        "PublicationReceipt": publication["runtime_material_receipt"]})
    database, _ = op.invoke("initial-published-capture-database-inputs", [stages.binary("system-backup-first-install-materials"),
        "bind-published-capture-database-inputs", "--inputs-file", bridge["File"], "--inputs-sha256", bridge["SHA256"]])
    op.pin_value(database)
    components = data(op, publication["ComponentsTemplate"])
    # Only the connected original native factory may fill this independent
    # pending grant. Its no-write owner/native preflight runs before Begin.
    # A nonempty caller hash is never accepted as proof of Teams authority.
    definition = data(op, publication["SourceDefinition"])
    teams = definition.get("TeamsSource")
    m.require(isinstance(teams, dict) and teams.get("Version") == "original-teams-object-source-issue.v1" and
              teams.get("PartsRegistry") and components.get("TeamsSource"),
              "original_independent_Teams_source_and_complete_inventory_required")
    selected_source = dict(teams["Source"])
    selected_source["GrantSHA256"] = components["TeamsSource"].get("GrantSHA256", "")
    m.require(selected_source == components["TeamsSource"], "same_original_Teams_source_mount_required")
    output = Path(runtime.core["capture_modules"]["path"]).parent
    args = [stages.binary("system-backup-first-install-materials"), *op.owner_common(),
            "--runtime-dsn-file", runtime.runtime_dsn["File"],
            "--definition-file", publication["SourceDefinition"]["File"], "--definition-sha256", publication["SourceDefinition"]["SHA256"],
            "--source-issuer-private-file", stages.issuer_private(),
            "--components-template-file", publication["ComponentsTemplate"]["File"], "--components-template-sha256", publication["ComponentsTemplate"]["SHA256"],
            "--database-source-definition-file", database["File"], "--database-source-definition-sha256", database["SHA256"],
            "--resolved-components-file", output/"capture-components.resolved.json", "--intermediate-file", output/"capture-materials.intermediate.json"]
    if stages.common()[3].get("runtime_profile") == "public-runtime-c1-minio-metadata-read.v1":
        args.append("--minio-metadata-profile")
    result, out = op.invoke("initial-capture-mappings", args)
    m.require(result.get("Version") == "original-six-part-source-material-result.v1" and
              result.get("File") == runtime.core["capture_modules"]["path"], "actual_native_original_mapping_finalizer_receipt_required")
    op.pin_value({"File": result["File"], "SHA256": result["SHA256"]})
    production.save_selection(op, "actual-initial-capture-mapping-selection.json", pin(out))
    stages.deliver_runtime_tree(runtime.host)
    stages.check_host(runtime.host)
    return {"state": "actual_original_native_capture_mappings_finalized_not_runtime_ready", "private_receipt": str(out), "backup_ready": False}


def dispatch(op, production, initial_runtime):
    if op.a.action == ACTIONS[0]:
        result = prepare_inputs(op, production, initial_runtime)
        return {"state": "actual_original_capture_input_DATA_selected_not_native_authority", "result": result, "backup_ready": False}
    return finalize_mappings(op, production, initial_runtime)
