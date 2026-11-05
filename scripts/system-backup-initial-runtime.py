"""Invoke the actual original first Forward/provider/publication issuers."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import re

DEPLOYMENT_SHA = "1634456a58697d23eb999eb31618ec4d77667b02e91260d814e2fe7351f515bb"
OWNER_ASSEMBLY_SHA = "05140777a87dbd8f7098a0e9aa9b02b6c1464e50d52eb55267fce7b240fe4083"
REDIS_SOURCE_SHA = "6642a08eb7a78b64413b1864584d2fbd3f6cf950ee3378c476b219833b53b248"
COMPLETE_INPUTS_SHA = "2848c1494ea69f85daf15827d080d1ba32ec6c498f08431bc2dde2f06cb1a325"
SOURCE_DATA_SHA = "210db9cdb4d054ddc21d6bdabfd34e765a011ce9856ee498de86f10646aed9bb"
DEPLOYMENT_SHA = "b69327c689f6fa15d08ee5d07eed266a79c2166e55a584b96523d0c1fcf235be"
OWNER_ASSEMBLY_SHA = "cbe8cc6be2fbd4192224a7758433bbc706659dc5c3388d42e2cfa080e1f17839"
INPUT_ASSEMBLY_SHA = "956d8d4cde985fe10f62dc2d7c10b6cbfa1153e08b6d03fa634b10c1eba07bd1"


def load(name, expected):
    path = Path(__file__).resolve().with_name(name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError("reviewed_initial_runtime_dependency_changed")
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def register_arguments(parser):
    parser.add_argument("--initial-provider-file", type=Path)
    parser.add_argument("--initial-provider-sha256")
    parser.add_argument("--initial-worker-jwt-identity-file")
    parser.add_argument("--defer-known-error-runtime", action="store_true", help="Explicit functional test scope for exact original two error Lite runtime rows; preserve all business SQL")


def prepare_core_arguments(operator):
    """Resolve the original core before the main SQL-role/source gate."""
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    inputs.prepare_core_input(m, m.DeploymentStages(operator))


def prepare_source_api_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-source-data.py", SOURCE_DATA_SHA)
    selected = inputs.source_api_inputs(m, m.DeploymentStages(operator))
    return m.decode(m.pinned(selected))


def prepare_source_api_successor_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-source-data.py", SOURCE_DATA_SHA)
    return inputs.source_api_successor(m, m.DeploymentStages(operator))


def prepare_source_coordinates_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-source-data.py", SOURCE_DATA_SHA)
    stages = m.DeploymentStages(operator)
    inputs.coordinates(m, stages)
    return m.decode(m.read(stages.directory / "initial-source-coordinates.result.json"))


def prepare_writer_source_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    sources = load("system-backup-initial-source-data.py", SOURCE_DATA_SHA)
    return sources.writer_source_inputs(m, m.DeploymentStages(operator), inputs)


def prepare_redis_source_arguments(operator, mode="prepare"):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    sources = load("system-backup-initial-redis-sources.py", REDIS_SOURCE_SHA)
    assembly = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    stages = m.DeploymentStages(operator)
    if mode == "prepare":
        operator.bind_writer_selection_argument()
        return sources.prepare(m, stages, assembly)
    m.need(mode in ("query", "recover", "recover-finalize"), "original_redis_native_mode_required")
    if mode == "query":
        return sources.resume(m, stages)
    return sources.recover(m, stages, mode)


def prepare_complete_source_arguments(operator, action="prepare"):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    assembly = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    complete = load("system-backup-initial-complete-inputs.py", COMPLETE_INPUTS_SHA)
    stages = m.DeploymentStages(operator)
    if action == "prepare":
        return complete.prepare(m, stages, assembly)
    return complete.provider_action(m, stages, assembly, action)


def prepare_runtime_test_scope_arguments(operator, query_only=False):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    complete = load("system-backup-initial-complete-inputs.py", COMPLETE_INPUTS_SHA)
    sources = load("system-backup-initial-source-data.py", SOURCE_DATA_SHA)
    return complete.runtime_test_scope_action(m, m.DeploymentStages(operator), sources, query_only)



def bind_complete_source_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    assembly = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    stages = m.DeploymentStages(operator)
    path = stages.directory / "initial-complete-source.result.json"
    if not path.exists():
        return
    value = m.decode(m.read(path))
    m.need(value["version"] == "operator-initial-complete-source-data.v1" and value["BackupReady"] is False and value["GrantsIssued"] is False, "original_initial_source_DATA_result_required")
    for field, key in (("deployment_source_selection", "SourceSelection"), ("deployment_writer_selection", "WriterSelection")):
        assembly.bind(m, stages.a, field, value[key])
    m.pinned(value["actual_native_receipt"])


def prepare_minio_options_arguments(operator):
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    inputs = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
    return inputs.prepare_initial_minio_options(m, m.DeploymentStages(operator))


def native_runtime_dsn(m, materials, args):
    selected = materials["files"]["mysql-runtime.dsn"]
    m.pinned(selected)
    if args.owner_runtime_dsn_file is not None:
        m.need({"File": str(args.owner_runtime_dsn_file), "SHA256": args.owner_runtime_dsn_sha256} == selected,
               "actual_dedicated_runtime_account_required_not_business_or_source")
    return selected


def provider_pins(m, receipt):
    m.need(receipt["Version"] == "original-runtime-provider-authorities-result.v1" and
           receipt["State"] == "original_authority_and_capabilities_committed_readback_verified",
           "actual_original_provider_sql_commit_and_readback_required")
    m.need(receipt["Unwrap"] != receipt["PublisherUnwrap"] and receipt["Generate"] != receipt["Unwrap"],
           "independent_original_formal_and_publisher_capabilities_required")
    for name in ("MappingRecord", "MappingSignature", "GenerateFile", "UnwrapFile", "PublisherUnwrapFile"):
        m.pinned(receipt[name])
    for name in ("FormalGrant", "PermitGrant"):
        m.pinned({"File": receipt[name]["File"], "SHA256": receipt[name]["SHA256"]})
    return {"MappingSource": receipt["MappingSource"], "MappingIssuer": receipt["InstallationIssuer"],
            "Generate": receipt["Generate"], "Unwrap": receipt["PublisherUnwrap"]}


def recovered_provider_result(m, query, pending, metadata):
    """Consume only A's full authenticated recovery, never merge pending JSON."""
    m.need(query.get("Version") == "original-runtime-provider-query.v1" and
           query.get("State") == "committed_original_rows_verified" and
           query.get("MaterialState") == "original_result_sources_verified" and
           query.get("OriginalAuthorizationExpired") is False and
           query.get("RetryAllowed") is False and
           query.get("PendingProviderResult") == pending and query.get("SQLMetadataReceipt") == metadata,
           "original_query_diagnostic_only_no_current_material_continuation")
    actual = query.get("ProviderResult")
    m.need(isinstance(actual, dict) and actual.get("SQLMetadataReceipt") == metadata,
           "native_full_original_provider_result_required")
    # The native reader authenticates every original source and current Pod.
    # Keep the pending file unchanged. Its two inert output fields differ from
    # A's recovered result; every other original byte-decoded field must match.
    original = m.decode(m.pinned(pending))
    m.need(original.get("Version") == actual.get("Version") and
           original.get("State") == "material_issued_sql_install_pending" and
           original.get("SQLMetadataReceipt") == {"File": "", "SHA256": ""},
           "original_native_pending_provider_result_required")
    ignored = {"State", "SQLMetadataReceipt"}
    m.need({k: v for k, v in original.items() if k not in ignored} ==
           {k: v for k, v in actual.items() if k not in ignored},
           "native_recovered_provider_original_sources_changed")
    m.pinned(metadata)
    provider_pins(m, actual)
    return actual


def read_provider_result(m, previous):
    response = m.decode(m.pinned(previous["native_receipt"]))
    if previous.get("version") == "operator-initial-provider-recovered.v1":
        m.pinned(previous["original_dispatch"])
        actual = recovered_provider_result(m, response, previous["pending_provider_result"], previous["metadata"])
    else:
        m.need(previous.get("version") == "operator-initial-provider-authorities.v1",
               "actual_original_provider_stage_required")
        actual = response
        provider_pins(m, actual)
    m.need(actual == previous["actual_producer_output"], "original_provider_native_result_changed")
    return actual


def retain_bytes(m, path, raw):
    if path.exists():
        m.need(m.read(path) == raw, "original_runtime_material_bytes_changed_no_reissue")
        return m.pin(path)
    return m.write(path, raw)


def restore_query_arguments(operator):
    """Recover original file selectors from the retained native dispatch only."""
    m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
    stages = m.DeploymentStages(operator)
    intent = m.decode(m.read(stages.directory / "initial-provider-authorities.send-unknown.json"))
    argv = intent.get("argv")
    m.need(intent.get("operation") == stages.operation and intent.get("stage") == "initial-provider-authorities" and
           intent.get("input") is None and isinstance(argv, list) and all(isinstance(v, str) for v in argv) and
           argv[:2] == [str(stages.binary("system-backup-first-install-materials")), "issue-initial-provider-authorities"],
           "original_provider_dispatch_required_for_query_arguments")
    def argument(flag):
        m.need(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv), "original_query_input_flag_invalid")
        return argv[argv.index(flag) + 1]
    for field, flag in (("owner_core", "core"), ("owner_request_files", "request-files")):
        file, sha = argument("--" + flag + "-file"), argument("--" + flag + "-sha256")
        m.pinned({"File": file, "SHA256": sha})
        previous_file, previous_sha = getattr(operator.a, field + "_file", None), getattr(operator.a, field + "_sha256", None)
        m.need(previous_file is None or str(previous_file) == file, "original_provider_query_file_selector_changed")
        m.need(previous_sha is None or previous_sha == sha, "original_provider_query_file_pin_changed")
        setattr(operator.a, field + "_file", Path(file))
        setattr(operator.a, field + "_sha256", sha)
    until = argument("--until")
    m.need(not operator.a.deployment_signing_until or operator.a.deployment_signing_until == until,
           "original_provider_query_deadline_cannot_be_extended")
    operator.a.deployment_signing_until = until


class InitialRuntimeStages:
    def __init__(self, operator):
        self.op = operator
        self.m = load("system-backup-operator-deployment.py", DEPLOYMENT_SHA)
        self.owner = load("system-backup-publication-owner-assembly.py", OWNER_ASSEMBLY_SHA)
        self.stages = self.m.DeploymentStages(operator)
        self.common, self.enrolled, self.plan, materials = self.stages.common()
        self.runtime_dsn = native_runtime_dsn(self.m, materials, operator.a)
        self.export = self.m.decode(self.m.read(self.stages.directory / "runtime-record-keys.result.json"))
        self.host = self.export["host"]
        self.stages.check_host(self.host)
        self.material = self.export["material"]
        self.m.pinned(self.material)
        self.m.pinned(self.export["export"])
        inputs = load("system-backup-initial-input-assembly.py", INPUT_ASSEMBLY_SHA)
        inputs.prepare_initial_runtime_inputs(self.m, self.stages)
        self.core_pin, self.core = self.input("core")
        self.request_pin, _ = self.input("request_files")
        self.m.need(self.core["key_directory"] == self.export["key_directory"], "core_runtime_key_directory_must_use_original_export")
        self.m.need(operator.a.deployment_signing_until, "actual_original_runtime_issuance_until_required")

    def input(self, name):
        path = getattr(self.op.a, "owner_" + name + "_file")
        sha = getattr(self.op.a, "owner_" + name + "_sha256")
        self.m.need(path is not None and re.fullmatch(r"[a-f0-9]{64}", sha or ""), "actual_original_producer_input_pin_required")
        pin = {"File": str(path), "SHA256": sha}
        return pin, self.m.decode(self.m.pinned(pin, limit=8 << 20 if name == "source_definition" else 262144))

    def flags(self):
        return [*self.common, "--runtime-dsn-file", self.runtime_dsn["File"],
                "--runtime-issuers-file", self.material["File"], "--runtime-issuers-sha256", self.material["SHA256"],
                "--request-files-file", self.request_pin["File"], "--request-files-sha256", self.request_pin["SHA256"],
                "--core-file", self.core_pin["File"], "--core-sha256", self.core_pin["SHA256"],
                "--controller-deployment", self.host["Deployment"], "--controller-pod-name", self.host["Pod"],
                "--until", self.op.a.deployment_signing_until]

    def forward(self):
        m, stages = self.m, self.stages
        profile = m.pin(Path(self.core["profile_file"]))
        output = Path(self.core["forward_grant"]["path"]).parent
        m.need(output.is_relative_to(stages.runtime_mirror()), "first_forward_output_must_use_actual_runtime_mount")
        output.mkdir(mode=0o700, exist_ok=True)
        _, _, _, sql_materials = stages.common()
        action = "issue-initial-forward-minio-metadata" if sql_materials.get("runtime_profile") == "public-runtime-c1-minio-metadata-read.v1" else "issue-initial-forward"
        # Routing selects an explicit authenticated owner; its live exact SQL
        # probe supplies verification, never this operational profile string.
        value, receipt = stages.call("initial-forward", [stages.binary("system-backup-first-install-materials"), action, *self.flags(),
            "--profile-file", profile["File"], "--profile-sha256", profile["SHA256"],
            "--record-export-file", self.export["export"]["File"], "--record-export-sha256", self.export["export"]["SHA256"],
            "--output-directory", output])
        m.need(value["Version"] == "original-runtime-execution-result.v1" and value["Grant"]["File"] == self.core["forward_grant"]["path"] and
               value["ControllerPodUID"] == self.host["PodUID"], "actual_first_forward_receipt_required")
        m.pinned(value["Grant"])
        m.pinned(value["PublicKey"])
        stages.check_host(self.host)
        delivered = stages.deliver_runtime_tree(self.host)
        result = {"version": "operator-initial-forward.v1", "host": self.host, "core": self.core_pin, "request_files": self.request_pin,
                  "profile": profile, "runtime_dsn": self.runtime_dsn, "material": self.material, "record_export": self.export["export"],
                  "grant": value["Grant"], "public_key": value["PublicKey"], "native_receipt": receipt,
                  "delivered_runtime_files": delivered, "backup_ready": False}
        stages.retain("initial-forward.result.json", result)
        return result

    def previous_forward(self):
        result = self.m.decode(self.m.read(self.stages.directory / "initial-forward.result.json"))
        self.m.need(result["host"] == self.host and result["core"] == self.core_pin and result["material"] == self.material and
                    result["record_export"] == self.export["export"] and result["runtime_dsn"] == self.runtime_dsn,
                    "same_actual_first_forward_scope_required")
        self.m.pinned(result["native_receipt"])
        self.m.pinned(result["grant"])
        return result

    def publication(self):
        forward = self.previous_forward()
        config, _ = self.input("config")
        actual = self.stages.publication_authorization(self.core_pin, config, forward["grant"]["SHA256"], self.runtime_dsn, self.request_pin)
        receipt = self.m.decode(self.m.pinned(actual["receipt"]))
        self.m.pinned(receipt["RuntimeOwnerInputs"])
        self.stages.check_host(self.host)
        result = {"version": "operator-initial-publication-authorization.v1", "host": self.host, "core": self.core_pin, "config": config,
                  "forward": forward["grant"], "runtime_dsn": self.runtime_dsn, "owner_inputs": receipt["RuntimeOwnerInputs"],
                  "native_receipt": actual["receipt"], "backup_ready": False}
        self.stages.retain("initial-publication.result.json", result)
        return result

    def previous_publication(self):
        forward = self.previous_forward()
        result = self.m.decode(self.m.read(self.stages.directory / "initial-publication.result.json"))
        self.m.need(result["host"] == self.host and result["core"] == self.core_pin and result["forward"] == forward["grant"] and result["runtime_dsn"] == self.runtime_dsn,
                    "same_actual_publication_authorization_required")
        self.m.pinned(result["native_receipt"])
        self.m.pinned(result["owner_inputs"])
        return forward, result

    def provider(self):
        m, stages = self.m, self.stages
        forward, publication = self.previous_publication()
        file, sha = self.op.a.initial_provider_file, self.op.a.initial_provider_sha256
        m.need(file is not None and re.fullmatch(r"[a-f0-9]{64}", sha or ""), "actual_native_provider_observer_source_required")
        provider = {"File": str(file), "SHA256": sha}
        m.pinned(provider)
        identity_file = self.op.a.initial_worker_jwt_identity_file
        m.need(isinstance(identity_file, str) and identity_file.startswith("/") and ".." not in Path(identity_file).parts,
               "actual_worker_projected_jwt_mount_locator_required")
        output = stages.runtime_mirror() / "initial-provider-authorities"
        output.mkdir(mode=0o700, exist_ok=True)
        value, receipt = stages.call("initial-provider-authorities", [stages.binary("system-backup-first-install-materials"), "issue-initial-provider-authorities", *self.flags(),
            "--forward-grant-file", forward["grant"]["File"], "--forward-grant-sha256", forward["grant"]["SHA256"],
            "--provider-file", provider["File"], "--provider-sha256", provider["SHA256"], "--worker-jwt-identity-file", identity_file,
            "--runtime-owner-inputs-file", publication["owner_inputs"]["File"], "--runtime-owner-inputs-sha256", publication["owner_inputs"]["SHA256"],
            "--output-directory", output])
        provider_pins(m, value)
        # Only the already delegated permit signer enters the runtime mount.
        original = m.decode(base64.b64decode(m.decode(m.pinned(self.material))["Record"], validate=True))
        source = original["Issuers"]["provider_permit_delivery"]["PrivateKey"]
        m.need(value["PermitSigningKeyFile"] == source["File"], "actual_original_delegated_permit_key_locator_required")
        raw = m.pinned(source, limit=64)
        m.need(len(raw) == 64 and base64.b64encode(raw[32:]).decode() == value["DeliveryPin"]["issuer_public_key"], "actual_delegated_permit_signer_mismatch")
        delegated = retain_bytes(m, stages.runtime_mirror() / "provider-permit-delivery.private", raw)
        stages.check_host(self.host)
        delivered = stages.deliver_runtime_tree(self.host)
        result = {"version": "operator-initial-provider-authorities.v1", "host": self.host, "core": self.core_pin,
                  "forward": forward["grant"], "provider_source": provider, "owner_inputs": publication["owner_inputs"],
                  "native_receipt": receipt, "actual_producer_output": value, "permit_signing_key": delegated,
                  "delivered_runtime_files": delivered, "backup_ready": False}
        stages.retain("initial-provider.result.json", result)
        return result

    def provider_query(self):
        m, stages = self.m, self.stages
        forward, publication = self.previous_publication()
        intent_path = stages.directory / "initial-provider-authorities.send-unknown.json"
        intent_pin = m.pin(intent_path)
        intent = m.decode(m.pinned(intent_pin))
        argv = intent.get("argv")
        m.need(intent.get("stage") == "initial-provider-authorities" and
               intent.get("operation") == stages.operation and intent.get("input") is None and
               isinstance(argv, list) and all(isinstance(s, str) for s in argv) and
               argv[:2] == [str(stages.binary("system-backup-first-install-materials")), "issue-initial-provider-authorities"],
               "original_provider_native_dispatch_required_no_new_issue")

        def argument(flag):
            m.need(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv), "original_provider_dispatch_flag_invalid")
            return argv[argv.index(flag) + 1]

        # Compare actual original issuer/runtime/controller/core/request pins,
        # not a caller's reconstructed pending receipt or fresh source IDs.
        expected = [*self.flags(), "--forward-grant-file", forward["grant"]["File"],
                    "--forward-grant-sha256", forward["grant"]["SHA256"],
                    "--runtime-owner-inputs-file", publication["owner_inputs"]["File"],
                    "--runtime-owner-inputs-sha256", publication["owner_inputs"]["SHA256"]]
        for flag, value in zip(expected[::2], expected[1::2]):
            m.need(argument(str(flag)) == str(value), "original_provider_query_scope_changed")
        output = stages.runtime_mirror() / "initial-provider-authorities"
        m.need(argument("--output-directory") == str(output), "original_provider_output_directory_changed")
        provider = {"File": argument("--provider-file"), "SHA256": argument("--provider-sha256")}
        m.pinned(provider)
        pending = m.pin(output / "runtime-provider-authorities.json")
        metadata = m.pin(output / "runtime-installed-metadata.receipt.json")
        query, stdout = self.op.invoke("initial-provider-query", [stages.binary("system-backup-first-install-materials"),
            "query-initial-provider-authorities", *self.common,
            "--runtime-sql-metadata-receipt-file", metadata["File"], "--runtime-sql-metadata-receipt-sha256", metadata["SHA256"],
            "--pending-provider-result-file", pending["File"], "--pending-provider-result-sha256", pending["SHA256"]], repeat=True)
        receipt = m.pin(stdout)
        m.need(query == m.decode(m.pinned(receipt)), "actual_provider_query_output_changed")
        # Exit zero can be expired/diagnostic-only. It must not create a
        # continuation, deliver files, repair markers or reconstruct any hold.
        actual = recovered_provider_result(m, query, pending, metadata)
        m.need(m.pin(intent_path) == intent_pin, "original_provider_dispatch_changed_during_query")
        stages.check_host(self.host)
        result = {"version": "operator-initial-provider-recovered.v1", "host": self.host, "core": self.core_pin,
                  "forward": forward["grant"], "provider_source": provider, "owner_inputs": publication["owner_inputs"],
                  "native_receipt": receipt, "actual_producer_output": actual,
                  "original_dispatch": intent_pin, "pending_provider_result": pending, "metadata": metadata,
                  "backup_ready": False}
        # One create-only continuation. Repeated queries preserve their own
        # original stdout; they cannot replace a prior confirmation or deadline.
        name = stages.directory / "initial-provider-recovered.result.json"
        if name.exists():
            previous = m.decode(m.read(name))
            m.need(read_provider_result(m, previous) == actual and previous["host"] == self.host and
                   previous["core"] == self.core_pin and previous["original_dispatch"] == intent_pin,
                   "previous_original_provider_confirmation_changed")
            return previous
        stages.retain(name.name, result)
        return result

    def runtime(self):
        m, stages = self.m, self.stages
        _, publication = self.previous_publication()
        previous_path = stages.directory / "initial-provider.result.json"
        if not previous_path.exists():
            previous_path = stages.directory / "initial-provider-recovered.result.json"
        previous = m.decode(m.read(previous_path))
        m.need(previous["host"] == self.host and previous["core"] == self.core_pin and previous["owner_inputs"] == publication["owner_inputs"], "same_original_provider_scope_required")
        actual = read_provider_result(m, previous)
        pins = provider_pins(m, actual)
        if previous["version"] == "operator-initial-provider-recovered.v1":
            original = m.decode(base64.b64decode(m.decode(m.pinned(self.material))["Record"], validate=True))
            source = original["Issuers"]["provider_permit_delivery"]["PrivateKey"]
            m.need(actual["PermitSigningKeyFile"] == source["File"], "original_delegated_permit_signer_changed")
            raw = m.pinned(source, limit=64)
            m.need(len(raw) == 64 and base64.b64encode(raw[32:]).decode() == actual["DeliveryPin"]["issuer_public_key"],
                   "original_delegated_permit_signer_mismatch")
            permit_key = retain_bytes(m, stages.runtime_mirror() / "provider-permit-delivery.private", raw)
        else:
            permit_key = previous["permit_signing_key"]
            m.pinned(permit_key)
        provider = m.decode(m.pinned(previous["provider_source"]))
        m.need(provider["Binding"] == actual["Binding"], "original_provider_binding_changed")
        ca = base64.b64decode(provider["CAPEM"], validate=True)
        m.need(b"BEGIN CERTIFICATE" in ca and b"PRIVATE KEY" not in ca and m.digest(ca) == actual["Binding"]["Provider"]["CAPEMSHA256"], "actual_original_provider_ca_required")
        ca_pin = retain_bytes(m, stages.runtime_mirror() / "publisher-unwrap-ca.pem", ca)
        jwt, review = self.owner.token_request(m, stages, provider["Publisher"], self.host)
        owner_inputs = m.decode(m.pinned(publication["owner_inputs"]))
        sources = self.owner.assemble_sources(m, owner_inputs, {"Binding": actual["Binding"], "Source": actual["MappingSource"]}, pins, jwt["File"], ca_pin["File"], self.host["Pod"])
        source_pin = self.op.capture_mapping_module().encode_runtime_sources(self.op, sources, "initial")
        # Typed consumer will independently authenticate the formal grant and
        # formal capability, and the distinct permit/business/delegate pair.
        formal = {"schema_version": "controller-verifier-materials.v1", "database": actual["Database"], "binding": actual["Binding"],
                  "generate_capability": actual["Generate"], "unwrap_capability": actual["Unwrap"], "installation_issuer": actual["InstallationIssuer"],
                  "ca_file": ca_pin["File"], "jwt_file": jwt["File"], "workload": actual["FormalWorkload"], "grant": actual["FormalGrant"],
                  "provider_permits": {"workload": actual["PermitWorkload"], "grant": actual["PermitGrant"],
                                       "signing_key_file": permit_key["File"], "delivery_pin": actual["DeliveryPin"]}}
        formal_file = Path(self.core["formal_verifier"]["path"])
        m.need(formal_file.is_relative_to(stages.runtime_mirror()) and formal_file.parent.is_dir(), "actual_formal_verifier_runtime_path_required")
        formal_pin = retain_bytes(m, formal_file, m.encoded(formal))
        definition, _ = self.input("source_definition")
        components, _ = self.input("components")
        output = Path(self.core["capture_modules"]["path"]).parent
        m.need(output.is_relative_to(stages.runtime_mirror()) and output.is_dir(), "actual_original_material_output_directory_required")
        value, receipt = stages.call("initial-publication-runtime", [stages.binary("system-backup-first-install-materials"), "issue-runtime-materials", *self.common,
            "--runtime-dsn-file", self.runtime_dsn["File"], "--source-definition-file", definition["File"], "--source-definition-sha256", definition["SHA256"],
            "--components-template-file", components["File"], "--components-template-sha256", components["SHA256"],
            "--runtime-sources-file", source_pin["File"], "--runtime-sources-sha256", source_pin["SHA256"],
            "--runtime-owner-inputs-file", publication["owner_inputs"]["File"], "--runtime-owner-inputs-sha256", publication["owner_inputs"]["SHA256"],
            "--output-definition-file", output / "publication-runtime.definition.json", "--output-components-file", output / "publication-runtime.components.json"])
        stages.check_host(self.host)
        delivered = stages.deliver_runtime_tree(self.host)
        result = {"version": "operator-publication-runtime-assembly-result.v1", "host": self.host, "original_owner_inputs": publication["owner_inputs"],
                  "runtime_material_receipt": receipt, "runtime_sources": source_pin, "formal_verifier": formal_pin,
                  "publisher_jwt_review": review, "SourceDefinition": value["SourceDefinition"], "ComponentsTemplate": value["ComponentsTemplate"],
                  "delivered_file_pins": delivered, "configuration_enabled": False, "backup_ready": False}
        stages.retain("publication-runtime.result.json", result)
        return result


def dispatch(operator):
    stages = InitialRuntimeStages(operator)
    return {"initial-forward": stages.forward, "initial-publication": stages.publication,
            "initial-provider": stages.provider, "initial-provider-query": stages.provider_query,
            "initial-runtime": stages.runtime}[operator.a.action]()
