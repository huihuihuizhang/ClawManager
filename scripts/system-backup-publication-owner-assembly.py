#!/usr/bin/env python3
"""Join real original-owner outputs and invoke the existing runtime issuer.

No SigningRecord, PublisherCaptureGrant, provider permission or observed UID is
accepted as a caller claim. Native Go issuers/consumers reauthenticate each one.
"""
import base64
import importlib.util
from pathlib import Path
import re

DEPLOYMENT_SHA = "adb21932f8df6d6503630d93674083f73c0b0faadf215292363916631f354eb0"
COMPOSITION_FILES = ("config", "bootstrap-grant", "consumption", "facts-receipt", "functional-receipt", "minio-input", "nonce-binding", "artifact-ca-binding", "evidence-ca-binding", "catalog-location", "kek-config", "evidence", "installer-dsn", "signing-consumer", "signing-consumer-pin")
COMPOSITION_DIRECTORIES = ("mapping-directory", "source-registry-directory", "status-relay-directory", "six-reference-directory", "kek-window-directory", "registry-directory", "nonce-directory")


def register_arguments(parser):
    for name in ("core", "config", "runtime-dsn", "source-definition", "components", "kek-input", "request-files"):
        parser.add_argument("--owner-" + name + "-file", type=Path)
        parser.add_argument("--owner-" + name + "-sha256")
    parser.add_argument("--owner-forward-grant-sha256")
    parser.add_argument("--owner-kek-material-directory", type=Path)
    for name in COMPOSITION_FILES:
        parser.add_argument("--compose-" + name + "-file", type=Path)
        parser.add_argument("--compose-" + name + "-sha256")
    for name in COMPOSITION_DIRECTORIES:
        parser.add_argument("--compose-" + name, type=Path)


def dispatch(operator):
    m = load_deployment()
    if operator.a.action == "prepare-composition":
        return prepare_composition(m, operator)
    values = {}
    for name in ("core", "config", "runtime_dsn", "source_definition", "components", "kek_input", "request_files"):
        path = getattr(operator.a, "owner_" + name + "_file")
        sha = getattr(operator.a, "owner_" + name + "_sha256")
        m.need(path is not None and re.fullmatch(r"[a-f0-9]{64}", sha or ""), "actual_owner_producer_input_pins_required")
        values[name] = {"File": str(path), "SHA256": sha}
    m.need(operator.a.owner_kek_material_directory is not None and re.fullmatch(r"[a-f0-9]{64}", operator.a.owner_forward_grant_sha256 or ""), "actual_original_kek_materials_and_forward_pin_required")
    return publication_runtime_chain(operator, values["core"], values["config"], operator.a.owner_forward_grant_sha256,
        values["runtime_dsn"], values["source_definition"], values["components"], operator.a.owner_kek_material_directory, values["kek_input"], values["request_files"])


def load_deployment():
    path = Path(__file__).with_name("system-backup-operator-deployment.py").resolve(strict=True)
    import hashlib
    if hashlib.sha256(path.read_bytes()).hexdigest() != DEPLOYMENT_SHA:
        raise ValueError("reviewed_deployment_module_changed")
    spec = importlib.util.spec_from_file_location("original_owner_deployment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assemble_sources(m, owner_inputs, mapping, original_pins, publisher_jwt_file, ca_file, pod_name):
    """Comparison projection only; the real Go runtime constructor follows."""
    m.need(owner_inputs["Version"] == "original-publication-runtime-owner-inputs.v1", "actual_native_publication_owner_inputs_required")
    m.need(owner_inputs["SigningPin"]["InstallationID"] == mapping["Binding"]["InstallationID"] and
           mapping["Source"] == original_pins["MappingSource"], "same_original_kek_and_publication_installation_required")
    mounts = owner_inputs["SigningMounts"]
    purposes = {"capture_certificate", "acceptance_record", "catalog_record"}
    m.need(len(mounts) == 3 and {v["binding"]["Purpose"] for v in mounts} == purposes, "three_independent_actual_signing_mounts_required")
    return {"Version": "original-publication-runtime-sources.v1", "SigningRecord": owner_inputs["SigningRecord"], "SigningPin": owner_inputs["SigningPin"],
            "SigningFiles": [{"Purpose": v["binding"]["Purpose"], "JWTFile": v["jwt_file"], "CAFile": v["ca_file"]} for v in mounts],
            "Binding": mapping["Binding"], "GenerateCapability": original_pins["Generate"], "UnwrapCapability": original_pins["Unwrap"],
            "InstallationIssuer": original_pins["MappingIssuer"], "VerifierCAFile": ca_file, "VerifierJWTFile": publisher_jwt_file,
            "VerifierGrant": owner_inputs["PublisherGrant"], "ControllerPodName": pod_name}


def check_publisher_role(m, role, host):
    m.need(role["Namespace"] == "clawmanager-zhanghui08-system" and role["PodUID"] == host["PodUID"] and
           role["ServiceAccountName"] == host["ServiceAccount"] and role["ServiceAccountUID"] == host["ServiceAccountUID"] and
           isinstance(role["Audience"], str) and role["Audience"] and not any(c.isspace() for c in role["Audience"]),
           "actual_final_controller_publisher_role_required")


def token_request(m, stages, role, host):
    check_publisher_role(m, role, host)
    stages.check_host(host)
    # Raw credentials go only into the original private stage stdout, never
    # argv, public receipts, an environment variable or a Kubernetes Secret.
    _, output = stages.call("publisher-bound-token-request", ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", stages.op.kube,
        "--request-timeout=30s", "-n", role["Namespace"], "create", "token", role["ServiceAccountName"], "--audience=" + role["Audience"], "--duration=600s",
        "--bound-object-kind=Pod", "--bound-object-name=" + host["Pod"], "--bound-object-uid=" + host["PodUID"]], json_output=False)
    raw = m.pinned(output).strip()
    m.need(32 <= len(raw) <= 16384 and not any(c in raw for c in b" \r\n\t\x00"), "actual_bound_jwt_result_required")
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": raw.decode("ascii"), "audiences": [role["Audience"]]}}
    reviewed, reviewed_pin = stages.call("publisher-bound-token-review", ["kubectl", "--context", "kubernetes-admin@kubernetes", "--kubeconfig", stages.op.kube,
        "--request-timeout=30s", "create", "--raw=/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-"], m.encoded(body))
    status = reviewed["status"]
    m.need(status.get("authenticated") is True and not status.get("error") and role["Audience"] in status.get("audiences", []) and
           status["user"]["username"] == "system:serviceaccount:" + role["Namespace"] + ":" + role["ServiceAccountName"] and status["user"]["uid"] == role["ServiceAccountUID"],
           "actual_publisher_jwt_review_failed")
    extra = status["user"].get("extra", {})
    m.need(extra.get("authentication.kubernetes.io/pod-uid") == [host["PodUID"]] and extra.get("authentication.kubernetes.io/pod-name") == [host["Pod"]], "actual_token_review_pod_binding_required")
    path = stages.runtime_mirror() / "publisher-unwrap.jwt"
    if path.exists():
        m.need(m.read(path) == raw, "original_publisher_jwt_changed_no_renewal")
        selected = m.pin(path)
    else:
        selected = m.write(path, raw)
    stages.check_host(host)
    return selected, reviewed_pin


def publication_runtime_chain(operator, core, config, forward_sha, runtime_dsn, source_definition, components, kek_directory, kek_input, request_files):
    m = load_deployment()
    stages = m.DeploymentStages(operator)
    stages.common()
    for selected in (core, config, runtime_dsn, source_definition, components, kek_input, request_files):
        m.pinned(selected, limit=8 << 20)
    # This is a real explicit business grant issuer, not a JSON join pretending
    # to supply the grant. A r2 authenticates the original first-install request;
    # installed binding/full runtime checks remain after actual bootstrap.
    authorization = stages.publication_authorization(core, config, forward_sha, runtime_dsn, request_files)
    native_receipt = m.decode(m.pinned(authorization["receipt"]))
    owner_pin = native_receipt["RuntimeOwnerInputs"]
    owner_inputs = m.decode(m.pinned(owner_pin))
    _, enrolled, original_plan, _ = stages.common()
    enrollment = m.decode(m.pinned(enrolled["Enrollment"]))
    m.need(owner_inputs["PlanSHA256"] == enrolled["Plan"]["SHA256"] and owner_inputs["EnrollmentDocumentSHA256"] == enrollment["DocumentSHA256"], "same_actual_original_enrollment_required")
    kek_directory = Path(kek_directory)
    mapping_pin = m.pin(kek_directory / "installation-authority.record.json")
    mapping = m.decode(m.pinned(mapping_pin))
    original_pins = m.decode(m.read(kek_directory / "original-source-pins.json"))
    issuer = m.read(kek_directory / "installation-authority.public-key", limit=32)
    m.need(len(issuer) == 32 and base64.b64encode(issuer).decode() == original_pins["MappingIssuer"] and
           mapping["Binding"]["InstallationID"] == original_plan["Target"]["InstallationID"], "original_mapping_issuer_material_required")
    m.read(kek_directory / "installation-authority.signature", limit=64)
    for name in ("generate.capability.json", "unwrap.capability.json"):
        m.decode(m.read(kek_directory / name))
    input_definition = m.decode(m.pinned(kek_input))
    provider = input_definition["Provider"]
    m.need(provider["Binding"] == mapping["Binding"], "actual_native_provider_binding_changed")
    host = authorization["host"]
    role = provider["Publisher"]
    check_publisher_role(m, role, host)
    ca = base64.b64decode(provider["CAPEM"], validate=True)
    m.need(0 < len(ca) <= 65536 and b"PRIVATE KEY" not in ca and b"BEGIN CERTIFICATE" in ca and m.digest(ca) == mapping["Binding"]["Provider"]["CAPEMSHA256"], "actual_original_unwrap_ca_required")
    ca_file = stages.runtime_mirror() / "publisher-unwrap-ca.pem"
    if ca_file.exists():
        m.need(m.read(ca_file) == ca, "original_unwrap_ca_changed")
    else:
        m.write(ca_file, ca)
    jwt, jwt_review = token_request(m, stages, role, host)
    sources = assemble_sources(m, owner_inputs, mapping, original_pins, jwt["File"], str(ca_file), host["Pod"])
    sources_pin = m.write(stages.runtime_mirror() / "publication-runtime-sources.json", m.encoded(sources))
    declaration = m.decode(m.pinned(source_definition, limit=8 << 20))
    core_value = m.decode(m.pinned(core))
    output_directory = Path(core_value["capture_modules"]["path"]).parent
    m.need(output_directory.is_relative_to(stages.runtime_mirror()) and output_directory.is_dir(), "actual_fixed_material_output_directory_required")
    common, _, _, _ = stages.common()
    output_definition, output_components = output_directory / "publication-runtime.definition.json", output_directory / "publication-runtime.components.json"
    produced, produced_pin = stages.call("publication-runtime-materials", [stages.binary("system-backup-first-install-materials"), "issue-runtime-materials", *common,
        "--runtime-dsn-file", runtime_dsn["File"], "--source-definition-file", source_definition["File"], "--source-definition-sha256", source_definition["SHA256"],
        "--components-template-file", components["File"], "--components-template-sha256", components["SHA256"], "--runtime-sources-file", sources_pin["File"], "--runtime-sources-sha256", sources_pin["SHA256"],
        "--runtime-owner-inputs-file", owner_pin["File"], "--runtime-owner-inputs-sha256", owner_pin["SHA256"],
        "--output-definition-file", output_definition, "--output-components-file", output_components])
    stages.check_host(host)
    delivered = stages.deliver_runtime_tree(host)
    result = {"version": "operator-publication-runtime-assembly-result.v1", "state": "actual_authorization_and_runtime_material_producers_completed_same_host",
              "host": host, "owner_authorization_receipt": authorization["receipt"], "original_owner_inputs": owner_pin, "original_mapping": mapping_pin,
              "publisher_jwt_review": jwt_review, "runtime_sources": sources_pin, "runtime_material_receipt": produced_pin,
              "SourceDefinition": produced["SourceDefinition"], "ComponentsTemplate": produced["ComponentsTemplate"], "delivered_file_pins": delivered,
              "configuration_enabled": False, "backup_ready": False}
    stages.retain("publication-runtime.result.json", result)
    return result


def prepare_composition(m, operator):
    stages = m.DeploymentStages(operator)
    stages.common()
    flags = []
    for name in COMPOSITION_FILES:
        path = getattr(operator.a, "compose_" + name.replace("-", "_") + "_file")
        sha = getattr(operator.a, "compose_" + name.replace("-", "_") + "_sha256")
        m.need(path is not None and re.fullmatch(r"[a-f0-9]{64}", sha or ""), "actual_original_composition_component_producer_missing")
        selected = {"File": str(path), "SHA256": sha}
        m.pinned(selected)
        flags += ["--" + name + "-file", path, "--" + name + "-sha256", sha]
    for name in COMPOSITION_DIRECTORIES:
        path = getattr(operator.a, "compose_" + name.replace("-", "_"))
        m.need(path is not None and path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(), "actual_original_owner_output_directory_missing")
        flags += ["--" + name, path]
    output = stages.runtime_mirror() / "bootstrap-composition"
    output.mkdir(mode=0o700, exist_ok=True)
    flags += ["--output-directory", output]
    actual, receipt = stages.call("prepare-composition", [stages.binary("system-backup-bootstrap-enrolled"), "prepare-composition", *flags])
    m.need(actual["Version"] == "original-composition-data-assembly-result.v1" and actual["configuration_mutated"] is False and actual["native_owners_verified"] is False,
           "actual_composition_assembly_result_required")
    for key in ("Composition", "Deployment"):
        m.pinned(actual[key])
    host = stages.host_result()["host"]
    stages.check_host(host)
    delivered = stages.deliver_runtime_tree(host)
    result = {"version": "operator-composition-prepare-result.v1", "state": actual["state"], "actual_producer_output": actual,
              "receipt": receipt, "host": host, "delivered_runtime_files": delivered, "configuration_enabled": False, "backup_ready": False}
    stages.retain("composition-prepare.result.json", result)
    return result
