"""Actual enrolled-owner purpose-key command; loaded by the sealed operator."""
import hashlib
import importlib.util
import secrets
from pathlib import Path

DEPLOYMENT_SHA = "adb21932f8df6d6503630d93674083f73c0b0faadf215292363916631f354eb0"


def prepare(operator, query=False):
    path = Path(__file__).resolve().with_name("system-backup-operator-deployment.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != DEPLOYMENT_SHA:
        raise RuntimeError("reviewed_deployment_module_changed")
    spec = importlib.util.spec_from_file_location("runtime_issuers_deployment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stages = module.DeploymentStages(operator)
    common, enrolled, _, materials = stages.common()
    dsn = materials["files"]["mysql-installer.dsn"]
    module.pinned(dsn)
    directory = operator.run / "original-runtime-issuers"
    arguments = [
        stages.binary("system-backup-original-enroll"), "runtime-issuers",
        "--mode", "query" if query else "prepare", *common,
        "--dsn-sha256", dsn["SHA256"],
        "--output-directory", directory,
    ]
    if query:
        material = module.pin(directory / "original-runtime-issuers.json")
        arguments += ["--material-file", material["File"], "--material-sha256", material["SHA256"]]
        stage = "runtime-issuers-query-" + secrets.token_hex(8)
    else:
        arguments += ["--source-issuer-private-file", stages.issuer_private()]
        stage = "runtime-issuers-prepare"
    value, receipt = stages.call(stage, arguments)
    module.need(value["Version"] == "original-runtime-purpose-issuers-produced.v1" and
                value["GrantsIssued"] is False and value["ConfigurationMutated"] is False and
                value["Material"]["File"] == str(directory / "original-runtime-issuers.json"),
                "actual_original_runtime_issuer_material_receipt_required")
    module.pinned(value["Material"])
    result = {"version": "operator-original-runtime-issuers.v1", "material": value["Material"],
              "native_receipt": receipt, "plan": enrolled["Plan"], "enrollment": enrolled["Enrollment"],
              "grants_issued": False, "configuration_mutated": False, "backup_ready": False}
    stages.retain(stage + ".result.json" if query else "runtime-issuers.result.json", result)
    # Purpose private keys stay exclusively in the operator owner directory.
    # Later trusted Go issuers receive its exact manifest pin, not copied JSON.
    return result
