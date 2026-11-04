"""Export only actual original record/capture bytes to the final runtime host."""
import hashlib
import importlib.util
from pathlib import Path

DEPLOYMENT_SHA = "5087d2607147ee01626bc6195e206b7ea051f548d559cb14124dfddfa9ea3c96"


def prepare(operator):
    path = Path(__file__).resolve().with_name("system-backup-operator-deployment.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != DEPLOYMENT_SHA:
        raise RuntimeError("reviewed_deployment_module_changed")
    spec = importlib.util.spec_from_file_location("runtime_record_key_deployment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stages = module.DeploymentStages(operator)
    common, _, _, materials = stages.common()
    dsn = materials["files"]["mysql-installer.dsn"]
    module.pinned(dsn)
    material = module.decode(module.read(stages.directory / "runtime-issuers.result.json"))["material"]
    module.pinned(material)
    host = module.decode(module.read(stages.directory / "materials.result.json"))["host"]
    stages.check_host(host)
    directory = stages.runtime_mirror() / "execution-keys"
    value, receipt = stages.call("runtime-record-key-export", [
        stages.binary("system-backup-original-enroll"), "runtime-issuers", "--mode", "export-record-keys", *common,
        "--dsn-sha256", dsn["SHA256"], "--source-issuer-private-file", stages.issuer_private(),
        "--material-file", material["File"], "--material-sha256", material["SHA256"], "--output-directory", directory])
    module.need(value["Version"] == "original-runtime-record-key-export-result.v1" and value["Material"] == material,
                "actual_original_record_key_export_required")
    for name, filename in (("Export", "record-export.signed.json"), ("RecordKey", "execution-record.key"), ("CaptureKey", "capture-record.key")):
        module.need(value[name]["File"] == str(directory / filename), "original_record_export_target_changed")
        module.pinned(value[name])
    stages.check_host(host)
    delivered = stages.deliver_runtime_tree(host)
    result = {"version": "operator-runtime-record-key-export.v1", "host": host, "key_directory": str(directory),
              "material": material, "export": value["Export"], "record_key": value["RecordKey"], "capture_key": value["CaptureKey"],
              "native_receipt": receipt, "delivered_runtime_files": delivered, "backup_ready": False}
    stages.retain("runtime-record-keys.result.json", result)
    return result
