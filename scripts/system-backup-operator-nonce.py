"""Actual original-owner nonce issue/resume, final host mount and binding.

No local key is treated as an original provider without the real owner CLI.
Mount insertion occurs before first host creation; never rolls a bound actor.
"""
import copy
from pathlib import Path

DIRECTORY = "/run/system-backup/nonce-materials"
ACTIONS = ("nonce-issue", "nonce-resume", "nonce-bind")


def register_arguments(parser):
    parser.add_argument("--nonce-until")
    parser.add_argument("--nonce-request-files-file", type=Path)
    parser.add_argument("--nonce-request-files-sha256")


def material(operator):
    # Only retained successful producer stdout; an unknown issue is resumed
    # with the same durable intent/key, never replaced with a second issue.
    candidates = sorted(operator.run.glob("nonce-resume-*.readback.json"))
    if (operator.run / "nonce-issue.readback.json").exists():
        candidates.append(operator.run / "nonce-issue.readback.json")
    operator_module(operator).require(candidates, "actual_original_nonce_issue_or_same_intent_resume_required")
    values = [operator_module(operator).load(Path(operator.completed(path.name.removesuffix(".readback.json"))["stdout"])) for path in candidates]
    value = values[0]
    operator_module(operator).require(all(item == value for item in values), "same_original_nonce_material_producer_outputs_drifted")
    operator_module(operator).require(value["Version"] == "original-nonce-file-material-result.v1" and value["State"] == "first-version-issued-native-readback-verified-not-mounted", "actual_original_nonce_material_producer_required")
    for key in ("Source", "Descriptor", "Material"):
        operator.pin_value(value[key])
    return value


def operator_module(operator):
    # Operator supplies exact same-release helpers, not a caller DTO module.
    return operator.source_helpers()


def mount_for_host(operator, pod_spec):
    m = operator_module(operator)
    issued = material(operator)
    volume, mount = issued["PodVolume"], issued["ContainerMount"]
    m.require(issued["MountDirectory"] == DIRECTORY and volume["name"] == "original-owner-nonce-file" and mount == {"name": volume["name"], "readOnly": True, "mountPath": DIRECTORY}, "fixed_original_nonce_mount_required")
    m.require(volume["secret"]["secretName"] == issued["Secret"] and volume["secret"]["defaultMode"] == 256 and volume["secret"]["items"] == [{"key": "nonce", "path": issued["RelativePath"]}], "exact_original_nonce_secret_key_profile_required")
    security = pod_spec["securityContext"]
    m.require(security.get("runAsUser") == 65532 and security.get("runAsGroup") == 65532 and security.get("fsGroup") == 65532, "actual_host_uid_gid_and_fsgroup_required_for_nonce_mount")
    m.require(not any(v["name"] == volume["name"] for v in pod_spec["volumes"]), "nonce_volume_already_present_do_not_rewrite")
    pod_spec["volumes"].append(copy.deepcopy(volume))
    m.require({c["name"] for c in pod_spec["containers"]} == {"controller", "installation-owner"}, "exact_actual_host_containers_required")
    for container in pod_spec["containers"]:
        for current in container.get("volumeMounts", []):
            m.require(not (current["mountPath"] == DIRECTORY or current["mountPath"].startswith(DIRECTORY + "/") or DIRECTORY.startswith(current["mountPath"].rstrip("/") + "/") and current["mountPath"] != "/run/system-backup"), "overlapping_nonce_mount_refused")
        container.setdefault("volumeMounts", []).append(copy.deepcopy(mount))
    return issued


def verify_readable(stages, identity):
    m = operator_module(stages.op)
    issued = material(stages.op)
    stages.check_host(identity)
    relative = Path(issued["RelativePath"])
    m.require(not relative.is_absolute() and ".." not in relative.parts and len(relative.parts) == 2, "fixed_original_nonce_relative_path_required")
    path = DIRECTORY + "/" + relative.as_posix()
    # This is actual execution under each final container UID, not PodSpec
    # inference. Kubernetes Secret projection symlinks are expected here.
    script = 'test "$(id -u):$(id -g)" = 65532:65532; test -r "$1"; test "$(wc -c < "$1" | tr -d " \\n")" = 32; sha256sum "$1"'
    for container in ("controller", "installation-owner"):
        raw = stages.op.k("-n", m.NS, "exec", identity["Pod"], "-c", container, "--", "/bin/sh", "-ec", script, "sh", path)
        m.require(raw.decode("ascii").split() == [issued["Material"]["SHA256"], path], "actual_nonce_mount_unreadable_or_wrong_original_bytes")
    stages.check_host(identity)
    return {"source": issued["Source"], "material_sha256": issued["Material"]["SHA256"], "actual_host": identity, "mount_directory": DIRECTORY, "read_only_secret_volume": issued["PodVolume"], "executing_uid": 65532, "backup_ready": False}


def dispatch(operator):
    m = operator_module(operator)
    common = operator.owner_common()
    deployment = operator.deployment_stages()
    action = operator.a.action
    m.require(action in ACTIONS, "unknown_original_nonce_action")
    output = operator.run / ("nonce-binding" if action == "nonce-bind" else "nonce-materials")
    if action == "nonce-issue":
        m.require(operator.a.nonce_until and not (operator.run / "deployment/host-observer.result.json").exists(), "nonce_first_issue_before_host_and_fixed_expiry_required")
        output.mkdir(mode=0o700)
        m.sync_dir(operator.run)
    elif action == "nonce-resume":
        m.require(operator.a.nonce_until is None and (operator.run / "nonce-issue.send-unknown.json").exists() and output.is_dir(), "resume_same_original_nonce_intent_only")
    flags = ["--action", action.removeprefix("nonce-"), *common, "--issuer-private-file", deployment.issuer_private(), "--output-directory", output]
    if action == "nonce-issue":
        flags += ["--until", operator.a.nonce_until]
    if action == "nonce-bind":
        m.require(operator.a.nonce_until is None and operator.a.nonce_request_files_file is not None and operator.a.nonce_request_files_sha256 is not None, "actual_original_request_files_pin_required_for_nonce_bind")
        request = {"File": str(operator.a.nonce_request_files_file), "SHA256": operator.a.nonce_request_files_sha256}
        operator.pin_value(request)
        issued = material(operator)
        identity = deployment.host_result()["host"]
        observation = verify_readable(deployment, identity)
        output.mkdir(mode=0o700)
        m.sync_dir(operator.run)
        flags += ["--source-file", issued["Source"]["File"], "--source-sha256", issued["Source"]["SHA256"], "--request-files-file", request["File"], "--request-files-sha256", request["SHA256"], "--controller-deployment", identity["Deployment"], "--controller-pod", identity["Pod"], "--container", "controller", "--volume", issued["PodVolume"]["name"]]
        deployment.retain("nonce-current-mount-observation.json", observation)
    value, out = operator.invoke(action, [deployment.binary("system-backup-original-nonce-material"), *flags], repeat=action == "nonce-resume")
    if action == "nonce-bind":
        m.require(value["Version"] == "original-nonce-file-mount-result.v1" and value["State"] == "original-signed-current-native-readonly-mount-verified", "actual_original_signed_nonce_mount_required")
        for key in ("Binding", "OwnerMaterial"):
            operator.pin_value(value[key])
        deployment.check_host(identity)
    return {"state": value["State"], "actual_producer_output": value, "private_receipt": str(out), "backup_ready": False}
