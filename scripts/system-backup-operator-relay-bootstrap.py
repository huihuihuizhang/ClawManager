"""Original pre-C1 relay PKI and actual read-only status listener.

Call before C1 roles/material issuance. This is a real mTLS SQL-status service,
not a worker-message receiver. Forward activation must use DeploymentService.
"""
import datetime
import hashlib
import json
import os
import secrets
import time
import urllib.error
import shlex
import ssl
import urllib.request
from pathlib import Path

ACTIONS = ("adopt-prepare-relay-pki", "adopt-query-relay-pki", "adopt-start-readonly-relay", "adopt-query-readonly-relay", "adopt-stop-readonly-relay", "adopt-query-relay-handover")

def pin(path):
    path = Path(path)
    return {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()}

def prepare_pki(op, production, query=False):
    m = op.source_helpers()
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "relay_install_before_original_adoption_only")
    stages = op.deployment_stages()
    observed = stages.host_result()
    host = observed["host"]
    stages.check_host(host)
    directory = production.ensure_directory(op, stages.runtime_mirror()/"original-relay-pki")
    deadline = min(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=24), datetime.datetime.fromisoformat(op.a.deployment_signing_until.replace("Z", "+00:00")))
    value = {"Version": "original-relay-pki-inputs.v1", "ControllerDeployment": host["Deployment"], "ControllerPod": host["Pod"], "Service": observed["control_service"]["Name"], "OutputDirectory": str(directory), "Until": deadline.replace(microsecond=0).isoformat().replace("+00:00", "Z")}
    selection = pin(op.run/"production-adoption/actual-relay-pki-inputs.json") if query else production.save_selection(op, "actual-relay-pki-inputs.json", value)
    args = [stages.binary("system-backup-c1-native-inputs"), "relay-pki", "--mode", "query" if query else "issue", *op.owner_common(), "--inputs-file", selection["File"], "--inputs-sha256", selection["SHA256"]]
    if not query:
        private = stages.issuer_private()
        args += ["--issuer-private-file", private, "--issuer-private-sha256", pin(private)["SHA256"]]
    result, out = op.invoke(ACTIONS[1] if query else ACTIONS[0], args, repeat=query)
    m.require(result.get("Version") == "original-relay-pki-result.v1" and result.get("State") == "original_relay_pki_material_issued_service_tls_not_yet_verified", "genuine_original_relay_pki_receipt_required")
    for name in ("Manifest", "Signature", "CA", "IssuerKey", "ServerCertificate", "ServerKey", "ClientCertificate", "ClientKey"):
        op.pin_value(result[name])
    return result, out

def start_readonly(op, production, pki, capacity):
    m = op.source_helpers()
    stages = op.deployment_stages()
    original = stages.host_result()
    host = original["host"]
    stages.check_host(host)
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "readonly_listener_must_start_before_capture")
    m.require(not (op.run/"production-adoption/readonly-relay-start-intent.json").exists(), "original_relay_start_unknown_query_only_no_respawn")
    m.require(capacity["State"] == "original_capacity_select_only_native_verified", "real_capacity_owner_receipt_required")
    binary = stages.binary("system-backup-c1-native-inputs")
    m.require(hashlib.sha256(binary.read_bytes()).hexdigest() == op.pins["files"]["bin/system-backup-c1-native-inputs"], "sealed_relay_listener_elf_required")
    directory = production.ensure_directory(op, stages.runtime_mirror()/"original-readonly-relay")
    op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'umask 077; mkdir -p -- "$1" "$2"; test "$(stat -c %u:%a "$1")" = 65532:700; test "$(stat -c %u:%a "$2")" = 65532:700', "sh", str(directory), str(Path(pki["Manifest"]["File"]).parent))
    # Signed PKI files preserve their exact paths. The listener does not receive
    # the worker CA signing key or the metadata client's private key.
    for name in ("Manifest", "Signature", "CA", "ServerCertificate", "ServerKey", "ClientCertificate"):
        source = pki[name]
        op.pin_value(source)
        stages.host_file(host, "relay-"+name.lower(), source["File"], Path(source["File"]).read_bytes())
    tls_directory = production.ensure_directory(op, stages.runtime_mirror()/"readonly-relay-sql-tls")
    tls_inputs = production.save_selection(op, "actual-relay-sql-tls-location.json", {"Version": "original-relay-sql-tls-location-inputs.v1", "OriginalTLS": capacity["CapacityTLS"], "OutputDirectory": str(tls_directory)})
    tls, tls_out = op.invoke("adopt-prepare-relay-sql-tls", [binary, "relay-tls", *op.owner_common(), "--inputs-file", tls_inputs["File"], "--inputs-sha256", tls_inputs["SHA256"]])
    m.require(tls["State"] == "same_original_SQL_CA_and_server_name_new_location_verified", "actual_owner_SQL_TLS_locator_required")
    original_tls = json.loads(Path(capacity["CapacityTLS"]["File"]).read_bytes())
    m.require(tls["OriginalTLS"] == capacity["CapacityTLS"] and tls["ServerName"] == original_tls["server_name"] and tls["CASHA256"] == original_tls["ca_sha256"] and pin(tls["CA"]["File"])["SHA256"] == tls["CASHA256"], "same_original_SQL_TLS_identity_required")
    op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'umask 077; mkdir -p -- "$1"; test "$(stat -c %u:%a "$1")" = 65532:700', "sh", str(tls_directory))
    stages.host_file(host, "readonly-relay-sql-ca", tls["CA"]["File"], Path(tls["CA"]["File"]).read_bytes())
    cpins = {}
    for name in ("CapacityConfig", "CapacityDSN", "CapacityTLS"):
        source = tls["TLS"] if name == "CapacityTLS" else capacity[name]
        op.pin_value(source)
        target = directory/(name+".private")
        raw = Path(source["File"]).read_bytes()
        if not target.exists():
            with target.open("xb") as output:
                target.chmod(0o600)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        m.require(target.read_bytes() == raw, "original_relay_capacity_bytes_changed")
        stages.host_file(host, "relay-"+name.lower(), str(target), raw)
        cpins[name] = pin(target)
    inputs = {"Version": "original-readonly-status-relay-inputs.v1", "Material": pki["Manifest"], "Signature": pki["Signature"], **cpins}
    selected = production.save_selection(op, "actual-readonly-relay-inputs.json", inputs)
    target = directory/"serve-inputs.json"
    raw = Path(selected["File"]).read_bytes()
    stages.host_file(host, "relay-serve-inputs", str(target), raw)
    common = dict(zip(original["installer_common_args"][::2], original["installer_common_args"][1::2]))
    argv = ["/usr/local/bin/system-backup-c1-native-inputs", "relay-serve"]
    for key in ("--plan-file", "--plan-sha256", "--issuer-public-file", "--issuer-public-sha256", "--kubeconfig-file", "--kubeconfig-sha256"):
        argv += [key, common[key]]
    argv += ["--inputs-file", str(target), "--inputs-sha256", hashlib.sha256(raw).hexdigest(), "--pod-name", host["Pod"]]
    pid = directory/"listener.pid"
    log = directory/"listener.private.log"
    shell = "umask 077; test ! -e "+shlex.quote(str(pid))+"; "+shlex.join(argv)+" >"+shlex.quote(str(log))+" 2>&1 </dev/null & child=$!; printf '%s\n' \"$child\" >"+shlex.quote(str(pid))
    # Dispatch is journalled before the real process start; a lost reply is not
    # permission to spawn a second listener. Query TLS/SQL at the same endpoint.
    production.save_selection(op, "readonly-relay-start-intent.json", {"PodUID": host["PodUID"], "Inputs": pin(Path(selected["File"])), "PIDFile": str(pid), "Endpoint": pki["Endpoint"]})
    op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", shell)
    return query_readonly(op, production, pki)


def query_readonly(op, production, pki):
    m = op.source_helpers()
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    intent_path = op.run/"production-adoption/readonly-relay-start-intent.json"
    intent = json.loads(intent_path.read_bytes())
    m.require(intent["PodUID"] == host["PodUID"] and intent["Endpoint"] == pki["Endpoint"], "same_original_readonly_listener_query_identity_required")
    stages.check_host(host)
    context = ssl.create_default_context(cafile=pki["CA"]["File"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(pki["ClientCertificate"]["File"], pki["ClientKey"]["File"])
    # Startup's initial Kube/SQL snapshot precedes bind. Poll only this original
    # endpoint under a fixed deadline; never respawn or alter its authorization.
    deadline = min(time.monotonic()+30, time.monotonic()+max(0, (datetime.datetime.fromisoformat(pki["Until"].replace("Z", "+00:00"))-datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
    while True:
        try:
            with urllib.request.urlopen(urllib.request.Request(pki["Endpoint"], method="GET"), context=context, timeout=3) as response:
                body = response.read(16385)
                m.require(response.status == 200 and len(body) <= 16384, "actual_readonly_relay_status_response_required")
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            m.require(time.monotonic() < deadline, "original_readonly_relay_start_unknown_query_same_identity_only")
            time.sleep(0.25)
    actual = json.loads(body)
    m.require(actual["version"] == "original-readonly-status-relay-status.v1" and actual["pod_uid"] == host["PodUID"] and actual["service_uid"] == pki["ServiceUID"] and actual["task_mutations_enabled"] is False, "actual_current_relay_SQL_and_Pod_identity_required")
    stages.check_host(host)
    return {"version": "operator-original-readonly-relay-result.v1", "state": "actual_original_readonly_relay_TLS_SQL_verified", "identity": actual, "PKI": pki, "Inputs": intent["Inputs"], "worker_relay_enabled": False, "backup_ready": False}


def stop_for_normal_runtime(op, production, pki, enable_response, request_files, query=False):
    """D calls after actual normal enable/Forward2/pub3 material preparation.

    This returns only actual original listener absence. It does not start or
    approve a controller; D then triggers the normal DeploymentService startup.
    """
    m = op.source_helpers()
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    directory = stages.runtime_mirror()/"original-relay-handover"
    op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'umask 077; mkdir -p -- "$1"; test "$(stat -c %u:%a "$1")" = 65532:700', "sh", str(directory))
    record_path = Path(pki["Manifest"]["File"]).parent/"readonly-relay.process.json"
    record_raw = op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/cat", str(record_path))
    record = json.loads(record_raw)
    m.require(record["PodUID"] == host["PodUID"] and record["ContainerID"] == host["Containers"]["installation-owner"]["ContainerID"], "same_original_listener_container_required")
    # These are the existing owner's actual mirrored RequestFiles/enable export.
    # Do not rewrite signed grant/config bytes or substitute an outside-Pod path.
    for key in ("ConfigFile", "GrantFile", "ObserverFile"):
        m.require(request_files[key].startswith("/run/system-backup/runtime/"), "owner_request_must_be_mirrored_before_native_handover")
    m.require(enable_response["File"].startswith("/run/system-backup/runtime/"), "actual_normal_enable_export_must_be_mirrored")
    inputs = {"Version": "original-readonly-relay-handover-inputs.v1", "OutputDirectory": str(directory), "PKIMaterial": pki["Manifest"], "PKISignature": pki["Signature"], "ProcessRecord": {"File": str(record_path), "SHA256": hashlib.sha256(record_raw).hexdigest()}, "EnableResponse": enable_response, "Request": request_files}
    selected = production.save_selection(op, "actual-relay-handover-inputs.json", inputs)
    native_input = directory/"handover-inputs.json"
    if not query:
        stages.host_file(host, "relay-handover-inputs", str(native_input), Path(selected["File"]).read_bytes())
    private = stages.issuer_private()
    native_private = "/run/installation-owner-private/installer/relay-handover-issuer.private"
    check = op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'if test -e "$1"; then test "$(stat -c %u:%a "$1")" = 65532:600; sha256sum -- "$1"; else printf ABSENT; fi', "sh", native_private).decode().split()
    if check == ["ABSENT"]:
        stages.host_file(host, "original-relay-handover-issuer", native_private, Path(private).read_bytes())
    else:
        m.require(check and check[0] == pin(private)["SHA256"], "original_private_handover_issuer_changed")
    # Existing private issuer delivery is owned by original signing preparation;
    # this helper never copies an operator secret into the normal controller.
    args = ["relay-handover", "--mode", "query" if query else "issue", "--inputs-file", str(native_input), "--inputs-sha256", selected["SHA256"], "--issuer-private-file", native_private, "--issuer-private-sha256", pin(private)["SHA256"]]
    # host_exec defaults place common flags before this CLI subcommand.
    # Preserve the bound original flags, after relay-handover as required.
    common = stages.host_result()["installer_common_args"]
    value, dispatch = stages.host_exec(("query-original-relay-handover-"+secrets.token_hex(8)) if query else "stop-original-readonly-relay", "system-backup-c1-native-inputs", [args[0], *common, *args[1:]], common=False)
    m.require(value["State"] == "original_readonly_listener_absent_normal_runtime_not_started" and value["OriginalListenerAbsent"] is True and value["RuntimeStarted"] is False, "actual_original_listener_absence_required_before_normal_start")
    return value, dispatch


def prepare_normal_runtime_trust(op, production, pki):
    """D MUST call before original deployment core/Forward hashing.

    Public original enrollment references are delivered to the input PVC and
    become part of the administrator-pinned core, never the handover packet's
    choice of root. The runtime rereads the actual immutable enrollment CM.
    """
    m = op.source_helpers()
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    enrolled = op.enrollment()
    directory = production.ensure_directory(op, stages.runtime_mirror()/"original-relay-trust")
    op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'umask 077; mkdir -p -- "$1"; test "$(stat -c %u:%a "$1")" = 65532:700', "sh", str(directory))
    refs = {}
    for key, filename in (("Plan", "plan.json"), ("IssuerPublic", "issuer.public")):
        op.pin_value(enrolled[key])
        raw = Path(enrolled[key]["File"]).read_bytes()
        destination = directory/filename
        if not destination.exists():
            with destination.open("xb") as out:
                destination.chmod(0o600)
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
        m.require(destination.read_bytes() == raw, "original_enrolled_runtime_trust_changed")
        check = op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'if test -e "$1"; then test ! -L "$1"; test "$(stat -c %u:%a "$1")" = 65532:600; sha256sum -- "$1"; else printf ABSENT; fi', "sh", str(destination)).decode().split()
        if check == ["ABSENT"]:
            stages.host_file(host, "original-relay-trust-"+key.lower()+"-"+hashlib.sha256(host["PodUID"].encode()).hexdigest()[:16], str(destination), raw)
        else:
            m.require(check and check[0] == enrolled[key]["SHA256"], "original_enrolled_runtime_trust_native_changed")
        refs[key] = {"File": str(destination), "SHA256": enrolled[key]["SHA256"]}
    op.pin_value(enrolled["Enrollment"])
    refs["Enrollment"] = json.loads(Path(enrolled["Enrollment"]["File"]).read_bytes())
    stages.check_host(host)
    return {"original_relay_enrollment": refs, "control_url": pki["Endpoint"], "tls": {"issuer_certificate": pki["CA"]["File"], "issuer_key": pki["IssuerKey"]["File"], "server_certificate": pki["ServerCertificate"]["File"], "server_key": pki["ServerKey"]["File"]}}


def runtime_handover_binding(op, production, pki, stopped):
    """Called BEFORE D starts the real full controller; returns its exact env.

    D must use the returned TLS paths in the original public deployment/core
    BEFORE granting Forward identity. This function does not issue that grant.
    """
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    m = op.source_helpers()
    m.require(stopped["OriginalListenerAbsent"] and not stopped["RuntimeStarted"], "same_original_stop_receipt_required")
    # Deliver only original exact material bytes; do not re-key or rewrite any
    # previous signed configuration. Destination is the existing input PVC.
    for name in ("IssuerKey", "ClientKey"):
        source = pki[name]
        op.pin_value(source)
        check = op.k("-n", "clawmanager-zhanghui08-system", "exec", host["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'if test -e "$1"; then test "$(stat -c %u:%a "$1")" = 65532:600; sha256sum -- "$1"; else printf ABSENT; fi', "sh", source["File"]).decode().split()
        if check == ["ABSENT"]:
            stages.host_file(host, "normal-relay-"+name.lower(), source["File"], Path(source["File"]).read_bytes())
        else:
            m.require(check and check[0] == source["SHA256"], "same_original_handover_material_required")
    value = {"Version": "original-relay-runtime-handover-inputs.v1", "Stop": stopped["Result"], "StopSignature": stopped["Signature"], "PKI": pki["Manifest"], "PKISignature": pki["Signature"], "ClientCertificate": pki["ClientCertificate"], "ClientKey": pki["ClientKey"]}
    selected = production.save_selection(op, "actual-normal-relay-handover-binding.json", value)
    destination = Path(pki["Manifest"]["File"]).parent/"normal-runtime-handover.json"
    stages.host_file(host, "normal-relay-handover-binding", str(destination), Path(selected["File"]).read_bytes())
    return {"env": {"SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE": str(destination), "SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_SHA256": selected["SHA256"]}, "tls": {"issuer_certificate": pki["CA"]["File"], "issuer_key": pki["IssuerKey"]["File"], "server_certificate": pki["ServerCertificate"]["File"], "server_key": pki["ServerKey"]["File"]}, "Inputs": selected, "Stop": stopped}


def query_normal_runtime_handover(op, pki, stopped, runtime_identity):
    """Read actual DeploymentService's private post-bind/TLS receipt endpoint.

    No normal runtime is spawned or granted here; D owns the startup trigger.
    """
    m = op.source_helpers()
    context = ssl.create_default_context(cafile=pki["CA"]["File"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(pki["ClientCertificate"]["File"], pki["ClientKey"]["File"])
    endpoint = pki["Endpoint"]+"/handover"
    with urllib.request.urlopen(urllib.request.Request(endpoint, method="GET"), context=context, timeout=10) as response:
        body = response.read(16385)
        m.require(response.status == 200 and len(body) <= 16384, "actual_normal_runtime_handover_readback_required")
    result = json.loads(body)
    m.require(result["Version"] == "original-relay-runtime-handover-result.v1" and result["RuntimeStarted"] is True and result["PodUID"] == runtime_identity["PodUID"] and result["StopSHA256"] == stopped["Result"]["SHA256"] and result["ConfigSHA256"] == stopped["ConfigSHA256"] and result["ConfigVersion"] == 2 and result["ServiceUID"] == pki["ServiceUID"], "original_normal_handover_identity_mismatch")
    return {"state": result["State"], "native_handover_receipt": result, "backup_ready": False, "page_backup_completed": False}
