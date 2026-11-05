"""One original native capacity collector with guarded process ownership."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ACTIONS = ("adopt-start-capacity-collector", "adopt-query-capacity-collector", "adopt-stop-capacity-collector")
REPORT = "/run/system-backup/runtime/registration-capacity.current.json"


def pin(path):
    path = Path(path)
    return {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()}


def load(op, name):
    path = op.run/"production-adoption"/name
    return op.source_helpers().load(op.pin_value(pin(path)))


def process(op):
    m = op.source_helpers()
    issued = load(op, "actual-capacity-collector-process.json")
    m.require(issued["BootID"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "original_capacity_process_boot_changed_query_no_respawn")
    pid = issued["PID"]
    m.require(type(pid) is int and pid > 1 and os.getpgid(pid) == pid, "original_capacity_process_group_required")
    proc = Path("/proc")/str(pid)
    fields = (proc/"stat").read_text().rsplit(")", 1)[1].split()
    m.require(fields[0] != "Z" and fields[19] == issued["StartTime"], "capacity_pid_reused_or_process_exited")
    m.require((proc/"cmdline").read_bytes().split(b"\x00")[:-1] == [v.encode() for v in issued["Argv"]] and Path(os.readlink(proc/"exe")).resolve(strict=True) == Path(sys.executable).resolve(strict=True), "original_capacity_process_executable_and_exact_dispatch_required")
    uid = [v for v in (proc/"status").read_text().splitlines() if v.startswith("Uid:")]
    m.require(len(uid) == 1 and uid[0].split()[1:] == ["0"]*4, "original_root_capacity_transport_uid_required")
    op.pin_value(issued["Plan"])
    return issued


def query(op):
    m = op.source_helpers()
    issued = process(op)
    selected = m.load(op.pin_value(issued["Plan"]))
    stages = op.deployment_stages()
    stages.check_host(selected["Host"])
    raw = op.k("-n", "clawmanager-zhanghui08-system", "exec", selected["Host"]["Pod"], "-c", "installation-owner", "--", "/bin/sh", "-eu", "-c", 'test ! -L "$1"; test "$(stat -c %u:%a "$1")" = 65532:640; cat -- "$1"', "sh", REPORT)
    value = json.loads(raw)
    m.require(set(value) == {"server_uuid", "database", "observed_at", "allocated_bytes", "available_bytes"} and value["server_uuid"] == selected["ServerUUID"] and value["database"] == selected["Database"], "actual_remote_capacity_source_required")
    observed = datetime.datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    m.require(0 <= (datetime.datetime.now(datetime.timezone.utc)-observed).total_seconds() < 5 and all(type(value[n]) is int and value[n] >= 0 for n in ("allocated_bytes", "available_bytes")), "actual_native_capacity_report_stale_or_invalid")
    stages.check_host(selected["Host"])
    process(op)
    return {"state": "actual_native_capacity_report_process_and_remote_transfer_current_not_admission", "report_file": REPORT, "report_sha256": hashlib.sha256(raw).hexdigest(), "capacity_collector_running": True, "backup_ready": False, "page_backup_completed": False}


def start(op, production, bridge, native):
    m = op.source_helpers()
    op.open()
    m.require(not (op.run/"production-adoption/capacity-collector-start-intent.json").exists(), "capacity_start_unknown_query_original_only_no_respawn")
    stages = op.deployment_stages()
    host = stages.host_result()["host"]
    stages.check_host(host)
    cap = native.capacity(op)
    config = cap["Config"]
    source = production.save_selection(op, "actual-capacity-collector-inputs.json", {"Version": "original-select-only-capacity-collector-inputs.v1", **{k: cap[k] for k in ("CapacityConfig", "CapacityDSN", "CapacityTLS")}})
    binary = stages.binary("system-backup-c1-native-inputs")
    args = bridge.prepare(op, [binary, "capacity-collect", "--inputs-file", source["File"], "--inputs-sha256", source["SHA256"]], collector=True)
    helper = Path(args[3])
    bridge_plan = {"File": str(args[5]), "SHA256": args[7]}
    op.pin_value(bridge_plan)
    m.require(op.pins["files"].get("scripts/"+helper.name) == pin(helper)["SHA256"], "sealed_capacity_mount_helper_required")
    report = stages.runtime_mirror()/"registration-capacity.current.json"
    m.require(str(report) == REPORT and not report.exists(), "new_original_capacity_report_path_required")
    script = op.root/"scripts/system-backup-capacity-report-transport.py"
    m.require(op.pins["files"].get("scripts/"+script.name) == pin(script)["SHA256"], "sealed_capacity_report_transport_required")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    source_plan = production.save_selection(op, "actual-capacity-report-transport-plan.json", {"Version": "original-live-capacity-report-transport.v1", "BootID": boot, "Namespace": "clawmanager-zhanghui08-system", "Host": host, "ReportFile": REPORT, "ServerUUID": config["server_uuid"], "Database": config["database"], "Helper": pin(helper), "BridgePlan": bridge_plan, "NativeInput": source, "Kubeconfig": pin(op.kube)})
    argv = [sys.executable, "-I", "-B", str(script), "--plan-file", source_plan["File"], "--plan-sha256", source_plan["SHA256"]]
    production.save_selection(op, "capacity-collector-start-intent.json", {"Plan": source_plan, "Argv": argv, "BootID": boot})
    log = op.run/"production-adoption/capacity-collector.private.log"
    with log.open("xb") as output:
        log.chmod(0o600)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True, close_fds=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    proc = Path("/proc")/str(child.pid)
    fields = (proc/"stat").read_text().rsplit(")", 1)[1].split()
    production.save_selection(op, "actual-capacity-collector-process.json", {"PID": child.pid, "StartTime": fields[19], "BootID": boot, "Argv": argv, "Plan": source_plan})
    # Native sample/Kube delivery is asynchronous. Poll only this dispatched
    # process; never restart or replay a report when startup is uncertain.
    for _ in range(40):
        m.require(child.poll() is None, "original_capacity_collector_exited_retain_private_log")
        if report.exists():
            return query(op)
        time.sleep(0.25)
    m.require(False, "original_capacity_collector_start_unconfirmed_query_same_process")


def stop(op, production):
    issued = process(op)
    production.save_selection(op, "capacity-collector-stop-intent.json", {"PID": issued["PID"], "StartTime": issued["StartTime"], "BootID": issued["BootID"]})
    os.killpg(issued["PID"], signal.SIGTERM)
    for _ in range(50):
        path = Path("/proc")/str(issued["PID"])/"stat"
        if not path.exists() or path.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return {"state": "original_owned_capacity_collector_stopped_reports_expire_within_5s", "capacity_collector_running": False, "backup_ready": False}
        time.sleep(0.1)
    op.source_helpers().require(False, "original_capacity_stop_unconfirmed_no_unowned_pid_signal")


def dispatch(op, production, bridge, native):
    op.open()
    if op.a.action == ACTIONS[0]:
        return start(op, production, bridge, native)
    if op.a.action == ACTIONS[1]:
        return query(op)
    return stop(op, production)
