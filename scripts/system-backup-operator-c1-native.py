"""Fixed original capacity owner transport and retained native input receipts.

The independent capacity account is never added to the original six-role
operation. Only the real Go owner can issue/query/drop its owned principal.
"""
import hashlib
from pathlib import Path

ACTIONS = ("adopt-prepare-capacity", "adopt-query-capacity", "adopt-rollback-capacity")
VERSION = "original-c1-capacity-account-result.v1"
STATE = "original_capacity_select_only_native_verified"


def pin(path):
    path = Path(path)
    return {"File": str(path), "SHA256": hashlib.sha256(path.read_bytes()).hexdigest()}


def data(op, selected):
    return op.source_helpers().load(op.pin_value(selected))


def capacity(op):
    selected = data(op, pin(op.run/"production-adoption/actual-capacity-producer-selection.json"))
    result = data(op, selected)
    m = op.source_helpers()
    m.require(result.get("Version") == VERSION and result.get("State") == STATE and result.get("OriginalUsersPreserved") is True, "actual_original_capacity_native_receipt_required")
    for name in ("Operation", "CapacityConfig", "CapacityDSN", "CapacityTLS"):
        op.pin_value(result[name])
    m.require(data(op, result["CapacityConfig"]) == result["Config"], "actual_capacity_config_receipt_mismatch")
    return result


def prepare_capacity(op, production, bridge, mode):
    m = op.source_helpers()
    m.require(mode in ("issue", "query", "rollback"), "fixed_capacity_owner_mode_required")
    op.open()
    m.require(not (op.run/"adopt.send-unknown.json").exists(), "capacity_owner_changes_after_capture_dispatch_forbidden")
    # This requires real six-role enrollment/materials before creating the
    # separate child principal. Original roster validation remains unchanged.
    common = op.owner_common()
    flags = dict(zip(common[::2], common[1::2]))
    enrolled = op.enrollment()
    plan = data(op, enrolled["Plan"])
    accounts = m.load(op.run/"sql-accounts/sql-accounts-materials.public.json")
    tls, _ = production.retained(op, "tls-apply")
    m.require(tls.get("Version") == "original-source-tls-bootstrap-receipt.v1" and tls.get("OperatorSQLTLSVerified") is True, "actual_original_tls_owner_receipt_required")
    for file_key, sha_key in (("DSNFile", "DSNSHA256"), ("SourceTLSFile", "SourceTLSSHA256")):
        op.pin_value({"File": tls[file_key], "SHA256": tls[sha_key]})
    m.require(tls["ServerUUID"] == plan["Target"]["ServerUUID"] == accounts["server_uuid"] and tls["Result"]["Native"]["Database"] == plan["Target"]["Database"] == accounts["database"], "actual_capacity_source_must_match_original_enrollment")
    selected_host = m.load(op.run/"sql-account-host-selection.json")
    output = production.ensure_directory(op, production.ensure_directory(op, op.run/"production-adoption")/"capacity-owner")
    binary = op.deployment_stages().binary("system-backup-c1-native-inputs")
    m.require(op.pins["files"].get("bin/"+binary.name) == pin(binary)["SHA256"], "sealed_actual_capacity_owner_elf_required")
    args = [binary, "capacity", "--mode", mode, "--admin-dsn-file", tls["DSNFile"], "--admin-dsn-sha256", tls["DSNSHA256"], "--source-tls-file", tls["SourceTLSFile"], "--source-tls-sha256", tls["SourceTLSSHA256"], "--kubeconfig-file", op.kube, "--kubeconfig-sha256", pin(op.kube)["SHA256"], "--namespace", plan["Target"]["Namespace"], "--namespace-uid", plan["Target"]["NamespaceUID"], "--cluster-uid", op.upgraded_released()["cluster_uid"], "--expected-server-uuid", tls["ServerUUID"], "--database", accounts["database"], "--local-admin-password-file", flags["-local-admin-password-file"], "--local-admin-username", accounts["local_admin_username"], "--account-host", selected_host["host"], "--output-directory", output]
    if selected_host["allow_wildcard_host"]:
        args.append("--allow-wildcard-host")
    stage = {"issue": ACTIONS[0], "query": ACTIONS[1], "rollback": ACTIONS[2]}[mode]
    if mode == "issue":
        m.require(not any(output.iterdir()), "original_capacity_directory_not_empty_query_original_only")
        m.require(not (op.run/(ACTIONS[2]+".send-unknown.json")).exists(), "original_capacity_rollback_started_no_reissue")
        args += ["--data-directory", "/var/lib/mysql"]
    else:
        m.require((op.run/(ACTIONS[0]+".send-unknown.json")).exists(), "original_capacity_dispatch_required_query_no_reissue")
        original = production.save_selection(op, "actual-capacity-operation-pin.json", pin(output/"capacity-operation.json"))
        operation = data(op, original)
        op.pin_value(operation)
        args += ["--operation-file", operation["File"], "--operation-sha256", operation["SHA256"]]
    result, out = bridge.invoke_capacity(op, stage, args, repeat=mode != "issue")
    if mode == "rollback":
        m.require(result.get("state") == "original_capacity_account_absent_original_users_preserved", "actual_owned_capacity_absence_required")
    else:
        m.require(result.get("Version") == VERSION and result.get("State") == STATE and result.get("OriginalUsersPreserved") is True, "actual_capacity_native_sql_and_readonly_mount_verification_required")
        for name in ("Operation", "CapacityConfig", "CapacityDSN", "CapacityTLS"):
            op.pin_value(result[name])
        production.save_selection(op, "actual-capacity-operation-pin.json", result["Operation"])
        selector = op.run/"production-adoption/actual-capacity-producer-selection.json"
        if selector.exists():
            original = capacity(op)
            m.require(all(original[name] == result[name] for name in ("Operation", "CapacityConfig", "CapacityDSN", "CapacityTLS", "Config")), "query_must_retain_original_capacity_files_no_replacement")
        else:
            production.save_selection(op, selector.name, pin(out))
        capacity(op)
    return {"state": result.get("State", result.get("state")), "private_receipt": str(out), "capacity_collector_running": False, "backup_ready": False, "page_backup_completed": False}
