#!/usr/bin/env python3
"""Original198 native SQL maintenance/backup/apply/query/rollback/release.

Original deployment operator only. Run on Linux; all secret bytes stay in the
private operation directory / original Pod private files. No authorization DTO.
Never source this script; no operation runs without an explicit CLI action.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import shlex
import subprocess
import struct
import tarfile
import time
try:
    import fcntl
except ImportError:
    fcntl=None

NS = "clawmanager-zhanghui08-system"
NS_UID = "337cfe30-2c17-4b8e-b32a-760778b8098e"
MYSQL_UID = "27916932-fc61-432c-b515-081f18db34a8"
APP_UID = "ed2c80de-9d24-4ca6-8f9c-877a990ac933"
SERVER = "f1f5f76a-95f5-11f1-b08e-366835b4a029"
V3 = "b0219f92ac0c3d38c2f13bcac3ebcc1535eb8e7f1f75890ecae1225d280e651a"
UPGRADE = "191f4326edd1ae0e7d949561cdcd3060cebaf18814fbac3db25bf15d9e97b897"
RENAME = "b97754e940e7ce0267aecc0ae06e6afa75aa243e0698002238dd295f4eff7ab0"
GUARD = ("SET @copy_guard=IF(DATABASE() REGEXP '^cm_import_[0-9a-f]{32}$','SELECT 1','ORIGINAL_DATABASE_WRITE_FORBIDDEN');\n"
         "PREPARE copy_guard_stmt FROM @copy_guard; EXECUTE copy_guard_stmt; DEALLOCATE PREPARE copy_guard_stmt;\n").encode()
LOCK_NAME = "clawmanager-original-upgrade198-operation"

# mysql.user.authentication_string contains native bytes, including possible
# TAB/LF/CR. The snapshot field named "authentication" is UPPERCASE HEX of
# those bytes (empty bytes -> ""), never a password/hash decoded as text.
# This encoding is used only for comparison; no original password is changed.
ACCOUNT_AUTHENTICATION_ENCODING = "mysql_hex_bytes_v1"
ACCOUNT_SNAPSHOT_SQL = "SELECT User,Host,plugin,HEX(authentication_string),account_locked FROM mysql.user ORDER BY User,Host;"


def parse_native_account_snapshot(raw):
    out = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) != 5: raise RuntimeError("account_inventory_unreadable")
        user, host, plugin, authentication, locked = fields
        account(user); account(host)
        if len(authentication) % 2 or re.fullmatch(r"[0-9A-F]*", authentication) is None:
            raise RuntimeError("account_inventory_unreadable")
        if locked not in ("Y", "N"): raise RuntimeError("account_lock_state_unknown")
        out.append({"user": user, "host": host, "plugin": plugin, "authentication": authentication, "locked": locked})
    return out

SAFE_REASON_CODES = frozenset({
    'account_inventory_unreadable',
    'account_lock_state_unknown',
    'account_missing_cancel_refused',
    'application_changed_before_close',
    'application_changed_finish_release_refused',
    'application_replaced',
    'application_spec_changed_original_restore_refused',
    'backup_capacity_unavailable',
    'backup_clone_exists_no_partial_restore_resume',
    'backup_or_restore_capacity_insufficient',
    'ddl_attempted_full_rollback_required',
    'dedicated_original_mysql_required_no_other_business_or_copy_databases',
    'early_exclusion_missing_without_delete_intent',
    'exact_migration_input_changed',
    'exact_passed_v3_archive_required',
    'exclusion_missing_without_original_delete_intent',
    'failed_state_archive_changed',
    'foreign_account_auth_during_release',
    'foreign_account_change_cancel_refused',
    'foreign_account_during_release',
    'foreign_account_during_release_controller_recovery',
    'foreign_controller_recovery_binding',
    'foreign_exclusion_do_not_delete',
    'foreign_grants_during_release',
    'foreign_native_session_present',
    'foreign_or_missing_mysql_account',
    'foreign_original_upgrade_exclusion',
    'foreign_release_intent',
    'foreign_release_recovery_intent',
    'foreign_root_create_lock_owner',
    'foreign_session_identity_invalid',
    'initial_principal_not_fully_confirmed',
    'initial_root_create_execution_not_settled_keep_cancel_marker',
    'linux_operator_required',
    'mysql_container_restarted',
    'mysql_datadir_not_bound_to_original_pvc',
    'mysql_deployment_replaced',
    'mysql_health_probe_not_account_lock_safe',
    'mysql_original_persistent_pvc_mapping_required',
    'mysql_owner_changed',
    'mysql_persistent_claim_not_bound',
    'mysql_persistent_volume_binding_changed',
    'mysql_pod_replaced',
    'mysql_recovery_container_not_ready',
    'mysql_recovery_image_changed',
    'mysql_recovery_pvc_pv_or_local_node_changed',
    'mysql_recovery_service_account_changed',
    'namespace_replaced',
    'native_background_sql_writer_present',
    'native_original35_preservation_still_needed',
    'native_original35_still_in_preservation_schema',
    'native_original_table_id_unreadable',
    'native_password_fence_unknown',
    'native_pending_session_invalid',
    'native_preservation_schema_invalid',
    'native_recovery_epoch_custody_changed',
    'native_recovery_epoch_invalid',
    'native_recovery_epochs_exhausted',
    'native_recovery_identity_missing',
    'native_recovery_password_outcome_unknown_keep_barrier',
    'native_sql_mutation_intent_present_early_cancel_refused',
    'new_private_operation_directory_required',
    'new_recovery_identity_not_confirmed',
    'no_original_ddl_use_release_before_upgrade',
    'not_exact_101_migrations',
    'original198_not_verified',
    'original_account_not_fenced',
    'original_account_set_not_restored',
    'original_account_state_not_restored',
    'original_application_recovery_readback_pending',
    'original_application_replaced',
    'original_application_restore_readback_pending',
    'original_application_spec_changed_cancel_refused',
    'original_auth_changed_during_release_controller_recovery',
    'original_cluster_exclusion_create_pending_query_same_operation',
    'original_cluster_exclusion_create_unknown_query_only',
    'original_control_table_set_changed',
    'original_database_defaults_unreadable',
    'original_ddl_already_attempted_query_or_full_rollback_only',
    'original_exclusion_replaced',
    'original_grants_changed_during_release_controller_recovery',
    'original_grants_not_restored',
    'original_innodb_control_table_identity_missing',
    'original_innodb_table_identity_unreadable',
    'original_kubernetes_context_changed',
    'original_management_application_not_stopped',
    'original_mysql_container_required',
    'original_mysql_deployment_changed',
    'original_mysql_deployment_spec_changed',
    'original_mysql_storage_changed',
    'original_namespace_replaced',
    'original_native_control_history_not_empty',
    'original_native_control_table_missing_or_replaced',
    'original_native_globals_not_restored',
    'original_native_grants_changed',
    'original_native_recovery_authentication_unavailable',
    'original_native_root_or_globals_unexpected',
    'original_operation_already_released',
    'original_persisted_global_unrecognized',
    'original_premaintenance_profile_rejected',
    'original_recovery_custody_changed',
    'original_recovery_identity_invalid',
    'original_release_not_completed_cleanup_refused',
    'original_restart_configuration_not_restored',
    'original_root_cancel_identity_unconfirmed',
    'original_root_create_lock_owner_invalid',
    'original_root_not_restored',
    'original_root_unavailable_early_cancel',
    'original_rows_changed',
    'original_rows_proof_invalid',
    'original_sql_barrier_lost',
    'original_sql_restart_barrier_lost',
    'original_state_exists_use_cancel_or_full_rollback',
    'original_table_changed',
    'original_upgrade_exclusion_missing',
    'original_upgrade_exclusion_replaced',
    'partial_initial_principal_recovery_cancel_only',
    'partial_prepare_foreign_account',
    'partial_prepare_original_auth_changed',
    'partial_prepare_original_grants_changed',
    'partial_prepare_recovery_cannot_cover_ddl',
    'persistent_dump_capacity_insufficient',
    'pod_material_changed',
    'preserved_original_native_table_changed',
    'private_native_command_failed',
    'private_original_state_invalid',
    'recovery_account_changed',
    'recovery_account_identity_missing',
    'recovery_native_grants_changed',
    'recovery_session_invalid',
    'release_started_no_old_backup_rollback_or_new_fence',
    'released_operation_not_capture_recoverable',
    'restored_duplicate_control_history_not_empty',
    'retained_original_readproof_changed',
    'retained_recovery_epoch_invalid',
    'retained_recovery_password_changed',
    'reviewed_mysql_8_4_8_required',
    'reviewed_original_linux_amd64_readproof_required',
    'same_original_native_recovery_identity_unconfirmed',
    'same_original_recovery_grants_changed',
    'saved_backup_changed',
    'saved_verified_backup_changed',
    'temporary_recovery_principal_not_locked',
    'temporary_recovery_principal_not_removed',
    'temporary_recovery_sessions_still_present',
    'unexpected_native_recovery_account_early_cancel_refused',
    'unexpected_recovery_identity',
    'unique_actual_mysql_recovery_pod_required',
    'unique_original_mysql_pod_required',
    'unknown_or_partial_ddl_restore_original_before_release',
    'unowned_clone_cleanup_refused',
    'unsafe_original_mysql_recovery_pod',
    'unsupported_original_account_name',
    'verified_restore_clone_cleanup_unknown',
})

def safe_reason(error):
    return str(error) if type(error) is RuntimeError and str(error) in SAFE_REASON_CODES else "private_native_or_custody_error"






def digest(b): return hashlib.sha256(b).hexdigest()


def file_hash(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest()


def write_new(p, b):
    with p.open("xb") as f:
        os.chmod(p, 0o600); f.write(b); f.flush(); os.fsync(f.fileno())
    fd = os.open(p.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def save_json(p, value): write_new(p, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def account(value):
    # Unknown original account spelling is refused, never silently omitted.
    if not re.fullmatch(r"[A-Za-z0-9_.@%:/-]{1,255}", value): raise RuntimeError("unsupported_original_account_name")
    return "'" + value + "'"


def strip_copy_guard(raw, expected):
    if digest(raw) != expected or not raw.startswith(GUARD): raise RuntimeError("exact_migration_input_changed")
    return raw[len(GUARD):]

def account_lock_safe_probe(probe):
    if not probe:return True
    if "tcpSocket" in probe:return True
    command=probe.get("exec",{}).get("command")
    if not isinstance(command,list) or not command:return False
    if command[0] in ("sh","/bin/sh","bash","/bin/bash"):
        if len(command)!=3 or command[1] not in ("-c","-ec"):return False
        script=command[2]
        if any(c in script for c in (";","|","&","`","\n","$(")):return False
        try:command=shlex.split(script)
        except ValueError:return False
    if command and command[0]=="exec":command=command[1:]
    if not command or command[0].rsplit("/",1)[-1]!="mysqladmin" or command.count("ping")!=1:return False
    allowed=("--user=","--password=","--host=","--port=","--socket=","--protocol=","--connect-timeout=","-u","-p","-h","-P")
    paired={"-h","--host","-u","--user","-P","--port","--socket","--protocol","--connect-timeout"}
    index=1
    while index<len(command):
        token=command[index]
        if token in paired:
            index+=1
            if index>=len(command) or command[index]=="ping" or command[index].startswith("-"):return False
        elif token!="ping" and token not in ("--silent","-s") and not token.startswith(allowed):return False
        index+=1
    return True

def safe_failure_coordinates(directory,log_path):
    # Static catalog markers/MySQL number only. Never return the SQL/error
    # line or data surrounding a match. Marker is observed progress, not an
    # assertion that the corresponding migration committed or can be replayed.
    result={}
    if log_path is None or not Path(log_path).is_file():return result
    with Path(log_path).open("rb") as stream:
        stream.seek(max(0,Path(log_path).stat().st_size-(256<<10)))
        raw=stream.read(256<<10)
    codes=re.findall(rb"\bERROR ([0-9]{1,5})\b",raw)
    if codes:result["mysql_code"]=int(codes[-1])
    profile=Path(directory)/"profile.json"
    if profile.is_file():
        try:allowed=set(json.loads(profile.read_bytes())["pending"])
        except (ValueError,KeyError,TypeError):allowed=set()
        markers=re.findall(rb"MIGRATION:([0-9]{3}_[A-Za-z0-9_.-]{1,200}\.sql)",raw)
        accepted=[x.decode("ascii") for x in markers if x.decode("ascii") in allowed]
        if accepted:result["last_observed_migration_marker"]=accepted[-1]
    return result


class OriginalUpgrade:
    def __init__(self, a):
        self.a = a; self.directory = a.operation_directory.resolve()
        self.stage = "original_identity"; self.state = None
        self.log = None
        self.root_fallback = False
        self.credentials_directory = None
        self.recovery_facts_file = "recovery-account.json"
        self.command_lock=None
        self.result={}
        self.native_guard_reads=False

    def auth_directory(self):return self.credentials_directory or self.state["remote"]

    def append(self, event, details=None):
        # Append-only, numbered create-only records before mutations. A lost
        # reply is classified by native readback, never inferred from timeout.
        names = list(self.directory.glob("event-[0-9]*.json"))
        save_json(self.directory / f"event-{len(names):06d}.json", {"event": event, "details": details, "time": time.time()})

    def k(self, *args, data=None, output=subprocess.PIPE, stdin=None, timeout=90):
        p = subprocess.run(["kubectl", "--context", self.a.context, "-n", NS, *args], input=data,
                           stdin=stdin, stdout=output, stderr=self.log, timeout=timeout)
        if p.returncode: raise RuntimeError("private_native_command_failed")
        return p.stdout

    def obj(self, kind, name): return json.loads(self.k("get", kind, name, "-o", "json"))

    def storage_identity(self,pod):
        pins=[]
        for volume in pod["spec"].get("volumes",[]):
            selected=volume.get("persistentVolumeClaim")
            if not selected:continue
            claim=self.obj("persistentvolumeclaim",selected["claimName"])
            if claim["metadata"].get("deletionTimestamp") or claim["status"].get("phase")!="Bound" or not claim["spec"].get("volumeName"):raise RuntimeError("mysql_persistent_claim_not_bound")
            pv=self.obj("persistentvolume",claim["spec"]["volumeName"])
            reference=pv["spec"].get("claimRef",{})
            if pv["metadata"].get("deletionTimestamp") or reference.get("uid")!=claim["metadata"]["uid"] or reference.get("namespace")!=NS or reference.get("name")!=selected["claimName"]:raise RuntimeError("mysql_persistent_volume_binding_changed")
            local="hostPath" in pv["spec"] or "local" in pv["spec"]
            node=self.obj("node",pod["spec"]["nodeName"]) if local else None
            pins.append({"volume":volume["name"],"claim":selected["claimName"],"claim_uid":claim["metadata"]["uid"],"claim_spec_sha256":digest(json.dumps(claim["spec"],sort_keys=True).encode()),"pv":pv["metadata"]["name"],"pv_uid":pv["metadata"]["uid"],"pv_spec_sha256":digest(json.dumps(pv["spec"],sort_keys=True).encode()),"local_node":pod["spec"]["nodeName"] if local else None,"local_node_uid":node["metadata"]["uid"] if local else None})
        return sorted(pins,key=lambda x:x["volume"])

    def native(self, script, *args, **kw):
        return self.k("exec", "-i", self.state["pod"], "-c", "mysql", "--", "sh", "-eu", "-c", script, "sh", *args, **kw)

    def identity(self):
        if self.obj("namespace", NS)["metadata"]["uid"] != NS_UID: raise RuntimeError("namespace_replaced")
        mysql=self.obj("deployment","mysql")
        if mysql["metadata"]["uid"] != MYSQL_UID: raise RuntimeError("mysql_deployment_replaced")
        if self.state.get("mysql_spec_sha256") and digest(json.dumps(mysql["spec"],sort_keys=True).encode())!=self.state["mysql_spec_sha256"]:raise RuntimeError("original_mysql_deployment_spec_changed")
        if self.state.get("kube_lock_uid"):
            raw=self.k("get","configmap",LOCK_NAME,"--ignore-not-found","-o","json")
            if not raw.strip():
                terminal_cleanup=self.a.action=="cleanup" and (self.directory/"kube-exclusion-delete.send-unknown.json").exists()
                terminal_early=self.a.action in ("early-cancel","early-query") and (self.directory/"early-exclusion-delete.send-unknown.json").exists()
                if not terminal_cleanup and not terminal_early:raise RuntimeError("original_upgrade_exclusion_missing")
            else:
                lock=json.loads(raw)
                if lock["metadata"]["uid"]!=self.state["kube_lock_uid"] or lock.get("data")!={"operation":self.state["operation"],"server_uuid":SERVER,"namespace_uid":NS_UID}: raise RuntimeError("original_upgrade_exclusion_replaced")
        pod = self.obj("pod", self.state["pod"])
        if pod["metadata"]["uid"] != self.state["pod_uid"] or pod["metadata"].get("deletionTimestamp"): raise RuntimeError("mysql_pod_replaced")
        statuses = [s for s in pod["status"].get("containerStatuses", []) if s["name"] == "mysql"]
        if len(statuses) != 1 or not statuses[0].get("ready") or statuses[0]["containerID"] != self.state["container_id"]: raise RuntimeError("mysql_container_restarted")
        if self.state.get("storage") is not None and self.storage_identity(pod)!=self.state["storage"]:raise RuntimeError("original_mysql_storage_changed")
        owners = [x for x in pod["metadata"].get("ownerReferences", []) if x.get("controller")]
        if len(owners) != 1 or owners[0]["kind"] != "ReplicaSet": raise RuntimeError("mysql_owner_changed")
        rs = self.obj("replicaset", owners[0]["name"])
        if rs["metadata"]["uid"] != owners[0]["uid"] or not any(o.get("controller") and o["kind"] == "Deployment" and o["uid"] == MYSQL_UID for o in rs["metadata"].get("ownerReferences", [])): raise RuntimeError("mysql_owner_changed")

    def sql(self, sql, database="mysql", recovery=True):
        if not self.native_guard_reads:self.identity()
        if recovery and not self.root_fallback:
            prefix = 'export MYSQL_PWD="$(cat "$1/password")"; exec mysql --skip-reconnect -u"$2" -N -B --raw --database="$3"'
            args = (self.auth_directory(), self.state["user"], database)
        else:
            prefix = 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysql --skip-reconnect -uroot -N -B --raw --database="$1"'
            args = (database,)
        return self.native(prefix, *args, data=sql.encode(), timeout=180).decode()

    def upload(self, name, raw):
        self.identity()
        self.native('cat > "$1/$2"; chmod 600 "$1/$2"', self.state["remote"], name, data=raw)
        actual = self.native('sha256sum "$1/$2"', self.state["remote"], name).decode().split()[0]
        if actual != digest(raw): raise RuntimeError("pod_material_changed")

    def user_rows(self):
        return parse_native_account_snapshot(self.sql(ACCOUNT_SNAPSHOT_SQL))

    def barrier(self,allow_owned_pending=False):
        # Batch only this PURE native read phase between full actual Kube/CRI/
        # PVC identity reads. Never cache identity for a mutating boundary.
        self.identity();self.native_guard_reads=True
        try:self.native_barrier_reads(allow_owned_pending=allow_owned_pending)
        finally:self.native_guard_reads=False
        self.identity()

    def native_barrier_reads(self,allow_owned_pending=False):
        if (self.directory / "released.json").exists(): raise RuntimeError("original_operation_already_released")
        actual = self.sql("SELECT @@server_uuid,DATABASE(),CURRENT_USER(),@@global.read_only,@@global.super_read_only;").strip().split("\t")
        if actual[:3] != [SERVER, "mysql", self.state["user"] + "@localhost"] or actual[3] != "1": raise RuntimeError("original_sql_barrier_lost")
        persisted=self.sql("SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='read_only';").strip().upper()
        if persisted not in ("ON","1"):raise RuntimeError("original_sql_restart_barrier_lost")
        originals = {(u["user"], u["host"]): u for u in self.state["users"]}
        current = self.user_rows()
        recovery_facts=json.loads((self.directory/self.recovery_facts_file).read_bytes())
        if len(current) != len(originals) + 1: raise RuntimeError("foreign_or_missing_mysql_account")
        for row in current:
            key = row["user"], row["host"]
            if key == (self.state["user"], "localhost"):
                if row!=recovery_facts["row"]: raise RuntimeError("recovery_account_changed")
                continue
            old = originals.get(key)
            if old is None or any(old[k] != row[k] for k in ("plugin", "authentication")) or row["locked"] != "Y": raise RuntimeError("original_account_not_fenced")
            if self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};").splitlines()!=old["grants"]:raise RuntimeError("original_native_grants_changed")
        if self.sql(f"SHOW GRANTS FOR {account(self.state['user'])}@'localhost';").splitlines()!=recovery_facts["grants"]:raise RuntimeError("recovery_native_grants_changed")
        others = self.sql("SELECT ID,USER FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND COMMAND<>'Daemon' AND USER<>'system user';")
        if others.strip():
            if not allow_owned_pending:raise RuntimeError("foreign_native_session_present")
            for line in others.splitlines():
                fields=line.split("\t")
                if len(fields)!=2 or not fields[0].isdigit() or fields[1]!=self.state["user"]:raise RuntimeError("foreign_native_session_present")
        # Replication/event writers can bypass client read_only; reject their
        # presence instead of treating the ordinary account barrier as enough.
        counts = self.sql("SELECT (SELECT COUNT(*) FROM performance_schema.replication_connection_configuration),(SELECT COUNT(*) FROM performance_schema.replication_group_members),(SELECT COUNT(*) FROM information_schema.EVENTS);").strip()
        if counts != "0\t0\t0": raise RuntimeError("native_background_sql_writer_present")
        app = self.obj("deployment", "clawmanager-app")
        if app["metadata"]["uid"] != APP_UID or app["spec"].get("replicas", 1) != 0 or app.get("status", {}).get("replicas", 0) != 0: raise RuntimeError("original_management_application_not_stopped")

    def exclusive_sql(self, body, database="clawmanager", output=None, source=None):
        self.barrier()
        # Native read_only remains ON; ONLY this private recovery account can
        # bypass it, all original ordinary/SUPER accounts are persistently
        # locked and old sessions were killed. No v2 gate table is needed.
        self.sql("SET GLOBAL super_read_only=OFF;")
        self.barrier()
        try:
            command = 'export MYSQL_PWD="$(cat "$1/password")"; exec mysql --skip-reconnect -u"$2" --database="$3"'
            kwargs = {"timeout": 1800, "output": output or self.log}
            if source is not None: kwargs["stdin"] = source
            else: kwargs["data"] = body
            self.native(command, self.auth_directory(), self.state["user"], database, **kwargs)
        finally:
            # Any error leaves durable account locks/read_only. Re-establish
            # the stronger barrier if possible; never automatically release.
            self.sql("SET GLOBAL super_read_only=ON;")

    def proof(self, phase, database, filename):
        self.barrier()
        r = self.state["remote"]
        self.native('socket=$(MYSQL_PWD="$(cat "$4/password")" mysql --skip-reconnect -u"$2" -N -B -e "SELECT @@socket"); '
                    'printf "%s:%s@unix(%s)/%s?parseTime=true\\n" "$2" "$(cat "$4/password")" "$socket" "$3" > "$1/proof.dsn"', r, self.state["user"], database,self.auth_directory())
        with (self.directory / filename).open("xb") as out:
            self.native('TMPDIR="$1/hash-temp" "$1/proof" --dsn-file "$1/proof.dsn" --source-inventory-file "$1/inventory.json" --phase "$2" --timeout 10m', r, phase, output=out, timeout=660)
            out.flush(); os.fsync(out.fileno())
        value = json.loads((self.directory / filename).read_bytes())
        if len(value["tables"]) != 99 or value["migration_authorized"]: raise RuntimeError("original_rows_proof_invalid")
        self.barrier()
        return value

    def dump(self, filename):
        self.barrier()
        estimate=self.sql("SELECT CEIL(COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0)/1024/1024) FROM information_schema.TABLES WHERE TABLE_SCHEMA='clawmanager';").strip()
        if not estimate.isdigit() or shutil.disk_usage(self.directory).free<(int(estimate)*3+1024)*1024*1024:raise RuntimeError("persistent_dump_capacity_insufficient")
        with (self.directory / filename).open("xb") as out:
            self.native('export MYSQL_PWD="$(cat "$1/password")"; exec mysqldump -u"$2" --single-transaction --quick --skip-lock-tables --skip-add-locks --set-gtid-purged=OFF --no-tablespaces --hex-blob --skip-comments --skip-dump-date --order-by-primary --skip-extended-insert clawmanager', self.auth_directory(), self.state["user"], output=out, timeout=1800)
            out.flush(); os.fsync(out.fileno())
        self.barrier()
        return {"file": filename, "sha256": file_hash(self.directory / filename), "bytes": (self.directory / filename).stat().st_size}

    def original_rows_equal(self, a, b, full=True):
        if a["preservation_sha256"] != b["preservation_sha256"]: raise RuntimeError("original_rows_changed")
        for left, right in zip(a["tables"], b["tables"]):
            fields = ("name", "rows", "sha256", "full_sha256") if full else ("name", "rows", "sha256")
            if any(left.get(k) != right.get(k) for k in fields): raise RuntimeError("original_table_changed")

    def load(self):
        self.state = json.loads((self.directory / "original-state.json").read_bytes())
        if self.state.get("context")!=self.a.context:raise RuntimeError("original_kubernetes_context_changed")
        if not re.fullmatch(r"[0-9a-f]{32}", self.state["operation"]) or self.state["remote"] != "/tmp/sbk-original-upgrade-" + self.state["operation"]: raise RuntimeError("private_original_state_invalid")
        bindings=sorted(self.directory.glob("controller-recovery-[0-9]*.json"))
        if bindings:
            binding=json.loads(bindings[-1].read_bytes())
            if binding["operation"]!=self.state["operation"] or binding["storage"]!=self.state["storage"]:raise RuntimeError("foreign_controller_recovery_binding")
            self.state.update(pod=binding["pod"],pod_uid=binding["pod_uid"],container_id=binding["container_id"])
            if binding.get("cancel_only_original_root"):
                if self.a.action not in ("cancel","cleanup"):raise RuntimeError("partial_initial_principal_recovery_cancel_only")
                self.root_fallback=True
        self.log = (self.directory / ("private-" + self.a.action + "-" + secrets.token_hex(4) + ".log")).open("xb")
        self.identity()
        if self.a.action=="cleanup":
            self.root_fallback=True
            return
        # A Pod temporary directory can disappear after a restart, but an old
        # operation never recreates it on a new container or extends its hold.
        if self.native('sha256sum "$1/password"', self.state["remote"]).decode().split()[0] != digest((self.directory / "recovery-password").read_bytes()): raise RuntimeError("original_recovery_custody_changed")
        # Recovery epochs are immutable files, never rewritten under an old
        # delayed kubectl exec. Old commands continue to name their OLD
        # credential directory and therefore cannot authenticate after fencing.
        heads=sorted(self.directory.glob("auth-*.intent.json"))
        if heads:
            intent=json.loads(heads[-1].read_bytes())
            self.credentials_directory=intent["directory"]
            name=intent["name"]
            if not re.fullmatch(r"auth-[0-9]{6}",name) or intent["directory"]!=self.state["remote"]+"/"+name:raise RuntimeError("native_recovery_epoch_invalid")
            private=(self.directory/(name+".password")).read_bytes()
            if digest(private)!=intent["password_sha256"] or self.native('sha256sum "$1/password"',intent["directory"]).decode().split()[0]!=intent["password_sha256"]:raise RuntimeError("native_recovery_epoch_custody_changed")
            if self.sql("SELECT @@server_uuid,CURRENT_USER();").strip()!=SERVER+"\t"+self.state["user"]+"@localhost":raise RuntimeError("native_recovery_password_outcome_unknown_keep_barrier")
            self.recovery_facts_file=name+".account.json"
            if not(self.directory/self.recovery_facts_file).exists():self.save_recovery_account(self.recovery_facts_file)
            if not(self.directory/(name+".confirmed.json")).exists():save_json(self.directory/(name+".confirmed.json"),{"state":"same_original_recovery_account_new_password_confirmed"})

    def save_recovery_account(self,filename):
        rows=[r for r in self.user_rows() if (r["user"],r["host"])==(self.state["user"],"localhost")]
        if len(rows)!=1:raise RuntimeError("native_recovery_identity_missing")
        save_json(self.directory/filename,{"row":rows[0],"grants":self.sql(f"SHOW GRANTS FOR {account(self.state['user'])}@'localhost';").splitlines()})

    def fence_pending_native(self,partial_prepare=False):
        # Authenticated SAME operation recovery, never a new migration. Rotate
        # only this private temporary principal, then kill its old sessions.
        # Original app/root password hashes are not changed. Delayed old exec
        # commands use immutable OLD credential paths and cannot restart DDL.
        if (self.directory/"released.json").exists() or (self.directory/"release.send-unknown.json").exists():raise RuntimeError("release_started_no_old_backup_rollback_or_new_fence")
        self.identity()
        if self.sql("SELECT @@server_uuid,CURRENT_USER();").strip()!=SERVER+"\t"+self.state["user"]+"@localhost":raise RuntimeError("original_recovery_identity_invalid")
        if partial_prepare:
            if (self.directory/"original-ddl.send-unknown.json").exists():raise RuntimeError("partial_prepare_recovery_cannot_cover_ddl")
            originals={(row["user"],row["host"]):row for row in self.state["users"]}
            current=self.user_rows()
            if len(current)!=len(originals)+1:raise RuntimeError("partial_prepare_foreign_account")
            for row in current:
                if (row["user"],row["host"])==(self.state["user"],"localhost"):continue
                old=originals.get((row["user"],row["host"]))
                if old is None or any(old[k]!=row[k] for k in ("plugin","authentication")):raise RuntimeError("partial_prepare_original_auth_changed")
                if self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};").splitlines()!=old["grants"]:raise RuntimeError("partial_prepare_original_grants_changed")
        else:self.barrier(allow_owned_pending=True)
        self.sql("SET GLOBAL super_read_only=OFF;")
        index=len(list(self.directory.glob("auth-*.intent.json")))+1
        if index>100:raise RuntimeError("native_recovery_epochs_exhausted")
        name=f"auth-{index:06d}";new_directory=self.state["remote"]+"/"+name
        password=secrets.token_hex(32).encode();write_new(self.directory/(name+".password"),password)
        self.native('mkdir -m 700 "$1"; cat > "$1/password"; chmod 600 "$1/password"',new_directory,data=password)
        intent={"name":name,"directory":new_directory,"password_sha256":digest(password),"operation":self.state["operation"]}
        save_json(self.directory/(name+".intent.json"),intent)
        self.append("same_original_recovery_principal_password_fence_send_unknown",{"epoch":name})
        self.sql(f"ALTER USER {account(self.state['user'])}@'localhost' IDENTIFIED BY '{password.decode()}';")
        self.credentials_directory=new_directory
        if self.sql("SELECT CURRENT_USER();").strip()!=self.state["user"]+"@localhost":raise RuntimeError("native_password_fence_unknown")
        self.recovery_facts_file=name+".account.json";self.save_recovery_account(self.recovery_facts_file)
        save_json(self.directory/(name+".confirmed.json"),{"state":"same_original_private_recovery_password_fenced"})
        ids=self.sql("SELECT ID FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND USER='"+self.state["user"]+"';").splitlines()
        for native_id in ids:
            if not native_id.isdigit():raise RuntimeError("native_pending_session_invalid")
            self.sql("KILL CONNECTION "+native_id+";")
        self.sql("SET GLOBAL super_read_only=ON;")

    def prepare(self):
        if self.directory.exists(): raise RuntimeError("new_private_operation_directory_required")
        self.directory.mkdir(mode=0o700)
        self.command_lock=(self.directory/"command.lock").open("a+b")
        fcntl.flock(self.command_lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.log = (self.directory / "private-prepare.log").open("xb")
        if file_hash(self.a.v3_archive) != V3: raise RuntimeError("exact_passed_v3_archive_required")
        # A new reviewed proof binary adds READ ONLY original-before/after;
        # it never weakens the original copy phases or contains migration DDL.
        proof = self.a.original_proof.read_bytes()
        if digest(proof) != self.a.original_proof_sha256 or proof[:6] != b"\x7fELF\x02\x01" or len(proof)<20 or struct.unpack_from("<H",proof,18)[0]!=62: raise RuntimeError("reviewed_original_linux_amd64_readproof_required")
        with tarfile.open(self.a.v3_archive, "r:gz") as t:
            inputs = {n: t.extractfile("upgrade198-copy/inputs/" + n).read() for n in ("inventory.json", "rename.sql", "upgrade.sql", "profile.json")}
        strip_copy_guard(inputs["rename.sql"], RENAME); strip_copy_guard(inputs["upgrade.sql"], UPGRADE)
        operation = secrets.token_hex(16)
        self.state = {"operation": operation, "remote": "/tmp/sbk-original-upgrade-" + operation,
                      "user": "cm_upg_" + operation[:24], "context": self.a.context}
        pods = json.loads(self.k("get", "pods", "-o", "json"))["items"]
        selected = []
        for pod in pods:
            for owner in pod["metadata"].get("ownerReferences", []):
                if owner.get("controller") and owner["kind"] == "ReplicaSet":
                    rs = self.obj("replicaset", owner["name"])
                    if rs["metadata"]["uid"] == owner["uid"] and any(o.get("controller") and o["kind"] == "Deployment" and o["uid"] == MYSQL_UID for o in rs["metadata"].get("ownerReferences", [])): selected.append(pod)
        if len(selected) != 1: raise RuntimeError("unique_original_mysql_pod_required")
        pod = selected[0]; status = [s for s in pod["status"]["containerStatuses"] if s["name"] == "mysql"]
        if len(status) != 1: raise RuntimeError("original_mysql_container_required")
        mysql_containers=[c for c in pod["spec"]["containers"] if c["name"]=="mysql"]
        if len(mysql_containers)!=1 or any(not account_lock_safe_probe(mysql_containers[0].get(kind)) for kind in ("startupProbe","readinessProbe","livenessProbe")):raise RuntimeError("mysql_health_probe_not_account_lock_safe")
        self.state.update(pod=pod["metadata"]["name"], pod_uid=pod["metadata"]["uid"], container_id=status[0]["containerID"])
        mysql=self.obj("deployment","mysql")
        self.state["mysql_spec_sha256"]=digest(json.dumps(mysql["spec"],sort_keys=True).encode())
        self.state["storage"]=self.storage_identity(pod)
        if not self.state["storage"]:raise RuntimeError("mysql_original_persistent_pvc_mapping_required")
        self.state["mysql_images"]={s["name"]:s["imageID"] for s in pod["status"].get("containerStatuses",[])}
        self.state["mysql_service_account"]=pod["spec"].get("serviceAccountName","default")
        self.state["mysql_service_account_uid"]=self.obj("serviceaccount",self.state["mysql_service_account"])["metadata"]["uid"]
        self.identity()
        # Real existing Kubernetes API/RBAC exclusion before any SQL account or
        # application mutation. A second host cannot create another operation
        # by inventing a private directory or a caller Passed/lease JSON.
        lock={"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":LOCK_NAME,"namespace":NS},"immutable":True,"data":{"operation":operation,"server_uuid":SERVER,"namespace_uid":NS_UID}}
        save_json(self.directory/"initial-kube-exclusion.intent.json",self.state)
        try:lock_raw=self.k("create","-f","-","-o","json",data=json.dumps(lock).encode())
        except Exception:
            lock_raw=self.k("get","configmap",LOCK_NAME,"--ignore-not-found","-o","json")
            if not lock_raw.strip():raise RuntimeError("original_cluster_exclusion_create_unknown_query_only")
        actual_lock=json.loads(lock_raw)
        if actual_lock.get("data")!=lock["data"] or actual_lock.get("immutable") is not True:raise RuntimeError("foreign_original_upgrade_exclusion")
        self.state["kube_lock_uid"]=actual_lock["metadata"]["uid"]
        save_json(self.directory/"initial-kube-exclusion.json",self.state)
        initial = self.sql("SELECT @@server_uuid,CURRENT_USER(),@@global.read_only,@@global.super_read_only;", recovery=False).strip().split("\t")
        if initial != [SERVER, "root@localhost", "0", "0"]: raise RuntimeError("original_native_root_or_globals_unexpected")
        if self.sql("SELECT VERSION();",recovery=False).strip()!="8.4.8":raise RuntimeError("reviewed_mysql_8_4_8_required")
        datadir=self.sql("SELECT @@datadir;",recovery=False).strip().rstrip("/")
        containers=[c for c in pod["spec"]["containers"] if c["name"]=="mysql"]
        stored={p["volume"] for p in self.state["storage"]}
        if len(containers)!=1 or not any(m["name"] in stored and not m.get("subPathExpr") and (datadir==m["mountPath"].rstrip("/") or datadir.startswith(m["mountPath"].rstrip("/")+"/")) for m in containers[0].get("volumeMounts",[])):raise RuntimeError("mysql_datadir_not_bound_to_original_pvc")
        databases = self.sql("SHOW DATABASES;", recovery=False).splitlines()
        if set(databases) != {"mysql", "sys", "information_schema", "performance_schema", "clawmanager"}: raise RuntimeError("dedicated_original_mysql_required_no_other_business_or_copy_databases")
        persisted = self.sql("SELECT VARIABLE_NAME,VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME IN ('read_only','super_read_only') ORDER BY VARIABLE_NAME;", recovery=False)
        self.state["persisted"] = persisted
        app = self.obj("deployment", "clawmanager-app")
        if app["metadata"]["uid"] != APP_UID or app["metadata"].get("deletionTimestamp"): raise RuntimeError("original_application_replaced")
        self.state["application"] = app
        r = self.state["remote"]
        self.native('mkdir -m 700 "$1"; mkdir -m 700 "$1/hash-temp"', r)
        password = secrets.token_hex(32).encode()
        write_new(self.directory / "recovery-password", password)
        write_new(self.directory / "original-proof",proof)
        self.state["original_proof_sha256"]=digest(proof)
        self.upload("password", password)
        self.upload("proof", proof); self.native('chmod 700 "$1/proof"', r)
        for name, raw in inputs.items(): write_new(self.directory / name, raw); self.upload(name, raw)
        # Refuse an unreviewed original99/97/control-work profile BEFORE any
        # account lock or application stop. This is only initial validation;
        # backup repeats the full baseline after the actual native barrier.
        self.stage="prepare/read_only_original_profile_before_any_sql_mutation"
        self.native('socket=$(MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --skip-reconnect -uroot -N -B -e "SELECT @@socket"); printf "root:%s@unix(%s)/clawmanager?parseTime=true\\n" "$MYSQL_ROOT_PASSWORD" "$socket" > "$1/preflight.dsn"',r)
        with (self.directory/"pre-maintenance-original-rows.json").open("xb") as output:
            self.native('TMPDIR="$1/hash-temp" "$1/proof" --dsn-file "$1/preflight.dsn" --source-inventory-file "$1/inventory.json" --phase original-before --timeout 10m',r,output=output,timeout=660)
            output.flush();os.fsync(output.fileno())
        preflight=json.loads((self.directory/"pre-maintenance-original-rows.json").read_bytes())
        if len(preflight["tables"])!=99 or preflight.get("read_mode")!="original_database_readonly_not_migration_authority" or preflight["migration_authorized"]:raise RuntimeError("original_premaintenance_profile_rejected")
        # Capture all original native accounts before introducing the one
        # operation-private recovery principal. Auth hashes stay private.
        users = parse_native_account_snapshot(self.sql(ACCOUNT_SNAPSHOT_SQL, recovery=False))
        for row in users:
            row["grants"] = self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};", recovery=False).splitlines()
        self.state["account_authentication_encoding"] = ACCOUNT_AUTHENTICATION_ENCODING
        self.state["users"] = users
        schema_defaults=self.sql("SELECT DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='clawmanager';",recovery=False).strip().split("\t")
        if len(schema_defaults)!=2 or any(not re.fullmatch(r"[a-z0-9_]+",v) for v in schema_defaults):raise RuntimeError("original_database_defaults_unreadable")
        self.state["database_defaults"]=schema_defaults
        source_inventory=json.loads(inputs["inventory.json"])
        old_names=sorted(t["name"] for t in source_inventory["schema"]["tables"] if t["name"].startswith(("system_backup","system_maintenance","system_restore","system_artifact")))
        if len(old_names)!=35:raise RuntimeError("original_control_table_set_changed")
        native_ids=self.sql("SELECT TABLE_ID,NAME FROM information_schema.INNODB_TABLES WHERE NAME LIKE 'clawmanager/%' ORDER BY NAME;",recovery=False)
        by_name={}
        for line in native_ids.splitlines():
            fields=line.split("\t")
            if len(fields)!=2 or not fields[0].isdigit():raise RuntimeError("original_innodb_table_identity_unreadable")
            by_name[fields[1]]=fields[0]
        self.state["original_control_tables"]=[]
        for index,name in enumerate(old_names,1):
            native_id=by_name.get("clawmanager/"+name)
            if native_id is None:raise RuntimeError("original_innodb_control_table_identity_missing")
            self.state["original_control_tables"].append({"name":name,"alias":f"dlegacy_{index:02d}_{name[:39]}","table_id":native_id})
        save_json(self.directory / "original-state.json", self.state)
        self.stage="prepare/create_native_recovery_and_lock_original_database_accounts"
        self.append("create_private_native_recovery_identity_send_unknown")
        user = account(self.state["user"]) + "@'localhost'"
        native_lock="cm_upg_create_"+operation
        create_sql=(f"SET @owned_create_lock=GET_LOCK('{native_lock}',0); SET @owned_create_assert=IF(@owned_create_lock=1,'DO 0','ORIGINAL_RECOVERY_CREATE_LOCK_UNAVAILABLE'); PREPARE owned_create_assert FROM @owned_create_assert; EXECUTE owned_create_assert; DEALLOCATE PREPARE owned_create_assert; CREATE USER {user} IDENTIFIED BY '{password.decode()}'; GRANT ALL PRIVILEGES ON *.* TO {user}; GRANT SYSTEM_USER,SYSTEM_VARIABLES_ADMIN,CONNECTION_ADMIN,PERSIST_RO_VARIABLES_ADMIN ON *.* TO {user};").encode()
        # Atomic native directory ownership plus cancel marker fence a delayed
        # ORIGINAL-root CREATE/GRANT exec, whose credential cannot be rotated.
        # Parent scratch is never recreated by this late command. A completed
        # cancellation removes it, so the delayed mkdir then fails safely.
        self.native('r="$1"; mkdir "$r/root-create-active"; trap \'rmdir "$r/root-create-active"\' EXIT; test ! -e "$r/cancel-root-create"; export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; set +e; mysql --skip-reconnect -uroot --database=mysql; rc=$?; printf "%s\\n" "$rc" > "$r/root-create.exit"; exit "$rc"',r,data=create_sql,output=self.log,timeout=180)
        if self.sql("SELECT @@server_uuid,CURRENT_USER();").strip() != SERVER + "\t" + self.state["user"] + "@localhost": raise RuntimeError("new_recovery_identity_not_confirmed")
        recovery_rows=[row for row in self.user_rows() if row["user"]==self.state["user"] and row["host"]=="localhost"]
        if len(recovery_rows)!=1:raise RuntimeError("recovery_account_identity_missing")
        save_json(self.directory/"recovery-account.json",{"row":recovery_rows[0],"grants":self.sql(f"SHOW GRANTS FOR {user};").splitlines()})
        # Persist all originals BEFORE sends. New clients including privileged
        # originals cannot bypass read_only once their native accounts lock.
        self.append("lock_all_original_native_accounts_send_unknown")
        for row in users:
            if row["locked"] == "N": self.sql(f"ALTER USER {account(row['user'])}@{account(row['host'])} ACCOUNT LOCK;")
        self.append("persistent_sql_readonly_send_unknown")
        self.sql("SET PERSIST read_only=ON; SET PERSIST super_read_only=ON;")
        # Terminate old sessions only after native account locks block new ones.
        ids = self.sql("SELECT ID FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND COMMAND<>'Daemon' AND USER<>'system user';").splitlines()
        for value in ids:
            if not re.fullmatch(r"[0-9]+", value): raise RuntimeError("foreign_session_identity_invalid")
            self.sql("KILL CONNECTION " + value + ";")
        self.append("close_original_management_deployment_send_unknown")
        self.stage="prepare/management_deployment_stop_and_native_barrier_readback"
        current = self.obj("deployment", "clawmanager-app")
        if current["spec"] != app["spec"]: raise RuntimeError("application_changed_before_close")
        patch = [{"op": "test", "path": "/metadata/uid", "value": APP_UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}, {"op": "replace", "path": "/spec/replicas", "value": 0}]
        self.k("patch", "deployment", "clawmanager-app", "--type=json", "-p", json.dumps(patch))
        for _ in range(120):
            current = self.obj("deployment", "clawmanager-app")
            if current["metadata"]["uid"] != APP_UID: raise RuntimeError("application_replaced")
            if current["spec"].get("replicas", 1) == 0 and current.get("status", {}).get("replicas", 0) == 0: break
            time.sleep(1)
        self.barrier()
        save_json(self.directory / "sql-held.json", {"operation": operation, "kind": "native_mysql_accounts_locked_readonly_and_management_app_stopped_not_B_physical_hold"})
        self.result={"state":"original_sql_writes_fenced_persistently_management_app_stopped","database_scope_only":True}

    def backup(self):
        self.load(); self.barrier()
        if (self.directory / "backup-verified.json").exists(): return
        estimate=self.sql("SELECT CEIL(COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0)/1024/1024) FROM information_schema.TABLES WHERE TABLE_SCHEMA='clawmanager';").strip()
        free=self.native('df -Pm /var/lib/mysql').decode().splitlines()
        if not estimate.isdigit() or len(free)!=2 or len(free[1].split())<4 or not free[1].split()[3].isdigit():raise RuntimeError("backup_capacity_unavailable")
        required=int(estimate)*3+1024
        if int(free[1].split()[3])<required or shutil.disk_usage(self.directory).free<required*1024*1024:raise RuntimeError("backup_or_restore_capacity_insufficient")
        # All writes are closed; original full baseline and saved-file restore
        # must match exactly, INCLUDING the full model updated_at hash.
        before = self.proof("original-before", "clawmanager", "original-before.json")
        self.stage="backup/save_full_original_schema_and_data"
        info = self.dump("original-full.sql")
        clone = "cm_import_" + self.state["operation"]
        if clone in self.sql("SHOW DATABASES;").splitlines():raise RuntimeError("backup_clone_exists_no_partial_restore_resume")
        save_json(self.directory/"backup-clone-create-intent.json",{"schema":clone,"observed_absent_under_actual_sql_barrier":True,"server_uuid":SERVER,"kube_lock_uid":self.state["kube_lock_uid"]})
        self.append("backup_restore_clone_create_send_unknown", clone)
        self.exclusive_sql(("CREATE DATABASE " + clone + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n").encode(), "mysql")
        self.append("backup_same_saved_file_restore_send_unknown", info)
        self.stage="backup/restore_and_prove_same_saved_file"
        with (self.directory / "original-full.sql").open("rb") as f: self.exclusive_sql(None, clone, source=f)
        restored = self.proof("before", clone, "backup-restored-rows.json")
        after = self.proof("original-before", "clawmanager", "original-before-after-backup.json")
        self.original_rows_equal(before, restored); self.original_rows_equal(before, after)
        if file_hash(self.directory / "original-full.sql") != info["sha256"]: raise RuntimeError("saved_backup_changed")
        save_json(self.directory / "backup-verified.json", {**info, "preservation_sha256": before["preservation_sha256"], "same_file_actually_restored": True})
        self.append("drop_verified_backup_clone_send_unknown", clone)
        self.exclusive_sql(("DROP DATABASE " + clone + ";\n").encode(), "mysql")
        if clone in self.sql("SHOW DATABASES;").splitlines():raise RuntimeError("verified_restore_clone_cleanup_unknown")
        self.result={"state":"original_final_cut_saved_backup_same_file_restored_and_full99_baseline_matched","backup_sha256":info["sha256"],"preservation_sha256":before["preservation_sha256"]}

    def apply(self):
        self.load(); self.barrier()
        verified = json.loads((self.directory / "backup-verified.json").read_bytes())
        if file_hash(self.directory / verified["file"]) != verified["sha256"]: raise RuntimeError("saved_verified_backup_changed")
        # Any attempted DDL is NEVER replayed/resumed; query same state or
        # restore original schema from the independently verified saved file.
        if (self.directory / "original-ddl.send-unknown.json").exists(): raise RuntimeError("original_ddl_already_attempted_query_or_full_rollback_only")
        current = self.proof("original-before", "clawmanager", "original-before-ddl.json")
        self.original_rows_equal(json.loads((self.directory / "original-before.json").read_bytes()), current)
        rename = strip_copy_guard((self.directory / "rename.sql").read_bytes(), RENAME)
        upgrade = strip_copy_guard((self.directory / "upgrade.sql").read_bytes(), UPGRADE)
        if upgrade.count(b"SELECT 'MIGRATION:") != 101: raise RuntimeError("not_exact_101_migrations")
        save_json(self.directory / "original-ddl.send-unknown.json", {"operation": self.state["operation"], "rename_input_sha256": RENAME, "upgrade_input_sha256": UPGRADE, "backup_sha256": verified["sha256"]})
        self.append("original_35_alias_and_101_ddl_send_unknown_not_transactional")
        self.stage="apply/rename_original35_aliases_once"
        self.exclusive_sql(rename)
        self.stage="apply/execute_exact101_migrations_once"
        self.exclusive_sql(upgrade)
        self.stage="apply/original198_and_full99_readback"
        self.verify_upgrade()

    def verify_upgrade(self):
        self.barrier()
        proof = self.proof("original-after", "clawmanager", "original-after-" + secrets.token_hex(4) + ".json")
        self.original_rows_equal(json.loads((self.directory / "original-before.json").read_bytes()), proof, full=False)
        if proof["expected_ledger_rows"] != 198: raise RuntimeError("original198_not_verified")
        if not (self.directory / "original-upgraded-readback.json").exists(): save_json(self.directory / "original-upgraded-readback.json", {"state": "original198_exact_readback_sql_barrier_retained", "preservation_sha256": proof["preservation_sha256"], "upgraded_schema_sha256": proof["upgraded_schema_sha256"]})
        self.result={"state":"original198_exact_readback_sql_barrier_retained","ledger_rows":198,"preservation_sha256":proof["preservation_sha256"],"original_database_upgraded":True}

    def rollback(self):
        self.load(); self.fence_pending_native(); self.barrier()
        self.stage="rollback/fence_old_sessions_and_validate_original_backup"
        verified = json.loads((self.directory / "backup-verified.json").read_bytes())
        if file_hash(self.directory / verified["file"]) != verified["sha256"]: raise RuntimeError("saved_verified_backup_changed")
        if not (self.directory / "original-ddl.send-unknown.json").exists(): raise RuntimeError("no_original_ddl_use_release_before_upgrade")
        # An earlier full restore whose reply was lost is verified rather than
        # overwritten. The native original35 metadata identity is checked too.
        if (self.directory/"full-original-restore.send-unknown.json").exists():
            try:
                already=self.proof("original-before","clawmanager","rollback-query-"+secrets.token_hex(4)+".json")
                self.original_rows_equal(json.loads((self.directory/"original-before.json").read_bytes()),already)
                if not(self.directory/"original-rollback-readback.json").exists():save_json(self.directory/"original-rollback-readback.json",{"state":"original99_97_exact_restore_verified_after_reply_loss"})
                self.result={"state":"original99_97_exact_restore_verified_after_reply_loss_barrier_retained","original_database_upgraded":False}
                return
            except Exception:pass
        # Retain failed original schema+rows before the first destructive
        # restore. It is never replaced by a later partly restored snapshot.
        failed = self.preserve_failed_original()
        # First prove the SAME backup is restorable again in isolation. No live
        # DROP/restore happens merely because an old success bit exists.
        clone = "cm_import_" + self.state["operation"]
        self.exclusive_sql(("DROP DATABASE IF EXISTS " + clone + "; CREATE DATABASE " + clone + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n").encode(), "mysql")
        with (self.directory / verified["file"]).open("rb") as f: self.exclusive_sql(None, clone, source=f)
        restored = self.proof("before", clone, "rollback-isolated-" + secrets.token_hex(4) + ".json")
        self.original_rows_equal(json.loads((self.directory / "original-before.json").read_bytes()), restored)
        preserved=self.preserve_original_control_tables()
        self.stage="rollback/restore_original99_schema_data_preserve_original35_dictionary"
        self.append("full_original_schema_restore_send_unknown", {"saved_backup_sha256": verified["sha256"], "failed_original_archive_sha256": failed["sha256"]})
        if not(self.directory/"full-original-restore.send-unknown.json").exists():save_json(self.directory/"full-original-restore.send-unknown.json",{"backup_sha256":verified["sha256"],"preserved_native_schema":preserved})
        # User explicitly selects rollback. Actual locked original identity,
        # failed-state archive and just-restored complete original99 proof
        # precede this exact original target. No migration ledger is repaired.
        charset,collation=self.state["database_defaults"]
        self.exclusive_sql(("SET FOREIGN_KEY_CHECKS=0; DROP DATABASE IF EXISTS clawmanager; CREATE DATABASE clawmanager CHARACTER SET "+charset+" COLLATE "+collation+";\n").encode(), "mysql")
        with (self.directory / verified["file"]).open("rb") as f: self.exclusive_sql(None, "clawmanager", source=f)
        # SQL dump roundtrip has ONE already-reviewed generated-expression
        # normalization in old system_artifact_leases. Restore the actual
        # ORIGINAL35 empty native tables by dictionary identity, instead of
        # weakening original schema equality or pretending a dump preserves
        # the original information_schema representation verbatim.
        self.restore_original_control_tables(preserved)
        proof = self.proof("original-before", "clawmanager", "original-rolled-back-" + secrets.token_hex(4) + ".json")
        self.original_rows_equal(json.loads((self.directory / "original-before.json").read_bytes()), proof)
        self.exclusive_sql(("DROP DATABASE " + clone + ";\n").encode(), "mysql")
        if not (self.directory / "original-rollback-readback.json").exists(): save_json(self.directory / "original-rollback-readback.json", {"state": "original99_97_schema_and_rows_restored_barrier_retained"})
        self.result={"state":"original99_97_schema_and_rows_restored_barrier_retained","original_database_upgraded":False}

    def preserve_failed_original(self):
        seal = self.directory / "failed-original-preserved.json"
        if not seal.exists():
            # A killed/timed-out dump may leave any amount of partial SQL.
            # Preserve that attempt without reusing it. A fresh create-only
            # attempt is allowed only while this same native barrier holds;
            # rollback cannot DROP original data until one complete seal exists.
            attempt = "failed-original-" + secrets.token_hex(16)
            filename = attempt + ".sql"
            save_json(self.directory / (attempt + ".intent.json"), {
                "operation": self.state["operation"], "server_uuid": SERVER,
                "file": filename, "state": "failed_original_full_dump_send_unknown"})
            failed = self.dump(filename)
            if failed["file"] != filename: raise RuntimeError("failed_state_archive_changed")
            self.barrier()
            if file_hash(self.directory / filename) != failed["sha256"] or (self.directory / filename).stat().st_size != failed["bytes"]:
                raise RuntimeError("failed_state_archive_changed")
            save_json(seal, failed)
        failed = json.loads(seal.read_bytes())
        if file_hash(self.directory / failed["file"]) != failed["sha256"] or (self.directory / failed["file"]).stat().st_size != failed["bytes"]:
            raise RuntimeError("failed_state_archive_changed")
        return failed

    def preserve_original_control_tables(self):
        schema="cm_native_"+self.state["operation"]
        if not re.fullmatch(r"cm_native_[0-9a-f]{32}",schema):raise RuntimeError("native_preservation_schema_invalid")
        names=self.sql("SHOW DATABASES;").splitlines()
        if schema not in names:self.exclusive_sql(("CREATE DATABASE "+schema+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n").encode(),"mysql")
        raw=self.sql("SELECT TABLE_ID,NAME FROM information_schema.INNODB_TABLES WHERE NAME LIKE 'clawmanager/%' OR NAME LIKE '"+schema+"/%' ORDER BY TABLE_ID;")
        by_id={}
        for line in raw.splitlines():
            fields=line.split("\t")
            if len(fields)!=2 or not fields[0].isdigit():raise RuntimeError("native_original_table_id_unreadable")
            by_id[fields[0]]=fields[1]
        moves=[]
        for old in self.state["original_control_tables"]:
            name=by_id.get(old["table_id"])
            allowed={"clawmanager/"+old["name"],"clawmanager/"+old["alias"],schema+"/"+old["name"]}
            if name not in allowed:raise RuntimeError("original_native_control_table_missing_or_replaced")
            database,table=name.split("/",1)
            if self.sql("SELECT COUNT(*) FROM `"+database+"`.`"+table+"`;").strip()!="0":raise RuntimeError("original_native_control_history_not_empty")
            if database!=schema:moves.append("`"+database+"`.`"+table+"` TO `"+schema+"`.`"+old["name"]+"`")
        self.append("preserve_original35_native_dictionary_ids_before_live_restore",{"schema":schema,"ids":[t["table_id"] for t in self.state["original_control_tables"]]})
        if moves:self.exclusive_sql(("SET FOREIGN_KEY_CHECKS=0; RENAME TABLE "+",".join(moves)+";\n").encode(),"mysql")
        return schema

    def restore_original_control_tables(self,schema):
        drops=[];moves=[]
        for old in self.state["original_control_tables"]:
            current=self.sql("SELECT TABLE_ID FROM information_schema.INNODB_TABLES WHERE NAME='"+schema+"/"+old["name"]+"';").strip()
            if current!=old["table_id"]:raise RuntimeError("preserved_original_native_table_changed")
            if self.sql("SELECT COUNT(*) FROM `clawmanager`.`"+old["name"]+"`;").strip()!="0":raise RuntimeError("restored_duplicate_control_history_not_empty")
            drops.append("`clawmanager`.`"+old["name"]+"`")
            moves.append("`"+schema+"`.`"+old["name"]+"` TO `clawmanager`.`"+old["name"]+"`")
        self.append("restore_exact_original35_dictionary_tables_not_dump_normalized_metadata")
        self.exclusive_sql(("SET FOREIGN_KEY_CHECKS=0; DROP TABLE "+",".join(drops)+"; RENAME TABLE "+",".join(moves)+"; SET FOREIGN_KEY_CHECKS=1;\n").encode(),"mysql")
        # Empty preservation schema can be removed only after full original
        # baseline readback; leave it untouched on any restoration failure.

    def query(self):
        self.load(); self.barrier()
        self.append("same_original_operation_native_barrier_query")
        if (self.directory / "original-ddl.send-unknown.json").exists() and not (self.directory / "original-rollback-readback.json").exists(): self.verify_upgrade()

    def recover(self):
        self.load();self.fence_pending_native();self.barrier()
        self.append("old_same_operation_sessions_cancelled_original_accounts_still_fenced")

    def release(self):
        self.load(); self.fence_pending_native(); self.barrier()
        attempted = (self.directory / "original-ddl.send-unknown.json").exists()
        rolled_back = (self.directory / "original-rollback-readback.json").exists()
        if attempted and not rolled_back and not (self.directory / "original-upgraded-readback.json").exists(): raise RuntimeError("unknown_or_partial_ddl_restore_original_before_release")
        if rolled_back:
            actual = self.proof("original-before", "clawmanager", "release-original-" + secrets.token_hex(4) + ".json")
            self.original_rows_equal(json.loads((self.directory / "original-before.json").read_bytes()), actual)
        elif attempted: self.verify_upgrade()
        self.cleanup_owned_schemas()
        self.append("release_original_sql_accounts_send_unknown_keep_application_stopped")
        save_json(self.directory/"release.send-unknown.json",{"operation":self.state["operation"],"original_result_readback_completed":True,"application_restore":rolled_back or not attempted})
        # Release credentials/globals only after exact result readback. The
        # management Deployment deliberately stays 0 for reviewed deployment;
        # do not automatically start an old application against new schema.
        self.sql("SET GLOBAL super_read_only=OFF;")
        for old in self.state["users"]:
            if old["locked"] == "N": self.sql(f"ALTER USER {account(old['user'])}@{account(old['host'])} ACCOUNT UNLOCK;")
        self.sql("SET GLOBAL read_only=OFF;")
        # Original globals were exactly 0/0 at Prepare. Restore original native
        # persistence entries, not just runtime values and a changed restart.
        original = dict(line.split("\t") for line in self.state["persisted"].splitlines())
        for variable in ("super_read_only", "read_only"):
            if variable in original:
                value = original[variable].upper()
                if value not in ("ON", "OFF", "0", "1"): raise RuntimeError("original_persisted_global_unrecognized")
                self.sql(f"SET PERSIST_ONLY {variable}={value};")
            else: self.sql(f"RESET PERSIST IF EXISTS {variable};")
        self.append("restore_original_replicas_only_when_original_schema_restored" if rolled_back or not attempted else "new_application_deployment_required")
        if rolled_back or not attempted:
            current = self.obj("deployment", "clawmanager-app"); old = self.state["application"]
            a = dict(current["spec"]); b = dict(old["spec"]); a.pop("replicas", None); b.pop("replicas", None)
            if current["metadata"]["uid"] != APP_UID or a != b: raise RuntimeError("application_spec_changed_original_restore_refused")
            patch = [{"op": "test", "path": "/metadata/uid", "value": APP_UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}, {"op": "replace", "path": "/spec/replicas", "value": old["spec"].get("replicas", 1)}]
            self.k("patch", "deployment", "clawmanager-app", "--type=json", "-p", json.dumps(patch))
        self.original_sql_state_readback()
        if rolled_back or not attempted:self.wait_original_application()
        save_json(self.directory / "released.json", {"state": "original_sql_accounts_globals_restored_actual_readback_completed", "upgraded": attempted and not rolled_back,"application_still_stopped":attempted and not rolled_back})
        self.result={"state":"original_sql_accounts_globals_restored_actual_readback_completed","application_still_stopped":attempted and not rolled_back}
        # The private recovery principal remains until a separately audited
        # final cleanup: deleting it before readback/recovery would strand a
        # partially released operation. Never publish its credential.

    def cancel(self):
        # Real recovery for a partial PREPARE, including root locked before the
        # application scale/read_only step. No DDL attempt may be cancelled as
        # though it were a transaction; that path must use full rollback.
        self.load()
        if (self.directory/"original-ddl.send-unknown.json").exists(): raise RuntimeError("ddl_attempted_full_rollback_required")
        if not(self.directory/"recovery-account.json").exists():self.root_fallback=True
        try:
            if self.root_fallback:raise RuntimeError("initial_principal_not_fully_confirmed")
            actual=self.sql("SELECT @@server_uuid,CURRENT_USER();").strip()
            if actual!=SERVER+"\t"+self.state["user"]+"@localhost": raise RuntimeError("unexpected_recovery_identity")
        except Exception:
            self.root_fallback=True
            if self.sql("SELECT @@server_uuid,CURRENT_USER();",recovery=False).strip()!=SERVER+"\troot@localhost": raise RuntimeError("original_native_recovery_authentication_unavailable")
        if self.root_fallback:
            self.native('mkdir -p "$1/cancel-root-create"',self.state["remote"])
            lock="cm_upg_create_"+self.state["operation"]
            for _ in range(120):
                owner=self.sql("SELECT IS_USED_LOCK('"+lock+"');",recovery=False).strip()
                if owner not in ("NULL",""):
                    if not owner.isdigit():raise RuntimeError("original_root_create_lock_owner_invalid")
                    if self.sql("SELECT USER FROM information_schema.PROCESSLIST WHERE ID="+owner+";",recovery=False).strip()!="root":raise RuntimeError("foreign_root_create_lock_owner")
                    self.sql("KILL CONNECTION "+owner+";",recovery=False)
                active=self.native('if test -d "$1/root-create-active"; then printf active; else printf absent; fi',self.state["remote"]).decode()
                if owner in ("NULL","") and active=="absent":break
                time.sleep(1)
            else:raise RuntimeError("initial_root_create_execution_not_settled_keep_cancel_marker")
        if not self.root_fallback:self.fence_pending_native(partial_prepare=True)
        if (self.directory/"sql-held.json").exists():
            self.barrier()
            self.cleanup_owned_schemas()
        rows=self.user_rows();old={(u["user"],u["host"]):u for u in self.state["users"]}
        for row in rows:
            if (row["user"],row["host"])==(self.state["user"],"localhost"):continue
            prior=old.get((row["user"],row["host"]))
            if prior is None or any(prior[k]!=row[k] for k in ("plugin","authentication")):raise RuntimeError("foreign_account_change_cancel_refused")
        if len(rows) not in (len(old),len(old)+1):raise RuntimeError("account_missing_cancel_refused")
        self.append("cancel_original_preDDL_maintenance_send_unknown")
        if not(self.directory/"release.send-unknown.json").exists():save_json(self.directory/"release.send-unknown.json",{"operation":self.state["operation"],"original_result_readback_completed":False,"application_restore":True,"preDDL_cancel":True})
        self.sql("SET GLOBAL super_read_only=OFF;")
        for prior in self.state["users"]:
            if prior["locked"]=="N":self.sql(f"ALTER USER {account(prior['user'])}@{account(prior['host'])} ACCOUNT UNLOCK;")
        self.sql("SET GLOBAL read_only=OFF;")
        original=dict(line.split("\t") for line in self.state["persisted"].splitlines())
        for variable in ("super_read_only","read_only"):
            if variable in original:
                value=original[variable].upper()
                if value not in ("ON","OFF","0","1"):raise RuntimeError("original_persisted_global_unrecognized")
                self.sql(f"SET PERSIST_ONLY {variable}={value};")
            else:self.sql(f"RESET PERSIST IF EXISTS {variable};")
        current=self.obj("deployment","clawmanager-app");prior=self.state["application"]
        a=dict(current["spec"]);b=dict(prior["spec"]);a.pop("replicas",None);b.pop("replicas",None)
        if current["metadata"]["uid"]!=APP_UID or a!=b:raise RuntimeError("original_application_spec_changed_cancel_refused")
        patch=[{"op":"test","path":"/metadata/uid","value":APP_UID},{"op":"test","path":"/metadata/resourceVersion","value":current["metadata"]["resourceVersion"]},{"op":"replace","path":"/spec/replicas","value":prior["spec"].get("replicas",1)}]
        self.k("patch","deployment","clawmanager-app","--type=json","-p",json.dumps(patch))
        self.original_sql_state_readback()
        self.wait_original_application()
        if not(self.directory/"cancelled.json").exists():save_json(self.directory/"cancelled.json",{"state":"original_preDDL_native_accounts_globals_application_restore_sent_readback_required"})

    def wait_original_application(self):
        wanted=self.state["application"]["spec"].get("replicas",1)
        for _ in range(120):
            app=self.obj("deployment","clawmanager-app")
            if app["metadata"]["uid"]!=APP_UID:raise RuntimeError("original_application_replaced")
            if app["spec"].get("replicas",1)==wanted and app.get("status",{}).get("readyReplicas",0)==wanted and app.get("status",{}).get("observedGeneration",0)>=app["metadata"]["generation"]:return
            time.sleep(1)
        raise RuntimeError("original_application_restore_readback_pending")

    def cleanup_owned_schemas(self):
        self.barrier()
        names=self.sql("SHOW DATABASES;").splitlines()
        clone="cm_import_"+self.state["operation"]
        preserved="cm_native_"+self.state["operation"]
        if clone in names:
            intent=json.loads((self.directory/"backup-clone-create-intent.json").read_bytes())
            if intent!={"schema":clone,"observed_absent_under_actual_sql_barrier":True,"server_uuid":SERVER,"kube_lock_uid":self.state["kube_lock_uid"]}:raise RuntimeError("unowned_clone_cleanup_refused")
            self.append("drop_same_operation_backup_restore_diagnostic_clone_before_original_accounts_unlock",clone)
            self.exclusive_sql(("DROP DATABASE "+clone+";\n").encode(),"mysql")
        if preserved in names:
            if not(self.directory/"original-rollback-readback.json").exists():raise RuntimeError("native_original35_preservation_still_needed")
            if self.sql("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+preserved+"';").strip()!="0":raise RuntimeError("native_original35_still_in_preservation_schema")
            self.append("drop_empty_original35_preservation_schema_after_full_rollback_readback",preserved)
            self.exclusive_sql(("DROP DATABASE "+preserved+";\n").encode(),"mysql")

    def original_sql_state_readback(self):
        originals={(r["user"],r["host"]):r for r in self.state["users"]}
        rows=self.user_rows()
        filtered=[r for r in rows if (r["user"],r["host"])!=(self.state["user"],"localhost")]
        if len(filtered)!=len(originals):raise RuntimeError("original_account_set_not_restored")
        for row in filtered:
            old=originals.get((row["user"],row["host"]))
            if old is None or any(old[k]!=row[k] for k in ("plugin","authentication","locked")):raise RuntimeError("original_account_state_not_restored")
            if self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};").splitlines()!=old["grants"]:raise RuntimeError("original_grants_not_restored")
        if self.sql("SELECT @@global.read_only,@@global.super_read_only;").strip()!="0\t0":raise RuntimeError("original_native_globals_not_restored")
        persisted=self.sql("SELECT VARIABLE_NAME,VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME IN ('read_only','super_read_only') ORDER BY VARIABLE_NAME;")
        if persisted!=self.state["persisted"]:raise RuntimeError("original_restart_configuration_not_restored")

    def finish_release(self):
        # Continue only restoration of original native account/global settings
        # after release has begun. Never replay or roll back migration/data;
        # business writes may legitimately have become possible already.
        self.load()
        intent=json.loads((self.directory/"release.send-unknown.json").read_bytes())
        if intent["operation"]!=self.state["operation"]:raise RuntimeError("foreign_release_intent")
        originals={(r["user"],r["host"]):r for r in self.state["users"]}
        current=self.user_rows()
        if len(current)!=len(originals)+1:raise RuntimeError("foreign_account_during_release")
        for row in current:
            if (row["user"],row["host"])==(self.state["user"],"localhost"):continue
            prior=originals.get((row["user"],row["host"]))
            if prior is None or any(prior[k]!=row[k] for k in ("plugin","authentication")):raise RuntimeError("foreign_account_auth_during_release")
            if self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};").splitlines()!=prior["grants"]:raise RuntimeError("foreign_grants_during_release")
        self.append("finish_same_original_release_not_migration_or_old_backup_restore")
        self.sql("SET GLOBAL super_read_only=OFF;")
        for row in self.state["users"]:
            state="LOCK" if row["locked"]=="Y" else "UNLOCK"
            self.sql(f"ALTER USER {account(row['user'])}@{account(row['host'])} ACCOUNT {state};")
        self.sql("SET GLOBAL read_only=OFF;")
        original=dict(line.split("\t") for line in self.state["persisted"].splitlines())
        for variable in ("super_read_only","read_only"):
            if variable in original:
                value=original[variable].upper()
                if value not in ("ON","OFF","0","1"):raise RuntimeError("original_persisted_global_unrecognized")
                self.sql(f"SET PERSIST_ONLY {variable}={value};")
            else:self.sql(f"RESET PERSIST IF EXISTS {variable};")
        self.original_sql_state_readback()
        if intent.get("application_restore"):
            app=self.obj("deployment","clawmanager-app");old=self.state["application"]
            actual=dict(app["spec"]);expected=dict(old["spec"]);actual.pop("replicas",None);expected.pop("replicas",None)
            if app["metadata"]["uid"]!=APP_UID or actual!=expected:raise RuntimeError("application_changed_finish_release_refused")
            patch=[{"op":"test","path":"/metadata/uid","value":APP_UID},{"op":"test","path":"/metadata/resourceVersion","value":app["metadata"]["resourceVersion"]},{"op":"replace","path":"/spec/replicas","value":old["spec"].get("replicas",1)}]
            self.k("patch","deployment","clawmanager-app","--type=json","-p",json.dumps(patch))
            self.wait_original_application()
        if not(self.directory/"released.json").exists():save_json(self.directory/"released.json",{"state":"same_original_release_completed_native_settings_readback","application_restore":intent.get("application_restore",False)})

    def early_query(self):
        if (self.directory/"original-state.json").exists():raise RuntimeError("original_state_exists_use_cancel_or_full_rollback")
        path=self.directory/"initial-kube-exclusion.json"
        if path.exists():self.state=json.loads(path.read_bytes())
        else:
            self.state=json.loads((self.directory/"initial-kube-exclusion.intent.json").read_bytes())
            raw=self.k("get","configmap",LOCK_NAME,"--ignore-not-found","-o","json")
            if not raw.strip():raise RuntimeError("original_cluster_exclusion_create_pending_query_same_operation")
            lock=json.loads(raw)
            if lock.get("immutable") is not True or lock.get("data")!={"operation":self.state["operation"],"server_uuid":SERVER,"namespace_uid":NS_UID}:raise RuntimeError("foreign_exclusion_do_not_delete")
            self.state["kube_lock_uid"]=lock["metadata"]["uid"]
            save_json(path,self.state)
        self.log=(self.directory/("private-early-query-"+secrets.token_hex(4)+".log")).open("xb")
        self.identity()
        events=[json.loads(p.read_bytes())["event"] for p in self.directory.glob("event-[0-9]*.json")]
        if events:raise RuntimeError("native_sql_mutation_intent_present_early_cancel_refused")
        if self.sql("SELECT @@server_uuid,CURRENT_USER();",recovery=False).strip()!=SERVER+"\troot@localhost":raise RuntimeError("original_root_unavailable_early_cancel")
        if self.sql("SELECT COUNT(*) FROM mysql.user WHERE User='"+self.state["user"]+"';",recovery=False).strip()!="0":raise RuntimeError("unexpected_native_recovery_account_early_cancel_refused")

    def early_cancel(self):
        self.early_query()
        # No native SQL mutating intent exists and the supposedly not-created
        # principal is independently absent. Only this confirmed operation's
        # scratch directory and UID/RV-pinned cluster exclusion are removed.
        self.native('case "$1" in /tmp/sbk-original-upgrade-????????????????????????????????) ;; *) exit 3;; esac; rm -rf -- "$1"',self.state["remote"])
        raw=self.k("get","configmap",LOCK_NAME,"--ignore-not-found","-o","json")
        if raw.strip():
            lock=json.loads(raw)
            options={"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":self.state["kube_lock_uid"],"resourceVersion":lock["metadata"]["resourceVersion"]}}
            if not(self.directory/"early-exclusion-delete.send-unknown.json").exists():save_json(self.directory/"early-exclusion-delete.send-unknown.json",options)
            self.k("delete","--raw",f"/api/v1/namespaces/{NS}/configmaps/{LOCK_NAME}","-f","-",data=json.dumps(options).encode())
        elif not(self.directory/"early-exclusion-delete.send-unknown.json").exists():raise RuntimeError("early_exclusion_missing_without_delete_intent")
        if not(self.directory/"early-cancel-completed.json").exists():save_json(self.directory/"early-cancel-completed.json",{"state":"early_owned_exclusion_and_scratch_removed_no_original_sql_or_app_mutation"})

    def recover_controller(self):
        # Actual fresh original deployment-operator recovery. No caller Pod UID,
        # Passed flag or replacement installer grant is accepted. Resolve the
        # real current singleton from the ORIGINAL Deployment UID, unchanged
        # spec/images/SA and same PVC/PV identity, then authenticate saved SAME
        # private principal against the ORIGINAL server_uuid and native state.
        self.state=json.loads((self.directory/"original-state.json").read_bytes())
        releasing=(self.directory/"release.send-unknown.json").exists()
        if releasing:
            release_intent=json.loads((self.directory/"release.send-unknown.json").read_bytes())
            if release_intent.get("operation")!=self.state["operation"]:raise RuntimeError("foreign_release_recovery_intent")
        if (self.directory/"released.json").exists() and not releasing:raise RuntimeError("released_operation_not_capture_recoverable")
        self.log=(self.directory/("private-controller-recovery-"+secrets.token_hex(4)+".log")).open("xb")
        if self.obj("namespace",NS)["metadata"]["uid"]!=NS_UID:raise RuntimeError("original_namespace_replaced")
        dep=self.obj("deployment","mysql")
        if dep["metadata"]["uid"]!=MYSQL_UID or digest(json.dumps(dep["spec"],sort_keys=True).encode())!=self.state["mysql_spec_sha256"]:raise RuntimeError("original_mysql_deployment_changed")
        selected=[]
        for pod in json.loads(self.k("get","pods","-o","json"))["items"]:
            owners=[o for o in pod["metadata"].get("ownerReferences",[]) if o.get("controller")]
            if len(owners)!=1 or owners[0]["kind"]!="ReplicaSet":continue
            rs=self.obj("replicaset",owners[0]["name"])
            if rs["metadata"]["uid"]==owners[0]["uid"] and any(o.get("controller") and o["kind"]=="Deployment" and o["uid"]==MYSQL_UID for o in rs["metadata"].get("ownerReferences",[])):selected.append(pod)
        if len(selected)!=1:raise RuntimeError("unique_actual_mysql_recovery_pod_required")
        pod=selected[0]
        if pod["metadata"].get("deletionTimestamp") or pod["spec"].get("ephemeralContainers") or pod["spec"].get("shareProcessNamespace"):raise RuntimeError("unsafe_original_mysql_recovery_pod")
        statuses=pod.get("status",{}).get("containerStatuses",[])
        if {s["name"]:s.get("imageID") for s in statuses}!=self.state["mysql_images"]:raise RuntimeError("mysql_recovery_image_changed")
        current=[s for s in statuses if s["name"]=="mysql"]
        if len(current)!=1 or not current[0].get("ready") or not current[0].get("containerID"):raise RuntimeError("mysql_recovery_container_not_ready")
        sa=pod["spec"].get("serviceAccountName","default")
        if sa!=self.state["mysql_service_account"] or self.obj("serviceaccount",sa)["metadata"]["uid"]!=self.state["mysql_service_account_uid"]:raise RuntimeError("mysql_recovery_service_account_changed")
        if self.storage_identity(pod)!=self.state["storage"]:raise RuntimeError("mysql_recovery_pvc_pv_or_local_node_changed")
        self.state.update(pod=pod["metadata"]["name"],pod_uid=pod["metadata"]["uid"],container_id=current[0]["containerID"])
        self.identity()
        r=self.state["remote"]
        # Rehydrate exclusively from retained original operation custody;
        # native account/password hashes remain on the SAME original PV.
        self.native('mkdir -p "$1/hash-temp"; chmod 700 "$1" "$1/hash-temp"',r)
        self.upload("password",(self.directory/"recovery-password").read_bytes())
        proof=(self.directory/"original-proof").read_bytes()
        if digest(proof)!=self.state["original_proof_sha256"]:raise RuntimeError("retained_original_readproof_changed")
        self.upload("proof",proof);self.native('chmod 700 "$1/proof"',r)
        for name in ("inventory.json","rename.sql","upgrade.sql","profile.json"):self.upload(name,(self.directory/name).read_bytes())
        intents=sorted(self.directory.glob("auth-*.intent.json"),reverse=True)
        candidates=[]
        for path in intents:
            head=json.loads(path.read_bytes());name=head["name"]
            if not re.fullmatch(r"auth-[0-9]{6}",name) or head["directory"]!=r+"/"+name:raise RuntimeError("retained_recovery_epoch_invalid")
            password=(self.directory/(name+".password")).read_bytes()
            if digest(password)!=head["password_sha256"]:raise RuntimeError("retained_recovery_password_changed")
            self.native('mkdir -p "$1"; chmod 700 "$1"; cat > "$1/password"; chmod 600 "$1/password"',head["directory"],data=password)
            candidates.append((head["directory"],name+".account.json"))
        candidates.append((r,"recovery-account.json"))
        authenticated=False
        for auth_dir,facts_name in candidates:
            self.credentials_directory=auth_dir;self.recovery_facts_file=facts_name
            try:
                authenticated=self.sql("SELECT @@server_uuid,CURRENT_USER();").strip()==SERVER+"\t"+self.state["user"]+"@localhost"
            except Exception:authenticated=False
            if authenticated:break
        cancel_only_root=False
        if not authenticated:
            if (self.directory/"recovery-account.json").exists() or (self.directory/"sql-held.json").exists() or (self.directory/"original-ddl.send-unknown.json").exists():raise RuntimeError("same_original_native_recovery_identity_unconfirmed")
            if self.sql("SELECT @@server_uuid,CURRENT_USER();",recovery=False).strip()!=SERVER+"\troot@localhost":raise RuntimeError("original_root_cancel_identity_unconfirmed")
            self.root_fallback=True;cancel_only_root=True
        if not cancel_only_root and not(self.directory/self.recovery_facts_file).exists():
            # Complete only genuine native password readback, never a guessed
            # password or time-renewed capture. Grants must remain original.
            expected=json.loads((self.directory/"recovery-account.json").read_bytes())["grants"]
            if self.sql(f"SHOW GRANTS FOR {account(self.state['user'])}@'localhost';").splitlines()!=expected:raise RuntimeError("same_original_recovery_grants_changed")
            self.save_recovery_account(self.recovery_facts_file)
        # PERSIST read_only + original account locks survive the server/PVC
        # restart. Independently require them before accepting the new target.
        partial_prepare=not(self.directory/"sql-held.json").exists() and not(self.directory/"original-ddl.send-unknown.json").exists()
        if releasing:
            # A released/partly released operation must NOT regain capture or
            # old-backup rollback authority merely because MySQL restarted.
            # Rebind only to finish original settings/credential cleanup.
            originals={(row["user"],row["host"]):row for row in self.state["users"]}
            rows=self.user_rows()
            if len(rows)!=len(originals)+1:raise RuntimeError("foreign_account_during_release_controller_recovery")
            for row in rows:
                if (row["user"],row["host"])==(self.state["user"],"localhost"):continue
                old=originals.get((row["user"],row["host"]))
                if old is None or any(row[k]!=old[k] for k in ("plugin","authentication")):raise RuntimeError("original_auth_changed_during_release_controller_recovery")
                if self.sql(f"SHOW GRANTS FOR {account(row['user'])}@{account(row['host'])};").splitlines()!=old["grants"]:raise RuntimeError("original_grants_changed_during_release_controller_recovery")
        elif not partial_prepare:self.barrier(allow_owned_pending=True)
        index=len(list(self.directory.glob("controller-recovery-[0-9]*.json")))+1
        binding={"operation":self.state["operation"],"pod":self.state["pod"],"pod_uid":self.state["pod_uid"],"container_id":self.state["container_id"],"storage":self.state["storage"],"server_uuid":SERVER}
        if cancel_only_root:binding["cancel_only_original_root"]=True
        save_json(self.directory/f"controller-recovery-{index:06d}.json",binding)
        if cancel_only_root:
            self.result={"state":"same_original_controller_rebound_initial_root_cancel_only"}
            return
        if releasing:
            self.append("same_original_controller_rebound_release_only_never_old_backup_or_capture",binding)
            self.result={"state":"same_original_controller_rebound_finish_release_or_cleanup_only"}
            return
        self.fence_pending_native(partial_prepare=partial_prepare)
        if not partial_prepare:self.barrier()
        self.append("same_original_server_volume_private_recovery_rebound_new_container_no_capture_renewal",binding)

    def retire_recovery_principal(self):
        # Caller has authenticated ORIGINAL root and read back restored state.
        # DROP USER alone does not close already-authenticated sessions. First
        # persist ACCOUNT LOCK and confirm it, closing the new-login race; then
        # kill peers and prove EOF both before and after DROP. Interrupted
        # cleanup retries this same principal, including already-absent cases.
        user = self.state["user"]
        current = [r for r in self.user_rows() if r["user"] == user]
        if any(r["host"] != "localhost" for r in current):
            raise RuntimeError("temporary_recovery_principal_not_removed")
        if current:
            self.append("lock_temporary_recovery_principal_before_drain_send_unknown")
            self.sql(f"ALTER USER {account(user)}@'localhost' ACCOUNT LOCK;", recovery=False)
            locked = [r for r in self.user_rows() if r["user"] == user]
            if len(locked) != 1 or locked[0]["host"] != "localhost" or locked[0]["locked"] != "Y":
                raise RuntimeError("temporary_recovery_principal_not_locked")
        query = "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='" + user + "';"
        for native_id in self.sql(query, recovery=False).splitlines():
            if not native_id.isdigit(): raise RuntimeError("recovery_session_invalid")
            self.sql("KILL CONNECTION " + native_id + ";", recovery=False)
        if self.sql(query, recovery=False).strip():
            raise RuntimeError("temporary_recovery_sessions_still_present")
        self.append("drop_temporary_recovery_principal_send_unknown_original_root_verified")
        self.sql(f"DROP USER IF EXISTS {account(user)}@'localhost';", recovery=False)
        if any(r["user"] == user for r in self.user_rows()):
            raise RuntimeError("temporary_recovery_principal_not_removed")
        if self.sql(query, recovery=False).strip():
            raise RuntimeError("temporary_recovery_sessions_still_present")

    def cleanup(self):
        self.load()
        if not (self.directory/"released.json").exists() and not(self.directory/"cancelled.json").exists():raise RuntimeError("original_release_not_completed_cleanup_refused")
        # Fresh original root was actually restored, not a retained temp-user
        # connection used to claim its own successful deletion.
        self.root_fallback=True
        if self.sql("SELECT @@server_uuid,CURRENT_USER();",recovery=False).strip()!=SERVER+"\troot@localhost":raise RuntimeError("original_root_not_restored")
        self.original_sql_state_readback()
        app=self.obj("deployment","clawmanager-app")
        restore=not(self.directory/"original-ddl.send-unknown.json").exists() or (self.directory/"original-rollback-readback.json").exists()
        expected=self.state["application"]["spec"].get("replicas",1) if restore else 0
        if app["metadata"]["uid"]!=APP_UID or app["spec"].get("replicas",1)!=expected or app.get("status",{}).get("readyReplicas",0)!=expected or app.get("status",{}).get("observedGeneration",0)<app["metadata"]["generation"]:raise RuntimeError("original_application_recovery_readback_pending")
        self.retire_recovery_principal()
        self.original_sql_state_readback()
        self.native('case "$1" in /tmp/sbk-original-upgrade-????????????????????????????????) ;; *) exit 3;; esac; rm -rf -- "$1"',self.state["remote"])
        lock_raw=self.k("get","configmap",LOCK_NAME,"--ignore-not-found","-o","json")
        if lock_raw.strip():
            lock=json.loads(lock_raw)
            if lock["metadata"]["uid"]!=self.state["kube_lock_uid"]:raise RuntimeError("original_exclusion_replaced")
            options={"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":self.state["kube_lock_uid"],"resourceVersion":lock["metadata"]["resourceVersion"]}}
            if not(self.directory/"kube-exclusion-delete.send-unknown.json").exists():save_json(self.directory/"kube-exclusion-delete.send-unknown.json",options)
            self.k("delete","--raw",f"/api/v1/namespaces/{NS}/configmaps/{LOCK_NAME}","-f","-",data=json.dumps(options).encode())
        elif not(self.directory/"kube-exclusion-delete.send-unknown.json").exists():raise RuntimeError("exclusion_missing_without_original_delete_intent")
        if not(self.directory/"cleanup-completed.json").exists():save_json(self.directory/"cleanup-completed.json",{"state":"original_native_accounts_globals_restored_temp_identity_and_uid_pinned_kube_exclusion_removed_private_backups_retained"})

    def run(self):
        # Local exclusive command owner; independent hosts must use this SAME
        # persisted operation directory, not generate replacement identities.
        self.stage=self.a.action
        if fcntl is None:raise RuntimeError("linux_operator_required")
        if self.a.action == "prepare": self.prepare()
        else:
            # Same-directory commands are serialized even before they make
            # native calls; the real cluster exclusion additionally fences
            # creation of a different operation on another operator machine.
            with (self.directory/"command.lock").open("a+b") as lock:
                fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                getattr(self,self.a.action.replace("-","_"))()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "backup", "apply", "query", "recover", "recover-controller", "rollback", "release", "finish-release", "cancel", "early-query", "early-cancel", "cleanup"))
    p.add_argument("--context", default="kubernetes-admin@kubernetes")
    p.add_argument("--operation-directory", type=Path, required=True)
    p.add_argument("--v3-archive", type=Path)
    p.add_argument("--original-proof", type=Path)
    p.add_argument("--original-proof-sha256")
    a = p.parse_args(); os.umask(0o077)
    if fcntl is None:p.error("Linux original operator environment is required")
    if not a.operation_directory.is_absolute():p.error("operation directory must be an absolute private path")
    if a.operation_directory.is_symlink():p.error("operation directory must not be a symlink")
    if a.operation_directory.exists() and (a.operation_directory.stat().st_mode&0o077 or a.operation_directory.stat().st_uid!=os.geteuid()):p.error("operation directory must be private and owned by the original operator")
    if a.action == "prepare" and not all((a.v3_archive, a.original_proof, a.original_proof_sha256)): p.error("prepare requires reviewed original-readproof and passed-v3 archive")
    tool = OriginalUpgrade(a)
    try:
        tool.run()
        print(json.dumps({"state": "original_native_upgrade_action_completed", "action": a.action, "operation_directory": str(tool.directory), "first_adoption_completed": False, "page_backup_completed": False,**tool.result}))
        return 0
    except Exception as error:
        # Native SQL text/errors may contain hashes/passwords/rows. Preserve
        # private logs and do not auto restore/release after a failed action.
        reason=safe_reason(error)
        coordinates={}
        if tool.log is not None:
            tool.log.flush()
            coordinates=safe_failure_coordinates(tool.directory,tool.log.name)
        print(json.dumps({"state": "original_native_upgrade_action_failed_keep_barrier_and_private_material", "action": a.action, "stage": tool.stage,"reason_code":reason, "operation_directory": str(tool.directory),**coordinates}))
        return 1
    finally:
        if tool.log is not None: tool.log.close()
        if tool.command_lock is not None:tool.command_lock.close()


if __name__ == "__main__": raise SystemExit(main())
