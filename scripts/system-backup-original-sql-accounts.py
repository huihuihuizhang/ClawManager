#!/usr/bin/env python3
"""Pinned original SQL producer orchestration; never prints credential bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def require(value):
    if not value:
        raise RuntimeError("original_sql_operation_not_confirmed_retain_private_files")


def read_file(path, pin=None, maximum=262144, private=True):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum
            and (os.name != "posix" or (before.st_mode & 0o077 == 0 if private else before.st_mode & 0o022 == 0)))
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
    require(pin is None or hashlib.sha256(raw).hexdigest() == pin)
    return raw


def json_file(path, pin=None):
    return json.loads(read_file(path, pin))


def invoke(argv, receipt):
    receipt = Path(receipt)
    require(receipt.is_absolute() and receipt.parent.resolve(strict=True) == receipt.parent
            and (os.name != "posix" or receipt.parent.stat().st_mode & 0o077 == 0))
    # Create before dispatch: timeout/error retains this exact output and no
    # implicit retry. Go holds its native session lock until the server is done.
    fd = os.open(receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        try:
            result = subprocess.run(argv, stdout=out, stderr=subprocess.DEVNULL,
                                    timeout=360, check=False)
        finally:
            out.flush()
            os.fsync(out.fileno())
    require(result.returncode == 0)
    return json_file(receipt)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("inspect", "prepare", "apply", "query", "rollback", "enroll", "repair-census-execute"))
    for name in ("tool-file", "tool-sha256", "tls-receipt-file", "tls-receipt-sha256",
                 "kubeconfig-file", "kubeconfig-sha256", "namespace", "namespace-uid",
                 "cluster-uid", "inventory-directory", "operation-directory", "receipt-file"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--local-admin-password-file", default="/root/.clawmanager-backup-install/admin-password")
    p.add_argument("--local-admin-username")
    p.add_argument("--inventory-sha256")
    p.add_argument("--prepare-receipt-file")
    p.add_argument("--prepare-receipt-sha256")
    p.add_argument("--account-host")
    p.add_argument("--allow-wildcard-host", action="store_true")
    p.add_argument("--runtime-profile", choices=("controller-historical14.v1", "public-runtime-publication-permits-control-evidence.v1", "public-runtime-c1-installer-bootstrap.v1", "public-runtime-c1-minio-metadata-read.v1"), default="controller-historical14.v1")
    p.add_argument("--fresh-installation", action="store_true")
    p.add_argument("--app-deployment")
    p.add_argument("--app-deployment-uid")
    p.add_argument("--tls-inspect-receipt-file")
    p.add_argument("--tls-inspect-receipt-sha256")
    p.add_argument("--pre-enroll-query-receipt-file")
    p.add_argument("--enrollment-output-directory")
    a = p.parse_args()
    minio_profile = "public-runtime-c1-minio-metadata-read.v1"
    c1 = a.runtime_profile in ("public-runtime-c1-installer-bootstrap.v1", minio_profile)
    require(not a.fresh_installation or a.runtime_profile == minio_profile)
    require(a.action != "repair-census-execute" or a.fresh_installation)
    fresh_apply = a.fresh_installation and a.action in ("apply", "repair-census-execute")
    if fresh_apply:
        require(a.app_deployment and a.app_deployment_uid)
    else:
        require(a.app_deployment is None and a.app_deployment_uid is None)
    state_prefix = "original_c1_sql_accounts" if c1 else "original198_sql_accounts"
    # A same-release existing binary; this is NOT a new build target.
    read_file(a.tool_file, a.tool_sha256, 256 << 20, private=False)
    read_file(a.kubeconfig_file, a.kubeconfig_sha256)
    tls = json_file(a.tls_receipt_file, a.tls_receipt_sha256)
    require(tls.get("Version") == "original-source-tls-bootstrap-receipt.v1"
            and tls.get("OperatorSQLTLSVerified") is True)
    if a.fresh_installation:
        require(a.tls_inspect_receipt_file and a.tls_inspect_receipt_sha256)
        inspected = json_file(a.tls_inspect_receipt_file, a.tls_inspect_receipt_sha256)
        require(inspected.get("Version") == tls["Version"]
                and inspected.get("State") == "actual_kube_and_local_admin_inspected_no_tls_change"
                and inspected["Operation"] == tls["Operation"] and inspected["ServerUUID"] == tls["ServerUUID"])
        plan = json_file(inspected["PlanFile"], inspected["PlanSHA256"])
        require((plan["Namespace"], plan["NamespaceUID"], plan["ClusterUID"], plan["Operation"])
                == (a.namespace, a.namespace_uid, a.cluster_uid, tls["Operation"]))
    for file_key, pin_key in (("DSNFile", "DSNSHA256"), ("SourceTLSFile", "SourceTLSSHA256")):
        read_file(tls[file_key], tls[pin_key])
    material = json_file(tls["SourceTLSFile"], tls["SourceTLSSHA256"])
    common = [a.tool_file, "sql-accounts", "--admin-dsn-file", tls["DSNFile"],
              "--admin-dsn-sha256", tls["DSNSHA256"], "--source-tls-file", tls["SourceTLSFile"],
              "--source-tls-sha256", tls["SourceTLSSHA256"], "--kubeconfig-file", a.kubeconfig_file,
              "--kubeconfig-sha256", a.kubeconfig_sha256, "--namespace", a.namespace,
              "--namespace-uid", a.namespace_uid, "--cluster-uid", a.cluster_uid,
              "--expected-server-uuid", tls["ServerUUID"], "--database", tls["Result"]["Native"]["Database"],
              "--local-admin-password-file", a.local_admin_password_file, "--runtime-profile", a.runtime_profile]
    if a.local_admin_username:
        common += ["--local-admin-username", a.local_admin_username]
    if a.allow_wildcard_host:
        common += ["--allow-wildcard-host"]
    if a.fresh_installation:
        common += ["--fresh-installation"]
    if a.action == "inspect":
        args = common + ["--mode", "inspect", "--output-directory", a.inventory_directory]
    else:
        require(a.inventory_sha256)
        inventory = json_file(Path(a.inventory_directory) / "inventory.json", a.inventory_sha256)
        require(inventory["server_uuid"] == tls["ServerUUID"])
        if a.fresh_installation:
            require(inventory["state"] == state_prefix + "_inventory_no_mutation"
                    and len(inventory["ledger"]) == inventory["ledger_rows"]
                    and "137_backup_producer_authority.sql" in inventory["ledger"])
        elif c1:
            require(isinstance(inventory["ledger_rows"], int) and inventory["ledger_rows"] > 198
                    and "137_backup_producer_authority.sql" in inventory["ledger"])
        else:
            require(inventory["ledger_rows"] == 198)
        args = common + ["--expected-ledger-sha256", inventory["ledger_sha256"],
                         "--output-directory", a.operation_directory]
        if a.action == "prepare":
            require(a.account_host)
            args += ["--mode", "prepare", "--account-host", a.account_host]
        else:
            require(a.prepare_receipt_file and a.prepare_receipt_sha256)
            prepared = json_file(a.prepare_receipt_file, a.prepare_receipt_sha256)
            require(prepared["state"] == state_prefix + "_prepared_no_sql_mutation"
                    and Path(prepared["operation_file"]) == Path(a.operation_directory) / "operation.json")
            args += ["--operation-file", prepared["operation_file"],
                     "--operation-sha256", prepared["operation_sha256"],
                     "--mode", "query" if a.action == "enroll" else a.action]
    if fresh_apply:
        args += ["--app-deployment", a.app_deployment, "--app-deployment-uid", a.app_deployment_uid]
    if a.action == "enroll":
        require(a.pre_enroll_query_receipt_file and a.enrollment_output_directory)
        checked = invoke(args, a.pre_enroll_query_receipt_file)
        require(checked["state"] == state_prefix + "_query_desired_actual_accounts_verified")
        materials = json_file(Path(a.operation_directory) / "sql-accounts-materials.public.json")
        require(materials["server_uuid"] == tls["ServerUUID"] and materials["source_tls"] == material)
        files = materials["files"]
        selected = []
        for key in ("mysql-installer.dsn", "mysql-business.dsn"):
            pin = files[key]
            read_file(pin["File"], pin["SHA256"])
            selected.append(pin["File"])
        # Username comes from the freshly verified native bcrypt producer.
        # It never defaults to admin, an id, or an arbitrary first SQL row.
        args = [a.tool_file, "--namespace", a.namespace, "--local-admin-username", materials["local_admin_username"],
                "--database-tls-server-name", material["server_name"], "--kubeconfig-file", a.kubeconfig_file,
                "--installer-dsn-file", selected[0], "--business-dsn-file", selected[1],
                "--database-ca-file", material["ca_file"], "--local-admin-password-file", a.local_admin_password_file,
                "--output-directory", a.enrollment_output_directory]
    result = invoke(args, a.receipt_file)
    raw = read_file(a.receipt_file)
    public = {"state": result.get("state", result.get("State")), "receipt_file": a.receipt_file,
              "receipt_sha256": hashlib.sha256(raw).hexdigest(), "local_admin_username": result.get("local_admin_username")}
    if a.action == "inspect":
        path = Path(a.inventory_directory) / "inventory.json"
        public.update(inventory_file=str(path), inventory_sha256=hashlib.sha256(read_file(path)).hexdigest())
    if a.action == "prepare":
        public.update(operation_file=result["operation_file"], operation_sha256=result["operation_sha256"])
    print(json.dumps(public, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print("Original SQL operation unconfirmed; retain exact receipts and private operation; do not blindly retry apply.", file=sys.stderr)
        sys.exit(3)
