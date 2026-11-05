#!/usr/bin/env python3
"""Pinned DB-only successor using the SAME original operation and journal.

Does not edit old release/operation receipts, invoke NFS/SSH, or grant backup
readiness. Actual native SQL maintenance still owns ALL mutation/proof/recovery.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True


def require(ok):
    if not ok:
        raise ValueError("original_database_maintenance_input_unconfirmed")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(path, digest, maximum=64 << 20):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file())
    raw = path.read_bytes()
    require(len(raw) <= maximum and sha(raw) == digest)
    return raw


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def verify_file(path, digest):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file())
    value = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(1 << 20)
            if not block:
                break
            value.update(block)
    require(value.hexdigest() == digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "backup", "apply", "query", "recover", "recover-controller", "rollback", "release", "finish-release", "cancel", "cleanup", "early-query", "early-cancel"))
    parser.add_argument("--release-directory", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--expected-operation", required=True)
    parser.add_argument("--tools-directory", type=Path, required=True)
    parser.add_argument("--tools-manifest-sha256", required=True)
    parser.add_argument("--copy-receipts-directory", type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{32}", args.expected_operation) is not None)
    for directory in (args.release_directory, args.run_directory, args.tools_directory):
        require(directory.is_absolute() and directory.resolve(strict=True) == directory and directory.is_dir())
    operation_path = args.run_directory / "operation.json"
    operation_raw = operation_path.read_bytes()
    operation = unique_json(operation_raw)
    require(operation["operation"] == args.expected_operation)
    release = unique_json(read_pin(args.release_directory/"operator-release-pins.json", operation["release_sha256"]))
    entry = args.release_directory / "scripts/system-backup-zhanghui08-operator.py"
    entry_raw = read_pin(entry, release["files"]["scripts/system-backup-zhanghui08-operator.py"])
    spec = importlib.util.spec_from_file_location("original_database_operation_custody", entry)
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    require(entry_raw == read_pin(entry, release["files"]["scripts/system-backup-zhanghui08-operator.py"]))
    manifest = unique_json(read_pin(args.tools_directory/"database-maintenance-tools.json", args.tools_manifest_sha256))
    require(manifest["version"] == "original-database-maintenance-tools.v1" and
            set(manifest["files"]) == {"system-backup-original-upgrade199.py", "system-backup-upgrade199-copy-qualification.py"})
    for name, digest in manifest["files"].items():
        read_pin(args.tools_directory/name, digest)
    # Original Operator.open verifies the old SEALED release, static original
    # kubeconfig hash, cluster/namespace and original app/MySQL Deployment UIDs.
    # We call its journal, never its old workspace-coupled db() entry.
    require(original.fcntl is not None and os.geteuid() == 0)
    lock_path = args.run_directory / "operator-command.lock"
    require(not lock_path.is_symlink())
    with lock_path.open("a+b") as command_lock:
        original.fcntl.flock(command_lock.fileno(), original.fcntl.LOCK_EX | original.fcntl.LOCK_NB)
        old_args = argparse.Namespace(release_directory=args.release_directory, run_directory=args.run_directory,
                                      copy_receipts_directory=args.copy_receipts_directory, action="db-"+args.action)
        tool = original.Operator(old_args)
        tool.open()
        require(unique_json(operation_path.read_bytes()) == operation)
        selection = {"version": "original-database-maintenance-code-selection.v1", "operation_sha256": sha(operation_raw),
                     "tools_directory": str(args.tools_directory), "tools_manifest_sha256": args.tools_manifest_sha256,
                     "files": manifest["files"], "driver_sha256": sha(Path(__file__).read_bytes()), "authority": False}
        selection_file = args.run_directory / "database-maintenance-code-selection.json"
        if selection_file.exists():
            require(unique_json(selection_file.read_bytes()) == selection)
        else:
            original.save(selection_file, selection)
        native = args.tools_directory / "system-backup-original-upgrade199.py"
        argv = [sys.executable, "-B", native, args.action, "--operation-directory", args.run_directory/"original199"]
        if args.action == "prepare":
            require(args.copy_receipts_directory is not None and args.copy_receipts_directory.is_absolute())
            archive = manifest["copy_archive"]
            proof = manifest["readproof"]
            require(archive["File"] == original.COPY_NAME and proof["File"] == "bin/system-backup-legacy-upgrade177-proof" and
                    archive["SHA256"] == original.COPY_SHA and proof["SHA256"] == original.PROOF_SHA)
            verify_file(args.release_directory/archive["File"], archive["SHA256"])
            verify_file(args.release_directory/proof["File"], proof["SHA256"])
            argv += ["--copy-receipts-directory", args.copy_receipts_directory,
                     "--v3-archive", args.release_directory/archive["File"],
                     "--original-proof", args.release_directory/proof["File"], "--original-proof-sha256", proof["SHA256"]]
        env = dict(os.environ)
        env["KUBECONFIG"] = str(tool.kube)
        # SAME permanent logical send intent and private stdout/readback files.
        # Existing prepare/apply intents therefore refuse resend. Original native
        # early-query/query/recover/rollback act only on original199, never a new op.
        value, out = tool.invoke("db-"+args.action, argv, repeat=args.action in original.REPEATABLE, env=env)
        require(operation_path.read_bytes() == operation_raw)
        print(json.dumps({"state": value.get("state"), "private_receipt": str(out), "original_operation": operation["operation"],
                          "original_database_upgraded": value.get("original_database_upgraded", False),
                          "action_scope": "original_database_maintenance_only", "workspace_native_proof_produced": False,
                          "backup_readiness_proven": False, "page_backup_completed": False}))



if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("original_database_maintenance_unconfirmed_keep_same_operation_and_private_receipts", file=sys.stderr)
        raise SystemExit(1)
