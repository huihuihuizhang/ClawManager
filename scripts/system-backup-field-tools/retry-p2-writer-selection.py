#!/usr/bin/env python3
"""Retry only prepare-selection with the retained pinned P2 inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

WORK = Path("/root/sbk-validation-tls-inspect.7LVU7vpE")
ENR = WORK / "fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native"
CONFIG = Path("/root/sbk/p2-writer-selection.4nqkam_7/source-config.json")
CONFIG_SHA = "281bef3b57ea2d63f9e626e9185b51e91efe6b85ccc58165407a6efed926dda1"
STARTUP = Path("/root/sbk/p2-materials-1dd1ae71.lVSEBfl2/runtime-startup-images/runtime-startup-images.json")
STARTUP_SHA = "28e979483e004141f3452f13609057fc0cde5bb82e4ca1d34e299cb536087068"


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def pinned(path, expected, maximum=8 << 20):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
         and path.stat().st_mode & 0o077 == 0 and 0 < path.stat().st_size <= maximum, "invalid private material file")
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, "material bytes changed: " + path.name)
    return raw


def owner_arguments():
    return ["--plan-file", str(ENR / "original-enrollment-plan.json"), "--plan-sha256", "a0aa44b5a12a453c352a402e73c4f4d42a675b2430d2cb69972a29df1f859752",
        "--issuer-public-file", str(ENR / "issuer.public"), "--issuer-public-sha256", "8a2df27b26737198ba78e49f5291bb53ad283e42099d228e1ba5762c6d318ac6",
        "--enrollment-pin-file", str(ENR / "original-enrollment-pin.json"), "--enrollment-pin-sha256", "ba649013288b0b62fb111e74ce151f344ad76169b8c9206da47fa1580b086256",
        "--kubeconfig-file", str(WORK / "operator.kubeconfig.yaml"), "--kubeconfig-sha256", "152d2049f8b1c3e9e043ed024bae24cf2253aa3b8da19bf1c67f9fa9a9979bde",
        "--dsn-file", str(WORK / "fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn"),
        "--database-ca-file", str(WORK / "mysql-source-ca.pem"), "--local-admin-password-file", str(WORK / "fresh-backup-bootstrap/admin-password")]


def main(directory, revision):
    os.umask(0o077)
    need(directory.is_absolute() and directory.resolve(strict=True) == directory and re.fullmatch(r"[a-f0-9]{40}", revision), "invalid tool directory/revision")
    need((directory / "SOURCE_REVISION").read_text().strip() == revision, "tool source revision mismatch")
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split()
        need(re.fullmatch(r"[a-f0-9]{64}", digest) and name not in sums and "/" not in name and "\\" not in name, "invalid delivery checksum entry")
        sums[name] = digest
    executable = directory / "system-backup-first-adoption"
    need(hashlib.sha256(executable.read_bytes()).hexdigest() == sums[executable.name], "prepare-selection executable changed")
    config = json.loads(pinned(CONFIG, CONFIG_SHA))
    pinned(STARTUP, STARTUP_SHA)
    need(config["namespace"] == "clawmanager-sbk-validation-system" and config["application_scope"] == "installation"
         and config["runtime_sources"]["shared_runtime_protocol"] == "shared-container-freeze.v1"
         and [row["ID"] for row in config["runtime_sources"]["runtime_test_scope"]["Deferred"]] == [4, 5, 6], "retained source configuration changed")
    records = Path(tempfile.mkdtemp(prefix="p2-writer-selection-retry.", dir="/root/sbk"))
    print("WRITER_SELECTION_RECORDS", records, flush=True)
    output, journal = records / "selection", records / "journal"
    output.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    argv = [str(executable), "--action", "prepare-selection", *owner_arguments(),
        "--source-config-file", str(CONFIG), "--source-config-sha256", CONFIG_SHA,
        "--runtime-startup-images-file", str(STARTUP), "--runtime-startup-images-sha256", STARTUP_SHA,
        "--observer-definition-file", str(WORK / "fresh-backup-bootstrap/observer-pki.definition.json"),
        "--observer-definition-sha256", "47de353412f9811338a87dfefffae3e328557269e41d486a11fd71b6b385733b",
        "--observer-receipt-file", str(WORK / "fresh-backup-bootstrap/observer-pki.receipt.json"),
        "--observer-receipt-sha256", "b0749959fb6ae25eef2ef7568b571e895cdab8daa619dd2894764e99481815b9",
        "--selection-output-directory", str(output), "--journal-directory", str(journal)]
    result = subprocess.run(argv, capture_output=True, timeout=160)
    (records / "prepare-selection.stdout.private").write_bytes(result.stdout)
    (records / "prepare-selection.stderr.private").write_bytes(result.stderr)
    if result.stdout:
        print(result.stdout.decode("utf-8", errors="replace").strip(), flush=True)
    need(result.returncode == 0, "original owner refused; retain the reported phase and private directory")
    receipt = json.loads(result.stdout)
    need(receipt["Version"] == "original-writer-selection-materials.v1" and receipt["SourceCount"] == 8, "unexpected owner receipt")
    selection = json.loads(pinned(receipt["Selection"]["File"], receipt["Selection"]["SHA256"]))
    pinned(receipt["SourceCoordinates"]["File"], receipt["SourceCoordinates"]["SHA256"])
    tenants = selection.get("TenantPro", [])
    need(len(tenants) == 1 and tenants[0]["Source"]["ID"] == 2
         and tenants[0]["Identity"]["Namespace"] == "clawmanager-sbk-validation-user-1", "tenant Pro source was not retained")
    (records / "writer-selection.receipt.json").write_bytes(result.stdout)
    print("TENANT_PRO_SELECTION", json.dumps({"id": 2, "namespace": tenants[0]["Identity"]["Namespace"],
        "deployment": tenants[0]["Deployment"], "deployment_uid": tenants[0]["Identity"]["DeploymentUID"]}), flush=True)
    print("P2_WRITER_SELECTION_AUTHORED", records, flush=True)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--bin-directory", type=Path, required=True)
        parser.add_argument("--expected-revision", required=True)
        args = parser.parse_args()
        main(args.bin_directory, args.expected_revision)
    except Exception as error:
        raise SystemExit("P2_WRITER_SELECTION_UNCONFIRMED " + str(error))
