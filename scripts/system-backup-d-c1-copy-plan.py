#!/usr/bin/env python3
"""Build exact formal137 complete178 SQL inputs for a disposable original-data COPY only.

No SQL connection, no original-ledger edits, no live-upgrade authorization.
The old through127 profile and its fixed outputs remain unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SHA = "71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f"
LEDGER_SHA = "5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903"
CATALOG_FILE_SHA = "d1d8ec8fd5fb7bddbabfd2047016a71740ba2764e06463a3c909709b31f57ba8"
CATALOG_SHA = "1efd02dc8ee4038f53c58f17aeee39ba49ad1e6c06f56cdad3a1147d10992494"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(migrations):
    raw = (ROOT / "docs/evidence/d-existing-db-live-inventory-direct-20261030.json").read_bytes()
    ledger_raw = (ROOT / "docs/evidence/d-existing-db-ledger-20261030.txt").read_bytes()
    catalog_raw = (ROOT / "docs/evidence/system-backup-d-c1-migration137-catalog-20261104.json").read_bytes()
    if (sha(raw), sha(ledger_raw), sha(catalog_raw)) != (INVENTORY_SHA, LEDGER_SHA, CATALOG_FILE_SHA):
        raise ValueError("original profile/catalog input bytes changed")
    inventory, catalog = json.loads(raw), json.loads(catalog_raw)
    names = sorted(t["name"] for t in inventory["schema"]["tables"])
    ledger = ledger_raw.decode("ascii").splitlines()
    old = [n for n in names if n.startswith(("system_backup", "system_maintenance", "system_restore", "system_artifact"))]
    if len(names) != 99 or len(old) != 35 or len(ledger) != 97 or inventory["schema_sha256"] != "140b053e6d3a40a8b5d7c305e3429020a1bc394b3c156167d9683072ec0908bf":
        raise ValueError("reviewed original99/35/97 profile changed")
    files = sorted(migrations.glob("*.sql"), key=lambda p: p.name)
    if [p.name for p in files] != catalog["filenames"]:
        raise ValueError("not exact formal137 complete178 migration filenames")
    pins = {p["filename"]: p["sha256"] for p in catalog["source_pins"]}
    digest = hashlib.sha256(b"system-backup-migration-catalog.v1\0")
    for p in files:
        content = p.read_bytes()
        if sha(content) != pins[p.name]:
            raise ValueError("exact migration source bytes changed: " + p.name)
        normalized = content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode()
        for value in (p.name.encode(), normalized):
            digest.update(struct.pack(">Q", len(value)))
            digest.update(value)
    if digest.hexdigest() != CATALOG_SHA:
        raise ValueError("exact embedded catalog hash changed")
    pending = [p for p in files if p.name not in set(ledger)]
    expected = sorted(set(ledger) | set(catalog["filenames"]))
    if len(pending) != 102 or len(expected) != 199:
        raise ValueError("reviewed pending102/final199 union changed")
    renamed = {n: f"dlegacy_{i:02d}_{n[:39]}" for i, n in enumerate(old, 1)}
    guard = "SET @copy_guard=IF(DATABASE() REGEXP '^cm_import_[0-9a-f]{32}$','SELECT 1','ORIGINAL_DATABASE_WRITE_FORBIDDEN');\nPREPARE copy_guard_stmt FROM @copy_guard; EXECUTE copy_guard_stmt; DEALLOCATE PREPARE copy_guard_stmt;\n"
    # All35 counts share ONE actual RR transaction. No other process is started
    # against this operation-owned clone; actual business init rejects cm_import.
    empty_sum = "+".join("(SELECT COUNT(*) FROM `" + n + "`)" for n in old)
    rename = "RENAME TABLE " + ",\n".join("`" + n + "` TO `" + renamed[n] + "`" for n in old)
    rename_sql = guard + "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; START TRANSACTION WITH CONSISTENT SNAPSHOT;\nSET @nonempty=" + empty_sum + ";\nSET @rename_sql=IF(@nonempty=0," + "'" + rename.replace("'", "''") + "','LEGACY_CONTROL_HISTORY_NOT_EMPTY');\nPREPARE rename_stmt FROM @rename_sql; EXECUTE rename_stmt; DEALLOCATE PREPARE rename_stmt;\nCOMMIT;\n"
    upgrade = bytearray(guard.encode())
    for p in pending:
        if p.name.startswith("128_"):
            authorities = ["system_backup_installation_kek_authority", "system_backup_installation_kek_authority_history",
                           "system_backup_installation_owner_heads", "system_backup_installation_owner_grants",
                           "system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs",
                           "system_backup_signing_resource_heads", "system_backup_signing_resource_grants"]
            alters = ["system_backup_v2_backups", "system_backup_v2_operations", "system_backup_v2_runtime_resources",
                      "system_backup_v2_staging_resources", "system_backup_v2_job_send_intents"]
            counts = "+".join("(SELECT COUNT(*) FROM `" + n + "`)" for n in alters)
            absent = "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + ",".join("'" + n + "'" for n in authorities) + ")"
            boundary = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; START TRANSACTION WITH CONSISTENT SNAPSHOT;\nSET @new_rows=" + counts + ";\nSET @authority_tables=(" + absent + ");\nSET @new_profile_guard=IF(@new_rows=0 AND @authority_tables=0,'SELECT 1','NEW128_PROFILE_NOT_FRESH');\nPREPARE new_profile_stmt FROM @new_profile_guard; EXECUTE new_profile_stmt; DEALLOCATE PREPARE new_profile_stmt; COMMIT;\n"
            upgrade.extend(boundary.encode())
        upgrade.extend(("SELECT 'MIGRATION:" + p.name + "';\n").encode())
        upgrade.extend(p.read_bytes())
        upgrade.extend(("\nINSERT INTO schema_migrations(filename,applied_at) VALUES('" + p.name + "',UTC_TIMESTAMP(6));\n").encode())
    payloads = {"rename.sql": rename_sql.encode(), "upgrade.sql": bytes(upgrade), "inventory.json": raw}
    for phase in ("before", "after"):
        sql = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY;\n"
        sql += "\n".join("SELECT '" + n + "',COUNT(*) FROM `" + (renamed.get(n, n) if phase == "after" else n) + "`;" for n in names)
        payloads["counts-" + phase + ".sql"] = (sql + "\nCOMMIT;\n").encode()
    profile = {"schema_version": "legacy-copy-c1-upgrade137-profile.v1", "experimental_copy_only": True,
               "catalog_sha256": CATALOG_SHA, "inventory_sha256": INVENTORY_SHA, "ledger_sha256": LEDGER_SHA,
               "source_schema_sha256": inventory["schema_sha256"], "source_tables": names,
               "legacy_renames": renamed, "original_ledger": ledger, "pending": [p.name for p in pending],
               "expected_final_ledger": expected, "payloads": {n: sha(b) for n, b in payloads.items()},
               "live_migration_authorized": False, "failure_policy": "Never retry partial DDL or fill missing ledger: collect safe failing marker, drop owned clone, recreate from a fresh full original snapshot."}
    payloads["profile.json"] = (json.dumps(profile, indent=2) + "\n").encode()
    return payloads


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--migrations-dir", type=Path, default=ROOT / "backend/internal/db/migrations")
    args = parser.parse_args()
    payloads = build(args.migrations_dir)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, data in payloads.items():
        with (args.output_dir / name).open("xb") as f:
            f.write(data)
        print(name, sha(data))
