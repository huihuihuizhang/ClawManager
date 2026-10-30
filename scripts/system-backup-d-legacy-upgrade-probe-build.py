#!/usr/bin/env python3
"""Recreate the SHA-pinned, disposable 2026-10-30 legacy-copy probe inputs.

These SQL files are for an isolated functional test only. This program does not
connect to a database or authorize an upgrade of the live installation.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/evidence/d-existing-db-live-inventory-direct-20261030.json"
LEDGER = ROOT / "docs/evidence/d-existing-db-ledger-20261030.txt"
MIGRATIONS = ROOT / "backend/internal/db/migrations"
EXPECTED_INVENTORY = "71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f"
EXPECTED_LEDGER = "5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903"
EXPECTED_FILES = {
    "rename": "d85f0e1f465606d3e06579d834a327f0ca08db74712badc251349e21d7b2cb15",
    "upgrade": "0ff4050dc12ea7824c6d779a68347813026fd4377517a42b5128e928626ff05f",
    "counts-before": "7823a24115375bf9202a8d5e608ac12dfa29808cd5270c540bf7ce4a1cae7671",
    "counts-after": "a14d72827cca30fef14a89d8582d937d6aa9a6ad33d28d7ba1aadcbc296bd01a",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build() -> dict[str, bytes]:
    inventory_raw = INVENTORY.read_bytes()
    ledger_raw = LEDGER.read_bytes()
    if sha(inventory_raw) != EXPECTED_INVENTORY or sha(ledger_raw) != EXPECTED_LEDGER:
        raise ValueError("observed source inventory or ledger bytes changed")
    inventory = json.loads(inventory_raw)
    if (inventory.get("server_uuid") != "f1f5f76a-95f5-11f1-b08e-366835b4a029"
            or inventory.get("database") != "clawmanager"
            or inventory.get("schema_sha256") != "140b053e6d3a40a8b5d7c305e3429020a1bc394b3c156167d9683072ec0908bf"):
        raise ValueError("observed source identity changed")
    names = sorted(table["name"] for table in inventory["schema"]["tables"])
    if len(names) != 99 or len(set(names)) != 99 or any(not re.fullmatch(r"[a-z0-9_]+", name) for name in names):
        raise ValueError("observed table inventory changed")
    old = [name for name in names if name.startswith(("system_backup", "system_maintenance", "system_restore", "system_artifact"))]
    if len(old) != 35:
        raise ValueError("legacy control-table set changed")
    renamed = {name: f"dlegacy_{index:02d}_{name[:39]}" for index, name in enumerate(old, 1)}
    if len(set(renamed.values())) != 35:
        raise ValueError("legacy table targets collide")
    ledger = ledger_raw.decode("utf-8").splitlines()
    if len(ledger) != 97 or len(set(ledger)) != 97 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+\.sql", name) for name in ledger):
        raise ValueError("observed migration ledger changed")
    entries = sorted(MIGRATIONS.glob("*.sql"), key=lambda entry: entry.name)
    pending = [entry for entry in entries if entry.name not in set(ledger)]
    if len(pending) != 92:
        raise ValueError("current migration catalog changed")

    rename = "RENAME TABLE " + ",\n".join(f"`{name}` TO `{renamed[name]}`" for name in old) + ";\n"
    counts = {}
    for phase in ("before", "after"):
        counts[phase] = "\n".join(
            f"SELECT '{name}',COUNT(*) FROM `{renamed.get(name, name) if phase == 'after' else name}`;"
            for name in names
        ) + "\n"
    upgrade = bytearray()
    for entry in pending:
        upgrade.extend(f"SELECT 'MIGRATION:{entry.name}' AS migration;\r\n".encode())
        upgrade.extend(entry.read_bytes())
        upgrade.extend(b"\r\n")
        upgrade.extend(f"INSERT INTO schema_migrations(filename,applied_at) VALUES('{entry.name}',UTC_TIMESTAMP());\r\n".encode())
    payloads = {
        "rename": rename.replace("\n", "\r\n").encode(),
        "upgrade": bytes(upgrade),
        "counts-before": counts["before"].replace("\n", "\r\n").encode(),
        "counts-after": counts["after"].replace("\n", "\r\n").encode(),
    }
    for name, raw in payloads.items():
        if sha(raw) != EXPECTED_FILES[name]:
            raise ValueError(f"reviewed {name} SQL changed")
    return payloads


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    payloads = build()  # Verify every byte before writing any output.
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, raw in payloads.items():
        target = args.output_dir / f"sbk-d-upgrade-probe-{name}.sql"
        if target.exists() and target.read_bytes() != raw:
            raise ValueError(f"refusing to replace different file: {target}")
        target.write_bytes(raw)
        print(f"{target.name} {sha(raw)}")


if __name__ == "__main__":
    main()
