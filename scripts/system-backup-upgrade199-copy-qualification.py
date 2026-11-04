#!/usr/bin/env python3
"""Read retained native copy receipts. This data check grants no authority.

No SQL, Kubernetes calls, subprocesses, archive extraction or ledger repair.
The original upgrade still acquires its own stop/backup/recovery barriers.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

ARCHIVE_SHA256 = "f82d59d1bf62558be69157a7a0d1f0d052bcd0a37361e3386598d65b5aaba7e5"
PROOF_SHA256 = "74f4c69383c9281687efe5247e9383cdf331f7cdcbeb1da1da64dc310fb5f655"
CATALOG = "1efd02dc8ee4038f53c58f17aeee39ba49ad1e6c06f56cdad3a1147d10992494"
INVENTORY = "71b22c009b3ad9bdeef324d2cafd2aa4c1a646110f2080d1b6f42746f8f7013f"
SCHEMA = "140b053e6d3a40a8b5d7c305e3429020a1bc394b3c156167d9683072ec0908bf"
LEDGER = "5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903"
SERVER = "f1f5f76a-95f5-11f1-b08e-366835b4a029"
EIGHT = tuple("system_backup_producer_" + n for n in (
    "command_receipts", "domains", "evidence_bindings", "evidence_refs",
    "grants", "result_receipts", "runs", "targets"))


def require(ok, code="copy199_retained_native_qualification_required"):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for k, v in items:
        require(k not in result)
        result[k] = v
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def regular(path, *, private=False, maximum=32 << 20):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and 0 < s.st_size <= maximum)
    if private and os.name == "posix":
        require(s.st_uid == os.geteuid() and not s.st_mode & 0o077)
    return path.read_bytes()


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def validate(archive, receipts):
    archive = Path(archive)
    raw_archive = regular(archive, maximum=128 << 20)
    require(sha(raw_archive) == ARCHIVE_SHA256, "exact_copy199_archive_required")
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:gz") as t:
        def member(name):
            members = [m for m in t.getmembers() if m.name == "upgrade199-copy/" + name]
            require(len(members) == 1 and members[0].isfile() and 0 < members[0].size <= 32 << 20)
            return t.extractfile(members[0]).read()
        inventory_raw = member("inputs/inventory.json")
        require(sha(inventory_raw) == INVENTORY)
        require(sha(member("system-backup-legacy-upgrade177-proof")) == PROOF_SHA256)
        inventory = decode(inventory_raw)
        profile = decode(member("inputs/profile.json"))
    require(profile["catalog_sha256"] == CATALOG and len(profile["pending"]) == 102
            and len(profile["original_ledger"]) == 97 and len(profile["expected_final_ledger"]) == 199)
    receipts = Path(receipts)
    require(receipts.is_absolute() and receipts.resolve(strict=True) == receipts and receipts.is_dir())
    if os.name == "posix":
        s = receipts.stat()
        require(s.st_uid == os.geteuid() and not s.st_mode & 0o077)
    files = {}
    def read(name):
        raw = regular(receipts / name, private=True)
        files[name] = sha(raw)
        return raw
    log = read("run-safe.log").decode("utf-8")
    # Native producer prints these only after the actual respective operations.
    # Reject failure/partial cleanup even if an earlier success marker survives.
    require(not re.search(r"(?:FAILED|MISMATCH|INCOMPLETE|IDENTITY_CHANGED|UNEXPECTED)", log))
    lines = log.splitlines()
    def once(line):
        require(lines.count(line) == 1)
    once("COPY_C1_EIGHT_TABLES_EMPTY_VERIFIED")
    once("COPY_ABSENT")
    once("POD_TEMP_ABSENT")
    for name in ("live-inventory.json", "live-inventory-after-copy.json"):
        require(sha(read("private/" + name)) == INVENTORY)
    before = decode(read("private/row-proof-before.json"))
    after = decode(read("private/row-proof-after.json"))
    copy_database = before.get("copy_database", "")
    require(re.fullmatch(r"cm_import_[0-9a-f]{32}", copy_database))
    once("COPY_CREATED: " + copy_database)
    source_tables = inventory["schema"]["tables"]
    require(len(source_tables) == 99 and len({t["name"] for t in source_tables}) == 99)
    previous = None
    for phase, proof in (("before", before), ("after", after)):
        require(proof.get("phase") == phase and proof.get("copy_server_uuid") == SERVER
                and proof.get("copy_database") == copy_database
                and proof.get("source_inventory_sha256") == INVENTORY
                and proof.get("source_schema_sha256") == SCHEMA
                and proof.get("original_ledger_sha256") == LEDGER
                and proof.get("target_catalog_sha256") == CATALOG
                and proof.get("expected_ledger_rows") == 199
                and proof.get("migration_authorized") is False
                and not proof.get("read_mode"))
        tables = proof["tables"]
        require(len(tables) == 99 and [t["name"] for t in tables] == [t["name"] for t in source_tables])
        aggregate = []
        for source, row in zip(source_tables, tables):
            require(type(row.get("rows")) is int and row["rows"] >= 0
                    and re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")))
            columns = [c for c in source["columns"] if source["name"] != "llm_models" or c != "updated_at"]
            aggregate.append({"table": {"name": source["name"], "columns": columns},
                              "rows": row["rows"], "sha256": row["sha256"]})
            if source["name"] == "schema_migrations":
                require(row["rows"] == 97)  # All original ledger rows, including their original fields.
        require(sha(compact(aggregate)) == proof.get("preservation_sha256"))
        stable = [(r["name"], r["rows"], r["sha256"]) for r in tables]
        if previous is not None:
            require(stable == previous, "copy199_original_rows_changed")
        previous = stable
    preservation = before["preservation_sha256"]
    require(after["preservation_sha256"] == preservation)
    once("BEFORE_ORIGINAL_ROW_SHA256=" + preservation)
    once("AFTER_ORIGINAL_ROW_SHA256=" + preservation)
    once("UPGRADE_C1_COPY_VERIFIED ledger=199 all99_original_column_sha256=" + preservation
         + " (only_llm_models_updated_at_exception)")
    require(lines.index("COPY_C1_EIGHT_TABLES_EMPTY_VERIFIED") < lines.index("AFTER_ORIGINAL_ROW_SHA256=" + preservation)
            < lines.index("COPY_ABSENT") < lines.index("POD_TEMP_ABSENT"))
    stream = read("private/source.out").decode("ascii")
    require(re.fullmatch(r"[0-9a-f]{64}  -\n", stream))
    once("DATA_STREAM_ROUNDTRIP_SHA256=" + stream[:64])
    n = before["llm_existing_protocol_rows"]
    require(type(n) is int and n >= 0 and before["llm_group_backfill_rows"] == 0
            and after["llm_existing_protocol_rows"] == n and after["llm_group_backfill_rows"] == n)
    once("MODEL_GROUP_BACKFILL_VERIFIED rows=" + str(n) + " original_columns_except_updated_at_unchanged=true")
    empty = read("private/c1-empty-after.out").decode("ascii").splitlines()
    require(empty == [name + "\t0" for name in EIGHT])
    shape = after["upgraded_schema"]
    shape_raw = compact(shape)
    # Go json.Marshal escapes HTML and U+2028/U+2029; metadata may contain defaults/comments.
    for old, new in ((b"<", b"\\u003c"), (b">", b"\\u003e"), (b"&", b"\\u0026"),
                     (b"\xe2\x80\xa8", b"\\u2028"), (b"\xe2\x80\xa9", b"\\u2029")):
        shape_raw = shape_raw.replace(old, new)
    require(sha(shape_raw) == after["upgraded_schema_sha256"])
    names = [t["name"] for t in shape["tables"]]
    require(len(set(names)) == len(names) and set(EIGHT) <= set(names))
    require(len([name for name in names if name.startswith("dlegacy_")]) == 35)
    # The actual upgraded full metadata remains retained and hash-bound. This
    # receipt does not represent an independent migration semantic review.
    return {"version": "copy199-retained-native-qualification.v1",
            "state": "copy199_native_receipts_verified_original_not_upgraded",
            "archive_sha256": ARCHIVE_SHA256, "proof_sha256": PROOF_SHA256,
            "target_catalog_sha256": CATALOG, "ledger_rows": 199,
            "original_ledger_rows_preserved": 97, "original_tables_preserved": 99,
            "new_c1_empty_tables": list(EIGHT), "copy_database": copy_database,
            "copy_server_uuid": SERVER, "preservation_sha256": preservation,
            "upgraded_schema_sha256": after["upgraded_schema_sha256"],
            "receipts_directory": str(receipts), "files": files,
            "reviewed_data_change": {"llm_model_group_backfill_rows": n,
                                     "only_original_column_exception": "llm_models.updated_at"},
            "original_database_upgraded": False, "production_authority": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--receipts-directory", type=Path, required=True)
    a = p.parse_args()
    try:
        print(json.dumps(validate(a.archive, a.receipts_directory), sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"state": "copy199_not_qualified_keep_original_unchanged",
                          "original_database_upgraded": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
