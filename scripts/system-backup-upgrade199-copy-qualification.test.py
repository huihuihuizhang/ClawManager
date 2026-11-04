"""Synthetic retained-receipt checks; these never qualify a native database."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("copy199_guard", HERE / "system-backup-upgrade199-copy-qualification.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Qualification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="copy199-guard-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.receipts = self.root / "receipts"
        (self.receipts / "private").mkdir(parents=True, mode=0o700)
        os.chmod(self.receipts, 0o700)
        # Deliberately synthetic schema. Original authority cannot come from
        # this test: the test substitutes the archive/inventory digests only.
        self.tables = [{"name": f"business_{i:02}", "columns": ["id"]} for i in range(97)]
        self.tables += [{"name": "llm_models", "columns": ["id", "protocol_type", "updated_at"]},
                        {"name": "schema_migrations", "columns": ["filename", "applied_at"]}]
        self.inventory = guard.compact({"schema": {"tables": self.tables}})
        self.inventory_sha = guard.sha(self.inventory)
        profile = {"catalog_sha256": guard.CATALOG, "pending": [str(i) for i in range(102)],
                   "original_ledger": [str(i) for i in range(97)], "expected_final_ledger": [str(i) for i in range(199)]}
        self.proof_bytes = b"synthetic proof, never executed"
        self.archive = self.root / "copy.tar.gz"
        with tarfile.open(self.archive, "w:gz") as t:
            for name, raw in (("inputs/inventory.json", self.inventory), ("inputs/profile.json", guard.compact(profile)),
                              ("system-backup-legacy-upgrade177-proof", self.proof_bytes)):
                entry = tarfile.TarInfo("upgrade199-copy/" + name)
                entry.size = len(raw)
                t.addfile(entry, io.BytesIO(raw))
        self.patch = mock.patch.multiple(guard, ARCHIVE_SHA256=guard.sha(self.archive.read_bytes()),
                                         PROOF_SHA256=guard.sha(self.proof_bytes), INVENTORY=self.inventory_sha)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        rows = [{"name": t["name"], "rows": 97 if t["name"] == "schema_migrations" else 2,
                 "sha256": hashlib.sha256(t["name"].encode()).hexdigest()} for t in self.tables]
        aggregate = [{"table": {"name": t["name"], "columns": [c for c in t["columns"] if t["name"] != "llm_models" or c != "updated_at"]},
                      "rows": r["rows"], "sha256": r["sha256"]} for t, r in zip(self.tables, rows)]
        self.preservation = guard.sha(guard.compact(aggregate))
        shape = {"tables": [{"name": n, "columns": ["id"]} for n in guard.EIGHT]
                 + [{"name": f"dlegacy_{i:02}_table", "columns": ["id"]} for i in range(35)], "facts": []}
        self.before = {"phase": "before", "copy_server_uuid": guard.SERVER, "copy_database": "cm_import_" + "a" * 32,
                       "source_inventory_sha256": self.inventory_sha, "source_schema_sha256": guard.SCHEMA,
                       "original_ledger_sha256": guard.LEDGER, "target_catalog_sha256": guard.CATALOG,
                       "expected_ledger_rows": 199, "migration_authorized": False, "tables": rows,
                       "preservation_sha256": self.preservation, "llm_existing_protocol_rows": 2,
                       "llm_group_backfill_rows": 0}
        self.after = copy.deepcopy(self.before)
        self.after.update(phase="after", llm_group_backfill_rows=2, upgraded_schema=shape,
                          upgraded_schema_sha256=guard.sha(guard.compact(shape)))
        self.log = "\n".join(["COPY_CREATED: " + self.before["copy_database"],
                  "DATA_STREAM_ROUNDTRIP_SHA256=" + "b" * 64,
                  "BEFORE_ORIGINAL_ROW_SHA256=" + self.preservation, "COPY_C1_EIGHT_TABLES_EMPTY_VERIFIED",
                  "AFTER_ORIGINAL_ROW_SHA256=" + self.preservation,
                  "MODEL_GROUP_BACKFILL_VERIFIED rows=2 original_columns_except_updated_at_unchanged=true",
                  "UPGRADE_C1_COPY_VERIFIED ledger=199 all99_original_column_sha256=" + self.preservation + " (only_llm_models_updated_at_exception)",
                  "COPY_ABSENT", "POD_TEMP_ABSENT", ""])
        self.write("private/live-inventory.json", self.inventory)
        self.write("private/live-inventory-after-copy.json", self.inventory)
        self.write("private/source.out", ("b" * 64 + "  -\n").encode())
        self.write("private/c1-empty-after.out", "".join(n + "\t0\n" for n in guard.EIGHT).encode())
        self.flush()

    def write(self, name, raw):
        path = self.receipts / name
        path.write_bytes(raw)
        os.chmod(path, 0o600)

    def flush(self):
        self.write("run-safe.log", self.log.encode())
        self.write("private/row-proof-before.json", guard.compact(self.before))
        self.write("private/row-proof-after.json", guard.compact(self.after))

    def check(self):
        return guard.validate(self.archive, self.receipts)

    def test_complete_synthetic_evidence_is_data_only(self):
        r = self.check()
        self.assertEqual(r["ledger_rows"], 199)
        self.assertFalse(r["production_authority"])
        self.assertFalse(r["original_database_upgraded"])

    def test_old198_never_qualifies(self):
        self.after["expected_ledger_rows"] = 198
        self.flush()
        with self.assertRaises(RuntimeError): self.check()

    def test_changed_original_row_hash_never_qualifies(self):
        self.after["tables"][0]["sha256"] = "f" * 64
        self.flush()
        with self.assertRaises(RuntimeError): self.check()

    def test_missing_new_table_proof_never_qualifies(self):
        self.write("private/c1-empty-after.out", "".join(n + "\t0\n" for n in guard.EIGHT[:-1]).encode())
        with self.assertRaises(RuntimeError): self.check()

    def test_nonempty_new_table_never_qualifies(self):
        self.write("private/c1-empty-after.out", "".join(n + "\t1\n" for n in guard.EIGHT).encode())
        with self.assertRaises(RuntimeError): self.check()

    def test_cleanup_missing_never_qualifies(self):
        self.log = self.log.replace("POD_TEMP_ABSENT\n", "")
        self.flush()
        with self.assertRaises(RuntimeError): self.check()

    def test_partial_failure_never_qualifies(self):
        self.log += "COPY_UPGRADE177_FAILED stage=after_original_99_table_row_proof\n"
        self.flush()
        with self.assertRaises(RuntimeError): self.check()

    def test_changed_archive_never_qualifies(self):
        with self.archive.open("ab") as f: f.write(b"changed")
        with self.assertRaises(RuntimeError): self.check()

    def test_cross_copy_receipts_never_qualify(self):
        self.after["copy_database"] = "cm_import_" + "c" * 32
        self.flush()
        with self.assertRaises(RuntimeError): self.check()

    def test_fabricated_authorization_never_qualifies(self):
        self.after["migration_authorized"] = True
        self.flush()
        with self.assertRaises(RuntimeError): self.check()


if __name__ == "__main__":
    unittest.main()
