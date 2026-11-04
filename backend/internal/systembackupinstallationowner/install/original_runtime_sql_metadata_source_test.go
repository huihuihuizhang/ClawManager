package install

import (
	"testing"

	a "clawreef/internal/systembackupkekadapter"
)

// DATA comparison only. No synthetic snapshot acquires the sealed attachment;
// actual Attach still requires Plan-root signatures and current complete SQL.
func TestOriginalRuntimeSQLMetadataPredicateAllowsOnlyExactInstalledRows(t *testing.T) {
	original := originalMetadataFactsFixture()
	for _, name := range []string{"system_backup_v2_evidence", "system_backup_v2_evidence_chunks"} {
		original.Tables = append(original.Tables, a.SQLCoverageTable{Partition: original.Tables[0].Partition, Table: name, SchemaSHA256: hash([]byte(name + "schema")), RowsSHA256: hash([]byte(name + "rows"))})
	}
	var evidence, chunks a.SQLCoverageTable
	for n, table := range original.Tables {
		switch table.Table {
		case "system_backup_v2_evidence":
			original.Tables[n].Rows = 3
			original.Tables[n].Bytes = 900
			evidence = original.Tables[n]
		case "system_backup_v2_evidence_chunks":
			chunks = table
		}
	}
	r := &originalRuntimeInstalledSQLMetadata{receipt: originalRuntimeSQLMetadataReceipt{Snapshot: a.RuntimeInstalledSQLSnapshot{Database: original.Database, InstallationID: original.InstallationID, Evidence: evidence, Chunks: chunks}}}
	r.origin = r
	for _, mode := range []string{"exact", "extra-evidence", "changed-hash", "changed-schema", "chunk", "legacy-row", "missing-evidence"} {
		t.Run(mode, func(t *testing.T) {
			f := original
			f.Tables = append([]a.SQLCoverageTable(nil), original.Tables...)
			for n, table := range f.Tables {
				if table.Table == "system_backup_v2_evidence" {
					switch mode {
					case "extra-evidence":
						f.Tables[n].Rows++
					case "changed-hash":
						f.Tables[n].RowsSHA256 = hash([]byte("other"))
					case "changed-schema":
						f.Tables[n].SchemaSHA256 = hash([]byte("other schema"))
					}
				}
				if table.Table == "system_backup_v2_evidence_chunks" && mode == "chunk" {
					f.Tables[n].Rows = 1
					f.Tables[n].Bytes = 1
				}
				if table.Table == "system_backup_tasks" && mode == "legacy-row" {
					f.Tables[n].Rows = 1
					f.Tables[n].Bytes = 1
				}
			}
			if mode == "missing-evidence" {
				filtered := f.Tables[:0]
				for _, table := range f.Tables {
					if table.Table != "system_backup_v2_evidence" {
						filtered = append(filtered, table)
					}
				}
				f.Tables = filtered
			}
			if r.classifiesTables(f) != (mode == "exact") {
				t.Fatal("unexpected row exemption")
			}
		})
	}
}
