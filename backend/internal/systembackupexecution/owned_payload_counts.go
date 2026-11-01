package systembackupexecution

import (
	"sort"

	"clawreef/internal/systembackup/domain"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Inert, redacted observations from the complete decompressed payload reader.
// Units are explicit: SQL cells exclude NULL/metadata; Redis includes the
// captured key/dump/group bytes; objects use actual body bytes; resources use
// captured JSON bytes; workspace counts tar entries and entry-content bytes.
// These facts do not grant capture, task ownership or manifest acceptance.
type ownedPayloadCounts struct {
	Version, Kind  string
	SQLTables      []ownedSQLTableCount
	Items          int64
	ContentBytes   int64
	ArchiveEntries int64
	Complete       bool
	SecretPolicy   *ownedSecretPolicyCoverage `json:",omitempty"`
}

type ownedSecretPolicyCoverage struct {
	Version, RegistryVersion, RegistrySHA256 string
	RequiredEntries, CapturedEntries         int64
	Complete                                 bool
}

type ownedSQLTableCount struct {
	Table     string
	Rows      int64
	CellBytes int64
}

// Called only after the surrounding reader validates the captured schema,
// rows, dependencies and original candidate counts. It retains no cell values
// or hashes of plaintext rows.
func countOwnedSQLSnapshot(snapshot domain.Snapshot) ownedPayloadCounts {
	observed := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Kind: "sql_raw_cell_bytes", Complete: true, Items: int64(len(snapshot.Tables)), SQLTables: make([]ownedSQLTableCount, 0, len(snapshot.Tables))}
	for _, table := range snapshot.Tables {
		count := ownedSQLTableCount{Table: table.Name, Rows: int64(len(table.Rows))}
		for _, row := range table.Rows {
			for _, cell := range row {
				if !cell.Null {
					count.CellBytes += int64(len(cell.Bytes))
				}
			}
		}
		observed.SQLTables = append(observed.SQLTables, count)
		observed.ContentBytes += count.CellBytes
	}
	sort.Slice(observed.SQLTables, func(i, j int) bool { return observed.SQLTables[i].Table < observed.SQLTables[j].Table })
	return observed
}

// This is part of the actual complete-publication capture admission. It runs
// before that producer returns its private receipt to any manifest/certificate
// caller. A successfully parsed but uncounted operation cannot become a
// complete publication input.
func publicationPayloadCountsComplete(parts []publicationVerifiedPart) bool {
	kinds := map[string]string{
		"capture-database":             "sql_raw_cell_bytes",
		"capture-source-redis":         "redis_key_dump_group_bytes",
		"capture-team-redis":           "redis_key_dump_bytes",
		"capture-skill-objects":        "object_payload_bytes",
		"capture-team-objects":         "object_payload_bytes",
		"capture-workspace":            "archive_entry_bytes",
		"capture-deployment-resources": "kubernetes_captured_json_bytes",
		"capture-secret-bundle":        "kubernetes_captured_json_bytes",
	}
	domains := map[string]bool{}
	for _, part := range parts {
		// The independently verified description is an administrative carrier,
		// like E/P, and cannot supply or replace any business-domain counts.
		if part.Part == cd.Part {
			if part.Operation != cd.Operation || part.RequestedPart != "" {
				return false
			}
			continue
		}
		if part.Part == ce.Part || part.Part == ce.ProofPart {
			continue
		}
		count := part.Counts
		if part.RequestedPart == "" || publicationRequestedPart(part.Operation) != part.RequestedPart || kinds[part.Operation] == "" || count.Version != "system-backup-inert-payload-counts.v1" || !count.Complete || count.Kind != kinds[part.Operation] || count.Items < 0 || count.ContentBytes < 0 || count.ArchiveEntries < 0 {
			return false
		}
		if part.Operation == "capture-database" {
			if len(count.SQLTables) < 1 || len(count.SQLTables) > 1000 || count.Items != int64(len(count.SQLTables)) || count.ArchiveEntries != 0 {
				return false
			}
			var total int64
			previous := ""
			for _, table := range count.SQLTables {
				if table.Table <= previous || table.Rows < 0 || table.CellBytes < 0 || table.CellBytes > count.ContentBytes-total {
					return false
				}
				total += table.CellBytes
				previous = table.Table
			}
			if total != count.ContentBytes {
				return false
			}
		} else if len(count.SQLTables) != 0 || part.Operation != "capture-workspace" && count.ArchiveEntries != 0 {
			return false
		}
		domains[part.RequestedPart] = true
	}
	return len(domains) == 6
}
