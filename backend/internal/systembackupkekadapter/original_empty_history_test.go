package systembackupkekadapter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Facts-level parser rules only, not actual SQL/native/fence/coverage evidence.
func emptyOriginalHistoryFixture() (SQLCoverageCensusFacts, []S3CoverageCensusFacts) {
	sql := SQLCoverageCensusFacts{Tables: []SQLCoverageTable{{Table: "original_backup_history"}}}
	sources := []S3CoverageCensusFacts{}
	for _, prefix := range []string{"artifact", "staging", "catalog"} {
		f := S3CoverageCensusFacts{Source: reg.SourceRecord{SourceID: "original-owner", RecordID: prefix, RecordVersion: "r1", ContentSHA256: strings.Repeat("a", 64)}, Scope: S3CoverageScope{Endpoint: "https://original.invalid", Region: "original", Bucket: "original", Prefix: prefix}, ObservedAt: time.Now().UTC()}
		raw, _ := json.Marshal([]S3CoverageMember{})
		f.MembersSHA256 = emptyHistoryBytesSHA(raw)
		f.Pages = []S3CoveragePage{{Kind: "versions", PayloadSHA256: strings.Repeat("b", 64)}, {Kind: "uploads", PayloadSHA256: strings.Repeat("c", 64)}}
		sources = append(sources, f)
	}
	return sql, sources
}
func TestOriginalEmptyHistoryLegalZeroWithoutInventedSample(t *testing.T) {
	sql, sources := emptyOriginalHistoryFixture()
	if err := emptyOriginalSources(sql, sources); err != nil {
		t.Fatal(err)
	}
	observation := &UnadmittedEmptyOriginalHistory{sql: sql, external: sources}
	refs, err := observation.EmptyReferences()
	if err != nil || refs == nil || len(refs) != 0 {
		t.Fatal("verified zero data required nonexistent historical sample", err)
	}
	if _, err = json.Marshal(observation); err == nil {
		t.Fatal("unadmitted observation serialized as authority")
	}
	var missing *UnadmittedEmptyOriginalHistory
	if _, err = missing.EmptyReferences(); err == nil {
		t.Fatal("nil scanner became empty proof")
	}
}
func TestOriginalEmptyHistoryRejectsPartialUnknownAndMissingSources(t *testing.T) {
	for _, mode := range []string{"missing-scope", "missing-eof", "truncated", "unknown-write", "delete-marker", "sql-history", "duplicate-root", "missing-page-hash"} {
		t.Run(mode, func(t *testing.T) {
			sql, sources := emptyOriginalHistoryFixture()
			switch mode {
			case "missing-scope":
				sources = sources[:2]
			case "missing-eof":
				sources[0].Pages = sources[0].Pages[:1]
			case "truncated":
				sources[0].Pages[0].Truncated = true
			case "unknown-write":
				sources[1].Members = []S3CoverageMember{{Kind: "multipart_unknown"}}
			case "delete-marker":
				sources[0].Members = []S3CoverageMember{{Kind: "delete_marker"}}
			case "sql-history":
				sql.Tables[0].Rows = 1
			case "duplicate-root":
				sources[1].Scope = sources[0].Scope
			case "missing-page-hash":
				sources[2].Pages[0].PayloadSHA256 = ""
			}
			if emptyOriginalSources(sql, sources) == nil {
				t.Fatal("unknown/partial/nonempty source treated as empty")
			}
		})
	}
}
