package systembackupevidence

import (
	"database/sql/driver"
	"strings"
	"testing"
)

// 001_init_schema.sql publishes audit_logs.resource_id INT. Override the
// scripted catalog independently: deriving this fact from gcDirectColumns
// would let the production type error reproduce itself in the fixture.
func TestAGCDirectAuditResourcePublishedInteger(t *testing.T) {
	for _, mode := range []string{"published_int", "wrong_type", "unexpected_fk"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			found := 0
			for _, row := range f.d.early.catalog[downloadGCEarlyColumnsSQL] {
				if row[0] == "audit_logs" && row[1] == "resource_id" {
					row[3] = "int"
					if mode == "wrong_type" {
						row[3] = "varchar"
					}
					found++
				}
			}
			if found != 1 {
				t.Fatal("independent published audit resource column absent or duplicated")
			}
			if mode == "unexpected_fk" {
				// Re-pin the outer fingerprint so the direct closed catalog must
				// itself reject this unpublished edge, not just a changed hash.
				f.d.early.catalog[downloadGCEarlyForeignKeysSQL] = append(f.d.early.catalog[downloadGCEarlyForeignKeysSQL], []driver.Value{f.d.identity.Database, "audit_logs", "audit_resource_unpublished_fk", "1", "resource_id", f.d.identity.Database, "system_backup_v2_operations", "id", "RESTRICT", "RESTRICT"})
			}
			f.d.early.service.c.Metadata = f.d.early.pins()
			before := f.d.reserved
			err := f.s.Collect(f.ctx, f.operation)
			if mode != "published_int" {
				if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.writes) != 0 || f.d.reserved != before {
					t.Fatal("unpublished column type or FK did not block collection")
				}
				return
			}
			if err != nil || f.d.commits != f.commits+1 {
				t.Fatal("published INT metadata rejected the otherwise eligible group", err)
			}
			for _, locked := range f.d.direct.initial {
				// Published backup audit writers leave the legacy INT resource
				// NULL and put sop_ identities in JSON. A public ID comparison
				// against resource_id is neither typed nor a published binding.
				if strings.Contains(locked.query, " WHERE resource_id=") {
					t.Fatal("legacy INT resource column treated as a public Operation reference")
				}
			}
		})
	}
}
