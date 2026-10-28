package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestDownloadResultRetentionOriginalGroupAndLockOrder(t *testing.T) {
	f, _, c := committedFixture(t)
	r := resultFixture(t, f)
	f.db.sessionRevoked, f.db.userActive = true, false
	f.db.activeConfig = 2
	admission := append([]driver.Value(nil), f.db.m.receipt...)
	if err := r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted", BytesWritten: 3}); err != nil {
		t.Fatal(err)
	}
	want := []driver.Value{c.rows.operationID, c.rows.receipt.Installation, c.operationID, c.rows.evidenceID, c.record.Manifest.Identity.ID,
		c.intentAuditID, int64(1730), int64(len(f.db.resultBody)), hash(f.db.resultBody), f.db.now, c.rows.retainUntil}
	if !reflect.DeepEqual(f.db.resultRetention, want) || !reflect.DeepEqual(f.db.m.receipt, admission) || f.db.resultRetentionReads < 3 {
		t.Fatal("result was not linked to the exact original immutable group", f.db.resultRetention)
	}
	last := -1
	for _, call := range []string{"result-actor", "result-retention-key", "L4", "L6", "result-audit", "result-retention-insert", "result-release", "commit"} {
		index := -1
		for n := last + 1; n < len(f.db.calls); n++ {
			if f.db.calls[n] == call {
				index = n
				break
			}
		}
		if index < 0 {
			t.Fatal("result retention acquired a backwards or missing lock", call, f.db.calls)
		}
		last = index
	}
}

func TestDownloadResultRetentionFailuresRollbackWholeResult(t *testing.T) {
	faults := []string{"result_retention_key", "result_retention_insert", "result_retention_zero", "result_retention_multiple", "result_retention_rows_error", "result_retention_read", "result_retention_missing", "existing_result"}
	for _, stage := range []string{"corrupt", "final"} {
		for n := 0; n < 11; n++ {
			faults = append(faults, "result_retention_"+stage+"_"+strconv.Itoa(n))
		}
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			f, _, c := committedFixture(t)
			r := resultFixture(t, f)
			if fault == "existing_result" {
				f.db.resultRetention = []driver.Value{c.rows.operationID}
			} else {
				f.db.fault = fault
			}
			before := f.db.record
			reserved := f.db.reserved
			retention := append([]driver.Value(nil), f.db.resultRetention...)
			if err := r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "rejected"}); err == nil {
				t.Fatal("unprotected result committed")
			}
			if f.db.commits != 1 || !reflect.DeepEqual(f.db.record, before) || len(f.db.resultBody) != 0 || !reflect.DeepEqual(retention, f.db.resultRetention) || f.db.reserved != reserved {
				t.Fatal("result audit, retention link, claim release or budget survived rollback")
			}
			queries := len(f.db.queries)
			if r.Finish(context.Background(), c, DownloadResultObservation{Outcome: "rejected"}) == nil || len(f.db.queries) != queries {
				t.Fatal("failed or existing result retried")
			}
		})
	}
}

func TestDownloadResultRetentionDDLAndClosedReferences(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/system-backup-d-download-admission-schema-proposal-20261019.sql")
	if err != nil {
		t.Fatal(err)
	}
	ddl := string(raw)
	start := strings.Index(ddl, "CREATE TABLE system_backup_v2_download_result_receipts (")
	if start < 0 {
		t.Fatal("result retention migration candidate absent")
	}
	result := ddl[start:]
	for _, clause := range []string{
		"PRIMARY KEY (operation_id)", "UNIQUE KEY uk_sb_download_result_audit (result_audit_id)",
		"FOREIGN KEY (origin_installation_id,operation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,retain_until)",
		"REFERENCES system_backup_v2_download_admission_receipts(origin_installation_id,operation_id,operation_public_id,evidence_id,evidence_public_id,intent_audit_id,retain_until) ON DELETE RESTRICT",
		"FOREIGN KEY (result_audit_id)", "REFERENCES audit_logs(id) ON DELETE RESTRICT", "result_at < retain_until", "result_audit_id <> intent_audit_id",
	} {
		if !strings.Contains(result, clause) {
			t.Fatal("result audit retention is not protected by DDL", clause)
		}
	}
	columns := taskOwnerDDLColumns(t)
	if columns["system_backup_v2_download_result_receipts.evidence_id"] != "bigint" || columns["system_backup_v2_download_result_receipts.evidence_public_id"] != "varchar" {
		t.Fatal("candidate result evidence graph incomplete")
	}
	f, _, s, m := sqlTaskOwnerFixture(t, "backup")
	m.refs["system_backup_v2_download_result_receipts"] = []int64{73, 74}
	tx, _, err := s.Registry().begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.LockOwnerReferences(context.Background(), tx, f.initial); err != nil {
		t.Fatal("result references not included in original L3 prefix", err)
	}
	for _, q := range f.db.queries {
		if strings.Contains(q, " FROM system_backup_v2_download_result_receipts WHERE ") && strings.Contains(q, "ORDER BY operation_id LIMIT 10001 FOR UPDATE") {
			return
		}
	}
	t.Fatal("result reference lookup missed the actual operation primary key")
}

func TestDownloadResultRetentionMissingMetadataRejectsBeforeChunks(t *testing.T) {
	for _, column := range []string{"evidence_id", "evidence_public_id"} {
		t.Run(column, func(t *testing.T) {
			f, _, s, m := sqlTaskOwnerFixture(t, "backup")
			delete(m.metadata, "system_backup_v2_download_result_receipts."+column)
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID); err == nil || m.chunkReads != 0 {
				t.Fatal("hidden result reference metadata admitted plaintext")
			}
		})
	}
}
