//go:build systembackup_mysql

package systembackupkekregistry

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"
)

// Actual pinned disposable TLS MySQL/real127 schema/Bind/AdoptCoverage/locking
// readback/rollback. Source guards are declared test models, never field proof.
func TestRecheckAdoptionOriginalTransactionNativeMySQL(t *testing.T) {
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") == "" || os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID") == "" {
		t.Fatal("explicit independent disposable TLS MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	owner, _, _, binding := bindingReadTLSMySQL(t, ctx)
	for _, mode := range []string{"current", "missing-coverage", "changed-coverage", "wrong-epoch", "binding-drift", "unknown-reference-added", "source-refused"} {
		t.Run(mode, func(t *testing.T) {
			tx, e := owner.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			bound, locked, e := (SQLStore{}).Bind(ctx, tx, binding.InstallationID)
			if e != nil {
				t.Fatal(e)
			}
			original := locked.Facts()
			var stamp time.Time
			if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&stamp) != nil {
				t.Fatal("actual SQL clock")
			}
			prepared := &coverageScanPrepared{snapshot: cloneSnapshot(original), until: stamp.Add(30 * time.Second)}
			prepared.snapshot.Coverage = adoptionRecheckSources()
			prepared.check = func(actual context.Context, view SQLReadView, snapshot LockedSnapshot, now time.Time) error {
				if actual != ctx || view != tx || !SameSnapshotFacts(snapshot.Facts(), original) || !now.Before(prepared.until) {
					return ErrKEKCoverage
				}
				return nil
			}
			if bound.AdoptCoverage(ctx, prepared) != nil {
				t.Fatal("actual first coverage writes")
			}
			switch mode {
			case "missing-coverage":
				_, e = tx.ExecContext(ctx, "DELETE FROM system_backup_v2_kek_coverage WHERE installation_id=? AND partition_name=?", binding.InstallationID, HoldsAndCatalog)
			case "changed-coverage":
				changed := prepared.Sources()[0]
				changed.FenceRevision = "changed"
				raw, digest, err := hashJSON(changed)
				if err != nil {
					t.Fatal(err)
				}
				_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_coverage SET source_json=?,source_sha256=? WHERE installation_id=? AND partition_name=?", raw, digest, binding.InstallationID, changed.Partition)
			case "wrong-epoch":
				_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?", binding.InstallationID)
			case "binding-drift":
				_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_bindings SET row_version=row_version+1 WHERE installation_id=?", binding.InstallationID)
			case "unknown-reference-added":
				r := Reference{Partition: RetainedArtifacts, State: ReferenceUnknown, SourceRecordID: "unresolved-original", SourceRecordVersion: "r1", Key: binding.Key}
				raw, digest, err := hashJSON(r)
				if err != nil {
					t.Fatal(err)
				}
				_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_kek_references(installation_id,partition_name,source_record_id,source_record_version,identity_hash,registry_version,reference_state,reference_sha256,reference_json) VALUES(?,?,?,?,?,?,?,?,?)", binding.InstallationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion, r.Key.IdentityHash, r.Key.RegistryVersion, r.State, digest, raw)
			case "source-refused":
				prepared.check = func(context.Context, SQLReadView, LockedSnapshot, time.Time) error { return ErrKEKCoverage }
			}
			if e != nil {
				t.Fatal("actual controlled drift", e)
			}
			e = bound.RecheckAdoption(ctx, prepared)
			if mode == "current" {
				if e != nil {
					t.Fatal("actual current derived index rejected", e)
				}
			} else if !errors.Is(e, ErrKEKCoverage) {
				t.Fatal("actual post-adoption drift accepted", mode, e)
			}
			if tx.Rollback() != nil {
				t.Fatal("original rollback unconfirmed")
			}
			var epoch, coverage, refs uint64
			if owner.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?", binding.InstallationID).Scan(&epoch) != nil || epoch != original.Epoch || owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_kek_coverage WHERE installation_id=?", binding.InstallationID).Scan(&coverage) != nil || coverage != 0 || owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_kek_references WHERE installation_id=?", binding.InstallationID).Scan(&refs) != nil || refs != 0 {
				t.Fatal("partial adoption survived rollback")
			}
		})
	}
}
