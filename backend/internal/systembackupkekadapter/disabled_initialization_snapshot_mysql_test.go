//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Actual MySQL component check only: it does not claim native historical
// source/17 issuance. Root owns execution and cleanup via the accepted fixture.
func TestDisabledInitializationExistingSnapshotReadOnlyMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	installation := "installation_disabled_snapshot_component"
	if _, e := db.ExecContext(ctx, "INSERT INTO system_backup_v2_kek_fences(installation_id,epoch) VALUES (?,7)", installation); e != nil {
		t.Fatal(e)
	}
	for _, scope := range []string{installation, "installation_missing_disabled_snapshot"} {
		tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if e != nil {
			t.Fatal(e)
		}
		s, e := (reg.SQLStore{}).ReadExistingSnapshotInView(ctx, tx, scope)
		if scope == installation {
			if e != nil || s.Database != identity || s.InstallationID != installation || s.Epoch != 7 {
				t.Fatalf("existing read: %+v %v", s, e)
			}
		} else if e == nil {
			t.Fatal("missing installation/fence was fabricated")
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
	}
	var epoch, count uint64
	if db.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?", installation).Scan(&epoch) != nil || epoch != 7 {
		t.Fatal("read advanced F epoch")
	}
	if db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_kek_fences WHERE installation_id=?", "installation_missing_disabled_snapshot").Scan(&count) != nil || count != 0 {
		t.Fatal("read created missing fence")
	}
}
