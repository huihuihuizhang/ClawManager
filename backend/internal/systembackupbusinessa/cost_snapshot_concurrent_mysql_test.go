//go:build systembackup_mysql

package systembackupbusinessa

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Called only inside the existing UID/server/owner-bound migrated restore
// fixture. The original collector runs on a new SELECT-only reader pool; the
// sole writer uses the already-owned fixture database and an explicit commit.
func businessCostSnapshotConcurrentCommit(t *testing.T, parent context.Context, cfg *mysql.Config, reader, writer *sql.DB, scope *CaptureScope, want SourceSnapshot, original NormalizedCostRecord, uuid, nonce string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if snapshotCostRows(want) != 1 || len(scope.tables) != 15 {
		t.Fatal("concurrent cost probe requires the one-row migrated fixture")
	}
	identitySQL := "SELECT @@server_uuid,DATABASE(),(SELECT owner_nonce FROM a_business_restore_probe_owner WHERE id=1)"
	checkIdentity := func(ctx context.Context, q interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) bool { var server, database, owner string; return q.QueryRowContext(ctx, identitySQL).Scan(&server, &database, &owner) == nil && server == uuid && database == cfg.DBName && owner == nonce }
	if !checkIdentity(ctx, reader) {
		t.Fatal("SELECT-only reader lost the exact migrated owner identity")
	}
	baseline, err := (SQLCountCollector{DB: reader}).CollectSnapshot(ctx, scope)
	if err != nil || !reflect.DeepEqual(baseline, want) {
		t.Fatal("source collector baseline differs from the authenticated fixture snapshot")
	}
	w, err := writer.Conn(ctx)
	if err != nil {
		t.Fatal("borrow run-owned writer connection")
	}
	defer w.Close()
	if !checkIdentity(ctx, w) {
		t.Fatal("writer lost the exact migrated owner identity")
	}
	var originalMoney string
	if w.QueryRowContext(ctx, "SELECT CAST(estimated_cost AS CHAR) FROM cost_records WHERE id=?", original.ID).Scan(&originalMoney) != nil || originalMoney != original.EstimatedCost {
		t.Fatal("concurrent cost probe original money mismatch")
	}
	// Restore even if a write/COMMIT reply fails: an error cannot establish that
	// no write committed. The outer fixture still owns exact database cleanup.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if !checkIdentity(cleanup, w) {
			t.Error("CLEANUP_PENDING concurrent cost fixture owner identity")
			return
		}
		if _, err := w.ExecContext(cleanup, "UPDATE cost_records SET estimated_cost=? WHERE id=?", originalMoney, original.ID); err != nil {
			t.Error("CLEANUP_PENDING concurrent cost fixture restoration")
			return
		}
		var restored string
		if w.QueryRowContext(cleanup, "SELECT CAST(estimated_cost AS CHAR) FROM cost_records WHERE id=?", original.ID).Scan(&restored) != nil || restored != originalMoney {
			t.Error("CLEANUP_PENDING concurrent cost fixture restored value")
		}
	}()
	connector, err := mysql.NewConnector(cfg.Clone())
	if err != nil {
		t.Fatal("construct independent SELECT-only collector transport")
	}
	writes := 0
	var changedMoney string
	hooked := sql.OpenDB(costSnapshotHookConnector{inner: connector, query: "SELECT COUNT(*) FROM `" + scope.tables[0] + "`", after: func(readCtx context.Context) error {
		writes++
		if writes != 1 || !checkIdentity(readCtx, w) {
			return errors.New("concurrent cost writer identity or dispatch changed")
		}
		tx, err := w.BeginTx(readCtx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(readCtx, "UPDATE cost_records SET estimated_cost=estimated_cost+0.00000001 WHERE id=?", original.ID)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errors.New("concurrent cost mutation did not change one original row")
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if w.QueryRowContext(readCtx, "SELECT CAST(estimated_cost AS CHAR) FROM cost_records WHERE id=?", original.ID).Scan(&changedMoney) != nil || changedMoney == originalMoney {
			return errors.New("concurrent cost committed value not observed")
		}
		return nil
	}})
	hooked.SetMaxOpenConns(1)
	hooked.SetMaxIdleConns(0)
	defer hooked.Close()
	frozen, err := (SQLCountCollector{DB: hooked}).CollectSnapshot(ctx, scope)
	if err != nil || writes != 1 || !reflect.DeepEqual(frozen, baseline) {
		t.Fatal("concurrent commit changed the original RR counts or cost aggregate")
	}
	changed := original
	changed.EstimatedCost = changedMoney
	wantChanged, err := normalizedCostAggregateHash([]NormalizedCostRecord{changed})
	if err != nil || wantChanged == baseline.CostAggregateSHA256 {
		t.Fatal("independent changed-row aggregate failed to distinguish the commit")
	}
	fresh, err := (SQLCountCollector{DB: reader}).CollectSnapshot(ctx, scope)
	if err != nil || !reflect.DeepEqual(fresh.Tables, baseline.Tables) || fresh.CostAggregateSHA256 != wantChanged {
		t.Fatal("fresh transaction did not observe the committed same-count cost change")
	}
	t.Log("PASS cost-snapshot-concurrent-commit first_count_closed=yes writer_commit=observed original_rr=unchanged fresh_rr=changed writer=fixture reader=select-only production_dump_proof=no")
}
