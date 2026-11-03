//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"os"
	"testing"
	"time"
)

// Actual original RR transaction, full source locks, exact17 evidence writes,
// KEK Bind and rollback. Non-SQL signatures remain explicit test fixtures, so
// neither this test nor the returned authentication is physical coverage.
func TestFirstAdoptionBindMySQLUsesOriginalTransactionAndRollsBack(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("explicit independently pinned disposable MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	installation := "installation_first_adoption_bind"
	scanner, err := NewSQLCoverageCensus(db, identity, installation)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := scanner.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pins, records := originalControlBatchFixture(t, observed)
	owner, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: db, Database: identity, InstallationID: installation, Adoption: pins.Adoption, Witnesses: pins.Witnesses})
	if err != nil {
		t.Fatal(err)
	}
	original, err := scanner.BeginOriginalTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Tx().Rollback()
	cut, err := scanner.PrepareOriginalAdoptionControlCut(ctx, original, observed, pins, time.Now().Add(45*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cut.Abort()
	if err := cut.Stage(ctx, records); err != nil {
		t.Fatal(err)
	}
	bound, auth, err := owner.BindFirstAdoptionControls(ctx, cut)
	if err != nil || bound == nil || auth == nil {
		t.Fatal("original transaction bind", err)
	}
	facts := bound.Snapshot().Facts()
	if facts.Database != identity || facts.InstallationID != installation || facts.Epoch != 0 || len(facts.Coverage) != 0 {
		t.Fatal("unexpected original registry facts")
	}
	var stamp time.Time
	if err := original.Tx().QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	if err := auth.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp); err != nil {
		t.Fatal("same native transaction rejected", err)
	}
	foreign, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Rollback()
	if err := auth.Recheck(ctx, foreign, bound.Snapshot(), stamp); err == nil {
		t.Fatal("foreign transaction reused authenticated original")
	}
	if err := cut.Abort(); err != nil {
		t.Fatal("original rollback unconfirmed", err)
	}
	for _, table := range []string{"system_backup_v2_evidence", "system_backup_v2_kek_fences", "system_backup_v2_kek_coverage"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count); err != nil || count != 0 {
			t.Fatal("partial original adoption state persisted", table, count, err)
		}
	}
}
