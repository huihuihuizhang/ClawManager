package systembackupexecution

import (
	"bytes"
	"context"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

// The original locks deliberately block independent writers until commit.
// Mutate rows with the SAME admitted transaction to prove the batched current
// read still detects writes by its own caller; rollback preserves the fixture.
func assertHeldCaptureCurrentFacts(t *testing.T, o *PublicJobOwner, a d.Authority) {
	t.Helper()
	ctx := context.Background()
	var app, metadata string
	if o.Gate.Authority.ApplicationScope == "" || o.Gate.Authority.DB.QueryRow("SELECT phase FROM system_backup_gate").Scan(&app) != nil || o.Gate.Authority.DB.QueryRow("SELECT gate_state FROM system_backup_v2_maintenance_locks").Scan(&metadata) != nil || app != "held" || metadata != "held" {
		t.Fatal("batched current recheck requires both original held gates")
	}
	for _, test := range []struct{ table, column, value string }{
		{"backups", "row_version", "row_version+1"},
		{"backups", "controller_lease_expires_at", "TIMESTAMPADD(SECOND,1,controller_lease_expires_at)"},
		{"backups", "controller_owner", "CONCAT(controller_owner,' ')"},
		{"backups", "schema_version", "UPPER(schema_version)"},
		{"backups", "task_type", "'Backup'"},
		{"backups", "status", "'Capturing'"},
		{"backups", "request_id", "CONCAT(request_id,' ')"},
		{"backups", "config_snapshot_json", "CONCAT(config_snapshot_json,' ')"},
		{"maintenance_locks", "row_version", "row_version+1"},
		{"maintenance_locks", "fencing_token", "fencing_token+1"},
		{"maintenance_locks", "lease_expires_at", "TIMESTAMPADD(SECOND,1,lease_expires_at)"},
		{"maintenance_locks", "absolute_hold_deadline_at", "TIMESTAMPADD(SECOND,1,absolute_hold_deadline_at)"},
		{"maintenance_locks", "lock_owner", "CONCAT(lock_owner,' ')"},
		{"installation_state", "row_version", "row_version+1"},
		{"installation_state", "schema_version", "UPPER(schema_version)"},
		{"attempts", "row_version", "row_version+1"},
		{"attempts", "status", "'Running'"},
	} {
		t.Run("held-current-"+test.table+"-"+test.column, func(t *testing.T) {
			tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			guard, err := o.Gate.Authority.Bind(ctx, tx, a)
			if err != nil || guard.Recheck(ctx, tx) != nil {
				t.Fatal("original held guard baseline", err)
			}
			table := "system_backup_v2_" + test.table
			var before, after []byte
			if tx.QueryRowContext(ctx, "SELECT "+test.column+" FROM "+table).Scan(&before) != nil {
				t.Fatal("original current field")
			}
			result, err := tx.ExecContext(ctx, "UPDATE "+table+" SET "+test.column+"="+test.value)
			if err != nil {
				t.Fatal(err)
			}
			count, err := result.RowsAffected()
			if err != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT "+test.column+" FROM "+table).Scan(&after) != nil || bytes.Equal(before, after) {
				t.Fatal("current field mutation not actually observed", count, err)
			}
			if guard.Recheck(ctx, tx) == nil || !guard.ValidUntil().IsZero() {
				t.Fatal("current field drift escaped original final guard")
			}
		})
	}
}
