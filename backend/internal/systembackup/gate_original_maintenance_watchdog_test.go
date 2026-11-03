package systembackup

import (
	"clawreef/internal/backupgate"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The original offline operation has no legacy or v2 capture task. Even an
// empty participant set must not let the historical watchdog manufacture
// collector exit and original-source recovery after the hold has expired.
func TestOriginalMaintenanceExpiryRetainsAdmissionWithEmptyParticipants(t *testing.T) {
	ctx := context.Background()
	db := controlDB(t)
	gate := Gate{db}
	const scope = "original-watchdog"
	owner := "adoption:" + strings.Repeat("a", 32)
	if err := gate.EnsureScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Begin(ctx, scope, owner, RegistryHash(), time.Second, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE system_backup_gate SET hold_deadline=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE scope=?", scope); err != nil {
		t.Fatal(err)
	}
	if released, err := gate.ForceReleaseExpired(ctx, scope); err != nil || released {
		t.Fatal("original source admission released without native recovery", released, err)
	}
	var actualPhase, actualOwner string
	if err := db.QueryRow("SELECT phase,owner FROM system_backup_gate WHERE scope=?", scope).Scan(&actualPhase, &actualOwner); err != nil || actualPhase != "acquiring" || actualOwner != owner {
		t.Fatal(actualPhase, actualOwner, err)
	}
	if _, err := backupgate.HoldRequest(ctx, db, scope); !errors.Is(err, backupgate.ErrMaintenance) {
		t.Fatal("expired original source admission opened", err)
	}
}
