package systembackupapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	shared "clawreef/internal/systembackup"
	read "clawreef/internal/systembackupread"
)

func TestVersionedTaskUsesTeamGateAndCurrentClaim(t *testing.T) {
	db, writer := submissionMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prepared, err := writer.Prepare(ctx, read.BackupTask, "createSystemBackup", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := prepared.Stage(realSubmissionSQL{ctx, tx, false}, TaskSubmissionIdentity{"installation_admission", "1", "createSystemBackup", "shared-gate-task-001"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Synthetic controller transition; this test verifies the actual admission
	// transaction, not a production scheduler or a capture Job.
	if _, err = db.Exec(`UPDATE system_backup_v2_backups SET status='acquiring_gate',started_at=UTC_TIMESTAMP(6),controller_owner='controller-a',controller_lease_expires_at=TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),row_version=row_version+1 WHERE public_id=?`, task.PublicID); err != nil {
		t.Fatal(err)
	}
	claim := shared.VersionedGateClaim{InstallationID: "installation_admission", TaskID: task.PublicID, ControllerOwner: "controller-a", RowVersion: 2}
	gate := shared.Gate{DB: db}
	if err = gate.EnsureScope(ctx, "installation"); err != nil {
		t.Fatal(err)
	}
	bad := claim
	bad.RowVersion--
	if _, err = gate.BeginVersionedCapture(ctx, "installation", bad, shared.RegistryHash(), time.Minute, time.Minute); !errors.Is(err, shared.ErrFence) {
		t.Fatal("stale claim admitted", err)
	}
	var closed bool
	if err = db.QueryRow("SELECT owner IS NOT NULL FROM system_backup_gate_admissions WHERE scope='installation'").Scan(&closed); err != nil || closed {
		t.Fatal("invalid claim closed application admission", closed, err)
	}
	lease, err := gate.AcquireMutation(ctx, "installation", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := gate.BeginVersionedCapture(ctx, "installation", claim, shared.RegistryHash(), time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resolved, phase, err := gate.ResolveVersionedCapture(ctx, "installation", claim, shared.RegistryHash())
	if err != nil || resolved != ownership || phase != "acquiring" {
		t.Fatal("lost response changed capture generation", resolved, phase, err)
	}
	if _, err = gate.AcquireMutation(ctx, "installation", time.Minute); !errors.Is(err, shared.ErrMaintenance) {
		t.Fatal("Team writer escaped versioned capture gate", err)
	}
	if _, err = gate.Begin(ctx, "installation", "legacy-controller", shared.RegistryHash(), time.Minute, time.Minute); !errors.Is(err, shared.ErrEngineConflict) {
		t.Fatal("legacy engine entered versioned task", err)
	}
	if _, err = db.Exec("UPDATE system_backup_mutation_leases SET expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE public_id=?", lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = gate.HoldVersionedCapture(ctx, claim, ownership); !errors.Is(err, shared.ErrMaintenance) {
		t.Fatal("expired writer treated as stopped", err)
	}
	if err = gate.ReleaseMutation(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET controller_owner='controller-b',row_version=row_version+1 WHERE public_id=?", task.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = gate.HoldVersionedCapture(ctx, claim, ownership); !errors.Is(err, shared.ErrFence) {
		t.Fatal("old controller held gate after takeover", err)
	}
	claim.ControllerOwner, claim.RowVersion = "controller-b", 3
	ownership, err = gate.HoldVersionedCapture(ctx, claim, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.ValidateCapture(ctx, ownership); err != nil {
		t.Fatal(err)
	}
	var independent int
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_maintenance_locks").Scan(&independent); err != nil || independent != 0 {
		t.Fatal("created a second maintenance authority", independent, err)
	}
	// No Job/remote writer was launched by this test. Release the same authority.
	if err = gate.BeginRelease(ctx, ownership); err != nil {
		t.Fatal(err)
	}
	if err = gate.FinishRelease(ctx, ownership); err != nil {
		t.Fatal(err)
	}
	if err = gate.ValidateCapture(ctx, ownership); !errors.Is(err, shared.ErrFence) {
		t.Fatal("released capture fence remains valid", err)
	}
	// A legacy watchdog may fence v2 work, but must not treat the absence of a
	// legacy plan as proof that the versioned collector exited.
	ownership, err = gate.BeginVersionedCapture(ctx, "installation", claim, shared.RegistryHash(), time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) VALUES('backup',?,1,'capture')", task.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE system_backup_gate SET hold_deadline=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE scope='installation'"); err != nil {
		t.Fatal(err)
	}
	if released, err := gate.ForceReleaseExpired(ctx, "installation"); err != nil || released {
		t.Fatal("watchdog reopened with unconfirmed v2 execution", released, err)
	}
	var gatePhase string
	if err = db.QueryRow("SELECT phase FROM system_backup_gate WHERE scope='installation'").Scan(&gatePhase); err != nil || gatePhase != "releasing" {
		t.Fatal("watchdog did not fence v2 capture", gatePhase, err)
	}
	if _, err = gate.AcquireMutation(ctx, "installation", time.Minute); !errors.Is(err, shared.ErrMaintenance) {
		t.Fatal("writer bypassed deferred v2 recovery", err)
	}
}
