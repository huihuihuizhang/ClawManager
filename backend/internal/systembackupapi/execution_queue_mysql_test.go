package systembackupapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	controller "clawreef/internal/systembackupcontroller"
	dispatch "clawreef/internal/systembackupdispatch"
	execution "clawreef/internal/systembackupexecution"
	read "clawreef/internal/systembackupread"
)

func TestExecutionQueueRealSQLAdmissionTakeoverAndInputIntegrity(t *testing.T) {
	db, w := submissionMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p, err := w.Prepare(ctx, read.BackupTask, "createSystemBackup", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := p.Stage(realSubmissionSQL{ctx, tx, false}, TaskSubmissionIdentity{"installation_admission", "1", "createSystemBackup", "execution-queue-task-001"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	queue := controller.SQLExecutionQueue{DB: db, InstallationID: "installation_admission", Owner: "controller-a", Policy: controller.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: time.Second}}
	// Tampering cannot claim/advance a task before input verification.
	if _, err = db.Exec("UPDATE system_backup_v2_execution_inputs SET request_json=? WHERE task_public_id=?", []byte(`{"task_purpose":"functional_test"}`), task.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.TakeBackup(ctx); !errors.Is(err, controller.ErrExecutionInput) {
		t.Fatal("changed request admitted", err)
	}
	var owner sql.NullString
	var status string
	if err = db.QueryRow("SELECT status,controller_owner FROM system_backup_v2_backups WHERE public_id=?", task.PublicID).Scan(&status, &owner); err != nil || status != "pending" || owner.Valid {
		t.Fatal("failed validation leaked claim", status, owner, err)
	}
	if _, err = db.Exec("UPDATE system_backup_v2_execution_inputs SET request_json=? WHERE task_public_id=?", p.(*preparedSQLTask).body, task.PublicID); err != nil {
		t.Fatal(err)
	}
	// The kill switch forbids new work without changing its pinned input.
	if _, err = db.Exec("UPDATE system_backup_v2_installation_state SET last_effective_enabled=FALSE"); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.TakeBackup(ctx); !errors.Is(err, controller.ErrClaimNotAcquired) {
		t.Fatal("disabled capture started", err)
	}
	if _, err = db.Exec("UPDATE system_backup_v2_installation_state SET last_effective_enabled=TRUE"); err != nil {
		t.Fatal(err)
	}
	// Audit failure rolls the claim and initial transition back together.
	if _, err = db.Exec("CREATE TRIGGER fail_execution_audit BEFORE INSERT ON system_backup_v2_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'"); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.TakeBackup(ctx); err == nil {
		t.Fatal("audit failure ignored")
	}
	if err = db.QueryRow("SELECT status,controller_owner FROM system_backup_v2_backups WHERE public_id=?", task.PublicID).Scan(&status, &owner); err != nil || status != "pending" || owner.Valid {
		t.Fatal("audit failure leaked execution", status, owner, err)
	}
	if _, err = db.Exec("DROP TRIGGER fail_execution_audit"); err != nil {
		t.Fatal(err)
	}
	// All six are intentionally the same owner: a local duplicate tick also
	// must not claim a second execution just because the string matches.
	var group sync.WaitGroup
	results := make(chan controller.ClaimedBackup, 6)
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, e := queue.TakeBackup(ctx)
			if e == nil {
				results <- got
			} else {
				errs <- e
			}
		}()
	}
	group.Wait()
	close(results)
	close(errs)
	if len(results) != 1 || len(errs) != 5 {
		t.Fatal("concurrent duplicate execution", len(results), len(errs))
	}
	for e := range errs {
		if !errors.Is(e, controller.ErrClaimNotAcquired) {
			t.Fatal(e)
		}
	}
	first := <-results
	if first.Status != "preparing" || first.RecoveryRequired || first.Claim.Target.PublicID != task.PublicID || string(first.Config) == "" || first.Claim.RowVersion != 3 {
		t.Fatal("invalid prepared task", first.Status, first.Claim.RowVersion)
	}
	cipher, err := execution.NewPlanCipher("test-v1", map[string][]byte{"test-v1": bytes.Repeat([]byte{37}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	vault := execution.PlanStore{DB: db, InstallationID: queue.InstallationID, Cipher: cipher, CapacityReportFile: w.capacityFile}
	rawPlan := json.RawMessage(`{"schema":"execution-plan.v1","source_refs":["test-source-v1"]}`)
	plan := dispatch.Plan{SchemaVersion: "execution-plan.v1", CanonicalJSON: rawPlan, SHA256: digestJSON(rawPlan)}
	stored, err := vault.Save(ctx, first.Claim, plan)
	if err != nil || !bytes.Equal(stored.CanonicalJSON, rawPlan) {
		t.Fatal("persist plan", err)
	}
	var encrypted, nonce []byte
	if err = db.QueryRow("SELECT ciphertext,nonce FROM system_backup_v2_execution_plans WHERE task_public_id=?", task.PublicID).Scan(&encrypted, &nonce); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("test-source")) || len(nonce) != 12 {
		t.Fatal("plan was not encrypted")
	}
	// Same operation after a lost response reuses exactly the original cipher.
	if _, err = vault.Save(ctx, first.Claim, plan); err != nil {
		t.Fatal("plan replay", err)
	}
	var replayed []byte
	if err = db.QueryRow("SELECT ciphertext FROM system_backup_v2_execution_plans WHERE task_public_id=?", task.PublicID).Scan(&replayed); err != nil || !bytes.Equal(encrypted, replayed) {
		t.Fatal("plan replay rewrote cipher", err)
	}
	different := dispatch.Plan{SchemaVersion: plan.SchemaVersion, CanonicalJSON: json.RawMessage(`{"source_refs":["replacement"]}`)}
	different.SHA256 = digestJSON(different.CanonicalJSON)
	if _, err = vault.Save(ctx, first.Claim, different); !errors.Is(err, execution.ErrPlan) {
		t.Fatal("overwrote original plan", err)
	}
	corrupted := append([]byte(nil), encrypted...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err = db.Exec("UPDATE system_backup_v2_execution_plans SET ciphertext=? WHERE task_public_id=?", corrupted, task.PublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Load(ctx, first.Claim); !errors.Is(err, execution.ErrPlan) {
		t.Fatal("tampered plan decrypted", err)
	}
	if _, err = db.Exec("UPDATE system_backup_v2_execution_plans SET ciphertext=? WHERE task_public_id=?", encrypted, task.PublicID); err != nil {
		t.Fatal(err)
	}
	// A crashed controller's active execution is taken only for reconciliation.
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE public_id=?", task.PublicID); err != nil {
		t.Fatal(err)
	}
	queue.Owner = "controller-b"
	recovered, err := queue.TakeBackup(ctx)
	if err != nil || !recovered.RecoveryRequired || recovered.Status != "preparing" || recovered.Claim.RowVersion != 4 {
		t.Fatal("takeover restarted work", recovered.Status, recovered.RecoveryRequired, err)
	}
	if _, err = (controller.ClaimCoordinator{Executor: db, InstallationID: queue.InstallationID}).Renew(ctx, first.Claim, queue.Policy); !errors.Is(err, controller.ErrClaimLost) {
		t.Fatal("old execution renewed", err)
	}
	if _, err = vault.Load(ctx, first.Claim); !errors.Is(err, controller.ErrClaimLost) {
		t.Fatal("old controller read plan", err)
	}
	if loaded, err := vault.Load(ctx, recovered.Claim); err != nil || !bytes.Equal(loaded.CanonicalJSON, rawPlan) {
		t.Fatal("new owner lost original plan", err)
	}
	var starts int
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type='task_status_changed' AND task_status='preparing'", task.PublicID).Scan(&starts); err != nil || starts != 1 {
		t.Fatal("takeover emitted duplicate start", starts, err)
	}
}
