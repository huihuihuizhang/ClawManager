package systembackupcontroller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

var ErrSourceGateWaiting = errors.New("waiting for original source gate owner")
var ErrSourceGateWaitExpired = errors.New("untouched source gate wait settled after timeout")

// WaitForSource records observation only. It cannot pause/resume any writer,
// acquire a gate or issue forward permission. Independent recovery authority
// permits an untouched task to settle even after its forward permission ends.
// The boolean means a foreign gate still blocks this task. A timeout is settled
// only after the same no-side-effect proof used by FailUntouched.
func (g SQLCaptureGate) WaitForSource(ctx context.Context, a d.Authority) (bool, error) {
	if !g.ready() || a.MaintenanceOwner != "" || a.MaintenanceFencingToken != 0 {
		return false, ErrExecutionRecoveryRequired
	}
	tx, err := g.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var engine, scope, phase, owner, admissionOwner string
	if tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR SHARE").Scan(&engine) != nil || engine != "v2" {
		return false, ErrExecutionRecoveryRequired
	}
	if tx.QueryRowContext(ctx, "SELECT scope,COALESCE(owner,'') FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE", g.Authority.ApplicationScope).Scan(&scope, &admissionOwner) != nil {
		return false, ErrExecutionRecoveryRequired
	}
	if tx.QueryRowContext(ctx, "SELECT phase,COALESCE(owner,'') FROM system_backup_gate WHERE scope=? FOR SHARE", scope).Scan(&phase, &owner) != nil {
		return false, ErrExecutionRecoveryRequired
	}
	if err = g.Recovery.CheckTx(ctx, tx, a); err != nil {
		return false, err
	}
	var status string
	var started sql.NullTime
	var now time.Time
	var snapshot []byte
	if tx.QueryRowContext(ctx, "SELECT status,source_gate_wait_started_at,UTC_TIMESTAMP(6),config_snapshot_json FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE", a.TaskPublicID).Scan(&status, &started, &now, &snapshot) != nil || (status != "preparing" && status != "ready_for_capture" && status != "acquiring_gate") {
		return false, ErrExecutionRecoveryRequired
	}
	defer clear(snapshot)
	var config struct {
		Durations struct {
			Seconds int64 `json:"gate_acquisition_timeout_seconds"`
		} `json:"durations"`
	}
	if recordHash(snapshot) != a.ConfigSHA256 || json.Unmarshal(snapshot, &config) != nil || config.Durations.Seconds < 10 || config.Durations.Seconds > 600 {
		return false, ErrExecutionRecoveryRequired
	}
	if owner == a.TaskPublicID && phase != "idle" {
		return false, nil
	} // resolve the original epoch; never wait/reacquire
	if (phase == "idle" && owner != "") || (phase != "idle" && (owner == "" || (phase != "acquiring" && phase != "held" && phase != "releasing"))) {
		return false, ErrExecutionRecoveryRequired
	}
	var effects int
	if err = tx.QueryRowContext(ctx, untouchedEffectsSQL, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID, a.TaskPublicID).Scan(&effects); err != nil || effects != 0 {
		return false, ErrExecutionRecoveryRequired
	}
	if !started.Valid {
		result, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_backups SET source_gate_wait_started_at=? WHERE public_id=? AND row_version=? AND controller_owner=? AND source_gate_wait_started_at IS NULL", now, a.TaskPublicID, a.ClaimRowVersion, a.ClaimOwner)
		if ok, z := exactlyOneRow(result); e != nil || z != nil || !ok {
			return false, ErrClaimLost
		}
		started = sql.NullTime{Time: now, Valid: true}
	}
	if now.Before(started.Time) {
		return false, ErrExecutionRecoveryRequired
	}
	expired := !now.Before(started.Time.Add(time.Duration(config.Durations.Seconds) * time.Second))
	blocked := phase != "idle" || (admissionOwner != "" && admissionOwner != a.TaskPublicID)
	if blocked {
		message := fmt.Sprintf("Waiting for another operation to release the shared source gate. UTC start %s; fixed wait budget %ds. No source action has been sent.", started.Time.UTC().Format(time.RFC3339Nano), config.Durations.Seconds)
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id)
SELECT ?,'backup',?,'diagnostic.d.source_gate_wait','warning',?,?,?
WHERE NOT EXISTS(SELECT 1 FROM system_backup_v2_events WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND event_type='diagnostic.d.source_gate_wait')`, a.InstallationID, a.TaskPublicID, status, message, a.RequestID, a.InstallationID, a.TaskPublicID)
		if err != nil {
			return false, err
		}
	}
	// Recheck the independent identity/claim immediately before committing the
	// observation; the timestamp is never refreshed by a retry or new controller.
	if err = g.Recovery.CheckTx(ctx, tx, a); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, ErrExecutionCommitUnknown
	}
	if expired {
		if err = g.failUntouched(ctx, a, "quiesce_timeout"); err != nil {
			return false, err
		}
		return false, ErrSourceGateWaitExpired
	}
	return blocked, nil
}
