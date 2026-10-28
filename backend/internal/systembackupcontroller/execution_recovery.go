package systembackupcontroller

import (
	"context"
	"database/sql"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// SQLRecoveryAuthority requires a separately issued current recovery grant.
// Expired/canceled forward execution never creates recovery permission.
type SQLRecoveryAuthority struct {
	DB                               *sql.DB
	InstallationID, ApplicationScope string
	Identity                         *PinnedExecutionIdentity
}

func (s SQLRecoveryAuthority) CheckTx(ctx context.Context, tx *sql.Tx, a d.Authority) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || s.Identity == nil || a.InstallationID != s.InstallationID || a.TaskType != "backup" {
		return ErrExecutionAuthority
	}
	// Match forward execution's gate-before-task ordering. Recovery must remain
	// possible after forward permission expires, but cannot invert its locks.
	for _, lock := range []struct {
		query string
		args  []any
	}{
		{"SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR SHARE", nil},
		{"SELECT phase FROM system_backup_gate WHERE scope=? FOR SHARE", []any{s.ApplicationScope}},
		{"SELECT row_version FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? AND lock_name='system_backup_capture_gate' FOR UPDATE", []any{s.InstallationID, CaptureGateScope}},
		{"SELECT row_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", []any{s.InstallationID}},
	} {
		var ignored any
		if tx.QueryRowContext(ctx, lock.query, lock.args...).Scan(&ignored) != nil {
			return ErrExecutionAuthority
		}
	}
	var owner, status, hash, request string
	var version, configVersion uint64
	var lease, deadline, now time.Time
	if !validExecutionInput(a, s.InstallationID) || tx.QueryRowContext(ctx, "SELECT controller_owner,row_version,controller_lease_expires_at,deadline_at,status,config_snapshot_sha256,request_id,config_version,UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", a.InstallationID, a.TaskPublicID).Scan(&owner, &version, &lease, &deadline, &status, &hash, &request, &configVersion, &now) != nil || owner != a.ClaimOwner || version != a.ClaimRowVersion || !now.Before(lease) || !deadline.Equal(a.DeadlineAt) || hash != a.ConfigSHA256 || request != a.RequestID || configVersion != a.ConfigVersion || status == "succeeded" || status == "failed" || status == "canceled" {
		return ErrExecutionAuthority
	}
	var attempt uint64
	if tx.QueryRowContext(ctx, "SELECT MAX(attempt_no) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase=?", a.TaskPublicID, a.Phase).Scan(&attempt) != nil || attempt != a.AttemptNo {
		return ErrExecutionAuthority
	}
	if err := s.Identity.checkSQLAction(ctx, tx, a, now, "recover"); err != nil {
		return err
	}
	if a.MaintenanceFencingToken != 0 {
		var scope, gateOwner, phase string
		var generation uint64
		var resumed sql.NullTime
		if tx.QueryRowContext(ctx, "SELECT application_scope,gate_generation,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR SHARE", a.TaskPublicID).Scan(&scope, &generation, &resumed) != nil || scope != s.ApplicationScope || generation != a.MaintenanceFencingToken {
			return ErrExecutionAuthority
		}
		if tx.QueryRowContext(ctx, "SELECT COALESCE(owner,''),generation,phase FROM system_backup_gate WHERE scope=? FOR SHARE", scope).Scan(&gateOwner, &generation, &phase) != nil {
			return ErrExecutionAuthority
		}
		if !resumed.Valid && phase == "idle" && gateOwner == "" && generation == a.MaintenanceFencingToken {
			return releasedCaptureProofTx(ctx, tx, a, scope)
		}
		if !resumed.Valid && (gateOwner != a.TaskPublicID || generation != a.MaintenanceFencingToken || (phase != "acquiring" && phase != "held" && phase != "releasing")) {
			return ErrExecutionAuthority
		}
		if resumed.Valid && (phase != "idle" || gateOwner != "" || generation != a.MaintenanceFencingToken) {
			return ErrExecutionAuthority
		}
	}
	return nil
}
func (s SQLRecoveryAuthority) Check(ctx context.Context, a d.Authority) error {
	if s.DB == nil {
		return ErrExecutionAuthority
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return s.CheckTx(ctx, tx, a)
}
