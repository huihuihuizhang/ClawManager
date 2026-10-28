package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

var ErrBackupStart = errors.New("public backup start unavailable")

// BackupStart is an exact task projection, NOT a complete Runner Input. Profile
// identity/revision and all real execution dependencies must still be resolved
// by the work store before Prepare. There is no empty/default production DTO.
type BackupStart struct {
	Authority      dispatch.Authority
	ConfigSnapshot []byte
	Spec           dispatch.BackupSpec
}

// BackupStartAdmission checks/reserves metadata capacity for the whole write
// set (one claim receipt, two core events and two attempt units) against the
// original physical report/policy in this same transaction. It also enforces
// business start readiness; it must not commit, open SQL or contact providers.
// These writes are tentative when AdmitStart runs and rollback on rejection.
// This is not A's purpose/resource grant and cannot substitute for it.
type BackupStartAdmission interface {
	AdmitStart(context.Context, *sql.Tx, BackupStart, time.Time) (BackupStartGuard, error)
}
type BackupStartGuard interface {
	RecheckStart(context.Context, *sql.Tx, BackupStart, time.Time) error
	ValidUntil() time.Time
}

type SQLBackupStartStore struct {
	Authority SQLExecutionAuthority
	Admission BackupStartAdmission
	Policy    LeasePolicy
}

// StartNext is the real persisted-schedule -> initial transaction caller. The
// full ExecutionWorkStore must first pass Ready (including Runner/plan/Job and
// recovery dependencies) before calling it. This is not an execution store or
// a fallback for missing owners; it never fabricates profile identity/plan.
func (s SQLBackupStartStore) StartNext(ctx context.Context, owner string, limit int) (*BackupStart, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if absentExecutionDependency(ctx) || ctx.Err() != nil || !controllerOwnerPattern.MatchString(owner) || limit < 1 || limit > 64 {
		return nil, ErrBackupStart
	}
	rows, err := s.Authority.DB.QueryContext(ctx, "SELECT public_id,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND status='pending' AND deadline_at>UTC_TIMESTAMP(6) AND next_reconcile_at<=UTC_TIMESTAMP(6) AND (controller_owner IS NULL OR controller_owner=? OR controller_lease_expires_at<=UTC_TIMESTAMP(6)) ORDER BY next_reconcile_at,id LIMIT ?", s.Authority.InstallationID, owner, limit)
	if err != nil {
		return nil, ErrBackupStart
	}
	// Close the listing connection BEFORE opening a claim transaction. Keeping
	// it while Start waits would deadlock a correctly restricted one-conn pool.
	type candidate struct {
		target  Target
		version uint64
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		if len(candidates) >= limit {
			rows.Close()
			return nil, ErrBackupStart
		}
		var id string
		var version uint64
		if rows.Scan(&id, &version) != nil {
			rows.Close()
			return nil, ErrBackupStart
		}
		target := Target{Kind: TargetBackup, PublicID: id}
		if _, err := target.descriptor(); err != nil || version == 0 {
			rows.Close()
			return nil, ErrBackupStart
		}
		candidates = append(candidates, candidate{target, version})
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrBackupStart
	}
	for _, c := range candidates {
		started, err := s.Start(ctx, c.target, owner, c.version)
		if errors.Is(err, ErrClaimNotAcquired) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &started, nil
	}
	return nil, nil
}

func (s SQLBackupStartStore) validate() error {
	if s.Authority.DB == nil || !installationIDPattern.MatchString(s.Authority.InstallationID) || !s.Authority.DeploymentEnabled || absentExecutionDependency(s.Authority.Authorization) || absentExecutionDependency(s.Admission) {
		return ErrBackupStart
	}
	return s.Policy.Validate()
}

func cloneBackupStart(in BackupStart) BackupStart {
	in.ConfigSnapshot = append([]byte(nil), in.ConfigSnapshot...)
	in.Spec.RequestedParts = append([]string(nil), in.Spec.RequestedParts...)
	return in
}

func loadBackupStart(ctx context.Context, tx *sql.Tx, installation string, token ClaimToken) (BackupStart, error) {
	var b BackupStart
	a := &b.Authority
	a.InstallationID = installation
	a.TaskPublicID = token.Target.PublicID
	a.TaskType = "backup"
	a.ClaimOwner = token.Owner
	a.ClaimRowVersion = token.RowVersion
	a.AttemptNo = 1
	a.Phase = "capture"
	var parts string
	var size uint64
	// The task is already locked by the shared claim CAS. Never substitute the
	// current configuration for this historical, admitted task snapshot.
	err := tx.QueryRowContext(ctx, "SELECT request_id,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,source_orchestrator,source_profile,matrix_key,datasource_topology,runner,task_purpose,requested_parts FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status='pending' AND started_at IS NULL AND maintenance_lock_owner IS NULL AND maintenance_fencing_token IS NULL AND commit_started_at IS NULL AND failure_category='none' FOR UPDATE", installation, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion).Scan(&a.RequestID, &a.ConfigVersion, &b.ConfigSnapshot, &size, &a.ConfigSHA256, &a.DeadlineAt, &b.Spec.SourceOrchestrator, &b.Spec.SourceProfile, &b.Spec.MatrixKey, &b.Spec.DatasourceTopology, &b.Spec.Runner, &b.Spec.TaskPurpose, &parts)
	if err != nil || size != uint64(len(b.ConfigSnapshot)) || !validExecutionInput(*a, installation) {
		return BackupStart{}, ErrBackupStart
	}
	b.Spec.RequestedParts = strings.Split(parts, ",")
	if !validBackupSpec(b.Spec) {
		return BackupStart{}, ErrBackupStart
	}
	return b, nil
}

func validBackupSpec(b dispatch.BackupSpec) bool {
	return dispatch.ValidateBackupSpec(&b) == nil
}

// Start is initial start only: no retry, takeover, source read, Job or provider
// action. It atomically commits common claim+receipt, pending->preparing, both
// capture/secret_capture phase units at attempt 1, and the two core events.
// Existing attempts/resources/actions refuse this path; a new owner must use
// the separate immutable-plan recovery protocol. No unknown commit is retried.
func (s SQLBackupStartStore) Start(ctx context.Context, target Target, owner string, expectedVersion uint64) (BackupStart, error) {
	var zero BackupStart
	if err := s.validate(); err != nil {
		return zero, err
	}
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || target.Kind != TargetBackup || expectedVersion >= ^uint64(0)-2 {
		return zero, ErrBackupStart
	}
	desc, err := validateMutation(ctx, s.Authority.DB, target, owner, expectedVersion)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.Policy.TTL)
	defer cancel()
	tx, err := s.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrBackupStart
	}
	defer tx.Rollback()
	// Common lock order: gate first. The initial start does not acquire it.
	if _, err = (SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, GateKey{InstallationID: s.Authority.InstallationID, Scope: CaptureGateScope}); err != nil {
		return zero, ErrBackupStart
	}
	entryNow, err := backupStartClock(ctx, tx)
	if err != nil {
		return zero, err
	}
	// Lock installation/config before task rows, as in SQLExecutionAuthority.
	var enabled bool
	var activeVersion uint64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.Authority.InstallationID).Scan(&activeVersion) != nil || activeVersion == 0 {
		return zero, ErrBackupStart
	}
	if tx.QueryRowContext(ctx, "SELECT enabled FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", s.Authority.InstallationID, activeVersion).Scan(&enabled) != nil || !enabled {
		return zero, ErrBackupStart
	}
	var eventIDs [3]int64
	receipt := stagedTaskClaimReceipt{ObservedAt: entryNow}
	token, err := stageTaskClaimWithReceipt(ctx, tx, s.Authority.InstallationID, target, owner, expectedVersion, s.Policy, desc, &receipt)
	if err != nil {
		return zero, err
	}
	eventIDs[0] = receipt.ID
	originalClaim, err := claimSnapshot(ctx, tx, desc.table, s.Authority.InstallationID, target)
	if err != nil || !originalClaim.valid(s.Authority.InstallationID, token, s.Policy) || originalClaim.status != "pending" || originalClaim.now.Before(receipt.ObservedAt) {
		return zero, ErrBackupStart
	}
	b, err := loadBackupStart(ctx, tx, s.Authority.InstallationID, token)
	if err != nil {
		return zero, err
	}
	update := "UPDATE system_backup_v2_backups SET status='preparing',pending_reason='none',started_at=UTC_TIMESTAMP(6),next_reconcile_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) AND status='pending' AND NOT EXISTS (SELECT 1 FROM system_backup_v2_attempts a WHERE a.target_type='backup' AND a.target_public_id=system_backup_v2_backups.public_id) AND NOT EXISTS (SELECT 1 FROM system_backup_v2_job_observations j WHERE j.target_type='backup' AND j.target_public_id=system_backup_v2_backups.public_id) AND NOT EXISTS (SELECT 1 FROM system_backup_v2_staging_resources r WHERE r.backup_public_id=system_backup_v2_backups.public_id) AND NOT EXISTS (SELECT 1 FROM system_backup_v2_external_actions x WHERE x.target_type='backup' AND x.target_public_id=system_backup_v2_backups.public_id)"
	result, err := tx.ExecContext(ctx, update, b.Authority.InstallationID, target.PublicID, owner, token.RowVersion)
	one, countErr := exactlyOneRow(result)
	if err != nil || countErr != nil || !one {
		return zero, ErrBackupStart
	}
	token.RowVersion++
	b.Authority.ClaimRowVersion = token.RowVersion
	for _, phase := range []string{"capture", "secret_capture"} {
		r, e := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_attempts (target_type,target_public_id,attempt_no,phase,status) VALUES ('backup',?,1,?,'preparing')", target.PublicID, phase)
		ok, re := exactlyOneRow(r)
		if e != nil || re != nil || !ok {
			return zero, ErrBackupStart
		}
	}
	for index, kind := range []string{"task_status_changed", "attempt_started"} {
		var previous, current any
		if kind == "task_status_changed" {
			previous, current = "pending", "preparing"
		}
		r, e := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events (origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,detail_previous_status,detail_current_status,detail_attempt_number,request_id,created_at) VALUES (?,'backup',?,?,'info','preparing','Backup preparation started.',TRUE,?,?,1,?,UTC_TIMESTAMP(6))", b.Authority.InstallationID, target.PublicID, kind, previous, current, b.Authority.RequestID)
		ok, re := exactlyOneRow(r)
		if e != nil || re != nil || !ok {
			return zero, ErrBackupStart
		}
		id, idErr := r.LastInsertId()
		if idErr != nil || id < 1 {
			return zero, ErrBackupStart
		}
		eventIDs[index+1] = id
	}
	guard, err := s.Authority.Bind(ctx, tx, b.Authority)
	if err != nil {
		return zero, err
	}
	bindFloor := guard.ObservedAt()
	if bindFloor.IsZero() || bindFloor.Before(originalClaim.now) {
		return zero, ErrBackupStart
	}
	now, err := backupStartClock(ctx, tx)
	if err != nil || now.Before(bindFloor) {
		return zero, ErrBackupStart
	}
	budget, err := s.Admission.AdmitStart(ctx, tx, cloneBackupStart(b), now)
	if err != nil || absentExecutionDependency(budget) {
		return zero, ErrBackupStart
	}
	until := budget.ValidUntil()
	if until.IsZero() || !now.Before(until) {
		return zero, ErrBackupStart
	}
	admittedAt := now
	now, err = backupStartClock(ctx, tx)
	if err != nil || now.Before(admittedAt) || !now.Before(until) || budget.RecheckStart(ctx, tx, cloneBackupStart(b), now) != nil || !budget.ValidUntil().Equal(until) {
		return zero, ErrBackupStart
	}
	// Run the final A callback before reloading BOTH units and the exact task
	// projection. No owner callback follows those fixed final SQL checks.
	if err = guard.RecheckAfter(ctx, tx, now); err != nil {
		return zero, err
	}
	authorityUntil := guard.ValidUntil()
	authorityFloor := guard.ObservedAt()
	if authorityUntil.IsZero() || authorityFloor.IsZero() || authorityFloor.Before(now) {
		return zero, ErrBackupStart
	}
	finalFloor, err := checkBackupStartFinal(ctx, tx, b, originalClaim, s.Policy, until, eventIDs, authorityFloor)
	if err != nil {
		return zero, err
	}
	finalNow, err := backupStartClock(ctx, tx)
	if err != nil || finalNow.Before(finalFloor) || !finalNow.Before(until) || !finalNow.Before(authorityUntil) || !finalNow.Before(originalClaim.until) || !finalNow.Before(b.Authority.DeadlineAt) || ctx.Err() != nil {
		return zero, ErrBackupStart
	}
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, ErrTaskClaimCommitUnknown
	}
	return cloneBackupStart(b), nil
}

func backupStartClock(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || now.IsZero() || offset != 0 {
		return time.Time{}, ErrBackupStart
	}
	return now, nil
}

func checkBackupStartFinal(ctx context.Context, tx *sql.Tx, b BackupStart, claim taskClaimSnapshot, policy LeasePolicy, until time.Time, eventIDs [3]int64, floor time.Time) (time.Time, error) {
	current, err := claimSnapshot(ctx, tx, "system_backup_v2_backups", b.Authority.InstallationID, Target{Kind: TargetBackup, PublicID: b.Authority.TaskPublicID})
	token := ClaimToken{Target: Target{Kind: TargetBackup, PublicID: b.Authority.TaskPublicID}, Owner: b.Authority.ClaimOwner, RowVersion: b.Authority.ClaimRowVersion}
	if err != nil || !current.valid(b.Authority.InstallationID, token, policy) || current.status != "preparing" || !current.heartbeat.Equal(claim.heartbeat) || !current.until.Equal(claim.until) || current.now.Before(claim.now) || current.now.Before(floor) || !current.now.Before(until) {
		return time.Time{}, ErrBackupStart
	}
	var cfg []byte
	var parts, orchestrator, profile, matrix, topology, runner, purpose string
	var scheduled, started time.Time
	err = tx.QueryRowContext(ctx, "SELECT config_snapshot_json,source_orchestrator,source_profile,matrix_key,datasource_topology,runner,task_purpose,requested_parts,started_at,next_reconcile_at FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", b.Authority.InstallationID, b.Authority.TaskPublicID).Scan(&cfg, &orchestrator, &profile, &matrix, &topology, &runner, &purpose, &parts, &started, &scheduled)
	want := b.Spec
	if err != nil || !bytes.Equal(cfg, b.ConfigSnapshot) || orchestrator != want.SourceOrchestrator || profile != want.SourceProfile || matrix != want.MatrixKey || topology != want.DatasourceTopology || runner != want.Runner || purpose != want.TaskPurpose || parts != strings.Join(want.RequestedParts, ",") || started.Before(claim.now) || started.After(current.now) || !scheduled.Equal(started) {
		return time.Time{}, ErrBackupStart
	}
	for _, phase := range []string{"capture", "secret_capture"} {
		var status string
		var version uint64
		if tx.QueryRowContext(ctx, "SELECT status,row_version FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=1 AND phase=? FOR SHARE", b.Authority.TaskPublicID, phase).Scan(&status, &version) != nil || status != "preparing" || version != 1 {
			return time.Time{}, ErrBackupStart
		}
	}
	for index, kind := range []string{TaskClaimAcquiredEvent, "task_status_changed", "attempt_started"} {
		var schema, actual, status, request string
		var attempt sql.NullInt64
		var previous, current sql.NullString
		if tx.QueryRowContext(ctx, "SELECT schema_version,event_type,task_status,request_id,detail_attempt_number,detail_previous_status,detail_current_status FROM system_backup_v2_events WHERE id=? AND origin_installation_id=? AND target_type='backup' AND target_public_id=? FOR SHARE", eventIDs[index], b.Authority.InstallationID, b.Authority.TaskPublicID).Scan(&schema, &actual, &status, &request, &attempt, &previous, &current) != nil || schema != "system-backup-event.v1" || actual != kind || request != b.Authority.RequestID {
			return time.Time{}, ErrBackupStart
		}
		if index == 0 {
			if status != "pending" || attempt.Valid || previous.Valid || current.Valid {
				return time.Time{}, ErrBackupStart
			}
		} else {
			if status != "preparing" || !attempt.Valid || attempt.Int64 != 1 {
				return time.Time{}, ErrBackupStart
			}
			if index == 1 {
				if !previous.Valid || previous.String != "pending" || !current.Valid || current.String != "preparing" {
					return time.Time{}, ErrBackupStart
				}
			} else if previous.Valid || current.Valid {
				return time.Time{}, ErrBackupStart
			}
		}
	}
	return current.now, nil
}
