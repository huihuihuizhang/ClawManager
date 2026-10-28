package systembackupcontroller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

var ErrExecutionRecoveryRequired = errors.New("backup execution requires original journal recovery")

// ExecutionInput restores the admitted profile and task's original config/spec.
// It neither discovers source data nor substitutes the current deployment config.
func (b ClaimedBackup) ExecutionInput(ctx context.Context, tx *sql.Tx) (d.Input, error) {
	var in d.Input
	var p struct {
		InstallationID string `json:"installation_id"`
		Profile        string `json:"source_profile"`
		Revision       string `json:"revision"`
	}
	if json.Unmarshal(b.Profile, &p) != nil || p.InstallationID != b.InstallationID || p.Profile == "" || p.Revision == "" {
		return in, ErrExecutionInput
	}
	in.Authority = d.Authority{InstallationID: b.InstallationID, TaskType: "backup", TaskPublicID: b.Claim.Target.PublicID, RequestID: b.RequestID, ConfigVersion: b.ConfigVersion, ConfigSHA256: b.ConfigSHA256, AttemptNo: 1, Phase: "capture", ClaimOwner: b.Claim.Owner, ClaimRowVersion: b.Claim.RowVersion, DeadlineAt: b.Deadline}
	in.ConfigSnapshot = append(json.RawMessage(nil), b.Config...)
	in.ProfileID = p.Profile
	in.ProfileRevision = p.Revision
	var spec d.BackupSpec
	var parts string
	var owner sql.NullString
	var fence sql.NullInt64
	if tx.QueryRowContext(ctx, "SELECT source_orchestrator,source_profile,matrix_key,datasource_topology,runner,task_purpose,requested_parts,maintenance_lock_owner,maintenance_fencing_token FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", b.InstallationID, b.Claim.Target.PublicID).Scan(&spec.SourceOrchestrator, &spec.SourceProfile, &spec.MatrixKey, &spec.DatasourceTopology, &spec.Runner, &spec.TaskPurpose, &parts, &owner, &fence) != nil {
		return d.Input{}, ErrExecutionInput
	}
	spec.RequestedParts = strings.Split(parts, ",")
	if d.ValidateBackupSpec(&spec) != nil {
		return d.Input{}, ErrExecutionInput
	}
	in.Backup = &spec
	if owner.Valid || fence.Valid {
		if !owner.Valid || !fence.Valid || fence.Int64 < 1 {
			return d.Input{}, ErrExecutionInput
		}
		in.Authority.MaintenanceOwner = owner.String
		in.Authority.MaintenanceFencingToken = uint64(fence.Int64)
	}
	return in, nil
}

// SQLExecutionWorkStore is the single production scheduler behind the public
// loop. Queue claims+receipts, phase CAS and outcome observations remain in the
// public task tables. DurableExecutionStore supplies immutable plan custody.
type SQLExecutionWorkStore struct {
	Queue     SQLExecutionQueue
	Authority SQLExecutionAuthority
	Records   SQLExecutionRecords
	// PrepareCapture must obtain/verify the shared pause barrier before returning
	// capture work. It is installed by the capture composition, never a default.
	PrepareCapture func(context.Context, ClaimedBackup) (*ExecutionWork, error)
	FinishCapture  func(context.Context, ExecutionWork, ExecutionOutcome) error
}

func (s *SQLExecutionWorkStore) Ready(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Queue.validate() != nil || s.Queue.Authorization == nil || s.Authority.DB != s.Queue.DB || s.Authority.Authorization == nil || s.Authority.ApplicationScope == "" || s.Queue.ApplicationScope != s.Authority.ApplicationScope || s.Authority.InstallationID != s.Queue.InstallationID || s.Records.Authority.DB != s.Queue.DB || s.Records.CapacityReportFile == "" || s.PrepareCapture == nil {
		return d.ErrNotReady
	}
	return s.Records.Ready(ctx)
}
func (s *SQLExecutionWorkStore) Next(ctx context.Context) (*ExecutionWork, error) {
	if err := s.Ready(ctx); err != nil {
		return nil, err
	}
	b, err := s.Queue.TakeBackup(ctx)
	if errors.Is(err, ErrClaimNotAcquired) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if b.Status == "ready_for_capture" || b.Status == "acquiring_gate" || b.Status == "capturing" || b.Status == "canceling" {
		return s.PrepareCapture(ctx, b)
	}
	if b.Status != "preparing" {
		return nil, ErrExecutionRecoveryRequired
	}
	if s.Queue.Recovery != nil {
		a := d.Authority{InstallationID: b.InstallationID, TaskType: "backup", TaskPublicID: b.Claim.Target.PublicID, RequestID: b.RequestID, ConfigVersion: b.ConfigVersion, ConfigSHA256: b.ConfigSHA256, AttemptNo: 1, Phase: "capture", ClaimOwner: b.Claim.Owner, ClaimRowVersion: b.Claim.RowVersion, DeadlineAt: b.Deadline}
		if e := s.Authority.Check(ctx, a); e != nil {
			return s.PrepareCapture(ctx, b)
		}
	}
	tx, err := s.Queue.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	in, err := b.ExecutionInput(ctx, tx)
	if err != nil {
		return nil, err
	}
	// The old plan format is retained as history, never dispatched by this runner.
	// Missing new plan with any external action needs reconciliation, not Prepare.
	var old, effects int
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM system_backup_v2_execution_plans WHERE origin_installation_id=? AND task_public_id=?),
 (SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE target_type='backup' AND target_public_id=?) + (SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?)`, b.InstallationID, b.Claim.Target.PublicID, b.Claim.Target.PublicID, b.Claim.Target.PublicID).Scan(&old, &effects) != nil || old != 0 || effects != 0 {
		return nil, ErrExecutionRecoveryRequired
	}
	guard, err := s.Authority.Bind(ctx, tx, in.Authority)
	if err != nil {
		return nil, err
	}
	if err = guard.Recheck(ctx, tx); err != nil {
		return nil, err
	}
	return &ExecutionWork{Step: ExecutionPrepare, Input: in}, nil
}

func (s *SQLExecutionWorkStore) Record(ctx context.Context, w ExecutionWork, out ExecutionOutcome) error {
	if err := s.Ready(ctx); err != nil {
		return err
	}
	if w.Step != ExecutionPrepare {
		return s.recordCapture(ctx, w, out)
	}
	if out.Err == nil && !executionPlanValid(out.Plan) {
		return ErrExecutionRecord
	}
	tx, err := s.Queue.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	guard, err := s.Authority.Bind(ctx, tx, w.Input.Authority)
	if err != nil {
		return err
	}
	if out.Err == nil {
		var digest string
		if tx.QueryRowContext(ctx, "SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan' FOR SHARE", w.Input.Authority.InstallationID, w.Input.Authority.TaskPublicID, w.Input.Authority.AttemptNo).Scan(&digest) != nil || digest != out.Plan.SHA256 {
			return ErrExecutionRecord
		}
	}
	if err = guard.Recheck(ctx, tx); err != nil {
		return err
	}
	status := "ready_for_capture"
	category := "none"
	var finished any
	if out.Err != nil {
		status = "failed"
		category = "runner_failed"
		var failedAt time.Time
		if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&failedAt) != nil {
			return ErrClaimLost
		}
		finished = failedAt
	}
	a := w.Input.Authority
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status=?,failure_category=?,finished_at=?,can_cancel=?,controller_owner=NULL,controller_lease_expires_at=NULL,next_reconcile_at=TIMESTAMPADD(SECOND,1,UTC_TIMESTAMP(6)),row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND status='preparing' AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6)`, status, category, finished, out.Err == nil, a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion)
	if ok, e := exactlyOneRow(result); err != nil || e != nil || !ok {
		return ErrClaimLost
	}
	if out.Err != nil {
		r, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_attempts SET status='failed',failure_category='runner_failed',started_at=COALESCE(started_at,?),finished_at=?,row_version=row_version+1 WHERE target_type='backup' AND target_public_id=? AND attempt_no=? AND phase IN ('capture','secret_capture') AND status='preparing'", finished, finished, a.TaskPublicID, a.AttemptNo)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		expected := int64(1)
		for _, part := range w.Input.Backup.RequestedParts {
			if part == "secret_bundle" {
				expected = 2
			}
		}
		if e != nil || n != expected {
			return ErrExecutionRecord
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) VALUES(?,'backup',?,'task_status_changed','info',?,'Preparation outcome persisted.',?)", a.InstallationID, a.TaskPublicID, status, a.RequestID); err != nil {
		return err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(guard.ValidUntil()) {
		return ErrClaimLost
	}
	if err = tx.Commit(); err != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}
func (s *SQLExecutionWorkStore) recordCapture(ctx context.Context, w ExecutionWork, out ExecutionOutcome) error {
	if s.FinishCapture != nil {
		return s.FinishCapture(ctx, w, out)
	}
	return ErrExecutionRecoveryRequired
}

var _ ExecutionWorkStore = (*SQLExecutionWorkStore)(nil)
