package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// TaskClaimAcquiredEvent is the D-owned common task-claim receipt protocol.
// It records a claim CAS, not B execution, attempt creation, or Job dispatch.
// B integration must consume this same task ledger/entry point; owner approval
// of B's adapter and its execution protocol remains a separate delivery.
const TaskClaimAcquiredEvent = "diagnostic.d.task_claim_acquired"

var (
	ErrTaskClaimReceipt       = errors.New("system backup task claim receipt unavailable")
	ErrTaskClaimCommitUnknown = errors.New("system backup task claim commit outcome unknown")
)

// SQLTaskClaimStore owns the only transaction for a task claim and its durable
// receipt. InstallationID comes from the admitted controller deployment, never
// task request JSON. This primitive does not grant execution authority or
// replace the original readiness, kill-switch, deadline, or action guards.
type SQLTaskClaimStore struct {
	DB             *sql.DB
	InstallationID string
}

type taskClaimSnapshot struct {
	schema, installation, publicID, kind, requestID, status, owner string
	until, heartbeat, now                                          time.Time
	version                                                        uint64
}

// Internal receipt observations, not an authorization token. Start initializes
// ObservedAt with its preceding SQL clock; the stage preserves that floor.
type stagedTaskClaimReceipt struct {
	ID         int64
	ObservedAt time.Time
}

func claimSnapshot(ctx context.Context, tx *sql.Tx, table string, installation string, target Target) (taskClaimSnapshot, error) {
	var s taskClaimSnapshot
	query := "SELECT schema_version,origin_installation_id,public_id,task_type,request_id,status,controller_owner,controller_lease_expires_at,row_version,heartbeat_at,UTC_TIMESTAMP(6) FROM " + table + " WHERE origin_installation_id=? AND public_id=? FOR UPDATE"
	err := tx.QueryRowContext(ctx, query, installation, target.PublicID).Scan(&s.schema, &s.installation, &s.publicID, &s.kind, &s.requestID, &s.status, &s.owner, &s.until, &s.version, &s.heartbeat, &s.now)
	if err != nil {
		return taskClaimSnapshot{}, ErrTaskClaimReceipt
	}
	return s, nil
}

func (s taskClaimSnapshot) valid(installation string, token ClaimToken, policy LeasePolicy) bool {
	if s.schema != "system-backup-task.v1" || s.installation != installation || s.publicID != token.Target.PublicID || s.kind != string(token.Target.Kind) || !controllerOwnerPattern.MatchString(s.requestID) || s.owner != token.Owner || s.version != token.RowVersion || s.now.IsZero() || s.heartbeat.IsZero() || s.until.IsZero() || s.now.Before(s.heartbeat) || !s.now.Before(s.until) || !s.until.Equal(s.heartbeat.Add(policy.TTL)) {
		return false
	}
	statuses := "pending,running,canceling"
	switch token.Target.Kind {
	case TargetBackup:
		statuses = "pending,preparing,ready_for_capture,acquiring_gate,capturing,validating,publishing,finalization_unknown,canceling"
	case TargetDrill:
		statuses = "pending,preflighting,provisioning,restoring,normalizing,verifying,canceling"
	case TargetPreflight, TargetArtifactVerify:
	default:
		return false
	}
	for _, status := range strings.Split(statuses, ",") {
		if s.status == status {
			return true
		}
	}
	return false
}

// AcquireWithReceipt performs the existing database-time CAS, reads its locked
// task identity/original request ID, inserts a fixed redacted receipt, then
// rechecks the exact owner/version/lease and monotonic database clock before
// the unique commit. Operation claims are deliberately excluded.
//
// A failed or ambiguous commit never returns a token and is never retried here.
// Callers must independently reload durable state; they may not turn this error
// into an execution lease or blindly issue another claim with a fresh version.
func (s SQLTaskClaimStore) AcquireWithReceipt(ctx context.Context, target Target, owner string, expectedRowVersion uint64, policy LeasePolicy) (ClaimToken, error) {
	var zero ClaimToken
	if absentExecutionDependency(ctx) || s.DB == nil || !installationIDPattern.MatchString(s.InstallationID) || target.Kind == TargetOperation || expectedRowVersion == ^uint64(0) {
		return zero, ErrTaskClaimReceipt
	}
	descriptor, err := validateMutation(ctx, s.DB, target, owner, expectedRowVersion)
	if err != nil {
		return zero, err
	}
	if err = policy.Validate(); err != nil {
		return zero, err
	}
	// This bound does not renew the SQL lease. Its original database until is
	// independently checked after the final statement and before commit.
	ctx, cancel := context.WithTimeout(ctx, policy.TTL)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrTaskClaimReceipt
	}
	defer tx.Rollback()
	token, err := stageTaskClaimWithReceipt(ctx, tx, s.InstallationID, target, owner, expectedRowVersion, policy, descriptor, nil)
	if err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, ErrTaskClaimCommitUnknown
	}
	return token, nil
}

// stageTaskClaimWithReceipt joins a D-owned transaction; it NEVER commits.
// The caller must preserve the original lease and perform its final SQL check
// after any additional state/attempt writes. This lets execution start share
// exactly the same CAS/receipt protocol as the pending deadline caller.
func stageTaskClaimWithReceipt(ctx context.Context, tx *sql.Tx, installation string, target Target, owner string, expectedRowVersion uint64, policy LeasePolicy, descriptor targetDescriptor, receipt *stagedTaskClaimReceipt) (ClaimToken, error) {
	var zero ClaimToken
	token, err := AcquireClaimInInstallation(ctx, tx, installation, target, owner, expectedRowVersion, policy)
	if err != nil {
		return zero, err
	}
	first, err := claimSnapshot(ctx, tx, descriptor.table, installation, target)
	if err != nil || !first.valid(installation, token, policy) {
		return zero, ErrTaskClaimReceipt
	}
	if receipt != nil && (first.now.Before(receipt.ObservedAt) || first.heartbeat.Before(receipt.ObservedAt)) {
		return zero, ErrTaskClaimReceipt
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events (origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,request_id,created_at) VALUES (?,?,?,?,'info',?,'Controller acquired task claim.',FALSE,?,UTC_TIMESTAMP(6))", installation, string(target.Kind), target.PublicID, TaskClaimAcquiredEvent, first.status, first.requestID)
	if err != nil {
		return zero, ErrTaskClaimReceipt
	}
	one, err := exactlyOneRow(result)
	if err != nil || !one {
		return zero, ErrTaskClaimReceipt
	}
	if receipt != nil {
		id, idErr := result.LastInsertId()
		if idErr != nil || id < 1 {
			return zero, ErrTaskClaimReceipt
		}
		receipt.ID = id
	}
	last, err := claimSnapshot(ctx, tx, descriptor.table, installation, target)
	if err != nil || !last.valid(installation, token, policy) || last.schema != first.schema || last.installation != first.installation || last.publicID != first.publicID || last.kind != first.kind || last.requestID != first.requestID || last.status != first.status || last.owner != first.owner || last.version != first.version || !last.until.Equal(first.until) || !last.heartbeat.Equal(first.heartbeat) || last.now.Before(first.now) || ctx.Err() != nil {
		return zero, ErrTaskClaimReceipt
	}
	if receipt != nil {
		receipt.ObservedAt = last.now
	}
	return token, nil
}
