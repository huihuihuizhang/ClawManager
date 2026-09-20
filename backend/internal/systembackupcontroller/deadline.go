package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

var ErrDeadlineTransitionRejected = errors.New("system backup pending deadline transition rejected")

// Transaction is intentionally narrower than a database session. Requiring
// commit and rollback keeps the terminal row update and its redacted event in
// one caller-supplied *sql.Tx; a plain *sql.DB cannot be passed accidentally.
type Transaction interface {
	Executor
	Commit() error
	Rollback() error
}

type deadlineDescriptor struct {
	updateSQL     string
	eventSQL      string
	acceptanceSQL string
}

func deadlineSQL(descriptor targetDescriptor, kind TargetKind) (deadlineDescriptor, error) {
	var updateAssignments string
	var noSideEffectGuard string
	var eventTargetType string
	var eventType string
	var eventTaskStatus string
	var eventMessage string
	var requestIDExpression string

	switch kind {
	case TargetBackup, TargetDrill, TargetPreflight, TargetArtifactVerify:
		updateAssignments = fmt.Sprintf(
			"status = 'failed', pending_reason = 'none', attention_reason = 'none', can_cancel = FALSE, retryable = TRUE, failure_category = 'deadline_exceeded', failure_message = NULL, %s = UTC_TIMESTAMP(6), %s = NULL, %s = NULL, next_reconcile_at = NULL, started_at = COALESCE(started_at, UTC_TIMESTAMP(6)), finished_at = UTC_TIMESTAMP(6), row_version = row_version + 1",
			descriptor.heartbeat,
			descriptor.ownerColumn,
			descriptor.leaseColumn,
		)
		noSideEffectGuard = fmt.Sprintf(
			"NOT EXISTS (SELECT 1 FROM system_backup_attempts AS attempt WHERE attempt.target_type = '%s' AND attempt.target_public_id = %s.public_id)",
			kind,
			descriptor.table,
		)
		if kind == TargetBackup {
			noSideEffectGuard += " AND NOT EXISTS (SELECT 1 FROM system_backup_external_actions AS action WHERE action.target_type = 'backup' AND action.target_public_id = system_backups.public_id)"
		} else {
			noSideEffectGuard += fmt.Sprintf(
				" AND NOT EXISTS (SELECT 1 FROM system_artifact_leases AS artifact_lease WHERE artifact_lease.holder_type = '%s' AND artifact_lease.holder_public_id = %s.public_id)",
				kind,
				descriptor.table,
			)
		}
		eventTargetType = string(kind)
		eventType = "task_status_changed"
		eventTaskStatus = "'failed'"
		eventMessage = "Task deadline elapsed before execution."
		requestIDExpression = "request_id"
	default:
		return deadlineDescriptor{}, fmt.Errorf("unsupported pending deadline target kind %q", kind)
	}

	updateSQL := fmt.Sprintf(
		"UPDATE %s SET %s WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'pending' AND %s = ? AND %s > UTC_TIMESTAMP(6) AND deadline_at <= UTC_TIMESTAMP(6) AND %s",
		descriptor.table,
		updateAssignments,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		noSideEffectGuard,
	)
	eventSQL := fmt.Sprintf(
		"INSERT INTO system_backup_events (origin_installation_id, target_type, target_public_id, event_type, level, task_status, message, details_present, detail_previous_status, detail_current_status, detail_reason, request_id) SELECT origin_installation_id, '%s', public_id, '%s', 'error', %s, '%s', TRUE, 'pending', 'failed', 'deadline_exceeded', %s FROM %s WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'failed'",
		eventTargetType,
		eventType,
		eventTaskStatus,
		eventMessage,
		requestIDExpression,
		descriptor.table,
	)
	var acceptanceSQL string
	if kind == TargetBackup || kind == TargetDrill {
		// The successful terminal CAS above locks this task row. INSERT SELECT
		// therefore observes its immutable purpose/config in the same transaction;
		// functional-test rows select nothing. A duplicate state row advances once
		// only because this statement runs after the one-row pending CAS.
		acceptanceSQL = fmt.Sprintf(`INSERT INTO system_backup_alert_states
  (origin_installation_id, rule_key, matrix_key, task_type, task_purpose,
   consecutive_anomaly_count, first_anomaly_at, last_observed_at, config_version)
SELECT incoming.origin_installation_id, ?, 'all', '%s', 'acceptance',
  1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), incoming.config_version
FROM (
  SELECT origin_installation_id, config_version FROM %s
  WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'failed' AND task_purpose = 'acceptance'
) AS incoming
WHERE ?
ON DUPLICATE KEY UPDATE
  first_anomaly_at = IF(consecutive_anomaly_count = 0,
    GREATEST(COALESCE(last_observed_at, UTC_TIMESTAMP(6)), UTC_TIMESTAMP(6)), first_anomaly_at),
  last_observed_at = GREATEST(COALESCE(last_observed_at, UTC_TIMESTAMP(6)), UTC_TIMESTAMP(6)),
  consecutive_anomaly_count = LEAST(consecutive_anomaly_count + 1, 4294967295),
  config_version = incoming.config_version, row_version = row_version + 1`, kind, descriptor.table)
	}
	return deadlineDescriptor{updateSQL: updateSQL, eventSQL: eventSQL, acceptanceSQL: acceptanceSQL}, nil
}

// ExpirePendingClaim performs the only owner-independent deadline transition:
// a claimed task that is still pending, is already past its database deadline,
// and has no attempt, external-action, or artifact-lease evidence is failed
// atomically with a redacted event. Generic operations are deliberately
// excluded because their authoritative detail ledgers require operation-type
// specific transactions. This function never invokes an A/B/C component.
func ExpirePendingClaim(ctx context.Context, tx Transaction, installationID string, token ClaimToken) (uint64, error) {
	if tx == nil {
		return 0, errors.New("nil system backup deadline transaction")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if !installationIDPattern.MatchString(installationID) {
		return 0, errors.New("invalid system backup deadline installation ID")
	}

	descriptor, err := validateMutation(ctx, tx, token.Target, token.Owner, token.RowVersion)
	if err != nil {
		return 0, err
	}
	statements, err := deadlineSQL(descriptor, token.Target.Kind)
	if err != nil {
		return 0, err
	}

	result, err := tx.ExecContext(ctx, statements.updateSQL, installationID, token.Target.PublicID, token.RowVersion, token.Owner)
	if err != nil {
		return 0, fmt.Errorf("expire pending %s claim: %w", token.Target.Kind, err)
	}
	updated, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !updated {
		return 0, ErrDeadlineTransitionRejected
	}

	newRowVersion := token.RowVersion + 1
	result, err = tx.ExecContext(ctx, statements.eventSQL, installationID, token.Target.PublicID, newRowVersion)
	if err != nil {
		return 0, fmt.Errorf("record pending %s deadline event: %w", token.Target.Kind, err)
	}
	eventInserted, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !eventInserted {
		return 0, errors.New("pending deadline transition did not produce exactly one event")
	}
	if statements.acceptanceSQL != "" {
		result, err = tx.ExecContext(ctx, statements.acceptanceSQL, acceptanceAnomalyStateKey, installationID, token.Target.PublicID, newRowVersion, true)
		if err != nil {
			return 0, fmt.Errorf("record pending %s acceptance deadline anomaly: %w", token.Target.Kind, err)
		}
		if result == nil {
			return 0, errors.New("nil acceptance deadline anomaly result")
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read acceptance deadline anomaly result: %w", err)
		}
		if affected < 0 || affected > 2 {
			return 0, fmt.Errorf("invalid acceptance deadline anomaly affected rows %d", affected)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit pending %s deadline transition: %w", token.Target.Kind, err)
	}
	committed = true
	return newRowVersion, nil
}
