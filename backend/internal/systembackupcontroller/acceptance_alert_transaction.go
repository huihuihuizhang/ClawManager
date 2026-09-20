package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

var ErrAcceptanceTerminalCASRejected = errors.New("acceptance terminal task CAS did not change exactly one row")

// AcceptanceTerminalMutation must perform only the D-owned task terminal CAS
// through the supplied transaction executor. The transaction boundary writes
// its own redacted event afterward. The callback must not do external work.
type AcceptanceTerminalMutation func(context.Context, Executor) (sql.Result, error)

// ApplyAcceptanceTerminalWithSequence owns the transaction so task terminal
// state and the low-cardinality sequence commit or roll back together. It
// locks the named task before the caller's CAS and verifies the same task's
// persisted terminal facts afterward; a one-row result for a different task
// cannot advance this sequence. It does not decide task eligibility or
// implement an A/B/C result adapter.
func ApplyAcceptanceTerminalWithSequence(
	ctx context.Context,
	db *sql.DB,
	installationID string,
	configVersion uint64,
	target Target,
	expectedRowVersion uint64,
	outcome AcceptanceTerminalOutcome,
	terminalCAS AcceptanceTerminalMutation,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if db == nil || terminalCAS == nil {
		return errors.New("acceptance terminal transaction requires database and CAS")
	}
	if !installationIDPattern.MatchString(installationID) || configVersion < 1 || expectedRowVersion < 1 || expectedRowVersion == math.MaxUint64 {
		return errors.New("invalid acceptance terminal installation or config version")
	}
	if err := validateAcceptanceTerminalOutcome(outcome); err != nil {
		return err
	}
	descriptor, err := target.descriptor()
	if err != nil || target.Kind != outcome.TaskType {
		return errors.New("invalid acceptance terminal task identity")
	}
	if !outcome.ObservedAt.IsZero() {
		return errors.New("acceptance terminal observation time must come from the database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin acceptance terminal transaction: %w", err)
	}
	defer tx.Rollback()
	var previousStatus string
	var previousVersion uint64
	preSQL := fmt.Sprintf("SELECT status, row_version FROM %s WHERE origin_installation_id = ? AND public_id = ? FOR UPDATE", descriptor.table)
	if err := tx.QueryRowContext(ctx, preSQL, installationID, target.PublicID).Scan(&previousStatus, &previousVersion); err != nil {
		return fmt.Errorf("lock acceptance terminal task: %w", err)
	}
	if previousVersion != expectedRowVersion || previousStatus == "succeeded" || previousStatus == "failed" || previousStatus == "canceled" {
		return ErrAcceptanceTerminalCASRejected
	}
	result, err := terminalCAS(ctx, tx)
	if err != nil {
		return fmt.Errorf("execute acceptance terminal CAS: %w", err)
	}
	if result == nil {
		return ErrAcceptanceTerminalCASRejected
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read acceptance terminal CAS result: %w", err)
	}
	if affected != 1 {
		return ErrAcceptanceTerminalCASRejected
	}
	var actualStatus, actualPurpose string
	var actualConfigVersion, actualRowVersion uint64
	var actualEligible bool
	var actualDecidedAt sql.NullTime
	postSQL := fmt.Sprintf("SELECT status, task_purpose, config_version, acceptance_eligible, eligibility_decided_at, row_version FROM %s WHERE origin_installation_id = ? AND public_id = ? FOR UPDATE", descriptor.table)
	if err := tx.QueryRowContext(ctx, postSQL, installationID, target.PublicID).Scan(
		&actualStatus, &actualPurpose, &actualConfigVersion, &actualEligible, &actualDecidedAt, &actualRowVersion,
	); err != nil {
		return fmt.Errorf("verify acceptance terminal task: %w", err)
	}
	if actualStatus != outcome.Status || actualPurpose != outcome.Purpose || actualConfigVersion != configVersion ||
		actualEligible != outcome.Eligible || actualDecidedAt.Valid != outcome.EligibilityDecided || actualRowVersion != expectedRowVersion+1 {
		return ErrAcceptanceTerminalCASRejected
	}
	eventSQL := fmt.Sprintf(`INSERT INTO system_backup_events
  (origin_installation_id, target_type, target_public_id, event_type, level,
   task_status, message, details_present, detail_previous_status,
   detail_current_status, detail_reason, request_id)
SELECT origin_installation_id, ?, public_id, 'task_status_changed',
  CASE WHEN status = 'failed' THEN 'error' ELSE 'info' END,
  status, 'Task reached terminal state.', TRUE, ?, status,
  CASE WHEN status IN ('failed', 'canceled') THEN failure_category ELSE NULL END,
  request_id
FROM %s
WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = ?`, descriptor.table)
	eventResult, err := tx.ExecContext(ctx, eventSQL, target.Kind, previousStatus, installationID, target.PublicID, actualRowVersion, outcome.Status)
	if err != nil {
		return fmt.Errorf("record acceptance terminal event: %w", err)
	}
	if eventResult == nil {
		return errors.New("acceptance terminal event returned nil result")
	}
	eventRows, err := eventResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("read acceptance terminal event result: %w", err)
	}
	if eventRows != 1 {
		return errors.New("acceptance terminal event did not insert exactly one row")
	}
	if outcome.Purpose == "acceptance" && outcome.Status != "canceled" {
		if err := updateAcceptanceSequenceInTx(ctx, tx, installationID, configVersion, outcome); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit acceptance terminal transaction: %w", err)
	}
	return nil
}

func updateAcceptanceSequenceInTx(ctx context.Context, tx *sql.Tx, installationID string, configVersion uint64, outcome AcceptanceTerminalOutcome) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO system_backup_alert_states
  (origin_installation_id, rule_key, matrix_key, task_type, task_purpose, config_version)
VALUES (?, ?, 'all', ?, 'acceptance', ?)
ON DUPLICATE KEY UPDATE id = id`, installationID, acceptanceAnomalyStateKey, outcome.TaskType, configVersion)
	if err != nil {
		return fmt.Errorf("ensure acceptance anomaly state: %w", err)
	}
	var id, rowVersion uint64
	var count uint32
	var first, last, success sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id, consecutive_anomaly_count, first_anomaly_at, last_observed_at,
  last_eligible_success_at, row_version
FROM system_backup_alert_states
WHERE origin_installation_id = ? AND rule_key = ? AND matrix_key = 'all'
  AND task_type = ? AND task_purpose = 'acceptance'
FOR UPDATE`, installationID, acceptanceAnomalyStateKey, outcome.TaskType).Scan(&id, &count, &first, &last, &success, &rowVersion)
	if err != nil {
		return fmt.Errorf("lock acceptance anomaly state: %w", err)
	}
	if id < 1 || rowVersion < 1 {
		return errors.New("invalid acceptance anomaly row identity or version")
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbNow); err != nil {
		return fmt.Errorf("read acceptance anomaly database time: %w", err)
	}
	if dbNow.IsZero() {
		return errors.New("empty acceptance anomaly database time")
	}
	outcome.ObservedAt = dbNow.UTC()
	previous := AcceptanceAlertSequence{Count: count, FirstAnomalyAt: nullTimePointer(first), LastObservedAt: nullTimePointer(last), LastEligibleSuccessAt: nullTimePointer(success)}
	next, changed, err := AdvanceAcceptanceAlertSequence(previous, outcome)
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("acceptance terminal sequence unexpectedly unchanged")
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_alert_states
SET consecutive_anomaly_count = ?, first_anomaly_at = ?, last_observed_at = ?,
  last_eligible_success_at = ?, config_version = ?, row_version = row_version + 1
WHERE id = ? AND origin_installation_id = ? AND row_version = ?`,
		next.Count, nullableTimeArg(next.FirstAnomalyAt), nullableTimeArg(next.LastObservedAt),
		nullableTimeArg(next.LastEligibleSuccessAt), configVersion, id, installationID, rowVersion)
	if err != nil {
		return fmt.Errorf("update acceptance anomaly sequence: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read acceptance anomaly update result: %w", err)
	}
	if updated != 1 {
		return errors.New("acceptance anomaly sequence CAS lost")
	}
	return nil
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}

func nullableTimeArg(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}
