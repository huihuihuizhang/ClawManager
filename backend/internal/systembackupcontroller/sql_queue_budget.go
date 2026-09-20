package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"clawreef/internal/systembackupcontract"
)

const MaxQueueBudgetRows = 10000

type QueueBudgetMetricSample struct {
	MetricName        string
	TaskType          string
	TaskPurpose       string
	PreflightMode     string
	VerificationScope string
	OperationType     string
	Value             float64
}

type SQLQueueBudgetReader struct {
	DB *sql.DB
}

// Collect reads only D-owned pending task/operation timing and emits the
// complete bounded label set, including zero samples for empty groups. It
// never reads public IDs or owner payloads, and never publishes partial data.
func (r SQLQueueBudgetReader) Collect(ctx context.Context, installationID string) ([]QueueBudgetMetricSample, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.DB == nil {
		return nil, errors.New("nil queue budget database")
	}
	if !installationIDPattern.MatchString(installationID) {
		return nil, errors.New("invalid queue budget installation ID")
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("begin queue budget snapshot: %w", err)
	}
	defer tx.Rollback()
	var databaseNow time.Time
	var offsetMicros int64
	if err := tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6), TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), CURRENT_TIMESTAMP(6))`).Scan(&databaseNow, &offsetMicros); err != nil {
		return nil, fmt.Errorf("read queue budget database clock: %w", err)
	}
	if databaseNow.IsZero() || offsetMicros != 0 {
		return nil, fmt.Errorf("queue budget database clock is not UTC (offset=%d microseconds)", offsetMicros)
	}

	taskRatios := make(map[string]float64, 4)
	for _, taskType := range []string{"backup", "drill"} {
		for _, purpose := range []string{"acceptance", "functional_test"} {
			taskRatios[taskType+":"+purpose] = 0
		}
	}
	operationRatios := make(map[string]float64, len(systembackupcontract.OperationTypes))
	for _, operationType := range systembackupcontract.OperationTypes {
		operationRatios[operationType] = 0
	}
	if len(operationRatios) != len(systembackupcontract.OperationTypes) {
		return nil, errors.New("duplicate queue budget operation type in contract snapshot")
	}
	preflightRatios := map[string]float64{"production_readonly": 0, "functional_test": 0}
	verificationRatios := map[string]float64{"health": 0, "full": 0}
	remaining := MaxQueueBudgetRows
	for _, source := range []struct {
		table string
		kind  string
		label string
	}{
		{table: "system_backups", kind: "backup", label: "task_purpose"},
		{table: "system_restore_drills", kind: "drill", label: "task_purpose"},
		{table: "system_backup_preflights", kind: "preflight", label: "preflight_mode"},
		{table: "system_backup_artifact_verifications", kind: "artifact_verify", label: "verification_scope"},
		{table: "system_backup_operations", kind: "operation", label: "operation_type"},
	} {
		if err := collectQueueBudgetSource(ctx, tx, source.table, source.label, source.kind, installationID, databaseNow, &remaining, taskRatios, preflightRatios, verificationRatios, operationRatios); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit queue budget read-only snapshot: %w", err)
	}

	samples := make([]QueueBudgetMetricSample, 0, len(taskRatios)+len(preflightRatios)+len(verificationRatios)+len(operationRatios))
	for _, taskType := range []string{"backup", "drill"} {
		for _, purpose := range []string{"acceptance", "functional_test"} {
			samples = append(samples, QueueBudgetMetricSample{
				MetricName: "clawmanager_system_backup_task_queue_deadline_utilization_ratio",
				TaskType:   taskType, TaskPurpose: purpose, Value: taskRatios[taskType+":"+purpose],
			})
		}
	}
	for _, mode := range []string{"production_readonly", "functional_test"} {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName:    "clawmanager_system_backup_preflight_queue_deadline_utilization_ratio",
			PreflightMode: mode, Value: preflightRatios[mode],
		})
	}
	for _, scope := range []string{"health", "full"} {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName:        "clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio",
			VerificationScope: scope, Value: verificationRatios[scope],
		})
	}
	operationTypes := append([]string(nil), systembackupcontract.OperationTypes...)
	sort.Strings(operationTypes)
	for _, operationType := range operationTypes {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName:    "clawmanager_system_backup_operation_queue_deadline_utilization_ratio",
			OperationType: operationType, Value: operationRatios[operationType],
		})
	}
	return samples, nil
}

func collectQueueBudgetSource(ctx context.Context, tx *sql.Tx, table, labelColumn, kind, installationID string, databaseNow time.Time, remaining *int, taskRatios, preflightRatios, verificationRatios, operationRatios map[string]float64) error {
	// One extra row proves whether the remaining global budget was exceeded,
	// while bounding data returned by the database for every scrape.
	query := fmt.Sprintf("SELECT %s, created_at, deadline_at FROM %s WHERE origin_installation_id = ? AND status = 'pending' LIMIT %d", labelColumn, table, *remaining+1)
	rows, err := tx.QueryContext(ctx, query, installationID)
	if err != nil {
		return fmt.Errorf("query pending %s queue budget: %w", table, err)
	}
	for rows.Next() {
		*remaining = *remaining - 1
		if *remaining < 0 {
			_ = rows.Close()
			return fmt.Errorf("pending queue budget exceeds %d rows", MaxQueueBudgetRows)
		}
		var label string
		var item PendingQueueBudget
		if err := rows.Scan(&label, &item.CreatedAt, &item.DeadlineAt); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan pending %s queue budget: %w", table, err)
		}
		ratio, err := MaxPendingQueueDeadlineUtilization(databaseNow, []PendingQueueBudget{item})
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("evaluate pending %s queue budget: %w", table, err)
		}
		var group map[string]float64
		key := label
		switch kind {
		case "backup", "drill":
			group, key = taskRatios, kind+":"+label
		case "preflight":
			group = preflightRatios
		case "artifact_verify":
			group = verificationRatios
		case "operation":
			group = operationRatios
		default:
			_ = rows.Close()
			return fmt.Errorf("unknown queue budget source %s", kind)
		}
		current, ok := group[key]
		if !ok {
			_ = rows.Close()
			return fmt.Errorf("unknown %s queue budget label", table)
		}
		if ratio > current {
			group[key] = ratio
		}
	}
	return errors.Join(rows.Err(), rows.Close())
}
