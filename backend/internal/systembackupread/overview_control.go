package systembackupread

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OverviewInstallationState contains persisted controller state, not a fresh
// evaluation of deployment switches. In particular LastEffectiveEnabled must
// not be treated as current effective_enabled without the deployment adapter.
type OverviewInstallationState struct {
	InstallationID       string
	ConfigVersion        uint64
	StateRowVersion      uint64
	ConfigRowVersion     uint64
	ConfigEnabled        bool
	FirstEnabledAt       sql.NullTime
	LastEffectiveEnabled bool
	MonitoringArmed      bool
	MonitoringReason     string
	MatrixKey            string
	ObservedAt           time.Time
}

func (OverviewInstallationState) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// OverviewControlSnapshot is only the D-owned control-table contribution to
// an overview. It has no aggregate active_task_count: catalog/import/prune
// facts, health, baseline, cleanup and failure-domain sources are still needed.
// It deliberately cannot be serialized as a public OverviewResource.
type OverviewControlSnapshot struct {
	state      OverviewInstallationState
	tasks      map[TaskKind]map[string]uint64
	operations map[string]uint64
}

func (OverviewControlSnapshot) MarshalJSON() ([]byte, error)                   { return nil, ErrInvalid }
func (s OverviewControlSnapshot) InstallationState() OverviewInstallationState { return s.state }

// The accessors return copies so a later builder cannot mutate a held snapshot
// through its returned status maps.
func (s OverviewControlSnapshot) TaskStatusCounts(kind TaskKind) map[string]uint64 {
	return copyOverviewCounts(s.tasks[kind])
}
func (s OverviewControlSnapshot) OperationStatusCounts() map[string]uint64 {
	return copyOverviewCounts(s.operations)
}
func copyOverviewCounts(source map[string]uint64) map[string]uint64 {
	if source == nil {
		return nil
	}
	result := make(map[string]uint64, len(source))
	for status, count := range source {
		result[status] = count
	}
	return result
}

// Only read methods are exposed to a future owner builder. The wrapper's dynamic
// type does not expose *sql.Tx, Exec, Commit or Rollback by type assertion.
type overviewReadSQL interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type overviewReadTx struct{ tx *sql.Tx }

func (q overviewReadTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return q.tx.QueryContext(ctx, query, args...)
}
func (q overviewReadTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return q.tx.QueryRowContext(ctx, query, args...)
}

// Future complete overview builders use this same transaction boundary, not a
// separately committed ReadOverviewControl result. RepeatableRead holds one
// snapshot for all status contributions; the production authorizer's locking
// current reads and final recheck retain current authority through Commit.
func readOverviewInTransaction[T any](ctx context.Context, r *Reader,
	build func(context.Context, overviewReadSQL, OverviewControlSnapshot) (T, error)) (T, error) {
	var zero T
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return zero, ErrDenied
	}
	if build == nil {
		return zero, ErrUnavailable
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return zero, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return zero, ErrDenied
	}
	q := overviewReadTx{tx}
	control, err := readOverviewControl(ctx, q, installation)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return zero, ErrUnavailable
	}
	var result T
	if !missing {
		result, err = build(ctx, q, control)
		if err != nil {
			return zero, ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	if err = r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return zero, scopeReadFailure(err)
	}
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	if missing {
		return zero, ErrUnavailable
	}
	return result, nil
}

func (r *Reader) ReadOverviewControl(ctx context.Context) (OverviewControlSnapshot, error) {
	return readOverviewInTransaction(ctx, r, func(_ context.Context, _ overviewReadSQL, control OverviewControlSnapshot) (OverviewControlSnapshot, error) {
		return control, nil
	})
}

const overviewInstallationSQL = `SELECT s.schema_version,s.origin_installation_id,s.active_config_version,s.row_version,
s.first_enabled_at,s.last_effective_enabled,s.monitoring_armed,s.monitoring_armed_reason,s.matrix_key,
c.schema_version,c.origin_installation_id,c.version,c.row_version,c.enabled,
UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))
FROM system_backup_v2_installation_state AS s
JOIN system_backup_v2_configs AS c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
WHERE s.origin_installation_id=? FOR SHARE`

// All four task contributions are read by one statement, at the same
// transaction snapshot as operations. No raw config, failure text or evidence
// payload is selected. Empty tables are initialized to explicit zero counts.
const overviewTaskCountsSQL = `SELECT 'backup',schema_version,task_type,status,COUNT(*) FROM system_backup_v2_backups WHERE origin_installation_id=? GROUP BY schema_version,task_type,status
UNION ALL SELECT 'drill',schema_version,task_type,status,COUNT(*) FROM system_backup_v2_restore_drills WHERE origin_installation_id=? GROUP BY schema_version,task_type,status
UNION ALL SELECT 'preflight',schema_version,task_type,status,COUNT(*) FROM system_backup_v2_preflights WHERE origin_installation_id=? GROUP BY schema_version,task_type,status
UNION ALL SELECT 'artifact_verify',schema_version,task_type,status,COUNT(*) FROM system_backup_v2_artifact_verifications WHERE origin_installation_id=? GROUP BY schema_version,task_type,status`
const overviewOperationCountsSQL = `SELECT schema_version,status,COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? GROUP BY schema_version,status`

func readOverviewControl(ctx context.Context, q overviewReadSQL, installation string) (OverviewControlSnapshot, error) {
	var zero OverviewControlSnapshot
	var s OverviewInstallationState
	var stateSchema, configSchema, configInstallation string
	var configVersion uint64
	var clockOffset int64
	err := q.QueryRowContext(ctx, overviewInstallationSQL, installation).Scan(
		&stateSchema, &s.InstallationID, &s.ConfigVersion, &s.StateRowVersion, &s.FirstEnabledAt,
		&s.LastEffectiveEnabled, &s.MonitoringArmed, &s.MonitoringReason, &s.MatrixKey,
		&configSchema, &configInstallation, &configVersion, &s.ConfigRowVersion, &s.ConfigEnabled, &s.ObservedAt, &clockOffset)
	if err != nil {
		return zero, err
	}
	if stateSchema != "system-backup-installation-state.v1" || configSchema != "system-backup-config.v1" ||
		s.InstallationID != installation || configInstallation != installation || configVersion != s.ConfigVersion ||
		s.ConfigVersion == 0 || s.ConfigVersion > maxJSONSafeInteger || s.StateRowVersion == 0 || s.StateRowVersion > maxJSONSafeInteger ||
		s.ConfigRowVersion == 0 || s.ConfigRowVersion > maxJSONSafeInteger || s.ObservedAt.IsZero() || clockOffset != 0 ||
		s.LastEffectiveEnabled && !s.ConfigEnabled || !validOverviewMonitoring(s) {
		return zero, ErrUnavailable
	}
	switch s.MatrixKey {
	case "k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node":
	default:
		return zero, ErrUnavailable
	}
	s.ObservedAt = s.ObservedAt.UTC()
	result := OverviewControlSnapshot{state: s, tasks: make(map[TaskKind]map[string]uint64), operations: make(map[string]uint64)}
	for kind, table := range taskTables {
		result.tasks[kind] = make(map[string]uint64, len(table.status))
		for status := range table.status {
			result.tasks[kind][status] = 0
		}
	}
	for status := range operationStatuses {
		result.operations[status] = 0
	}
	rows, err := q.QueryContext(ctx, overviewTaskCountsSQL, installation, installation, installation, installation)
	if err != nil {
		return zero, ErrUnavailable
	}
	seen := make(map[TaskKind]map[string]bool)
	totals := make(map[TaskKind]uint64)
	for rows.Next() {
		var kind TaskKind
		var schemaVersion, storedKind, status string
		var count uint64
		if err = rows.Scan(&kind, &schemaVersion, &storedKind, &status, &count); err != nil {
			rows.Close()
			return zero, ErrUnavailable
		}
		table, ok := taskTables[kind]
		if !ok || schemaVersion != "system-backup-task.v1" || storedKind != string(kind) || !table.status[status] || count == 0 || count > maxJSONSafeInteger || totals[kind] > maxJSONSafeInteger-count || seen[kind][status] {
			rows.Close()
			return zero, ErrUnavailable
		}
		if seen[kind] == nil {
			seen[kind] = make(map[string]bool)
		}
		seen[kind][status] = true
		totals[kind] += count
		result.tasks[kind][status] = count
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return zero, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	rows, err = q.QueryContext(ctx, overviewOperationCountsSQL, installation)
	if err != nil {
		return zero, ErrUnavailable
	}
	seenOperations := make(map[string]bool)
	var total uint64
	for rows.Next() {
		var schemaVersion, status string
		var count uint64
		if err = rows.Scan(&schemaVersion, &status, &count); err != nil {
			rows.Close()
			return zero, ErrUnavailable
		}
		if schemaVersion != "system-backup-operation.v1" || !operationStatuses[status] || count == 0 || count > maxJSONSafeInteger || total > maxJSONSafeInteger-count || seenOperations[status] {
			rows.Close()
			return zero, ErrUnavailable
		}
		seenOperations[status] = true
		total += count
		result.operations[status] = count
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return zero, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	return result, nil
}

func validOverviewMonitoring(s OverviewInstallationState) bool {
	if s.FirstEnabledAt.Valid && (s.FirstEnabledAt.Time.IsZero() || s.FirstEnabledAt.Time.After(s.ObservedAt)) {
		return false
	}
	if !s.MonitoringArmed {
		return s.MonitoringReason == "none" && !s.FirstEnabledAt.Valid && !s.LastEffectiveEnabled
	}
	switch s.MonitoringReason {
	case "deployment_required":
		return !s.LastEffectiveEnabled || s.FirstEnabledAt.Valid
	case "previously_enabled":
		return s.FirstEnabledAt.Valid
	default:
		return false
	}
}
