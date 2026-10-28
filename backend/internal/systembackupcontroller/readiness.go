package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type utcClockQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// SQLUTCReadinessProbe requires the controller's database session clock to
// agree with UTC before DATETIME(6) task deadlines or queue ages are read.
// It is read-only; the application writer's own session still needs a
// separate UTC admission check before backup is enabled.
type SQLUTCReadinessProbe struct {
	DB utcClockQueryer
}

func (p SQLUTCReadinessProbe) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.DB == nil {
		return errors.New("nil system backup UTC readiness database")
	}
	var offsetMicros int64
	if err := p.DB.QueryRowContext(ctx, `SELECT TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), CURRENT_TIMESTAMP(6))`).Scan(&offsetMicros); err != nil {
		return fmt.Errorf("probe database UTC session clock: %w", err)
	}
	if offsetMicros != 0 {
		return fmt.Errorf("database session clock differs from UTC by %d microseconds", offsetMicros)
	}
	return nil
}

// ReadinessProbe verifies a dependency needed by every controller replica.
// It must not require leadership or mutate business state.
type ReadinessProbe interface {
	Check(context.Context) error
}

// SQLClaimReadinessProbe executes zero-row, claim-shaped UPDATE statements.
// Unlike SELECT or EXPLAIN, execution proves that the controller identity has
// UPDATE permission and that the exact claim columns exist, while WHERE 1=0
// guarantees that no task, operation, lease, timestamp or row version changes.
type SQLClaimReadinessProbe struct {
	DB Executor
}

func (p SQLClaimReadinessProbe) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.DB == nil {
		return errors.New("nil system backup claim readiness database")
	}
	for _, kind := range []TargetKind{TargetBackup, TargetDrill, TargetPreflight, TargetArtifactVerify, TargetOperation} {
		descriptor, ok := targetDescriptors[kind]
		if !ok {
			return fmt.Errorf("missing system backup claim descriptor for %s", kind)
		}
		query := fmt.Sprintf(
			"UPDATE %s SET %s = %s, %s = %s, row_version = row_version WHERE 1 = 0",
			descriptor.table,
			descriptor.ownerColumn,
			descriptor.ownerColumn,
			descriptor.leaseColumn,
			descriptor.leaseColumn,
		)
		if _, err := p.DB.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("probe %s claim statement: %w", kind, err)
		}
	}
	return nil
}

// SQLDeadlineAlertReadinessProbe exercises the exact acceptance deadline
// INSERT/UPSERT shape with its outer row predicate bound false. It validates
// the alert table and required SELECT/INSERT/UPDATE grants without inserting
// or modifying a row, even if a task with the probe ID somehow exists.
type SQLDeadlineAlertReadinessProbe struct {
	DB Executor
}

func (p SQLDeadlineAlertReadinessProbe) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.DB == nil {
		return errors.New("nil system backup deadline alert readiness database")
	}
	for _, kind := range []TargetKind{TargetBackup, TargetDrill} {
		descriptor, ok := targetDescriptors[kind]
		if !ok {
			return fmt.Errorf("missing system backup deadline alert descriptor for %s", kind)
		}
		statements, err := deadlineSQL(descriptor, kind)
		if err != nil {
			return fmt.Errorf("build %s deadline alert probe: %w", kind, err)
		}
		if statements.acceptanceSQL == "" {
			return fmt.Errorf("missing %s deadline alert probe statement", kind)
		}
		result, err := p.DB.ExecContext(ctx, statements.acceptanceSQL,
			acceptanceAnomalyStateKey, "installation_readiness_probe", "__readiness_probe__", uint64(0), false)
		if err != nil {
			return fmt.Errorf("probe %s deadline alert statement: %w", kind, err)
		}
		if result == nil {
			return fmt.Errorf("nil %s deadline alert probe result", kind)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read %s deadline alert probe result: %w", kind, err)
		}
		if affected != 0 {
			return fmt.Errorf("%s deadline alert probe unexpectedly affected %d rows", kind, affected)
		}
	}
	return nil
}

type ReadinessProbeFunc func(context.Context) error

func (f ReadinessProbeFunc) Check(ctx context.Context) error {
	if f == nil {
		return errors.New("nil system backup readiness probe function")
	}
	return f(ctx)
}

type ReadinessProbeSet []ReadinessProbe

func (p ReadinessProbeSet) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(p) == 0 {
		return errors.New("empty system backup readiness probe set")
	}
	for index, probe := range p {
		if probe == nil {
			return fmt.Errorf("nil system backup readiness probe at index %d", index)
		}
		if err := probe.Check(ctx); err != nil {
			return fmt.Errorf("system backup readiness probe %d: %w", index, err)
		}
	}
	return nil
}
