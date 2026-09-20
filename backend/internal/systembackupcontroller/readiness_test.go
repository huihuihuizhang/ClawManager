package systembackupcontroller

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSQLClaimReadinessProbeChecksAllClaimAuthoritiesWithoutMatchingRows(t *testing.T) {
	executor := &recordedExec{rows: 0}
	if err := (SQLClaimReadinessProbe{DB: executor}).Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(executor.queries) != 5 {
		t.Fatalf("queries=%d, want 5", len(executor.queries))
	}
	for _, query := range executor.queries {
		for _, required := range []string{"UPDATE system_", "row_version = row_version", "WHERE 1 = 0"} {
			if !strings.Contains(query, required) {
				t.Fatalf("readiness query missing %q: %s", required, query)
			}
		}
		for _, forbidden := range []string{"UTC_TIMESTAMP", "status =", "row_version +", "INSERT", "DELETE"} {
			if strings.Contains(query, forbidden) {
				t.Fatalf("readiness query contains %q: %s", forbidden, query)
			}
		}
	}
}

func TestSQLClaimReadinessProbeFailsClosed(t *testing.T) {
	if err := (SQLClaimReadinessProbe{}).Check(context.Background()); err == nil {
		t.Fatal("nil database accepted")
	}
	executor := &recordedExec{err: errors.New("update denied")}
	if err := (SQLClaimReadinessProbe{DB: executor}).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "backup") {
		t.Fatalf("permission error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	executor = &recordedExec{}
	if err := (SQLClaimReadinessProbe{DB: executor}).Check(ctx); !errors.Is(err, context.Canceled) || len(executor.queries) != 0 {
		t.Fatalf("canceled error=%v queries=%#v", err, executor.queries)
	}
}

func TestSQLDeadlineAlertReadinessProbeUsesActualSQLWithFalseWriteGuard(t *testing.T) {
	executor := &recordedExec{rows: 0}
	if err := (SQLDeadlineAlertReadinessProbe{DB: executor}).Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(executor.queries) != 2 || len(executor.args) != 2 {
		t.Fatalf("queries/args = %d/%d, want 2/2", len(executor.queries), len(executor.args))
	}
	for index, table := range []string{"system_backups", "system_restore_drills"} {
		query := executor.queries[index]
		for _, required := range []string{"INSERT INTO system_backup_alert_states", "FROM " + table, "WHERE ?", "ON DUPLICATE KEY UPDATE"} {
			if !strings.Contains(query, required) {
				t.Fatalf("probe query %d missing %q: %s", index, required, query)
			}
		}
		args := executor.args[index]
		if len(args) != 5 || args[0] != acceptanceAnomalyStateKey || args[1] != "installation_readiness_probe" || args[2] != "__readiness_probe__" || args[3] != uint64(0) || args[4] != false {
			t.Fatalf("probe %d args = %#v", index, args)
		}
	}
}

func TestSQLDeadlineAlertReadinessProbeFailsClosed(t *testing.T) {
	if err := (SQLDeadlineAlertReadinessProbe{}).Check(context.Background()); err == nil {
		t.Fatal("nil database accepted")
	}
	executor := &recordedExec{err: errors.New("alert grant denied")}
	if err := (SQLDeadlineAlertReadinessProbe{DB: executor}).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "backup") {
		t.Fatalf("grant error = %v", err)
	}
	executor = &recordedExec{rows: 1}
	if err := (SQLDeadlineAlertReadinessProbe{DB: executor}).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "affected 1 rows") {
		t.Fatalf("unexpected write error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	executor = &recordedExec{}
	if err := (SQLDeadlineAlertReadinessProbe{DB: executor}).Check(ctx); !errors.Is(err, context.Canceled) || len(executor.queries) != 0 {
		t.Fatalf("canceled error=%v queries=%#v", err, executor.queries)
	}
}

func TestReadinessProbeSetStopsAtFirstFailure(t *testing.T) {
	calls := 0
	probes := ReadinessProbeSet{
		ReadinessProbeFunc(func(context.Context) error { calls++; return nil }),
		ReadinessProbeFunc(func(context.Context) error { calls++; return errors.New("unavailable") }),
		ReadinessProbeFunc(func(context.Context) error { calls++; return nil }),
	}
	if err := probes.Check(context.Background()); err == nil || calls != 2 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
	if err := (ReadinessProbeSet{}).Check(context.Background()); err == nil {
		t.Fatal("empty readiness set accepted")
	}
}
