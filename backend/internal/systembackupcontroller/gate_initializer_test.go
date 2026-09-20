package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSQLGateInitializerCreatesOnlyMissingCaptureGate(t *testing.T) {
	executor := &recordedExec{rows: 1}
	initializer := SQLGateInitializer{DB: executor}
	if err := initializer.Ensure(context.Background(), "installation_primary", validGatePolicy()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(executor.queries) != 1 || len(executor.args) != 1 {
		t.Fatalf("queries=%#v args=%#v", executor.queries, executor.args)
	}
	query := executor.queries[0]
	for _, required := range []string{
		"INSERT INTO system_maintenance_locks",
		"origin_installation_id",
		"scope",
		"lock_ttl_seconds",
		"VALUES (?, ?, ?)",
		"ON DUPLICATE KEY UPDATE id = id",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("initializer SQL missing %q: %s", required, query)
		}
	}
	for _, forbidden := range []string{
		"gate_state =", "generation =", "fencing_token =", "lock_owner =", "heartbeat_at =", "lease_expires_at =", "row_version =",
	} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("initializer duplicate path mutates active gate field %q: %s", forbidden, query)
		}
	}
	wantArgs := []any{"installation_primary", CaptureGateScope, gateSeconds(DefaultMaintenanceLockTTL)}
	if !reflect.DeepEqual(executor.args[0], wantArgs) {
		t.Fatalf("initializer args=%#v want=%#v", executor.args[0], wantArgs)
	}
}

func TestSQLGateInitializerFailsBeforePersistenceForInvalidInputOrCancellation(t *testing.T) {
	for _, run := range []func(*recordedExec) error{
		func(executor *recordedExec) error {
			return (SQLGateInitializer{DB: executor}).Ensure(context.Background(), "invalid", validGatePolicy())
		},
		func(executor *recordedExec) error {
			policy := validGatePolicy()
			policy.LockTTL = policy.MaxHold
			return (SQLGateInitializer{DB: executor}).Ensure(context.Background(), "installation_primary", policy)
		},
		func(executor *recordedExec) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return (SQLGateInitializer{DB: executor}).Ensure(ctx, "installation_primary", validGatePolicy())
		},
	} {
		executor := &recordedExec{rows: 1}
		if err := run(executor); err == nil {
			t.Fatal("invalid initializer call accepted")
		}
		if len(executor.queries) != 0 {
			t.Fatalf("invalid initializer call reached persistence: %#v", executor.queries)
		}
	}

	if err := (SQLGateInitializer{}).Ensure(context.Background(), "installation_primary", validGatePolicy()); err == nil {
		t.Fatal("nil initializer database accepted")
	}
}

func TestSQLGateInitializerWrapsPersistenceFailure(t *testing.T) {
	executor := &recordedExec{err: errors.New("database unavailable")}
	err := (SQLGateInitializer{DB: executor}).Ensure(context.Background(), "installation_primary", validGatePolicy())
	if err == nil || !strings.Contains(err.Error(), "ensure system backup capture gate") || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("Ensure error = %v", err)
	}
}
