package systembackupcontroller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func validBackupTarget() Target {
	return Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}
}

func TestClaimCoordinatorAcquireRenewReleaseUseExactDatabaseTimeCAS(t *testing.T) {
	executor := &recordedExec{rows: 1}
	coordinator := ClaimCoordinator{Executor: executor, InstallationID: "installation_test"}
	token, err := coordinator.Acquire(context.Background(), validBackupTarget(), "controller:pod-1", 7, validPolicy())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if token.RowVersion != 8 {
		t.Fatalf("acquired token=%#v", token)
	}
	token, err = coordinator.Renew(context.Background(), token, validPolicy())
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if token.RowVersion != 9 {
		t.Fatalf("renewed token=%#v", token)
	}
	version, err := coordinator.Release(context.Background(), token, DefaultReconcile)
	if err != nil || version != 10 {
		t.Fatalf("Release version=%d error=%v", version, err)
	}
	if len(executor.queries) != 3 {
		t.Fatalf("queries=%#v", executor.queries)
	}
	for index, required := range []string{
		"DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)",
		"controller_lease_expires_at > UTC_TIMESTAMP(6)",
		"next_reconcile_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)",
	} {
		if !strings.Contains(executor.queries[index], required) {
			t.Fatalf("query %d missing %q: %s", index, required, executor.queries[index])
		}
		if !strings.Contains(executor.queries[index], "WHERE origin_installation_id = ? AND public_id = ?") {
			t.Fatalf("query %d is not installation fenced: %s", index, executor.queries[index])
		}
	}
}

func TestClaimCoordinatorSupportsOperationClaimsWithoutTaskHeartbeat(t *testing.T) {
	executor := &recordedExec{rows: 1}
	coordinator := ClaimCoordinator{Executor: executor, InstallationID: "installation_test"}
	target := Target{Kind: TargetOperation, PublicID: "sop_11111111-1111-4111-8111-111111111111"}
	if _, err := coordinator.Acquire(context.Background(), target, "controller:pod-1", 1, validPolicy()); err != nil {
		t.Fatalf("Acquire operation: %v", err)
	}
	if strings.Contains(executor.queries[0], "heartbeat_at") || !strings.Contains(executor.queries[0], "claim_owner") || !strings.Contains(executor.queries[0], "claim_expires_at") {
		t.Fatalf("operation claim SQL=%s", executor.queries[0])
	}
}

func TestClaimCoordinatorRejectsInvalidInputBeforePersistence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, run := range []func(ClaimCoordinator) error{
		func(coordinator ClaimCoordinator) error {
			_, err := coordinator.Acquire(context.Background(), Target{}, "controller:pod-1", 1, validPolicy())
			return err
		},
		func(coordinator ClaimCoordinator) error {
			_, err := coordinator.Acquire(context.Background(), validBackupTarget(), "bad owner!", 1, validPolicy())
			return err
		},
		func(coordinator ClaimCoordinator) error {
			_, err := coordinator.Renew(context.Background(), ClaimToken{}, validPolicy())
			return err
		},
		func(coordinator ClaimCoordinator) error {
			_, err := coordinator.Release(context.Background(), ClaimToken{Target: validBackupTarget(), Owner: "controller:pod-1", RowVersion: 1}, MinReconcileInterval-time.Microsecond)
			return err
		},
		func(coordinator ClaimCoordinator) error {
			_, err := coordinator.Acquire(ctx, validBackupTarget(), "controller:pod-1", 1, validPolicy())
			return err
		},
	} {
		executor := &recordedExec{rows: 1}
		if err := run(ClaimCoordinator{Executor: executor, InstallationID: "installation_test"}); err == nil {
			t.Fatal("invalid claim call accepted")
		}
		if len(executor.queries) != 0 {
			t.Fatalf("invalid claim reached persistence: %#v", executor.queries)
		}
	}
}

func TestClaimCoordinatorRejectsNilExecutorAndSurfacesCASContention(t *testing.T) {
	if _, err := (ClaimCoordinator{}).Acquire(context.Background(), validBackupTarget(), "controller:pod-1", 1, validPolicy()); err == nil {
		t.Fatal("nil executor accepted")
	}
	executor := &recordedExec{rows: 0}
	_, err := (ClaimCoordinator{Executor: executor, InstallationID: "installation_test"}).Acquire(context.Background(), validBackupTarget(), "controller:pod-1", 1, validPolicy())
	if !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("CAS contention error=%v", err)
	}
}

func TestClaimCoordinatorRequiresInstallationBeforeSQL(t *testing.T) {
	executor := &recordedExec{rows: 1}
	coordinator := ClaimCoordinator{Executor: executor}
	if _, err := coordinator.Acquire(context.Background(), validBackupTarget(), "controller:pod-1", 1, validPolicy()); err == nil {
		t.Fatal("claim coordinator accepted missing installation")
	}
	if len(executor.queries) != 0 {
		t.Fatalf("claim coordinator reached SQL without installation: %#v", executor.queries)
	}
}
