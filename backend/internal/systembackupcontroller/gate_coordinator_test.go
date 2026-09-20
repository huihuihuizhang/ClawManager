package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/migrationcoord"
)

type recordedMigrationLock struct {
	releases int
	err      error
}

func (l *recordedMigrationLock) Release(context.Context) error {
	l.releases++
	return l.err
}

type recordedMigrationLocker struct {
	lock  *recordedMigrationLock
	err   error
	calls int
}

func (l *recordedMigrationLocker) Acquire(context.Context) (migrationcoord.Lock, error) {
	l.calls++
	if l.err != nil {
		return nil, l.err
	}
	return l.lock, nil
}

func TestGateCoordinatorBeginAndHoldUseCoordinationTransactions(t *testing.T) {
	key := validGateKey()
	beginTx := &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateIdle, Generation: 4, FencingToken: 7, RowVersion: 10}}
	beginFactory := &recordedCoordinationFactory{tx: beginTx}
	migrationLock := &recordedMigrationLock{}
	migrationLocker := &recordedMigrationLocker{lock: migrationLock}
	coordinator := GateCoordinator{Factory: beginFactory, MigrationExclusion: migrationLocker}
	token, err := coordinator.BeginAcquisition(context.Background(), key, "controller:pod-1", 10, validGatePolicy())
	if err != nil {
		t.Fatalf("BeginAcquisition: %v", err)
	}
	if token.State != GateAcquiring || token.Generation != 5 || migrationLocker.calls != 1 || migrationLock.releases != 1 || !reflect.DeepEqual(beginTx.order, []string{"lock_gate", "exec", "exec", "commit"}) {
		t.Fatalf("token=%#v lock calls=%d releases=%d order=%#v", token, migrationLocker.calls, migrationLock.releases, beginTx.order)
	}

	holdTx := &recordedCoordinationTx{rows: 1, gate: token.GateSnapshot}
	holdFactory := &recordedCoordinationFactory{tx: holdTx}
	readiness := &recordedReadiness{}
	coordinator = GateCoordinator{Factory: holdFactory, HoldReadiness: readiness}
	held, err := coordinator.AdvanceHeld(context.Background(), token, validGatePolicy())
	if err != nil {
		t.Fatalf("AdvanceHeld: %v", err)
	}
	if held.State != GateHeld || held.FencingToken != token.FencingToken+1 || readiness.calls != 1 || !reflect.DeepEqual(holdTx.order, []string{"lock_gate", "count_leases", "verify_participants", "exec", "exec", "commit"}) {
		t.Fatalf("held=%#v readiness=%d order=%#v", held, readiness.calls, holdTx.order)
	}
}

func TestNewSQLGateCoordinatorInstallsMigrationExclusion(t *testing.T) {
	if _, err := NewSQLGateCoordinator(nil); err == nil {
		t.Fatal("nil database accepted")
	}
	oneConnection := &sql.DB{}
	oneConnection.SetMaxOpenConns(1)
	if _, err := NewSQLGateCoordinator(oneConnection); err == nil || !strings.Contains(err.Error(), "at least two") {
		t.Fatalf("single-connection pool error=%v", err)
	}
	coordinator, err := NewSQLGateCoordinator(&sql.DB{})
	if err != nil || coordinator.Factory == nil || coordinator.Executor == nil || coordinator.MigrationExclusion == nil {
		t.Fatalf("coordinator=%#v error=%v", coordinator, err)
	}
}

func TestGateCoordinatorProofDependenciesFailClosedBeforeTransaction(t *testing.T) {
	token := acquiringGateToken()
	for _, run := range []func(GateCoordinator) error{
		func(coordinator GateCoordinator) error {
			_, err := coordinator.AdvanceHeld(context.Background(), token, validGatePolicy())
			return err
		},
		func(coordinator GateCoordinator) error {
			_, err := coordinator.RecoverAcquiring(context.Background(), token.Key, token.RowVersion)
			return err
		},
	} {
		factory := &recordedCoordinationFactory{}
		err := run(GateCoordinator{Factory: factory})
		if err == nil || factory.calls != 0 {
			t.Fatalf("missing proof error=%v factory calls=%d", err, factory.calls)
		}
	}
}

func TestGateCoordinatorDirectLifecycleUsesExactExecutorCAS(t *testing.T) {
	policy := validGatePolicy()
	acquiring := acquiringGateToken()
	executor := &recordedExec{rows: 1}
	coordinator := GateCoordinator{Executor: executor}
	renewed, err := coordinator.Renew(context.Background(), acquiring, policy)
	if err != nil || renewed.RowVersion != acquiring.RowVersion+1 {
		t.Fatalf("Renew=%#v error=%v", renewed, err)
	}
	abortTx := &recordedCoordinationTx{rows: 1}
	coordinator = GateCoordinator{Factory: &recordedCoordinationFactory{tx: abortTx}}
	if _, err := coordinator.AbortAcquisition(context.Background(), renewed); err != nil {
		t.Fatalf("AbortAcquisition: %v", err)
	}
	if !reflect.DeepEqual(abortTx.order, []string{"exec", "exec", "commit"}) {
		t.Fatalf("abort order=%#v", abortTx.order)
	}

	held := acquiring
	held.State = GateHeld
	held.FencingToken = 8
	held.RowVersion = 20
	releaseTx := &recordedCoordinationTx{rows: 1}
	coordinator = GateCoordinator{Factory: &recordedCoordinationFactory{tx: releaseTx}}
	releasing, err := coordinator.BeginRelease(context.Background(), held)
	if err != nil || releasing.State != GateReleasing {
		t.Fatalf("BeginRelease=%#v error=%v", releasing, err)
	}
	finishTx := &recordedCoordinationTx{rows: 1}
	coordinator = GateCoordinator{Factory: &recordedCoordinationFactory{tx: finishTx}}
	if _, err := coordinator.FinishRelease(context.Background(), releasing); err != nil {
		t.Fatalf("FinishRelease: %v", err)
	}
	if len(executor.queries) != 1 || len(abortTx.queries) != 2 || len(releaseTx.queries) != 2 || len(finishTx.queries) != 2 {
		t.Fatalf("renew=%#v abort=%#v release=%#v finish=%#v", executor.queries, abortTx.queries, releaseTx.queries, finishTx.queries)
	}
	for name, queries := range map[string][]string{"abort": abortTx.queries, "release": releaseTx.queries, "finish": finishTx.queries} {
		if !strings.Contains(queries[1], "INSERT INTO system_backup_events") || !strings.Contains(queries[1], "'gate_changed'") {
			t.Fatalf("%s event=%s", name, queries[1])
		}
	}
}

func TestGateCoordinatorRecoveryUsesExplicitProofOrOnlyFencesTowardRelease(t *testing.T) {
	key := validGateKey()
	acquiring := GateSnapshot{Key: key, State: GateAcquiring, Generation: 5, FencingToken: 7, Owner: "controller:old", RowVersion: 20}
	recoveryTx := &recordedCoordinationTx{rows: 1, gate: acquiring}
	recoveryFactory := &recordedCoordinationFactory{tx: recoveryTx}
	recoveryProof := &recordedRecoveryReadiness{}
	coordinator := GateCoordinator{Factory: recoveryFactory, RecoveryReadiness: recoveryProof}
	version, err := coordinator.RecoverAcquiring(context.Background(), key, acquiring.RowVersion)
	if err != nil || version != acquiring.RowVersion+1 || recoveryProof.calls != 1 {
		t.Fatalf("RecoverAcquiring version=%d proof=%d error=%v", version, recoveryProof.calls, err)
	}

	held := GateSnapshot{Key: key, State: GateHeld, Generation: 5, FencingToken: 8, Owner: "controller:old", RowVersion: 30}
	releaseTx := &recordedCoordinationTx{rows: 1, gate: held}
	releaseFactory := &recordedCoordinationFactory{tx: releaseTx}
	coordinator = GateCoordinator{Factory: releaseFactory}
	token, err := coordinator.RecoverRelease(context.Background(), key, "controller:new", held.RowVersion, validGatePolicy())
	if err != nil || token.State != GateReleasing || token.FencingToken != held.FencingToken+1 {
		t.Fatalf("RecoverRelease token=%#v error=%v", token, err)
	}
}

func TestGateCoordinatorRejectsInvalidInputBeforePersistence(t *testing.T) {
	for _, run := range []func(GateCoordinator) error{
		func(coordinator GateCoordinator) error {
			_, err := coordinator.BeginAcquisition(context.Background(), GateKey{}, "controller:pod-1", 1, validGatePolicy())
			return err
		},
		func(coordinator GateCoordinator) error {
			_, err := coordinator.Renew(context.Background(), GateToken{}, validGatePolicy())
			return err
		},
		func(coordinator GateCoordinator) error {
			_, err := coordinator.BeginRelease(context.Background(), GateToken{})
			return err
		},
	} {
		factory := &recordedCoordinationFactory{}
		executor := &recordedExec{rows: 1}
		if err := run(GateCoordinator{Factory: factory, Executor: executor}); err == nil {
			t.Fatal("invalid gate call accepted")
		}
		if factory.calls != 0 || len(executor.queries) != 0 {
			t.Fatalf("invalid call persisted: factory=%d queries=%#v", factory.calls, executor.queries)
		}
	}
}

func TestGateCoordinatorPropagatesFactoryFailure(t *testing.T) {
	factory := &recordedCoordinationFactory{err: errors.New("database unavailable")}
	lock := &recordedMigrationLock{}
	_, err := (GateCoordinator{Factory: factory, MigrationExclusion: &recordedMigrationLocker{lock: lock}}).BeginAcquisition(context.Background(), validGateKey(), "controller:pod-1", 1, validGatePolicy())
	if err == nil || !strings.Contains(err.Error(), "begin system backup gate transaction") {
		t.Fatalf("BeginAcquisition error=%v", err)
	}
	if lock.releases != 1 {
		t.Fatalf("migration exclusion releases=%d", lock.releases)
	}
}

func TestGateCoordinatorMigrationExclusionFailsClosed(t *testing.T) {
	factory := &recordedCoordinationFactory{}
	_, err := (GateCoordinator{Factory: factory}).BeginAcquisition(context.Background(), validGateKey(), "controller:pod-1", 1, validGatePolicy())
	if err == nil || !strings.Contains(err.Error(), "migration exclusion") || factory.calls != 0 {
		t.Fatalf("missing exclusion error=%v factory calls=%d", err, factory.calls)
	}

	locker := &recordedMigrationLocker{err: errors.New("migration active")}
	_, err = (GateCoordinator{Factory: factory, MigrationExclusion: locker}).BeginAcquisition(context.Background(), validGateKey(), "controller:pod-1", 1, validGatePolicy())
	if err == nil || !strings.Contains(err.Error(), "migration active") || factory.calls != 0 || locker.calls != 1 {
		t.Fatalf("busy exclusion error=%v factory calls=%d locker calls=%d", err, factory.calls, locker.calls)
	}
}
