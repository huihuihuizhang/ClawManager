package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func validMutationLeaseRequest() MutationLeaseRequest {
	return MutationLeaseRequest{
		LeaseID:            "11111111-1111-4111-8111-111111111111",
		Key:                validGateKey(),
		OperationIdentity:  "update.system_image_setting",
		RequestID:          "request:1",
		Owner:              "api:pod-1",
		ExpectedGeneration: 4,
	}
}

func TestMutationLeaseCoordinatorAcquireUsesOneGateLockedTransaction(t *testing.T) {
	request := validMutationLeaseRequest()
	tx := &recordedCoordinationTx{
		rows: 1,
		gate: GateSnapshot{Key: request.Key, State: GateIdle, Generation: request.ExpectedGeneration, RowVersion: 10},
	}
	factory := &recordedCoordinationFactory{tx: tx}
	token, err := (MutationLeaseCoordinator{Factory: factory}).Acquire(context.Background(), request, validMutationPolicy())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if token.LeaseID != request.LeaseID || token.Key != request.Key || token.Owner != request.Owner || token.Generation != request.ExpectedGeneration || token.RowVersion != 1 {
		t.Fatalf("token=%#v", token)
	}
	if factory.calls != 1 || !reflect.DeepEqual(tx.order, []string{"lock_gate", "exec", "commit"}) {
		t.Fatalf("factory calls=%d order=%#v", factory.calls, tx.order)
	}
	if len(tx.queries) != 1 || !strings.HasPrefix(tx.queries[0], "INSERT INTO system_maintenance_mutation_leases") {
		t.Fatalf("queries=%#v", tx.queries)
	}
}

func TestMutationLeaseCoordinatorRenewAndReleasePreserveLockOrder(t *testing.T) {
	token := validMutationToken()
	lease := MutationLeaseSnapshot{LeaseID: token.LeaseID, Key: token.Key, Owner: token.Owner, Generation: token.Generation, RowVersion: token.RowVersion, Live: true}
	gate := GateSnapshot{Key: token.Key, State: GateIdle, Generation: token.Generation, RowVersion: 10}

	renewTx := &recordedCoordinationTx{rows: 1, gate: gate, lease: lease}
	renewFactory := &recordedCoordinationFactory{tx: renewTx}
	renewed, err := (MutationLeaseCoordinator{Factory: renewFactory}).Renew(context.Background(), token, validMutationPolicy())
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.RowVersion != token.RowVersion+1 || !reflect.DeepEqual(renewTx.order, []string{"lock_gate", "lock_lease", "exec", "commit"}) {
		t.Fatalf("renewed=%#v order=%#v", renewed, renewTx.order)
	}

	lease.RowVersion = renewed.RowVersion
	gate.State = GateAcquiring
	gate.Generation++
	gate.Owner = "controller:pod-1"
	releaseTx := &recordedCoordinationTx{rows: 1, gate: gate, lease: lease}
	releaseFactory := &recordedCoordinationFactory{tx: releaseTx}
	if err := (MutationLeaseCoordinator{Factory: releaseFactory}).Release(context.Background(), renewed); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !reflect.DeepEqual(releaseTx.order, []string{"lock_gate", "lock_lease", "exec", "commit"}) || !strings.HasPrefix(releaseTx.queries[0], "DELETE FROM system_maintenance_mutation_leases") {
		t.Fatalf("order=%#v queries=%#v", releaseTx.order, releaseTx.queries)
	}
}

func TestMutationLeaseCoordinatorRejectsInvalidInputBeforeBeginningTransaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, run := range []func(MutationLeaseCoordinator) error{
		func(coordinator MutationLeaseCoordinator) error {
			_, err := coordinator.Acquire(context.Background(), MutationLeaseRequest{}, validMutationPolicy())
			return err
		},
		func(coordinator MutationLeaseCoordinator) error {
			_, err := coordinator.Renew(context.Background(), MutationLeaseToken{}, validMutationPolicy())
			return err
		},
		func(coordinator MutationLeaseCoordinator) error {
			return coordinator.Release(context.Background(), MutationLeaseToken{})
		},
		func(coordinator MutationLeaseCoordinator) error {
			_, err := coordinator.Acquire(ctx, validMutationLeaseRequest(), validMutationPolicy())
			return err
		},
	} {
		factory := &recordedCoordinationFactory{}
		if err := run(MutationLeaseCoordinator{Factory: factory}); err == nil {
			t.Fatal("invalid mutation lease call accepted")
		}
		if factory.calls != 0 {
			t.Fatalf("invalid call began %d transactions", factory.calls)
		}
	}
}

func TestMutationLeaseCoordinatorPropagatesBeginFailure(t *testing.T) {
	factory := &recordedCoordinationFactory{err: errors.New("database unavailable")}
	_, err := (MutationLeaseCoordinator{Factory: factory}).Acquire(context.Background(), validMutationLeaseRequest(), validMutationPolicy())
	if err == nil || !strings.Contains(err.Error(), "begin system backup mutation lease transaction") || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("Acquire error=%v", err)
	}
	if factory.calls != 1 {
		t.Fatalf("factory calls=%d", factory.calls)
	}
}

func TestMutationLeaseCoordinatorRejectsNilFactory(t *testing.T) {
	_, err := (MutationLeaseCoordinator{}).Acquire(context.Background(), validMutationLeaseRequest(), validMutationPolicy())
	if err == nil || !strings.Contains(err.Error(), "nil system backup mutation lease transaction factory") {
		t.Fatalf("Acquire error=%v", err)
	}
}
