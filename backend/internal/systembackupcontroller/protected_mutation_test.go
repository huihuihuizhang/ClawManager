package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordedCoordinationFactory struct {
	tx    CoordinationTransaction
	err   error
	calls int
}

func (f *recordedCoordinationFactory) BeginCoordination(context.Context) (CoordinationTransaction, error) {
	f.calls++
	return f.tx, f.err
}

func validProtectedMutationTx(token MutationLeaseToken) *recordedCoordinationTx {
	return &recordedCoordinationTx{
		rows: 1,
		gate: GateSnapshot{Key: token.Key, State: GateIdle, Generation: token.Generation, RowVersion: 10},
		lease: MutationLeaseSnapshot{
			LeaseID: token.LeaseID, Key: token.Key, Owner: token.Owner, Generation: token.Generation, RowVersion: token.RowVersion, Live: true,
		},
	}
}

func TestExecuteProtectedMutationLocksGateThenLeaseBeforeBusinessWrite(t *testing.T) {
	token := validMutationToken()
	tx := validProtectedMutationTx(token)
	factory := &recordedCoordinationFactory{tx: tx}
	err := ExecuteProtectedMutation(context.Background(), factory, token, func(ctx context.Context, executor Executor) error {
		_, err := executor.ExecContext(ctx, "UPDATE d_owned_resource SET value = ? WHERE id = ?", "new", 1)
		return err
	})
	if err != nil {
		t.Fatalf("ExecuteProtectedMutation: %v", err)
	}
	if factory.calls != 1 || !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "exec", "commit"}) {
		t.Fatalf("factory calls=%d order=%#v", factory.calls, tx.order)
	}
	if len(tx.queries) != 1 || tx.queries[0] != "UPDATE d_owned_resource SET value = ? WHERE id = ?" {
		t.Fatalf("business queries=%#v", tx.queries)
	}
}

func TestExecuteProtectedMutationRollsBackBeforeCallbackWhenLeaseIsLost(t *testing.T) {
	token := validMutationToken()
	tx := validProtectedMutationTx(token)
	tx.lease.Live = false
	factory := &recordedCoordinationFactory{tx: tx}
	called := false
	err := ExecuteProtectedMutation(context.Background(), factory, token, func(context.Context, Executor) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrMutationLeaseLost) || called {
		t.Fatalf("error=%v callback=%t", err, called)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "rollback"}) {
		t.Fatalf("order=%#v", tx.order)
	}
}

func TestExecuteProtectedMutationRollsBackCallbackFailure(t *testing.T) {
	token := validMutationToken()
	tx := validProtectedMutationTx(token)
	factory := &recordedCoordinationFactory{tx: tx}
	err := ExecuteProtectedMutation(context.Background(), factory, token, func(context.Context, Executor) error {
		return errors.New("business validation failed")
	})
	if err == nil || !strings.Contains(err.Error(), "execute system backup protected mutation") || !strings.Contains(err.Error(), "business validation failed") {
		t.Fatalf("unexpected callback error: %v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "rollback"}) {
		t.Fatalf("order=%#v", tx.order)
	}
}

func TestExecuteProtectedMutationCancellationBeforeBeginDoesNotTouchDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	factory := &recordedCoordinationFactory{}
	if err := ExecuteProtectedMutation(ctx, factory, validMutationToken(), func(context.Context, Executor) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error=%v", err)
	}
	if factory.calls != 0 {
		t.Fatalf("canceled mutation began %d transactions", factory.calls)
	}
}

func TestExecuteProtectedMutationCancellationAfterCallbackRollsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	token := validMutationToken()
	tx := validProtectedMutationTx(token)
	factory := &recordedCoordinationFactory{tx: tx}
	err := ExecuteProtectedMutation(ctx, factory, token, func(context.Context, Executor) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error=%v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "rollback"}) {
		t.Fatalf("order=%#v", tx.order)
	}
}

func TestExecuteProtectedMutationCommitFailureRollsBack(t *testing.T) {
	token := validMutationToken()
	tx := validProtectedMutationTx(token)
	tx.commitErr = errors.New("commit unavailable")
	factory := &recordedCoordinationFactory{tx: tx}
	err := ExecuteProtectedMutation(context.Background(), factory, token, func(context.Context, Executor) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "commit system backup protected mutation") {
		t.Fatalf("commit error=%v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "commit", "rollback"}) {
		t.Fatalf("order=%#v", tx.order)
	}
}

func TestExecuteProtectedMutationRejectsNilBoundaryInputs(t *testing.T) {
	if err := ExecuteProtectedMutation(context.Background(), nil, validMutationToken(), func(context.Context, Executor) error { return nil }); err == nil {
		t.Fatal("nil factory accepted")
	}
	factory := &recordedCoordinationFactory{tx: validProtectedMutationTx(validMutationToken())}
	if err := ExecuteProtectedMutation(context.Background(), factory, validMutationToken(), nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	factory = &recordedCoordinationFactory{}
	if err := ExecuteProtectedMutation(context.Background(), factory, MutationLeaseToken{}, func(context.Context, Executor) error { return nil }); err == nil || factory.calls != 0 {
		t.Fatalf("invalid token error=%v factory calls=%d", err, factory.calls)
	}
}

func TestSQLCoordinationTransactionFactoryRejectsNilDatabase(t *testing.T) {
	if _, err := (SQLCoordinationTransactionFactory{}).BeginCoordination(context.Background()); err == nil {
		t.Fatal("nil SQL coordination database accepted")
	}
}
