package systembackupproducer

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestCallerOwnedFinalGuardDoesNotCommit(t *testing.T) {
	r, state, policy := setupTx(t)
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = r.GuardInTx(ctx, tx, func(ctx context.Context, work *Transaction) error {
		return work.CAS(ctx, "UPDATE synthetic SET value=1")
	}); err != nil {
		t.Fatal(err)
	}
	if state.commits != 0 {
		t.Fatal("caller transaction committed by guard")
	}
	if err = tx.Commit(); err != nil || state.commits != 1 {
		t.Fatal("caller commit", err)
	}

	r, state, policy = setupTx(t)
	policy.recheckError = ErrGuardRequired
	tx, err = r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.GuardInTx(ctx, tx, func(ctx context.Context, work *Transaction) error {
		return work.CAS(ctx, "UPDATE synthetic SET value=1")
	}); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("missing final guard failure", err)
	}
	if state.commits != 0 {
		t.Fatal("failed guard committed")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
