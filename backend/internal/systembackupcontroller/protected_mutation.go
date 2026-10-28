package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type CoordinationTransactionFactory interface {
	BeginCoordination(context.Context) (CoordinationTransaction, error)
}

type SQLCoordinationTransactionFactory struct {
	DB *sql.DB
}

func (f SQLCoordinationTransactionFactory) BeginCoordination(ctx context.Context) (CoordinationTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.DB == nil {
		return nil, errors.New("nil system backup coordination database")
	}
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin system backup coordination transaction: %w", err)
	}
	return SQLCoordinationTransaction{Tx: tx}, nil
}

// ExecuteProtectedMutation is the D-owned business-write boundary. It locks
// the capture gate first and the caller's mutation lease second, validates
// both against database time, then exposes only ExecContext to the callback.
// The callback cannot commit early; all of its writes share the validated
// transaction and are rolled back on error, cancellation, or lost fencing.
func ExecuteProtectedMutation(
	ctx context.Context,
	factory CoordinationTransactionFactory,
	token MutationLeaseToken,
	mutate func(context.Context, Executor) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if factory == nil {
		return errors.New("nil system backup coordination transaction factory")
	}
	if mutate == nil {
		return errors.New("nil system backup protected mutation")
	}
	if err := token.validate(); err != nil {
		return err
	}
	tx, err := factory.BeginCoordination(ctx)
	if err != nil {
		return err
	}
	if tx == nil {
		return errors.New("coordination transaction factory returned nil transaction")
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	if err := ValidateMutationLeaseForCommit(ctx, tx, token); err != nil {
		return err
	}
	if err := mutate(ctx, tx); err != nil {
		return fmt.Errorf("execute system backup protected mutation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit system backup protected mutation: %w", err)
	}
	committed = true
	return nil
}
