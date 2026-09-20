package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

// MutationLeaseCoordinator is the production lifecycle entry point for the
// D-owned mutation lease. It only opens coordination transactions and delegates
// to the lock-order-preserving primitives; it has no gate hold, participant,
// external execution, or business-resource surface.
type MutationLeaseCoordinator struct {
	Factory CoordinationTransactionFactory
}

func (c MutationLeaseCoordinator) begin(ctx context.Context) (CoordinationTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Factory == nil {
		return nil, errors.New("nil system backup mutation lease transaction factory")
	}
	tx, err := c.Factory.BeginCoordination(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin system backup mutation lease transaction: %w", err)
	}
	if tx == nil {
		return nil, errors.New("mutation lease transaction factory returned nil transaction")
	}
	return tx, nil
}

func (c MutationLeaseCoordinator) Acquire(ctx context.Context, request MutationLeaseRequest, policy MutationLeasePolicy) (MutationLeaseToken, error) {
	if err := ctx.Err(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := request.validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return MutationLeaseToken{}, err
	}
	return AcquireMutationLease(ctx, tx, request, policy)
}

func (c MutationLeaseCoordinator) Renew(ctx context.Context, token MutationLeaseToken, policy MutationLeasePolicy) (MutationLeaseToken, error) {
	if err := ctx.Err(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := token.validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return MutationLeaseToken{}, err
	}
	return RenewMutationLease(ctx, tx, token, policy)
}

func (c MutationLeaseCoordinator) Release(ctx context.Context, token MutationLeaseToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := token.validate(); err != nil {
		return err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return err
	}
	return ReleaseMutationLease(ctx, tx, token)
}
