package systembackupcontroller

import (
	"context"
	"errors"
	"time"
)

// ClaimCoordinator is the production lifecycle entry point for D-owned task
// and operation claims. Candidate selection and state advancement remain
// outside this type; every method delegates to one database-time CAS.
type ClaimCoordinator struct {
	Executor       Executor
	InstallationID string
}

func (c ClaimCoordinator) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Executor == nil {
		return errors.New("nil system backup claim coordinator executor")
	}
	if !installationIDPattern.MatchString(c.InstallationID) {
		return errors.New("invalid system backup claim coordinator installation ID")
	}
	return nil
}

func (c ClaimCoordinator) Acquire(ctx context.Context, target Target, owner string, expectedRowVersion uint64, policy LeasePolicy) (ClaimToken, error) {
	if _, err := target.descriptor(); err != nil {
		return ClaimToken{}, err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return ClaimToken{}, errors.New("invalid system backup controller owner")
	}
	if expectedRowVersion < 1 {
		return ClaimToken{}, errors.New("expected row version must be at least 1")
	}
	if err := policy.Validate(); err != nil {
		return ClaimToken{}, err
	}
	if err := c.validate(ctx); err != nil {
		return ClaimToken{}, err
	}
	return AcquireClaimInInstallation(ctx, c.Executor, c.InstallationID, target, owner, expectedRowVersion, policy)
}

func (c ClaimCoordinator) Renew(ctx context.Context, token ClaimToken, policy LeasePolicy) (ClaimToken, error) {
	if _, err := token.Target.descriptor(); err != nil {
		return ClaimToken{}, err
	}
	if !controllerOwnerPattern.MatchString(token.Owner) || token.RowVersion < 1 {
		return ClaimToken{}, errors.New("invalid system backup claim token")
	}
	if err := policy.Validate(); err != nil {
		return ClaimToken{}, err
	}
	if err := c.validate(ctx); err != nil {
		return ClaimToken{}, err
	}
	return RenewClaimInInstallation(ctx, c.Executor, c.InstallationID, token, policy)
}

func (c ClaimCoordinator) Release(ctx context.Context, token ClaimToken, retryAfter time.Duration) (uint64, error) {
	if _, err := token.Target.descriptor(); err != nil {
		return 0, err
	}
	if !controllerOwnerPattern.MatchString(token.Owner) || token.RowVersion < 1 {
		return 0, errors.New("invalid system backup claim token")
	}
	if retryAfter < MinReconcileInterval || retryAfter > MaxReconcileInterval || retryAfter%time.Microsecond != 0 {
		return 0, errors.New("invalid system backup claim retry delay")
	}
	if err := c.validate(ctx); err != nil {
		return 0, err
	}
	return ReleaseClaimInInstallation(ctx, c.Executor, c.InstallationID, token, retryAfter)
}
