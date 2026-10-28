package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"clawreef/internal/migrationcoord"
)

// GateCoordinator is the D-owned production facade for maintenance-gate
// persistence. Participant state is never inferred: acquiring -> held and
// expired acquiring -> idle require explicit external proof interfaces.
type GateCoordinator struct {
	Factory            CoordinationTransactionFactory
	Executor           Executor
	MigrationExclusion migrationcoord.Locker
	HoldReadiness      GateHoldReadinessVerifier
	RecoveryReadiness  GateRecoveryReadinessVerifier
}

// NewSQLGateCoordinator returns the production D-owned gate facade with the
// migration/capture advisory exclusion installed. Proof adapters remain
// explicit because their evidence is owned by B, not inferred by D.
func NewSQLGateCoordinator(db *sql.DB) (GateCoordinator, error) {
	if db == nil {
		return GateCoordinator{}, errors.New("nil system backup gate database")
	}
	if maximum := db.Stats().MaxOpenConnections; maximum == 1 {
		return GateCoordinator{}, errors.New("system backup gate database pool needs at least two open connections")
	}
	return GateCoordinator{
		Factory:            SQLCoordinationTransactionFactory{DB: db},
		Executor:           db,
		MigrationExclusion: migrationcoord.SQLLocker{DB: db},
	}, nil
}

func (c GateCoordinator) begin(ctx context.Context) (CoordinationTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Factory == nil {
		return nil, errors.New("nil system backup gate transaction factory")
	}
	tx, err := c.Factory.BeginCoordination(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin system backup gate transaction: %w", err)
	}
	if tx == nil {
		return nil, errors.New("gate transaction factory returned nil transaction")
	}
	return tx, nil
}

func (c GateCoordinator) executor(ctx context.Context) (Executor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Executor == nil {
		return nil, errors.New("nil system backup gate executor")
	}
	return c.Executor, nil
}

func (c GateCoordinator) BeginAcquisition(ctx context.Context, key GateKey, owner string, expectedRowVersion uint64, policy GatePolicy) (token GateToken, returnErr error) {
	if err := key.validate(); err != nil {
		return GateToken{}, err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return GateToken{}, errors.New("invalid system backup maintenance gate owner")
	}
	if expectedRowVersion < 1 {
		return GateToken{}, errors.New("expected maintenance gate row version must be at least 1")
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	if c.MigrationExclusion == nil {
		return GateToken{}, errors.New("nil system backup migration exclusion locker")
	}
	guard, err := c.MigrationExclusion.Acquire(ctx)
	if err != nil {
		return GateToken{}, fmt.Errorf("acquire system backup migration exclusion: %w", err)
	}
	if guard == nil {
		return GateToken{}, errors.New("migration exclusion locker returned nil lock")
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := guard.Release(releaseCtx); err != nil && returnErr == nil {
			token = GateToken{}
			returnErr = fmt.Errorf("release system backup migration exclusion: %w", err)
		}
	}()
	tx, err := c.begin(ctx)
	if err != nil {
		return GateToken{}, err
	}
	return BeginGateAcquisition(ctx, tx, key, owner, expectedRowVersion, policy)
}

func (c GateCoordinator) AdvanceHeld(ctx context.Context, token GateToken, policy GatePolicy) (GateToken, error) {
	if err := token.validate(GateAcquiring); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	if c.HoldReadiness == nil {
		return GateToken{}, errors.New("nil system backup gate hold readiness verifier")
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return GateToken{}, err
	}
	return AdvanceGateHeld(ctx, tx, token, policy, c.HoldReadiness)
}

func (c GateCoordinator) Renew(ctx context.Context, token GateToken, policy GatePolicy) (GateToken, error) {
	if token.State != GateAcquiring && token.State != GateHeld && token.State != GateReleasing {
		return GateToken{}, errors.New("maintenance gate renewal requires an active token")
	}
	if err := token.validate(token.State); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	executor, err := c.executor(ctx)
	if err != nil {
		return GateToken{}, err
	}
	return RenewGate(ctx, executor, token, policy)
}

func (c GateCoordinator) AbortAcquisition(ctx context.Context, token GateToken) (uint64, error) {
	if err := token.validate(GateAcquiring); err != nil {
		return 0, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return 0, err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)
	version, err := AbortGateAcquisition(ctx, tx, token)
	if err != nil {
		return 0, err
	}
	if err := insertGateTransitionEvent(ctx, tx, token.Key, GateAcquiring, GateIdle, gateReasonAcquisitionAborted, "Maintenance gate acquisition aborted."); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit system backup gate acquisition abort: %w", err)
	}
	committed = true
	return version, nil
}

func (c GateCoordinator) BeginRelease(ctx context.Context, token GateToken) (GateToken, error) {
	if err := token.validate(GateHeld); err != nil {
		return GateToken{}, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return GateToken{}, err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)
	releasing, err := BeginGateRelease(ctx, tx, token)
	if err != nil {
		return GateToken{}, err
	}
	if err := insertGateTransitionEvent(ctx, tx, token.Key, GateHeld, GateReleasing, gateReasonReleaseRequested, "Maintenance gate release started."); err != nil {
		return GateToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return GateToken{}, fmt.Errorf("commit system backup gate release start: %w", err)
	}
	committed = true
	return releasing, nil
}

func (c GateCoordinator) FinishRelease(ctx context.Context, token GateToken) (uint64, error) {
	if err := token.validate(GateReleasing); err != nil {
		return 0, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return 0, err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)
	version, err := FinishGateRelease(ctx, tx, token)
	if err != nil {
		return 0, err
	}
	if err := insertGateTransitionEvent(ctx, tx, token.Key, GateReleasing, GateIdle, gateReasonParticipantsResumed, "Maintenance gate returned to idle."); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit system backup gate release finish: %w", err)
	}
	committed = true
	return version, nil
}

func (c GateCoordinator) RecoverAcquiring(ctx context.Context, key GateKey, expectedRowVersion uint64) (uint64, error) {
	if err := key.validate(); err != nil {
		return 0, err
	}
	if expectedRowVersion < 1 {
		return 0, errors.New("expected maintenance gate row version must be at least 1")
	}
	if c.RecoveryReadiness == nil {
		return 0, errors.Join(ErrGateRecoveryNotReady, errors.New("nil system backup gate recovery readiness verifier"))
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return 0, err
	}
	return RecoverGateIdle(ctx, tx, key, expectedRowVersion, c.RecoveryReadiness)
}

func (c GateCoordinator) RecoverRelease(ctx context.Context, key GateKey, owner string, expectedRowVersion uint64, policy GatePolicy) (GateToken, error) {
	if err := key.validate(); err != nil {
		return GateToken{}, err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return GateToken{}, errors.New("invalid system backup maintenance gate owner")
	}
	if expectedRowVersion < 1 {
		return GateToken{}, errors.New("expected maintenance gate row version must be at least 1")
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return GateToken{}, err
	}
	return RecoverGateRelease(ctx, tx, key, owner, expectedRowVersion, policy)
}
