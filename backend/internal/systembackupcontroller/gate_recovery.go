package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

const MaxGateRecoveryBatch = 100

type GateRecoveryCandidate struct {
	Key        GateKey
	State      GateState
	RowVersion uint64
}

func (c GateRecoveryCandidate) validate() error {
	if err := c.Key.validate(); err != nil {
		return err
	}
	if c.RowVersion < 1 {
		return errors.New("maintenance gate recovery row version must be at least 1")
	}
	switch c.State {
	case GateAcquiring, GateHeld, GateReleasing:
		return nil
	default:
		return fmt.Errorf("maintenance gate state %q is not recoverable", c.State)
	}
}

// GateRecoveryStore is deliberately limited to expired gate rows. It cannot
// pause/resume participants, finish a release, create a task, or call a runner.
type GateRecoveryStore interface {
	ListExpiredGates(context.Context, string, int) ([]GateRecoveryCandidate, error)
	RecoverAcquiring(context.Context, GateRecoveryCandidate, GateRecoveryReadinessVerifier) (uint64, error)
	FenceForRelease(context.Context, GateRecoveryCandidate, string, GatePolicy) (GateToken, error)
}

type GateRecoveryReconciler struct {
	Store            GateRecoveryStore
	InstallationID   string
	Owner            string
	Policy           GatePolicy
	RunningReadiness GateRecoveryReadinessVerifier
	Limit            int
}

type GateRecoveryReport struct {
	Selected              int
	ReturnedIdle          int
	FencedForRelease      int
	CASContentions        int
	ParticipantProofBlock int
}

func (r GateRecoveryReconciler) Validate() error {
	if r.Store == nil {
		return errors.New("nil system backup gate recovery store")
	}
	if !installationIDPattern.MatchString(r.InstallationID) {
		return errors.New("invalid system backup gate recovery installation ID")
	}
	if !controllerOwnerPattern.MatchString(r.Owner) {
		return errors.New("invalid system backup gate recovery owner")
	}
	if err := r.Policy.Validate(); err != nil {
		return err
	}
	if r.Limit < 1 || r.Limit > MaxGateRecoveryBatch {
		return fmt.Errorf("gate recovery limit must be between 1 and %d", MaxGateRecoveryBatch)
	}
	return nil
}

// RunOnce performs a bounded database-time recovery pass. Expired held or
// releasing owners are fenced and moved only toward releasing. An expired
// acquiring row returns to idle only when the B-owned participant boundary
// supplies positive running proof; absence of that proof is a normal,
// fail-closed blocked result and never authorizes a mutation.
func (r GateRecoveryReconciler) RunOnce(ctx context.Context) (GateRecoveryReport, error) {
	var report GateRecoveryReport
	if err := r.Validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	candidates, err := r.Store.ListExpiredGates(ctx, r.InstallationID, r.Limit)
	if err != nil {
		return report, fmt.Errorf("list expired maintenance gates: %w", err)
	}
	if len(candidates) > r.Limit {
		return report, errors.New("gate recovery store returned more candidates than requested")
	}
	report.Selected = len(candidates)

	var failures []error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			return report, errors.Join(failures...)
		}
		if err := candidate.validate(); err != nil {
			return report, fmt.Errorf("gate recovery store returned invalid candidate: %w", err)
		}
		if candidate.Key.InstallationID != r.InstallationID {
			return report, errors.New("gate recovery store returned candidate for another installation")
		}

		if candidate.State == GateAcquiring {
			if r.RunningReadiness == nil {
				report.ParticipantProofBlock++
				continue
			}
			version, recoverErr := r.Store.RecoverAcquiring(ctx, candidate, r.RunningReadiness)
			if errors.Is(recoverErr, ErrGateTransitionRejected) {
				report.CASContentions++
				continue
			}
			if errors.Is(recoverErr, ErrGateRecoveryNotReady) {
				report.ParticipantProofBlock++
				continue
			}
			if recoverErr != nil {
				failures = append(failures, fmt.Errorf("recover acquiring gate %s: %w", candidate.Key.Scope, recoverErr))
				continue
			}
			if version != candidate.RowVersion+1 {
				failures = append(failures, fmt.Errorf("recover acquiring gate %s returned unexpected row version", candidate.Key.Scope))
				continue
			}
			report.ReturnedIdle++
			continue
		}

		token, recoverErr := r.Store.FenceForRelease(ctx, candidate, r.Owner, r.Policy)
		if errors.Is(recoverErr, ErrGateTransitionRejected) {
			report.CASContentions++
			continue
		}
		if recoverErr != nil {
			failures = append(failures, fmt.Errorf("fence expired %s gate %s for release: %w", candidate.State, candidate.Key.Scope, recoverErr))
			continue
		}
		if token.Key != candidate.Key || token.State != GateReleasing || token.Owner != r.Owner || token.RowVersion != candidate.RowVersion+1 || token.Generation < 1 || token.FencingToken < 1 {
			failures = append(failures, fmt.Errorf("fence expired %s gate %s returned invalid token", candidate.State, candidate.Key.Scope))
			continue
		}
		report.FencedForRelease++
	}
	return report, errors.Join(failures...)
}
