package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

const MaxDeadlineSweepBatch = 100

var deadlineTaskKinds = []TargetKind{
	TargetBackup,
	TargetDrill,
	TargetPreflight,
	TargetArtifactVerify,
}

type DeadlineCandidate struct {
	Target     Target
	RowVersion uint64
}

// DeadlineStore is the complete persistence surface used by the no-side-effect
// pending deadline sweep. It intentionally has no generic reconcile, runner,
// Job, provider, catalog, or verifier method.
type DeadlineStore interface {
	ListExpiredPending(context.Context, string, TargetKind, string, int) ([]DeadlineCandidate, error)
	Acquire(context.Context, string, DeadlineCandidate, string, LeasePolicy) (ClaimToken, error)
	Expire(context.Context, string, ClaimToken) (uint64, error)
	Release(context.Context, string, ClaimToken, LeasePolicy) (uint64, error)
}

type DeadlineSweeper struct {
	Store          DeadlineStore
	InstallationID string
	Owner          string
	Policy         LeasePolicy
	Limit          int
}

type DeadlineSweepReport struct {
	Selected         int
	Acquired         int
	Expired          int
	ClaimContentions int
	GuardRejections  int
	ReleaseFailures  int
}

func (s DeadlineSweeper) Validate() error {
	if s.Store == nil {
		return errors.New("nil system backup deadline store")
	}
	if !installationIDPattern.MatchString(s.InstallationID) {
		return errors.New("invalid system backup deadline installation ID")
	}
	if !controllerOwnerPattern.MatchString(s.Owner) {
		return errors.New("invalid system backup deadline sweeper owner")
	}
	if err := s.Policy.Validate(); err != nil {
		return err
	}
	if s.Limit < 1 || s.Limit > MaxDeadlineSweepBatch {
		return fmt.Errorf("deadline sweep limit must be between 1 and %d", MaxDeadlineSweepBatch)
	}
	return nil
}

// RunOnce performs one bounded, fair pass over the four D-owned task ledgers.
// It continues after per-row CAS contention, aggregates persistence failures,
// and stops immediately when leader context is canceled.
func (s DeadlineSweeper) RunOnce(ctx context.Context) (DeadlineSweepReport, error) {
	var report DeadlineSweepReport
	if err := s.Validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}

	queues := make([][]DeadlineCandidate, 0, len(deadlineTaskKinds))
	for _, kind := range deadlineTaskKinds {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		candidates, err := s.Store.ListExpiredPending(ctx, s.InstallationID, kind, s.Owner, s.Limit)
		if err != nil {
			return report, fmt.Errorf("list expired pending %s tasks: %w", kind, err)
		}
		for _, candidate := range candidates {
			if candidate.Target.Kind != kind {
				return report, fmt.Errorf("deadline store returned %s candidate in %s queue", candidate.Target.Kind, kind)
			}
			if _, err := candidate.Target.descriptor(); err != nil {
				return report, fmt.Errorf("deadline store returned invalid candidate: %w", err)
			}
			if candidate.RowVersion < 1 {
				return report, errors.New("deadline store returned candidate with invalid row version")
			}
		}
		queues = append(queues, candidates)
	}

	selected := roundRobinDeadlineCandidates(queues, s.Limit)
	report.Selected = len(selected)
	var failures []error
	for _, candidate := range selected {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			return report, errors.Join(failures...)
		}
		token, err := s.Store.Acquire(ctx, s.InstallationID, candidate, s.Owner, s.Policy)
		if errors.Is(err, ErrClaimNotAcquired) {
			report.ClaimContentions++
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("acquire expired pending %s task %s: %w", candidate.Target.Kind, candidate.Target.PublicID, err))
			continue
		}
		report.Acquired++

		if _, err := s.Store.Expire(ctx, s.InstallationID, token); err == nil {
			report.Expired++
			continue
		} else if errors.Is(err, ErrDeadlineTransitionRejected) {
			report.GuardRejections++
			if _, releaseErr := s.Store.Release(ctx, s.InstallationID, token, s.Policy); releaseErr != nil && !errors.Is(releaseErr, ErrClaimLost) {
				report.ReleaseFailures++
				failures = append(failures, fmt.Errorf("release rejected %s task %s claim: %w", candidate.Target.Kind, candidate.Target.PublicID, releaseErr))
			}
			continue
		} else {
			// Leave an errored claim in place. Its database lease is the recovery
			// boundary; another controller may take it only after expiry.
			failures = append(failures, fmt.Errorf("expire pending %s task %s: %w", candidate.Target.Kind, candidate.Target.PublicID, err))
		}
	}
	return report, errors.Join(failures...)
}

func roundRobinDeadlineCandidates(queues [][]DeadlineCandidate, limit int) []DeadlineCandidate {
	result := make([]DeadlineCandidate, 0, limit)
	for offset := 0; len(result) < limit; offset++ {
		added := false
		for _, queue := range queues {
			if offset >= len(queue) {
				continue
			}
			result = append(result, queue[offset])
			added = true
			if len(result) == limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return result
}
