package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

const MaxKillSwitchBatch = 100

var ErrKillSwitchTransitionRejected = errors.New("system backup kill-switch transition rejected")

type PendingReason string

const (
	PendingNone               PendingReason = "none"
	PendingGlobalCaptureQueue PendingReason = "global_capture_queue"
	PendingKillSwitch         PendingReason = "kill_switch"
	PendingDependencyBackoff  PendingReason = "dependency_backoff"
)

func (r PendingReason) valid() bool {
	switch r {
	case PendingNone, PendingGlobalCaptureQueue, PendingKillSwitch, PendingDependencyBackoff:
		return true
	default:
		return false
	}
}

type KillSwitchCandidate struct {
	Target        Target
	RowVersion    uint64
	PendingReason PendingReason
}

type KillSwitchStore interface {
	ListPending(context.Context, string, TargetKind, bool, int) ([]KillSwitchCandidate, error)
	TransitionPending(context.Context, string, KillSwitchCandidate, PendingReason) (uint64, error)
}

type KillSwitchReconciler struct {
	Store            KillSwitchStore
	InstallationID   string
	EffectiveEnabled bool
	Limit            int
}

type KillSwitchReport struct {
	Selected       int
	Transitioned   int
	CASContentions int
}

func (r KillSwitchReconciler) Validate() error {
	if r.Store == nil {
		return errors.New("nil system backup kill-switch store")
	}
	if !installationIDPattern.MatchString(r.InstallationID) {
		return errors.New("invalid system backup kill-switch installation ID")
	}
	if r.Limit < 1 || r.Limit > MaxKillSwitchBatch {
		return fmt.Errorf("kill-switch batch limit must be between 1 and %d", MaxKillSwitchBatch)
	}
	return nil
}

func desiredPendingReason(kind TargetKind, effectiveEnabled bool) (PendingReason, error) {
	if _, ok := targetDescriptors[kind]; !ok || kind == TargetOperation {
		return "", fmt.Errorf("unsupported kill-switch target kind %q", kind)
	}
	if !effectiveEnabled {
		return PendingKillSwitch, nil
	}
	if kind == TargetBackup {
		return PendingGlobalCaptureQueue, nil
	}
	return PendingNone, nil
}

func (r KillSwitchReconciler) RunOnce(ctx context.Context) (KillSwitchReport, error) {
	var report KillSwitchReport
	if err := r.Validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}

	queues := make([][]KillSwitchCandidate, 0, len(deadlineTaskKinds))
	for _, kind := range deadlineTaskKinds {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		candidates, err := r.Store.ListPending(ctx, r.InstallationID, kind, r.EffectiveEnabled, r.Limit)
		if err != nil {
			return report, fmt.Errorf("list %s kill-switch candidates: %w", kind, err)
		}
		for _, candidate := range candidates {
			if candidate.Target.Kind != kind {
				return report, fmt.Errorf("kill-switch store returned %s candidate in %s queue", candidate.Target.Kind, kind)
			}
			if _, err := candidate.Target.descriptor(); err != nil {
				return report, fmt.Errorf("kill-switch store returned invalid candidate: %w", err)
			}
			if candidate.RowVersion < 1 || !candidate.PendingReason.valid() {
				return report, errors.New("kill-switch store returned invalid candidate state")
			}
			if (r.EffectiveEnabled && candidate.PendingReason != PendingKillSwitch) || (!r.EffectiveEnabled && candidate.PendingReason == PendingKillSwitch) {
				return report, errors.New("kill-switch store returned candidate outside the requested transition")
			}
		}
		queues = append(queues, candidates)
	}

	selected := roundRobinKillSwitchCandidates(queues, r.Limit)
	report.Selected = len(selected)
	var failures []error
	for _, candidate := range selected {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			return report, errors.Join(failures...)
		}
		desired, err := desiredPendingReason(candidate.Target.Kind, r.EffectiveEnabled)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if _, err := r.Store.TransitionPending(ctx, r.InstallationID, candidate, desired); errors.Is(err, ErrKillSwitchTransitionRejected) {
			report.CASContentions++
		} else if err != nil {
			failures = append(failures, fmt.Errorf("transition pending %s task %s from %s to %s: %w", candidate.Target.Kind, candidate.Target.PublicID, candidate.PendingReason, desired, err))
		} else {
			report.Transitioned++
		}
	}
	return report, errors.Join(failures...)
}

func roundRobinKillSwitchCandidates(queues [][]KillSwitchCandidate, limit int) []KillSwitchCandidate {
	result := make([]KillSwitchCandidate, 0, limit)
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
