package systembackupcontroller

import (
	"errors"
	"fmt"
	"math"
	"time"
)

type AcceptanceAlertSequence struct {
	Count                 uint32
	FirstAnomalyAt        *time.Time
	LastObservedAt        *time.Time
	LastEligibleSuccessAt *time.Time
}

type AcceptanceTerminalOutcome struct {
	TaskType           TargetKind
	Purpose            string
	Status             string
	EligibilityDecided bool
	Eligible           bool
	ObservedAt         time.Time
}

// AdvanceAcceptanceAlertSequence is the D-owned transition predicate. Its
// caller must apply the result in the same transaction as a successful task
// terminal-status CAS; this function alone does not provide replay fencing.
func AdvanceAcceptanceAlertSequence(previous AcceptanceAlertSequence, outcome AcceptanceTerminalOutcome) (AcceptanceAlertSequence, bool, error) {
	if err := validateAcceptanceAlertSequence(previous); err != nil {
		return AcceptanceAlertSequence{}, false, err
	}
	if err := validateAcceptanceTerminalOutcome(outcome); err != nil {
		return AcceptanceAlertSequence{}, false, err
	}
	if outcome.ObservedAt.IsZero() {
		return AcceptanceAlertSequence{}, false, errors.New("acceptance observation time is required")
	}
	if outcome.Purpose == "functional_test" || outcome.Status == "canceled" {
		return previous, false, nil
	}
	now := outcome.ObservedAt.UTC()
	if previous.LastObservedAt != nil && now.Before(*previous.LastObservedAt) {
		return AcceptanceAlertSequence{}, false, errors.New("acceptance observation time moved backwards")
	}
	next := previous
	next.LastObservedAt = &now
	if outcome.Eligible {
		next.Count = 0
		next.FirstAnomalyAt = nil
		next.LastEligibleSuccessAt = &now
		return next, true, nil
	}
	if next.Count == 0 {
		next.FirstAnomalyAt = &now
	}
	if next.Count < math.MaxUint32 {
		next.Count++
	}
	return next, true, nil
}

func validateAcceptanceTerminalOutcome(outcome AcceptanceTerminalOutcome) error {
	if outcome.TaskType != TargetBackup && outcome.TaskType != TargetDrill {
		return fmt.Errorf("unsupported acceptance task type %q", outcome.TaskType)
	}
	if outcome.Purpose != "acceptance" && outcome.Purpose != "functional_test" {
		return errors.New("invalid acceptance task purpose")
	}
	if outcome.Status != "succeeded" && outcome.Status != "failed" && outcome.Status != "canceled" {
		return errors.New("acceptance outcome must be terminal")
	}
	if outcome.Eligible && (outcome.Status != "succeeded" || outcome.Purpose != "acceptance") {
		return errors.New("only a succeeded acceptance task may be eligible")
	}
	if outcome.Status == "succeeded" && outcome.Purpose == "acceptance" && !outcome.EligibilityDecided {
		return errors.New("succeeded acceptance eligibility must be decided before sequence update")
	}
	return nil
}

func validateAcceptanceAlertSequence(state AcceptanceAlertSequence) error {
	if (state.Count == 0) != (state.FirstAnomalyAt == nil) {
		return errors.New("acceptance anomaly count and first timestamp disagree")
	}
	if state.Count > 0 && state.LastObservedAt == nil {
		return errors.New("acceptance anomaly sequence lacks last observation")
	}
	if state.FirstAnomalyAt != nil && state.LastObservedAt != nil && state.FirstAnomalyAt.After(*state.LastObservedAt) {
		return errors.New("acceptance anomaly timestamps are reversed")
	}
	if state.LastEligibleSuccessAt != nil && (state.LastObservedAt == nil || state.LastEligibleSuccessAt.After(*state.LastObservedAt)) {
		return errors.New("acceptance eligible success is later than last observation")
	}
	return nil
}
