package systembackupcontroller

import (
	"math"
	"testing"
	"time"
)

func TestAcceptanceAlertSequenceCountsOnlyAcceptanceAnomalies(t *testing.T) {
	start := time.Unix(2_000_000_000, 0).UTC()
	state := AcceptanceAlertSequence{}
	for index, outcome := range []AcceptanceTerminalOutcome{
		{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed", ObservedAt: start},
		{TaskType: TargetBackup, Purpose: "functional_test", Status: "failed", ObservedAt: start.Add(time.Second)},
		{TaskType: TargetBackup, Purpose: "acceptance", Status: "succeeded", EligibilityDecided: true, Eligible: false, ObservedAt: start.Add(2 * time.Second)},
		{TaskType: TargetBackup, Purpose: "acceptance", Status: "canceled", ObservedAt: start.Add(3 * time.Second)},
		{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed", ObservedAt: start.Add(4 * time.Second)},
	} {
		var changed bool
		var err error
		state, changed, err = AdvanceAcceptanceAlertSequence(state, outcome)
		if err != nil {
			t.Fatal(err)
		}
		if changed != (index == 0 || index == 2 || index == 4) {
			t.Fatalf("outcome %d changed sequence unexpectedly", index)
		}
	}
	if state.Count != 3 || state.FirstAnomalyAt == nil || !state.FirstAnomalyAt.Equal(start) || state.LastObservedAt == nil || !state.LastObservedAt.Equal(start.Add(4*time.Second)) {
		t.Fatalf("acceptance anomaly sequence = %#v", state)
	}
	reset, changed, err := AdvanceAcceptanceAlertSequence(state, AcceptanceTerminalOutcome{
		TaskType: TargetBackup, Purpose: "acceptance", Status: "succeeded", EligibilityDecided: true, Eligible: true, ObservedAt: start.Add(5 * time.Second),
	})
	if err != nil || !changed || reset.Count != 0 || reset.FirstAnomalyAt != nil || reset.LastEligibleSuccessAt == nil || !reset.LastEligibleSuccessAt.Equal(start.Add(5*time.Second)) {
		t.Fatalf("eligible acceptance success did not reset sequence: %#v changed=%t err=%v", reset, changed, err)
	}
}

func TestAcceptanceAlertSequenceSaturatesAndRejectsInvalidInputs(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	previous := AcceptanceAlertSequence{Count: math.MaxUint32, FirstAnomalyAt: &now, LastObservedAt: &now}
	next, changed, err := AdvanceAcceptanceAlertSequence(previous, AcceptanceTerminalOutcome{
		TaskType: TargetDrill, Purpose: "acceptance", Status: "failed", ObservedAt: now.Add(time.Second),
	})
	if err != nil || !changed || next.Count != math.MaxUint32 {
		t.Fatalf("UINT32 sequence overflowed: %#v changed=%t err=%v", next, changed, err)
	}
	for _, test := range []struct {
		state   AcceptanceAlertSequence
		outcome AcceptanceTerminalOutcome
	}{
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetOperation, Purpose: "acceptance", Status: "failed", ObservedAt: now}},
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "unknown", Status: "failed", ObservedAt: now}},
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "running", ObservedAt: now}},
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed", Eligible: true, ObservedAt: now}},
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "succeeded", ObservedAt: now}},
		{outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}},
		{state: AcceptanceAlertSequence{Count: 1}, outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed", ObservedAt: now}},
		{state: AcceptanceAlertSequence{LastObservedAt: &now}, outcome: AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed", ObservedAt: now.Add(-time.Second)}},
	} {
		if result, changed, err := AdvanceAcceptanceAlertSequence(test.state, test.outcome); err == nil || changed || result != (AcceptanceAlertSequence{}) {
			t.Fatalf("invalid acceptance outcome accepted: %#v / %#v", test.state, test.outcome)
		}
	}
}
