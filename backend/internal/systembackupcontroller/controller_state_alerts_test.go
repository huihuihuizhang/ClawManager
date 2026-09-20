package systembackupcontroller

import (
	"testing"
	"time"
)

func TestControllerStateAlertsFixedClockAndProfile(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, profile := range []string{"production", "development"} {
		decisions, err := EvaluateControllerStateAlerts(ControllerStateAlertSnapshot{
			Profile: profile,
			Now:     now,
			AcceptanceAnomalies: map[TargetKind]uint64{
				TargetBackup: 2,
				TargetDrill:  3,
			},
			EvidenceWrites: []EvidenceWriteAlertCandidate{{Age: 89 * time.Second, ImmutableDeadline: 100 * time.Second}},
			ProviderProofIssuer: &ProviderProofIssuerAlertCandidate{
				ExpiresAt: now.Add(2 * time.Hour), ProofMaxAge: time.Hour, EvidenceRetention: 2 * time.Hour,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(decisions) != 4 || decisions[0].Firing || !decisions[1].Firing || decisions[2].Firing || decisions[3].Firing {
			t.Fatalf("unexpected %s controller-state decisions: %#v", profile, decisions)
		}
		if decisions[0].RuleID != "acceptance-consecutive-anomalies."+profile || decisions[0].TaskType != TargetBackup || decisions[1].TaskType != TargetDrill || decisions[0].TaskPurpose != "acceptance" {
			t.Fatalf("unexpected acceptance alert identity: %#v", decisions)
		}
		wantSeverity := "critical"
		if profile == "development" {
			wantSeverity = "info"
		}
		if decisions[0].Severity != wantSeverity || decisions[1].Severity != wantSeverity || decisions[2].Severity != "critical" || decisions[3].Severity != "warning" {
			t.Fatalf("unexpected alert severity: %#v", decisions)
		}
	}
}

func TestControllerStateAlertsExactBoundariesAndMissingSeries(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	decisions, err := EvaluateControllerStateAlerts(ControllerStateAlertSnapshot{
		Profile: "production", Now: now,
		EvidenceWrites: []EvidenceWriteAlertCandidate{{Age: 9 * time.Nanosecond, ImmutableDeadline: 10 * time.Nanosecond}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decisions[0].Firing || !decisions[1].Firing || !decisions[2].Firing || !decisions[3].Firing {
		t.Fatalf("missing-series or 90%% boundary drifted: %#v", decisions)
	}
	decisions, err = EvaluateControllerStateAlerts(ControllerStateAlertSnapshot{
		Profile: "production", Now: now,
		AcceptanceAnomalies: map[TargetKind]uint64{TargetBackup: 0, TargetDrill: 0},
		ProviderProofIssuer: &ProviderProofIssuerAlertCandidate{
			ExpiresAt: now.Add(time.Hour - time.Nanosecond), ProofMaxAge: time.Hour, EvidenceRetention: time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decisions[0].Firing || decisions[1].Firing || decisions[2].Firing || !decisions[3].Firing {
		t.Fatalf("recovery or strict issuer-key threshold drifted: %#v", decisions)
	}
}

func TestControllerStateAlertsRejectInvalidInputs(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, snapshot := range []ControllerStateAlertSnapshot{
		{Profile: "unknown", Now: now},
		{Profile: "production"},
		{Profile: "production", Now: now, AcceptanceAnomalies: map[TargetKind]uint64{TargetOperation: 3}},
		{Profile: "production", Now: now, EvidenceWrites: []EvidenceWriteAlertCandidate{{Age: -time.Second, ImmutableDeadline: time.Minute}}},
		{Profile: "production", Now: now, EvidenceWrites: []EvidenceWriteAlertCandidate{{Age: time.Second}}},
		{Profile: "production", Now: now, ProviderProofIssuer: &ProviderProofIssuerAlertCandidate{ExpiresAt: now, ProofMaxAge: time.Hour}},
	} {
		if decisions, err := EvaluateControllerStateAlerts(snapshot); err == nil || decisions != nil {
			t.Fatalf("invalid alert snapshot accepted: %#v", snapshot)
		}
	}
}
