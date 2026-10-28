package systembackupcontroller

import (
	"testing"
	"time"
)

func TestControllerStateAlertsFixedClockAndProfile(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, profile := range []string{"production", "development"} {
		decisions, err := EvaluateControllerStateAlerts(ControllerStateAlertSnapshot{
			CleanupOwners: &CleanupAlertCollection{Complete: true, ObservedAt: now},
			Profile:       profile,
			Now:           now,
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
		if len(decisions) != 6 || decisions[0].Firing || !decisions[1].Firing || decisions[2].Firing || decisions[3].Firing {
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
		CleanupOwners: &CleanupAlertCollection{Complete: true, ObservedAt: now},
		Profile:       "production", Now: now,
		EvidenceWrites: []EvidenceWriteAlertCandidate{{Age: 9 * time.Nanosecond, ImmutableDeadline: 10 * time.Nanosecond}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decisions[0].Firing || !decisions[1].Firing || !decisions[2].Firing || !decisions[3].Firing {
		t.Fatalf("missing-series or 90%% boundary drifted: %#v", decisions)
	}
	decisions, err = EvaluateControllerStateAlerts(ControllerStateAlertSnapshot{
		CleanupOwners: &CleanupAlertCollection{Complete: true, ObservedAt: now},
		Profile:       "production", Now: now,
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
		snapshot.CleanupOwners = &CleanupAlertCollection{Complete: true, ObservedAt: now}
		if decisions, err := EvaluateControllerStateAlerts(snapshot); err == nil || decisions != nil {
			t.Fatalf("invalid alert snapshot accepted: %#v", snapshot)
		}
	}
}

func dCleanupStateSnapshot(profile string, now time.Time, collection *CleanupAlertCollection) ControllerStateAlertSnapshot {
	return ControllerStateAlertSnapshot{
		Profile: profile, Now: now,
		AcceptanceAnomalies: map[TargetKind]uint64{TargetBackup: 0, TargetDrill: 0},
		ProviderProofIssuer: &ProviderProofIssuerAlertCandidate{ExpiresAt: now.Add(2 * time.Hour), ProofMaxAge: time.Hour, EvidenceRetention: time.Hour},
		CleanupOwners:       collection,
	}
}

func TestControllerCleanupUsesEachImmutableDeadline(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	maximum := time.Duration(1<<63 - 1)
	cases := []struct {
		name   string
		owners []CleanupAlertCandidate
		firing bool
	}{
		{name: "confirmed_empty"},
		{name: "before", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: 59 * time.Second, ImmutableDeadline: time.Minute}}},
		{name: "equal_is_not_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: time.Minute, ImmutableDeadline: time.Minute}}},
		{name: "one_nanosecond_after", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: time.Minute + time.Nanosecond, ImmutableDeadline: time.Minute}}, firing: true},
		{name: "younger_owner_is_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}, {ResidualVolume: dCleanupResidualVolume(false), Age: 100 * time.Second, ImmutableDeadline: time.Minute}}, firing: true},
		{name: "same_global_gauges_but_no_owner_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}, {ResidualVolume: dCleanupResidualVolume(false), Age: 100 * time.Second, ImmutableDeadline: 900 * time.Second}}},
		{name: "overdue_owner_first", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: 100 * time.Second, ImmutableDeadline: time.Minute}, {ResidualVolume: dCleanupResidualVolume(false), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}}, firing: true},
		{name: "maximum_equal", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: maximum, ImmutableDeadline: maximum}}},
		{name: "maximum_one_after", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: maximum, ImmutableDeadline: maximum - 1}}, firing: true},
	}
	for _, profile := range []string{"production", "development"} {
		for _, tc := range cases {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				collection := &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: tc.owners}
				decisions, err := EvaluateControllerStateAlerts(dCleanupStateSnapshot(profile, now, collection))
				if err != nil {
					t.Fatal(err)
				}
				if len(decisions) != 6 {
					t.Fatalf("expected six decisions, got %#v", decisions)
				}
				for i, decision := range decisions {
					if i < 4 && decision.Firing {
						t.Fatalf("previous healthy rule changed: %#v", decision)
					}
				}
				cleanup := decisions[4]
				if cleanup.RuleID != "cleanup-overdue" || cleanup.Severity != "critical" || cleanup.Firing != tc.firing || cleanup.TaskType != "" || cleanup.TaskPurpose != "" {
					t.Fatalf("cleanup decision drifted: %#v, want firing=%v", cleanup, tc.firing)
				}
			})
		}
	}
}

func TestControllerCleanupRejectsUnknownPartialOrInvalidCollections(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cases := []struct {
		name       string
		collection *CleanupAlertCollection
	}{
		{name: "not_read"},
		{name: "partial_empty", collection: &CleanupAlertCollection{ObservedAt: now}},
		{name: "partial_nonempty", collection: &CleanupAlertCollection{ObservedAt: now, Owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: time.Hour, ImmutableDeadline: time.Minute}}}},
		{name: "missing_clock", collection: &CleanupAlertCollection{Complete: true}},
		{name: "stale_clock", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now.Add(-time.Nanosecond)}},
		{name: "future_clock", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now.Add(time.Nanosecond)}},
		{name: "negative_age", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: -time.Nanosecond, ImmutableDeadline: time.Minute}}}},
		{name: "zero_deadline", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: time.Minute}}}},
		{name: "negative_deadline", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), ImmutableDeadline: -time.Nanosecond}}}},
		{name: "overdue_before_invalid_owner", collection: &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: time.Hour, ImmutableDeadline: time.Minute}, {ResidualVolume: dCleanupResidualVolume(false), Age: time.Second}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decisions, err := EvaluateControllerStateAlerts(dCleanupStateSnapshot("production", now, tc.collection))
			if err == nil || decisions != nil {
				t.Fatalf("invalid cleanup collection accepted: %#v / %v", decisions, err)
			}
		})
	}
}

func dCleanupResidualVolume(value bool) *bool { return &value }

func TestControllerResidualVolumeUsesEachImmutableDeadline(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	cases := []struct {
		name   string
		owners []CleanupAlertCandidate
		firing bool
	}{
		{name: "confirmed_empty"},
		{name: "volume_before", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(true), Age: 59 * time.Second, ImmutableDeadline: time.Minute}}},
		{name: "volume_equal", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(true), Age: time.Minute, ImmutableDeadline: time.Minute}}},
		{name: "volume_one_after", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(true), Age: time.Minute + time.Nanosecond, ImmutableDeadline: time.Minute}}, firing: true},
		{name: "nonvolume_overdue_does_not_make_volume_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(false), Age: 100 * time.Second, ImmutableDeadline: time.Minute}, {ResidualVolume: dCleanupResidualVolume(true), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}}},
		{name: "younger_volume_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(true), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}, {ResidualVolume: dCleanupResidualVolume(true), Age: 100 * time.Second, ImmutableDeadline: time.Minute}}, firing: true},
		{name: "same_global_gauges_no_volume_overdue", owners: []CleanupAlertCandidate{{ResidualVolume: dCleanupResidualVolume(true), Age: 700 * time.Second, ImmutableDeadline: 900 * time.Second}, {ResidualVolume: dCleanupResidualVolume(true), Age: 100 * time.Second, ImmutableDeadline: 900 * time.Second}}},
	}
	for _, profile := range []string{"production", "development"} {
		for _, tc := range cases {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				collection := &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: tc.owners}
				decisions, err := EvaluateControllerStateAlerts(dCleanupStateSnapshot(profile, now, collection))
				if err != nil {
					t.Fatal(err)
				}
				if len(decisions) != 6 {
					t.Fatalf("expected six decisions, got %#v", decisions)
				}
				decision := decisions[5]
				if decision.RuleID != "restore-residual-volume-overdue" || decision.Severity != "critical" || decision.Firing != tc.firing || decision.TaskType != "" || decision.TaskPurpose != "" {
					t.Fatalf("residual-volume decision drifted: %#v, want firing=%v", decision, tc.firing)
				}
			})
		}
	}
}

func TestControllerCleanupRejectsUnknownResidualVolumeFacts(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, owners := range [][]CleanupAlertCandidate{
		{{Age: time.Second, ImmutableDeadline: time.Minute}},
		{{ResidualVolume: dCleanupResidualVolume(true), Age: time.Hour, ImmutableDeadline: time.Minute}, {Age: time.Second, ImmutableDeadline: time.Minute}},
	} {
		collection := &CleanupAlertCollection{Complete: true, ObservedAt: now, Owners: owners}
		decisions, err := EvaluateControllerStateAlerts(dCleanupStateSnapshot("production", now, collection))
		if err == nil || decisions != nil {
			t.Fatalf("unknown residual-volume fact accepted: %#v / %v", decisions, err)
		}
	}
}
