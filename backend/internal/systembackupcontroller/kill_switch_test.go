package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type recordedKillSwitchTransition struct {
	candidate KillSwitchCandidate
	desired   PendingReason
}

type recordedKillSwitchStore struct {
	queues      map[TargetKind][]KillSwitchCandidate
	transitions []recordedKillSwitchTransition
	reject      map[string]bool
}

func (s *recordedKillSwitchStore) ListPending(_ context.Context, _ string, kind TargetKind, _ bool, _ int) ([]KillSwitchCandidate, error) {
	return append([]KillSwitchCandidate(nil), s.queues[kind]...), nil
}

func (s *recordedKillSwitchStore) TransitionPending(_ context.Context, _ string, candidate KillSwitchCandidate, desired PendingReason) (uint64, error) {
	s.transitions = append(s.transitions, recordedKillSwitchTransition{candidate: candidate, desired: desired})
	if s.reject[candidate.Target.PublicID] {
		return 0, ErrKillSwitchTransitionRejected
	}
	return candidate.RowVersion + 1, nil
}

func killSwitchCandidate(kind TargetKind, sequence int, reason PendingReason) KillSwitchCandidate {
	prefix := targetDescriptors[kind].idPrefix
	return KillSwitchCandidate{
		Target:        Target{Kind: kind, PublicID: fmt.Sprintf("%s00000000-0000-4000-8000-%012d", prefix, sequence)},
		RowVersion:    uint64(sequence),
		PendingReason: reason,
	}
}

func TestKillSwitchDisableIsBoundedFairAndCASOnly(t *testing.T) {
	store := &recordedKillSwitchStore{
		queues: map[TargetKind][]KillSwitchCandidate{},
		reject: map[string]bool{},
	}
	sequence := 1
	for _, kind := range deadlineTaskKinds {
		for index := 0; index < 3; index++ {
			store.queues[kind] = append(store.queues[kind], killSwitchCandidate(kind, sequence, PendingDependencyBackoff))
			sequence++
		}
	}
	store.reject[store.queues[TargetDrill][0].Target.PublicID] = true
	reconciler := KillSwitchReconciler{
		Store:            store,
		InstallationID:   "installation_primary",
		EffectiveEnabled: false,
		Limit:            6,
	}
	report, err := reconciler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if report.Selected != 6 || report.Transitioned != 5 || report.CASContentions != 1 || len(store.transitions) != 6 {
		t.Fatalf("report=%#v transitions=%d", report, len(store.transitions))
	}
	wantKinds := []TargetKind{TargetBackup, TargetDrill, TargetPreflight, TargetArtifactVerify, TargetBackup, TargetDrill}
	for index, transition := range store.transitions {
		if transition.candidate.Target.Kind != wantKinds[index] || transition.desired != PendingKillSwitch {
			t.Fatalf("transition[%d] = %#v", index, transition)
		}
	}
}

func TestKillSwitchEnableRestoresContractPendingReasons(t *testing.T) {
	store := &recordedKillSwitchStore{queues: map[TargetKind][]KillSwitchCandidate{}, reject: map[string]bool{}}
	sequence := 1
	for _, kind := range deadlineTaskKinds {
		store.queues[kind] = []KillSwitchCandidate{killSwitchCandidate(kind, sequence, PendingKillSwitch)}
		sequence++
	}
	reconciler := KillSwitchReconciler{Store: store, InstallationID: "installation_primary", EffectiveEnabled: true, Limit: 4}
	report, err := reconciler.RunOnce(context.Background())
	if err != nil || report.Transitioned != 4 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	for _, transition := range store.transitions {
		want := PendingNone
		if transition.candidate.Target.Kind == TargetBackup {
			want = PendingGlobalCaptureQueue
		}
		if transition.desired != want {
			t.Fatalf("%s desired=%s want=%s", transition.candidate.Target.Kind, transition.desired, want)
		}
	}
}

func TestKillSwitchRejectsInvalidStoreCandidates(t *testing.T) {
	store := &recordedKillSwitchStore{
		queues: map[TargetKind][]KillSwitchCandidate{
			TargetBackup: {killSwitchCandidate(TargetBackup, 1, PendingKillSwitch)},
		},
		reject: map[string]bool{},
	}
	_, err := (KillSwitchReconciler{Store: store, InstallationID: "installation_primary", EffectiveEnabled: false, Limit: 1}).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "outside the requested transition") {
		t.Fatalf("invalid candidate error = %v", err)
	}
}

func TestKillSwitchSQLIsScopedAndPreservesTaskIdentityAndDeadlines(t *testing.T) {
	for _, kind := range deadlineTaskKinds {
		for _, enabled := range []bool{false, true} {
			query, err := killSwitchCandidateSQL(kind, enabled)
			if err != nil {
				t.Fatalf("candidate SQL %s enabled=%t: %v", kind, enabled, err)
			}
			for _, required := range []string{"origin_installation_id = ?", "status = 'pending'", "ORDER BY id LIMIT ?"} {
				if !strings.Contains(query, required) {
					t.Fatalf("candidate SQL missing %q: %s", required, query)
				}
			}
			for _, forbidden := range []string{"deadline_at", "created_at", "idempotency_key", "request_hash", "system_backup_attempts"} {
				if strings.Contains(query, forbidden) {
					t.Fatalf("candidate SQL contains %q: %s", forbidden, query)
				}
			}
		}
	}
	if _, err := desiredPendingReason(TargetOperation, true); err == nil {
		t.Fatal("operation accepted by kill-switch task reconciler")
	}
}

func TestKillSwitchCancellationStopsBeforeStoreMutation(t *testing.T) {
	store := &recordedKillSwitchStore{queues: map[TargetKind][]KillSwitchCandidate{}, reject: map[string]bool{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (KillSwitchReconciler{Store: store, InstallationID: "installation_primary", Limit: 1}).RunOnce(ctx)
	if !errors.Is(err, context.Canceled) || len(store.transitions) != 0 {
		t.Fatalf("error=%v transitions=%d", err, len(store.transitions))
	}
}
