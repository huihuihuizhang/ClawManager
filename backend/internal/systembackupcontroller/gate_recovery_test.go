package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordedGateRecoveryStore struct {
	candidates      []GateRecoveryCandidate
	listErr         error
	acquiringErrors map[string]error
	releaseErrors   map[string]error
	listCalls       int
	acquiringCalls  []string
	releaseCalls    []string
	onFence         func()
}

func (s *recordedGateRecoveryStore) ListExpiredGates(context.Context, string, int) ([]GateRecoveryCandidate, error) {
	s.listCalls++
	return append([]GateRecoveryCandidate(nil), s.candidates...), s.listErr
}

func (s *recordedGateRecoveryStore) RecoverAcquiring(_ context.Context, candidate GateRecoveryCandidate, readiness GateRecoveryReadinessVerifier) (uint64, error) {
	s.acquiringCalls = append(s.acquiringCalls, candidate.Key.Scope)
	if readiness == nil {
		return 0, errors.New("test received nil readiness")
	}
	if err := s.acquiringErrors[candidate.Key.Scope]; err != nil {
		return 0, err
	}
	return candidate.RowVersion + 1, nil
}

func (s *recordedGateRecoveryStore) FenceForRelease(_ context.Context, candidate GateRecoveryCandidate, owner string, _ GatePolicy) (GateToken, error) {
	s.releaseCalls = append(s.releaseCalls, candidate.Key.Scope)
	if s.onFence != nil {
		s.onFence()
	}
	if err := s.releaseErrors[candidate.Key.Scope]; err != nil {
		return GateToken{}, err
	}
	return GateToken{GateSnapshot: GateSnapshot{
		Key: candidate.Key, State: GateReleasing, Generation: 4, FencingToken: 8, Owner: owner, RowVersion: candidate.RowVersion + 1,
	}}, nil
}

func recoveryCandidate(scope string, state GateState, rowVersion uint64) GateRecoveryCandidate {
	return GateRecoveryCandidate{Key: GateKey{InstallationID: "installation_primary", Scope: scope}, State: state, RowVersion: rowVersion}
}

func validGateRecoveryReconciler(store GateRecoveryStore) GateRecoveryReconciler {
	return GateRecoveryReconciler{
		Store: store, InstallationID: "installation_primary", Owner: "controller:pod-1", Policy: validGatePolicy(), Limit: MaxGateRecoveryBatch,
	}
}

func TestGateRecoveryFailClosedWithoutParticipantRunningProof(t *testing.T) {
	store := &recordedGateRecoveryStore{candidates: []GateRecoveryCandidate{
		recoveryCandidate("capture-a", GateAcquiring, 10),
		recoveryCandidate("capture-b", GateHeld, 20),
		recoveryCandidate("capture-c", GateReleasing, 30),
	}}
	reconciler := validGateRecoveryReconciler(store)
	report, err := reconciler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if report.Selected != 3 || report.ParticipantProofBlock != 1 || report.FencedForRelease != 2 || report.ReturnedIdle != 0 {
		t.Fatalf("report = %#v", report)
	}
	if len(store.acquiringCalls) != 0 || !reflect.DeepEqual(store.releaseCalls, []string{"capture-b", "capture-c"}) {
		t.Fatalf("acquiring=%#v release=%#v", store.acquiringCalls, store.releaseCalls)
	}
}

func TestGateRecoveryUsesInjectedProofAndContinuesAfterCASContention(t *testing.T) {
	store := &recordedGateRecoveryStore{
		candidates: []GateRecoveryCandidate{
			recoveryCandidate("capture-a", GateAcquiring, 10),
			recoveryCandidate("capture-b", GateHeld, 20),
			recoveryCandidate("capture-c", GateReleasing, 30),
		},
		releaseErrors: map[string]error{"capture-b": ErrGateTransitionRejected},
	}
	reconciler := validGateRecoveryReconciler(store)
	reconciler.RunningReadiness = &recordedRecoveryReadiness{}
	report, err := reconciler.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if report.ReturnedIdle != 1 || report.FencedForRelease != 1 || report.CASContentions != 1 || report.ParticipantProofBlock != 0 {
		t.Fatalf("report = %#v", report)
	}
	if !reflect.DeepEqual(store.acquiringCalls, []string{"capture-a"}) || !reflect.DeepEqual(store.releaseCalls, []string{"capture-b", "capture-c"}) {
		t.Fatalf("acquiring=%#v release=%#v", store.acquiringCalls, store.releaseCalls)
	}
}

func TestGateRecoveryTreatsMissingRunningProofAsBlockedAndAggregatesPersistenceFailure(t *testing.T) {
	store := &recordedGateRecoveryStore{
		candidates: []GateRecoveryCandidate{
			recoveryCandidate("capture-a", GateAcquiring, 10),
			recoveryCandidate("capture-b", GateHeld, 20),
		},
		acquiringErrors: map[string]error{"capture-a": errors.Join(ErrGateRecoveryNotReady, errors.New("participant still paused"))},
		releaseErrors:   map[string]error{"capture-b": errors.New("database unavailable")},
	}
	reconciler := validGateRecoveryReconciler(store)
	reconciler.RunningReadiness = &recordedRecoveryReadiness{}
	report, err := reconciler.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("RunOnce error = %v", err)
	}
	if report.ParticipantProofBlock != 1 || report.FencedForRelease != 0 {
		t.Fatalf("report = %#v", report)
	}
}

func TestGateRecoveryRejectsInvalidOrCrossInstallationCandidate(t *testing.T) {
	for _, candidate := range []GateRecoveryCandidate{
		recoveryCandidate("capture", GateIdle, 1),
		{Key: GateKey{InstallationID: "installation_other", Scope: "capture"}, State: GateHeld, RowVersion: 1},
	} {
		store := &recordedGateRecoveryStore{candidates: []GateRecoveryCandidate{candidate}}
		if _, err := validGateRecoveryReconciler(store).RunOnce(context.Background()); err == nil {
			t.Fatalf("invalid candidate accepted: %#v", candidate)
		}
		if len(store.acquiringCalls) != 0 || len(store.releaseCalls) != 0 {
			t.Fatalf("invalid candidate reached mutation: %#v", candidate)
		}
	}
}

func TestGateRecoveryCancellationStopsBeforeNextMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &recordedGateRecoveryStore{candidates: []GateRecoveryCandidate{
		recoveryCandidate("capture-a", GateHeld, 20),
		recoveryCandidate("capture-b", GateHeld, 30),
	}, onFence: cancel}
	report, err := validGateRecoveryReconciler(store).RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce error = %v", err)
	}
	if report.FencedForRelease != 1 || !reflect.DeepEqual(store.releaseCalls, []string{"capture-a"}) {
		t.Fatalf("report=%#v calls=%#v", report, store.releaseCalls)
	}
}

func TestExpiredGateCandidateSQLUsesDatabaseTimeAndStateSpecificRecovery(t *testing.T) {
	query := expiredGateCandidateSQL()
	for _, required := range []string{
		"origin_installation_id = ?",
		"gate_state = 'acquiring' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6))",
		"gate_state = 'held' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6))",
		"gate_state = 'releasing' AND lease_expires_at <= UTC_TIMESTAMP(6)",
		"ORDER BY state_changed_at, id",
		"LIMIT ?",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("candidate SQL missing %q: %s", required, query)
		}
	}
	if strings.Contains(query, "NOW()") || strings.Contains(query, "gate_state = 'idle'") {
		t.Fatalf("candidate SQL is not fail-safe: %s", query)
	}
}

func TestSQLGateRecoveryStoreRejectsNilDatabaseAndWrongTransition(t *testing.T) {
	store := SQLGateRecoveryStore{}
	if _, err := store.ListExpiredGates(context.Background(), "installation_primary", 1); err == nil {
		t.Fatal("nil database list accepted")
	}
	if _, err := store.RecoverAcquiring(context.Background(), recoveryCandidate("capture", GateAcquiring, 1), &recordedRecoveryReadiness{}); err == nil {
		t.Fatal("nil database acquiring recovery accepted")
	}
	if _, err := store.FenceForRelease(context.Background(), recoveryCandidate("capture", GateHeld, 1), "controller:pod-1", validGatePolicy()); err == nil {
		t.Fatal("nil database release recovery accepted")
	}
}
