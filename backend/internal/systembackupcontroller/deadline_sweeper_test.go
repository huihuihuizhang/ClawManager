package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeDeadlineStore struct {
	listed        map[TargetKind][]DeadlineCandidate
	listErr       error
	acquireErr    map[string]error
	expireErr     map[string]error
	releaseErr    map[string]error
	acquired      []string
	expired       []string
	released      []string
	listKindOrder []TargetKind
	cancel        context.CancelFunc
	cancelOnList  TargetKind
	installations []string
}

func (s *fakeDeadlineStore) ListExpiredPending(ctx context.Context, installationID string, kind TargetKind, owner string, limit int) ([]DeadlineCandidate, error) {
	s.installations = append(s.installations, installationID)
	s.listKindOrder = append(s.listKindOrder, kind)
	if s.cancel != nil && kind == s.cancelOnList {
		s.cancel()
	}
	if s.listErr != nil {
		return nil, s.listErr
	}
	items := s.listed[kind]
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s *fakeDeadlineStore) Acquire(ctx context.Context, installationID string, candidate DeadlineCandidate, owner string, policy LeasePolicy) (ClaimToken, error) {
	s.installations = append(s.installations, installationID)
	s.acquired = append(s.acquired, candidate.Target.PublicID)
	if err := s.acquireErr[candidate.Target.PublicID]; err != nil {
		return ClaimToken{}, err
	}
	return ClaimToken{Target: candidate.Target, Owner: owner, RowVersion: candidate.RowVersion + 1}, nil
}

func (s *fakeDeadlineStore) Expire(ctx context.Context, installationID string, token ClaimToken) (uint64, error) {
	s.installations = append(s.installations, installationID)
	s.expired = append(s.expired, token.Target.PublicID)
	if err := s.expireErr[token.Target.PublicID]; err != nil {
		return 0, err
	}
	return token.RowVersion + 1, nil
}

func (s *fakeDeadlineStore) Release(ctx context.Context, installationID string, token ClaimToken, policy LeasePolicy) (uint64, error) {
	s.installations = append(s.installations, installationID)
	s.released = append(s.released, token.Target.PublicID)
	if err := s.releaseErr[token.Target.PublicID]; err != nil {
		return 0, err
	}
	return token.RowVersion + 1, nil
}

func candidate(kind TargetKind, id string, rowVersion uint64) DeadlineCandidate {
	return DeadlineCandidate{Target: Target{Kind: kind, PublicID: id}, RowVersion: rowVersion}
}

func TestDeadlineSweeperRoundRobinsTaskKindsAndExpiresBoundedRows(t *testing.T) {
	store := &fakeDeadlineStore{listed: map[TargetKind][]DeadlineCandidate{
		TargetBackup: {
			candidate(TargetBackup, "sbk_11111111-1111-4111-8111-111111111111", 1),
			candidate(TargetBackup, "sbk_22222222-2222-4222-8222-222222222222", 2),
		},
		TargetDrill: {
			candidate(TargetDrill, "sdr_11111111-1111-4111-8111-111111111111", 3),
		},
		TargetPreflight: {
			candidate(TargetPreflight, "spf_11111111-1111-4111-8111-111111111111", 4),
		},
		TargetArtifactVerify: {
			candidate(TargetArtifactVerify, "sav_11111111-1111-4111-8111-111111111111", 5),
		},
	}}
	sweeper := DeadlineSweeper{Store: store, InstallationID: "installation_test", Owner: "controller:pod-1", Policy: validPolicy(), Limit: 5}
	report, err := sweeper.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	wantOrder := []string{
		"sbk_11111111-1111-4111-8111-111111111111",
		"sdr_11111111-1111-4111-8111-111111111111",
		"spf_11111111-1111-4111-8111-111111111111",
		"sav_11111111-1111-4111-8111-111111111111",
		"sbk_22222222-2222-4222-8222-222222222222",
	}
	if !reflect.DeepEqual(store.acquired, wantOrder) || !reflect.DeepEqual(store.expired, wantOrder) {
		t.Fatalf("acquired/expired order = %#v / %#v, want %#v", store.acquired, store.expired, wantOrder)
	}
	if report != (DeadlineSweepReport{Selected: 5, Acquired: 5, Expired: 5}) {
		t.Fatalf("report = %#v", report)
	}
	if !reflect.DeepEqual(store.listKindOrder, deadlineTaskKinds) {
		t.Fatalf("listed kinds = %#v, want %#v", store.listKindOrder, deadlineTaskKinds)
	}
	for _, installationID := range store.installations {
		if installationID != "installation_test" {
			t.Fatalf("deadline action escaped installation: %q", installationID)
		}
	}
}

func TestDeadlineSweeperHandlesContentionAndGuardRejectionWithoutUnsafeRetry(t *testing.T) {
	backupID := "sbk_11111111-1111-4111-8111-111111111111"
	drillID := "sdr_11111111-1111-4111-8111-111111111111"
	preflightID := "spf_11111111-1111-4111-8111-111111111111"
	store := &fakeDeadlineStore{
		listed: map[TargetKind][]DeadlineCandidate{
			TargetBackup:    {candidate(TargetBackup, backupID, 1)},
			TargetDrill:     {candidate(TargetDrill, drillID, 2)},
			TargetPreflight: {candidate(TargetPreflight, preflightID, 3)},
		},
		acquireErr: map[string]error{backupID: ErrClaimNotAcquired},
		expireErr:  map[string]error{drillID: ErrDeadlineTransitionRejected, preflightID: errors.New("event store unavailable")},
		releaseErr: map[string]error{},
	}
	sweeper := DeadlineSweeper{Store: store, InstallationID: "installation_test", Owner: "controller:pod-1", Policy: validPolicy(), Limit: 10}
	report, err := sweeper.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "event store unavailable") {
		t.Fatalf("RunOnce error = %v, want aggregated event failure", err)
	}
	if report != (DeadlineSweepReport{Selected: 3, Acquired: 2, ClaimContentions: 1, GuardRejections: 1}) {
		t.Fatalf("report = %#v", report)
	}
	if !reflect.DeepEqual(store.released, []string{drillID}) {
		t.Fatalf("released = %#v, want only guard-rejected drill", store.released)
	}
}

func TestDeadlineSweeperRejectsInvalidStoreOutputBeforeClaim(t *testing.T) {
	store := &fakeDeadlineStore{listed: map[TargetKind][]DeadlineCandidate{
		TargetBackup: {candidate(TargetDrill, "sdr_11111111-1111-4111-8111-111111111111", 1)},
	}}
	sweeper := DeadlineSweeper{Store: store, InstallationID: "installation_test", Owner: "controller:pod-1", Policy: validPolicy(), Limit: 10}
	if _, err := sweeper.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "candidate in backup queue") {
		t.Fatalf("invalid candidate error = %v", err)
	}
	if len(store.acquired) != 0 {
		t.Fatalf("invalid store output reached claim: %#v", store.acquired)
	}
}

func TestExpiredPendingCandidateSQLIsDBTimeReadOnlyAndTaskOnly(t *testing.T) {
	for _, kind := range deadlineTaskKinds {
		query, err := expiredPendingCandidateSQL(kind)
		if err != nil {
			t.Fatalf("expiredPendingCandidateSQL(%s): %v", kind, err)
		}
		for _, required := range []string{
			"SELECT public_id, row_version",
			"WHERE origin_installation_id = ? AND status = 'pending'",
			"status = 'pending'",
			"deadline_at <= UTC_TIMESTAMP(6)",
			"next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)",
			"NOT EXISTS (SELECT 1 FROM system_backup_attempts",
			"ORDER BY deadline_at, id LIMIT ?",
		} {
			if !strings.Contains(query, required) {
				t.Fatalf("%s query missing %q: %s", kind, required, query)
			}
		}
		for _, forbidden := range []string{"UPDATE ", "INSERT ", "DELETE ", "NOW()", "provider_payload", "credential"} {
			if strings.Contains(strings.ToUpper(query), strings.ToUpper(forbidden)) {
				t.Fatalf("%s candidate query contains forbidden %q: %s", kind, forbidden, query)
			}
		}
	}
	if _, err := expiredPendingCandidateSQL(TargetOperation); err == nil {
		t.Fatal("operation candidate SQL must remain unsupported")
	}
}

func TestSQLDeadlineStoreListsOnlyBoundInstallation(t *testing.T) {
	publicID := "sbk_11111111-1111-4111-8111-111111111111"
	state := &acceptanceStateTestDB{values: [][]driver.Value{{publicID, int64(7)}}}
	db := sql.OpenDB(acceptanceStateTestConnector{state: state})
	defer db.Close()
	store := SQLDeadlineStore{DB: db}
	candidates, err := store.ListExpiredPending(context.Background(), "installation_test", TargetBackup, "controller:pod-1", 5)
	if err != nil || len(candidates) != 1 || candidates[0].Target.PublicID != publicID || candidates[0].RowVersion != 7 {
		t.Fatalf("scoped deadline candidates = %#v, err=%v", candidates, err)
	}
	if !strings.Contains(state.query, "WHERE origin_installation_id = ? AND status = 'pending'") || len(state.args) != 3 ||
		state.args[0].Value != "installation_test" || state.args[1].Value != "controller:pod-1" || state.args[2].Value != int64(5) {
		t.Fatalf("unscoped deadline query/args: %q %#v", state.query, state.args)
	}
	state.query = ""
	if _, err := store.ListExpiredPending(context.Background(), "", TargetBackup, "controller:pod-1", 5); err == nil || state.query != "" {
		t.Fatalf("invalid installation queried deadline candidates: err=%v query=%q", err, state.query)
	}
}

func TestDeadlineSweeperCanceledLeaderContextDoesNotListOrClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeDeadlineStore{listed: map[TargetKind][]DeadlineCandidate{}}
	sweeper := DeadlineSweeper{Store: store, InstallationID: "installation_test", Owner: "controller:pod-1", Policy: validPolicy(), Limit: 10}
	_, err := sweeper.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sweep error = %v, want context.Canceled", err)
	}
	if len(store.listKindOrder) != 0 || len(store.acquired) != 0 {
		t.Fatalf("canceled sweep touched store: list=%#v claim=%#v", store.listKindOrder, store.acquired)
	}
}

func TestDeadlineSweeperStopsListingWhenLeaderContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &fakeDeadlineStore{
		listed:       map[TargetKind][]DeadlineCandidate{},
		cancel:       cancel,
		cancelOnList: TargetBackup,
	}
	sweeper := DeadlineSweeper{Store: store, InstallationID: "installation_test", Owner: "controller:pod-1", Policy: validPolicy(), Limit: 10}
	_, err := sweeper.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sweep error = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(store.listKindOrder, []TargetKind{TargetBackup}) || len(store.acquired) != 0 {
		t.Fatalf("canceled sweep continued: list=%#v claim=%#v", store.listKindOrder, store.acquired)
	}
}
