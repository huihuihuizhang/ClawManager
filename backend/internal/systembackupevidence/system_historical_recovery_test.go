package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type historicalAuthorityFixture struct {
	channel ProducerEvidenceChannel
	sample  time.Time
	finish  *pd.RecoveryFinishRequest
	session SystemHistoricalAuthoritySession
}

func (a *historicalAuthorityFixture) PrepareHistoricalAuthority(_ context.Context, _ pd.RecoveryRequest, _ string, finish *pd.RecoveryFinishRequest) (SystemHistoricalAuthoritySession, ProducerEvidenceChannel, *time.Time, error) {
	a.finish = finish
	s := a.session
	if s == nil {
		s = &historicalAuthoritySessionFixture{}
	}
	return s, a.channel, &a.sample, nil
}

type historicalSQLFixture struct{ db *sql.DB }

func (s historicalSQLFixture) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, ErrDenied
}
func (s historicalSQLFixture) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}
func (s historicalSQLFixture) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, query, args...)
}
func (historicalSQLFixture) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, ErrDenied
}

type historicalAuthorizingSessionFixture struct {
	historicalAuthoritySessionFixture
	admission pd.RecoveryAdmission
	facts     SystemPeerFacts
	binding   string
}

func (s *historicalAuthorizingSessionFixture) Authorize(_ context.Context, _ pd.SQL, _ pd.RecoveryRequest, _ pd.Hash, _ string, facts SystemPeerFacts, binding string) (pd.RecoveryAdmission, error) {
	s.facts, s.binding = facts, binding
	return s.admission, nil
}

func (*historicalAuthorizingSessionFixture) Recheck(context.Context, pd.ReadSQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryAdmission, time.Time) error {
	return nil
}

// These methods are not used by the preparation test. They deny rather than
// accidentally standing in for current deployment or C provider authority.
type historicalAuthoritySessionFixture struct{}

func (*historicalAuthoritySessionFixture) LockInstallation(context.Context, pd.SQL, pd.RecoveryRequest) error {
	return ErrDenied
}
func (*historicalAuthoritySessionFixture) Authorize(context.Context, pd.SQL, pd.RecoveryRequest, pd.Hash, string, SystemPeerFacts, string) (pd.RecoveryAdmission, error) {
	return pd.RecoveryAdmission{}, ErrDenied
}
func (*historicalAuthoritySessionFixture) LockReferences(context.Context, pd.SQL, pd.RecoveryRequest, pd.HistoricalBindingRecord) error {
	return ErrDenied
}
func (*historicalAuthoritySessionFixture) Reserve(context.Context, pd.SQL, pd.RecoveryRequest, uint64) error {
	return ErrDenied
}
func (*historicalAuthoritySessionFixture) Audit(context.Context, pd.SQL, pd.RecoveryRequest, string) error {
	return ErrDenied
}
func (*historicalAuthoritySessionFixture) VerifyStat(context.Context, pd.SQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryFinishRequest) (pd.RecoveryStatAdmission, error) {
	return pd.RecoveryStatAdmission{}, ErrDenied
}
func (*historicalAuthoritySessionFixture) Recheck(context.Context, pd.ReadSQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryAdmission, time.Time) error {
	return ErrDenied
}

func TestSystemHistoricalRecoveryPreparationIsBoundToPeerAndEvidence(t *testing.T) {
	if _, err := new(SystemHistoricalRecoveryEnvironment).PrepareRecovery(context.Background(), pd.RecoveryRequest{}, "claim", nil); err != ErrDenied {
		t.Fatal("zero environment accepted", err)
	}
	auth, f, c := systemPeerFixture(t)
	peer, err := auth.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	a := &historicalAuthorityFixture{channel: ProducerEvidenceChannel{Root: "evidence", Store: KeyRef{Identity: strings.Repeat("a", 64), Version: "store-v1"}, Write: KeyRef{Identity: strings.Repeat("b", 64), Version: "write-v1"}, RecoveryProfileHash: strings.Repeat("c", 64)}, sample: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err := NewSystemHistoricalRecoveryEnvironment(auth, &SystemPeer{}, a); err != ErrDenied {
		t.Fatal("unbound peer accepted", err)
	}
	env, err := NewSystemHistoricalRecoveryEnvironment(auth, peer, a)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryRequest{Scope: c.Scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	if _, err := env.PrepareRecovery(context.Background(), r, "claim", nil); err != nil {
		t.Fatal("valid workload preparation rejected", err)
	}
	other := r
	other.EvidenceID = "sev_aaaaaaaa-2222-4333-8444-555555555555"
	if _, err := env.PrepareRecovery(context.Background(), other, "claim", nil); err != nil {
		t.Fatal("new exact evidence should create its own intent", err)
	}
	other.Scope.Database = "other"
	if _, err := env.PrepareRecovery(context.Background(), other, "claim", nil); err != ErrDenied {
		t.Fatal("cross-scope request accepted", err)
	}
	if _, err := env.PrepareRecovery(context.Background(), r, "publish", nil); err != ErrDenied {
		t.Fatal("producer operation accepted", err)
	}
	a.channel.RecoveryProfileHash = ""
	if _, err := env.PrepareRecovery(context.Background(), r, "claim", nil); err != ErrDenied {
		t.Fatal("missing historical profile accepted", err)
	}
	a.channel.RecoveryProfileHash = strings.Repeat("c", 64)
	auth.Close()
	if _, err := env.PrepareRecovery(context.Background(), r, "claim", nil); err != ErrAuth {
		t.Fatal("closed identity accepted", err)
	}
}

func TestSystemHistoricalRecoveryCopiesFrozenInputs(t *testing.T) {
	auth, f, c := systemPeerFixture(t)
	peer, err := auth.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	a := &historicalAuthorityFixture{channel: ProducerEvidenceChannel{Root: "evidence", Store: KeyRef{Identity: strings.Repeat("a", 64), Version: "store-v1"}, Write: KeyRef{Identity: strings.Repeat("b", 64), Version: "write-v1"}, RecoveryProfileHash: strings.Repeat("c", 64)}, sample: time.Now().UTC().Truncate(time.Microsecond)}
	env, err := NewSystemHistoricalRecoveryEnvironment(auth, peer, a)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryRequest{Scope: c.Scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	version := pd.Text("object-version")
	finish := pd.RecoveryFinishRequest{State: "ready", ImmutableVersion: &version}
	prepared, err := env.PrepareRecovery(context.Background(), r, "finish", &finish)
	if err != nil {
		t.Fatal(err)
	}
	version = "changed"
	a.sample = a.sample.Add(time.Minute)
	s := prepared.Session.(*systemHistoricalRecoverySession)
	if *a.finish.ImmutableVersion != "object-version" || *s.finish.ImmutableVersion != "object-version" || prepared.CapacityObservedAt.Equal(a.sample) {
		t.Fatal("authority or capacity input was not frozen")
	}
	if _, err := s.LockEvidence(context.Background(), nil, r, pd.HistoricalBindingRecord{Scope: r.Scope, Evidence: pd.EvidenceBinding{EvidenceID: r.EvidenceID}}); err != ErrDenied {
		t.Fatal("L8 accepted before L2 authorization", err)
	}
}

func TestSystemHistoricalRecoveryAuthorizesCurrentWorkloadIdentity(t *testing.T) {
	auth, f, c := systemPeerFixture(t)
	requestCtx, endRequest := context.WithCancel(f.request.Context())
	defer endRequest()
	f.request = f.request.WithContext(requestCtx)
	peer, err := auth.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := pd.Hash(strings.Repeat("d", 64))
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := &historicalAuthorizingSessionFixture{admission: pd.RecoveryAdmission{VerifiedRequestHash: requestHash, IdentityHash: pd.Hash(auth.workload), RevocationEpoch: "1", IdentityExpiresAt: systemPublicationTimestamp(now.Add(time.Minute)), DeploymentExpiresAt: systemPublicationTimestamp(now.Add(time.Minute)), StatAllowed: true}}
	a := &historicalAuthorityFixture{channel: ProducerEvidenceChannel{Root: "evidence", Store: KeyRef{Identity: strings.Repeat("a", 64), Version: "store-v1"}, Write: KeyRef{Identity: strings.Repeat("b", 64), Version: "write-v1"}, RecoveryProfileHash: strings.Repeat("c", 64)}, sample: now, session: session}
	env, err := NewSystemHistoricalRecoveryEnvironment(auth, peer, a)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryRequest{Scope: c.Scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	prepared, err := env.PrepareRecovery(context.Background(), r, "claim", nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func() historicalSQLFixture {
		f.db.plan = []authorityQuery{{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{time.Now().UTC().Truncate(time.Microsecond)}}}
		f.db.index = 0
		return historicalSQLFixture{db: f.c.DB}
	}
	s := prepared.Session.(*systemHistoricalRecoverySession)
	if _, err := s.Authorize(context.Background(), check(), r, requestHash, "claim"); err != nil || session.facts.WorkloadIdentityHash != auth.workload || session.binding != s.intent.binding {
		t.Fatal("current identity binding rejected", err)
	}
	if _, err := s.Authorize(context.Background(), check(), r, requestHash, "claim"); err != ErrDenied {
		t.Fatal("single-use authority session accepted a second authorization", err)
	}
	loadPrepared, err := env.PrepareRecovery(context.Background(), r, "load", nil)
	if err != nil {
		t.Fatal(err)
	}
	load := loadPrepared.Session.(*systemHistoricalRecoverySession)
	if _, err := load.Authorize(context.Background(), check(), r, requestHash, "load"); err != nil {
		t.Fatal("load authorization rejected", err)
	}
	h := pd.HistoricalBindingRecord{Scope: r.Scope, Evidence: pd.EvidenceBinding{EvidenceID: r.EvidenceID}}
	if err := load.Recheck(context.Background(), nil, r, h, time.Now().UTC().Truncate(time.Microsecond)); err != ErrIntegrity {
		t.Fatal("historical load accepted without L8 original evidence lock", err)
	}
	load.binding = strings.Repeat("f", 64)
	if err := load.Recheck(context.Background(), nil, r, h, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("changed evidence-purpose binding accepted at final guard", err)
	}
	load.binding = session.binding
	endRequest()
	if err := load.Recheck(context.Background(), nil, r, h, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("completed request accepted at final guard", err)
	}
	// Each negative admission uses a fresh session, so it reaches the actual
	// identity/deadline comparison instead of the single-use check above.
	auth, f, c = systemPeerFixture(t)
	peer, err = auth.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	authz := func() *systemHistoricalRecoverySession {
		env, e := NewSystemHistoricalRecoveryEnvironment(auth, peer, a)
		if e != nil {
			t.Fatal(e)
		}
		prepared, e := env.PrepareRecovery(context.Background(), r, "claim", nil)
		if e != nil {
			t.Fatal(e)
		}
		return prepared.Session.(*systemHistoricalRecoverySession)
	}
	session.admission.IdentityHash = pd.Hash(strings.Repeat("e", 64))
	if _, err := authz().Authorize(context.Background(), check(), r, requestHash, "claim"); err != ErrDenied {
		t.Fatal("different workload admitted", err)
	}
	session.admission.IdentityHash = pd.Hash(auth.workload)
	session.admission.IdentityExpiresAt = systemPublicationTimestamp(now.Add(time.Hour))
	if _, err := authz().Authorize(context.Background(), check(), r, requestHash, "claim"); err != ErrDenied {
		t.Fatal("identity deadline extended beyond certificate", err)
	}
	session.admission.IdentityExpiresAt = systemPublicationTimestamp(now.Add(time.Minute))
	session.admission.RevocationEpoch = "0"
	if _, err := authz().Authorize(context.Background(), check(), r, requestHash, "claim"); err != ErrDenied {
		t.Fatal("missing current revocation epoch accepted", err)
	}
	session.admission.RevocationEpoch = "1"
	session.admission.DeploymentExpiresAt = systemPublicationTimestamp(now.Add(-time.Second))
	if _, err := authz().Authorize(context.Background(), check(), r, requestHash, "claim"); err != ErrDenied {
		t.Fatal("expired current deployment accepted", err)
	}
}
