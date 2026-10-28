package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type recoveryAuthorityDecisionFixture struct {
	next   pd.RecoveryDeploymentProposal
	calls  int
	audits []string
}

func (f *recoveryAuthorityDecisionFixture) NextDeployment(_ context.Context, _ pd.SQL, _ pd.RecoveryAuthorityRequest, _ *pd.RecoveryDeploymentProposal, _ RecoveryManagerPeerFacts) (pd.RecoveryDeploymentProposal, error) {
	f.calls++
	return f.next, nil
}
func (f *recoveryAuthorityDecisionFixture) Audit(_ context.Context, _ pd.SQL, _ pd.RecoveryAuthorityRequest, stage string) error {
	f.audits = append(f.audits, stage)
	return nil
}

func recoveryAuthorityAdapterFixture(t *testing.T, manage bool) (pd.RecoveryAuthoritySession, pd.RecoveryAuthorityRequest, *authorityDB, *recoveryAuthorityDecisionFixture, *RecoveryManagerPeerAuthenticator, time.Time) {
	t.Helper()
	_, peerFixture, c := systemPeerFixture(t)
	mapping := RecoveryManagerPeerConfig{Scope: c.Scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256, CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Close)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts, err := auth.Check(context.Background(), peer, c.Scope, now)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(h string) driver.Value {
		v, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	key, err := pd.RecoveryScopeKey(c.Scope)
	if err != nil {
		t.Fatal(err)
	}
	row := []driver.Value{string(c.Scope.Installation), decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash),
		true, true, manage, true, now.Add(time.Minute), nil, int64(1)}
	scripted := &authorityDB{t: t, plan: []authorityQuery{
		{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{now}},
		{match: recoveryManagerSelect + " FOR UPDATE", args: []driver.Value{key, decode(facts.IdentityHash)}, values: row},
		{match: recoveryManagerSelect, args: []driver.Value{key, decode(facts.IdentityHash)}, values: row},
		{match: recoveryManagerSelect, args: []driver.Value{key, decode(facts.IdentityHash)}, values: row},
	}}
	decision := &recoveryAuthorityDecisionFixture{next: pd.RecoveryDeploymentProposal{ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash)}}
	env, err := NewSystemRecoveryAuthorityEnvironment(auth, peer, decision)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{
		Scope: c.Scope, Operation: "register", IdentityHash: pd.Hash(strings.Repeat("a", 64)),
		ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(strings.Repeat("b", 64)),
	}, ExpectedDeploymentVersion: "0", Nonce: "manager-register-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	s, err := env.PrepareRecoveryAuthority(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, scripted, decision, auth, now
}

func TestSystemRecoveryAuthorityBindsManagerRowAndFinalGuard(t *testing.T) {
	s, r, scripted, decision, _, now := recoveryAuthorityAdapterFixture(t, true)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	tx := historicalSQLFixture{db: db}
	if err := s.Audit(context.Background(), tx, r, "intent"); err != ErrDenied {
		t.Fatalf("audit before manager admission accepted: %v", err)
	}
	a, err := s.LockManager(context.Background(), tx, r, nil)
	if err != nil || !a.WriteFenceAllowed || !a.ManageAllowed || decision.calls != 1 {
		t.Fatal("current manager admission rejected", err)
	}
	want, err := pd.RecoveryAuthorityHash(r)
	if err != nil || a.VerifiedRequestHash != want {
		t.Fatal("management request hash not bound", err)
	}
	if err := s.Audit(context.Background(), tx, r, "intent"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecheckManager(context.Background(), tx, r, now); err != nil {
		t.Fatal(err)
	}
	if scripted.index != len(scripted.plan) || len(decision.audits) != 1 {
		t.Fatal("management row or audit was skipped")
	}
	changed := r
	changed.Nonce = "other-nonce"
	if err := s.Audit(context.Background(), tx, changed, "result"); err != ErrDenied {
		t.Fatalf("changed management request accepted: %v", err)
	}
}

func TestSystemRecoveryAuthorityRejectsMissingManagePermission(t *testing.T) {
	s, r, scripted, decision, _, _ := recoveryAuthorityAdapterFixture(t, false)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	if _, err := s.LockManager(context.Background(), historicalSQLFixture{db: db}, r, nil); err != ErrDenied {
		t.Fatalf("manager without deployment permission admitted: %v", err)
	}
	if decision.calls != 0 {
		t.Fatal("policy proposal called before current grant")
	}
}
