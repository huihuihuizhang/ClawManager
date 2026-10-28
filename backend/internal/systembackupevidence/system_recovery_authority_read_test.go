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

func recoveryAuthorityReadAdapterFixture(t *testing.T, read bool) (pd.RecoveryAuthorityReadSession, pd.RecoveryAuthorityReadRequest, *authorityDB, time.Time) {
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
		read, false, false, true, now.Add(time.Minute), nil, int64(1)}
	scripted := &authorityDB{t: t, plan: []authorityQuery{
		{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{now}},
		{match: recoveryManagerSelect + " FOR UPDATE", args: []driver.Value{key, decode(facts.IdentityHash)}, values: row},
		{match: recoveryManagerSelect, args: []driver.Value{key, decode(facts.IdentityHash)}, values: row},
	}}
	env, err := NewSystemRecoveryAuthorityReadEnvironment(auth, peer)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryAuthorityReadRequest{Scope: c.Scope, Nonce: "manager-read-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	s, err := env.PrepareRecoveryAuthorityRead(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, scripted, now
}

func TestSystemRecoveryAuthorityReadBindsCurrentPermission(t *testing.T) {
	s, r, scripted, now := recoveryAuthorityReadAdapterFixture(t, true)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	tx := historicalSQLFixture{db: db}
	hash, err := pd.RecoveryAuthorityReadHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LockManagerRead(context.Background(), tx, r, nil, pd.Hash(strings.Repeat("0", 64))); err != ErrDenied {
		t.Fatalf("wrong read hash accepted: %v", err)
	}
	a, err := s.LockManagerRead(context.Background(), tx, r, nil, hash)
	if err != nil || !a.ReadAllowed || a.VerifiedRequestHash != hash {
		t.Fatal("current read permission rejected", err)
	}
	if err := s.RecheckManagerRead(context.Background(), tx, r, now); err != nil {
		t.Fatal(err)
	}
	if scripted.index != len(scripted.plan) {
		t.Fatal("manager row final read skipped")
	}
	changed := r
	changed.Nonce = "other-read"
	if err := s.RecheckManagerRead(context.Background(), tx, changed, now); err != ErrDenied {
		t.Fatalf("changed read request accepted: %v", err)
	}
}

func TestSystemRecoveryAuthorityReadRejectsMissingGrant(t *testing.T) {
	s, r, scripted, _ := recoveryAuthorityReadAdapterFixture(t, false)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	hash, err := pd.RecoveryAuthorityReadHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LockManagerRead(context.Background(), historicalSQLFixture{db: db}, r, nil, hash); err != ErrDenied {
		t.Fatalf("absent read grant accepted: %v", err)
	}
}
