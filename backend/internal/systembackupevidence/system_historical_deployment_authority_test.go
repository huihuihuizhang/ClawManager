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

type deploymentBoundInnerSession struct {
	historicalAuthoritySessionFixture
	admission        pd.RecoveryAdmission
	locked           bool
	referencesLocked bool
	checked          bool
}

func (s *deploymentBoundInnerSession) LockInstallation(context.Context, pd.SQL, pd.RecoveryRequest) error {
	s.locked = true
	return nil
}

func (s *deploymentBoundInnerSession) Authorize(_ context.Context, _ pd.SQL, _ pd.RecoveryRequest, hash pd.Hash, _ string, _ SystemPeerFacts, _ string) (pd.RecoveryAdmission, error) {
	if !s.locked {
		return pd.RecoveryAdmission{}, ErrDenied
	}
	a := s.admission
	a.VerifiedRequestHash = hash
	return a, nil
}

func (s *deploymentBoundInnerSession) LockReferences(context.Context, pd.SQL, pd.RecoveryRequest, pd.HistoricalBindingRecord) error {
	if !s.locked {
		return ErrDenied
	}
	s.referencesLocked = true
	return nil
}

func (s *deploymentBoundInnerSession) Recheck(context.Context, pd.ReadSQL, pd.RecoveryRequest, pd.HistoricalBindingRecord, pd.RecoveryAdmission, time.Time) error {
	if !s.referencesLocked {
		return ErrDenied
	}
	s.checked = true
	return nil
}

func TestDeploymentBoundHistoricalAuthorityChecksL1aAndFinalGuard(t *testing.T) {
	guard, facts, admission, scripted, now := historicalDeploymentFixture(t)
	key, err := pd.RecoveryScopeKey(facts.Scope)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := hex.DecodeString(string(admission.IdentityHash))
	if err != nil {
		t.Fatal(err)
	}
	currentDeployment := scripted.plan[3]
	l2Values := []driver.Value{int64(1), nil, int64(1)}
	scripted.plan = append(scripted.plan[:3],
		authorityQuery{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{now}},
		authorityQuery{match: systemHistoricalRevocationSelect + " FOR UPDATE", args: []driver.Value{key, identity}, values: l2Values},
		currentDeployment,
		authorityQuery{match: systemHistoricalRevocationSelect, args: []driver.Value{key, identity}, values: l2Values})
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	inner := &deploymentBoundInnerSession{admission: admission}
	authority := &historicalAuthorityFixture{session: inner, channel: ProducerEvidenceChannel{
		Root: "evidence", Store: KeyRef{Identity: strings.Repeat("a", 64), Version: "store-v1"},
		Write: KeyRef{Identity: strings.Repeat("b", 64), Version: "write-v1"}, RecoveryProfileHash: guard.profile,
	}}
	bound, err := NewSystemDeploymentBoundHistoricalAuthority(authority, guard.managementIssuer)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryRequest{Scope: facts.Scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	s, _, _, err := bound.PrepareHistoricalAuthority(context.Background(), r, "load", nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := historicalSQLFixture{db: db}
	if _, err := s.Authorize(context.Background(), tx, r, "request-hash", "load", facts, "binding"); err != ErrDenied {
		t.Fatalf("authorization before deployment lock accepted: %v", err)
	}
	if err := s.LockInstallation(context.Background(), tx, r); err != nil {
		t.Fatal(err)
	}
	a, err := s.Authorize(context.Background(), tx, r, "request-hash", "load", facts, "binding")
	if err != nil {
		t.Fatal(err)
	}
	h := pd.HistoricalBindingRecord{Scope: facts.Scope}
	if err := s.LockReferences(context.Background(), tx, r, h); err != nil {
		t.Fatal(err)
	}
	if err := s.Recheck(context.Background(), tx, r, h, a, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !inner.checked || scripted.index != len(scripted.plan) {
		t.Fatal("current deployment or delegated final guard was skipped")
	}
}

func TestDeploymentBoundHistoricalAuthorityRejectsMismatchedEpoch(t *testing.T) {
	guard, facts, admission, scripted, now := historicalDeploymentFixture(t)
	scripted.plan = append(scripted.plan[:3], authorityQuery{match: "SELECT UTC_TIMESTAMP(6)", values: []driver.Value{now}})
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	admission.RevocationEpoch = "2"
	inner := &deploymentBoundInnerSession{admission: admission}
	authority := &historicalAuthorityFixture{session: inner, channel: ProducerEvidenceChannel{
		Root: "evidence", Store: KeyRef{Identity: strings.Repeat("a", 64), Version: "store-v1"},
		Write: KeyRef{Identity: strings.Repeat("b", 64), Version: "write-v1"}, RecoveryProfileHash: guard.profile,
	}}
	bound, err := NewSystemDeploymentBoundHistoricalAuthority(authority, guard.managementIssuer)
	if err != nil {
		t.Fatal(err)
	}
	r := pd.RecoveryRequest{Scope: facts.Scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	s, _, _, err := bound.PrepareHistoricalAuthority(context.Background(), r, "load", nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := historicalSQLFixture{db: db}
	if err := s.LockInstallation(context.Background(), tx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(context.Background(), tx, r, "request-hash", "load", facts, "binding"); err != ErrDenied {
		t.Fatalf("deployment and revocation epochs diverged: %v", err)
	}
}
