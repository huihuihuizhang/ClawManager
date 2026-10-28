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

func historicalDeploymentFixture(t *testing.T) (*SystemHistoricalDeploymentGuard, SystemPeerFacts, pd.RecoveryAdmission, *authorityDB, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Hour)
	scope := pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_test"}
	hash := func(c string) string { return strings.Repeat(c, 64) }
	facts := SystemPeerFacts{
		Scope: scope, WorkloadIdentityHash: hash("a"), IssuerIdentityHash: hash("b"), SubjectHash: hash("c"),
		ActorIdentityHash: hash("d"), AdmissionHash: hash("e"), ClientCASHA256: hash("f"),
		CertificateSHA256: hash("0"), ExpiresAt: until,
	}
	profile, manager := hash("1"), hash("2")
	guard, err := NewSystemHistoricalDeploymentGuard(scope, profile, manager)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(s string) driver.Value {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	values := []driver.Value{string(scope.Installation), decode(facts.WorkloadIdentityHash), decode(facts.IssuerIdentityHash),
		decode(facts.SubjectHash), decode(manager), decode(facts.ActorIdentityHash), decode(facts.AdmissionHash),
		decode(facts.ClientCASHA256), decode(facts.CertificateSHA256), decode(profile), true, int64(1), until, int64(1)}
	key, err := pd.RecoveryScopeKey(scope)
	if err != nil {
		t.Fatal(err)
	}
	db := &authorityDB{t: t, plan: []authorityQuery{
		{match: "ORDER BY origin_installation_id FOR UPDATE", values: []driver.Value{string(scope.Installation)}},
		{match: "WHERE origin_installation_id=? FOR UPDATE", args: []driver.Value{string(scope.Installation)}, values: []driver.Value{string(scope.Installation)}},
		{match: historicalDeploymentSelect + " FOR UPDATE", args: []driver.Value{key, string(scope.Installation)}, values: values},
		{match: historicalDeploymentSelect, args: []driver.Value{key, string(scope.Installation)}, values: values},
	}}
	admission := pd.RecoveryAdmission{IdentityHash: pd.Hash(facts.WorkloadIdentityHash), RevocationEpoch: "1",
		IdentityExpiresAt: systemPublicationTimestamp(until), DeploymentExpiresAt: systemPublicationTimestamp(until), StatAllowed: true}
	return guard, facts, admission, db, now
}

func TestSystemHistoricalDeploymentGuardSQL(t *testing.T) {
	guard, facts, admission, scripted, now := historicalDeploymentFixture(t)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	tx := historicalSQLFixture{db: db}
	if err := guard.Lock(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err := guard.Admit(facts, admission, now); err != nil {
		t.Fatal(err)
	}
	if err := guard.Recheck(context.Background(), tx, facts, admission, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if scripted.index != len(scripted.plan) {
		t.Fatalf("incomplete SQL checks: %d/%d", scripted.index, len(scripted.plan))
	}
	for name, change := range map[string]func(*SystemPeerFacts, *pd.RecoveryAdmission){
		"subject":     func(f *SystemPeerFacts, _ *pd.RecoveryAdmission) { f.SubjectHash = strings.Repeat("3", 64) },
		"certificate": func(f *SystemPeerFacts, _ *pd.RecoveryAdmission) { f.CertificateSHA256 = strings.Repeat("3", 64) },
		"epoch":       func(_ *SystemPeerFacts, a *pd.RecoveryAdmission) { a.RevocationEpoch = "2" },
		"deadline": func(_ *SystemPeerFacts, a *pd.RecoveryAdmission) {
			a.DeploymentExpiresAt = systemPublicationTimestamp(now.Add(2 * time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, a := facts, admission
			change(&f, &a)
			if err := guard.Admit(f, a, now); err != ErrDenied {
				t.Fatalf("changed admission accepted: %v", err)
			}
		})
	}
	if err := guard.Admit(facts, admission, now.Add(time.Hour)); err != ErrDenied {
		t.Fatalf("expired deployment accepted: %v", err)
	}
}

func TestSystemHistoricalDeploymentGuardRejectsCurrentRowDrift(t *testing.T) {
	for name, mutate := range map[string]func([]driver.Value){
		"disabled": func(v []driver.Value) { v[10] = false },
		"version":  func(v []driver.Value) { v[13] = int64(2) },
		"subject":  func(v []driver.Value) { v[3] = make([]byte, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			guard, facts, admission, scripted, now := historicalDeploymentFixture(t)
			values := append([]driver.Value(nil), scripted.plan[3].values...)
			mutate(values)
			scripted.plan[3].values = values
			db := sql.OpenDB(scripted)
			t.Cleanup(func() { db.Close() })
			tx := historicalSQLFixture{db: db}
			if err := guard.Lock(context.Background(), tx); err != nil {
				t.Fatal(err)
			}
			if err := guard.Recheck(context.Background(), tx, facts, admission, now); err != ErrDenied {
				t.Fatalf("changed row accepted: %v", err)
			}
		})
	}
}
