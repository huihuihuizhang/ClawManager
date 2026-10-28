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

func recoveryManagerGuardFixture(t *testing.T) (*RecoveryManagerRowGuard, RecoveryManagerPeerFacts, *authorityDB, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_test"}
	hash := func(c string) string { return strings.Repeat(c, 64) }
	facts := RecoveryManagerPeerFacts{Scope: scope, IdentityHash: hash("a"), IssuerIdentityHash: hash("b"), CredentialBindingHash: hash("c"), ExpiresAt: now.Add(time.Hour)}
	g, err := NewRecoveryManagerRowGuard(scope, facts)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pd.RecoveryScopeKey(scope)
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
	values := []driver.Value{string(scope.Installation), decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), true, true, false, true, now.Add(time.Hour), nil, int64(1)}
	db := &authorityDB{t: t, plan: []authorityQuery{
		{match: recoveryManagerSelect + " FOR UPDATE", args: []driver.Value{key, decode(facts.IdentityHash)}, values: values},
		{match: recoveryManagerSelect, args: []driver.Value{key, decode(facts.IdentityHash)}, values: values},
	}}
	return g, facts, db, now
}

func TestRecoveryManagerRowGuardSQL(t *testing.T) {
	g, facts, scripted, now := recoveryManagerGuardFixture(t)
	db := sql.OpenDB(scripted)
	t.Cleanup(func() { db.Close() })
	tx := historicalSQLFixture{db: db}
	if err := g.Lock(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	for _, permission := range []RecoveryManagerPermission{RecoveryManagerReadFence, RecoveryManagerWriteFence} {
		if err := g.Admit(facts, permission, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Admit(facts, RecoveryManagerManageDeployment, now); err != ErrDenied {
		t.Fatalf("management admitted: %v", err)
	}
	if err := g.Recheck(context.Background(), tx, facts, RecoveryManagerWriteFence, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if scripted.index != len(scripted.plan) {
		t.Fatalf("incomplete SQL checks: %d/%d", scripted.index, len(scripted.plan))
	}
	changed := facts
	changed.CredentialBindingHash = strings.Repeat("d", 64)
	if err := g.Admit(changed, RecoveryManagerWriteFence, now); err != ErrDenied {
		t.Fatalf("changed credential admitted: %v", err)
	}
	if err := g.Admit(facts, RecoveryManagerWriteFence, now.Add(time.Hour)); err != ErrDenied {
		t.Fatalf("expired row admitted: %v", err)
	}
}

func TestRecoveryManagerRowGuardRejectsDrift(t *testing.T) {
	for name, mutate := range map[string]func([]driver.Value){
		"revoked":    func(v []driver.Value) { v[8] = time.Now().UTC().Truncate(time.Microsecond) },
		"disabled":   func(v []driver.Value) { v[6] = false },
		"permission": func(v []driver.Value) { v[4] = false },
		"version":    func(v []driver.Value) { v[9] = int64(2) },
	} {
		t.Run(name, func(t *testing.T) {
			g, facts, scripted, now := recoveryManagerGuardFixture(t)
			values := append([]driver.Value(nil), scripted.plan[1].values...)
			mutate(values)
			scripted.plan[1].values = values
			db := sql.OpenDB(scripted)
			t.Cleanup(func() { db.Close() })
			tx := historicalSQLFixture{db: db}
			if err := g.Lock(context.Background(), tx); err != nil {
				t.Fatal(err)
			}
			if err := g.Recheck(context.Background(), tx, facts, RecoveryManagerWriteFence, now); err != ErrDenied {
				t.Fatalf("changed row admitted: %v", err)
			}
		})
	}
}
