package systembackupinstallationowner

import (
	"context"
	"database/sql"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestCaptureSigningIdentityOnlyCandidateRetainsCurrentSourceWithoutNewUse(t *testing.T) {
	for _, history := range []bool{true, false} {
		f := newCaptureCandidateFixture(t)
		identity, e := NewCaptureSigningIdentityOnlyValidator(f.a.capture.pin, f.a.capture.files)
		if e != nil {
			t.Fatal(e)
		}
		a, e := identity.IdentityOnlyCandidateAuthority(f.original)
		if e != nil {
			t.Fatal(e)
		}
		prepared, e := a.PrepareBootstrapCandidates(f.ctx, f.grant, f.config, f.request)
		if e != nil || *f.signs != 0 {
			t.Fatal("identity-only preparation required physical observer", e)
		}
		f.state.now = time.Now().UTC().Truncate(time.Microsecond)
		db := sql.OpenDB(captureGuardConnector{state: f.state})
		policy := &captureCandidatePolicy{fixture: f, session: prepared.Session, replay: history}
		runner, e := pd.NewTransactions(db, f.request.Scope, policy)
		if e != nil {
			db.Close()
			t.Fatal(e)
		}
		tx, e := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if e != nil {
			db.Close()
			t.Fatal(e)
		}
		e = runner.GuardInTx(f.ctx, tx, func(ctx context.Context, guard *pd.Transaction) error {
			return prepared.Session.Recheck(ctx, guard, f.request, pd.BootstrapConsumptionFacts{Replayed: history}, f.state.now)
		})
		_ = tx.Rollback()
		_ = db.Close()
		if history && e != nil {
			t.Fatal("authenticated exact history preempted by absent physical observer", e)
		}
		if !history && e == nil {
			t.Fatal("identity-only source authorized fresh resource use")
		}
		if *f.signs != 0 {
			t.Fatal("identity-only candidate performed provider signing")
		}
	}
}
