package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Original database/sql protocol transport, NOT native SQL/lock evidence. The
// caller-owned transaction and pd.Transaction/SampleTime are the real factory.
type bootstrapSourceIdentityClock struct {
	f         *authorityFixture
	samples   int
	expireAt  int
	until     time.Time
	lateReads int
}
type bootstrapSourceIdentityConnector struct{ state *bootstrapSourceIdentityClock }
type bootstrapSourceIdentityConn struct {
	driver.Conn
	state *bootstrapSourceIdentityClock
}
func (c bootstrapSourceIdentityConnector) Driver() driver.Driver { return authDriver{} }
func (c bootstrapSourceIdentityConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (authorityConnector{s: c.state.f.s}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &bootstrapSourceIdentityConn{Conn: base, state: c.state}, nil
}
func (c *bootstrapSourceIdentityConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}
func (c *bootstrapSourceIdentityConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.state
	if query == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))" {
		return row(m.f.s.auth.server, m.f.i.plan.Target.Database, time.Now().UTC().Truncate(time.Microsecond), int64(0)), nil
	}
	if query == "SELECT UTC_TIMESTAMP(6)" {
		m.samples++
		if m.expireAt != 0 && m.samples == m.expireAt {
			// Last sample inside the ORIGINAL capture guard is still legal.
			// The actual local-file tail follows; the next controlled SQL sample
			// is after expiry. Removing B's final sample makes this test fail.
			return row(m.until.Add(-time.Microsecond)), nil
		}
		if m.expireAt != 0 && m.samples > m.expireAt {
			m.lateReads++
			return row(m.until.Add(time.Microsecond)), nil
		}
		return row(time.Now().UTC().Truncate(time.Microsecond)), nil
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

type bootstrapSourceIdentityPolicy struct{ f *authorityFixture }
func (p bootstrapSourceIdentityPolicy) LockAndAuthorize(ctx context.Context, q pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	var username, role, provider string
	var active bool
	if q.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE", p.f.grant.UserID).Scan(&username, &role, &active, &provider) != nil || username != p.f.grant.Username || role != "admin" || !active || provider != "local" {
		return pd.GuardPlan{}, ErrInstall
	}
	// This test policy supplies only the admin prefix, not A20/other owners.
	// B's original signed record must independently enforce its tighter Until.
	return pd.GuardPlan{BindingHash: pd.Hash(strings.Repeat("a", 64)), Deadlines: []time.Time{p.f.record.Until.Add(time.Minute)}}, nil
}
func (bootstrapSourceIdentityPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func runBootstrapSourceIdentityGuard(t *testing.T, ctx context.Context, c *captureConsumerFixture, work func(*pd.Transaction, *bootstrapSourceIdentityClock) error) error {
	t.Helper()
	c.f.s.auth.account = c.f.i.plan.Target.DatabaseAccount
	model := &bootstrapSourceIdentityClock{f: c.f, until: c.f.record.Until}
	db := sql.OpenDB(bootstrapSourceIdentityConnector{state: model})
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	scope := pd.Scope{Installation: pd.Installation(c.f.record.Target.InstallationID), ServerUUID: pd.ServerUUID(c.f.record.Target.ServerUUID), Database: pd.Database(c.f.record.Target.Database)}
	guard, err := pd.NewTransactions(db, scope, bootstrapSourceIdentityPolicy{f: c.f})
	if err != nil {
		t.Fatal(err)
	}
	return guard.GuardInTx(ctx, tx, func(_ context.Context, q *pd.Transaction) error { return work(q, model) })
}

func TestBootstrapSourceRegistryConsumerFinalFilesPrecedeLastControlledSample(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, p, _ := newAuthenticatedBootstrapSourceIdentity(t, ctx, 6*time.Second)
	requests := c.apiCalls.Load()
	err := runBootstrapSourceIdentityGuard(t, ctx, c, func(q *pd.Transaction, model *bootstrapSourceIdentityClock) error {
		if _, err := p.AuthorizeIdentity(ctx, q); err != nil {
			t.Fatal("positive actual source identity must reach original SQL guard", err)
		}
		if err := p.RecheckIdentity(ctx, q); err != nil {
			t.Fatal("positive original controlled tail", err)
		}
		// Measure the actual original guard in isolation, not B's final-sample
		// count. Thus the expiration injection remains at the guard's LAST legal
		// sample even if B's post-file sample is accidentally removed later.
		before := model.samples
		if err := p.guard.RecheckCandidateIdentity(ctx, q); err != nil {
			t.Fatal("positive original capture tail for fault-point calibration", err)
		}
		guardSamples := model.samples - before
		if guardSamples == 0 {
			t.Fatal("actual capture guard did not sample controlled SQL time")
		}
		model.expireAt = model.samples + 1 + guardSamples
		for n := 0; n < 32; n++ {
			p.files = append(p.files, p.files[0])
		}
		err := p.RecheckIdentity(ctx, q)
		if model.lateReads != 1 || model.samples != model.expireAt+1 {
			t.Fatal("expiry must reach B's last SQL sample AFTER the actual local-file tail", model.samples, model.expireAt, model.lateReads)
		}
		if err == nil || !p.failed.Load() {
			t.Fatal("last local tail crossed signed SQL deadline without poisoning original source")
		}
		model.expireAt = 0
		if p.RecheckIdentity(ctx, q) == nil {
			t.Fatal("restoring the original clock revived failed source identity")
		}
		if _, err := q.SampleTime(ctx); err == nil {
			t.Fatal("resetting transport clock bypassed original D clock floor/failure latch")
		}
		return errors.New("expected source deadline rejection")
	})
	if err == nil || c.apiCalls.Load() != requests {
		t.Fatal("guard unexpectedly succeeded or performed provider I/O under SQL", err)
	}
}

func TestBootstrapSourceRegistryConsumerContextOnlyFileCheckRefusesSQLPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, p, d := newAuthenticatedBootstrapSourceIdentity(t, ctx, 6*time.Second)
	err := runBootstrapSourceIdentityGuard(t, ctx, c, func(q *pd.Transaction, _ *bootstrapSourceIdentityClock) error {
		if _, err := p.AuthorizeIdentity(ctx, q); err != nil {
			t.Fatal("positive actual SQL identity", err)
		}
		if p.RecheckSelectedFile(ctx, d.Connections[0].Credential) == nil || !p.failed.Load() || p.RecheckIdentity(ctx, q) == nil {
			t.Fatal("context-only private file check bypassed controlled SQL view or revived original attempt")
		}
		return errors.New("expected context-only file API rejection")
	})
	if err == nil {
		t.Fatal("context-only file API admitted after SQL prefix")
	}
}
