package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync/atomic"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Forward every original SQL-model query unchanged, counting the actual query
// boundary rather than only the installer's auth-query subset. This is a
// component regression; it does not claim native SQL or another resource owner.
type consumerContextSQLTrace struct {
	base    driver.Connector
	queries atomic.Int32
}

func (c *consumerContextSQLTrace) Driver() driver.Driver { return c.base.Driver() }
func (c *consumerContextSQLTrace) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := c.base.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return &consumerContextTraceConn{Conn: conn, trace: c}, nil
}

type consumerContextTraceConn struct {
	driver.Conn
	trace *consumerContextSQLTrace
}

func (c *consumerContextTraceConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}
func (c *consumerContextTraceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.trace.queries.Add(1)
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func consumerWrongContext(mode string) (context.Context, context.CancelFunc) {
	if mode == "nil" {
		return nil, func() {}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	if mode == "canceled" {
		cancel()
	}
	return ctx, cancel
}
func consumerTraceTransaction(t *testing.T, ctx context.Context, f *authorityFixture) (*sql.Tx, *consumerContextSQLTrace) {
	t.Helper()
	f.s.auth.account = f.i.plan.Target.DatabaseAccount
	trace := &consumerContextSQLTrace{base: authorityConnector{f.s}}
	db := sql.OpenDB(trace)
	t.Cleanup(func() { db.Close() })
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx, trace
}

func TestCaptureConsumerLegacyContextRefusalIsTerminal(t *testing.T) {
	for _, mode := range []string{"foreign", "canceled", "nil"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f := newCaptureConsumerFixture(t, ctx)
			check, e := f.source.Prepare(ctx, f.f.grant, f.f.config)
			if e != nil {
				t.Fatal("actual independent source/probe preparation", e)
			}
			wrapper, ok := check.(*captureConsumerCheck)
			if !ok || wrapper.original == nil {
				t.Fatal("actual legacy consumer wrapper missing")
			}
			tx, trace := consumerTraceTransaction(t, ctx, f.f)
			beforeQueries, beforeSigns, beforeAPI := trace.queries.Load(), f.f.signs.Load(), f.apiCalls.Load()
			wrong, stopWrong := consumerWrongContext(mode)
			defer stopWrong()
			now := time.Now().UTC().Truncate(time.Microsecond)
			if wrapper.AuthorizeBootstrapOriginal(wrong, tx, f.f.grant, f.f.config, now) != ErrInstall {
				t.Fatal("wrong context accepted")
			}
			if wrapper.AuthorizeBootstrapOriginal(ctx, tx, f.f.grant, f.f.config, now) != ErrInstall {
				t.Fatal("restored original context revived rejected legacy preparation")
			}
			if wrapper.Recheck(ctx, tx, now) != ErrInstall {
				t.Fatal("legacy resource recheck revived rejected preparation")
			}
			if trace.queries.Load() != beforeQueries || f.f.signs.Load() != beforeSigns || f.apiCalls.Load() != beforeAPI {
				t.Fatal("rejected/restored legacy wrapper reached SQL/provider/API")
			}
		})
	}
}

// This named spy ALWAYS denies. Reaching Authorize also performs a counted SQL
// read, so tests detect both original-authority entry and any SQL boundary.
// It supplies no synthetic success or missing production owner implementation.
type consumerContextDeniedAuthority struct {
	tx    *sql.Tx
	calls atomic.Int32
}

func (a *consumerContextDeniedAuthority) Authorize(ctx context.Context, _ pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ pd.DomainRecord, _ time.Time) (pd.BootstrapConsumptionAdmission, error) {
	a.calls.Add(1)
	var account, server, database string
	_ = a.tx.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`).Scan(&account, &server, &database)
	return pd.BootstrapConsumptionAdmission{}, ErrInstall
}
func (a *consumerContextDeniedAuthority) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.calls.Add(1)
	return ErrInstall
}
func (a *consumerContextDeniedAuthority) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.calls.Add(1)
	return ErrInstall
}
func (a *consumerContextDeniedAuthority) Reserve(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.calls.Add(1)
	return ErrInstall
}
func (a *consumerContextDeniedAuthority) LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	a.calls.Add(1)
	return nil, ErrInstall
}
func (a *consumerContextDeniedAuthority) Recheck(context.Context, pd.BootstrapReadSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts, time.Time) error {
	a.calls.Add(1)
	return ErrInstall
}

func TestCaptureConsumerCandidateContextRefusalIsTerminal(t *testing.T) {
	for _, mode := range []string{"foreign", "canceled", "nil"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f := newCaptureConsumerFixture(t, ctx)
			check, e := f.source.Prepare(ctx, f.f.grant, f.f.config)
			if e != nil {
				t.Fatal("actual independent consumer source/probe preparation", e)
			}
			// Reuse the real successfully verified state in the actual production
			// candidate wrapper. Only the never-entered inner boundary is a spy.
			verified := check.(*captureConsumerCheck).state
			tx, trace := consumerTraceTransaction(t, ctx, f.f)
			inner := &consumerContextDeniedAuthority{tx: tx}
			wrapper := &captureConsumerSession{state: verified, original: inner}
			beforeQueries, beforeSigns, beforeAPI := trace.queries.Load(), f.f.signs.Load(), f.apiCalls.Load()
			wrong, stopWrong := consumerWrongContext(mode)
			defer stopWrong()
			now := time.Now().UTC().Truncate(time.Microsecond)
			if _, e := wrapper.Authorize(wrong, nil, pd.BootstrapConsumptionRequest{}, pd.DomainRecord{}, now); e != ErrInstall {
				t.Fatal("wrong candidate context accepted")
			}
			if _, e := wrapper.Authorize(ctx, nil, pd.BootstrapConsumptionRequest{}, pd.DomainRecord{}, now); e != ErrInstall {
				t.Fatal("restored original context revived candidate preparation")
			}
			if wrapper.Recheck(ctx, nil, pd.BootstrapConsumptionRequest{}, pd.BootstrapConsumptionFacts{Replayed: true}, now) != ErrInstall {
				t.Fatal("historical recheck revived rejected candidate state")
			}
			if inner.calls.Load() != 0 || trace.queries.Load() != beforeQueries || f.f.signs.Load() != beforeSigns || f.apiCalls.Load() != beforeAPI {
				t.Fatal("rejected/restored candidate wrapper entered original authority or SQL/provider/API")
			}
		})
	}
}
