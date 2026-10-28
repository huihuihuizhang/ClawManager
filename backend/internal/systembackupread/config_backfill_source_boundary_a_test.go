package systembackupread

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

// Synchronous callbacks mutate only the caller-owned slice. This is not a
// concurrent data-race test and does not claim to authenticate source provenance.
type backfillSourceBoundary struct {
	fixture *configFixture
	hooks   map[string]func()
	commits int
}

func (b *backfillSourceBoundary) call(stage string) {
	if f := b.hooks[stage]; f != nil {
		f()
	}
}
func (b *backfillSourceBoundary) AuthorizeRead(ctx context.Context, tx *sql.Tx) (string, error) {
	b.call("authorize")
	return b.fixture.AuthorizeRead(ctx, tx)
}
func (b *backfillSourceBoundary) RecheckRead(ctx context.Context, tx *sql.Tx, installation string) error {
	b.call("recheck")
	return b.fixture.RecheckRead(ctx, tx, installation)
}
func (b *backfillSourceBoundary) Connect(context.Context) (driver.Conn, error) {
	return &backfillSourceBoundaryConn{configConn: &configConn{b.fixture}, boundary: b}, nil
}
func (*backfillSourceBoundary) Driver() driver.Driver { return pageDriver{} }

type backfillSourceBoundaryConn struct {
	*configConn
	boundary *backfillSourceBoundary
}

func (c *backfillSourceBoundaryConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return backfillSourceBoundaryTx{c.boundary}, nil
}
func (c *backfillSourceBoundaryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.boundary.call("query")
	rows, err := c.configConn.QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &backfillSourceBoundaryRows{Rows: rows, boundary: c.boundary}, nil
}

type backfillSourceBoundaryRows struct {
	driver.Rows
	boundary *backfillSourceBoundary
}

func (r *backfillSourceBoundaryRows) Close() error {
	r.boundary.call("rows-close")
	return r.Rows.Close()
}

type backfillSourceBoundaryTx struct{ boundary *backfillSourceBoundary }

func (tx backfillSourceBoundaryTx) Commit() error {
	tx.boundary.commits++
	tx.boundary.call("commit")
	return nil
}
func (backfillSourceBoundaryTx) Rollback() error { return nil }

func TestConfigBackfillSourceOwnsBytesBeforeEveryCallback(t *testing.T) {
	for _, stage := range []string{"authorize", "query", "rows-close", "recheck", "commit"} {
		t.Run(stage, func(t *testing.T) {
			f := configTestFixture(t)
			source := append([]byte(nil), f.row[6].([]byte)...)
			original := append([]byte(nil), source...)
			called := false
			b := &backfillSourceBoundary{fixture: f, hooks: map[string]func(){stage: func() { called = true; source[0] = 'x' }}}
			db := sql.OpenDB(b)
			defer db.Close()
			r, err := NewReader(db, b)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := r.VerifyConfigBackfillSource(context.Background(), 1, source)
			if err != nil || !called || b.commits != 1 || !bytes.Equal(verified.canonical, original) || verified.configSHA256 != f.row[4] || verified.installationID != "installation_test" || verified.version != 1 {
				t.Fatal("source verification did not retain the originally checked bytes", err)
			}
			if bytes.Equal(source, original) {
				t.Fatal("callback did not actually mutate caller input")
			}
		})
	}
}

func TestConfigBackfillSourceCancellationNeverReturnsReceipt(t *testing.T) {
	for _, stage := range []string{"before", "authorize", "query", "rows-close", "recheck", "commit"} {
		t.Run(stage, func(t *testing.T) {
			f := configTestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			b := &backfillSourceBoundary{fixture: f, hooks: map[string]func(){stage: func() { called = true; cancel() }}}
			db := sql.OpenDB(b)
			defer db.Close()
			r, err := NewReader(db, b)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "before" {
				called = true
				cancel()
			}
			verified, err := r.VerifyConfigBackfillSource(ctx, 1, f.row[6].([]byte))
			if !called || ctx.Err() == nil || err == nil || verified.installationID != "" || verified.version != 0 || verified.configSHA256 != "" || len(verified.canonical) != 0 {
				t.Fatal("canceled verification exposed a source receipt")
			}
			if stage == "commit" && (!errors.Is(err, ErrUnavailable) || b.commits != 1) {
				t.Fatal("cancellation was not injected inside driver COMMIT", err)
			}
		})
	}
}
