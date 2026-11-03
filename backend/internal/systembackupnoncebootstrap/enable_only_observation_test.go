package systembackupnoncebootstrap

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnableOnlyNonceObservesActiveAndHistoricalMaterial(t *testing.T) {
	f := setup(t)
	current, e := sec.DecodeConfigValues(f.c.CanonicalJSON())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, e := f.v.observeEnableOnlyCurrent(ctx, current)
	if e != nil || o == nil {
		t.Fatal(e)
	}
	deadline, _ := ctx.Deadline()
	if o.ValidUntil().After(deadline) {
		t.Fatal("deadline extended")
	}
	if e := os.Remove(f.v.binding.Keys[1].MaterialFile); e != nil {
		t.Fatal(e)
	}
	if _, e := f.v.observeEnableOnlyCurrent(ctx, current); e == nil {
		t.Fatal("missing historical key silently dropped")
	}
	if o.Recheck(ctx, nil, time.Now().UTC()) == nil || !o.ValidUntil().IsZero() {
		t.Fatal("invalid transaction not latched")
	}
}

// SQL delivery is synthetic here. This verifies the new mutation observation's
// complete retained census, fixed tail deadline and transaction latch; it is
// not native InnoDB/installation/adoption evidence.
type enableNonceSQLState struct {
	server, database, active, identity, retained string
	tail                                         time.Time
	queries, commits                             int
}
type enableNonceConnector struct{ s *enableNonceSQLState }

func (c enableNonceConnector) Driver() driver.Driver { return enableNonceDriver{} }
func (c enableNonceConnector) Connect(context.Context) (driver.Conn, error) {
	return &enableNonceConn{s: c.s}, nil
}

type enableNonceDriver struct{}

func (enableNonceDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type enableNonceConn struct{ s *enableNonceSQLState }

func (*enableNonceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*enableNonceConn) Close() error                { return nil }
func (c *enableNonceConn) Begin() (driver.Tx, error) { return enableNonceTx{c.s}, nil }
func (c *enableNonceConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type enableNonceTx struct{ s *enableNonceSQLState }

func (t enableNonceTx) Commit() error { t.s.commits++; return nil }
func (enableNonceTx) Rollback() error { return nil }

type enableNonceRows struct {
	cols   []string
	values [][]driver.Value
}

func (r *enableNonceRows) Columns() []string { return r.cols }
func (*enableNonceRows) Close() error        { return nil }
func (r *enableNonceRows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (c *enableNonceConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.s.queries++
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		return &enableNonceRows{[]string{"server", "database"}, [][]driver.Value{{c.s.server, c.s.database}}}, nil
	case q == "SELECT UTC_TIMESTAMP(6)":
		return &enableNonceRows{[]string{"now"}, [][]driver.Value{{c.s.tail}}}, nil
	case strings.HasPrefix(q, "SELECT nonce_hmac_ref_version"):
		return &enableNonceRows{[]string{"version", "identity", "retained"}, [][]driver.Value{{c.s.active, c.s.identity, nil}, {c.s.retained, nil, c.s.tail.Add(time.Minute)}}}, nil
	}
	return nil, errors.New("unexpected SQL")
}
func TestEnableOnlyNonceRetainedCensusAndFinalDeliveryLatch(t *testing.T) {
	for _, which := range []string{"valid", "unknown_retained", "tail_expired"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			current, e := sec.DecodeConfigValues(f.c.CanonicalJSON())
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			o, e := f.v.observeEnableOnlyCurrent(ctx, current)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			state := &enableNonceSQLState{server: f.g.ServerUUID, database: f.g.Database, active: f.active.Version, identity: f.active.IdentityHash, retained: f.v.binding.Keys[1].Version, tail: now}
			if which == "unknown_retained" {
				state.retained = "unmapped-retained-version"
			}
			if which == "tail_expired" {
				state.tail = o.ValidUntil()
			}
			db := sql.OpenDB(enableNonceConnector{state})
			defer db.Close()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			e = o.Recheck(ctx, tx, now)
			if (e == nil) != (which == "valid") {
				t.Fatal("wrong mutation nonce guard result", which, e)
			}
			if state.commits != 0 {
				t.Fatal("resource guard committed caller transaction")
			}
			if which != "valid" {
				queries := state.queries
				state.tail = now
				state.retained = f.v.binding.Keys[1].Version
				if o.Recheck(ctx, tx, now) == nil || state.queries != queries {
					t.Fatal("failed observation revived or continued SQL")
				}
			}
		})
	}
}
