package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type gcConnectionPolicy struct{}

func (*gcConnectionPolicy) LockScope(context.Context, *sql.Tx, string, Identity) error {
	panic("connection helper authorized scope")
}
func (*gcConnectionPolicy) Admit(context.Context, *sql.Tx, Record, time.Time) error {
	panic("connection helper admitted work")
}
func (*gcConnectionPolicy) Authorize(context.Context, *sql.Tx, Actor, Record, []string) error {
	panic("connection helper authorized work")
}
func (*gcConnectionPolicy) Deletable(context.Context, *sql.Tx, Record, time.Time) error {
	panic("connection helper authorized deletion")
}
func (*gcConnectionPolicy) Audit(context.Context, *sql.Tx, Audit) error {
	panic("connection helper wrote audit")
}
func (*gcConnectionPolicy) OwnerDeadline(context.Context, *sql.Tx, Identity) (time.Time, error) {
	panic("connection helper read owner")
}

type gcConnectionPool struct {
	t                                *testing.T
	mu                               sync.Mutex
	next, closed, commits, rollbacks int
	mode                             string
	wantCtx                          context.Context
	rolled                           chan struct{}
}
type gcConnectionTransport struct {
	p                      *gcConnectionPool
	id                     int
	active, locked, closed bool
}
type gcConnectionDriver struct{}

func (gcConnectionDriver) Open(string) (driver.Conn, error) { return nil, errors.New("no DSN/network") }
func (p *gcConnectionPool) Driver() driver.Driver           { return gcConnectionDriver{} }
func (p *gcConnectionPool) Connect(context.Context) (driver.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mode == "connect" {
		return nil, errors.New("PRIVATE connect")
	}
	p.next++
	return &gcConnectionTransport{p: p, id: p.next}, nil
}
func (c *gcConnectionTransport) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("no prepare")
}
func (c *gcConnectionTransport) Begin() (driver.Tx, error) {
	return nil, errors.New("RR BeginTx required")
}
func (c *gcConnectionTransport) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	if ctx != c.p.wantCtx || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly || c.active {
		c.p.t.Error("connection ownership/context/isolation changed")
	}
	if c.p.mode == "begin" {
		return nil, errors.New("PRIVATE begin")
	}
	c.active = true
	return c, nil
}
func (c *gcConnectionTransport) Close() error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	c.p.closed++
	if c.p.mode == "close_error" {
		return errors.New("PRIVATE physical close response unknown")
	}
	c.closed = true
	c.active = false
	c.locked = false
	return nil
}
func (c *gcConnectionTransport) ResetSession(context.Context) error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	if c.closed {
		return driver.ErrBadConn
	}
	return nil
}
func (c *gcConnectionTransport) IsValid() bool {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	return !c.closed
}
func (c *gcConnectionTransport) Commit() error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	c.active = false
	c.p.commits++
	if c.p.mode == "unknown_commit" {
		return errors.New("PRIVATE lost COMMIT reply")
	}
	return nil
}
func (c *gcConnectionTransport) Rollback() error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	c.p.rollbacks++
	select {
	case c.p.rolled <- struct{}{}:
	default:
	}
	if c.p.mode == "rollback_error" {
		return errors.New("PRIVATE rollback failed")
	}
	c.active = false
	return nil
}

type gcConnectionRows struct {
	width  int
	values []driver.Value
	read   bool
	fault  string
}

func (r *gcConnectionRows) Columns() []string { return make([]string, r.width) }
func (r *gcConnectionRows) Close() error {
	if r.fault == "rows_close" {
		return errors.New("PRIVATE row close")
	}
	return nil
}
func (r *gcConnectionRows) Next(out []driver.Value) error {
	if r.fault == "row_error" {
		return errors.New("PRIVATE row read")
	}
	if r.read || r.fault == "missing" {
		return io.EOF
	}
	r.read = true
	copy(out, r.values)
	return nil
}
func (c *gcConnectionTransport) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	if ctx != c.p.wantCtx || q != downloadGCConnectionIdentitySQL || len(a) != 0 || !c.active {
		c.p.t.Error("SQL escaped original connection/transaction/context")
	}
	if c.p.mode == "query" {
		return nil, errors.New("PRIVATE identity query")
	}
	values := []driver.Value{"server", "gc_test", time.Now().UTC().Truncate(time.Microsecond), int64(0)}
	switch c.p.mode {
	case "server":
		values[0] = "other"
	case "database":
		values[1] = "other"
	case "clock":
		values[2] = time.Time{}
	case "offset":
		values[3] = int64(1)
	}
	width := 4
	if c.p.mode == "scan" {
		width = 3
	}
	return &gcConnectionRows{width: width, values: values, fault: c.p.mode}, nil
}
func gcConnectionFixture(t *testing.T, ctx context.Context) (SQLRegistry, *gcConnectionPool) {
	t.Helper()
	p := &gcConnectionPool{t: t, wantCtx: ctx, rolled: make(chan struct{}, 1)}
	db := sql.OpenDB(p)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	return SQLRegistry{DB: db, Policy: &gcConnectionPolicy{}, Installation: "installation_test", ServerUUID: "server", Database: "gc_test"}, p
}

func TestDownloadGCConnectionLifecycle(t *testing.T) {
	for _, mode := range []string{"commit", "rollback", "unknown_commit", "rollback_error", "canceled", "panic", "close_error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, p := gcConnectionFixture(t, ctx)
			p.mode = mode
			owned, at, e := beginDownloadGCConnection(ctx, r)
			if e != nil || at.IsZero() {
				t.Fatal(e)
			}
			t.Cleanup(func() { owned.close() })
			var oldID int
			var old *gcConnectionTransport
			if e = owned.conn.Raw(func(raw any) error { old = raw.(*gcConnectionTransport); oldID = old.id; old.locked = true; return nil }); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "commit", "close_error":
				if e = owned.commit(); e != nil {
					t.Fatal(e)
				}
			case "unknown_commit":
				if e = owned.commit(); e == nil {
					t.Fatal("unknown reply accepted")
				}
			case "canceled":
				cancel()
				select {
				case <-p.rolled:
				case <-time.After(5 * time.Second):
					t.Fatal("canceled transaction did not roll back")
				}
			case "panic":
				var recovered any
				func() {
					defer func() { recovered = recover() }()
					defer owned.close()
					panic("collector callback panic")
				}()
				if recovered != "collector callback panic" {
					t.Fatal("lost original panic", recovered)
				}
			}
			if mode == "commit" || mode == "unknown_commit" || mode == "close_error" {
				if stats := r.DB.Stats(); stats.InUse != 1 || stats.Idle != 0 || p.closed != 0 {
					t.Fatal("commit prematurely returned session", stats)
				}
				borrowCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer stop()
				other, err := r.DB.Conn(borrowCtx)
				if other != nil {
					other.Close()
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("committed connection was borrowable before cleanup", err)
				}
			}
			owned.close()
			owned.close()
			if owned.conn != nil || owned.tx != nil || p.closed != 1 || r.DB.Stats().OpenConnections != 0 {
				t.Fatal("session was not discarded exactly once", p.closed, r.DB.Stats())
			}
			if mode != "close_error" && (!old.closed || old.locked || old.active) {
				t.Fatal("driver close did not clean model session")
			}
			if mode == "close_error" && (!old.locked || old.closed) {
				t.Fatal("must not claim remote release after driver close error")
			}
			fresh, err := r.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err = fresh.Raw(func(raw any) error {
				c := raw.(*gcConnectionTransport)
				if c.id == oldID || c.locked {
					t.Error("discarded session was reused")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if (mode == "commit" || mode == "unknown_commit" || mode == "close_error") && (p.commits != 1 || p.rollbacks != 0) {
				t.Fatal("known/unknown commit was retried or claimed rolled back", p.commits, p.rollbacks)
			}
		})
	}
}

func TestDownloadGCConnectionInitializationFailures(t *testing.T) {
	for _, mode := range []string{"connect", "begin", "query", "scan", "missing", "row_error", "rows_close", "server", "database", "clock", "offset"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			r, p := gcConnectionFixture(t, ctx)
			p.mode = mode
			owned, at, e := beginDownloadGCConnection(ctx, r)
			if !errors.Is(e, ErrUnavailable) || owned != nil || !at.IsZero() || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("initialization leaked private/partial state", e)
			}
			wantClosed := 1
			if mode == "connect" {
				wantClosed = 0
			}
			if p.closed != wantClosed || r.DB.Stats().OpenConnections != 0 || p.commits != 0 {
				t.Fatal("failed initialization reused session", p.closed, r.DB.Stats())
			}
		})
	}
	for _, mode := range []string{"nil_context", "canceled", "nil_database", "nil_policy", "typed_nil_policy", "installation", "server", "database"} {
		t.Run("config/"+mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, p := gcConnectionFixture(t, ctx)
			switch mode {
			case "nil_context":
				ctx = nil
			case "canceled":
				cancel()
			case "nil_database":
				r.DB = nil
			case "nil_policy":
				r.Policy = nil
			case "typed_nil_policy":
				r.Policy = (*gcConnectionPolicy)(nil)
			case "installation":
				r.Installation = "bad"
			case "server":
				r.ServerUUID = ""
			case "database":
				r.Database = ""
			}
			owned, at, e := beginDownloadGCConnection(ctx, r)
			if !errors.Is(e, ErrUnavailable) || owned != nil || !at.IsZero() || p.next != 0 {
				t.Fatal("invalid configuration opened a session", e)
			}
		})
	}
	var zero downloadGCConnection
	zero.close()
	(*downloadGCConnection)(nil).close()
}

func TestDownloadRetentionGCConnectionDisposalAndOriginalOutcome(t *testing.T) {
	for _, mode := range []string{"success", "denied", "late_write", "unknown_commit", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			before := gcConnectionGroupSnapshot(f.d)
			switch mode {
			case "denied":
				f.policy.denyGuard = true
			case "late_write":
				f.d.afterWrite = func(q string) {
					if q == downloadGCDeleteResultSQL {
						f.policy.denyGuard = true
					}
				}
			case "unknown_commit":
				f.d.commitUnknown = true
			case "panic":
				f.d.afterWrite = func(q string) {
					if q == downloadGCTombstoneInsertSQL {
						panic("policy callback panic")
					}
				}
			}
			var err error
			var recovered any
			func() { defer func() { recovered = recover() }(); err = f.s.Collect(f.ctx, f.operation) }()
			if !reflect.DeepEqual(f.d.connectionEvents, []string{"connect", "close"}) || f.s.c.Registry.DB.Stats().OpenConnections != 0 || f.d.active {
				t.Fatal("collector returned an active/pooled session", f.d.connectionEvents)
			}
			if mode == "success" || mode == "unknown_commit" {
				if f.d.commits != f.commits+1 || len(f.d.stone) != 23 || len(f.d.m.op) != 0 {
					t.Fatal("collector outcome changed", err)
				}
				if mode == "success" && err != nil || mode == "unknown_commit" && !errors.Is(err, ErrDownloadRetentionGCCommitUnknown) {
					t.Fatal("wrong commit outcome", err)
				}
			} else {
				if mode == "panic" && recovered != "policy callback panic" || mode != "panic" && err == nil {
					t.Fatal("denial/panic hidden", err, recovered)
				}
				if f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) {
					t.Fatal("connection cleanup changed original group rollback", err)
				}
			}
		})
	}
}

func gcConnectionGroupSnapshot(d *retentionGCModel) admissionTxSnapshot {
	return admissionTxSnapshot{record: d.record, op: append([]driver.Value(nil), d.m.op...), receipt: append([]driver.Value(nil), d.m.receipt...), nonce: append([]driver.Value(nil), d.nonce...), body: append([]byte(nil), d.body...), user: d.user, resource: d.resource, action: d.action, kind: d.kind, created: d.created, consumed: d.consumed, reserved: d.reserved, activeConfig: d.activeConfig, sample: d.sample, resultBody: append([]byte(nil), d.resultBody...), resultCreated: d.resultCreated, resultRetention: append([]driver.Value(nil), d.resultRetention...)}
}
