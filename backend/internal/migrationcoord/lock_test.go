package migrationcoord

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockDriverState struct {
	mu           sync.Mutex
	opened       int
	closed       int
	acquireError bool
	acquireBusy  bool
	releaseError bool
	releaseValue int64
}

type lockConnector struct{ state *lockDriverState }

func (c lockConnector) Connect(context.Context) (driver.Conn, error) {
	c.state.mu.Lock()
	c.state.opened++
	c.state.mu.Unlock()
	return &lockDriverConn{state: c.state}, nil
}

func (c lockConnector) Driver() driver.Driver { return lockDriver{state: c.state} }

type lockDriver struct{ state *lockDriverState }

func (d lockDriver) Open(string) (driver.Conn, error) {
	return lockConnector{state: d.state}.Connect(context.Background())
}

type lockDriverConn struct{ state *lockDriverState }

func (*lockDriverConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}
func (*lockDriverConn) Begin() (driver.Tx, error) { return nil, errors.New("not implemented") }
func (c *lockDriverConn) Close() error {
	c.state.mu.Lock()
	c.state.closed++
	c.state.mu.Unlock()
	return nil
}

func (c *lockDriverConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "GET_LOCK") {
		c.state.mu.Lock()
		defer c.state.mu.Unlock()
		if c.state.acquireError {
			return nil, errors.New("acquire transport failure")
		}
		if c.state.acquireBusy {
			return &lockRows{value: 0}, nil
		}
		return &lockRows{value: 1}, nil
	}
	if strings.Contains(query, "RELEASE_LOCK") {
		c.state.mu.Lock()
		defer c.state.mu.Unlock()
		if c.state.releaseError {
			return nil, errors.New("release transport failure")
		}
		return &lockRows{value: c.state.releaseValue}, nil
	}
	return nil, errors.New("unexpected query")
}

type lockRows struct {
	value int64
	read  bool
}

func (*lockRows) Columns() []string { return []string{"lock_result"} }
func (*lockRows) Close() error      { return nil }
func (r *lockRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	dest[0] = r.value
	return nil
}

func newLockTestDB(state *lockDriverState) *sql.DB {
	db := sql.OpenDB(lockConnector{state: state})
	db.SetMaxIdleConns(1)
	return db
}

func TestSQLLockerRejectsInvalidConfigurationBeforeDatabaseUse(t *testing.T) {
	if len(LockName) > 64 || !strings.Contains(LockName, "migration-capture") {
		t.Fatalf("invalid MySQL advisory lock name %q", LockName)
	}
	if _, err := (SQLLocker{}).Acquire(context.Background()); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil database error=%v", err)
	}
	if _, err := (SQLLocker{Timeout: 1500 * time.Millisecond}).Acquire(context.Background()); err == nil {
		t.Fatal("fractional lock timeout accepted")
	}
}

func TestSQLLockerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (SQLLocker{}).Acquire(ctx); err != context.Canceled {
		t.Fatalf("Acquire error=%v", err)
	}
}

func TestSQLLockReleaseKeepsHealthyConnectionReusable(t *testing.T) {
	state := &lockDriverState{releaseValue: 1}
	db := newLockTestDB(state)
	defer db.Close()
	lock, err := (SQLLocker{DB: db}).AcquireSQL(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.opened != 1 || state.closed != 0 {
		t.Fatalf("healthy connection opened=%d closed=%d", state.opened, state.closed)
	}
}

func TestSQLLockReleaseFailureDiscardsPhysicalConnection(t *testing.T) {
	for _, releaseError := range []bool{true, false} {
		state := &lockDriverState{releaseError: releaseError, releaseValue: 0}
		db := newLockTestDB(state)
		lock, err := (SQLLocker{DB: db}).AcquireSQL(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lock.Release(context.Background()); err == nil {
			t.Fatalf("releaseError=%t: ambiguous release accepted", releaseError)
		}
		if err := db.Ping(); err != nil {
			t.Fatal(err)
		}
		state.mu.Lock()
		opened, closed := state.opened, state.closed
		state.mu.Unlock()
		if opened != 2 || closed != 1 {
			t.Fatalf("releaseError=%t opened=%d closed=%d; failed connection was reused", releaseError, opened, closed)
		}
		_ = db.Close()
	}
}

func TestSQLLockAcquireFailureDiscardsPhysicalConnection(t *testing.T) {
	for _, acquireError := range []bool{true, false} {
		state := &lockDriverState{acquireError: acquireError, acquireBusy: !acquireError}
		db := newLockTestDB(state)
		if _, err := (SQLLocker{DB: db}).AcquireSQL(context.Background()); err == nil {
			t.Fatalf("acquireError=%t: failed acquisition accepted", acquireError)
		}
		if err := db.Ping(); err != nil {
			t.Fatal(err)
		}
		state.mu.Lock()
		opened, closed := state.opened, state.closed
		state.mu.Unlock()
		if opened != 2 || closed != 1 {
			t.Fatalf("acquireError=%t opened=%d closed=%d; uncertain connection was reused", acquireError, opened, closed)
		}
		_ = db.Close()
	}
}
