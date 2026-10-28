package repository_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/repository"
	upper "github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/mysql"
)

// Shared by the offline regression and the real MySQL probe. Close the
// database/sql pool, NOT upper.Session: the latter destroys the adapter and
// subsequent upper/db v4.10.0 Exec dereferences a nil *sql.DB before returning
// an error. A closed pool instead exercises the real repository error path.
func assertLoginStateClosedPool(t *testing.T, session upper.Session, state repository.LoginState) {
	t.Helper()
	pool, ok := session.Driver().(*sql.DB)
	if !ok || pool == nil {
		t.Fatal("fault fixture requires an intact SQL adapter")
	}
	if err := pool.Close(); err != nil {
		t.Fatal("could not close fault fixture pool")
	}
	if session.Driver() != pool {
		t.Fatal("fault injection destroyed the adapter")
	}
	err := repository.NewUserRepository(session).(repository.LoginStateRepository).UpdateLoginState(state)
	if err == nil || err.Error() != "login state unavailable" {
		t.Fatal("database failure not rejected safely")
	}
}

// This transport implements only adapter initialization. database/sql and
// upper/db are real; no MySQL server or network is used. Once the pool is
// closed, UpdateLoginState must fail without reaching the driver again.
func TestLoginStateClosedPoolReturnsUnavailable(t *testing.T) {
	c := &loginStateInitConnector{}
	pool := sql.OpenDB(c)
	t.Cleanup(func() { pool.Close() })
	session, err := mysql.New(pool)
	if err != nil {
		t.Fatal("could not initialize offline adapter fixture")
	}
	t.Cleanup(func() { session.Close() })
	before := c.calls.Load()
	assertLoginStateClosedPool(t, session, repository.LoginState{
		UserID: 1, PasswordHash: "synthetic-offline-hash", AuthProvider: "local",
		ExpectedRole: "user", Role: "user", At: time.Now().UTC(),
	})
	if c.calls.Load() != before || c.closes.Load() != 1 {
		t.Fatal("closed pool reached the driver or failed to close its connection")
	}
}

type loginStateInitConnector struct{ calls, closes atomic.Int32 }

func (c *loginStateInitConnector) Connect(context.Context) (driver.Conn, error) {
	c.calls.Add(1)
	return &loginStateInitConn{c}, nil
}
func (c *loginStateInitConnector) Driver() driver.Driver { return loginStateInitDriver{} }

type loginStateInitDriver struct{}

func (loginStateInitDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("offline fixture requires connector")
}

type loginStateInitConn struct{ c *loginStateInitConnector }

func (c *loginStateInitConn) Close() error { c.c.closes.Add(1); return nil }
func (c *loginStateInitConn) Prepare(string) (driver.Stmt, error) {
	c.c.calls.Add(1)
	return nil, errors.New("unexpected offline prepare")
}
func (c *loginStateInitConn) Begin() (driver.Tx, error) {
	c.c.calls.Add(1)
	return nil, errors.New("unexpected offline transaction")
}
func (c *loginStateInitConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.c.calls.Add(1)
	if strings.Join(strings.Fields(query), " ") != "SELECT DATABASE() AS name" || len(args) != 0 {
		return nil, fmt.Errorf("unexpected offline initialization query %q with %d arguments", query, len(args))
	}
	return &loginStateInitRows{}, nil
}

type loginStateInitRows struct{ done bool }

func (*loginStateInitRows) Columns() []string { return []string{"name"} }
func (*loginStateInitRows) Close() error      { return nil }
func (r *loginStateInitRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	values[0], r.done = "offline_login_state", true
	return nil
}
