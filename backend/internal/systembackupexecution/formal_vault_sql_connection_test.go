package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
)

type vaultLazyConnector struct {
	verified       *atomic.Bool
	tlsOK          bool
	opened, closed int
}

func (c *vaultLazyConnector) Connect(context.Context) (driver.Conn, error) {
	c.opened++
	c.verified.Store(c.tlsOK)
	return &vaultLazyConn{c}, nil
}
func (c *vaultLazyConnector) Driver() driver.Driver { return vaultLazyDriver{} }

type vaultLazyDriver struct{}

func (vaultLazyDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type vaultLazyConn struct{ owner *vaultLazyConnector }

func (c *vaultLazyConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *vaultLazyConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *vaultLazyConn) Close() error                        { c.owner.closed++; return nil }

func TestBootstrapVaultSQLAcquiresConnectionBeforeTLSCheck(t *testing.T) {
	for _, tlsOK := range []bool{true, false} {
		verified := &atomic.Bool{}
		connector := &vaultLazyConnector{verified: verified, tlsOK: tlsOK}
		db := sql.OpenDB(connector)
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(0)
		if verified.Load() || connector.opened != 0 {
			t.Fatal("OpenDB unexpectedly connected")
		}
		conn, err := bootstrapVaultSQLConnection(context.Background(), db, verified)
		if tlsOK {
			if err != nil || conn == nil || connector.opened != 1 || connector.closed != 0 {
				t.Fatal("verified physical connection not retained", err)
			}
			conn.Close()
		} else if err == nil || conn != nil {
			t.Fatal("unverified connection accepted")
		}
		if connector.closed != 1 {
			t.Fatal("connection leaked", connector.closed)
		}
		db.Close()
	}
}
