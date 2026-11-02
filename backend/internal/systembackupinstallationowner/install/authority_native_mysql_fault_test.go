//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"sync/atomic"
)

// This finite fault drops only the caller-visible acknowledgement AFTER the
// real MySQL driver's successful COMMIT. It does not model/replace SQL rows,
// query results, TLS, CURRENT_USER or server transaction/locking behavior.
// It is controlled driver-boundary lost-ack evidence, not a wire fault claim.
type nativeAuthorityLostAck struct {
	base                         driver.Connector
	armed                        atomic.Bool
	execs, committed, suppressed atomic.Int32
	headArrivals                 chan<- struct{}
	headRelease                  <-chan struct{}
	headAttempts                 atomic.Int32
}

func (c *nativeAuthorityLostAck) Driver() driver.Driver { return c.base.Driver() }
func (c *nativeAuthorityLostAck) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := c.base.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return &nativeAuthorityFaultConn{Conn: conn, owner: c}, nil
}

type nativeAuthorityFaultConn struct {
	driver.Conn
	owner *nativeAuthorityLostAck
}

func (c *nativeAuthorityFaultConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *nativeAuthorityFaultConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, e := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if e != nil {
		return nil, e
	}
	return &nativeAuthorityFaultTx{Tx: tx, owner: c.owner, readonly: options.ReadOnly}, nil
}
func (c *nativeAuthorityFaultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	// Synchronize the first two original write transactions AFTER their real
	// admin locks and BEFORE their real head FOR UPDATE statements. Queries
	// and rows are still executed/delivered exclusively by the MySQL driver.
	if c.owner.headArrivals != nil && strings.HasPrefix(q, "SELECT head_revision,") && strings.HasSuffix(q, " FOR UPDATE") && c.owner.headAttempts.Add(1) <= 2 {
		select {
		case c.owner.headArrivals <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-c.owner.headRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *nativeAuthorityFaultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.owner.execs.Add(1)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *nativeAuthorityFaultConn) CheckNamedValue(v *driver.NamedValue) error {
	if checker, ok := c.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(v)
	}
	return driver.ErrSkip
}
func (c *nativeAuthorityFaultConn) Ping(ctx context.Context) error {
	return c.Conn.(driver.Pinger).Ping(ctx)
}
func (c *nativeAuthorityFaultConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}
func (c *nativeAuthorityFaultConn) IsValid() bool { return c.Conn.(driver.Validator).IsValid() }

type nativeAuthorityFaultTx struct {
	driver.Tx
	owner    *nativeAuthorityLostAck
	readonly bool
}

func (t *nativeAuthorityFaultTx) Commit() error {
	if e := t.Tx.Commit(); e != nil {
		return e
	}
	if !t.readonly {
		t.owner.committed.Add(1)
		if t.owner.armed.CompareAndSwap(true, false) {
			t.owner.suppressed.Add(1)
			return errors.New("controlled loss of actual MySQL commit acknowledgement")
		}
	}
	return nil
}
