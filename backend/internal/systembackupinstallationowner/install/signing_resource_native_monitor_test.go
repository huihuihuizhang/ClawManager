//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Boundary instrumentation only. Every SQL statement/row/lock/commit is still
// executed by the actual SAN/TLS MySQL driver. Acquired events are emitted
// after the driver actually delivers its first row, not before a lock wait.
type nativeSignerLockEvent struct {
	key          string
	acquired     bool
	connectionID int64
}
type nativeSignerLockMonitor struct {
	base   driver.Connector
	events chan nativeSignerLockEvent
}
type nativeSignerLockConn struct {
	*nativeAuthorityFaultConn
	monitor      *nativeSignerLockMonitor
	connectionID int64
}
type nativeSignerLockRows struct {
	driver.Rows
	owner *nativeSignerLockConn
	ctx   context.Context
	key   string
	sent  bool
}

type nativeSignerLockStmt struct {
	driver.Stmt
	owner *nativeSignerLockConn
	query string
	ctx   context.Context
}

func (m *nativeSignerLockMonitor) Driver() driver.Driver { return m.base.Driver() }
func (m *nativeSignerLockMonitor) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := m.base.Connect(ctx)
	if e != nil {
		return nil, e
	}
	rows, e := conn.(driver.QueryerContext).QueryContext(ctx, `SELECT CONNECTION_ID()`, nil)
	if e != nil {
		_ = conn.Close()
		return nil, e
	}
	values := make([]driver.Value, 1)
	if e = rows.Next(values); e != nil {
		_ = rows.Close()
		_ = conn.Close()
		return nil, e
	}
	var id int64
	switch v := values[0].(type) {
	case int64:
		id = v
	case uint64:
		if v <= uint64(^uint64(0)>>1) {
			id = int64(v)
		}
	case []byte:
		id, _ = strconv.ParseInt(string(v), 10, 64)
	case string:
		id, _ = strconv.ParseInt(v, 10, 64)
	}
	_ = rows.Close()
	if id < 1 {
		_ = conn.Close()
		return nil, errors.New("actual native connection ID unavailable")
	}
	return &nativeSignerLockConn{nativeAuthorityFaultConn: &nativeAuthorityFaultConn{Conn: conn, owner: &nativeAuthorityLostAck{}}, monitor: m, connectionID: id}, nil
}
func nativeSignerLockKey(q string, args []driver.NamedValue) string {
	if !strings.HasSuffix(q, " FOR UPDATE") || len(args) < 4 {
		return ""
	}
	purpose, ok := args[3].Value.(string)
	if !ok || purpose != "acceptance_record" && purpose != "catalog_record" {
		return ""
	}
	if strings.Contains(q, "FROM system_backup_signing_resource_heads ") {
		return "head:" + purpose
	}
	if strings.Contains(q, "FROM system_backup_signing_resource_grants ") {
		return "grant:" + purpose
	}
	return ""
}
func (c *nativeSignerLockConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	key := nativeSignerLockKey(q, args)
	if key != "" {
		select {
		case c.monitor.events <- nativeSignerLockEvent{key: key, connectionID: c.connectionID}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	// Preserve ErrSkip unchanged: database/sql, not the monitor, chooses the
	// driver's default prepared fallback. Prepare below wraps its statement.
	return c.lockRows(ctx, key, rows, e)
}
func (c *nativeSignerLockConn) lockRows(ctx context.Context, key string, rows driver.Rows, e error) (driver.Rows, error) {
	if e != nil || key == "" {
		return rows, e
	}
	return &nativeSignerLockRows{Rows: rows, owner: c, ctx: ctx, key: key}, nil
}

// The pinned driver's default InterpolateParams=false makes parameterized
// Conn.QueryContext return ErrSkip. database/sql then prepares and queries a
// native statement. Observe those REAL rows too, without changing its query,
// arguments, execution route, close lifetime or driver configuration.
func (c *nativeSignerLockConn) Prepare(q string) (driver.Stmt, error) {
	statement, e := c.Conn.Prepare(q)
	if e != nil {
		return nil, e
	}
	return &nativeSignerLockStmt{Stmt: statement, owner: c, query: q, ctx: context.Background()}, nil
}
func (c *nativeSignerLockConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	preparer, ok := c.Conn.(driver.ConnPrepareContext)
	if !ok {
		return nil, errors.New("actual native context prepare unavailable")
	}
	statement, e := preparer.PrepareContext(ctx, q)
	if e != nil {
		return nil, e
	}
	return &nativeSignerLockStmt{Stmt: statement, owner: c, query: q, ctx: ctx}, nil
}
func (s *nativeSignerLockStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("actual native prepared context query unavailable")
	}
	rows, e := queryer.QueryContext(ctx, args)
	return s.owner.lockRows(ctx, nativeSignerLockKey(s.query, args), rows, e)
}
func (s *nativeSignerLockStmt) Query(args []driver.Value) (driver.Rows, error) {
	values := make([]driver.NamedValue, len(args))
	for i, value := range args {
		values[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	rows, e := s.Stmt.Query(args)
	return s.owner.lockRows(s.ctx, nativeSignerLockKey(s.query, values), rows, e)
}
func (s *nativeSignerLockStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := s.Stmt.(driver.StmtExecContext)
	if !ok {
		return nil, errors.New("actual native prepared context exec unavailable")
	}
	return execer.ExecContext(ctx, args)
}
func (s *nativeSignerLockStmt) ColumnConverter(index int) driver.ValueConverter {
	if converter, ok := s.Stmt.(driver.ColumnConverter); ok {
		return converter.ColumnConverter(index)
	}
	return driver.DefaultParameterConverter
}
func (r *nativeSignerLockRows) Next(values []driver.Value) error {
	e := r.Rows.Next(values)
	if e == nil && !r.sent {
		r.sent = true
		select {
		case r.owner.monitor.events <- nativeSignerLockEvent{key: r.key, acquired: true, connectionID: r.owner.connectionID}:
		case <-r.ctx.Done():
			return r.ctx.Err()
		}
	}
	return e
}

// Require a real server wait edge for the exact owned schema/table and both
// actual connection IDs. Lack of server metadata is a failure, never PASS.
func requireNativeSignerWait(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, waiting, blocking int64, table string) {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		e := f.n.root.QueryRowContext(deadline, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.threads waiter ON waiter.THREAD_ID=w.REQUESTING_THREAD_ID JOIN performance_schema.threads blocker ON blocker.THREAD_ID=w.BLOCKING_THREAD_ID JOIN performance_schema.data_locks requested ON requested.ENGINE=w.ENGINE AND requested.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE waiter.PROCESSLIST_ID=? AND blocker.PROCESSLIST_ID=? AND requested.OBJECT_SCHEMA=? AND requested.OBJECT_NAME=? AND requested.LOCK_STATUS='WAITING'`, waiting, blocking, f.n.database, table).Scan(&count)
		if e != nil {
			t.Fatal("actual owned InnoDB wait metadata unavailable", e)
		}
		if count > 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.Done():
			t.Fatal("no actual exact original InnoDB lock wait", table)
		}
	}
}
