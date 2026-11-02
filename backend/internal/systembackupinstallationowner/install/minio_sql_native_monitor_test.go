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
type nativeMinioLockEvent struct {
	key          string
	acquired     bool
	connectionID int64
}
type nativeMinioLockMonitor struct {
	base   driver.Connector
	events chan nativeMinioLockEvent
}
type nativeMinioLockConn struct {
	*nativeAuthorityFaultConn
	monitor      *nativeMinioLockMonitor
	connectionID int64
}
type nativeMinioLockRows struct {
	driver.Rows
	owner *nativeMinioLockConn
	ctx   context.Context
	key   string
	sent  bool
}

type nativeMinioLockStmt struct {
	driver.Stmt
	owner *nativeMinioLockConn
	query string
	ctx   context.Context
}

func (m *nativeMinioLockMonitor) Driver() driver.Driver { return m.base.Driver() }
func (m *nativeMinioLockMonitor) Connect(ctx context.Context) (driver.Conn, error) {
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
	return &nativeMinioLockConn{nativeAuthorityFaultConn: &nativeAuthorityFaultConn{Conn: conn, owner: &nativeAuthorityLostAck{}}, monitor: m, connectionID: id}, nil
}
func nativeMinioLockKey(q string, args []driver.NamedValue) string {
	key := ""
	if strings.HasSuffix(q, " FOR UPDATE") {
		switch {
		case strings.Contains(q, "FROM system_backup_minio_owner_heads "):
			key = "head"
		case strings.Contains(q, "FROM system_backup_minio_owner_grants "):
			key = "grant"
		case strings.Contains(q, "FROM system_backup_minio_owner_refs ") && len(args) == 6:
			key, _ = args[5].Value.(string)
		}
	}
	return key
}
func (c *nativeMinioLockConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	key := nativeMinioLockKey(q, args)
	if key != "" {
		select {
		case c.monitor.events <- nativeMinioLockEvent{key: key, connectionID: c.connectionID}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	// Preserve ErrSkip unchanged: database/sql, not the monitor, chooses the
	// driver's default prepared fallback. Prepare below wraps its statement.
	return c.lockRows(ctx, key, rows, e)
}
func (c *nativeMinioLockConn) lockRows(ctx context.Context, key string, rows driver.Rows, e error) (driver.Rows, error) {
	if e != nil || key == "" {
		return rows, e
	}
	return &nativeMinioLockRows{Rows: rows, owner: c, ctx: ctx, key: key}, nil
}

// The pinned driver's default InterpolateParams=false makes parameterized
// Conn.QueryContext return ErrSkip. database/sql then prepares and queries a
// native statement. Observe those REAL rows too, without changing its query,
// arguments, execution route, close lifetime or driver configuration.
func (c *nativeMinioLockConn) Prepare(q string) (driver.Stmt, error) {
	statement, e := c.Conn.Prepare(q)
	if e != nil {
		return nil, e
	}
	return &nativeMinioLockStmt{Stmt: statement, owner: c, query: q, ctx: context.Background()}, nil
}
func (c *nativeMinioLockConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	preparer, ok := c.Conn.(driver.ConnPrepareContext)
	if !ok {
		return nil, errors.New("actual native context prepare unavailable")
	}
	statement, e := preparer.PrepareContext(ctx, q)
	if e != nil {
		return nil, e
	}
	return &nativeMinioLockStmt{Stmt: statement, owner: c, query: q, ctx: ctx}, nil
}
func (s *nativeMinioLockStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("actual native prepared context query unavailable")
	}
	rows, e := queryer.QueryContext(ctx, args)
	return s.owner.lockRows(ctx, nativeMinioLockKey(s.query, args), rows, e)
}
func (s *nativeMinioLockStmt) Query(args []driver.Value) (driver.Rows, error) {
	values := make([]driver.NamedValue, len(args))
	for i, value := range args {
		values[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	rows, e := s.Stmt.Query(args)
	return s.owner.lockRows(s.ctx, nativeMinioLockKey(s.query, values), rows, e)
}
func (s *nativeMinioLockStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := s.Stmt.(driver.StmtExecContext)
	if !ok {
		return nil, errors.New("actual native prepared context exec unavailable")
	}
	return execer.ExecContext(ctx, args)
}
func (s *nativeMinioLockStmt) ColumnConverter(index int) driver.ValueConverter {
	if converter, ok := s.Stmt.(driver.ColumnConverter); ok {
		return converter.ColumnConverter(index)
	}
	return driver.DefaultParameterConverter
}
func (r *nativeMinioLockRows) Next(values []driver.Value) error {
	e := r.Rows.Next(values)
	if e == nil && !r.sent {
		r.sent = true
		select {
		case r.owner.monitor.events <- nativeMinioLockEvent{key: r.key, acquired: true, connectionID: r.owner.connectionID}:
		case <-r.ctx.Done():
			return r.ctx.Err()
		}
	}
	return e
}

// Require a real server wait edge for the exact owned schema/table and both
// actual connection IDs. Lack of server metadata is a failure, never PASS.
func requireNativeMinioWait(t *testing.T, ctx context.Context, f *nativeMinioSQLFixture, waiting, blocking int64, table string) {
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
