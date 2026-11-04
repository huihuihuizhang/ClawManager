//go:build systembackup_mysql

package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	mysql "github.com/go-sql-driver/mysql"
)

// This test-only connector delegates to the actual mysql v1.9.0 connector.
// It neither replaces SQL responses nor changes arguments, transaction options,
// cancellation, conversion, result bytes, privileges or retry decisions.
// Only fixed business SQL, interface names and error classes/codes are logged.
// No argument, DSN, credentials, row value or raw error message is logged.
func bootstrapNativeTraceEvent(t *testing.T, operation, query string, err error) {
	t.Helper()
	status := "ok"
	var code uint16
	var server *mysql.MySQLError
	switch {
	case err == nil:
	case errors.As(err, &server):
		status, code = "mysql", server.Number
	case errors.Is(err, io.EOF):
		status = "eof"
	case errors.Is(err, driver.ErrSkip):
		status = "driver_skip"
	case errors.Is(err, driver.ErrBadConn):
		status = "driver_bad_connection"
	case errors.Is(err, context.Canceled):
		status = "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		status = "context_deadline"
	default:
		status = "other_error"
	}
	t.Logf("native business op=%s sql=%q status=%s mysql_code=%d error_type=%T", operation, query, status, code, err)
}

type bootstrapNativeTraceConnector struct {
	driver.Connector
	t *testing.T
}

// The pinned real mysql connection implements exactly these optional paths.
// Embedding delegates the remaining methods (including conversion, session
// reset and validity) directly, without inventing fallback behavior.
type bootstrapNativeRealConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.Queryer
	driver.QueryerContext
	driver.Execer
	driver.ExecerContext
	driver.NamedValueChecker
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

type bootstrapNativeTraceConn struct {
	bootstrapNativeRealConn
	t *testing.T
}

func (c bootstrapNativeTraceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	bootstrapNativeTraceEvent(c.t, "Connect", "", err)
	if err != nil {
		return conn, err
	}
	real, ok := conn.(bootstrapNativeRealConn)
	if !ok {
		conn.Close()
		return nil, errors.New("pinned mysql connection interface mismatch")
	}
	return &bootstrapNativeTraceConn{bootstrapNativeRealConn: real, t: c.t}, nil
}

func (c *bootstrapNativeTraceConn) Begin() (driver.Tx, error) {
	tx, err := c.bootstrapNativeRealConn.Begin()
	bootstrapNativeTraceEvent(c.t, "Begin", "", err)
	if err != nil {
		return tx, err
	}
	return bootstrapNativeTraceTx{Tx: tx, t: c.t}, nil
}

func (c *bootstrapNativeTraceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.bootstrapNativeRealConn.BeginTx(ctx, opts)
	bootstrapNativeTraceEvent(c.t, "BeginTx", "", err)
	if err != nil {
		return tx, err
	}
	return bootstrapNativeTraceTx{Tx: tx, t: c.t}, nil
}

func (c *bootstrapNativeTraceConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.bootstrapNativeRealConn.Prepare(query)
	bootstrapNativeTraceEvent(c.t, "Prepare", query, err)
	return bootstrapNativeWrapStmt(c.t, stmt, query, err)
}

func (c *bootstrapNativeTraceConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := c.bootstrapNativeRealConn.PrepareContext(ctx, query)
	bootstrapNativeTraceEvent(c.t, "PrepareContext", query, err)
	return bootstrapNativeWrapStmt(c.t, stmt, query, err)
}

func (c *bootstrapNativeTraceConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	rows, err := c.bootstrapNativeRealConn.Query(query, args)
	bootstrapNativeTraceEvent(c.t, "Query", query, err)
	return bootstrapNativeWrapRows(c.t, rows, query, err)
}

func (c *bootstrapNativeTraceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.bootstrapNativeRealConn.QueryContext(ctx, query, args)
	bootstrapNativeTraceEvent(c.t, "QueryContext", query, err)
	return bootstrapNativeWrapRows(c.t, rows, query, err)
}

func (c *bootstrapNativeTraceConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	result, err := c.bootstrapNativeRealConn.Exec(query, args)
	bootstrapNativeTraceEvent(c.t, "Exec", query, err)
	return result, err
}

func (c *bootstrapNativeTraceConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.bootstrapNativeRealConn.ExecContext(ctx, query, args)
	bootstrapNativeTraceEvent(c.t, "ExecContext", query, err)
	return result, err
}

type bootstrapNativeTraceTx struct {
	driver.Tx
	t *testing.T
}

func (tx bootstrapNativeTraceTx) Commit() error {
	err := tx.Tx.Commit()
	bootstrapNativeTraceEvent(tx.t, "Commit", "", err)
	return err
}

func (tx bootstrapNativeTraceTx) Rollback() error {
	err := tx.Tx.Rollback()
	bootstrapNativeTraceEvent(tx.t, "Rollback", "", err)
	return err
}

type bootstrapNativeRealStmt interface {
	driver.Stmt
	driver.StmtExecContext
	driver.StmtQueryContext
	driver.ColumnConverter
	driver.NamedValueChecker
}

type bootstrapNativeTraceStmt struct {
	bootstrapNativeRealStmt
	t     *testing.T
	query string
}

func bootstrapNativeWrapStmt(t *testing.T, stmt driver.Stmt, query string, err error) (driver.Stmt, error) {
	if err != nil {
		return stmt, err
	}
	real, ok := stmt.(bootstrapNativeRealStmt)
	if !ok {
		stmt.Close()
		return nil, errors.New("pinned mysql statement interface mismatch")
	}
	return &bootstrapNativeTraceStmt{bootstrapNativeRealStmt: real, t: t, query: query}, nil
}

func (s *bootstrapNativeTraceStmt) Exec(args []driver.Value) (driver.Result, error) {
	result, err := s.bootstrapNativeRealStmt.Exec(args)
	bootstrapNativeTraceEvent(s.t, "Stmt.Exec", s.query, err)
	return result, err
}

func (s *bootstrapNativeTraceStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	result, err := s.bootstrapNativeRealStmt.ExecContext(ctx, args)
	bootstrapNativeTraceEvent(s.t, "Stmt.ExecContext", s.query, err)
	return result, err
}

func (s *bootstrapNativeTraceStmt) Query(args []driver.Value) (driver.Rows, error) {
	rows, err := s.bootstrapNativeRealStmt.Query(args)
	bootstrapNativeTraceEvent(s.t, "Stmt.Query", s.query, err)
	return bootstrapNativeWrapRows(s.t, rows, s.query, err)
}

func (s *bootstrapNativeTraceStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := s.bootstrapNativeRealStmt.QueryContext(ctx, args)
	bootstrapNativeTraceEvent(s.t, "Stmt.QueryContext", s.query, err)
	return bootstrapNativeWrapRows(s.t, rows, s.query, err)
}

// Embed the actual optional row metadata interfaces to preserve Scan and
// multiple-result-set behavior. Never print the contents of dest or rows.
type bootstrapNativeRealRows interface {
	driver.Rows
	driver.RowsNextResultSet
	driver.RowsColumnTypeDatabaseTypeName
	driver.RowsColumnTypeNullable
	driver.RowsColumnTypePrecisionScale
	driver.RowsColumnTypeScanType
}

type bootstrapNativeTraceRows struct {
	bootstrapNativeRealRows
	t     *testing.T
	query string
}

func bootstrapNativeWrapRows(t *testing.T, rows driver.Rows, query string, err error) (driver.Rows, error) {
	if err != nil {
		return rows, err
	}
	real, ok := rows.(bootstrapNativeRealRows)
	if !ok {
		rows.Close()
		return nil, errors.New("pinned mysql rows interface mismatch")
	}
	return &bootstrapNativeTraceRows{bootstrapNativeRealRows: real, t: t, query: query}, nil
}

func (r *bootstrapNativeTraceRows) Next(dest []driver.Value) error {
	err := r.bootstrapNativeRealRows.Next(dest)
	if err != nil {
		bootstrapNativeTraceEvent(r.t, "Rows.Next", r.query, err)
	}
	return err
}

func (r *bootstrapNativeTraceRows) Close() error {
	err := r.bootstrapNativeRealRows.Close()
	if err != nil {
		bootstrapNativeTraceEvent(r.t, "Rows.Close", r.query, err)
	}
	return err
}

func (r *bootstrapNativeTraceRows) NextResultSet() error {
	err := r.bootstrapNativeRealRows.NextResultSet()
	if err != nil {
		bootstrapNativeTraceEvent(r.t, "Rows.NextResultSet", r.query, err)
	}
	return err
}
