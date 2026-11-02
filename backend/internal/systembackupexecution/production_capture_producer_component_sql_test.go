package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// Strict database/sql transport model for A's actual authentication and
// read-only original source snapshots. It is not native MySQL/TLS/GRANT proof.
type producerComponentSQL struct {
	account, server, database, username, stored string
	userID                                      int64
	clockBeyondOriginalWindow                   atomic.Bool
	afterSourceWindow                           time.Time
	queries, executions, openTx                 atomic.Int64
}

type producerComponentConnector struct{ model *producerComponentSQL }
type producerComponentDriver struct{}
type producerComponentConn struct{ model *producerComponentSQL }
type producerComponentTx struct{ model *producerComponentSQL }
type producerComponentRows struct {
	width int
	rows  [][]driver.Value
}

func (c producerComponentConnector) Driver() driver.Driver { return producerComponentDriver{} }
func (c producerComponentConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &producerComponentConn{c.model}, nil
}
func (producerComponentDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("component requires its explicit connector")
}
func (c *producerComponentConn) Close() error { return nil }
func (c *producerComponentConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("component rejects unplanned prepare")
}
func (c *producerComponentConn) Begin() (driver.Tx, error) {
	return nil, errors.New("component requires explicit readonly repeatable-read")
}
func (c *producerComponentConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if ctx.Err() != nil || !options.ReadOnly || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.model.openTx.Add(1) != 1 {
		return nil, errors.New("component rejected transaction shape")
	}
	return producerComponentTx{c.model}, nil
}
func (t producerComponentTx) Commit() error   { t.model.openTx.Add(-1); return nil }
func (t producerComponentTx) Rollback() error { t.model.openTx.Add(-1); return nil }
func (c *producerComponentConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.model.executions.Add(1)
	return nil, errors.New("source producer must never write SQL")
}
func (r *producerComponentRows) Columns() []string {
	names := make([]string, r.width)
	for n := range names {
		names[n] = "component_column"
	}
	return names
}
func (*producerComponentRows) Close() error { return nil }
func (r *producerComponentRows) Next(values []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(values, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}
func componentRow(values ...driver.Value) driver.Rows {
	return &producerComponentRows{width: len(values), rows: [][]driver.Value{values}}
}
func (c *producerComponentConn) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m := c.model
	m.queries.Add(1)
	switch query {
	case "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)":
		now := time.Now().UTC().Truncate(time.Microsecond)
		if m.clockBeyondOriginalWindow.Load() {
			now = m.afterSourceWindow
		}
		return componentRow(m.account, m.server, m.database, now), nil
	case "SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?":
		if len(arguments) != 1 || arguments[0].Value != m.username {
			break
		}
		return componentRow(m.userID, m.username, m.stored, "admin", true, "local"), nil
	case "SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE":
		if len(arguments) != 1 || arguments[0].Value != m.userID || m.openTx.Load() != 1 {
			break
		}
		return componentRow(m.username, m.stored, "admin", true, "local"), nil
	default:
		if strings.HasPrefix(query, "SELECT head_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_installation_owner_heads WHERE ") && strings.HasSuffix(query, " FOR SHARE") && len(arguments) == 2 && m.openTx.Load() == 1 {
			// This original first-issuance fixture has an enrolled issuer and
			// no prior capture owner head. No capture record supplies scope.
			return &producerComponentRows{width: 6}, nil
		}
	}
	return nil, errors.New("component rejected unexpected original source query")
}
