package install

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Transaction/locking SQL protocol model only, not InnoDB or production grants.
type authoritySQLData struct {
	head   []driver.Value
	grants map[string][]driver.Value
}
type authoritySQLState struct {
	auth            *authSQLState
	data            authoritySQLData
	openTx          atomic.Int32
	writes, commits int
	commitLost      bool
	failGrantInsert bool
}
type authorityConnector struct{ s *authoritySQLState }

func (c authorityConnector) Driver() driver.Driver { return authDriver{} }
func (c authorityConnector) Connect(context.Context) (driver.Conn, error) {
	return &authorityConn{s: c.s, base: &authConn{s: c.s.auth}}, nil
}

type authorityConn struct {
	s        *authoritySQLState
	base     *authConn
	working  *authoritySQLData
	readonly bool
}

func (c *authorityConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *authorityConn) Close() error                        { return nil }
func (c *authorityConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func cloneValues(v []driver.Value) []driver.Value {
	out := append([]driver.Value(nil), v...)
	for n, x := range out {
		if b, ok := x.([]byte); ok {
			out[n] = bytes.Clone(b)
		}
	}
	return out
}
func (c *authorityConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if c.working != nil {
		return nil, errors.New("nested original tx")
	}
	d := authoritySQLData{head: cloneValues(c.s.data.head), grants: map[string][]driver.Value{}}
	for k, v := range c.s.data.grants {
		d.grants[k] = cloneValues(v)
	}
	c.working = &d
	c.readonly = o.ReadOnly
	c.base.tx = true
	c.s.openTx.Add(1)
	return authorityTx{c}, nil
}

type authorityTx struct{ c *authorityConn }

func (t authorityTx) Commit() error {
	c := t.c
	if !c.readonly {
		c.s.data = *c.working
		c.s.commits++
	}
	c.working = nil
	c.base.tx = false
	c.s.openTx.Add(-1)
	if !c.readonly && c.s.commitLost {
		c.s.commitLost = false
		return errors.New("lost original commit response")
	}
	return nil
}
func (t authorityTx) Rollback() error {
	if t.c.working != nil {
		t.c.working = nil
		t.c.base.tx = false
		t.c.s.openTx.Add(-1)
	}
	return nil
}

type authorityRows struct {
	width  int
	values [][]driver.Value
	index  int
}

func (r *authorityRows) Columns() []string { return make([]string, r.width) }
func (*authorityRows) Close() error        { return nil }
func (r *authorityRows) Next(out []driver.Value) error {
	if r.index == len(r.values) {
		return io.EOF
	}
	copy(out, r.values[r.index])
	r.index++
	return nil
}
func row(v ...driver.Value) driver.Rows {
	return &authorityRows{width: len(v), values: [][]driver.Value{v}}
}
func empty(width int) driver.Rows { return &authorityRows{width: width} }
func counter(v driver.Value) uint64 {
	switch n := v.(type) {
	case int64:
		return uint64(n)
	case uint64:
		return n
	default:
		panic("unexpected counter type")
	}
}
func grantKey(id string, revision driver.Value) string {
	return id + ":" + strconv.FormatUint(counter(revision), 10)
}
func (c *authorityConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if q == `SELECT UTC_TIMESTAMP(6)` {
		return row(time.Now().UTC().Truncate(time.Microsecond)), nil
	}
	if q == `SELECT CURRENT_USER(),@@server_uuid,DATABASE()` {
		return row(c.s.auth.account, c.s.auth.server, c.s.auth.plan.Target.Database), nil
	}
	if q == `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE` {
		return row(c.s.auth.plan.LocalAdminUsername, c.s.auth.role, c.s.auth.active, c.s.auth.provider), nil
	}
	if strings.Contains(q, "FROM system_backup_installation_owner_") {
		if c.working == nil || !strings.HasSuffix(q, " FOR SHARE") && !strings.HasSuffix(q, " FOR UPDATE") {
			return nil, errors.New("unlocked original source query")
		}
		if len(args) < 2 || args[0].Value != c.s.auth.plan.Target.InstallationID || args[1].Value != c.s.auth.plan.EnrollmentID {
			return nil, errors.New("foreign installation source")
		}
		if strings.HasPrefix(q, "SELECT head_revision,") {
			if c.working.head == nil {
				return empty(6), nil
			}
			return row(c.working.head...), nil
		}
		if strings.HasPrefix(q, "SELECT signed_head,signature FROM") {
			if c.working.head == nil {
				return empty(2), nil
			}
			return row(c.working.head[2], c.working.head[3]), nil
		}
		if len(args) != 4 {
			return nil, errors.New("foreign grant source")
		}
		v, ok := c.working.grants[grantKey(args[2].Value.(string), args[3].Value)]
		if strings.HasPrefix(q, "SELECT record_sha256 FROM") {
			if !ok {
				return empty(1), nil
			}
			return row(v[0]), nil
		}
		if !ok {
			return empty(5), nil
		}
		return row(v...), nil
	}
	return c.base.QueryContext(ctx, q, args)
}
func (c *authorityConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.working == nil || c.readonly {
		return nil, errors.New("write outside original writable transaction")
	}
	v := func(n int) driver.Value { return args[n].Value }
	switch {
	case strings.HasPrefix(q, "INSERT INTO system_backup_installation_owner_heads("):
		if len(args) != 6 || c.working.head != nil {
			return nil, errors.New("duplicate/invalid head")
		}
		c.working.head = []driver.Value{v(2), v(3), bytes.Clone(v(4).([]byte)), bytes.Clone(v(5).([]byte)), "active", int64(1)}
	case strings.HasPrefix(q, "UPDATE system_backup_installation_owner_heads SET"):
		if len(args) != 10 || c.working.head == nil {
			return nil, errors.New("missing current head")
		}
		old := c.working.head
		if counter(old[5]) != counter(v(7)) || counter(old[0]) != counter(v(8)) || old[1] != v(9) || old[4] != "active" {
			return driver.RowsAffected(0), nil
		}
		c.working.head = []driver.Value{v(0), v(1), bytes.Clone(v(2).([]byte)), bytes.Clone(v(3).([]byte)), v(4), int64(counter(old[5]) + 1)}
	case strings.HasPrefix(q, "INSERT INTO system_backup_installation_owner_grants("):
		if c.s.failGrantInsert {
			return nil, errors.New("original grant insert rejected")
		}
		if len(args) != 7 {
			return nil, errors.New("invalid grant insert")
		}
		key := grantKey(v(2).(string), v(3))
		if _, ok := c.working.grants[key]; ok {
			return nil, errors.New("duplicate grant")
		}
		c.working.grants[key] = []driver.Value{v(4), bytes.Clone(v(5).([]byte)), bytes.Clone(v(6).([]byte)), "active", int64(1)}
	case strings.HasPrefix(q, "UPDATE system_backup_installation_owner_grants SET grant_state='revoked'"):
		if len(args) != 6 {
			return nil, errors.New("invalid revoke")
		}
		key := grantKey(v(2).(string), v(3))
		old, ok := c.working.grants[key]
		if !ok || counter(old[4]) != counter(v(4)) || old[0] != v(5) || old[3] != "active" {
			return driver.RowsAffected(0), nil
		}
		next := cloneValues(old)
		next[3] = "revoked"
		next[4] = int64(counter(old[4]) + 1)
		c.working.grants[key] = next
	default:
		return nil, errors.New("non-owner source write attempted")
	}
	c.s.writes++
	return driver.RowsAffected(1), nil
}

func requireNoOpenAuthorityTx(t *testing.T, s *authoritySQLState) {
	t.Helper()
	if s.openTx.Load() != 0 {
		t.Error("network/provider I/O under original SQL locks")
	}
}
