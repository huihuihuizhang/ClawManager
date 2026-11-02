package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync/atomic"
	"time"
)

// Strict actual database/sql transport model with isolated working copies,
// seven-row commit/rollback, CAS predicates and lost commit acknowledgement.
// It is NOT native InnoDB/TLS/GRANT/row-wait evidence.
type minioSQLData struct {
	head, grant []driver.Value
	refs        map[string][]driver.Value
}
type minioSQLModel struct {
	auth                                         *authSQLState
	data                                         minioSQLData
	installation, enrollment, authority, grantID string
	open                                         atomic.Int32
	commits, execs, captureQueries               int
	commitLost                                   bool
	failPurpose, failOperation                   string
	clock                                        time.Time
	writeOrder                                   []string
	afterWriteCommit                             func()
	expireAfterPurpose                           string
	expireClock                                  time.Time
}
type minioSQLConnector struct{ m *minioSQLModel }
type minioSQLConn struct {
	m               *minioSQLModel
	base            *authConn
	working         *minioSQLData
	readonly, admin bool
}
type minioSQLTx struct{ c *minioSQLConn }

func (c minioSQLConnector) Driver() driver.Driver { return authDriver{} }
func (c minioSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &minioSQLConn{m: c.m, base: &authConn{s: c.m.auth}}, nil
}
func (*minioSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unplanned prepare")
}
func (*minioSQLConn) Close() error { return nil }
func (*minioSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit original tx required")
}
func cloneMinioSQLData(d minioSQLData) minioSQLData {
	c := minioSQLData{head: cloneValues(d.head), grant: cloneValues(d.grant), refs: map[string][]driver.Value{}}
	for k, v := range d.refs {
		c.refs[k] = cloneValues(v)
	}
	return c
}
func (c *minioSQLConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if ctx.Err() != nil || c.working != nil || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.m.open.Load() != 0 {
		return nil, errors.New("wrong/nested original tx")
	}
	d := cloneMinioSQLData(c.m.data)
	c.working = &d
	c.readonly = o.ReadOnly
	c.admin = false
	c.base.tx = true
	c.m.open.Add(1)
	return minioSQLTx{c}, nil
}
func (t minioSQLTx) Commit() error {
	c := t.c
	if c.working == nil {
		return errors.New("missing tx")
	}
	if !c.readonly {
		c.m.data = cloneMinioSQLData(*c.working)
		c.m.commits++
	}
	c.working = nil
	c.base.tx = false
	c.m.open.Add(-1)
	if !c.readonly && c.m.afterWriteCommit != nil {
		hook := c.m.afterWriteCommit
		c.m.afterWriteCommit = nil
		hook()
	}
	if !c.readonly && c.m.commitLost {
		c.m.commitLost = false
		return errors.New("lost actual commit response")
	}
	return nil
}
func (t minioSQLTx) Rollback() error {
	c := t.c
	if c.working != nil {
		c.working = nil
		c.base.tx = false
		c.m.open.Add(-1)
	}
	return nil
}

func (c *minioSQLConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if strings.Contains(q, "system_backup_installation_owner_") {
		c.m.captureQueries++
		return nil, errors.New("capture ledger is not MinIO domain authority")
	}
	if q == `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)` && !c.m.clock.IsZero() {
		return row(c.m.auth.account, c.m.auth.server, c.m.auth.plan.Target.Database, c.m.clock), nil
	}
	if q == `SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE` {
		if c.working == nil {
			return nil, errors.New("admin prefix outside tx")
		}
		c.admin = true
		return c.base.QueryContext(ctx, q, a)
	}
	if q == `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE` {
		if !c.admin || len(a) != 1 || a[0].Value != int64(7) {
			return nil, errors.New("wrong/unlocked original actor")
		}
		return row(c.m.auth.plan.LocalAdminUsername, c.m.auth.role, c.m.auth.active, c.m.auth.provider), nil
	}
	if !strings.Contains(q, "FROM system_backup_minio_owner_") {
		return c.base.QueryContext(ctx, q, a)
	}
	if c.working == nil || !c.admin || len(a) < 3 || a[0].Value != c.m.installation || a[1].Value != c.m.enrollment || a[2].Value != c.m.authority || !strings.HasSuffix(q, " FOR SHARE") && !strings.HasSuffix(q, " FOR UPDATE") {
		return nil, errors.New("wrong/unlocked MinIO original key")
	}
	if c.readonly && strings.HasSuffix(q, " FOR UPDATE") {
		return nil, errors.New("readonly source cannot use write lock")
	}
	d := c.working
	if strings.Contains(q, "FROM system_backup_minio_owner_heads ") {
		if d.head == nil {
			if strings.HasPrefix(q, "SELECT current_grant_id,") {
				return empty(4), nil
			}
			return empty(9), nil
		}
		if strings.HasPrefix(q, "SELECT current_grant_id,") {
			return row(d.head[2], d.head[3], d.head[1], d.head[8]), nil
		}
		return row(d.head...), nil
	}
	if len(a) < 5 || a[3].Value != c.m.grantID || counter(a[4].Value) != 1 {
		return nil, errors.New("wrong selected grant key")
	}
	if strings.Contains(q, "FROM system_backup_minio_owner_grants ") {
		if d.grant == nil {
			return empty(6), nil
		}
		if strings.HasPrefix(q, "SELECT row_version ") {
			return row(d.grant[5]), nil
		}
		return row(d.grant...), nil
	}
	if len(a) != 6 {
		return nil, errors.New("wrong exact ref key")
	}
	p, ok := a[5].Value.(string)
	if !ok {
		return nil, errors.New("wrong purpose type")
	}
	v, ok := d.refs[p]
	if !ok {
		if strings.HasPrefix(q, "SELECT row_version ") {
			return empty(1), nil
		}
		return empty(10), nil
	}
	if strings.HasPrefix(q, "SELECT row_version ") {
		return row(v[9]), nil
	}
	return row(v...), nil
}

func (c *minioSQLConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil || c.working == nil || c.readonly || !c.admin {
		return nil, errors.New("unauthorized original mutation")
	}
	a := make([]driver.Value, len(args))
	for n, v := range args {
		a[n] = v.Value
	}
	d := c.working
	c.m.execs++
	scope := func(start int) bool {
		return len(a) > start+2 && a[start] == c.m.installation && a[start+1] == c.m.enrollment && a[start+2] == c.m.authority
	}
	switch {
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_heads("):
		if len(a) != 10 || !scope(0) || d.head != nil {
			return nil, errors.New("head unique/FK/key conflict")
		}
		d.head = cloneValues([]driver.Value{a[3], a[4], a[5], a[6], a[7], a[8], a[9], "active", int64(1)})
		c.m.writeOrder = append(c.m.writeOrder, "insert-head")
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_grants("):
		if len(a) != 9 || !scope(0) || d.head == nil || d.grant != nil || a[3] != c.m.grantID || counter(a[4]) != 1 {
			return nil, errors.New("grant unique/FK/key conflict")
		}
		d.grant = cloneValues([]driver.Value{a[5], a[6], a[7], a[8], "active", int64(1)})
		c.m.writeOrder = append(c.m.writeOrder, "insert-grant")
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_refs("):
		if len(a) != 14 || !scope(0) || d.grant == nil || a[3] != c.m.grantID || counter(a[4]) != 1 {
			return nil, errors.New("ref FK/key conflict")
		}
		p, ok := a[5].(string)
		if !ok || d.refs[p] != nil {
			return nil, errors.New("ref unique conflict")
		}
		if c.m.failOperation == "insert" && c.m.failPurpose == p {
			return driver.RowsAffected(0), nil
		}
		d.refs[p] = cloneValues([]driver.Value{a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], "active", int64(1)})
		c.m.writeOrder = append(c.m.writeOrder, "insert-"+p)
		if c.m.expireAfterPurpose == p {
			c.m.clock = c.m.expireClock
		}
	case strings.HasPrefix(q, "UPDATE system_backup_minio_owner_heads SET"):
		if len(a) != 13 || !scope(4) || d.head == nil || counter(d.head[0]) != counter(a[7]) || counter(d.head[1]) != counter(a[8]) || d.head[2] != a[9] || counter(d.head[3]) != counter(a[10]) || d.head[4] != a[11] || counter(d.head[8]) != counter(a[12]) || d.head[7] != "active" {
			return driver.RowsAffected(0), nil
		}
		d.head = cloneValues([]driver.Value{a[0], d.head[1], d.head[2], d.head[3], a[1], a[2], a[3], "revoked", int64(counter(d.head[8]) + 1)})
		c.m.writeOrder = append(c.m.writeOrder, "revoke-head")
	case strings.HasPrefix(q, "UPDATE system_backup_minio_owner_grants SET"):
		if len(a) != 8 || !scope(0) || a[3] != c.m.grantID || counter(a[4]) != 1 || d.grant == nil || counter(d.grant[0]) != counter(a[5]) || d.grant[1] != a[6] || counter(d.grant[5]) != counter(a[7]) || d.grant[4] != "active" {
			return driver.RowsAffected(0), nil
		}
		d.grant[4] = "revoked"
		d.grant[5] = int64(counter(d.grant[5]) + 1)
		c.m.writeOrder = append(c.m.writeOrder, "revoke-grant")
	case strings.HasPrefix(q, "UPDATE system_backup_minio_owner_refs SET"):
		if len(a) != 8 || !scope(0) || a[3] != c.m.grantID || counter(a[4]) != 1 {
			return nil, errors.New("wrong revoke ref key")
		}
		p, ok := a[5].(string)
		if !ok {
			return nil, errors.New("wrong revoke purpose")
		}
		v := d.refs[p]
		if v == nil || v[5] != a[6] || counter(v[9]) != counter(a[7]) || v[8] != "active" {
			return driver.RowsAffected(0), nil
		}
		if c.m.failOperation == "revoke" && c.m.failPurpose == p {
			return driver.RowsAffected(0), nil
		}
		v[8] = "revoked"
		v[9] = int64(counter(v[9]) + 1)
		c.m.writeOrder = append(c.m.writeOrder, "revoke-"+p)
	default:
		return nil, errors.New("mutation outside three MinIO metadata tables")
	}
	return driver.RowsAffected(1), nil
}
