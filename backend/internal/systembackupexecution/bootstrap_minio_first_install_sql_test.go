package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
)

// Strict transactional SQL TRANSPORT MODEL only. All authenticated Installer,
// signature, seven-row lifecycle and actual TLS probe methods run unchanged.
// Native MySQL/wait-edge evidence belongs to root's separate verified roots.
type minioFirstInstallData struct {
	head, grant []driver.Value
	refs        map[string][]driver.Value
}
type minioFirstInstallSQL struct {
	f                   *minioTerminalComponent
	auth                *producerComponentSQL
	data                minioFirstInstallData
	execs, writeCommits int
	lostAck             bool
	order               []string
}
type minioFirstInstallConnector struct{ m *minioFirstInstallSQL }
type minioFirstInstallConn struct {
	m               *minioFirstInstallSQL
	working         *minioFirstInstallData
	readonly, admin bool
}
type minioFirstInstallTx struct{ c *minioFirstInstallConn }

func (c minioFirstInstallConnector) Driver() driver.Driver { return producerComponentDriver{} }
func (c minioFirstInstallConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &minioFirstInstallConn{m: c.m}, nil
}
func (*minioFirstInstallConn) Close() error { return nil }
func (*minioFirstInstallConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared component query")
}
func (*minioFirstInstallConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit original transaction required")
}
func firstInstallValues(v []driver.Value) []driver.Value {
	if v == nil {
		return nil
	}
	out := append([]driver.Value(nil), v...)
	for i, value := range out {
		if raw, ok := value.([]byte); ok {
			out[i] = append([]byte(nil), raw...)
		}
	}
	return out
}
func firstInstallClone(d minioFirstInstallData) minioFirstInstallData {
	out := minioFirstInstallData{head: firstInstallValues(d.head), grant: firstInstallValues(d.grant), refs: map[string][]driver.Value{}}
	for key, value := range d.refs {
		out.refs[key] = firstInstallValues(value)
	}
	return out
}
func (c *minioFirstInstallConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if ctx.Err() != nil || c.working != nil || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.m.auth.openTx.Load() != 0 || c.m.f.model.open.Load() != 0 {
		return nil, errors.New("wrong/nested original transaction")
	}
	d := firstInstallClone(c.m.data)
	c.working = &d
	c.readonly = o.ReadOnly
	c.admin = false
	c.m.auth.openTx.Add(1)
	c.m.f.model.open.Add(1)
	return minioFirstInstallTx{c: c}, nil
}
func (t minioFirstInstallTx) Commit() error {
	c := t.c
	if c.working == nil {
		return errors.New("missing original transaction")
	}
	if !c.readonly {
		c.m.data = firstInstallClone(*c.working)
		c.m.writeCommits++
	}
	c.working = nil
	c.m.auth.openTx.Add(-1)
	c.m.f.model.open.Add(-1)
	if !c.readonly && c.m.lostAck {
		c.m.lostAck = false
		return errors.New("controlled loss after component metadata commit")
	}
	return nil
}
func (t minioFirstInstallTx) Rollback() error {
	c := t.c
	if c.working != nil {
		c.working = nil
		c.m.auth.openTx.Add(-1)
		c.m.f.model.open.Add(-1)
	}
	return nil
}
func (c *minioFirstInstallConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m := c.m
	f := m.f
	if q == "SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE" {
		if c.working == nil {
			return nil, errors.New("admin lock outside transaction")
		}
		c.admin = true
	}
	if q == "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE" {
		if !c.admin || len(a) != 1 || a[0].Value != m.auth.userID {
			return nil, errors.New("wrong/unlocked original admin")
		}
		return componentRow(m.auth.username, "admin", true, "local"), nil
	}
	if !strings.Contains(q, "FROM system_backup_minio_owner_") {
		return (&producerComponentConn{model: m.auth}).QueryContext(ctx, q, a)
	}
	p := f.input.Pin
	if c.working == nil || !c.admin || len(a) < 3 || a[0].Value != p.Target.InstallationID || a[1].Value != p.Enrollment.ID || a[2].Value != p.AuthorityID || !strings.HasSuffix(q, " FOR SHARE") && !strings.HasSuffix(q, " FOR UPDATE") {
		return nil, errors.New("wrong original seven-row source key/prefix")
	}
	if c.readonly && strings.HasSuffix(q, " FOR UPDATE") {
		return nil, errors.New("readonly path acquired exclusive lock")
	}
	d := c.working
	if strings.Contains(q, "FROM system_backup_minio_owner_heads ") {
		if d.head == nil {
			width := 9
			if strings.HasPrefix(q, "SELECT current_grant_id,") {
				width = 4
			}
			return &producerComponentRows{width: width}, nil
		}
		if strings.HasPrefix(q, "SELECT current_grant_id,") {
			return componentRow(d.head[2], d.head[3], d.head[1], d.head[8]), nil
		}
		return componentRow(d.head...), nil
	}
	if len(a) < 5 || a[3].Value != p.GrantID || a[4].Value != int64(1) {
		return nil, errors.New("wrong original selected grant")
	}
	if strings.Contains(q, "FROM system_backup_minio_owner_grants ") {
		if d.grant == nil {
			return &producerComponentRows{width: 6}, nil
		}
		if strings.HasPrefix(q, "SELECT row_version ") {
			return componentRow(d.grant[5]), nil
		}
		return componentRow(d.grant...), nil
	}
	if len(a) != 6 {
		return nil, errors.New("wrong exact purpose key")
	}
	purpose, ok := a[5].Value.(string)
	if !ok {
		return nil, errors.New("wrong purpose type")
	}
	ref := d.refs[purpose]
	if ref == nil {
		width := 10
		if strings.HasPrefix(q, "SELECT row_version ") {
			width = 1
		}
		return &producerComponentRows{width: width}, nil
	}
	if strings.HasPrefix(q, "SELECT row_version ") {
		return componentRow(ref[9]), nil
	}
	return componentRow(ref...), nil
}
func (c *minioFirstInstallConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil || c.working == nil || c.readonly || !c.admin {
		return nil, errors.New("unlocked/unqualified original mutation")
	}
	a := make([]driver.Value, len(args))
	for i, value := range args {
		a[i] = value.Value
	}
	d := c.working
	p := c.m.f.input.Pin
	if len(a) < 3 || a[0] != p.Target.InstallationID || a[1] != p.Enrollment.ID || a[2] != p.AuthorityID {
		return nil, errors.New("foreign installation mutation")
	}
	switch {
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_heads("):
		if len(a) != 10 || d.head != nil {
			return nil, errors.New("head uniqueness/key violation")
		}
		d.head = firstInstallValues([]driver.Value{a[3], a[4], a[5], a[6], a[7], a[8], a[9], "active", int64(1)})
		c.m.order = append(c.m.order, "head")
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_grants("):
		if len(a) != 9 || d.head == nil || d.grant != nil || a[3] != p.GrantID || a[4] != int64(1) {
			return nil, errors.New("grant FK/key violation")
		}
		d.grant = firstInstallValues([]driver.Value{a[5], a[6], a[7], a[8], "active", int64(1)})
		c.m.order = append(c.m.order, "grant")
	case strings.HasPrefix(q, "INSERT INTO system_backup_minio_owner_refs("):
		if len(a) != 14 || d.grant == nil || a[3] != p.GrantID || a[4] != int64(1) {
			return nil, errors.New("ref FK/key violation")
		}
		purpose, ok := a[5].(string)
		if !ok || d.refs[purpose] != nil {
			return nil, errors.New("ref unique purpose violation")
		}
		d.refs[purpose] = firstInstallValues([]driver.Value{a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], "active", int64(1)})
		c.m.order = append(c.m.order, purpose)
	default:
		return nil, errors.New("entry mutated outside original initial seven-row metadata")
	}
	c.m.execs++
	return driver.RowsAffected(1), nil
}
