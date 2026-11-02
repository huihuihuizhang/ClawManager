package systembackupminioauthority

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Strict SELECT-only transport model. Not actual MySQL/TLS/GRANT evidence.
// Any FOR UPDATE, Exec, prepare or transaction completion by source fails.
type sqlSourceModel struct {
	f                                         *sqlRecordFixture
	scenario                                  string
	open, writes, exclusiveLocks, sharedLocks int
	prefix                                    bool
	order                                     []string
}
type sqlSourceConnector struct{ m *sqlSourceModel }
type sqlSourceDriver struct{}
type sqlSourceConn struct{ m *sqlSourceModel }
type sqlSourceTx struct{ m *sqlSourceModel }
type sqlSourceRows struct {
	width  int
	values [][]driver.Value
}

func (c sqlSourceConnector) Driver() driver.Driver { return sqlSourceDriver{} }
func (c sqlSourceConnector) Connect(context.Context) (driver.Conn, error) {
	return &sqlSourceConn{c.m}, nil
}
func (sqlSourceDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("explicit test connector only")
}
func (*sqlSourceConn) Close() error { return nil }
func (*sqlSourceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare forbidden")
}
func (*sqlSourceConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit readonly transaction required")
}
func (c *sqlSourceConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if ctx.Err() != nil || !o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.m.open != 0 {
		return nil, errors.New("wrong original tx")
	}
	c.m.open++
	return sqlSourceTx{c.m}, nil
}
func (t sqlSourceTx) Commit() error   { t.m.open--; return nil }
func (t sqlSourceTx) Rollback() error { t.m.open--; return nil }
func (c *sqlSourceConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.m.writes++
	return nil, errors.New("SELECT-only role")
}
func (r *sqlSourceRows) Columns() []string {
	v := make([]string, r.width)
	for n := range v {
		v[n] = "original_column"
	}
	return v
}
func (*sqlSourceRows) Close() error { return nil }
func (r *sqlSourceRows) Next(v []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(v, r.values[0])
	r.values = r.values[1:]
	return nil
}
func sqlSourceRow(v ...driver.Value) driver.Rows { return &sqlSourceRows{len(v), [][]driver.Value{v}} }

func (c *sqlSourceConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	f := m.f
	if ctx.Err() != nil || m.open != 1 {
		return nil, errors.New("escaped original transaction")
	}
	if strings.Contains(q, "FOR UPDATE") {
		m.exclusiveLocks++
		return nil, errors.New("SELECT-only role rejects FOR UPDATE")
	}
	if strings.HasSuffix(q, "FOR SHARE") {
		m.sharedLocks++
	}
	state := f.head.State
	if m.scenario == "head-state-index-drift" {
		state = StateRevoked
	}
	switch {
	case q == `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`:
		account := f.pin.Target.ConsumerDatabaseAccount
		if m.scenario == "installer-account" {
			account = f.grant.Actor.InstallerDatabaseAccount
		}
		if m.scenario == "wrong-account" {
			account = "foreign@localhost"
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if m.scenario == "expired-original-window" {
			now = f.grant.Until.Add(time.Microsecond)
		}
		return sqlSourceRow(account, f.pin.Target.ServerUUID, f.pin.Target.Database, now), nil
	case q == `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`:
		if len(args) != 1 || args[0].Value != f.grant.Actor.LocalAdminUserID {
			return nil, errors.New("wrong original actor")
		}
		if !m.prefix {
			m.prefix = true
			m.order = append(m.order, "admin-prefix")
		} else {
			m.order = append(m.order, "admin-tail")
		}
		return sqlSourceRow(f.grant.Actor.LocalAdminUsername, "admin", m.scenario != "actor-disabled", "local"), nil
	case strings.HasPrefix(q, `SELECT head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_minio_owner_heads `):
		if !m.prefix || !strings.HasSuffix(q, "FOR SHARE") || len(args) != 3 || args[0].Value != f.pin.Target.InstallationID || args[1].Value != f.pin.Enrollment.ID || args[2].Value != f.pin.AuthorityID {
			return nil, errors.New("wrong original head key or prefix")
		}
		m.order = append(m.order, "head")
		return sqlSourceRow(int64(f.head.HeadRevision), int64(1), f.grant.GrantID, int64(1), string(digest(f.headRaw)), f.headRaw, f.headSig, state, int64(1)), nil
	case strings.HasPrefix(q, `SELECT permission_epoch,record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_minio_owner_grants `):
		if !strings.HasSuffix(q, "FOR SHARE") || len(args) != 5 || args[3].Value != f.grant.GrantID || args[4].Value != int64(1) {
			return nil, errors.New("wrong selected grant")
		}
		m.order = append(m.order, "grant")
		grantSHA := digest(f.grantRaw)
		if m.scenario == "grant-hash-drift" {
			grantSHA = digest([]byte("wrong"))
		}
		return sqlSourceRow(int64(1), string(grantSHA), f.grantRaw, f.grantSig, state, int64(1)), nil
	case strings.HasPrefix(q, `SELECT descriptor_sha256,provider_identity_hash,scope_hash,identity_hash,identity_version,ref_sha256,signed_ref,signature,ref_state,row_version FROM system_backup_minio_owner_refs `):
		if !strings.HasSuffix(q, "FOR SHARE") || len(args) != 6 {
			return nil, errors.New("wrong original ref query")
		}
		p, ok := args[5].Value.(string)
		if !ok {
			return nil, errors.New("wrong purpose type")
		}
		for n, v := range f.signedRefs {
			if string(v.Purpose) != p {
				continue
			}
			m.order = append(m.order, p)
			if n == 0 && m.scenario == "missing-ref" {
				return &sqlSourceRows{width: 10}, nil
			}
			r := f.refs[n].Reference
			identity := r.IdentityHash
			if n == 0 && m.scenario == "ref-index-drift" {
				identity = digest([]byte("wrong identity"))
			}
			refState := state
			if n == 0 && m.scenario == "ref-state-drift" {
				refState = StateRevoked
			}
			return sqlSourceRow(string(r.DescriptorSHA256), string(r.ProviderIdentityHash), string(r.ScopeSHA256), string(identity), r.IdentityVersion, string(digest(v.Record)), v.Record, v.Signature, refState, int64(1)), nil
		}
	}
	return nil, errors.New("unplanned original SQL query")
}

func openSQLSourceModel(t *testing.T, m *sqlSourceModel) (context.Context, *sql.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	db := sql.OpenDB(sqlSourceConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var username, role, provider string
	var active bool
	if e = tx.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, m.f.grant.Actor.LocalAdminUserID).Scan(&username, &role, &active, &provider); e != nil {
		t.Fatal(e)
	}
	return ctx, tx
}

func TestMinIOSQLConsumerUsesSelectOnlySharedOriginalRowsInOrder(t *testing.T) {
	f := newSQLRecordFixture(t)
	m := &sqlSourceModel{f: f}
	ctx, tx := openSQLSourceModel(t, m)
	s, e := ReadSQLCurrent(ctx, tx, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	expected, now, e := s.Comparison()
	if e != nil || expected.HeadRowVersion != 1 || len(expected.ReferenceRows) != 5 || s.RequireCurrent(now) != nil {
		t.Fatal("current original identity tuple/window", e)
	}
	want := []string{"admin-prefix", "head", "grant", "artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read", "admin-tail"}
	if !reflect.DeepEqual(m.order, want) || m.exclusiveLocks != 0 || m.writes != 0 || m.sharedLocks != 9 || m.open != 1 {
		t.Fatal("wrong SELECT-only original lock strength/order/transaction", m.order, m.sharedLocks)
	}
	expected.ReferenceRows[0].RowVersion = 99
	again, _, e := s.Comparison()
	if e != nil || again.ReferenceRows[0].RowVersion != 1 {
		t.Fatal("caller mutated original CAS tuple", e)
	}
	if e = tx.Rollback(); e != nil || m.open != 0 {
		t.Fatal("caller retains sole original transaction lifecycle", e)
	}
}

func TestMinIOSQLCurrentRejectsProjectionStateIdentityAndWindowDrift(t *testing.T) {
	for _, scenario := range []string{"wrong-account", "grant-hash-drift", "ref-index-drift", "missing-ref", "ref-state-drift", "head-state-index-drift", "actor-disabled", "signed-head-revoked", "expired-original-window", "installer-account"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSQLRecordFixture(t)
			if scenario == "signed-head-revoked" {
				f.head.State = StateRevoked
				f.head.HeadRevision = 2
				var e error
				f.headRaw, e = EncodeSQLHead(f.head)
				if e != nil {
					t.Fatal(e)
				}
				f.headSig = ed25519.Sign(f.key, append([]byte(SQLHeadDomain), f.headRaw...))
			}
			m := &sqlSourceModel{f: f, scenario: scenario}
			ctx, tx := openSQLSourceModel(t, m)
			s, e := ReadSQLCurrent(ctx, tx, f.pin)
			inspectable := scenario == "signed-head-revoked" || scenario == "expired-original-window"
			if (e == nil) != inspectable {
				t.Fatal("wrong current-source refusal", e)
			}
			if inspectable {
				_, now, e := s.Comparison()
				if e != nil || s.RequireCurrent(now) == nil {
					t.Fatal("revoked/expired current identity became fresh authorization", e)
				}
			}
			if scenario == "installer-account" {
				if _, e = ReadSQLCurrentForInstaller(ctx, tx, f.pin); e != nil {
					t.Fatal("actual distinct signed installer account metadata read", e)
				}
			}
			if m.exclusiveLocks != 0 || m.writes != 0 || m.open != 1 {
				t.Fatal("source acquired write permission or completed original transaction")
			}
		})
	}
}
