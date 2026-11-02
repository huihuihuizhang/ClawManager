package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
	pd "clawreef/internal/systembackupproducer"
)

// Strict seven-row SQL transport MODEL, never actual native lock evidence.
// The factory-issued pd.Transaction, SampleTime floor/failure latch, signed
// shared reader and concrete terminal methods are the real implementations.
type minioTerminalComponentSQL struct {
	f                                           *minioTerminalComponent
	open                                        atomic.Int32
	rowVersion                                  int64
	revoked, disabled, foreignAccount, refDrift bool
	clockAt                                     time.Time
	clockFailure                                bool
	clockQueries                                int
	order                                       []string
	prefix                                      bool
}
type minioTerminalComponentConnector struct{ m *minioTerminalComponentSQL }
type minioTerminalComponentDriver struct{}
type minioTerminalComponentConn struct{ m *minioTerminalComponentSQL }
type minioTerminalComponentTx struct{ m *minioTerminalComponentSQL }
type minioTerminalComponentRows struct {
	values []driver.Value
	done   bool
}

func (c minioTerminalComponentConnector) Driver() driver.Driver {
	return minioTerminalComponentDriver{}
}
func (c minioTerminalComponentConnector) Connect(context.Context) (driver.Conn, error) {
	return &minioTerminalComponentConn{m: c.m}, nil
}
func (minioTerminalComponentDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("original component connector required")
}
func (*minioTerminalComponentConn) Close() error { return nil }
func (*minioTerminalComponentConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare in strict component transport")
}
func (*minioTerminalComponentConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit original transaction required")
}
func (c *minioTerminalComponentConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if ctx.Err() != nil || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !c.m.open.CompareAndSwap(0, 1) {
		return nil, errors.New("wrong component transaction")
	}
	c.m.prefix = false
	return minioTerminalComponentTx{m: c.m}, nil
}
func (t minioTerminalComponentTx) Commit() error {
	t.m.open.Store(0)
	return errors.New("component must not commit")
}
func (t minioTerminalComponentTx) Rollback() error { t.m.open.Store(0); return nil }
func (*minioTerminalComponentConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("concrete terminal attempted SQL mutation")
}
func (r *minioTerminalComponentRows) Columns() []string {
	names := make([]string, len(r.values))
	for i := range names {
		names[i] = "column" + strconv.Itoa(i)
	}
	return names
}
func (*minioTerminalComponentRows) Close() error { return nil }
func (r *minioTerminalComponentRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(values, r.values)
	return nil
}
func minioTerminalComponentRow(values ...driver.Value) (driver.Rows, error) {
	return &minioTerminalComponentRows{values: values}, nil
}
func (m *minioTerminalComponentSQL) now() time.Time {
	if !m.clockAt.IsZero() {
		return m.clockAt
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
func (c *minioTerminalComponentConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	f := m.f
	g := f.declaration
	p := f.input.Pin
	if ctx.Err() != nil || m.open.Load() != 1 {
		return nil, errors.New("query outside original component transaction")
	}
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return minioTerminalComponentRow(g.Target.ServerUUID, g.Target.Database, m.now(), int64(0))
	case "SELECT UTC_TIMESTAMP(6)":
		m.clockQueries++
		if m.clockFailure {
			return nil, errors.New("controlled original sample failure")
		}
		return minioTerminalComponentRow(m.now())
	case "SELECT CURRENT_USER(),@@server_uuid,DATABASE()":
		account := g.Target.ConsumerDatabaseAccount
		if m.foreignAccount {
			account = "foreign@localhost"
		}
		return minioTerminalComponentRow(account, g.Target.ServerUUID, g.Target.Database)
	case "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE":
		if len(args) != 1 || args[0].Value != g.Actor.LocalAdminUserID {
			return nil, errors.New("foreign admin key")
		}
		if !m.prefix {
			m.prefix = true
			m.order = append(m.order, "admin-prefix")
		} else {
			m.order = append(m.order, "admin-tail")
		}
		return minioTerminalComponentRow(g.Actor.LocalAdminUsername, "admin", !m.disabled, "local")
	}
	if !m.prefix || !strings.HasSuffix(q, " FOR SHARE") || len(args) < 3 || args[0].Value != p.Target.InstallationID || args[1].Value != p.Enrollment.ID || args[2].Value != p.AuthorityID {
		return nil, errors.New("unplanned source query or missing original admin prefix")
	}
	state := ma.StateActive
	row := m.rowVersion
	if m.revoked {
		state = ma.StateRevoked
		row++
	}
	switch {
	case strings.HasPrefix(q, "SELECT head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_minio_owner_heads "):
		if len(args) != 3 {
			return nil, errors.New("wrong exact head key")
		}
		m.order = append(m.order, "head")
		head := f.head
		raw, signature := f.bundle.Head, f.bundle.HeadSignature
		if m.revoked {
			head.HeadRevision = 2
			head.State = state
			var e error
			raw, e = ma.EncodeSQLHead(head)
			if e != nil {
				return nil, e
			}
			signature = ed25519.Sign(f.key, append([]byte(ma.SQLHeadDomain), raw...))
		}
		return minioTerminalComponentRow(int64(head.HeadRevision), int64(1), g.GrantID, int64(1), hash(raw), raw, signature, state, row)
	case strings.HasPrefix(q, "SELECT permission_epoch,record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_minio_owner_grants "):
		if len(args) != 5 || args[3].Value != g.GrantID || args[4].Value != int64(1) {
			return nil, errors.New("wrong exact original grant")
		}
		m.order = append(m.order, "grant")
		return minioTerminalComponentRow(int64(1), hash(f.bundle.Grant), f.bundle.Grant, f.bundle.GrantSignature, state, row)
	case strings.HasPrefix(q, "SELECT descriptor_sha256,provider_identity_hash,scope_hash,identity_hash,identity_version,ref_sha256,signed_ref,signature,ref_state,row_version FROM system_backup_minio_owner_refs "):
		if len(args) != 6 || args[3].Value != g.GrantID || args[4].Value != int64(1) {
			return nil, errors.New("wrong exact original ref")
		}
		purpose, ok := args[5].Value.(string)
		if !ok {
			return nil, errors.New("wrong purpose type")
		}
		for i, record := range f.refs {
			r := record.Reference
			if string(r.Purpose) != purpose {
				continue
			}
			m.order = append(m.order, purpose)
			identity := string(r.IdentityHash)
			if m.refDrift {
				identity = hash([]byte("foreign-reference"))
			}
			signed := f.bundle.References[i]
			return minioTerminalComponentRow(string(r.DescriptorSHA256), string(r.ProviderIdentityHash), string(r.ScopeSHA256), identity, r.IdentityVersion, hash(signed.Record), signed.Record, signed.Signature, state, row)
		}
	}
	return nil, errors.New("unexpected SQL/clock/provider callback in strict terminal component")
}

// A test-only admin prefix policy supplies no MinIO approval and never stands
// in for A20. The concrete owner must independently read/verify all seven
// original records through the actual factory-issued transaction capability.
type minioTerminalComponentPolicy struct{ f *minioTerminalComponent }

func (p minioTerminalComponentPolicy) LockAndAuthorize(ctx context.Context, q pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	var username, role, provider string
	var active bool
	e := q.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE", p.f.grant.UserID).Scan(&username, &role, &active, &provider)
	if e != nil {
		return pd.GuardPlan{}, e
	}
	return pd.GuardPlan{BindingHash: pd.Hash(hash([]byte("original-component-guard"))), Deadlines: []time.Time{p.f.declaration.Until}}, nil
}
func (p minioTerminalComponentPolicy) Recheck(ctx context.Context, q pd.ReadSQL, _ pd.Scope, _ pd.GuardPlan, _ time.Time) error {
	var username, role, provider string
	var active bool
	if e := q.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE", p.f.grant.UserID).Scan(&username, &role, &active, &provider); e != nil {
		return e
	}
	if username != p.f.grant.Username || role != "admin" || !active || provider != "local" {
		return errors.New("original component admin changed at final guard")
	}
	return nil
}

func (f *minioTerminalComponent) guard(t *testing.T, ctx context.Context, work func(*pd.Transaction) error) error {
	t.Helper()
	db := sql.OpenDB(minioTerminalComponentConnector{m: f.model})
	defer db.Close()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	scope := pd.Scope{Installation: pd.Installation(f.grant.InstallationID), ServerUUID: pd.ServerUUID(f.grant.ServerUUID), Database: pd.Database(f.grant.Database)}
	guard, e := pd.NewTransactions(db, scope, minioTerminalComponentPolicy{f: f})
	if e != nil {
		t.Fatal(e)
	}
	return guard.GuardInTx(ctx, tx, func(_ context.Context, q *pd.Transaction) error { return work(q) })
}
