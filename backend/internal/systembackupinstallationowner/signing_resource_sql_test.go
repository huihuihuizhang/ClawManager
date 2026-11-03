package systembackupinstallationowner

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Query/row protocol model only. Native MySQL locking/privileges must be
// verified by root after D supplies the actual two-table migration/lifecycle.
type signingResourceSQLModel struct {
	f                                    *signingResourceFixture
	head, headSig                        []byte
	headState, grantState, account, role string
	headRevision                         uint64
	queries                              []string
	now                                  time.Time
	samples                              int
	regress                              bool
}
type signingResourceSQLConnector struct{ data *signingResourceSQLModel }

func (c signingResourceSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return c.data, nil
}
func (signingResourceSQLConnector) Driver() driver.Driver { return ownerSQLDriver{} }
func (*signingResourceSQLModel) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unsupported")
}
func (*signingResourceSQLModel) Close() error              { return nil }
func (*signingResourceSQLModel) Begin() (driver.Tx, error) { return nil, errors.New("unsupported") }
func (m *signingResourceSQLModel) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m.queries = append(m.queries, q)
	p := m.f.pin
	var values []driver.Value
	check := func(want ...any) bool {
		if len(args) != len(want) {
			return false
		}
		for n, arg := range args {
			if !reflect.DeepEqual(arg.Value, want[n]) {
				return false
			}
		}
		return true
	}
	switch q {
	case `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`:
		if !check() {
			return nil, ErrOwner
		}
		values = []driver.Value{m.account, p.Target.ServerUUID, p.Target.Database}
	case `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`:
		if !check(p.Actor.UserID) {
			return nil, ErrOwner
		}
		values = []driver.Value{p.Actor.Username, m.role, true, "local"}
	case SigningResourceHeadReadSQL:
		if !check(p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose) {
			return nil, ErrOwner
		}
		values = []driver.Value{int64(m.headRevision), int64(1), p.GrantID, int64(1), digest(m.head), m.head, m.headSig, m.headState, int64(m.headRevision)}
	case SigningResourceGrantReadSQL:
		if !check(p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, p.GrantID, int64(p.GrantRevision)) {
			return nil, ErrOwner
		}
		values = []driver.Value{int64(1), p.GrantSHA256, m.f.raw, m.f.sig, m.grantState, int64(m.headRevision)}
	default:
		// Raw UTC scans, task/config/capture reads, or broad privilege reads fail.
		return nil, errors.New("unexpected signer-resource query")
	}
	return &ownerSQLRows{values: values}, nil
}

type signingResourceSQLView struct {
	*sql.DB
	model *signingResourceSQLModel
}

func (q signingResourceSQLView) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, ErrOwner
}

func (q signingResourceSQLView) SampleTime(context.Context) (time.Time, error) {
	q.model.samples++
	if q.model.regress && q.model.samples > 1 {
		return q.model.now.Add(-time.Microsecond), nil
	}
	return q.model.now, nil
}
func originalSigningResourceSQLFixture(t *testing.T, revoked bool) (signingResourceSQLView, *signingResourceSQLModel) {
	t.Helper()
	f := originalSigningResourceFixture(t, "catalog_record")
	raw, sig := f.head(t, revoked)
	m := &signingResourceSQLModel{f: f, head: raw, headSig: sig, headState: "active", grantState: "active", account: f.pin.Target.DatabaseAccount, role: "admin", headRevision: 1, now: time.Now().UTC().Truncate(time.Microsecond)}
	if revoked {
		m.headState, m.grantState, m.headRevision = "revoked", "revoked", 2
	}
	db := sql.OpenDB(signingResourceSQLConnector{data: m})
	t.Cleanup(func() { _ = db.Close() })
	return signingResourceSQLView{DB: db, model: m}, m
}

func TestSigningResourceCurrentSQLExactPurposeAndSharedClock(t *testing.T) {
	q, m := originalSigningResourceSQLFixture(t, false)
	s, e := ReadSigningResourceCandidate(context.Background(), q, m.f.pin)
	if e != nil || s == nil || s.RequireCurrent(m.now) != nil || m.samples != 2 {
		t.Fatal("current exact source", e)
	}
	want := []string{`SELECT CURRENT_USER(),@@server_uuid,DATABASE()`, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, SigningResourceHeadReadSQL, SigningResourceGrantReadSQL}
	if !reflect.DeepEqual(m.queries, want) {
		t.Fatal("admin -> purpose head -> grant ordering", m.queries)
	}
	if s.RequireCurrent(m.f.grant.Until) == nil {
		t.Fatal("expired current grant admitted")
	}
	// Read-only DATA snapshots cannot create the guarded terminal transaction.
	p := &signingResourcePrepared{}
	p.origin = p
	before := len(m.queries)
	if _, e := p.AuthorizeIdentity(context.Background(), q); e == nil || len(m.queries) != before || !p.failed.Load() {
		t.Fatal("ordinary SQL view minted terminal authority")
	}
}

func TestSigningResourceCurrentRevocationAndSourceDrift(t *testing.T) {
	q, m := originalSigningResourceSQLFixture(t, true)
	s, e := ReadSigningResourceCandidate(context.Background(), q, m.f.pin)
	if e != nil || s == nil || s.RequireCurrent(m.now) == nil {
		t.Fatal("revoked current data/history separation", e)
	}
	for _, tc := range []struct {
		name string
		edit func(*signingResourceSQLModel)
	}{
		{"role_revoked", func(m *signingResourceSQLModel) { m.role = "user" }},
		{"wrong_account", func(m *signingResourceSQLModel) { m.account = "other@localhost" }},
		{"head_signature", func(m *signingResourceSQLModel) { m.headSig[0] ^= 1 }},
		{"grant_signature", func(m *signingResourceSQLModel) { m.f.sig[0] ^= 1 }},
		{"head_projection", func(m *signingResourceSQLModel) { m.headState = "revoked" }},
		{"grant_projection", func(m *signingResourceSQLModel) { m.grantState = "revoked" }},
		{"clock_regression", func(m *signingResourceSQLModel) { m.regress = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, m := originalSigningResourceSQLFixture(t, false)
			tc.edit(m)
			if _, e := ReadSigningResourceCandidate(context.Background(), q, m.f.pin); e == nil {
				t.Fatal("invalid current source accepted")
			}
		})
	}
}
