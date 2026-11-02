package systembackupinstallationowner

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type ownerSQLData struct {
	f                                        recordFixture
	head                                     Head
	headRaw, headSig                         []byte
	headState, grantState, username, account string
	active                                   bool
	rowVersion                               uint64
	now                                      time.Time
	queries                                  []string
	afterFacts                               bool
}
type ownerSQLConnector struct{ data *ownerSQLData }

func (c ownerSQLConnector) Driver() driver.Driver                        { return ownerSQLDriver{} }
func (c ownerSQLConnector) Connect(context.Context) (driver.Conn, error) { return c.data, nil }

type ownerSQLDriver struct{}

func (ownerSQLDriver) Open(string) (driver.Conn, error)                              { return nil, errors.New("unused") }
func (*ownerSQLData) Prepare(string) (driver.Stmt, error)                            { return nil, errors.New("unused") }
func (*ownerSQLData) Close() error                                                   { return nil }
func (d *ownerSQLData) Begin() (driver.Tx, error)                                    { return d, nil }
func (d *ownerSQLData) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return d, nil }
func (*ownerSQLData) Commit() error                                                  { return nil }
func (*ownerSQLData) Rollback() error                                                { return nil }

type ownerSQLRows struct {
	values []driver.Value
	used   bool
}

func (r *ownerSQLRows) Columns() []string {
	out := make([]string, len(r.values))
	for i := range out {
		out[i] = "column"
	}
	return out
}
func (*ownerSQLRows) Close() error { return nil }
func (r *ownerSQLRows) Next(out []driver.Value) error {
	if r.used {
		return io.EOF
	}
	r.used = true
	copy(out, r.values)
	return nil
}
func (d *ownerSQLData) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	d.queries = append(d.queries, q)
	var v []driver.Value
	switch {
	case q == "SELECT UTC_TIMESTAMP(6)":
		v = []driver.Value{d.now}
		if d.afterFacts && len(d.queries) > 2 {
			v[0] = d.f.record.Until
		}
	case strings.Contains(q, "FROM users"):
		v = []driver.Value{d.username, "admin", d.active, "local"}
	case strings.Contains(q, "SELECT head_revision"):
		v = []driver.Value{int64(d.head.Revision), digest(d.headRaw), d.headRaw, d.headSig, d.headState, int64(d.rowVersion)}
	case strings.Contains(q, "SELECT signed_head,signature"):
		v = []driver.Value{d.headRaw, d.headSig}
	case strings.Contains(q, "FROM system_backup_installation_owner_grants"):
		v = []driver.Value{d.f.pin.RecordSHA256, d.f.raw, d.f.sig, d.grantState, int64(d.rowVersion)}
	case q == "SELECT CURRENT_USER(),@@server_uuid,DATABASE()":
		v = []driver.Value{d.account, d.f.pin.ServerUUID, d.f.pin.Database}
	default:
		return nil, errors.New("unexpected query")
	}
	return &ownerSQLRows{values: v}, nil
}
func newOwnerSQLFixture(t *testing.T) (*PreparedCaptureSigning, *ownerSQLData, *sql.Tx, context.Context) {
	t.Helper()
	f := ownerRecordFixture(t)
	h := Head{SchemaVersion: HeadVersion, InstallationID: f.pin.InstallationID, EnrollmentID: f.pin.EnrollmentID, IssuerID: f.pin.IssuerID, OwnerSubject: f.pin.OwnerSubject, EnrollmentRevision: 1, Revision: 1, GrantID: f.pin.GrantID, GrantRevision: 1, RecordSHA256: f.pin.RecordSHA256, State: "active", NotBefore: f.record.NotBefore, Until: f.record.Until}
	raw, _ := EncodeHead(h)
	data := &ownerSQLData{f: f, head: h, headRaw: raw, headSig: ed25519.Sign(f.private, append([]byte(HeadDomain), raw...)), headState: "active", grantState: "active", username: f.record.Actor.Username, account: f.pin.DatabaseAccount, active: true, rowVersion: 1, now: time.Now().UTC().Truncate(time.Microsecond)}
	db := sql.OpenDB(ownerSQLConnector{data})
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tx.Rollback() })
	dir := t.TempDir()
	files := RecordFiles{filepath.Join(dir, "record.json"), filepath.Join(dir, "record.sig")}
	if os.WriteFile(files.RecordFile, f.raw, 0600) != nil || os.WriteFile(files.SignatureFile, f.sig, 0600) != nil {
		t.Fatal("files")
	}
	auth, e := VerifyRecord(f.raw, f.sig, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	// Private DATA setup skips resource Prepare deliberately; it grants no full
	// bootstrap success. All current identity checks still use actual signatures.
	p := &PreparedCaptureSigning{validator: &CaptureSigningValidator{pin: f.pin, files: files}, ctx: ctx, auth: auth}
	p.origin = p
	return p, data, tx, ctx
}

func TestInstallationOwnerCopiedPreparationCannotMintAnotherL2Guard(t *testing.T) {
	p, d, tx, ctx := newOwnerSQLFixture(t)
	var copied PreparedCaptureSigning
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(p).Elem())
	before := len(d.queries)
	if _, e := copied.AuthorizeOriginal(ctx, tx, copied.grant, copied.config); e == nil || len(d.queries) != before {
		t.Fatal("copied preparation reached SQL or minted authority")
	}
	if _, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config); e != nil {
		t.Fatal("copy rejection altered original private lifecycle", e)
	}
}
func TestInstallationOwnerCurrentHeadAdminAndIdentityRemainMandatory(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*ownerSQLData)
	}{
		{"revoked_head", func(d *ownerSQLData) { d.headState = "revoked" }},
		{"revoked_grant", func(d *ownerSQLData) { d.grantState = "revoked" }},
		{"inactive_admin", func(d *ownerSQLData) { d.active = false }},
		{"wrong_admin", func(d *ownerSQLData) { d.username = "other" }},
		{"wrong_sql_account", func(d *ownerSQLData) { d.account = "other@localhost" }},
		{"head_signature", func(d *ownerSQLData) { d.headSig[0] ^= 1 }},
		{"grant_signature", func(d *ownerSQLData) { d.f.sig[0] ^= 1 }},
		{"expiry_after_delivery", func(d *ownerSQLData) { d.afterFacts = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d, tx, ctx := newOwnerSQLFixture(t)
			tc.edit(d)
			if _, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config); e == nil {
				t.Fatal("invalid current owner accepted")
			}
			if !p.failed {
				t.Fatal("failure not latched")
			}
		})
	}
}
func TestInstallationOwnerHistoricalIdentityDoesNotReusePhysicalPermission(t *testing.T) {
	p, d, tx, ctx := newOwnerSQLFixture(t)
	g, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config)
	if e != nil {
		t.Fatal(e)
	}
	if g.RecheckOriginalIdentity(ctx, tx) != nil {
		t.Fatal("current historical identity refused because observation missing")
	}
	if p.Recheck(ctx, tx, d.now) == nil {
		t.Fatal("missing physical observation admitted new consumption")
	}
	p2, d2, tx2, ctx2 := newOwnerSQLFixture(t)
	g2, e := p2.AuthorizeOriginal(ctx2, tx2, p2.grant, p2.config)
	if e != nil {
		t.Fatal(e)
	}
	d2.headState = "revoked"
	if g2.RecheckOriginalIdentity(ctx2, tx2) == nil {
		t.Fatal("history bypassed current revocation")
	}
}
func TestInstallationOwnerUnlinkedL2AndForeignTransactionRefuse(t *testing.T) {
	p, d, tx, ctx := newOwnerSQLFixture(t)
	if p.Recheck(ctx, tx, d.now) == nil {
		t.Fatal("resource check minted L2 authority")
	}
	p, d, tx, ctx = newOwnerSQLFixture(t)
	g, e := p.AuthorizeOriginal(ctx, tx, p.grant, p.config)
	if e != nil {
		t.Fatal(e)
	}
	if g.RecheckOriginalIdentity(context.Background(), tx) == nil {
		t.Fatal("foreign context accepted")
	}
	p, d, tx, ctx = newOwnerSQLFixture(t)
	g, e = p.AuthorizeOriginal(ctx, tx, p.grant, p.config)
	if e != nil {
		t.Fatal(e)
	}
	if g.RecheckOriginalIdentity(ctx, new(sql.Tx)) == nil {
		t.Fatal("foreign transaction accepted")
	}
}
