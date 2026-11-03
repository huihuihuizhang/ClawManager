package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Strict SQL transport model around the actual A authenticated installer.
// It is not a native database/schema/permission or provider observation.
type signerSQLData struct{ heads, grants map[string][]driver.Value }
type signerSQLModel struct {
	base                *authoritySQLState
	data                signerSQLData
	trace               []string
	execs, captureReads int
	loseCommit          bool
}
type signerSQLConnector struct{ model *signerSQLModel }
type signerSQLConn struct {
	base     driver.Conn
	model    *signerSQLModel
	working  *signerSQLData
	readonly bool
}
type signerSQLTx struct {
	conn *signerSQLConn
	base driver.Tx
}

func cloneSignerSQLData(in signerSQLData) signerSQLData {
	out := signerSQLData{heads: map[string][]driver.Value{}, grants: map[string][]driver.Value{}}
	for key, row := range in.heads {
		out.heads[key] = cloneValues(row)
	}
	for key, row := range in.grants {
		out.grants[key] = cloneValues(row)
	}
	return out
}
func (c signerSQLConnector) Driver() driver.Driver { return authDriver{} }
func (c signerSQLConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (authorityConnector{s: c.model.base}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &signerSQLConn{base: base, model: c.model}, nil
}
func (c *signerSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (c *signerSQLConn) Close() error { return c.base.Close() }
func (c *signerSQLConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *signerSQLConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if c.working != nil {
		return nil, errors.New("nested transaction")
	}
	tx, err := c.base.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	data := cloneSignerSQLData(c.model.data)
	c.working = &data
	c.readonly = options.ReadOnly
	return &signerSQLTx{conn: c, base: tx}, nil
}
func (tx *signerSQLTx) Rollback() error { tx.conn.working = nil; return tx.base.Rollback() }
func (tx *signerSQLTx) Commit() error {
	if tx.conn.working == nil {
		return errors.New("transaction closed")
	}
	data := cloneSignerSQLData(*tx.conn.working)
	if err := tx.base.Commit(); err != nil {
		tx.conn.working = nil
		return err
	}
	if !tx.conn.readonly {
		tx.conn.model.data = data
	}
	tx.conn.working = nil
	if tx.conn.model.loseCommit && !tx.conn.readonly {
		tx.conn.model.loseCommit = false
		return errors.New("original commit acknowledged outcome unknown")
	}
	return nil
}
func (c *signerSQLConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "system_backup_installation_owner_") {
		c.model.captureReads++
		return nil, errors.New("capture domain forbidden")
	}
	if !strings.Contains(query, "system_backup_signing_resource_") {
		return c.base.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	if c.working == nil || ctx.Err() != nil || len(args) < 4 || !strings.HasSuffix(query, " FOR SHARE") && !strings.HasSuffix(query, " FOR UPDATE") || c.readonly && strings.HasSuffix(query, " FOR UPDATE") {
		return nil, errors.New("unlocked signer read")
	}
	if args[0].Value != c.model.base.auth.plan.Target.InstallationID || args[1].Value != c.model.base.auth.plan.EnrollmentID {
		return nil, errors.New("foreign signer target")
	}
	purpose, _ := args[3].Value.(string)
	if strings.Contains(query, "FROM system_backup_signing_resource_heads") {
		c.model.trace = append(c.model.trace, "head:"+purpose)
		if row := c.working.heads[purpose]; row != nil {
			return rowValues(row), nil
		}
		return empty(9), nil
	}
	c.model.trace = append(c.model.trace, "grant:"+purpose)
	if row := c.working.grants[purpose]; row != nil {
		return rowValues(row), nil
	}
	return empty(6), nil
}
func rowValues(values []driver.Value) driver.Rows {
	return &authorityRows{width: len(values), values: [][]driver.Value{cloneValues(values)}}
}
func (c *signerSQLConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.working == nil || c.readonly || ctx.Err() != nil || !strings.Contains(query, "system_backup_signing_resource_") {
		return nil, errors.New("unowned signer write")
	}
	values := make([]driver.Value, len(args))
	for n, arg := range args {
		values[n] = arg.Value
	}
	c.model.execs++
	if strings.HasPrefix(query, "INSERT INTO system_backup_signing_resource_heads") {
		p := values[3].(string)
		if c.working.heads[p] != nil {
			return driver.RowsAffected(0), nil
		}
		c.model.trace = append(c.model.trace, "write-head:"+p)
		c.working.heads[p] = []driver.Value{values[4], values[5], values[6], values[7], values[8], values[9], values[10], "active", int64(1)}
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(query, "INSERT INTO system_backup_signing_resource_grants") {
		p := values[3].(string)
		if c.working.grants[p] != nil || c.working.heads[p] == nil {
			return driver.RowsAffected(0), nil
		}
		c.model.trace = append(c.model.trace, "write-grant:"+p)
		c.working.grants[p] = []driver.Value{values[6], values[7], values[8], values[9], "active", int64(1)}
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(query, "UPDATE system_backup_signing_resource_heads") {
		p := values[6].(string)
		r := c.working.heads[p]
		if len(r) != 9 || counter(r[0]) != counter(values[7]) || counter(r[1]) != counter(values[8]) || r[2] != values[9] || counter(r[3]) != counter(values[10]) || r[4] != values[11] || counter(r[8]) != counter(values[12]) || r[7] != "active" || !reflect.DeepEqual(r[5], values[13]) || !reflect.DeepEqual(r[6], values[14]) {
			return driver.RowsAffected(0), nil
		}
		r[0], r[4], r[5], r[6], r[7], r[8] = int64(2), values[0], values[1], values[2], "revoked", int64(counter(r[8])+1)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(query, "UPDATE system_backup_signing_resource_grants") {
		p := values[3].(string)
		r := c.working.grants[p]
		if len(r) != 6 || counter(r[0]) != counter(values[6]) || r[1] != values[7] || counter(r[5]) != counter(values[8]) || r[4] != "active" || !reflect.DeepEqual(r[2], values[9]) || !reflect.DeepEqual(r[3], values[10]) {
			return driver.RowsAffected(0), nil
		}
		r[4], r[5] = "revoked", int64(counter(r[5])+1)
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unexpected signer write")
}

func signerSQLFixture(t *testing.T) (*authorityFixture, *signerSQLModel, SigningResourceSQLInput, SigningResourceBundle) {
	t.Helper()
	pin, bundle, f := originalSigningResourceBundleFixture(t)
	model := &signerSQLModel{base: f.s, data: signerSQLData{heads: map[string][]driver.Value{}, grants: map[string][]driver.Value{}}}
	db := sql.OpenDB(signerSQLConnector{model: model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.i.db = db
	raw, err := canonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return f, model, SigningResourceSQLInput{Pin: pin, Bundle: raw, SHA256: hash(raw)}, bundle
}
func signerSQLRevoke(t *testing.T, input SigningResourceSQLInput, bundle SigningResourceBundle, f *authorityFixture, cas owner.SigningResourceCAS) SigningResourceSQLInput {
	t.Helper()
	head, err := owner.InspectSigningResourceHead(bundle.Head, bundle.HeadSignature, input.Pin)
	if err != nil {
		t.Fatal(err)
	}
	head.HeadRevision, head.State = 2, "revoked"
	bundle.Action, bundle.Expected = "revoke", cas
	bundle.Head, err = owner.EncodeSigningResourceHead(head)
	if err != nil {
		t.Fatal(err)
	}
	bundle.HeadSignature = ed25519.Sign(f.key, append([]byte(owner.SigningResourceHeadDomain), bundle.Head...))
	raw, err := canonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	input.Bundle, input.SHA256 = raw, hash(raw)
	return input
}

func TestSigningResourceSQLInstallReplayRevokeAndUnknownResolveComponent(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "ack", true: "commit-unknown"}[lost], func(t *testing.T) {
			f, model, input, bundle := signerSQLFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			beforeSigns := f.signs.Load()
			model.loseCommit = lost
			receipt, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input})
			if lost {
				if !errors.Is(err, ErrCommitUnknown) {
					t.Fatal("lost original commit incorrectly reported", err)
				}
			} else if err != nil || len(receipt.Items) != 1 {
				t.Fatal("actual independent two-row import", err)
			}
			receipt, err = f.i.ResolveSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input})
			if err != nil || len(receipt.Items) != 1 || receipt.Items[0].Comparison.State != "active" || receipt.Items[0].Comparison.HeadRowVersion != 1 {
				t.Fatal("exact committed tuple did not resolve", err)
			}
			writes := model.execs
			replay, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input})
			if err != nil || !replay.Items[0].Replayed || model.execs != writes {
				t.Fatal("same original retry changed rows", err)
			}
			revoked := signerSQLRevoke(t, input, bundle, f, receipt.Items[0].Comparison)
			if receipt, err = f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{revoked}); err != nil || receipt.Items[0].Comparison.State != "revoked" || receipt.Items[0].Comparison.HeadRowVersion != 2 || receipt.Items[0].Comparison.GrantRowVersion != 2 {
				t.Fatal("terminal revocation failed", err)
			}
			if !bytes.Equal(model.data.grants[input.Pin.Purpose][2].([]byte), bundle.Grant) || !bytes.Equal(model.data.grants[input.Pin.Purpose][3].([]byte), bundle.GrantSignature) {
				t.Fatal("revocation rewrote original grant/signature")
			}
			writes = model.execs
			if _, err = f.i.ResolveSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input}); err == nil {
				t.Fatal("old active tuple resolved over current revoke")
			}
			if _, err = f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input}); err == nil || model.execs != writes {
				t.Fatal("revoked signer resource reactivated")
			}
			if _, err = f.i.ResolveSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{revoked}); err != nil || model.execs != writes || model.captureReads != 0 || f.signs.Load() != beforeSigns || f.s.openTx.Load() != 0 {
				t.Fatal("resolve mutated/signed/probed capture or left transaction", err)
			}
		})
	}
}

func TestSigningResourceSQLRejectsChangedExpectedTupleWithoutWritesComponent(t *testing.T) {
	f, model, input, bundle := signerSQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	receipt, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input})
	if err != nil {
		t.Fatal(err)
	}
	wrong := receipt.Items[0].Comparison
	wrong.GrantRowVersion++
	changed := signerSQLRevoke(t, input, bundle, f, wrong)
	before := cloneSignerSQLData(model.data)
	writes := model.execs
	if _, err = f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{changed}); err == nil || model.execs != writes || !reflect.DeepEqual(before, model.data) {
		t.Fatal("changed exact CAS accepted or wrote partial state")
	}
}

func TestSigningResourceSQLPurposeOrderUsesOriginalCodecComponent(t *testing.T) {
	f, model, catalog, bundle := signerSQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	grant, err := owner.InspectSigningResourceGrant(bundle.Grant, bundle.GrantSignature, catalog.Pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range grant.Bindings {
		if binding.Purpose == "acceptance_record" {
			grant.Binding = binding
		}
	}
	grant.GrantID = "acceptance-original"
	id, err := owner.SigningResourceReferenceIdentity(grant.Binding)
	if err != nil {
		t.Fatal(err)
	}
	grant.Reference.Purpose, grant.Reference.IdentityHash, grant.Reference.Version = "acceptance_signing", id, grant.Binding.KeyVersion
	b := bundle
	b.Grant, err = owner.EncodeSigningResourceGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	b.GrantSignature = ed25519.Sign(f.key, append([]byte(owner.SigningResourceGrantDomain), b.Grant...))
	p := catalog.Pin
	p.Purpose, p.GrantID, p.GrantSHA256 = "acceptance_record", grant.GrantID, hash(b.Grant)
	h, err := owner.InspectSigningResourceHead(bundle.Head, bundle.HeadSignature, catalog.Pin)
	if err != nil {
		t.Fatal(err)
	}
	h.Purpose, h.CurrentGrantID, h.GrantSHA256 = p.Purpose, p.GrantID, p.GrantSHA256
	b.Head, err = owner.EncodeSigningResourceHead(h)
	if err != nil {
		t.Fatal(err)
	}
	b.HeadSignature = ed25519.Sign(f.key, append([]byte(owner.SigningResourceHeadDomain), b.Head...))
	raw, err := canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	acceptance := SigningResourceSQLInput{Pin: p, Bundle: raw, SHA256: hash(raw)}
	receipt, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{catalog, acceptance})
	if err != nil || len(receipt.Items) != 2 || receipt.Items[0].Purpose != "acceptance_record" || receipt.Items[1].Purpose != "catalog_record" {
		t.Fatal("two-purpose original import", err)
	}
	if len(model.trace) < 3 || model.trace[0] != "head:acceptance_record" || model.trace[1] != "head:catalog_record" || model.trace[2] != "write-head:acceptance_record" {
		t.Fatal("purpose gap lock order or write-before-all-locks", model.trace)
	}
}
