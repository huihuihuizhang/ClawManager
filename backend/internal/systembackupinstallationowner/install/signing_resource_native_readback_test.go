//go:build systembackup_mysql

package install

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
)

// Actual SELECT-only SQL view of DATA; it cannot mint the actual A terminal
// guarded read view. Every clock comes from the same real native transaction.
type nativeSignerReadView struct {
	*sql.Tx
	ctx    context.Context
	floor  time.Time
	failed bool
}

func (*nativeSignerReadView) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, owner.ErrOwner
}
func (v *nativeSignerReadView) SampleTime(ctx context.Context) (time.Time, error) {
	if v == nil || v.failed || !consumerSameContext(v.ctx, ctx) || ctx.Err() != nil {
		if v != nil {
			v.failed = true
		}
		return time.Time{}, owner.ErrOwner
	}
	var now time.Time
	if v.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || now.IsZero() || now.Nanosecond()%1000 != 0 || now.Before(v.floor) {
		v.failed = true
		return time.Time{}, owner.ErrOwner
	}
	v.floor = now
	return now, nil
}

// A supplies REAL IssueSigningResourceInstall output for this exact native
// installer/enrollment. D only verifies and wraps it; never changes a Target,
// public key, purpose, record, signature or original time window.
func nativeSignerIssuedInputs(t *testing.T, f *nativeSigningSQLFixture, pins []owner.SigningResourceTrustPin, bundles [][]byte) []SigningResourceSQLInput {
	t.Helper()
	if len(pins) != 2 || len(bundles) != 2 {
		t.Fatal("both actual original A-issued signer bundles required")
	}
	inputs := make([]SigningResourceSQLInput, 2)
	for n, p := range pins {
		plan := f.n.f.i.plan
		if p.Purpose != owner.SigningResourcePurposes()[n] || p.Target != plan.Target || p.EnrollmentID != plan.EnrollmentID || p.EnrollmentRevision != plan.EnrollmentRevision || p.IssuerID != plan.IssuerID || p.EnrollmentDocumentSHA256 != f.n.f.enrollment.DocumentSHA256 || !bytes.Equal(p.Issuer, f.n.f.i.public) {
			t.Fatal("A original signing tuple does not match independently enrolled native target")
		}
		b, err := DecodeSigningResourceBundle(bundles[n], hash(bundles[n]), p)
		if err != nil || b.Action != "install" || b.PlanSHA256 != f.n.f.i.planHash || b.EnrollmentDocumentSHA256 != f.n.f.enrollment.DocumentSHA256 {
			t.Fatal("A original bundle/issuer/enrollment verification", err)
		}
		if _, err := owner.InspectSigningResourceGrant(b.Grant, b.GrantSignature, p); err != nil {
			t.Fatal("actual enrolled grant signature", err)
		}
		if _, err := owner.InspectSigningResourceHead(b.Head, b.HeadSignature, p); err != nil {
			t.Fatal("actual enrolled head signature", err)
		}
		inputs[n] = SigningResourceSQLInput{Pin: p, Bundle: bytes.Clone(bundles[n]), SHA256: hash(bundles[n])}
	}
	return inputs
}

func nativeSignerConsumer(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput, active bool) *sql.Tx {
	t.Helper()
	tx, err := f.n.consumer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	view := &nativeSignerReadView{Tx: tx, ctx: ctx}
	for _, input := range inputs {
		snapshot, err := owner.ReadSigningResourceCandidate(ctx, view, input.Pin)
		if err != nil {
			tx.Rollback()
			t.Fatal("actual SELECT-only consumer/codec/head-grant read", err)
		}
		if active != (snapshot.RequireCurrent(view.floor) == nil) {
			tx.Rollback()
			t.Fatal("revoked/expired native resource admitted or active source refused")
		}
	}
	return tx
}

func nativeSignerExactFour(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput) {
	t.Helper()
	if len(inputs) != 2 {
		t.Fatal("exact four-row set requires both original purposes")
	}
	for _, table := range []string{"system_backup_signing_resource_heads", "system_backup_signing_resource_grants"} {
		var count int
		if f.n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 2 {
			t.Fatal("native signer row set is partial or contains unknown rows", table)
		}
	}
	tx, err := f.n.consumer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	view := &nativeSignerReadView{Tx: tx, ctx: ctx}
	for _, input := range inputs {
		b, err := DecodeSigningResourceBundle(input.Bundle, input.SHA256, input.Pin)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := owner.ReadSigningResourceCandidate(ctx, view, input.Pin)
		if err != nil {
			t.Fatal("independent actual consumer tuple", err)
		}
		grant, signature, head, headSignature, err := snapshot.SignedRecords()
		if err != nil || !bytes.Equal(grant, b.Grant) || !bytes.Equal(signature, b.GrantSignature) || !bytes.Equal(head, b.Head) || !bytes.Equal(headSignature, b.HeadSignature) {
			t.Fatal("native exact raw/signature tuple differs", err)
		}
		cas, err := snapshot.Comparison()
		if err != nil {
			t.Fatal(err)
		}
		version := uint64(1)
		if b.Action == "revoke" {
			version = 2
		}
		if cas.HeadRevision != version || cas.HeadRowVersion != version || cas.GrantRowVersion != version || cas.GrantRevision != 1 || cas.PermissionEpoch != 1 {
			t.Fatal("native exact original CAS changed")
		}
	}
}

func nativeSignerRevoke(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput) []SigningResourceSQLInput {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private original revocation inputs")
	}
	result := make([]SigningResourceSQLInput, 0, len(inputs))
	for _, input := range inputs {
		if SaveFrozenSigningResourceBundle(directory, input.Bundle, input.SHA256, input.Pin) != nil {
			t.Fatal("save actual A original bundle")
		}
		file := directory + string(os.PathSeparator) + input.Pin.Purpose + ".signing-resource.bundle.json"
		raw, err := f.n.f.i.IssueSigningResourceRevocation(ctx, f.n.f.password, f.n.f.enrollment, input.Pin, file, input.SHA256, f.n.f.key)
		if err != nil {
			t.Fatal("actual A provider-independent terminal revocation", err)
		}
		old, err := DecodeSigningResourceBundle(input.Bundle, input.SHA256, input.Pin)
		if err != nil {
			t.Fatal(err)
		}
		revoked, err := DecodeSigningResourceBundle(raw, hash(raw), input.Pin)
		if err != nil || !bytes.Equal(old.Grant, revoked.Grant) || !bytes.Equal(old.GrantSignature, revoked.GrantSignature) {
			t.Fatal("A revoke re-signed/replaced original grant", err)
		}
		result = append(result, SigningResourceSQLInput{Pin: input.Pin, Bundle: raw, SHA256: hash(raw)})
	}
	return result
}
