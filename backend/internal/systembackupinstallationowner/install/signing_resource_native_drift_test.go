//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql"
	"testing"

	owner "clawreef/internal/systembackupinstallationowner"
)

func nativeSignerRejectIndexedStateAndSignatureDrift(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput) {
	t.Helper()
	input := inputs[0]
	p := input.Pin
	args := []any{p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose}
	reject := func() {
		t.Helper()
		tx, err := f.n.consumer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		view := &nativeSignerReadView{Tx: tx, ctx: ctx}
		if snapshot, err := owner.ReadSigningResourceCandidate(ctx, view, p); err == nil || snapshot != nil {
			t.Fatal("actual consumer accepted indexed mismatch or invalid original signature")
		}
	}
	// The DDL permits either indexed state independently. It is the REAL A
	// consumer that must reject head active/grant revoked; ENUM is not a join.
	if one(f.n.root.ExecContext(ctx, `UPDATE system_backup_signing_resource_grants SET grant_state='revoked' WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND record_revision=1`, args...)) != nil {
		t.Fatal("owned indexed-state drift injection")
	}
	reject()
	if one(f.n.root.ExecContext(ctx, `UPDATE system_backup_signing_resource_grants SET grant_state='active' WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND record_revision=1`, args...)) != nil {
		t.Fatal("restore exact original owned indexed state")
	}
	bundle, err := DecodeSigningResourceBundle(input.Bundle, input.SHA256, p)
	if err != nil {
		t.Fatal(err)
	}
	withSignature := append([]any{make([]byte, 64)}, args...)
	if one(f.n.root.ExecContext(ctx, `UPDATE system_backup_signing_resource_heads SET signature=? WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=?`, withSignature...)) != nil {
		t.Fatal("owned signature drift injection")
	}
	reject()
	withSignature[0] = bundle.HeadSignature
	if one(f.n.root.ExecContext(ctx, `UPDATE system_backup_signing_resource_heads SET signature=? WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=?`, withSignature...)) != nil {
		t.Fatal("restore exact original owned head signature")
	}
	nativeSignerExactFour(t, ctx, f, inputs)
}
