//go:build systembackup_mysql

package install

import (
	"context"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// DDL-only negative scaffolding stays in an explicitly rolled-back root
// transaction. These unsigned '{}' payloads are NEVER owner inputs, committed
// authority, permission proof, a source grant or successful lifecycle rows.
func nativeSignerDDLConstraints(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture) {
	t.Helper()
	tx, err := f.n.root.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	requireCode := func(err error, code uint16) {
		t.Helper()
		var mysqlErr *mysql.MySQLError
		if !errors.As(err, &mysqlErr) || mysqlErr.Number != code {
			t.Fatal("actual native FK/CHECK boundary differs", code, err)
		}
	}
	headSQL := `INSERT INTO system_backup_signing_resource_heads(installation_id,enrollment_id,authority_id,purpose,head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version) VALUES(?,?,?,'acceptance_record',?,?,'constraint-grant',1,?,?,?,'active',1)`
	payload := []byte(`{}`)
	base := []any{f.n.f.i.plan.Target.InstallationID, f.n.f.i.plan.EnrollmentID, "constraint-only-never-owner", uint64(1), uint64(1), hash(payload), payload, make([]byte, 64)}
	for _, fault := range []string{"head-revision", "permission-epoch", "short-signature", "wrong-raw-sha", "invalid-json"} {
		values := append([]any{}, base...)
		switch fault {
		case "head-revision":
			values[3] = uint64(3)
		case "permission-epoch":
			values[4] = uint64(2)
		case "short-signature":
			values[7] = make([]byte, 63)
		case "wrong-raw-sha":
			values[5] = hash([]byte("different-raw"))
		case "invalid-json":
			values[6] = []byte("not-json")
			values[5] = hash(values[6].([]byte))
		}
		_, err := tx.ExecContext(ctx, headSQL, values...)
		requireCode(err, 3819)
	}
	grantSQL := `INSERT INTO system_backup_signing_resource_grants(installation_id,enrollment_id,authority_id,purpose,grant_id,record_revision,permission_epoch,record_sha256,signed_record,signature,grant_state,row_version) VALUES(?,?,?,'acceptance_record','constraint-grant',?,1,?,?,?,'active',1)`
	grantValues := []any{base[0], base[1], base[2], uint64(1), hash(payload), payload, make([]byte, 64)}
	_, err = tx.ExecContext(ctx, grantSQL, grantValues...)
	requireCode(err, 1452)
	if _, err = tx.ExecContext(ctx, headSQL, base...); err != nil {
		t.Fatal("DDL-only transactional FK anchor", err)
	}
	grantValues[3] = uint64(2)
	_, err = tx.ExecContext(ctx, grantSQL, grantValues...)
	requireCode(err, 3819)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"system_backup_signing_resource_heads", "system_backup_signing_resource_grants"} {
		var count int
		if f.n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("DDL-only negative scaffolding escaped rollback", table)
		}
	}
}
