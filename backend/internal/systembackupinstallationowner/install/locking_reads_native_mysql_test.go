//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func requireInstallerLockReadMySQL(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") == "" || os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID") == "" {
		t.Fatal("explicit root-owned disposable TLS MySQL and independent UUID required")
	}
}

// All SQL reaches actual independently pinned TLS MySQL8.4. Enroll is called
// by the existing native fixture itself, so its original lockAdmin/commit path
// must work before this test can proceed. Kube/Vault stay controlled fixtures.
func TestInstallerLockReadNativeMySQL84ModeAndSnapshot(t *testing.T) {
	requireInstallerLockReadMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	n := newNativeAuthorityFixture(t, ctx)
	var version string
	if n.root.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version) != nil || !strings.HasPrefix(version, "8.4.") {
		t.Fatal("native MySQL8.4 required for locking-read regression")
	}
	ro, err := n.installer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Rollback()
	var id int64
	err = ro.QueryRowContext(ctx, "SELECT id FROM users WHERE id=7 FOR SHARE").Scan(&id)
	if err != nil || id != 7 {
		t.Fatal("actual READ ONLY FOR SHARE failed", err)
	}
	if err := ro.Rollback(); err != nil {
		t.Fatal("READ ONLY shared-read rollback", err)
	}
	negative, err := n.root.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer negative.Rollback()
	err = negative.QueryRowContext(ctx, "SELECT id FROM users WHERE id=7 FOR UPDATE").Scan(&id)
	var native *mysql.MySQLError
	if !errors.As(err, &native) || native.Number != 1792 {
		t.Fatal("actual READ ONLY FOR UPDATE did not enforce MySQL1792", err)
	}
	if err := negative.Rollback(); err != nil {
		t.Fatal("negative update rollback", err)
	}
	s, err := n.f.i.authenticate(ctx, n.f.password)
	if err != nil {
		t.Fatal("native original administrator", err)
	}
	current, stamp, err := snapshot(ctx, s)
	if err != nil || current.cas.HeadRevision != 0 || stamp.Before(s.sqlTime) || !stamp.Before(s.until) {
		t.Fatal("actual original locking snapshot", err)
	}
	readback, after, err := originalAdoptionAuthoritySnapshot(ctx, s)
	if err != nil || readback.cas != current.cas || after.Before(stamp) || !after.Before(s.until) {
		t.Fatal("actual original adoption authority readback", err)
	}
	// Prove that the same original FOR SHARE still holds a real row lock;
	// both READ ONLY and ordinary RR must retain the actual shared lock.
	rw, err := n.installer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Rollback()
	if _, err := s.lockAdmin(ctx, rw); err != nil {
		t.Fatal("actual lockAdmin", err)
	}
	blocked, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = n.root.ExecContext(blocked, "UPDATE users SET is_active=is_active WHERE id=7")
	timedOut := errors.Is(blocked.Err(), context.DeadlineExceeded)
	stop()
	if err == nil || !timedOut && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("original shared admin lock did not block concurrent update until deadline")
	}
	if err := rw.Rollback(); err != nil {
		t.Fatal("lock-capable RR rollback", err)
	}
	if _, err := n.root.ExecContext(ctx, "UPDATE users SET is_active=is_active WHERE id=7"); err != nil {
		t.Fatal("original shared lock not released", err)
	}
	for _, table := range []string{"system_backup_installation_owner_heads", "system_backup_installation_owner_grants"} {
		var count int
		if n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("read-only operation mutated original authority", table)
		}
	}
}

// Real original issuer -> actual full177 signer SQL import/readback -> actual
// export snapshot -> original revocation reading exact installed bytes. No
// declaration/fake-driver shortcut is used for these production lock readers.
func TestInstallerLockReadNativeSigningIssueReadbackExportAndRevoke(t *testing.T) {
	requireInstallerLockReadMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
	defer cancel()
	f := newNativeSigningSQLFixture(t, ctx)
	pins, bundles := issueSigningResourcesForNativeTarget(t, ctx, f.n.f)
	inputs := nativeSignerIssuedInputs(t, f, pins, bundles)
	if result, err := f.n.f.i.ImportSigningResourceSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, inputs); err != nil || len(result.Items) != 2 {
		t.Fatal("actual original issued signer import/readback", err)
	}
	s, err := f.n.f.i.authenticate(ctx, f.n.f.password)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := signingResourceSQLChanges(ctx, s, f.n.f.enrollment, inputs)
	if err != nil {
		t.Fatal(err)
	}
	rows, floor, err := signingResourceExportSnapshot(ctx, s, changes, s.sqlTime)
	if err != nil || len(rows) != 2 || floor.Before(s.sqlTime) || !floor.Before(s.until) {
		t.Fatal("native committed original signer export snapshot", err)
	}
	if result, err := f.n.f.i.ResolveSigningResourceSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, inputs); err != nil || len(result.Items) != 2 {
		t.Fatal("native signer current readback", err)
	}
	revoked := nativeSignerRevoke(t, ctx, f, inputs)
	if len(revoked) != 2 {
		t.Fatal("actual original revocation reads failed")
	}
	// Issuing revocation transport must leave all four installed rows active.
	nativeSignerExactFour(t, ctx, f, inputs)
}
