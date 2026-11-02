//go:build systembackup_mysql

package install

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	"github.com/go-sql-driver/mysql"
)

// Actual migration 134, two real limited MySQL accounts, real transactions and
// original L2. Kubernetes/Vault remain the explicitly controlled local fixture.
// No app admission, other resource validator or six-domain success is claimed.
func TestOwnerAuthorityNativeTLSMySQLLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	n := newNativeAuthorityFixture(t, ctx)
	f := n.f
	t.Run("real_account_privileges", func(t *testing.T) {
		var account string
		if n.installer.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&account) != nil || account != f.i.plan.InstallerDatabaseAccount {
			t.Fatal("actual installer account changed")
		}
		if n.consumer.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&account) != nil || account != f.i.plan.Target.DatabaseAccount {
			t.Fatal("actual consumer account changed")
		}
		var password string
		e := n.consumer.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=7`).Scan(&password)
		requireNativeAuthorityDenied(t, e)
		_, e = n.consumer.ExecContext(ctx, `UPDATE system_backup_installation_owner_heads SET row_version=row_version`)
		requireNativeAuthorityDenied(t, e)
		_, e = n.installer.ExecContext(ctx, `UPDATE users SET is_active=FALSE WHERE id=7`)
		requireNativeAuthorityDenied(t, e)
		_, e = n.installer.ExecContext(ctx, `DELETE FROM system_backup_installation_owner_grants`)
		requireNativeAuthorityDenied(t, e)
	})
	var initial []byte
	t.Run("initial_issue_import_original_l2", func(t *testing.T) {
		initial = nativeAuthorityIssue(t, ctx, n, "native-initial")
		var count int
		if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_heads`).Scan(&count) != nil || count != 0 {
			t.Fatal("issue wrote source rows")
		}
		r, e := f.i.ImportCapture(ctx, f.password, f.enrollment, initial, hash(initial), f.files)
		if e != nil || r.HeadRevision != 1 || r.HeadRowVersion != 1 || r.GrantRowVersion != 1 || r.Replayed {
			t.Fatal("real initial import", e, r)
		}
		nativeAuthorityExactBundle(t, ctx, n, initial)
		dir := nativeAuthorityExport(t, ctx, n, initial)
		nativeAuthorityConsume(t, ctx, n, n.consumer, dir, true)
		// Same exact bytes and source, different actual connection principal.
		nativeAuthorityConsume(t, ctx, n, n.installer, dir, false)
		beforeSigns := f.signs.Load()
		r, e = f.i.ImportCapture(ctx, f.password, f.enrollment, initial, hash(initial), f.files)
		if e != nil || !r.Replayed || f.signs.Load() != beforeSigns {
			t.Fatal("duplicate original import reprobed/rewrote", e)
		}
		nativeAuthorityExactBundle(t, ctx, n, initial)
	})
	if t.Failed() {
		return
	}
	var winner []byte
	t.Run("concurrent_original_head_cas_one_winner", func(t *testing.T) {
		packs := [][]byte{nativeAuthorityIssue(t, ctx, n, "native-race-a"), nativeAuthorityIssue(t, ctx, n, "native-race-b")}
		arrivals, release := make(chan struct{}, 2), make(chan struct{})
		raceConnector := &nativeAuthorityLostAck{base: n.installerConnector, headArrivals: arrivals, headRelease: release}
		raceDB := sql.OpenDB(raceConnector)
		raceDB.SetMaxOpenConns(4)
		defer raceDB.Close()
		racing := *f.i
		racing.db = raceDB
		type result struct {
			index   int
			receipt AuthorityReceipt
			err     error
		}
		start, results := make(chan struct{}), make(chan result, 2)
		for index, pack := range packs {
			go func(index int, pack []byte) {
				<-start
				r, e := racing.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files)
				results <- result{index: index, receipt: r, err: e}
			}(index, pack)
		}
		close(start)
		var early []result
		arrived := 0
	awaitBoth:
		for arrived < 2 {
			select {
			case <-arrivals:
				arrived++
			case r := <-results:
				early = append(early, r)
				break awaitBoth
			case <-ctx.Done():
				break awaitBoth
			}
		}
		close(release)
		if arrived != 2 {
			t.Error("both actual write transactions did not reach the original head CAS together")
		}
		successes, winnerIndex := 0, -1
		outcomes := early
		for len(outcomes) < len(packs) {
			select {
			case r := <-results:
				outcomes = append(outcomes, r)
			case <-ctx.Done():
				t.Fatal("native CAS operations did not finish")
			}
		}
		for _, r := range outcomes {
			if r.err == nil {
				successes++
				winnerIndex = r.index
				if r.receipt.HeadRevision != 2 || r.receipt.HeadRowVersion != 2 || r.receipt.Replayed {
					t.Error("concurrent import did not use original CAS")
				}
			} else if !errors.Is(r.err, ErrInstall) {
				t.Error("unexpected concurrent import outcome", r.err)
			}
		}
		if successes != 1 {
			t.Fatalf("distinct bundles for one original head: successes=%d, want exactly one", successes)
		}
		winner = packs[winnerIndex]
		nativeAuthorityExactBundle(t, ctx, n, winner)
		loser := nativeAuthorityDecode(t, packs[1-winnerIndex])
		var record owner.Record
		if decodeExact(loser.Record, &record) != nil {
			t.Fatal("loser record")
		}
		var count int
		if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_grants WHERE grant_id=?`, record.GrantID).Scan(&count) != nil || count != 0 {
			t.Fatal("losing CAS persisted grant")
		}
		if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_grants`).Scan(&count) != nil || count != 2 {
			t.Fatal("one source head race wrote extra grants")
		}
		beforeSigns := f.signs.Load()
		if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, initial, hash(initial), f.files); e == nil || f.signs.Load() != beforeSigns {
			t.Fatal("stale initial source was reprobed or reimported")
		}
		nativeAuthorityConsume(t, ctx, n, n.consumer, nativeAuthorityExport(t, ctx, n, winner), true)
	})
	if t.Failed() {
		return
	}
	fault := &nativeAuthorityLostAck{base: n.installerConnector}
	faultDB := sql.OpenDB(fault)
	faultDB.SetMaxOpenConns(4)
	t.Cleanup(func() { faultDB.Close() })
	instrumented := *f.i
	instrumented.db = faultDB
	var actualAccount string
	if faultDB.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&actualAccount) != nil || actualAccount != f.i.plan.InstallerDatabaseAccount {
		t.Fatal("fault connection did not retain actual installer identity")
	}
	requireNativeAuthorityTLS(t, ctx, faultDB)
	t.Run("real_grant_failure_rolls_back_head", func(t *testing.T) {
		pack := nativeAuthorityIssue(t, ctx, n, "native-rollback")
		if _, e := n.root.ExecContext(ctx, `CREATE TRIGGER owner_authority_reject_insert BEFORE INSERT ON system_backup_installation_owner_grants FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='controlled grant insert refusal'`); e != nil {
			t.Fatal("owned failure trigger", e)
		}
		// Only this stage runs while the owned trigger exists. Any early test
		// exit still removes it through the verified owned-schema cleanup.
		_, e := instrumented.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files)
		if e == nil || fault.execs.Load() != 2 || fault.committed.Load() != 0 {
			t.Fatal("expected real head write then rejected grant insert/rollback", e)
		}
		if _, e := n.root.ExecContext(ctx, `DROP TRIGGER owner_authority_reject_insert`); e != nil {
			t.Fatal("owned failure trigger removal", e)
		}
		nativeAuthorityExactBundle(t, ctx, n, winner)
		var count int
		if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_grants`).Scan(&count) != nil || count != 2 {
			t.Fatal("rollback persisted a grant")
		}
	})
	if t.Failed() {
		return
	}
	var committed []byte
	t.Run("real_commit_lost_ack_exact_original_readback", func(t *testing.T) {
		committed = nativeAuthorityIssue(t, ctx, n, "native-lost-ack")
		fault.execs.Store(0)
		fault.armed.Store(true)
		_, e := instrumented.ImportCapture(ctx, f.password, f.enrollment, committed, hash(committed), f.files)
		if !errors.Is(e, ErrCommitUnknown) || fault.committed.Load() != 1 || fault.suppressed.Load() != 1 || fault.execs.Load() != 2 {
			t.Fatal("actual successful commit with suppressed acknowledgement not uncertain", e)
		}
		nativeAuthorityExactBundle(t, ctx, n, committed)
		signs, writes := f.signs.Load(), fault.execs.Load()
		r, e := instrumented.Resolve(ctx, f.password, f.enrollment, committed, hash(committed))
		if e != nil || !r.Replayed || r.HeadRevision != 3 || r.HeadRowVersion != 3 || fault.execs.Load() != writes || fault.committed.Load() != 1 || f.signs.Load() != signs {
			t.Fatal("original lost-ack recovery wrote, re-signed, re-probed or changed source", e, r)
		}
		nativeAuthorityExactBundle(t, ctx, n, committed)
		var count int
		if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_grants`).Scan(&count) != nil || count != 3 {
			t.Fatal("lost-ack recovery created extra source rows")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("real_revocation_denies_original_consumer_l2", func(t *testing.T) {
		dir := nativeAuthorityExport(t, ctx, n, committed)
		nativeAuthorityConsume(t, ctx, n, n.consumer, dir, true)
		beforeSigns := f.signs.Load()
		f.resourceDrift.Store(true)
		revoked, e := f.i.IssueRevocation(ctx, f.password, f.enrollment, f.key)
		if e != nil {
			t.Fatal("revoke freeze required healthy provider", e)
		}
		r, e := f.i.ImportRevocation(ctx, f.password, f.enrollment, revoked, hash(revoked))
		if e != nil || r.State != "revoked" || r.HeadRevision != 4 || r.HeadRowVersion != 4 || r.GrantRowVersion != 2 || f.signs.Load() != beforeSigns {
			t.Fatal("actual atomic head/grant revoke", e, r)
		}
		nativeAuthorityExactBundle(t, ctx, n, revoked)
		if r, e = f.i.Resolve(ctx, f.password, f.enrollment, revoked, hash(revoked)); e != nil || !r.Replayed || r.State != "revoked" {
			t.Fatal("actual revoked result readback", e)
		}
		// Restore only controlled public provider metadata to isolate SQL state.
		f.resourceDrift.Store(false)
		nativeAuthorityConsume(t, ctx, n, n.consumer, dir, false)
		if _, e = f.i.ImportCapture(ctx, f.password, f.enrollment, committed, hash(committed), f.files); e == nil {
			t.Fatal("old source resurrected revoked enrollment")
		}
		nativeAuthorityExactBundle(t, ctx, n, revoked)
	})
}

func nativeAuthorityIssue(t *testing.T, ctx context.Context, n *nativeAuthorityFixture, grantID string) []byte {
	t.Helper()
	r := n.f.record
	r.GrantID = grantID
	draft, e := owner.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	pack, e := n.f.i.IssueCapture(ctx, n.f.password, n.f.enrollment, draft, hash(draft), n.f.key, n.f.files)
	if e != nil {
		t.Fatal("actual authenticated native issue", e)
	}
	return pack
}
func nativeAuthorityDecode(t *testing.T, pack []byte) AuthorityBundle {
	t.Helper()
	var b AuthorityBundle
	if decodeExact(pack, &b) != nil {
		t.Fatal("frozen original bundle")
	}
	return b
}
func nativeAuthorityExactBundle(t *testing.T, ctx context.Context, n *nativeAuthorityFixture, pack []byte) {
	t.Helper()
	b := nativeAuthorityDecode(t, pack)
	var h owner.Head
	if decodeExact(b.Head, &h) != nil {
		t.Fatal("frozen head")
	}
	var rev, version, grantVersion uint64
	var sha, state, grantSHA, grantState string
	var raw, sig, record, recordSig []byte
	p := n.f.i.plan
	e := n.root.QueryRowContext(ctx, `SELECT head_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=?`, p.Target.InstallationID, p.EnrollmentID).Scan(&rev, &sha, &raw, &sig, &state, &version)
	if e != nil || rev != b.Expected.HeadRevision+1 || version != b.Expected.HeadRowVersion+1 || sha != hash(b.Head) || state != h.State || !bytes.Equal(raw, b.Head) || !bytes.Equal(sig, b.HeadSignature) {
		t.Fatal("independent exact real SQL head/counter readback", e)
	}
	e = n.root.QueryRowContext(ctx, `SELECT record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_installation_owner_grants WHERE installation_id=? AND enrollment_id=? AND grant_id=? AND record_revision=?`, p.Target.InstallationID, p.EnrollmentID, h.GrantID, h.GrantRevision).Scan(&grantSHA, &record, &recordSig, &grantState, &grantVersion)
	wantGrantVersion := uint64(1)
	if b.SchemaVersion == RevocationBundleVersion {
		wantGrantVersion = b.Expected.GrantRowVersion + 1
	}
	if e != nil || grantVersion != wantGrantVersion || grantState != h.State || grantSHA != hash(b.Record) || !bytes.Equal(record, b.Record) || !bytes.Equal(recordSig, b.RecordSignature) {
		t.Fatal("independent exact real SQL grant/counter readback", e)
	}
}
func nativeAuthorityExport(t *testing.T, ctx context.Context, n *nativeAuthorityFixture, pack []byte) string {
	t.Helper()
	directory := t.TempDir()
	if _, e := n.f.i.ExportCommitted(ctx, n.f.password, n.f.enrollment, pack, hash(pack), directory); e != nil {
		t.Fatal("actual committed consumer export", e)
	}
	return directory
}
func nativeAuthorityConsume(t *testing.T, ctx context.Context, n *nativeAuthorityFixture, db *sql.DB, directory string, allowed bool) {
	t.Helper()
	var pin owner.TrustPin
	raw, e := os.ReadFile(filepath.Join(directory, "owner.pin.json"))
	if e != nil || decodeExact(raw, &pin) != nil || !bytes.Equal(pin.Issuer, n.f.i.public) || pin.DatabaseAccount != n.f.i.plan.Target.DatabaseAccount {
		t.Fatal("actual enrolled independent consumer pin", e)
	}
	request, e := readRequest(n.f.i, n.f.files)
	if e != nil {
		t.Fatal(e)
	}
	defer request.observer.Close()
	validator, e := owner.NewCaptureSigningValidator(pin, RecordFilesAt(directory), request.observer)
	if e != nil {
		t.Fatal(e)
	}
	check, e := validator.Prepare(ctx, n.f.grant, n.f.config)
	if e != nil {
		t.Fatal("original concrete prepare", e)
	}
	prepared, ok := check.(*owner.PreparedCaptureSigning)
	if !ok {
		t.Fatal("original concrete prepared owner")
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal("actual consumer transaction", e)
	}
	defer tx.Rollback()
	guard, e := prepared.AuthorizeOriginal(ctx, tx, n.f.grant, n.f.config)
	if !allowed {
		if e == nil || guard != nil {
			t.Fatal("actual wrong account/revoked original L2 allowed")
		}
		return
	}
	if e != nil || guard.RecheckOriginalIdentity(ctx, tx) != nil {
		t.Fatal("actual consumer original L2 identity", e)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || prepared.Recheck(ctx, tx, now) != nil {
		t.Fatal("actual consumer L3 observation recheck")
	}
	if tx.Commit() != nil {
		t.Fatal("actual consumer transaction commit")
	}
}
func requireNativeAuthorityDenied(t *testing.T, e error) {
	t.Helper()
	var mysqlError *mysql.MySQLError
	if !errors.As(e, &mysqlError) || (mysqlError.Number != 1142 && mysqlError.Number != 1143) {
		t.Fatal("expected actual SQL table/column privilege denial, not a simulated/transport error", e)
	}
}
