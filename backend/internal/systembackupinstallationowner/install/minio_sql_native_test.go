//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
)

func nativeMinioExact(t *testing.T, ctx context.Context, f *nativeMinioSQLFixture, raw []byte) {
	t.Helper()
	b := mustMinioSQLBundle(t, raw)
	var h ma.SQLHead
	if json.Unmarshal(b.Head, &h) != nil {
		t.Fatal("original signed head")
	}
	s, e := f.n.f.i.authenticate(ctx, f.n.f.password)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, missing, e := minioSQLRead(ctx, s, f.f.intent.Pin)
	if e != nil || missing || !minioSQLExact(snapshot, b, h) {
		t.Fatal("actual seven original SQL rows/index/signature/CAS parity", e)
	}
	nativeMinioCounts(t, ctx, f, 1, 1, 5)
}

// Real migration135, seven actual MySQL rows, exact limited TLS accounts and
// real original users/migration134 prefix. No real MinIO/Kubernetes/field proof.
func TestMinIOSQLOwnerNativeTLSSevenRowsSelectOnlyAndTerminalCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	f := newNativeMinioSQLFixture(t, ctx)
	raw := f.f.issue(t, ctx)
	nativeMinioCounts(t, ctx, f, 0, 0, 0)
	r := importMinioSQLFixture(t, ctx, f.f, raw)
	if r.State != "active" || r.Replayed {
		t.Fatal("actual initial metadata installation")
	}
	nativeMinioExact(t, ctx, f, raw)
	resolved, e := f.n.f.i.ResolveMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, raw, hash(raw))
	if e != nil || !resolved.Replayed || !reflect.DeepEqual(r.Comparison, resolved.Comparison) {
		t.Fatal("actual original tuple independent resolve", e)
	}
	// Account permissions remain exact: SELECT on new three tables, no added
	// UPDATE/DELETE/LOCK TABLES or password_hash column access for consumer.
	var version uint64
	e = f.n.consumer.QueryRowContext(ctx, `SELECT row_version FROM system_backup_minio_owner_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? FOR UPDATE`, f.f.intent.Pin.Target.InstallationID, f.f.intent.Pin.Enrollment.ID, f.f.intent.Pin.AuthorityID).Scan(&version)
	requireNativeAuthorityDenied(t, e)
	for _, table := range []string{"system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs"} {
		_, e = f.n.consumer.ExecContext(ctx, "UPDATE "+table+" SET row_version=row_version")
		requireNativeAuthorityDenied(t, e)
		_, e = f.n.consumer.ExecContext(ctx, "DELETE FROM "+table)
		requireNativeAuthorityDenied(t, e)
		_, e = f.n.installer.ExecContext(ctx, "DELETE FROM "+table)
		requireNativeAuthorityDenied(t, e)
	}
	var password string
	e = f.n.consumer.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=7`).Scan(&password)
	requireNativeAuthorityDenied(t, e)
	tx := nativeMinioConsumer(t, ctx, f, true)
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	revoke, e := f.n.f.i.IssueMinIOSQLRevocation(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, f.n.f.key)
	if e != nil {
		t.Fatal(e)
	}
	r = importMinioSQLFixture(t, ctx, f.f, revoke)
	if r.State != "revoked" || r.Comparison.HeadRevision != 2 || r.Comparison.HeadRowVersion != 2 || r.Comparison.GrantRowVersion != 2 {
		t.Fatal("actual terminal CAS tuple")
	}
	for _, row := range r.Comparison.ReferenceRows {
		if row.RowVersion != 2 {
			t.Fatal("ref revoke not atomic")
		}
	}
	nativeMinioExact(t, ctx, f, revoke)
	if _, e = f.n.f.i.ImportMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, raw, hash(raw)); e == nil {
		t.Fatal("actual old active bundle resurrected authority")
	}
	if _, e = f.n.f.i.IssueMinIOSQLRevocation(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, f.n.f.key); e == nil {
		t.Fatal("actual revoked source signed another transition")
	}
	// The real original prefix remains valid, while MinIO current SQL source
	// authenticates the signed revoke and refuses current identity use.
	tx = nativeMinioConsumer(t, ctx, f, false)
	snapshot, e := ma.ReadSQLCurrent(ctx, tx, f.f.intent.Pin)
	if e != nil {
		t.Fatal(e)
	}
	_, now, e := snapshot.Comparison()
	if e != nil || snapshot.RequireCurrent(now) == nil {
		t.Fatal("real revoked SQL source authorized current use", e)
	}
}

// Mid-batch failures are actual MySQL trigger SIGNALs on owned rows, not fake
// query results or a model. All earlier writes must roll back in InnoDB.
func TestMinIOSQLOwnerNativeTLSAtomicRollbackAndUnknownResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	f := newNativeMinioSQLFixture(t, ctx)
	raw := f.f.issue(t, ctx)
	if _, e := f.n.root.ExecContext(ctx, `CREATE TRIGGER owned_minio_insert_fail BEFORE INSERT ON system_backup_minio_owner_refs FOR EACH ROW BEGIN IF NEW.purpose='artifact_write' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned_minio_insert_rollback'; END IF; END`); e != nil {
		t.Fatal("owned rollback trigger", e)
	}
	if r, e := f.n.f.i.ImportMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, raw, hash(raw)); e == nil || r.Version != "" {
		t.Fatal("actual mid-insert failure succeeded", e)
	}
	nativeMinioCounts(t, ctx, f, 0, 0, 0)
	if _, e := f.n.root.ExecContext(ctx, `DROP TRIGGER owned_minio_insert_fail`); e != nil {
		t.Fatal(e)
	}
	// Drop only caller acknowledgement AFTER actual server COMMIT. No row,
	// query, identity, TLS or locking semantics are supplied by this wrapper.
	lost := &nativeAuthorityLostAck{base: f.n.installerConnector}
	lost.armed.Store(true)
	db := sql.OpenDB(lost)
	db.SetMaxOpenConns(4)
	defer db.Close()
	issuer := *f.n.f.i
	issuer.db = db
	if r, e := issuer.ImportMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, raw, hash(raw)); !errors.Is(e, ErrCommitUnknown) || r.Version != "" || lost.committed.Load() != 1 || lost.suppressed.Load() != 1 || lost.execs.Load() != 7 {
		t.Fatal("actual commit acknowledgement loss was not uncertain", e)
	}
	nativeMinioExact(t, ctx, f, raw)
	writes := lost.execs.Load()
	r, e := f.n.f.i.ResolveMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, raw, hash(raw))
	if e != nil || !r.Replayed || lost.execs.Load() != writes {
		t.Fatal("actual exact resolve mutated authority", e)
	}
	revoke, e := f.n.f.i.IssueMinIOSQLRevocation(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, f.n.f.key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.n.root.ExecContext(ctx, `CREATE TRIGGER owned_minio_revoke_fail BEFORE UPDATE ON system_backup_minio_owner_refs FOR EACH ROW BEGIN IF OLD.purpose='artifact_write' AND NEW.ref_state='revoked' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned_minio_revoke_rollback'; END IF; END`); e != nil {
		t.Fatal(e)
	}
	if r, e = f.n.f.i.ImportMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, revoke, hash(revoke)); e == nil || r.Version != "" {
		t.Fatal("actual mid-revoke failure succeeded", e)
	}
	nativeMinioExact(t, ctx, f, raw)
	if _, e = f.n.root.ExecContext(ctx, `DROP TRIGGER owned_minio_revoke_fail`); e != nil {
		t.Fatal(e)
	}
	importMinioSQLFixture(t, ctx, f.f, revoke)
	nativeMinioExact(t, ctx, f, revoke)
}

func TestMinIOSQLOwnerNativeTLSSharedLocksBlockRevokeInOrder(t *testing.T) {
	for _, blocked := range []string{"head", "catalog_append"} {
		t.Run(blocked, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			f := newNativeMinioSQLFixture(t, ctx)
			raw := f.f.issue(t, ctx)
			importMinioSQLFixture(t, ctx, f.f, raw)
			revoke, e := f.n.f.i.IssueMinIOSQLRevocation(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, f.n.f.key)
			if e != nil {
				t.Fatal(e)
			}
			blocker := nativeMinioConsumer(t, ctx, f, blocked == "head")
			defer blocker.Rollback()
			var blockerID int64
			if blocker.QueryRowContext(ctx, `SELECT CONNECTION_ID()`).Scan(&blockerID) != nil || blockerID < 1 {
				t.Fatal("actual blocker connection ID")
			}
			if blocked == "catalog_append" {
				// Diagnostic SELECT-only blocker, NOT a production admission: it
				// holds only this ref after REAL admin/capture prefix to expose the
				// writer's later ref order without first blocking its head lock.
				var sha string
				if blocker.QueryRowContext(ctx, `SELECT ref_sha256 FROM system_backup_minio_owner_refs WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=1 AND purpose='catalog_append' FOR SHARE`, f.f.intent.Pin.Target.InstallationID, f.f.intent.Pin.Enrollment.ID, f.f.intent.Pin.AuthorityID, f.f.intent.Pin.GrantID).Scan(&sha) != nil {
					t.Fatal("actual diagnostic shared ref blocker")
				}
			}
			monitor := &nativeMinioLockMonitor{base: f.n.installerConnector, events: make(chan nativeMinioLockEvent, 64)}
			db := sql.OpenDB(monitor)
			db.SetMaxOpenConns(4)
			defer func() { _ = blocker.Rollback(); cancel(); _ = db.Close() }()
			writer := *f.n.f.i
			writer.db = db
			type outcome struct {
				r MinIOSQLReceipt
				e error
			}
			done := make(chan outcome, 1)
			go func() {
				r, e := writer.ImportMinIOSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, f.f.intent.Pin, revoke, hash(revoke))
				done <- outcome{r, e}
			}()
			acquired := []string{}
			var waiting int64
		awaitBlocked:
			for {
				select {
				case event := <-monitor.events:
					if event.acquired {
						acquired = append(acquired, event.key)
					} else if event.key == blocked {
						waiting = event.connectionID
						break awaitBlocked
					}
				case result := <-done:
					t.Fatal("writer finished before actual expected lock wait", result.e)
				case <-ctx.Done():
					t.Fatal("writer did not reach original lock stage")
				}
			}
			table := "system_backup_minio_owner_heads"
			expectedPrefix := []string{}
			if blocked != "head" {
				table = "system_backup_minio_owner_refs"
				expectedPrefix = []string{"head", "grant", "artifact_delete", "artifact_read", "artifact_write"}
			}
			if !reflect.DeepEqual(acquired, expectedPrefix) {
				t.Fatal("actual acquired lock prefix differs", acquired)
			}
			requireNativeMinioWait(t, ctx, f, waiting, blockerID, table)
			select {
			case result := <-done:
				t.Fatal("actual waiter committed through held shared lock", result.e)
			default:
			}
			if e = blocker.Rollback(); e != nil {
				t.Fatal(e)
			}
			var result outcome
			select {
			case result = <-done:
			case <-ctx.Done():
				t.Fatal("actual writer did not finish after blocker release")
			}
			if result.e != nil || result.r.State != "revoked" {
				t.Fatal("actual ordered revoke after release", result.e)
			}
			for {
				select {
				case event := <-monitor.events:
					if event.acquired {
						acquired = append(acquired, event.key)
					}
				default:
					goto drained
				}
			}
		drained:
			if !reflect.DeepEqual(acquired, []string{"head", "grant", "artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read"}) {
				t.Fatal("actual seven-row exclusive lock order differs", acquired)
			}
			nativeMinioExact(t, ctx, f, revoke)
		})
	}
}
