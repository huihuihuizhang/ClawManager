//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// The provider and policy inputs are explicitly synthetic. Only persistence,
// CAS, rollback, reference/retention locking and GC tombstones are established
// by this test; no production KMS/HTTP identity/capability is approved.
func TestAEvidenceMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(uid) || os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("isolated marker required")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort("127.0.0.1", "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.MultiStatements = true
	admin, e := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, e)
	defer admin.Close()
	var gotRun, gotUID, pinned, server string
	mustSQL(t, admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinned))
	mustSQL(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server))
	if gotRun != run || gotUID != uid || server != pinned {
		t.Fatal("isolated identity mismatch")
	}
	ddl, e := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, e)
	if hash(ddl) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("DDL digest mismatch")
	}
	var entropy [16]byte
	_, e = rand.Read(entropy[:])
	mustSQL(t, e)
	name := "aev_" + hex.EncodeToString(entropy[:])
	_, e = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	mustSQL(t, e)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var current string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&current) != nil || current != server {
			t.Error("CLEANUP_PENDING evidence database identity")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+name); e != nil {
			t.Error("CLEANUP_PENDING evidence database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING evidence database absence")
			return
		}
		t.Log("CLEANED evidence run-owned database")
	}()
	cfg.DBName = name
	db, e := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, e)
	defer db.Close()
	_, e = db.ExecContext(ctx, string(ddl))
	mustSQL(t, e)
	_, e = db.ExecContext(ctx, `CREATE TABLE a_owner(public_id VARCHAR(128) PRIMARY KEY,installation VARCHAR(128),deadline DATETIME(6),referenced BOOLEAN,allowed BOOLEAN); CREATE TABLE a_audit(id BIGINT AUTO_INCREMENT PRIMARY KEY,request_id VARCHAR(128),action VARCHAR(64),outcome VARCHAR(64));`)
	mustSQL(t, e)
	p, _, object, keys := fixture(t, int(ChunkSize)+3)
	id := p.manifest.Identity.ID
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	deadline := now.Add(time.Hour)
	_, e = db.ExecContext(ctx, "INSERT INTO a_owner VALUES(?,?,?,FALSE,TRUE)", p.manifest.Identity.OwnerID, "installation_test", deadline)
	mustSQL(t, e)
	registry := SQLRegistry{DB: db, Installation: "installation_test", ServerUUID: server, Database: name, Policy: mysqlPolicy{deadline: deadline}}
	store := &testStore{authoritative: true}
	s := Service{Registry: registry, Store: store, Keys: keys, Failure: func(context.Context, string, string) {}}
	t.Run("pending_intent_chunks_atomic_and_duplicate_rejected", func(t *testing.T) {
		mustSQL(t, s.Register(ctx, p, "evidence", Ref{Identity: strings.Repeat("a", 64), Version: "v1"}, now, now.Add(time.Hour), now.Add(time.Hour), deadline))
		if e := s.Register(ctx, p, "evidence", Ref{Identity: strings.Repeat("a", 64), Version: "v1"}, now, now.Add(time.Hour), now.Add(time.Hour), deadline); e == nil {
			t.Fatal("duplicate replaced intent")
		}
		var evidence, chunks int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&evidence))
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence_chunks").Scan(&chunks))
		if evidence != 1 || chunks != 2 || store.puts != 0 {
			t.Fatal("intent not atomic")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("recovery_scan_filters_due_claim_store_and_literal_installation", func(t *testing.T) {
		prefix := "evidence/installation_test/"
		identity := strings.Repeat("a", 64)
		var sequence int64
		mustSQL(t, db.QueryRowContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&sequence))
		check := func(after int64, store, version, scope string, expected int) {
			t.Helper()
			rows, err := db.QueryContext(ctx, recoveryCandidatesSQL, after, store, version, len(scope), scope, 2)
			mustSQL(t, err)
			defer rows.Close()
			count := 0
			for rows.Next() {
				var seq int64
				var found string
				mustSQL(t, rows.Scan(&seq, &found))
				if seq != sequence || found != id {
					t.Fatal("wrong recovery candidate")
				}
				count++
			}
			mustSQL(t, rows.Err())
			if count != expected {
				t.Fatal("recovery candidate filter failed")
			}
		}
		check(0, identity, "v1", prefix, 1)
		check(sequence, identity, "v1", prefix, 0)
		check(0, strings.Repeat("b", 64), "v1", prefix, 0)
		check(0, identity, "v2", prefix, 0)
		check(0, identity, "v1", "evidence/installationXtest/", 0)
		check(0, identity, "v1", "evidence/installation%test/", 0)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET next_reconcile_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 DAY)")
		mustSQL(t, e)
		check(0, identity, "v1", prefix, 0)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET next_reconcile_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND),claim_owner='scan-test',claim_expires_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 DAY)")
		mustSQL(t, e)
		check(0, identity, "v1", prefix, 0)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET claim_expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND)")
		mustSQL(t, e)
		check(0, identity, "v1", prefix, 1)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET next_reconcile_at=NULL,claim_owner=NULL,claim_expires_at=NULL")
		mustSQL(t, e)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET owner_target_type='system',owner_target_public_id='installation_test',evidence_type='capability_snapshot' WHERE public_id=?", id)
		mustSQL(t, e)
		check(0, identity, "v1", prefix, 0)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET evidence_type='diagnostic' WHERE public_id=?", id)
		mustSQL(t, e)
		check(0, identity, "v1", prefix, 1)
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET owner_target_type=?,owner_target_public_id=?,evidence_type=? WHERE public_id=?", p.manifest.Identity.OwnerType, p.manifest.Identity.OwnerID, p.manifest.Identity.Type, id)
		mustSQL(t, e)
	})
	if t.Failed() {
		return
	}
	t.Run("publish_and_exact_version_read", func(t *testing.T) {
		mustSQL(t, s.Publish(ctx, id, source(object)))
		mustSQL(t, registry.WithLocked(ctx, id, func(tx Locked) error {
			r := tx.Record()
			if r.State != "ready" || r.Ref.ImmutableVersion != "immutable-v1" {
				t.Fatal("not ready")
			}
			b, e := OpenRange(ctx, r.Manifest, r.Ref, store, keys, ChunkSize-2, ChunkSize+2)
			if len(b) != 5 || e != nil {
				t.Fatal(e)
			}
			return nil
		}))
	})
	if t.Failed() {
		return
	}
	t.Run("retention_and_references_block_gc", func(t *testing.T) {
		if s.GC(ctx, []string{id})[0] != ErrConflict || store.deletes != 0 {
			t.Fatal("retention bypass")
		}
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET created_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 2 DAY),expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY),protected_until=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY)")
		mustSQL(t, e)
		_, e = db.ExecContext(ctx, "UPDATE a_owner SET referenced=TRUE")
		mustSQL(t, e)
		if s.GC(ctx, []string{id})[0] != ErrConflict || store.deletes != 0 {
			t.Fatal("reference bypass")
		}
		_, e = db.ExecContext(ctx, "UPDATE a_owner SET referenced=FALSE")
		mustSQL(t, e)
	})
	if t.Failed() {
		return
	}
	t.Run("audit_failure_rolls_back_claim_before_delete", func(t *testing.T) {
		_, e = db.ExecContext(ctx, `CREATE TRIGGER a_reject BEFORE INSERT ON a_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'`)
		mustSQL(t, e)
		if s.GC(ctx, []string{id})[0] != ErrAudit || store.deletes != 0 {
			t.Fatal("failed audit dispatched delete")
		}
		_, e = db.ExecContext(ctx, "DROP TRIGGER a_reject")
		mustSQL(t, e)
	})
	if t.Failed() {
		return
	}
	// Exercise the production GC observation Save path on real MySQL. This
	// explicit test adapter does not claim to implement operation/mTLS admission.
	s.Registry = mysqlObservedGCRegistry{registry}
	t.Run("unknown_delete_retains_ref_and_schedules_retry", func(t *testing.T) {
		store.deleteUnknown = true
		if s.GC(ctx, []string{id})[0] == nil {
			t.Fatal("unknown deletion accepted")
		}
		var state, version string
		mustSQL(t, db.QueryRowContext(ctx, "SELECT storage_state,storage_immutable_version FROM system_backup_v2_evidence").Scan(&state, &version))
		if state != "delete_failed" || version == "" {
			t.Fatal("lost recoverable state")
		}
		var health string
		var checked, retry time.Time
		mustSQL(t, db.QueryRowContext(ctx, "SELECT observed_health,last_checked_at,next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&health, &checked, &retry))
		if health != "unknown" || checked.IsZero() || !retry.Equal(checked.Add(time.Minute)) {
			t.Fatal("GC failure observation and retry were not persisted")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("gc_result_audit_failure_preserves_observation_and_reference", func(t *testing.T) {
		var beforeHealth string
		var beforeChecked, beforeRetry time.Time
		mustSQL(t, db.QueryRowContext(ctx, "SELECT observed_health,last_checked_at,next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&beforeHealth, &beforeChecked, &beforeRetry))
		var beforeAudits int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM a_audit WHERE action='evidence.gc.result'").Scan(&beforeAudits))
		_, e = db.ExecContext(ctx, `CREATE TRIGGER a_reject_result BEFORE INSERT ON a_audit FOR EACH ROW BEGIN IF NEW.action='evidence.gc.result' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic GC result audit failure'; END IF; END`)
		mustSQL(t, e)
		store.deleteUnknown = false
		if s.GC(ctx, []string{id})[0] != ErrAudit {
			t.Fatal("result audit failure did not abort transaction")
		}
		_, e = db.ExecContext(ctx, "DROP TRIGGER a_reject_result")
		mustSQL(t, e)
		var state, version, health string
		var checked, retry time.Time
		mustSQL(t, db.QueryRowContext(ctx, "SELECT storage_state,storage_immutable_version,observed_health,last_checked_at,next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&state, &version, &health, &checked, &retry))
		var audits, chunks int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM a_audit WHERE action='evidence.gc.result'").Scan(&audits))
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence_chunks").Scan(&chunks))
		if state != "deleting" || version == "" || health != beforeHealth || !checked.Equal(beforeChecked) || !retry.Equal(beforeRetry) || audits != beforeAudits || chunks != 2 {
			t.Fatal("failed result transaction changed durable GC observation/ref/audit")
		}
		// Simulate later takeover solely inside this run-owned test database.
		_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET claim_expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE public_id=?", id)
		mustSQL(t, e)
	})
	if t.Failed() {
		return
	}
	t.Run("confirmed_gc_clears_payload_and_retry", func(t *testing.T) {
		deletes := store.deletes
		mustSQL(t, s.GC(ctx, []string{id})[0])
		var count int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE storage_state='deleted' AND storage_relative_key IS NULL AND content_checksum IS NOT NULL").Scan(&count))
		if count != 1 {
			t.Fatal("minimum tombstone missing")
		}
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence_chunks").Scan(&count))
		if count != 0 {
			t.Fatal("chunks retained")
		}
		var health string
		var checked, retry sql.NullTime
		mustSQL(t, db.QueryRowContext(ctx, "SELECT observed_health,last_checked_at,next_reconcile_at FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&health, &checked, &retry))
		if health != "unknown" || !checked.Valid || retry.Valid || store.deletes != deletes {
			t.Fatal("confirmed absence retained retry or repeated DELETE")
		}
	})
	if !t.Failed() {
		t.Run("live_authority_concurrency", func(t *testing.T) { testMySQLLiveAuthorities(t, ctx, registry) })
	}
}

type mysqlObservedGCRegistry struct{ SQLRegistry }

func (r mysqlObservedGCRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	return r.SQLRegistry.WithLocked(ctx, id, func(tx Locked) error {
		return fn(gcLocked{sqlLocked: tx.(*sqlLocked), actor: "gc:synthetic-mysql-probe", retry: time.Minute})
	})
}

type mysqlPolicy struct{ deadline time.Time }

func (p mysqlPolicy) LockScope(ctx context.Context, tx *sql.Tx, install string, i Identity) error {
	var got string
	if tx.QueryRowContext(ctx, "SELECT installation FROM a_owner WHERE public_id=? FOR UPDATE", i.OwnerID).Scan(&got) != nil || got != install {
		return ErrDenied
	}
	return nil
}
func (p mysqlPolicy) OwnerDeadline(context.Context, *sql.Tx, Identity) (time.Time, error) {
	return p.deadline, nil
}
func (p mysqlPolicy) Admit(context.Context, *sql.Tx, Record, time.Time) error { return nil } // explicitly synthetic
func (p mysqlPolicy) Authorize(ctx context.Context, tx *sql.Tx, _ Actor, r Record, _ []string) error {
	var allowed bool
	if tx.QueryRowContext(ctx, "SELECT allowed FROM a_owner WHERE public_id=? FOR UPDATE", r.Manifest.Identity.OwnerID).Scan(&allowed) != nil || !allowed {
		return ErrDenied
	}
	return nil
}
func (p mysqlPolicy) Deletable(ctx context.Context, tx *sql.Tx, r Record, _ time.Time) error {
	var referenced bool
	if tx.QueryRowContext(ctx, "SELECT referenced FROM a_owner WHERE public_id=? FOR UPDATE", r.Manifest.Identity.OwnerID).Scan(&referenced) != nil || referenced {
		return ErrConflict
	}
	return nil
}
func (p mysqlPolicy) Audit(ctx context.Context, tx *sql.Tx, a Audit) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO a_audit(request_id,action,outcome) VALUES (?,?,?)", a.ID, a.Action, a.Outcome)
	return e
}
func mustSQL(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		if me, ok := e.(*mysql.MySQLError); ok {
			t.Fatalf("MySQL error number=%d", me.Number)
		}
		t.Fatal("evidence probe failed", boundary(e))
	}
}
