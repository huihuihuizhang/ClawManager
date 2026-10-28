//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real InnoDB transactions and real pinned mTLS, using production authority,
// claim, provider authorization and result code. Control tables below are SQL
// projections, NOT full production config/operation schema acceptance. Owner
// policy, projected JWT and object provider remain explicitly synthetic.
func testMySQLLiveAuthorities(t *testing.T, ctx context.Context, registry SQLRegistry) {
	db := registry.DB
	db.SetMaxOpenConns(8)
	exec := func(q string, args ...any) { t.Helper(); _, err := db.ExecContext(ctx, q, args...); mustSQL(t, err) }
	exec(`CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,active_config_version BIGINT NOT NULL) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128),version BIGINT,config_sha256 CHAR(64),evidence_store_identity_hash CHAR(64),evidence_store_ref_version VARCHAR(128),evidence_delete_identity_hash CHAR(64),evidence_delete_ref_version VARCHAR(128),evidence_read_identity_hash CHAR(64),evidence_read_ref_version VARCHAR(128),retry_max_backoff_seconds BIGINT,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),public_id VARCHAR(128),operation_type VARCHAR(64),target_type VARCHAR(64),target_public_id VARCHAR(128),actor_type VARCHAR(64),actor_id VARCHAR(128),status VARCHAR(64),claim_owner VARCHAR(128),claim_expires_at DATETIME(6),row_version BIGINT,deadline_at DATETIME(6),PRIMARY KEY(origin_installation_id,public_id)) ENGINE=InnoDB;`)
	peer := newTaskFixture(t, false) // Reuse only generated test credentials; its scripted DB is never used.
	registry.Policy = mysqlLivePolicy{}
	p, _, object, keys := fixture(t, 9000)
	id := p.manifest.Identity.ID
	c := GCAuthorityConfig{Registry: registry, ConfigVersion: 1, ConfigSHA256: hash([]byte("mysql-authority-config")), Root: "evidence", Store: KeyRef{strings.Repeat("a", 64), "v1"}, Delete: KeyRef{strings.Repeat("d", 64), "delete-v1"}, OperationID: "sop_11111111-2222-4333-8444-555555555555", OperationClaim: "worker-one", OperationRowVersion: 1, ClientCAPEM: peer.c.ClientCAPEM, ClientCASHA256: peer.c.ClientCASHA256, CertificateSHA256: peer.c.CertificateSHA256, Issuer: peer.c.Issuer, Audience: peer.c.Audience, Subject: peer.c.Subject, TokenFile: peer.c.TokenFile, ExpiresAt: peer.c.ExpiresAt}
	rc := WriteRecoveryConfig{Registry: registry, ConfigVersion: c.ConfigVersion, ConfigSHA256: c.ConfigSHA256, Root: c.Root, Store: c.Store, Read: KeyRef{strings.Repeat("e", 64), "read-v1"}, ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256, CertificateSHA256: c.CertificateSHA256, Issuer: c.Issuer, Audience: c.Audience, Subject: c.Subject, TokenFile: c.TokenFile, ExpiresAt: c.ExpiresAt, Failure: func(context.Context, string, string) {}}
	reset := func(t *testing.T, recovery bool) *mysqlAuthorityStore {
		t.Helper()
		for _, table := range []string{"system_backup_v2_evidence_chunks", "system_backup_v2_evidence", "a_audit", "system_backup_v2_operations", "system_backup_v2_configs", "system_backup_v2_installation_state"} {
			exec("DELETE FROM " + table)
		}
		exec("INSERT INTO system_backup_v2_installation_state VALUES(?,1)", registry.Installation)
		exec("INSERT INTO system_backup_v2_configs VALUES(?,1,?,?,?,?,?,?,?,60)", registry.Installation, c.ConfigSHA256, c.Store.Identity, c.Store.Version, c.Delete.Identity, c.Delete.Version, rc.Read.Identity, rc.Read.Version)
		exec("INSERT INTO system_backup_v2_operations VALUES(?,?,'evidence_gc','system',?,'system','system:controller','running',?,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 5 MINUTE),1,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE))", registry.Installation, c.OperationID, registry.Installation, c.OperationClaim)
		var now time.Time
		mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
		exec("UPDATE a_owner SET deadline=?,referenced=FALSE,allowed=TRUE", now.Add(time.Hour))
		baseStore := mysqlAuthoritySeedStore()
		s := Service{Registry: registry, Store: baseStore, Keys: keys}
		mustSQL(t, s.Register(ctx, p, "evidence", Ref{Identity: c.Store.Identity, Version: c.Store.Version}, now, now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)))
		if !recovery {
			if err := s.Publish(ctx, id, source(object)); err != nil {
				t.Fatalf("GC fixture publish failed before authority/concurrency checks: %v", err)
			}
		}
		exec("UPDATE a_owner SET deadline=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 MINUTE)")
		exec("UPDATE system_backup_v2_evidence SET created_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 2 DAY),expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY),protected_until=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 DAY)")
		store := &mysqlAuthorityStore{info: ObjectInfo{Version: "immutable-v1", SHA256: p.manifest.ObjectHash, Size: p.manifest.ObjectSize}}
		store.present.Store(true)
		return store
	}
	gc := func(t *testing.T, store *mysqlAuthorityStore, config GCAuthorityConfig) <-chan error {
		t.Helper()
		a, err := NewSQLGCAuthority(config)
		mustSQL(t, err)
		store.authority = a
		return mysqlPeerCall(t, ctx, peer, a.AuthenticateRequest, func(ctx context.Context) error {
			return (Service{Registry: gcRegistry{authority: a}, Store: store}).GC(ctx, []string{id})[0]
		})
	}
	recover := func(t *testing.T, store *mysqlAuthorityStore) <-chan error {
		t.Helper()
		a, err := NewSQLWriteRecovery(rc)
		mustSQL(t, err)
		store.authority = a
		return mysqlPeerCall(t, ctx, peer, a.AuthenticateRequest, func(ctx context.Context) error { return a.Reconcile(ctx, id, store) })
	}
	check := func(t *testing.T, state string, results int) {
		t.Helper()
		var got string
		var audits, chunks int
		var version sql.NullString
		mustSQL(t, db.QueryRowContext(ctx, "SELECT storage_state,storage_immutable_version FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&got, &version))
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM a_audit WHERE action IN ('evidence.gc.result','evidence.recovery.result')").Scan(&audits))
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence_chunks").Scan(&chunks))
		if got != state || audits != results || (state == "deleted" && (chunks != 0 || version.Valid)) || (state != "deleted" && chunks != 1) {
			t.Fatalf("state/result/payload mismatch: state=%s results=%d chunks=%d", got, audits, chunks)
		}
	}

	for _, recovery := range []bool{false, true} {
		kind := "gc"
		if recovery {
			kind = "recovery"
		}
		t.Run(kind+"_two_workers_one_live_claim", func(t *testing.T) {
			first := reset(t, recovery)
			entered, release := mysqlBarrier(t)
			first.afterStat = func(ctx context.Context) error { return mysqlPause(ctx, entered, release) }
			start := func(s *mysqlAuthorityStore) <-chan error {
				if recovery {
					return recover(t, s)
				}
				return gc(t, s, c)
			}
			done := start(first)
			mysqlAwait(t, entered)
			second := &mysqlAuthorityStore{info: first.info}
			second.present.Store(true)
			if err := mysqlResult(t, start(second)); err != ErrConflict {
				t.Fatalf("competing worker: %v", err)
			}
			if second.stats.Load() != 0 || second.deletes.Load() != 0 {
				t.Fatal("loser accessed provider")
			}
			close(release)
			mustSQL(t, mysqlResult(t, done))
			state := "deleted"
			if recovery {
				state = "ready"
			}
			check(t, state, 1)
		})
		t.Run(kind+"_expired_claim_takeover_rejects_old_result", func(t *testing.T) {
			first := reset(t, recovery)
			entered, release := mysqlBarrier(t)
			first.afterStat = func(ctx context.Context) error { return mysqlPause(ctx, entered, release) }
			start := func(s *mysqlAuthorityStore) <-chan error {
				if recovery {
					return recover(t, s)
				}
				return gc(t, s, c)
			}
			done := start(first)
			mysqlAwait(t, entered)
			var oldClaim string
			var oldRow int64
			mustSQL(t, db.QueryRowContext(ctx, "SELECT claim_owner,row_version FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&oldClaim, &oldRow))
			exec("UPDATE system_backup_v2_evidence SET claim_expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE public_id=?", id)
			second := &mysqlAuthorityStore{info: first.info}
			second.present.Store(true)
			mustSQL(t, mysqlResult(t, start(second)))
			close(release)
			want := ErrConflict
			if recovery {
				want = ErrState
			}
			if err := mysqlResult(t, done); err != want {
				t.Fatalf("stale worker result: got %v want %v", err, want)
			}
			if first.deletes.Load() != 0 {
				t.Fatal("stale worker deleted")
			}
			var row int64
			mustSQL(t, db.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&row))
			if oldClaim == "" || row != oldRow+2 {
				t.Fatal("takeover did not use a fresh CAS")
			}
			state := "deleted"
			if recovery {
				state = "ready"
			}
			check(t, state, 1)
		})
		t.Run(kind+"_persisted_backoff_blocks_direct_retry", func(t *testing.T) {
			store := reset(t, recovery)
			store.unavailable = true
			start := func(s *mysqlAuthorityStore) <-chan error {
				if recovery {
					return recover(t, s)
				}
				return gc(t, s, c)
			}
			if mysqlResult(t, start(store)) != ErrUnavailable {
				t.Fatal("unknown result accepted")
			}
			var checked, due time.Time
			var row int64
			mustSQL(t, db.QueryRowContext(ctx, "SELECT last_checked_at,next_reconcile_at,row_version FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&checked, &due, &row))
			if !due.Equal(checked.Add(time.Minute)) {
				t.Fatal("wrong persisted backoff")
			}
			second := &mysqlAuthorityStore{info: store.info}
			second.present.Store(true)
			if mysqlResult(t, start(second)) != ErrConflict || second.stats.Load() != 0 {
				t.Fatal("direct retry bypassed backoff")
			}
			var after int64
			mustSQL(t, db.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_evidence WHERE public_id=?", id).Scan(&after))
			if after != row {
				t.Fatal("denied retry mutated record")
			}
			exec("UPDATE system_backup_v2_evidence SET next_reconcile_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE public_id=?", id)
			mustSQL(t, mysqlResult(t, start(second)))
			state := "deleted"
			if recovery {
				state = "ready"
			}
			check(t, state, 2)
		})
		for _, drift := range []string{"active_config", "config_hash", "credential_ref"} {
			t.Run(kind+"_"+drift+"_revokes_inflight_result", func(t *testing.T) {
				store := reset(t, recovery)
				entered, release := mysqlBarrier(t)
				store.afterStat = func(ctx context.Context) error { return mysqlPause(ctx, entered, release) }
				var done <-chan error
				if recovery {
					done = recover(t, store)
				} else {
					done = gc(t, store, c)
				}
				mysqlAwait(t, entered)
				switch drift {
				case "active_config":
					exec("UPDATE system_backup_v2_installation_state SET active_config_version=2")
				case "config_hash":
					exec("UPDATE system_backup_v2_configs SET config_sha256=?", strings.Repeat("f", 64))
				case "credential_ref":
					if recovery {
						exec("UPDATE system_backup_v2_configs SET evidence_read_ref_version='revoked'")
					} else {
						exec("UPDATE system_backup_v2_configs SET evidence_delete_ref_version='revoked'")
					}
				}
				close(release)
				if mysqlResult(t, done) != ErrDenied || store.deletes.Load() != 0 {
					t.Fatal("configuration revocation bypassed")
				}
				state := "deleting"
				if recovery {
					state = "pending"
				}
				check(t, state, 0)
			})
		}
	}
	for _, mutation := range []string{"operation_lease", "operation_takeover", "new_reference"} {
		t.Run("gc_"+mutation+"_before_delete", func(t *testing.T) {
			store := reset(t, false)
			entered, release := mysqlBarrier(t)
			store.afterStat = func(ctx context.Context) error { return mysqlPause(ctx, entered, release) }
			done := gc(t, store, c)
			mysqlAwait(t, entered)
			switch mutation {
			case "operation_lease":
				exec("UPDATE system_backup_v2_operations SET claim_expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND)")
			case "operation_takeover":
				exec("UPDATE system_backup_v2_operations SET claim_owner='worker-two',row_version=row_version+1")
			case "new_reference":
				exec("UPDATE a_owner SET referenced=TRUE")
			}
			close(release)
			if mysqlResult(t, done) != ErrDenied || store.deletes.Load() != 0 {
				t.Fatal("revoked worker deleted")
			}
			state := "deleting"
			results := 0
			if mutation == "new_reference" {
				state = "delete_failed"
				results = 1
			}
			check(t, state, results)
		})
	}
	t.Run("gc_reference_added_after_delete_retains_payload", func(t *testing.T) {
		store := reset(t, false)
		entered, release := mysqlBarrier(t)
		store.afterDelete = func(ctx context.Context) error { return mysqlPause(ctx, entered, release) }
		done := gc(t, store, c)
		mysqlAwait(t, entered)
		exec("UPDATE a_owner SET referenced=TRUE")
		close(release)
		if mysqlResult(t, done) != ErrUnavailable || store.deletes.Load() != 1 {
			t.Fatal("reference race accepted")
		}
		check(t, "delete_failed", 1)
	})
	t.Run("gc_operation_expires_during_real_row_lock_wait", func(t *testing.T) {
		store := reset(t, false)
		exec("UPDATE system_backup_v2_operations SET claim_expires_at=DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 2 SECOND)")
		holder, err := db.BeginTx(ctx, nil)
		mustSQL(t, err)
		defer holder.Rollback()
		var row int64
		mustSQL(t, holder.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id).Scan(&row))
		done := gc(t, store, c)
		// Observe an actual blocked InnoDB transaction, not a timing assumption.
		limit := time.Now().Add(5 * time.Second)
		for {
			var waits int
			mustSQL(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.threads th ON th.THREAD_ID=w.REQUESTING_THREAD_ID WHERE th.PROCESSLIST_DB=?`, registry.Database).Scan(&waits))
			if waits > 0 {
				break
			}
			if time.Now().After(limit) {
				t.Fatal("worker never waited for evidence row lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		for {
			var expired bool
			mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)>=claim_expires_at FROM system_backup_v2_operations WHERE public_id=?", c.OperationID).Scan(&expired))
			if expired {
				break
			}
			if time.Now().After(limit) {
				t.Fatal("database lease clock did not advance")
			}
			time.Sleep(20 * time.Millisecond)
		}
		mustSQL(t, holder.Commit())
		if mysqlResult(t, done) != ErrDenied || store.stats.Load() != 0 || store.deletes.Load() != 0 {
			t.Fatal("expired waiter acquired GC claim")
		}
		check(t, "ready", 0)
		var audits int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM a_audit").Scan(&audits))
		if audits != 0 {
			t.Fatal("expired waiter committed intent audit")
		}
	})
	t.Log("SCOPE real_mysql_authority=yes real_mtls=yes control_schema=projection owner_policy=synthetic provider=synthetic")
}

type mysqlLivePolicy struct{ mysqlPolicy }

// Fixture setup owns this empty synthetic store and can confirm absence.
// Publish must retain its normal refusal to PUT on unknown absence.
func mysqlAuthoritySeedStore() *testStore { return &testStore{authoritative: true} }

// Runs locally with the MySQL build tag, without a database. Exercise the same
// provider initialization used by every GC fixture through real Publish code.
func TestMySQLAuthoritySeed(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		name := "confirmed_absence_publishes_ready"
		if !confirmed {
			name = "unknown_absence_blocks_put"
		}
		t.Run(name, func(t *testing.T) {
			p, _, object, keys := fixture(t, 9000)
			now := time.Now().UTC().Truncate(time.Microsecond)
			registry := &memoryRegistry{now: now}
			store := mysqlAuthoritySeedStore()
			if !confirmed {
				store.authoritative = false
			}
			s := Service{Registry: registry, Store: store, Keys: keys}
			if err := s.Register(context.Background(), p, "evidence", Ref{Identity: strings.Repeat("a", 64), Version: "v1"}, now, now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			err := s.Publish(context.Background(), p.manifest.Identity.ID, source(object))
			if confirmed {
				if err != nil || store.puts != 1 || registry.r.State != "ready" || registry.r.Ref.ImmutableVersion != "immutable-v1" || !matchObject(registry.r, store.info) {
					t.Fatalf("GC seed must be ready after exactly one PUT: err=%v state=%s puts=%d", err, registry.r.State, store.puts)
				}
			} else if err != ErrUnavailable || store.puts != 0 || registry.r.State != "write_unknown" || registry.r.Ref.ImmutableVersion != "" {
				t.Fatal("unknown absence bypassed publication gate")
			}
		})
	}

}

func (mysqlLivePolicy) OwnerDeadline(ctx context.Context, tx *sql.Tx, i Identity) (time.Time, error) {
	var deadline time.Time
	err := tx.QueryRowContext(ctx, "SELECT deadline FROM a_owner WHERE public_id=? FOR UPDATE", i.OwnerID).Scan(&deadline)
	return deadline, err
}

type mysqlAuthorityStore struct {
	authority              S3WebIdentityAuthority
	info                   ObjectInfo
	present                atomic.Bool
	stats, deletes         atomic.Int32
	unavailable            bool
	afterStat, afterDelete func(context.Context) error
}

func (s *mysqlAuthorityStore) allow(ctx context.Context, scope S3Scope) error {
	g, err := s.authority.AuthorizeS3(ctx, scope)
	wipe(g.Token)
	return err
}
func (s *mysqlAuthorityStore) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	if err := s.allow(ctx, S3Scope{Ref: ref, Operation: S3Stat}); err != nil {
		return ObjectInfo{}, err
	}
	s.stats.Add(1)
	if s.afterStat != nil {
		if err := s.afterStat(ctx); err != nil {
			return ObjectInfo{}, err
		}
	}
	if s.unavailable || !s.present.Load() {
		return ObjectInfo{}, ErrUnavailable
	}
	return s.info, nil
}
func (s *mysqlAuthorityStore) Delete(ctx context.Context, ref Ref, info ObjectInfo) error {
	if err := s.allow(ctx, S3Scope{Ref: ref, Operation: S3Delete, Object: info}); err != nil {
		return err
	}
	s.deletes.Add(1)
	s.present.Store(false)
	if s.afterDelete != nil {
		return s.afterDelete(ctx)
	}
	return nil
}
func (s *mysqlAuthorityStore) Absent(ctx context.Context, ref Ref) (Absence, error) {
	if err := s.allow(ctx, S3Scope{Ref: ref, Operation: S3Stat}); err != nil {
		return Absence{}, err
	}
	return Absence{Authoritative: !s.unavailable && !s.present.Load(), Version: ref.ImmutableVersion}, nil
}
func (*mysqlAuthorityStore) Put(context.Context, Ref, io.Reader, ObjectInfo, time.Time) error {
	return ErrDenied
}
func (*mysqlAuthorityStore) Range(context.Context, Ref, int64, int64) (io.ReadCloser, error) {
	return nil, ErrDenied
}

// Each call uses a separate TLS request and a live request context. No fabricated
// TLS state or context imported from another authority is used by these probes.
func mysqlPeerCall(t *testing.T, parent context.Context, peer *taskFixture, auth func(*http.Request) (context.Context, error), fn func(context.Context) error) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	done := make(chan error, 1)
	callctx, cancel := context.WithTimeout(parent, 15*time.Second)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(peer.c.ClientCAPEM)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := auth(r)
		if err == nil {
			err = fn(ctx)
		}
		result <- err
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	client := server.Client()
	client.Timeout = 15 * time.Second
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{peer.client}
	t.Cleanup(func() { cancel(); client.CloseIdleConnections(); server.Close() })
	go func() {
		defer cancel()
		request, err := http.NewRequestWithContext(callctx, http.MethodPost, server.URL, nil)
		if err != nil {
			done <- err
			return
		}
		response, err := client.Do(request)
		if err != nil {
			done <- err
			return
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			done <- fmt.Errorf("peer status %d", response.StatusCode)
			return
		}
		done <- <-result
	}()
	return done
}
func mysqlBarrier(t *testing.T) (chan struct{}, chan struct{}) {
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	return entered, release
}
func mysqlPause(ctx context.Context, entered, release chan struct{}) error {
	close(entered)
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func mysqlAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not reach provider barrier")
	}
}
func mysqlResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("worker did not finish")
		return ErrUnavailable
	}
}
