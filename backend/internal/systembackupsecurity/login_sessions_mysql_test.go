//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

const sessionProbeInstallation = "installation_session_probe"
const sessionProbePassword = "synthetic-verified-password-hash"

// Only the existing disposable migration harness may supply these markers.
// Missing configuration is a failure, never a skipped/passing MySQL test.
func sessionProbeConfig(run, uid, host, password string) (*mysql.Config, error) {
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uid) || password == "" {
		return nil, errors.New("isolated MySQL marker required")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") {
		return nil, errors.New("isolated IPv4 required")
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "root", password, "tcp", net.JoinHostPort(host, "3306"), "clawmanager"
	c.ParseTime, c.Loc, c.MultiStatements = true, time.UTC, true
	c.Params = map[string]string{"time_zone": "'+00:00'"}
	c.Timeout, c.ReadTimeout, c.WriteTimeout = 5*time.Second, 20*time.Second, 20*time.Second
	return c, nil
}

// No database access: catch malformed fixture tokens and unsafe harness input
// before compiling/uploading a Linux probe. This is not MySQL acceptance.
func TestLoginSessionMySQLSeed(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	s := &SQLLoginSessions{secret: secret}
	p := sessionProbePair(t, secret, time.Now().UTC(), "")
	a, err := s.token(p.AccessToken, "access")
	mysqlMust(t, err)
	r, err := s.token(p.RefreshToken, "refresh")
	mysqlMust(t, err)
	if a.UserID != 42 || r.UserID != 42 || a.Session == r.Session || !r.SessionExpiresAt.After(a.SessionExpiresAt) || p.CredentialSHA256 != registrationHash(sessionProbePassword) {
		t.Fatal("session fixture binding")
	}
	run, uid := "sbk-mig-260930000000-abcd", "11111111-2222-3333-4444-555555555555"
	if _, err := sessionProbeConfig(run, uid, "", "synthetic"); err != nil {
		t.Fatal("valid fixture rejected")
	}
	for _, v := range [][4]string{{"production", uid, "", "synthetic"}, {run, "invalid", "", "synthetic"}, {run, uid, "mysql.example", "synthetic"}, {run, uid, "::1", "synthetic"}, {run, uid, "", ""}} {
		if _, err := sessionProbeConfig(v[0], v[1], v[2], v[3]); err == nil {
			t.Fatal("unsafe harness input accepted")
		}
	}
}

func sessionProbePair(t *testing.T, secret []byte, now time.Time, parent string) LoginSessionPair {
	t.Helper()
	p := LoginSessionPair{UserID: 42, CredentialSHA256: registrationHash(sessionProbePassword), PreviousRefreshToken: parent}
	for _, kind := range []string{"access", "refresh"} {
		var nonce [16]byte
		_, err := rand.Read(nonce[:])
		mysqlMust(t, err)
		expires := now.Add(5 * time.Minute)
		if kind == "refresh" {
			expires = now.Add(time.Hour)
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": 42, "token_type": kind, "jti": hex.EncodeToString(nonce[:]), "iat": now.Add(-2 * time.Second).Unix(), "exp": expires.Unix(),
		}).SignedString(secret)
		mysqlMust(t, err)
		if kind == "access" {
			p.AccessToken = raw
		} else {
			p.RefreshToken = raw
		}
	}
	return p
}

type sessionMySQLProbe struct {
	db       *sql.DB
	config   *mysql.Config
	identity DatabaseIdentity
	secret   []byte
}

func (f sessionMySQLProbe) service(t *testing.T, db *sql.DB, installation string) *SQLLoginSessions {
	t.Helper()
	s, err := NewSQLLoginSessions(db, f.identity, installation, f.secret)
	mysqlMust(t, err)
	return s
}

func (f sessionMySQLProbe) pair(t *testing.T, ctx context.Context, parent string) LoginSessionPair {
	t.Helper()
	var now time.Time
	mysqlMust(t, f.db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	return sessionProbePair(t, f.secret, now, parent)
}

func (f sessionMySQLProbe) counts(t *testing.T, ctx context.Context, sessions, revoked, audits, epochs int) {
	t.Helper()
	for _, c := range []struct {
		query string
		want  int
	}{
		{"SELECT COUNT(*) FROM system_backup_v2_admin_sessions", sessions},
		{"SELECT COUNT(*) FROM system_backup_v2_admin_sessions WHERE revoked=TRUE", revoked},
		{"SELECT COUNT(*) FROM audit_logs", audits},
		{"SELECT COUNT(*) FROM system_backup_v2_admin_revocations", epochs},
	} {
		var got int
		mysqlMust(t, f.db.QueryRowContext(ctx, c.query).Scan(&got))
		if got != c.want {
			t.Fatalf("atomic row counts: got %d want %d for %s", got, c.want, c.query)
		}
	}
}

type sessionProbeWorker struct {
	id     int64
	result <-chan error
}

// Each worker owns one physical connection. The observer uses its connection
// ID and requested table to prove the precise InnoDB wait before releasing it.
func (f sessionMySQLProbe) start(t *testing.T, ctx context.Context, call func(context.Context, *SQLLoginSessions) error) sessionProbeWorker {
	t.Helper()
	db, err := sql.Open("mysql", f.config.FormatDSN())
	mysqlMust(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var id int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id))
	s := f.service(t, db, sessionProbeInstallation)
	work, cancel := context.WithTimeout(ctx, 15*time.Second)
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- call(work, s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("session worker did not drain")
		}
		db.Close()
	})
	return sessionProbeWorker{id, result}
}

func (f sessionMySQLProbe) waiting(t *testing.T, ctx context.Context, w sessionProbeWorker, table string) {
	t.Helper()
	limit := time.Now().Add(8 * time.Second)
	for {
		var count int
		mysqlMust(t, f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
JOIN performance_schema.threads th ON th.THREAD_ID=w.REQUESTING_THREAD_ID
JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE
WHERE th.PROCESSLIST_ID=? AND l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=?`, w.id, f.identity.Database, table).Scan(&count))
		if count > 0 {
			t.Logf("OBSERVED session lock wait table=%s", table)
			return
		}
		select {
		case <-w.result:
			t.Fatal("worker ended before required row-lock wait")
		default:
		}
		if time.Now().After(limit) || ctx.Err() != nil {
			t.Fatal("required InnoDB row-lock wait not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sessionWorkerResult(t *testing.T, ctx context.Context, w sessionProbeWorker) error {
	t.Helper()
	select {
	case err := <-w.result:
		return err
	case <-ctx.Done():
		t.Fatal("session worker timed out")
		return ctx.Err()
	}
}

func sessionExpect(t *testing.T, got, want error) {
	t.Helper()
	if got != want {
		t.Fatal("session outcome did not match expected public error")
	}
}

func TestALoginSessionsMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer admin.Close()
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if run != gotRun || uid != gotUID || pinnedUUID != actualUUID {
		t.Fatal("isolated database marker mismatch")
	}
	ddl, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	digest := sha256.Sum256(ddl)
	if hex.EncodeToString(digest[:]) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || len(ddl) < 1000 || len(ddl) > 65536 {
		t.Fatal("session DDL digest/size mismatch")
	}
	var entropy [16]byte
	_, err = rand.Read(entropy[:])
	mysqlMust(t, err)
	database := "als_" + hex.EncodeToString(entropy[:])
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+database+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	mysqlMust(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		var current string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&current) != nil || current != pinnedUUID {
			t.Error("CLEANUP_PENDING session server identity")
			return
		}
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+database); err != nil {
			t.Error("CLEANUP_PENDING session run-owned database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING session database absence")
			return
		}
		t.Log("CLEANED login-sessions run-owned database")
	}()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	db.SetMaxOpenConns(12)
	_, err = db.ExecContext(ctx, string(ddl))
	mysqlMust(t, err)
	f := sessionMySQLProbe{db, cfg, DatabaseIdentity{ServerUUID: actualUUID, Database: database}, []byte(strings.Repeat("s", 32))}
	svc := f.service(t, db, sessionProbeInstallation)
	exec := func(t *testing.T, q string, args ...any) {
		t.Helper()
		_, e := db.ExecContext(ctx, q, args...)
		mysqlMust(t, e)
	}
	reset := func(t *testing.T) {
		exec(t, "DELETE FROM system_backup_v2_admin_sessions; DELETE FROM system_backup_v2_admin_revocations; DELETE FROM audit_logs; DELETE FROM users")
		exec(t, "INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'session-probe','session-probe@example.invalid',?,'admin',TRUE)", sessionProbePassword)
	}
	hold := func(t *testing.T, query string, args ...any) *sql.Tx {
		t.Helper()
		tx, e := db.BeginTx(ctx, nil)
		mysqlMust(t, e)
		t.Cleanup(func() { tx.Rollback() })
		var value int
		mysqlMust(t, tx.QueryRowContext(ctx, query, args...).Scan(&value))
		return tx
	}
	issue := func(t *testing.T) LoginSessionPair {
		p := f.pair(t, ctx, "")
		mysqlMust(t, svc.RecordPair(ctx, p))
		return p
	}
	startPair := func(t *testing.T, p LoginSessionPair) sessionProbeWorker {
		return f.start(t, ctx, func(c context.Context, s *SQLLoginSessions) error { return s.RecordPair(c, p) })
	}
	startLogout := func(t *testing.T) sessionProbeWorker {
		return f.start(t, ctx, func(c context.Context, s *SQLLoginSessions) error { return s.RevokeUserSessions(c, 42) })
	}
	runCase := func(name string, fn func(*testing.T)) bool {
		return t.Run(name, func(t *testing.T) { reset(t); fn(t) })
	}
	if !runCase("pair_and_audit_commit_atomically", func(t *testing.T) {
		p := issue(t)
		f.counts(t, ctx, 2, 0, 1, 0)
		var count int
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_admin_sessions WHERE session_sha256 IN (?,?) AND credential_hash=? AND subject='user:42' AND origin_installation_id=?", registrationHash(p.AccessToken), registrationHash(p.RefreshToken), p.CredentialSHA256, sessionProbeInstallation).Scan(&count))
		if count != 2 {
			t.Fatal("persisted pair binding mismatch")
		}
	}) {
		return
	}
	if !runCase("same_refresh_has_exactly_one_concurrent_winner", func(t *testing.T) {
		parent := issue(t)
		block := hold(t, "SELECT id FROM users WHERE id=42 FOR UPDATE")
		defer block.Rollback()
		var workers []sessionProbeWorker
		for n := 0; n < 3; n++ {
			w := startPair(t, f.pair(t, ctx, parent.RefreshToken))
			f.waiting(t, ctx, w, "users")
			workers = append(workers, w)
		}
		mysqlMust(t, block.Commit())
		wins := 0
		for _, w := range workers {
			err := sessionWorkerResult(t, ctx, w)
			if err == nil {
				wins++
			} else {
				sessionExpect(t, err, ErrLoginSessionRejected)
			}
		}
		if wins != 1 {
			t.Fatal("refresh did not have exactly one winner")
		}
		f.counts(t, ctx, 4, 1, 2, 0)
	}) {
		return
	}
	if !runCase("refresh_commits_before_logout_all_tokens_revoked", func(t *testing.T) {
		parent := issue(t)
		block := hold(t, "SELECT user_id FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND session_sha256=? FOR UPDATE", sessionProbeInstallation, registrationHash(parent.RefreshToken))
		defer block.Rollback()
		refresh := startPair(t, f.pair(t, ctx, parent.RefreshToken))
		f.waiting(t, ctx, refresh, "system_backup_v2_admin_sessions")
		logout := startLogout(t)
		f.waiting(t, ctx, logout, "users")
		mysqlMust(t, block.Commit())
		sessionExpect(t, sessionWorkerResult(t, ctx, refresh), nil)
		sessionExpect(t, sessionWorkerResult(t, ctx, logout), nil)
		f.counts(t, ctx, 4, 4, 2, 1)
	}) {
		return
	}
	if !runCase("logout_commits_before_refresh_no_new_pair", func(t *testing.T) {
		parent := issue(t)
		exec(t, "INSERT INTO system_backup_v2_admin_revocations VALUES(?,42,DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE))", sessionProbeInstallation)
		block := hold(t, "SELECT user_id FROM system_backup_v2_admin_revocations WHERE origin_installation_id=? AND user_id=42 FOR UPDATE", sessionProbeInstallation)
		defer block.Rollback()
		logout := startLogout(t)
		f.waiting(t, ctx, logout, "system_backup_v2_admin_revocations")
		refresh := startPair(t, f.pair(t, ctx, parent.RefreshToken))
		f.waiting(t, ctx, refresh, "users")
		mysqlMust(t, block.Commit())
		sessionExpect(t, sessionWorkerResult(t, ctx, logout), nil)
		sessionExpect(t, sessionWorkerResult(t, ctx, refresh), ErrLoginSessionRejected)
		f.counts(t, ctx, 2, 2, 1, 1)
	}) {
		return
	}
	for _, refresh := range []bool{false, true} {
		for _, mutation := range []string{"password", "disable"} {
			name := "login_waits_for_" + mutation
			if refresh {
				name = "refresh_waits_for_" + mutation
			}
			if !runCase(name, func(t *testing.T) {
				parent, rows, audits := "", 0, 0
				if refresh {
					parent, rows, audits = issue(t).RefreshToken, 2, 1
				}
				p := f.pair(t, ctx, parent)
				block := hold(t, "SELECT id FROM users WHERE id=42 FOR UPDATE")
				defer block.Rollback()
				w := startPair(t, p)
				f.waiting(t, ctx, w, "users")
				q := "UPDATE users SET password_hash='changed-synthetic-hash' WHERE id=42"
				if mutation == "disable" {
					q = "UPDATE users SET is_active=FALSE WHERE id=42"
				}
				_, err := block.ExecContext(ctx, q)
				mysqlMust(t, err)
				mysqlMust(t, block.Commit())
				sessionExpect(t, sessionWorkerResult(t, ctx, w), ErrLoginSessionRejected)
				f.counts(t, ctx, rows, 0, audits, 0)
			}) {
				return
			}
		}
	}
	if !runCase("old_refresh_cannot_rebind_new_password", func(t *testing.T) {
		parent := issue(t)
		exec(t, "UPDATE users SET password_hash='changed-synthetic-hash' WHERE id=42")
		p := f.pair(t, ctx, parent.RefreshToken)
		p.CredentialSHA256 = registrationHash("changed-synthetic-hash")
		sessionExpect(t, svc.RecordPair(ctx, p), ErrLoginSessionRejected)
		f.counts(t, ctx, 2, 0, 1, 0)
	}) {
		return
	}
	for _, refresh := range []bool{false, true} {
		name := "login_audit_failure_rolls_back_pair"
		if refresh {
			name = "refresh_audit_failure_restores_parent_and_allows_retry"
		}
		if !runCase(name, func(t *testing.T) {
			parent, rows, audits := "", 0, 0
			if refresh {
				parent, rows, audits = issue(t).RefreshToken, 2, 1
			}
			p := f.pair(t, ctx, parent)
			exec(t, "CREATE TRIGGER a_session_reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'")
			t.Cleanup(func() { exec(t, "DROP TRIGGER IF EXISTS a_session_reject_audit") })
			sessionExpect(t, svc.RecordPair(ctx, p), ErrLoginSessionUnavailable)
			f.counts(t, ctx, rows, 0, audits, 0)
			exec(t, "DROP TRIGGER a_session_reject_audit")
			mysqlMust(t, svc.RecordPair(ctx, p))
			revoked := 0
			if refresh {
				revoked = 1
			}
			f.counts(t, ctx, rows+2, revoked, audits+1, 0)
		}) {
			return
		}
	}
	if !runCase("logout_failure_rolls_back_epoch_and_revocations", func(t *testing.T) {
		issue(t)
		exec(t, "CREATE TRIGGER a_session_reject_revoke BEFORE UPDATE ON system_backup_v2_admin_sessions FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic revoke failure'")
		t.Cleanup(func() { exec(t, "DROP TRIGGER IF EXISTS a_session_reject_revoke") })
		sessionExpect(t, svc.RevokeUserSessions(ctx, 42), ErrRegistrationUnavailable)
		f.counts(t, ctx, 2, 0, 1, 0)
		exec(t, "DROP TRIGGER a_session_reject_revoke")
		mysqlMust(t, svc.RevokeUserSessions(ctx, 42))
		f.counts(t, ctx, 2, 2, 1, 1)
	}) {
		return
	}
	if !runCase("token_expires_during_observed_user_lock_wait", func(t *testing.T) {
		p := f.pair(t, ctx, "")
		var now time.Time
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
		expires := now.Add(3 * time.Second).Truncate(time.Second)
		p.AccessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "access", "jti": "short-lived-probe", "iat": now.Add(-2 * time.Second).Unix(), "exp": expires.Unix()}).SignedString(f.secret)
		mysqlMust(t, err)
		block := hold(t, "SELECT id FROM users WHERE id=42 FOR UPDATE")
		defer block.Rollback()
		w := startPair(t, p)
		f.waiting(t, ctx, w, "users")
		limit := time.Now().Add(6 * time.Second)
		for {
			var expired bool
			mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)>=?", expires).Scan(&expired))
			if expired {
				break
			}
			if time.Now().After(limit) {
				t.Fatal("database clock did not reach expiry")
			}
			time.Sleep(10 * time.Millisecond)
		}
		mysqlMust(t, block.Commit())
		sessionExpect(t, sessionWorkerResult(t, ctx, w), ErrLoginSessionRejected)
		f.counts(t, ctx, 0, 0, 0, 0)
	}) {
		return
	}
	if !runCase("wrong_database_pin_rejects_before_writes", func(t *testing.T) {
		wrong := f
		wrong.identity.Database = "unrelated_database"
		sessionExpect(t, wrong.service(t, db, sessionProbeInstallation).RecordPair(ctx, f.pair(t, ctx, "")), ErrLoginSessionUnavailable)
		f.counts(t, ctx, 0, 0, 0, 0)
	}) {
		return
	}
	if !runCase("logout_is_scoped_to_exact_installation", func(t *testing.T) {
		p := issue(t)
		other := f.service(t, db, "installation_session_other")
		mysqlMust(t, other.RecordPair(ctx, p))
		mysqlMust(t, svc.RevokeUserSessions(ctx, 42))
		f.counts(t, ctx, 4, 2, 2, 1)
		var live int
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_admin_sessions WHERE origin_installation_id='installation_session_other' AND revoked=FALSE").Scan(&live))
		if live != 2 {
			t.Fatal("logout affected another installation")
		}
	}) {
		return
	}
	t.Log("SCOPE real_mysql_sessions=yes real_lock_waits=yes authentication_callback=synthetic full_login_http=no ldap_events=no provider=no")
}
