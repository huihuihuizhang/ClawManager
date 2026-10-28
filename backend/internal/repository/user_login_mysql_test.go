//go:build systembackup_mysql

package repository_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	"clawreef/internal/repository"
	controller "clawreef/internal/systembackupcontroller"
	driver "github.com/go-sql-driver/mysql"
	upper "github.com/upper/db/v4"
	mysql "github.com/upper/db/v4/adapter/mysql"
)

type loginStateProbeInputs struct {
	Kind          string   `json:"kind"`
	CatalogSHA256 string   `json:"catalog_sha256"`
	Filenames     []string `json:"filenames"`
}

func loginStateInputs(raw []byte, digest string) error {
	h := sha256.Sum256(raw)
	if len(raw) == 0 || len(raw) > 65536 || hex.EncodeToString(h[:]) != digest {
		return errors.New("probe input digest/size mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var v loginStateProbeInputs
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Kind != "a_login_state_probe_inputs" {
		return errors.New("probe input invalid")
	}
	c, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || c.Hash != controller.ContractMigrationCatalogHash || len(c.Filenames) != controller.ContractMigrationCatalogFileCount ||
		v.CatalogSHA256 != c.Hash || !slices.Equal(v.Filenames, c.Filenames) {
		return errors.New("compiled migration inputs differ")
	}
	return nil
}

func loginStateURL(run, uid, host, password string) (mysql.ConnectionURL, error) {
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uid) || password == "" {
		return mysql.ConnectionURL{}, errors.New("isolated MySQL identity required")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") {
		return mysql.ConnectionURL{}, errors.New("isolated IPv4 required")
	}
	return mysql.ConnectionURL{Host: net.JoinHostPort(host, "3306"), User: "root", Password: password, Database: "clawmanager", Options: map[string]string{
		"parseTime": "true", "loc": "UTC", "time_zone": "'+00:00'", "clientFoundRows": "false",
		"timeout": "5s", "readTimeout": "20s", "writeTimeout": "20s", "innodb_lock_wait_timeout": "12",
	}}, nil
}

// Offline gate only. A successful seed test never means MySQL was exercised.
func TestLoginStateMySQLSeed(t *testing.T) {
	run, uid := "sbk-mig-260930000000-abcd", "11111111-2222-3333-4444-555555555555"
	valid, err := loginStateURL(run, uid, "", "synthetic")
	loginStateMust(t, err)
	if valid.Options["clientFoundRows"] != "false" || valid.Database != "clawmanager" {
		t.Fatal("changed-rows fixture required")
	}
	for _, a := range [][4]string{{"production", uid, "", "synthetic"}, {run, "bad", "", "synthetic"}, {run, uid, "mysql.example", "synthetic"}, {run, uid, "::1", "synthetic"}, {run, uid, "", ""}} {
		if _, err := loginStateURL(a[0], a[1], a[2], a[3]); err == nil {
			t.Fatal("unsafe fixture accepted")
		}
	}
	c, err := appdb.EmbeddedMigrationCatalog()
	loginStateMust(t, err)
	v := loginStateProbeInputs{"a_login_state_probe_inputs", c.Hash, c.Filenames}
	check := func(v loginStateProbeInputs, wantOK bool) {
		raw, err := json.Marshal(v)
		loginStateMust(t, err)
		h := sha256.Sum256(raw)
		if (loginStateInputs(raw, hex.EncodeToString(h[:])) == nil) != wantOK {
			t.Fatal("input acceptance mismatch")
		}
		if loginStateInputs(raw, strings.Repeat("0", 64)) == nil {
			t.Fatal("digest mismatch accepted")
		}
	}
	check(v, true)
	v.CatalogSHA256 = strings.Repeat("0", 64)
	check(v, false)
	v.CatalogSHA256 = c.Hash
	v.Filenames = c.Filenames[:len(c.Filenames)-1]
	check(v, false)
	v.Filenames = append(append([]string{}, c.Filenames...), c.Filenames[0])
	check(v, false)
}

func loginStateMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		var mysqlError *driver.MySQLError
		if errors.As(err, &mysqlError) {
			t.Fatalf("login-state MySQL failure code=%d (details withheld)", mysqlError.Number)
		}
		t.Fatal("login-state probe operation failed (details withheld)")
	}
}

func loginStateOpen(t *testing.T, ctx context.Context, cfg mysql.ConnectionURL) (upper.Session, *sql.DB) {
	t.Helper()
	s, err := mysql.Open(cfg)
	loginStateMust(t, err)
	s.SetMaxOpenConns(1)
	s.SetMaxIdleConns(1)
	db, ok := s.Driver().(*sql.DB)
	if !ok {
		s.Close()
		t.Fatal("SQL driver required")
	}
	return s.WithContext(ctx), db
}

type loginStateRow struct {
	Password, Provider, Role string
	External                 sql.NullString
	Active                   bool
	Last                     sql.NullTime
}

func loginStateRead(t *testing.T, ctx context.Context, db *sql.DB, id int) loginStateRow {
	t.Helper()
	var r loginStateRow
	loginStateMust(t, db.QueryRowContext(ctx, "SELECT password_hash,auth_provider,role,external_id,is_active,last_login FROM users WHERE id=?", id).Scan(&r.Password, &r.Provider, &r.Role, &r.External, &r.Active, &r.Last))
	return r
}

func loginStateCounter(t *testing.T, ctx context.Context, db *sql.DB) uint64 {
	t.Helper()
	var name string
	var n uint64
	// SHOW does not increment Com_select; this proves the real fallback SELECT
	// executed on the one-connection repository session, without SQL mocking.
	loginStateMust(t, db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_select'").Scan(&name, &n))
	if name != "Com_select" {
		t.Fatal("statement counter unavailable")
	}
	return n
}

func TestALoginStateMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.Cleanup(cancel)
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := loginStateURL(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	loginStateMust(t, err)
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	loginStateMust(t, err)
	loginStateMust(t, loginStateInputs(raw, os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256")))
	admin, adb := loginStateOpen(t, ctx, cfg)
	t.Cleanup(func() { admin.Close() })
	var markerRun, markerUID, pinned, actual string
	loginStateMust(t, adb.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&markerRun, &markerUID, &pinned))
	loginStateMust(t, adb.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actual))
	if markerRun != run || markerUID != uid || pinned != actual {
		t.Fatal("isolated server identity mismatch")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	loginStateMust(t, err)
	rows, err := adb.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	loginStateMust(t, err)
	var applied []string
	for rows.Next() {
		var name string
		loginStateMust(t, rows.Scan(&name))
		applied = append(applied, name)
	}
	loginStateMust(t, rows.Err())
	loginStateMust(t, rows.Close())
	if !slices.Equal(applied, catalog.Filenames) {
		t.Fatal("full fresh migration ledger required")
	}
	t.Logf("MIGRATION_INPUT files=%d catalog_sha256=%s", len(applied), catalog.Hash)
	var entropy [16]byte
	_, err = rand.Read(entropy[:])
	loginStateMust(t, err)
	database := "alu_" + hex.EncodeToString(entropy[:])
	_, err = adb.ExecContext(ctx, "CREATE DATABASE "+database+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	loginStateMust(t, err)
	// Parent Cleanup runs even if a child panics; parent defers do not.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		var current string
		if adb.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&current) != nil || current != pinned {
			t.Error("CLEANUP_PENDING login-state server identity")
			return
		}
		if _, err := adb.ExecContext(cleanup, "DROP DATABASE "+database); err != nil {
			t.Error("CLEANUP_PENDING login-state database")
			return
		}
		var count int
		if adb.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING login-state absence")
			return
		}
		t.Log("CLEANED login-state run-owned database")
	})
	// Clone the actual post-migration users schema, including generated columns
	// and indexes, not an abbreviated 001 CREATE or a hand-written fixture.
	_, err = adb.ExecContext(ctx, "CREATE TABLE "+database+".users LIKE clawmanager.users")
	loginStateMust(t, err)
	cfg.Database = database
	observer, db := loginStateOpen(t, ctx, cfg)
	t.Cleanup(func() { observer.Close() })
	repoSession, rdb := loginStateOpen(t, ctx, cfg)
	t.Cleanup(func() { repoSession.Close() })
	repo := repository.NewUserRepository(repoSession).(repository.LoginStateRepository)
	var sourceName, sourceDDL, cloneName, cloneDDL string
	loginStateMust(t, adb.QueryRowContext(ctx, "SHOW CREATE TABLE users").Scan(&sourceName, &sourceDDL))
	loginStateMust(t, db.QueryRowContext(ctx, "SHOW CREATE TABLE users").Scan(&cloneName, &cloneDDL))
	// CREATE LIKE does not retain the source auto-increment counter (seed data).
	normalize := func(s string) string { return regexp.MustCompile(` AUTO_INCREMENT=[0-9]+`).ReplaceAllString(s, "") }
	if normalize(sourceDDL) != normalize(cloneDDL) {
		t.Fatal("full users schema clone differs")
	}
	dh := sha256.Sum256([]byte(normalize(sourceDDL)))
	t.Logf("USERS_SCHEMA normalized_create_sha256=%s", hex.EncodeToString(dh[:]))
	exec := func(t *testing.T, q string, args ...any) {
		t.Helper()
		_, e := db.ExecContext(ctx, q, args...)
		loginStateMust(t, e)
	}
	seed := func(t *testing.T, ldap bool) repository.LoginState {
		t.Helper()
		exec(t, "DELETE FROM users")
		provider := "local"
		var external *string
		if ldap {
			provider = "ldap"
			dn := "CN=Probe,OU=People,DC=example,DC=test"
			external = &dn
		}
		r, err := db.ExecContext(ctx, "INSERT INTO users(username,email,password_hash,auth_provider,external_id,role,is_active) VALUES ('probe','probe@example.invalid','SyntheticHash',?,?,'user',TRUE)", provider, external)
		loginStateMust(t, err)
		id, err := r.LastInsertId()
		loginStateMust(t, err)
		return repository.LoginState{UserID: int(id), PasswordHash: "SyntheticHash", AuthProvider: provider, ExpectedRole: "user", Role: "user", ExternalID: external, At: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}
	}
	for _, ldap := range []bool{false, true} {
		name := "local"
		if ldap {
			name = "ldap"
		}
		t.Run(name+"_changed_and_zero_changed_rows", func(t *testing.T) {
			s := seed(t, ldap)
			before := loginStateCounter(t, ctx, rdb)
			loginStateMust(t, repo.UpdateLoginState(s))
			if loginStateCounter(t, ctx, rdb) != before {
				t.Fatal("first update unexpectedly used fallback")
			}
			loginStateMust(t, repo.UpdateLoginState(s))
			if loginStateCounter(t, ctx, rdb) != before+1 {
				t.Fatal("zero changed rows fallback not observed")
			}
			got := loginStateRead(t, ctx, db, s.UserID)
			if !got.Last.Valid || !got.Last.Time.Equal(s.At) || got.Role != "user" || got.Provider != s.AuthProvider || !got.Active {
				t.Fatal("login state not persisted")
			}
			t.Log("OBSERVED zero-changed-rows fallback SELECT")
		})
	}
	for _, role := range []string{"admin", "user"} {
		t.Run("ldap_role_to_"+role, func(t *testing.T) {
			s := seed(t, true)
			if role == "user" {
				exec(t, "UPDATE users SET role='admin' WHERE id=?", s.UserID)
				s.ExpectedRole = "admin"
			}
			s.Role = role
			loginStateMust(t, repo.UpdateLoginState(s))
			if loginStateRead(t, ctx, db, s.UserID).Role != role {
				t.Fatal("LDAP role not synchronized")
			}
		})
	}
	changes := []struct{ name, query string }{
		{"password", "UPDATE users SET password_hash='NewHash' WHERE id=?"},
		{"password_case", "UPDATE users SET password_hash='synthetichash' WHERE id=?"},
		{"password_trailing_space", "UPDATE users SET password_hash='SyntheticHash ' WHERE id=?"},
		{"disabled", "UPDATE users SET is_active=FALSE WHERE id=?"},
		{"role", "UPDATE users SET role='admin' WHERE id=?"},
		{"provider", "UPDATE users SET auth_provider='local' WHERE id=?"},
		{"external_id", "UPDATE users SET external_id='CN=Other,DC=example,DC=test' WHERE id=?"},
		{"external_id_case", "UPDATE users SET external_id='cn=probe,ou=people,dc=example,dc=test' WHERE id=?"},
		{"external_id_null", "UPDATE users SET external_id=NULL WHERE id=?"},
	}
	for _, change := range changes {
		t.Run("stale_"+change.name, func(t *testing.T) {
			s := seed(t, true)
			exec(t, change.query, s.UserID)
			before := loginStateRead(t, ctx, db, s.UserID)
			counter := loginStateCounter(t, ctx, rdb)
			err := repo.UpdateLoginState(s)
			if err == nil || err.Error() != "login state conflict" {
				t.Fatal("stale login not rejected safely")
			}
			if loginStateCounter(t, ctx, rdb) != counter+1 {
				t.Fatal("predicate rejection fallback not observed")
			}
			if loginStateRead(t, ctx, db, s.UserID) != before {
				t.Fatal("stale login overwrote current account")
			}
		})
	}
	t.Run("null_external_is_not_empty", func(t *testing.T) {
		s := seed(t, false)
		exec(t, "UPDATE users SET external_id='' WHERE id=?", s.UserID)
		if err := repo.UpdateLoginState(s); err == nil {
			t.Fatal("NULL identity matched empty identity")
		}
		if loginStateRead(t, ctx, db, s.UserID).Last.Valid {
			t.Fatal("rejected login changed timestamp")
		}
	})
	t.Run("missing_user", func(t *testing.T) {
		s := seed(t, false)
		exec(t, "DELETE FROM users WHERE id=?", s.UserID)
		if err := repo.UpdateLoginState(s); err == nil {
			t.Fatal("missing user accepted")
		}
	})
	// The writer holds an actual users row lock while the production repository
	// UPDATE waits. Observe that exact connection and blocker before committing.
	for _, change := range changes {
		if change.name == "password_case" || change.name == "password_trailing_space" || change.name == "external_id_case" {
			continue
		}
		t.Run("waiting_for_"+change.name, func(t *testing.T) {
			s := seed(t, true)
			work, stop := context.WithTimeout(ctx, 18*time.Second)
			defer stop()
			worker, wdb := loginStateOpen(t, work, cfg)
			defer worker.Close()
			var workerID int64
			loginStateMust(t, wdb.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&workerID))
			tx, err := db.BeginTx(ctx, nil)
			loginStateMust(t, err)
			defer tx.Rollback()
			var blockerID int64
			loginStateMust(t, tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&blockerID))
			_, err = tx.ExecContext(ctx, change.query, s.UserID)
			loginStateMust(t, err)
			done := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				done <- repository.NewUserRepository(worker).(repository.LoginStateRepository).UpdateLoginState(s)
			}()
			defer func() {
				tx.Rollback()
				stop()
				// WithContext cancellation unblocks the production SQL, even if a
				// failed assertion interrupted the normal result path.
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					t.Error("worker did not drain")
				}
			}()
			deadline := time.Now().Add(8 * time.Second)
			for {
				var count int
				loginStateMust(t, adb.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
JOIN performance_schema.threads r ON r.THREAD_ID=w.REQUESTING_THREAD_ID
JOIN performance_schema.threads b ON b.THREAD_ID=w.BLOCKING_THREAD_ID
JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE
WHERE r.PROCESSLIST_ID=? AND b.PROCESSLIST_ID=? AND l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='users'`, workerID, blockerID, database).Scan(&count))
				if count > 0 {
					t.Log("OBSERVED login-state lock wait table=users exact_blocker=yes")
					break
				}
				if time.Now().After(deadline) || work.Err() != nil {
					t.Fatal("required row-lock wait not observed")
				}
				time.Sleep(10 * time.Millisecond)
			}
			loginStateMust(t, tx.Commit())
			before := loginStateRead(t, ctx, db, s.UserID)
			select {
			case err := <-done:
				if err == nil || err.Error() != "login state conflict" {
					t.Fatal("waiting stale login accepted")
				}
			case <-work.Done():
				t.Fatal("login-state worker timeout")
			}
			if loginStateRead(t, ctx, db, s.UserID) != before || before.Last.Valid {
				t.Fatal("waiting login changed current account")
			}
		})
	}
	t.Run("database_failure_is_redacted", func(t *testing.T) {
		s := seed(t, false)
		unavailable, _ := loginStateOpen(t, ctx, cfg)
		defer unavailable.Close()
		assertLoginStateClosedPool(t, unavailable, s)
		if loginStateRead(t, ctx, db, s.UserID).Last.Valid {
			t.Fatal("database failure changed login state")
		}
	})
}
