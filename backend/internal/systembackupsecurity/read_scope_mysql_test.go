//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
	"github.com/golang-jwt/jwt/v5"
)

func TestAAdminReadMySQLSeed(t *testing.T) {
	raw, err := os.ReadFile("../../../scripts/system-backup-a-admin-read-probe.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"users", "system_backup_v2_installation_state", "system_backup_v2_configs", "system_backup_v2_admin_sessions", "system_backup_v2_backups"} {
		if !strings.Contains(string(raw), "CREATE TABLE "+table+" (") {
			t.Fatal("missing probe table", table)
		}
	}
	if strings.Contains(strings.ToUpper(string(raw)), "DROP DATABASE") || len(raw) < 1000 || len(raw) > 65536 {
		t.Fatal("unsafe probe DDL")
	}
}

// The disposable schema is intentionally narrow: this probe verifies A's
// InnoDB authorization/session locks and D's ScopeProvider call sequence.
// D's full task rows, query plans and production schema require their own gate.
func TestAAdminReadAuthorityMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
		t.Fatal("isolated MySQL identity mismatch")
	}
	ddl, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	digest := sha256.Sum256(ddl)
	if hex.EncodeToString(digest[:]) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || len(ddl) < 1000 || len(ddl) > 65536 {
		t.Fatal("probe DDL digest mismatch")
	}
	var entropy [16]byte
	_, err = rand.Read(entropy[:])
	mysqlMust(t, err)
	database := "aar_" + hex.EncodeToString(entropy[:])
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+database+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	mysqlMust(t, err)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var current string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&current) != nil || current != pinnedUUID {
			t.Error("CLEANUP_PENDING admin-read server identity")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+database); e != nil {
			t.Error("CLEANUP_PENDING admin-read database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING admin-read database absence")
			return
		}
		t.Log("CLEANED admin-read run-owned database")
	}()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	db.SetMaxOpenConns(6)
	_, err = db.ExecContext(ctx, string(ddl))
	mysqlMust(t, err)
	const installation = "installation_a_admin_read"
	const passwordHash = "synthetic-admin-read-password-hash"
	secret := []byte(strings.Repeat("s", 32))
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 42, "token_type": "access", "jti": "a-admin-read-probe", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}).SignedString(secret)
	mysqlMust(t, err)
	rbac := []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"read-v1","installation_id":"installation_a_admin_read","bindings":[{"actor_id":"42","subject":"user:42","role":"viewer"}]}`)
	rbacHash := registrationHash(string(rbac))
	root := t.TempDir()
	registryPath := filepath.Join(root, "rbac_bindings", "read-v1", rbacHash+".json")
	mysqlMust(t, os.MkdirAll(filepath.Dir(registryPath), 0700))
	mysqlMust(t, os.WriteFile(registryPath, rbac, 0600))
	pins := SystemBackupReadPins{InstallationID: installation, ConfigVersion: 1, RBACVersion: "read-v1", RBACSHA256: rbacHash, RegistryDirectory: root}
	pinsRaw, err := json.Marshal(pins)
	mysqlMust(t, err)
	pinsPath := filepath.Join(root, "read-pins.json")
	mysqlMust(t, os.WriteFile(pinsPath, pinsRaw, 0600))
	_, err = db.ExecContext(ctx, "INSERT INTO users VALUES(42,?,'admin',TRUE)", passwordHash)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_configs VALUES(?,1,'provider-v1',REPEAT('a',64),'strong-v1',REPEAT('b',64),'read-v1',?,'nonce-v1',REPEAT('d',64),300,0,300,86400,2592000,60,1073741824)`, installation, rbacHash)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_installation_state VALUES(?,1)", installation)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_admin_sessions VALUES(?,?,?,?,?,UTC_TIMESTAMP(6) + INTERVAL 5 MINUTE,FALSE)", installation, registrationHash(token), 42, "user:42", registrationHash(passwordHash))
	mysqlMust(t, err)
	identity := DatabaseIdentity{ServerUUID: actualUUID, Database: database}
	sessions, err := NewSQLLoginSessions(db, identity, installation, secret)
	mysqlMust(t, err)
	authorizer, err := LoadSystemBackupReadAuthorizer(sessions, pinsPath, registrationHash(string(pinsRaw)))
	mysqlMust(t, err)
	newScope := func() *SystemBackupReadScope {
		request := httptest.NewRequest("GET", "/api/v1/admin/system-backups", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		scope, e := authorizer.Scope(request)
		mysqlMust(t, e)
		return scope
	}
	scope := newScope()
	reader, err := systembackupread.NewReader(db, scope)
	mysqlMust(t, err)
	page, err := reader.ListTasks(scope.Context(), systembackupread.PageRequest{Kind: systembackupread.BackupTask, Limit: 10})
	mysqlMust(t, err)
	if page.InstallationID != installation || len(page.Items) != 0 {
		t.Fatal("A scope did not bind D reader to installation")
	}
	tx, err := db.BeginTx(scope.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	mysqlMust(t, err)
	defer tx.Rollback()
	got, err := scope.AuthorizeRead(scope.Context(), tx)
	mysqlMust(t, err)
	if got != installation {
		t.Fatal("authorized installation mismatch")
	}
	updateCtx, stopUpdate := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopUpdate()
	updated := make(chan error, 1)
	go func() {
		_, e := db.ExecContext(updateCtx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", installation, registrationHash(token))
		updated <- e
	}()
	select {
	case e := <-updated:
		t.Fatal("revocation bypassed held session row lock", e)
	case <-time.After(200 * time.Millisecond):
	}
	mysqlMust(t, scope.RecheckRead(scope.Context(), tx, installation))
	mysqlMust(t, tx.Commit())
	select {
	case e := <-updated:
		mysqlMust(t, e)
	case <-updateCtx.Done():
		t.Fatal("revocation did not complete after read commit")
	}
	denied := newScope()
	tx, err = db.BeginTx(denied.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	mysqlMust(t, err)
	if _, err = denied.AuthorizeRead(denied.Context(), tx); err != ErrRegistrationPermission {
		t.Fatal("revoked session retained read access", err)
	}
	_ = tx.Rollback()
}
