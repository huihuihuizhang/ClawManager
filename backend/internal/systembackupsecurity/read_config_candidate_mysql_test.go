//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
	"github.com/golang-jwt/jwt/v5"
)

// Candidate-only probe: the DDL is applied only inside the UID-pinned,
// disposable full-migration namespace, never to an installed database.
func TestDConfigCanonicalCandidateMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("config candidate probe is outside the pinned run-owned MySQL")
	}
	for _, name := range []string{"097_backup_v2_add_system_backup_config_and_operations.sql", "109_backup_v2_add_system_backup_registration_runtime.sql"} {
		var count int
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE filename=?", name).Scan(&count))
		if count != 1 {
			t.Fatal("migration missing", name)
		}
	}
	ddl, err := os.ReadFile(os.Getenv("D_CONFIG_CANDIDATE_DDL"))
	mysqlMust(t, err)
	digest := sha256.Sum256(ddl)
	if hex.EncodeToString(digest[:]) != os.Getenv("D_CONFIG_CANDIDATE_DDL_SHA256") ||
		!strings.Contains(string(ddl), "ADD COLUMN canonical_config_json MEDIUMBLOB NULL") ||
		strings.Contains(strings.ToUpper(string(ddl)), "DROP DATABASE") {
		t.Fatal("candidate DDL is not pinned")
	}
	_, err = db.ExecContext(ctx, string(ddl))
	mysqlMust(t, err)
	const installation = "installation_d_config_candidate"
	var userID int64
	var passwordHash string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT id,password_hash FROM users WHERE role='admin' AND is_active=TRUE ORDER BY id LIMIT 1").Scan(&userID, &passwordHash))
	rbac := []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"read-v1","installation_id":"` + installation + `","bindings":[{"actor_id":"` + strconv.FormatInt(userID, 10) + `","subject":"user:` + strconv.FormatInt(userID, 10) + `","role":"viewer"}]}`)
	rbacHash := registrationHash(string(rbac))
	var source map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(bootstrapFixture(t), &source))
	var registries []BootstrapRegistryRef
	mysqlMust(t, json.Unmarshal(source["registries"], &registries))
	for i := range registries {
		if registries[i].Kind == "rbac_bindings" {
			registries[i].Version, registries[i].SHA256 = "read-v1", rbacHash
		}
	}
	source["registries"], err = json.Marshal(registries)
	mysqlMust(t, err)
	raw, err := json.Marshal(source)
	mysqlMust(t, err)
	config, err := DecodeBootstrapConfig(raw)
	mysqlMust(t, err)
	actor := strconv.FormatInt(userID, 10)
	insert := func(tx *sql.Tx, columns []string, args []any) {
		t.Helper()
		marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
		_, e := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_configs ("+strings.Join(columns, ",")+") VALUES ("+marks+")", args...)
		mysqlMust(t, e)
	}
	tx, err := db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	columns, args := config.sqlValues(installation, actor, "isolated candidate")
	insert(tx, columns, args)
	_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
		(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key)
		VALUES (?,1,FALSE,UTC_TIMESTAMP(6),'k8s-cluster')`, installation)
	mysqlMust(t, err)
	mysqlMust(t, tx.Commit())

	secret := []byte(strings.Repeat("s", 32))
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID, "token_type": "access", "jti": "d-config-candidate",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}).SignedString(secret)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_admin_sessions
		(origin_installation_id,session_sha256,user_id,subject,credential_hash,expires_at,revoked)
		VALUES(?,?,?,?,?,UTC_TIMESTAMP(6)+INTERVAL 5 MINUTE,FALSE)`,
		installation, registrationHash(token), userID, "user:"+actor, registrationHash(passwordHash))
	mysqlMust(t, err)
	root := t.TempDir()
	registryPath := filepath.Join(root, "rbac_bindings", "read-v1", rbacHash+".json")
	mysqlMust(t, os.MkdirAll(filepath.Dir(registryPath), 0700))
	mysqlMust(t, os.WriteFile(registryPath, rbac, 0600))
	sessions, err := NewSQLLoginSessions(db, DatabaseIdentity{ServerUUID: actualUUID, Database: cfg.DBName}, installation, secret)
	mysqlMust(t, err)
	newService := func(version int64) (*systembackupread.Service, context.Context) {
		t.Helper()
		pins, e := json.Marshal(SystemBackupReadPins{InstallationID: installation, ConfigVersion: version,
			RBACVersion: "read-v1", RBACSHA256: rbacHash, RegistryDirectory: root})
		mysqlMust(t, e)
		path := filepath.Join(root, "read-pins-"+strconv.FormatInt(version, 10)+".json")
		mysqlMust(t, os.WriteFile(path, pins, 0600))
		authorizer, e := LoadSystemBackupReadAuthorizer(sessions, path, registrationHash(string(pins)))
		mysqlMust(t, e)
		request := httptest.NewRequest("GET", "/api/v1/admin/system-backup-config", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		scope, e := authorizer.Scope(request)
		mysqlMust(t, e)
		service, e := systembackupread.NewService(db, scope, []byte(strings.Repeat("c", 32)))
		mysqlMust(t, e)
		return service, scope.Context()
	}
	service1, readContext1 := newService(1)
	if _, err := service1.ReadActiveConfigDTO(readContext1); !errors.Is(err, systembackupread.ErrUnavailable) {
		t.Fatalf("old row without canonical bytes was readable: %v", err)
	}
	columns, args = config.sqlValuesWithCanonical(installation, actor, "isolated candidate")
	args[1] = int64(2)
	tx, err = db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	insert(tx, columns, args)
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=2 WHERE origin_installation_id=?", installation)
	mysqlMust(t, err)
	mysqlMust(t, tx.Commit())
	if _, err := service1.ReadActiveConfigDTO(readContext1); !errors.Is(err, ErrRegistrationUnavailable) {
		t.Fatalf("stale deployment pin survived version rotation: %v", err)
	}
	service2, readContext2 := newService(2)
	resource, err := service2.ReadActiveConfigDTO(readContext2)
	mysqlMust(t, err)
	if resource.Version != 2 || resource.OriginInstallationID != installation || !resource.Active || resource.EffectiveEnabled {
		t.Fatalf("candidate canonical row not projected: %+v", resource)
	}
	if _, err := service2.ReadConfigVersionDTO(readContext2, 1); !errors.Is(err, systembackupread.ErrUnavailable) {
		t.Fatalf("old row became readable: %v", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET config_sha256=REPEAT('f',64) WHERE origin_installation_id=? AND version=2", installation)
	mysqlMust(t, err)
	if _, err := service2.ReadActiveConfigDTO(readContext2); !errors.Is(err, systembackupread.ErrUnavailable) {
		t.Fatalf("hash drift was readable: %v", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET config_sha256=? WHERE origin_installation_id=? AND version=2", config.SHA256(), installation)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET alert_profile='production' WHERE origin_installation_id=? AND version=2", installation)
	mysqlMust(t, err)
	if _, err := service2.ReadActiveConfigDTO(readContext2); !errors.Is(err, systembackupread.ErrUnavailable) {
		t.Fatalf("materialized drift was readable: %v", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET alert_profile='development' WHERE origin_installation_id=? AND version=2", installation)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", installation, registrationHash(token))
	mysqlMust(t, err)
	if _, err := service2.ReadActiveConfigDTO(readContext2); !errors.Is(err, ErrRegistrationPermission) {
		t.Fatalf("revoked session retained config read: %v", err)
	}
	t.Run("bootstrap_canonical_commit_and_receipt_rollback", func(t *testing.T) {
		testDConfigBootstrapCandidateMySQL(t, ctx, db, cfg.DBName, actualUUID, userID, config, raw)
	})
	t.Log("PASS candidate canonical DDL, old-row fail closed, pin rotation, hash/materialized drift, A read revocation, bootstrap atomicity")
}

// Synthetic admission isolates the database transaction under test. It never
// represents the offline operator grant or production owner resolution.
type dConfigBootstrapCandidateAdmission struct{}

func (dConfigBootstrapCandidateAdmission) Authorize(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error {
	return nil
}
func (dConfigBootstrapCandidateAdmission) ValidateAndReserve(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error {
	return nil
}

func testDConfigBootstrapCandidateMySQL(t *testing.T, ctx context.Context, db *sql.DB, database, serverUUID string, userID int64, config BootstrapConfig, raw []byte) {
	t.Helper()
	var username string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT username FROM users WHERE id=?", userID).Scan(&username))
	grant := OfflineBootstrapGrant{
		InstallationID: "installation_d_config_bootstrap_candidate", ServerUUID: serverUUID, Database: database,
		Username: username, UserID: userID, MatrixKey: "k8s-cluster", ConfigSHA256: config.SHA256(),
		IdempotencyKey: "d-config-bootstrap-candidate-001", ChangeReason: "isolated candidate transaction",
	}
	service := ConfigBootstrapService{DB: db, Admission: dConfigBootstrapCandidateAdmission{}, CanonicalSnapshot: true}
	result, err := service.Bootstrap(ctx, grant, raw)
	mysqlMust(t, err)
	if result.Version != 1 || result.Replayed || result.ConfigSHA256 != config.SHA256() {
		t.Fatalf("candidate bootstrap result: %+v", result)
	}
	var stored []byte
	var hash string
	var size int64
	mysqlMust(t, db.QueryRowContext(ctx, `SELECT canonical_config_json,config_sha256,config_size_bytes
		FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1`, grant.InstallationID).Scan(&stored, &hash, &size))
	if !bytes.Equal(stored, config.CanonicalJSON()) || hash != config.SHA256() || size != int64(len(stored)) {
		t.Fatal("candidate bootstrap committed a mismatched canonical snapshot")
	}
	verifyCount := func(installation string, want int) {
		t.Helper()
		for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations"} {
			var count int
			mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE origin_installation_id=?", installation).Scan(&count))
			if count != want {
				t.Fatalf("%s rows=%d want=%d", table, count, want)
			}
		}
		var audits int
		mysqlMust(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs
			WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'$.installation_id'))=?`, installation).Scan(&audits))
		if audits != want*2 {
			t.Fatalf("audit rows=%d want=%d", audits, want*2)
		}
	}
	verifyCount(grant.InstallationID, 1)
	rollbackGrant := grant
	rollbackGrant.InstallationID = "installation_d_config_bootstrap_rollback"
	rollbackGrant.IdempotencyKey = "d-config-bootstrap-rollback-001"
	const trigger = "d_config_bootstrap_candidate_reject"
	_, err = db.ExecContext(ctx, `CREATE TRIGGER `+trigger+` BEFORE INSERT ON system_backup_v2_operations FOR EACH ROW
		BEGIN IF NEW.origin_installation_id='installation_d_config_bootstrap_rollback'
		THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='candidate receipt rejection'; END IF; END`)
	mysqlMust(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, e := db.ExecContext(cleanup, "DROP TRIGGER "+trigger); e != nil {
			t.Error("CLEANUP_PENDING candidate bootstrap trigger", e)
		}
	}()
	if result, err = service.Bootstrap(ctx, rollbackGrant, raw); err != ErrProviderEvidenceStorage || result.OperationPublicID != "" {
		t.Fatalf("candidate receipt failure did not fail closed: result=%+v err=%v", result, err)
	}
	verifyCount(rollbackGrant.InstallationID, 0)
	t.Log("PASS canonical bootstrap real MySQL commit, exact bytes and receipt-failure rollback; synthetic admission")
}
