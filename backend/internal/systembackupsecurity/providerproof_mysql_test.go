//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Runs only on the disposable MySQL server created by the existing D smoke
// harness. It verifies real InnoDB SQL/transactions using migrations 065/066/075
// unchanged, with minimal synthetic config/target/auth/capacity dependencies.
// It is not application HTTP authorization or a real provider attestation test.
func TestDProviderRegistrationMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(uid) || os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("isolated MySQL marker and root secret are required")
	}
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") {
		t.Fatal("isolated IPv4 required")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.MultiStatements = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer admin.Close()
	var gotRun, gotUID, expectedUUID, serverUUID string
	mysqlMust(t, admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &expectedUUID))
	mysqlMust(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&serverUUID))
	if gotRun != run || gotUID != uid || expectedUUID != serverUUID {
		t.Fatal("isolated database marker mismatch")
	}
	ddl, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	hash := sha256.Sum256(ddl)
	if hex.EncodeToString(hash[:]) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || len(ddl) < 1000 || len(ddl) > 131072 {
		t.Fatal("DDL bundle digest/size mismatch")
	}
	var entropy [16]byte
	_, err = rand.Read(entropy[:])
	mysqlMust(t, err)
	database := "dpr_" + hex.EncodeToString(entropy[:])
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+database+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	mysqlMust(t, err)
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		var currentUUID string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&currentUUID) != nil || currentUUID != serverUUID {
			t.Error("CLEANUP_PENDING server identity changed")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+database); e != nil {
			t.Error("CLEANUP_PENDING run-owned database")
			return
		}
		var n int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&n) != nil || n != 0 {
			t.Error("CLEANUP_PENDING database absence not verified")
			return
		}
		t.Log("CLEANED provider-registration run-owned database")
	}()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	db.SetMaxOpenConns(8)
	_, err = db.ExecContext(ctx, registrationMySQLDependencies)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, string(ddl))
	mysqlMust(t, err)
	var now time.Time
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	r, pc, providerKey := providerSignedFixture(t)
	pc.DatabaseNow = now
	pc.Keys[0].NotBefore = now.Add(-time.Hour)
	pc.Keys[0].NotAfter = now.Add(time.Hour)
	r.Proof.IssuedAt = now.Add(-time.Second).Format(time.RFC3339)
	r.Proof.ExpiresAt = now.Add(4 * time.Minute).Format(time.RFC3339)
	providerResign(t, &r, pc, providerKey)
	_, actor, _, proof, synthetic := registrationFixture(t)
	authKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	proof.Payload.AuthTime = now.Add(-time.Second).Format(time.RFC3339)
	proof.Payload.ExpiresAt = now.Add(4 * time.Minute).Format(time.RFC3339)
	body := mysqlRequest(t, r, &proof, authKey)
	a := mysqlRegistrationAuthority{pc: pc, sc: syntheticAuthorityConfig(t, synthetic, actor, authKey)}
	service := ProviderRegistrationService{DB: db, InstallationID: pc.Scope.InstallationID, Authority: a}
	_, err = db.ExecContext(ctx, `INSERT INTO users VALUES(42,'admin',true);
		INSERT INTO system_backup_v2_installation_state VALUES('installation_synthetic',1);
		INSERT INTO system_backup_v2_configs VALUES('installation_synthetic',1,'synthetic-v1',REPEAT('a',64),'auth-v1',REPEAT('b',64),'rbac-v1',REPEAT('c',64),'v1',REPEAT('d',64),300,0,300,86400,2592000,60,1073741824)`)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_external_actions VALUES(?,?,3)", pc.Scope.InstallationID, r.Target.TargetPublicID)
	mysqlMust(t, err)
	var first ProviderRegistrationResult
	t.Run("concurrent_same_request_has_one_atomic_result", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan ProviderRegistrationResult, 6)
		failures := make(chan error, 6)
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, e := service.Register(ctx, actor, body, proof)
				if e != nil {
					failures <- e
				} else {
					results <- v
				}
			}()
		}
		wg.Wait()
		close(results)
		close(failures)
		for e := range failures {
			t.Error(e)
		}
		created := 0
		for v := range results {
			if first.OperationPublicID == "" {
				first = v
			}
			if v.OperationPublicID != first.OperationPublicID || v.EvidencePublicID != first.EvidencePublicID {
				t.Error("duplicate operation/evidence")
			}
			if !v.Replayed {
				created++
			}
		}
		if created != 1 {
			t.Fatalf("created=%d", created)
		}
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	if t.Failed() {
		return
	}
	t.Run("body_conflict", func(t *testing.T) {
		changed := r
		changed.ExpectedRowVersion++
		raw, _ := json.Marshal(changed)
		_, e := service.Register(ctx, actor, raw, proof)
		if e != ErrRegistrationConflict {
			t.Fatal(e)
		}
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	t.Run("nonce_replay_with_new_idempotency_key", func(t *testing.T) {
		changed := r
		changed.IdempotencyKey = "d-mysql-second-request-01"
		p := proof
		raw := mysqlRequest(t, changed, &p, authKey)
		_, e := service.Register(ctx, actor, raw, p)
		var v *VerificationError
		if !errors.As(e, &v) || v.Code != FailureReplayed {
			t.Fatal(e)
		}
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	t.Run("result_audit_failure_rolls_back_every_table", func(t *testing.T) {
		_, e := db.ExecContext(ctx, `CREATE TRIGGER d_reject_result BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='system_backup.provider_proof.succeeded' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'; END IF; END`)
		mysqlMust(t, e)
		defer func() { _, e := db.ExecContext(ctx, "DROP TRIGGER d_reject_result"); mysqlMust(t, e) }()
		changed := r
		changed.IdempotencyKey = "d-mysql-third-request-001"
		p := proof
		p.Payload.Nonce = "nonce_MySQLFreshNonce_123456"
		raw := mysqlRequest(t, changed, &p, authKey)
		_, e = service.Register(ctx, actor, raw, p)
		if e != ErrProviderEvidenceStorage {
			t.Fatal(e)
		}
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	t.Run("permission_revocation_blocks_committed_retry", func(t *testing.T) {
		_, e := db.ExecContext(ctx, "UPDATE users SET is_active=false WHERE id=42")
		mysqlMust(t, e)
		_, e = service.Register(ctx, actor, body, Proof{})
		if e != ErrRegistrationPermission {
			t.Fatal(e)
		}
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	t.Run("https_registration_replay_conflict_and_revocation", func(t *testing.T) {
		_, e := db.ExecContext(ctx, "UPDATE users SET is_active=true WHERE id=42")
		mysqlMust(t, e)
		api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: service}}
		server := httptest.NewTLSServer(api)
		defer server.Close()
		client := server.Client()
		client.Timeout = 10 * time.Second
		call := func(payload []byte, status int) {
			t.Helper()
			request, e := http.NewRequestWithContext(ctx, "POST", server.URL+ProviderRegistrationPath, bytes.NewReader(payload))
			mysqlMust(t, e)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", r.IdempotencyKey)
			response, e := client.Do(request)
			mysqlMust(t, e)
			defer response.Body.Close()
			_, e = io.Copy(io.Discard, io.LimitReader(response.Body, 32768))
			mysqlMust(t, e)
			if response.StatusCode != status {
				t.Fatalf("HTTPS status=%d expected=%d", response.StatusCode, status)
			}
		}
		call(body, http.StatusCreated)
		changed := r
		changed.ExpectedRowVersion++
		changedRaw, _ := json.Marshal(changed)
		call(changedRaw, http.StatusConflict)
		_, e = db.ExecContext(ctx, "UPDATE users SET is_active=false WHERE id=42")
		mysqlMust(t, e)
		call(body, http.StatusForbidden)
		mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
	})
	var rowVersion int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_external_actions").Scan(&rowVersion))
	if rowVersion != 3 {
		t.Fatal("registration mutated target")
	}
	t.Run("totp_persistence_replay_throttle_and_session_revocation", func(t *testing.T) { testTOTPMySQL(t, db, ctx) })
	t.Run("https_jwt_mfa_registration_and_config_revocation", func(t *testing.T) { testRegistrationHTTPMySQL(t, db, ctx) })
	t.Run("first_config_bootstrap_atomicity", func(t *testing.T) { testConfigBootstrapMySQL(t, ctx, admin, cfg, serverUUID, ddl) })
}

func mysqlMust(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		var driverError *mysql.MySQLError
		if errors.As(e, &driverError) {
			t.Fatalf("MySQL probe failed (mysql_error=%d; raw driver diagnostics withheld)", driverError.Number)
		}
		t.Fatal("MySQL probe failed (raw driver diagnostics withheld)")
	}
}
func mysqlRequest(t *testing.T, r ProviderProofRegistration, p *Proof, key ed25519.PrivateKey) []byte {
	t.Helper()
	p.Payload.IdempotencyKey = r.IdempotencyKey
	p.Payload.RequestHash, _ = ProviderProofRequestSHA256(r)
	payload, e := CanonicalPayload(p.Payload)
	mysqlMust(t, e)
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	raw, e := json.Marshal(r)
	mysqlMust(t, e)
	return raw
}
func syntheticAuthorityConfig(t *testing.T, _ *registrationTestState, actor RegistrationActor, key ed25519.PrivateKey) VerifyConfig {
	t.Helper()
	c := testConfig(Ed25519JWSVerifier{})
	c.ExpectedSubject = actor.Subject
	c.ExpectedSession = actor.Session
	c.ActiveNonceHMACKeyVersion = "v1"
	c.NonceHMACKeys = map[string][]byte{"v1": []byte(strings.Repeat("n", 32))}
	c.TrustedSigners["issuer-admin-mfa-v1"] = map[string]SignatureVerifier{"v1": Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "strong-key", KeyVersion: "v1", Purpose: "strong_auth_issuer"}}
	return c
}

type mysqlRegistrationAuthority struct {
	pc ProviderProofRegistrationContext
	sc VerifyConfig
}

func (a mysqlRegistrationAuthority) Authorize(context.Context, *sql.Tx, RegistrationActor, ProviderProofTarget, RegistrationConfig) error {
	return nil
} // Synthetic session/visibility fixture only.
func (a mysqlRegistrationAuthority) Load(_ context.Context, _ *sql.Tx, _ RegistrationActor, _ ProviderProofTarget, _ RegistrationConfig, _ []string, _ time.Time) (ProviderProofRegistrationContext, VerifyConfig, error) {
	return a.pc, a.sc, nil
}
func (a mysqlRegistrationAuthority) ReserveCapacity(ctx context.Context, tx *sql.Tx, c RegistrationConfig, n int) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO d_capacity_reservations(bytes) VALUES(?)", n)
	return e
}
func mysqlRegistrationCounts(t *testing.T, db *sql.DB, want ...int) {
	t.Helper()
	for i, table := range []string{"system_backup_v2_operations", "system_backup_v2_evidence", "system_backup_v2_strong_auth_nonces", "audit_logs", "d_capacity_reservations"} {
		var n int
		mysqlMust(t, db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
		if n != want[i] {
			t.Fatalf("%s count=%d want=%d", table, n, want[i])
		}
	}
}

const registrationMySQLDependencies = `
CREATE TABLE users(id INT PRIMARY KEY,role VARCHAR(16),is_active BOOLEAN) ENGINE=InnoDB;
CREATE TABLE audit_logs(id INT AUTO_INCREMENT PRIMARY KEY,user_id INT,action VARCHAR(100),resource_type VARCHAR(50),details JSON,FOREIGN KEY(user_id) REFERENCES users(id)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,active_config_version BIGINT UNSIGNED) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin,version BIGINT UNSIGNED,
provider_proof_issuers_registry_version VARCHAR(128),provider_proof_issuers_registry_sha256 CHAR(64),strong_auth_issuers_registry_version VARCHAR(128),strong_auth_issuers_registry_sha256 CHAR(64),rbac_bindings_registry_version VARCHAR(128),rbac_bindings_registry_sha256 CHAR(64),nonce_hmac_ref_version VARCHAR(128),nonce_hmac_identity_hash CHAR(64),strong_auth_max_age_seconds INT,strong_auth_clock_skew_seconds INT,provider_proof_max_age_seconds INT,evidence_retention_seconds INT,control_metadata_retention_seconds INT,operation_deadline_seconds INT,control_metadata_capacity_bytes BIGINT,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_external_actions(origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin,public_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin,row_version BIGINT,PRIMARY KEY(origin_installation_id,public_id)) ENGINE=InnoDB;
CREATE TABLE d_capacity_reservations(id BIGINT AUTO_INCREMENT PRIMARY KEY,bytes BIGINT) ENGINE=InnoDB;
`
