//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Real SQL/JWT/password/TOTP/HTTPS and Ed25519; issuer/registry/key material is
// synthetic. This suite never executes ConfigMutationService or a backfill.
type configProofMySQLSigner struct {
	key    ed25519.PrivateKey
	fail   bool
	before func(context.Context) error
}

func (s *configProofMySQLSigner) Sign(ctx context.Context, raw []byte) ([]byte, error) {
	if s.before != nil {
		if err := s.before(ctx); err != nil {
			return nil, err
		}
	}
	if s.fail {
		return nil, errors.New("synthetic signer unavailable")
	}
	return ed25519.Sign(s.key, raw), nil
}

type configProofMySQLFixture struct {
	db                                      *sql.DB
	ctx                                     context.Context
	cfg                                     *mysql.Config
	identity                                DatabaseIdentity
	installation, username, password, token string
	userID                                  int64
	actor                                   RegistrationActor
	svc                                     SQLTOTPService
	jwtSecret, seed                         []byte
	signer                                  *configProofMySQLSigner
	current                                 RegistrationConfig
	revokedRBAC                             []byte
}

func configProofDBNow(t *testing.T, ctx context.Context, db *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	return now
}

func newConfigProofMySQLFixture(t *testing.T, ctx context.Context, db *sql.DB, cfg *mysql.Config, identity DatabaseIdentity) *configProofMySQLFixture {
	t.Helper()
	var entropy [12]byte
	_, err := rand.Read(entropy[:])
	mysqlMust(t, err)
	name := hex.EncodeToString(entropy[:])
	f := &configProofMySQLFixture{db: db, ctx: ctx, cfg: cfg, identity: identity, installation: "installation_config_proof_" + name, username: "config-proof-" + name, password: "synthetic-config-proof-password", jwtSecret: bytes.Repeat([]byte{7}, 32), seed: bytes.Repeat([]byte{9}, 20)}
	hash, err := bcrypt.GenerateFromPassword([]byte(f.password), bcrypt.MinCost)
	mysqlMust(t, err)
	result, err := db.ExecContext(ctx, "INSERT INTO users(username,email,password_hash,role,is_active) VALUES(?,?,?,'admin',TRUE)", f.username, f.username+"@example.invalid", string(hash))
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-user-insert")
	}
	mysqlMust(t, err)
	f.userID, err = result.LastInsertId()
	mysqlMust(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var server string
		if db.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&server) != nil || server != identity.ServerUUID {
			t.Error("CLEANUP_PENDING config-proof server identity")
			return
		}
		for _, table := range []string{"system_backup_v2_installation_state", "system_backup_v2_configs", "system_backup_v2_totp_credentials", "system_backup_v2_admin_sessions", "system_backup_v2_admin_revocations"} {
			if _, e := db.ExecContext(cleanup, "DELETE FROM "+table+" WHERE origin_installation_id=?", f.installation); e != nil {
				t.Error("CLEANUP_PENDING config-proof owned installation rows")
				return
			}
		}
		if _, e := db.ExecContext(cleanup, "DELETE FROM audit_logs WHERE user_id=?", f.userID); e != nil {
			t.Error("CLEANUP_PENDING config-proof audit rows")
			return
		}
		if _, e := db.ExecContext(cleanup, "DELETE FROM users WHERE id=? AND username=?", f.userID, f.username); e != nil {
			t.Error("CLEANUP_PENDING config-proof user")
			return
		}
		var count int
		if db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM users WHERE id=?", f.userID).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING config-proof user absence")
			return
		}
		wipeSecret(f.seed)
		wipeSecret(f.jwtSecret)
		t.Log("CLEANED config-proof owned installation/user/credentials/sessions/revocations/audit")
	})
	now := configProofDBNow(t, ctx, db)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	mysqlMust(t, err)
	f.signer = &configProofMySQLSigner{key: key}
	sk := StrongAuthRegistryKey{Issuer: "synthetic-config-proof", KeyID: "config-proof-key", KeyVersion: "v1", Purpose: "strong_auth_issuer", PublicKey: public, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Policy: IssuerPolicy{Methods: []string{"totp"}, AMR: []string{"otp"}}}
	strong, err := json.Marshal(StrongAuthIssuerRegistry{SchemaVersion: "system-backup-strong-auth-issuers.draft.v1", Version: "proof-strong-v1", Audience: "config-proof-mysql", Keys: []StrongAuthRegistryKey{sk}})
	mysqlMust(t, err)
	rbac, err := json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": "proof-rbac-v1", "installation_id": f.installation, "bindings": []map[string]string{{"actor_id": strconv.FormatInt(f.userID, 10), "subject": "user:" + strconv.FormatInt(f.userID, 10), "role": "security_admin"}}})
	mysqlMust(t, err)
	f.revokedRBAC = bytes.ReplaceAll(bytes.ReplaceAll(rbac, []byte("proof-rbac-v1"), []byte("proof-rbac-v2")), []byte("security_admin"), []byte("viewer"))
	var document map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(bootstrapFixture(t), &document))
	var registries []BootstrapRegistryRef
	mysqlMust(t, json.Unmarshal(document["registries"], &registries))
	for n := range registries {
		switch registries[n].Kind {
		case "rbac_bindings":
			registries[n].Version = "proof-rbac-v1"
			registries[n].SHA256 = registrationHash(string(rbac))
		case "strong_auth_issuers":
			registries[n].Version = "proof-strong-v1"
			registries[n].SHA256 = registrationHash(string(strong))
		}
	}
	document["registries"], err = json.Marshal(registries)
	mysqlMust(t, err)
	configRaw, err := json.Marshal(document)
	mysqlMust(t, err)
	config, err := DecodeBootstrapConfig(configRaw)
	mysqlMust(t, err)
	columns, args := config.sqlValues(f.installation, strconv.FormatInt(f.userID, 10), "synthetic config proof fixture")
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-config-insert")
	}
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, configProofInstallationStateInsert, f.installation, now)
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-installation-state-insert")
	}
	mysqlMust(t, err)
	tx, err := db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	f.current, err = lockRegistrationConfig(ctx, tx, f.installation)
	_ = tx.Rollback()
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-active-config-lock")
	}
	mysqlMust(t, err)
	registriesByKey := map[string][]byte{"rbac_bindings/proof-rbac-v1": rbac, "rbac_bindings/proof-rbac-v2": f.revokedRBAC, "strong_auth_issuers/proof-strong-v1": strong}
	authority := configuredAuthority{database: identity, expected: f.current, PinnedRegistrationAuthority: PinnedRegistrationAuthority{InstallationID: f.installation, RegistryBytes: func(kind, version, digest string) ([]byte, error) {
		raw := registriesByKey[kind+"/"+version]
		if registrationHash(string(raw)) != digest {
			return nil, ErrRegistrationUnavailable
		}
		return append([]byte(nil), raw...), nil
	}}}
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{8}, 32))
	mysqlMust(t, err)
	f.svc = SQLTOTPService{DB: db, DatabaseIdentity: &f.identity, InstallationID: f.installation, Box: box, Authorize: authority.AuthorizeMFA, Issuer: StrongAuthProofIssuer{Key: sk, Audience: "config-proof-mysql", Signer: f.signer, Lifetime: time.Minute}}
	f.login(t, time.Hour, string(hash))
	encrypted, err := box.seal(f.seed, f.svc.identity(f.actor))
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_totp_credentials(origin_installation_id,user_id,encrypted_seed,credential_hash,confirmed,last_step) VALUES(?,?,?,?,TRUE,-1)", f.installation, f.userID, encrypted, registrationHash(string(hash)))
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-totp-insert")
	}
	mysqlMust(t, err)
	return f
}

func (f *configProofMySQLFixture) login(t *testing.T, lifetime time.Duration, passwordHash string) {
	t.Helper()
	now := configProofDBNow(t, f.ctx, f.db)
	pair := LoginSessionPair{UserID: f.userID, CredentialSHA256: registrationHash(passwordHash)}
	for _, kind := range []string{"access", "refresh"} {
		expiry := now.Add(lifetime)
		if kind == "refresh" {
			expiry = now.Add(2 * time.Hour)
		}
		var nonce [16]byte
		_, err := rand.Read(nonce[:])
		mysqlMust(t, err)
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": f.userID, "token_type": kind, "jti": hex.EncodeToString(nonce[:]), "iat": now.Add(-time.Second).Unix(), "exp": expiry.Unix()}).SignedString(f.jwtSecret)
		mysqlMust(t, err)
		if kind == "access" {
			pair.AccessToken = token
		} else {
			pair.RefreshToken = token
		}
	}
	sessions, err := NewSQLLoginSessions(f.db, f.identity, f.installation, f.jwtSecret)
	mysqlMust(t, err)
	err = sessions.RecordPair(f.ctx, pair)
	if err != nil {
		t.Log("MYSQL_PROBE_STAGE synthetic-login-session-record")
	}
	mysqlMust(t, err)
	f.token = pair.AccessToken
	r := httptest.NewRequest("POST", "https://probe.invalid", nil)
	r.Header.Set("Authorization", "Bearer "+f.token)
	f.actor, err = (JWTRegistrationAuthenticator{Secret: f.jwtSecret}).Authenticate(r)
	mysqlMust(t, err)
}
func (f *configProofMySQLFixture) request(t *testing.T, endpoint string) ConfigMutationRequest {
	t.Helper()
	raw := []byte(`{"expected_version":1,"change_reason":"synthetic rollback","rollback_from_version":1}`)
	if endpoint == ConfigUpdateEndpoint {
		var err error
		raw, err = json.Marshal(map[string]any{"expected_version": 1, "change_reason": "synthetic update", "config": json.RawMessage(bootstrapFixture(t))})
		mysqlMust(t, err)
	}
	request, err := DecodeConfigMutationRequest(endpoint, raw)
	mysqlMust(t, err)
	return request
}
func (f *configProofMySQLFixture) code(t *testing.T) string {
	return totpCode(f.seed, configProofDBNow(t, f.ctx, f.db).Unix()/30, 6)
}
func (f *configProofMySQLFixture) issue(t *testing.T, svc SQLTOTPService) (Proof, error) {
	return svc.VerifyConfigMutationAndIssue(f.ctx, f.actor, f.password, f.code(t), f.request(t, ConfigUpdateEndpoint), "config_proof_mysql_key_012345")
}
func (f *configProofMySQLFixture) state(t *testing.T) (int64, int) {
	t.Helper()
	var step int64
	var count int
	mysqlMust(t, f.db.QueryRowContext(f.ctx, "SELECT last_step FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=?", f.installation, f.userID).Scan(&step))
	mysqlMust(t, f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='system_backup.strong_auth.verified'", f.userID).Scan(&count))
	return step, count
}

func (f *configProofMySQLFixture) start(t *testing.T, code string, request ConfigMutationRequest) sessionProbeWorker {
	t.Helper()
	db, err := sql.Open("mysql", f.cfg.FormatDSN())
	mysqlMust(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var id int64
	mysqlMust(t, db.QueryRowContext(f.ctx, "SELECT CONNECTION_ID()").Scan(&id))
	work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	result, done := make(chan error, 1), make(chan struct{})
	svc := f.svc
	svc.DB = db
	go func() {
		defer close(done)
		proof, err := svc.VerifyConfigMutationAndIssue(work, f.actor, f.password, code, request, "config_proof_mysql_key_012345")
		if err != nil && proof.SchemaVersion != "" {
			err = errors.New("failed worker returned proof")
		}
		result <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("config proof worker did not drain")
		}
		db.Close()
	})
	return sessionProbeWorker{id: id, result: result}
}

func (f *configProofMySQLFixture) http(t *testing.T, endpoint string) Proof {
	t.Helper()
	api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc}
	server := httptest.NewTLSServer(api)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second
	request := f.request(t, endpoint)
	body, err := json.Marshal(map[string]any{"password": f.password, "code": f.code(t), "endpoint": endpoint, "idempotency_key": "config_proof_mysql_key_012345", "request": json.RawMessage(request.CanonicalJSON())})
	mysqlMust(t, err)
	r, err := http.NewRequestWithContext(f.ctx, "POST", server.URL+strongAuthBase+"/proof", bytes.NewReader(body))
	mysqlMust(t, err)
	r.Header.Set("Authorization", "Bearer "+f.token)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	mysqlMust(t, err)
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	mysqlMust(t, err)
	if response.StatusCode != 200 || len(raw) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("config proof HTTPS rejected; response withheld")
	}
	var transport struct {
		HeaderName  string `json:"header_name"`
		HeaderValue string `json:"header_value"`
	}
	mysqlMust(t, json.Unmarshal(raw, &transport))
	if transport.HeaderName != StrongAuthProofHeader {
		t.Fatal("wrong proof header")
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(transport.HeaderValue)
	mysqlMust(t, err)
	var proof Proof
	mysqlMust(t, json.Unmarshal(encoded, &proof))
	digest, err := request.RequestHash(f.installation, "admin", strconv.FormatInt(f.userID, 10))
	mysqlMust(t, err)
	key := f.svc.Issuer.Key
	_, err = Verify(proof, RequestBinding{Issuer: key.Issuer, Audience: f.svc.Issuer.Audience, Subject: f.actor.Subject, Session: f.actor.Session, Endpoint: endpoint, RequestHash: digest, IdempotencyKey: "config_proof_mysql_key_012345"}, VerifyConfig{Now: configProofDBNow(t, f.ctx, f.db), MaxAge: 5 * time.Minute, ClockSkew: time.Second, ExpectedAudience: f.svc.Issuer.Audience, ExpectedSubject: f.actor.Subject, ExpectedSession: f.actor.Session, TrustedSigners: map[string]map[string]SignatureVerifier{key.Issuer: {key.KeyVersion: Ed25519JWSVerifier{PublicKey: key.PublicKey, KeyID: key.KeyID, KeyVersion: key.KeyVersion, Purpose: key.Purpose}}}, TrustedIssuerPolicies: map[string]IssuerPolicy{key.Issuer: key.Policy}, NonceHMACKeys: map[string][]byte{"v1": bytes.Repeat([]byte{4}, 32)}, ActiveNonceHMACKeyVersion: "v1", RequiredNonceHMACKeyVersions: []string{"v1"}})
	mysqlMust(t, err)
	var details string
	mysqlMust(t, f.db.QueryRowContext(f.ctx, "SELECT details FROM audit_logs WHERE user_id=? AND action='system_backup.strong_auth.verified' ORDER BY id DESC LIMIT 1", f.userID).Scan(&details))
	if strings.Contains(details, f.token) || strings.Contains(details, f.password) || strings.Contains(details, proof.Payload.Nonce) {
		t.Fatal("raw credential/proof leaked into audit")
	}
	return proof
}

type configProofLostCommitConnector struct {
	base driver.Connector
	lost atomic.Bool
}

func (c *configProofLostCommitConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *configProofLostCommitConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &configProofLostCommitConn{Conn: conn, owner: c}, nil
}

type configProofLostCommitConn struct {
	driver.Conn
	owner *configProofLostCommitConnector
}

func (c *configProofLostCommitConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return configProofLostCommitTx{tx, c.owner}, nil
}
func (c *configProofLostCommitConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *configProofLostCommitConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

type configProofLostCommitTx struct {
	driver.Tx
	owner *configProofLostCommitConnector
}

func (t configProofLostCommitTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if t.owner.lost.CompareAndSwap(false, true) {
		return errors.New("synthetic lost COMMIT reply after real commit")
	}
	return nil
}

func TestAConfigProofMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	db.SetMaxOpenConns(12)
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("config proof probe is outside the run-owned database")
	}
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	inputs, err := decodeConfigProofProbeInputs(raw, os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256"))
	mysqlMust(t, err)
	rows, err := db.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	mysqlMust(t, err)
	var actualFiles []string
	for rows.Next() {
		var name string
		mysqlMust(t, rows.Scan(&name))
		actualFiles = append(actualFiles, name)
	}
	mysqlMust(t, rows.Err())
	mysqlMust(t, rows.Close())
	if !reflect.DeepEqual(actualFiles, inputs.Filenames) {
		t.Fatal("full fresh migration ledger differs from pinned capsule")
	}
	for _, table := range []string{"users", "audit_logs", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_totp_credentials", "system_backup_v2_admin_sessions", "system_backup_v2_admin_revocations"} {
		var engine string
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&engine))
		if engine != "InnoDB" {
			t.Fatal("real InnoDB tables required")
		}
	}
	identity := DatabaseIdentity{ServerUUID: actualUUID, Database: cfg.DBName}
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		if !t.Run("https_"+endpoint, func(t *testing.T) {
			f := newConfigProofMySQLFixture(t, ctx, db, cfg, identity)
			f.http(t, endpoint)
			step, count := f.state(t)
			if step < 0 || count != 1 {
				t.Fatal("HTTPS proof not committed atomically")
			}
		}) {
			return
		}
	}
	for _, name := range []string{"same_totp_concurrent_once", "missing_session", "revoked_session", "shortened_session", "revoked_at_issue", "inactive_user", "password_changed", "unconfirmed_totp", "signer_failure", "audit_failure_rollback", "commit_reply_lost", "observed_config_lock_revocation", "session_expires_in_signer"} {
		if !t.Run(name, func(t *testing.T) {
			f := newConfigProofMySQLFixture(t, ctx, db, cfg, identity)
			expiredInSigner := false
			exec := func(q string, args ...any) { _, e := db.ExecContext(ctx, q, args...); mysqlMust(t, e) }
			switch name {
			case "same_totp_concurrent_once":
				code := f.code(t)
				request := f.request(t, ConfigUpdateEndpoint)
				entered, release := make(chan struct{}, 1), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				f.signer.before = func(call context.Context) error {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-release:
						return nil
					case <-call.Done():
						return call.Err()
					}
				}
				first := f.start(t, code, request)
				select {
				case <-entered:
				case <-first.result:
					t.Fatal("first issuance ended before signer")
				case <-time.After(8 * time.Second):
					t.Fatal("first signer did not start in time")
				case <-ctx.Done():
					t.Fatal("first signer did not start")
				}
				second := f.start(t, code, request)
				(sessionMySQLProbe{db: db, identity: identity}).waiting(t, ctx, second, "system_backup_v2_installation_state")
				unblock()
				successes := 0
				for _, worker := range []sessionProbeWorker{first, second} {
					e := sessionWorkerResult(t, ctx, worker)
					if e == nil {
						successes++
					} else if e != ErrTOTPRejected {
						t.Fatal("unexpected concurrent rejection")
					}
				}
				step, count := f.state(t)
				if successes != 1 || step < 0 || count != 1 {
					t.Fatal("TOTP did not have one real atomic issuance")
				}
				return
			case "missing_session":
				exec("DELETE FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND session_sha256=?", f.installation, f.actor.Session)
			case "revoked_session":
				exec("UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", f.installation, f.actor.Session)
			case "shortened_session":
				exec("UPDATE system_backup_v2_admin_sessions SET expires_at=? WHERE origin_installation_id=? AND session_sha256=?", f.actor.SessionExpiresAt.Add(-time.Microsecond), f.installation, f.actor.Session)
			case "revoked_at_issue":
				exec("INSERT INTO system_backup_v2_admin_revocations(origin_installation_id,user_id,revoked_before) VALUES(?,?,?)", f.installation, f.userID, f.actor.SessionIssuedAt)
			case "inactive_user":
				exec("UPDATE users SET is_active=FALSE WHERE id=?", f.userID)
			case "password_changed":
				hash, e := bcrypt.GenerateFromPassword([]byte("synthetic-new-password"), bcrypt.MinCost)
				mysqlMust(t, e)
				exec("UPDATE users SET password_hash=? WHERE id=?", string(hash), f.userID)
			case "unconfirmed_totp":
				exec("UPDATE system_backup_v2_totp_credentials SET confirmed=FALSE,pending_until=UTC_TIMESTAMP(6)+INTERVAL 10 MINUTE WHERE origin_installation_id=? AND user_id=?", f.installation, f.userID)
			case "signer_failure":
				f.signer.fail = true
			case "audit_failure_rollback":
				trigger := "acp_audit_" + strings.TrimPrefix(f.installation, "installation_config_proof_")
				exec("CREATE TRIGGER " + trigger + " BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.user_id=" + strconv.FormatInt(f.userID, 10) + " AND NEW.action='system_backup.strong_auth.verified' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit rejection'; END IF; END")
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
					defer stop()
					if _, e := db.ExecContext(cleanup, "DROP TRIGGER IF EXISTS "+trigger); e != nil {
						t.Error("CLEANUP_PENDING config-proof audit trigger")
					}
				})
			case "commit_reply_lost":
				base, e := mysql.NewConnector(cfg)
				mysqlMust(t, e)
				fault := sql.OpenDB(&configProofLostCommitConnector{base: base})
				defer fault.Close()
				svc := f.svc
				svc.DB = fault
				code, request := f.code(t), f.request(t, ConfigUpdateEndpoint)
				proof, e := svc.VerifyConfigMutationAndIssue(ctx, f.actor, f.password, code, request, "config_proof_mysql_key_012345")
				if e != ErrRegistrationCommitUnknown || proof.SchemaVersion != "" {
					t.Fatal("unknown COMMIT released a proof")
				}
				step, count := f.state(t)
				if step < 0 || count != 1 {
					t.Fatal("real COMMIT was not preserved")
				}
				proof, e = f.svc.VerifyConfigMutationAndIssue(ctx, f.actor, f.password, code, request, "config_proof_mysql_key_012345")
				if e != ErrTOTPRejected || proof.SchemaVersion != "" {
					t.Fatal("unknown COMMIT was blindly reissued")
				}
				return
			case "observed_config_lock_revocation":
				block, e := db.BeginTx(ctx, nil)
				mysqlMust(t, e)
				defer block.Rollback()
				_, e = block.ExecContext(ctx, "UPDATE system_backup_v2_configs SET rbac_bindings_registry_version='proof-rbac-v2',rbac_bindings_registry_sha256=? WHERE origin_installation_id=? AND version=1", registrationHash(string(f.revokedRBAC)), f.installation)
				mysqlMust(t, e)
				w := f.start(t, f.code(t), f.request(t, ConfigUpdateEndpoint))
				(sessionMySQLProbe{db: db, identity: identity}).waiting(t, ctx, w, "system_backup_v2_configs")
				mysqlMust(t, block.Commit())
				if e = sessionWorkerResult(t, ctx, w); e != ErrRegistrationUnavailable {
					t.Fatal("worker authorized stale config after observed wait")
				}
				step, count := f.state(t)
				if step != -1 || count != 0 {
					t.Fatal("revocation left committed proof state")
				}
				return
			case "session_expires_in_signer":
				var passwordHash string
				mysqlMust(t, db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id=?", f.userID).Scan(&passwordHash))
				f.login(t, 5*time.Second, passwordHash)
				f.signer.before = func(call context.Context) error {
					deadline := time.Now().Add(10 * time.Second)
					for {
						var expired bool
						if e := db.QueryRowContext(call, "SELECT UTC_TIMESTAMP(6)>=?", f.actor.SessionExpiresAt).Scan(&expired); e != nil {
							return e
						}
						if expired {
							expiredInSigner = true
							return nil
						}
						if time.Now().After(deadline) {
							return errors.New("database expiry not reached")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
			proof, e := f.issue(t, f.svc)
			if name == "session_expires_in_signer" && !expiredInSigner {
				t.Fatal("expiry was not actually observed in signer")
			}
			if e == nil || proof.SchemaVersion != "" || proof.Payload.Nonce != "" {
				t.Fatal("negative MySQL case released proof")
			}
			step, count := f.state(t)
			if step != -1 || count != 0 {
				t.Fatal("failed proof retained step or verified audit")
			}
			if name == "missing_session" {
				var count int
				mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND session_sha256=?", f.installation, f.actor.Session).Scan(&count))
				if count != 0 {
					t.Fatal("proof enrolled missing access session")
				}
			}
		}) {
			return
		}
	}
	t.Log("SCOPE config-proof real_mysql=yes https_jwt=yes current_config_rbac=yes totp_single_use=yes real_row_wait=yes commit_loss=synthetic_after_real_commit human_mfa=no production_grant=no config_write=no backfill=no")
}
