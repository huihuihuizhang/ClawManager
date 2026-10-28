package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// SQL remains a transaction model; password, AES-GCM, JWT, TOTP, request hash
// and Ed25519 proof verification below use the actual implementations.
type configProofTOTPRow struct {
	seed       []byte
	credential string
	confirmed  bool
	step       int64
	failures   int64
	locked     any
}
type configProofDB struct {
	loginSessionDB
	row, working                     configProofTOTPRow
	audit, workingAudit              string
	authorizations, executions       int
	failAt, sessionEnrollments       int
	denyFinal, activeTx, allowEnroll bool
	afterCommit                      func()
}
type configProofConnector struct{ s *configProofDB }

func (c configProofConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c configProofConnector) Connect(context.Context) (driver.Conn, error) {
	return &configProofConn{loginSessionConn{&c.s.loginSessionDB}, c.s}, nil
}

type configProofConn struct {
	loginSessionConn
	s *configProofDB
}

func (c *configProofConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if c.s.activeTx {
		return nil, errors.New("nested proof transaction")
	}
	tx, err := c.loginSessionConn.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	c.s.activeTx = true
	c.s.working, c.s.workingAudit = c.s.row, ""
	return &configProofTx{tx, c.s}, nil
}
func (c *configProofConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !c.s.activeTx {
		return nil, errors.New("proof query outside transaction")
	}
	if strings.HasPrefix(q, "SELECT encrypted_seed") {
		if len(args) != 2 || args[0].Value != "installation_sessions" || args[1].Value != int64(42) || !strings.HasSuffix(q, "FOR UPDATE") {
			return nil, errors.New("wrong TOTP lock")
		}
		r := c.s.working
		return registrationRow(r.seed, r.credential, r.confirmed, c.s.now.Add(time.Hour), r.step, r.failures, r.locked), nil
	}
	if strings.Contains(q, "TIMESTAMPDIFF") {
		return registrationRow(c.s.finalNow, c.s.offset), nil
	}
	return c.loginSessionConn.QueryContext(ctx, q, args)
}
func (c *configProofConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if !s.activeTx || strings.Count(q, "?") != len(args) {
		return nil, errors.New("proof write transaction/arguments")
	}
	s.executions++
	if s.executions == s.failAt {
		return nil, errors.New("PRIVATE proof storage failure")
	}
	switch {
	case strings.HasPrefix(q, "INSERT IGNORE INTO system_backup_v2_totp_credentials"):
	case strings.HasPrefix(q, "UPDATE system_backup_v2_totp_credentials SET confirmed"):
		s.working.confirmed, s.working.step = true, args[0].Value.(int64)
	case strings.HasPrefix(q, "UPDATE system_backup_v2_totp_credentials SET failures"):
		s.working.failures, s.working.locked = args[0].Value.(int64), args[1].Value
	case strings.HasPrefix(q, "INSERT INTO audit_logs"):
		details := "{}"
		if len(args) == 2 {
			details = args[1].Value.(string)
		}
		s.workingAudit = q + ":" + details
	case strings.HasPrefix(q, "INSERT INTO system_backup_v2_admin_sessions"):
		s.sessionEnrollments++
		if !s.allowEnroll {
			return nil, errors.New("configuration proof tried to enroll a session")
		}
	default:
		return nil, errors.New("unexpected proof write: " + q)
	}
	return driver.RowsAffected(1), nil
}

type configProofTx struct {
	driver.Tx
	s *configProofDB
}

func (t *configProofTx) Commit() error {
	t.s.activeTx = false
	t.s.row, t.s.audit = t.s.working, t.s.workingAudit
	err := t.Tx.Commit()
	if t.s.afterCommit != nil {
		t.s.afterCommit()
	}
	return err
}
func (t *configProofTx) Rollback() error {
	t.s.activeTx = false
	t.s.workingAudit = ""
	return t.Tx.Rollback()
}

type configProofSigner struct {
	key      ed25519.PrivateKey
	callback func()
	fail     bool
}

func (s *configProofSigner) Sign(_ context.Context, input []byte) ([]byte, error) {
	if s.callback != nil {
		s.callback()
	}
	if s.fail {
		return nil, errors.New("PRIVATE signer failure")
	}
	return ed25519.Sign(s.key, input), nil
}

type configProofFixture struct {
	svc             SQLTOTPService
	actor           RegistrationActor
	model           *configProofDB
	signer          *configProofSigner
	request         ConfigMutationRequest
	password, token string
	seed, jwtSecret []byte
}

func newConfigProofFixture(t *testing.T, endpoint string) *configProofFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &configProofFixture{password: "synthetic-config-mfa-password", seed: bytes.Repeat([]byte{9}, 20), jwtSecret: bytes.Repeat([]byte{8}, 32)}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()})
	var err error
	f.token, err = token.SignedString(f.jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("POST", "https://control.example"+strongAuthBase+"/proof", nil)
	httpRequest.Header.Set("Authorization", "Bearer "+f.token)
	f.actor, err = (JWTRegistrationAuthenticator{Secret: f.jwtSecret}).Authenticate(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(f.password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	f.model = &configProofDB{loginSessionDB: loginSessionDB{now: now, finalNow: now, password: string(hash), role: "admin", active: true, server: "11111111-2222-3333-4444-555555555555", rows: map[string]loginSessionRow{}}}
	f.model.rows[f.actor.Session] = loginSessionRow{user: 42, subject: f.actor.Subject, credential: registrationHash(string(hash)), expires: f.actor.SessionExpiresAt}
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := box.seal(f.seed, "installation_sessions/user:42")
	if err != nil {
		t.Fatal(err)
	}
	f.model.row = configProofTOTPRow{seed: encrypted, credential: registrationHash(string(hash)), confirmed: true, step: -1}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.signer = &configProofSigner{key: key}
	db := sql.OpenDB(configProofConnector{f.model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close(); wipeSecret(f.seed) })
	f.svc = SQLTOTPService{DB: db, InstallationID: "installation_sessions", DatabaseIdentity: &DatabaseIdentity{ServerUUID: f.model.server, Database: "synthetic"}, Box: box,
		Issuer: StrongAuthProofIssuer{Key: StrongAuthRegistryKey{Issuer: "synthetic-config-mfa", KeyID: "config-mfa-key", KeyVersion: "v1", Purpose: "strong_auth_issuer", PublicKey: public, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}, Audience: "synthetic-config-audience", Signer: f.signer, Lifetime: time.Minute}}
	f.svc.Authorize = func(_ context.Context, _ *sql.Tx, actor RegistrationActor) error {
		f.model.authorizations++
		if actor != f.actor || f.model.denyFinal && f.model.authorizations > 1 {
			return ErrRegistrationPermission
		}
		return nil
	}
	raw := []byte(`{"expected_version":1,"change_reason":"synthetic rollback","rollback_from_version":1}`)
	if endpoint == ConfigUpdateEndpoint {
		_, _, raw, _, _ = mutationTransactionFixture(t)
	}
	f.request, err = DecodeConfigMutationRequest(endpoint, raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *configProofFixture) issue(code string) (Proof, error) {
	return f.svc.VerifyConfigMutationAndIssue(context.Background(), f.actor, f.password, code, f.request, "config_mfa_key_0123456789")
}
func (f *configProofFixture) code() string { return totpCode(f.seed, f.model.now.Unix()/30, 6) }

func (f *configProofFixture) verify(t *testing.T, proof Proof) {
	t.Helper()
	digest, err := f.request.RequestHash(f.svc.InstallationID, "admin", "42")
	if err != nil {
		t.Fatal(err)
	}
	key := f.svc.Issuer.Key
	cfg := VerifyConfig{Now: f.model.finalNow, MaxAge: 5 * time.Minute, ClockSkew: time.Second,
		ExpectedAudience: f.svc.Issuer.Audience, ExpectedSubject: f.actor.Subject, ExpectedSession: f.actor.Session,
		TrustedSigners:        map[string]map[string]SignatureVerifier{key.Issuer: {key.KeyVersion: Ed25519JWSVerifier{PublicKey: key.PublicKey, KeyID: key.KeyID, KeyVersion: key.KeyVersion, Purpose: key.Purpose}}},
		TrustedIssuerPolicies: map[string]IssuerPolicy{key.Issuer: {Methods: []string{"totp"}, AMR: []string{"otp"}}},
		NonceHMACKeys:         map[string][]byte{"v1": bytes.Repeat([]byte{1}, 32)}, ActiveNonceHMACKeyVersion: "v1", RequiredNonceHMACKeyVersions: []string{"v1"}}
	binding := RequestBinding{Issuer: key.Issuer, Audience: f.svc.Issuer.Audience, Subject: f.actor.Subject, Session: f.actor.Session,
		Endpoint: f.request.Endpoint(), RequestHash: digest, IdempotencyKey: "config_mfa_key_0123456789"}
	if _, err := Verify(proof, binding, cfg); err != nil {
		t.Fatal("issued proof rejected by mutation verifier", err)
	}
	for _, field := range []string{"endpoint", "hash", "key", "subject", "session"} {
		changed := binding
		switch field {
		case "endpoint":
			changed.Endpoint = ProviderRegistrationEndpoint
		case "hash":
			changed.RequestHash = strings.Repeat("a", 64)
		case "key":
			changed.IdempotencyKey = "different_config_key_012345"
		case "subject":
			changed.Subject = "user:7"
		case "session":
			changed.Session = strings.Repeat("b", 64)
		}
		if _, err := Verify(proof, changed, cfg); err == nil {
			t.Fatal("cross-request proof accepted")
		}
	}
}

func TestConfigProofIssuesBoundUpdateAndRollbackOnce(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			f := newConfigProofFixture(t, endpoint)
			proof, err := f.issue(f.code())
			if err != nil || f.model.commits != 1 || f.model.row.step != f.model.now.Unix()/30 || f.model.authorizations != 2 || f.model.sessionEnrollments != 0 || f.model.activeTx {
				t.Fatal("proof transaction", err)
			}
			f.verify(t, proof)
			if strings.Contains(f.model.audit, f.password) || strings.Contains(f.model.audit, f.token) || strings.Contains(f.model.audit, proof.Payload.Nonce) {
				t.Fatal("credential/proof leaked into audit")
			}
			if p, err := f.issue(f.code()); err != ErrTOTPRejected || p.SchemaVersion != "" || f.model.row.failures != 1 {
				t.Fatal("same TOTP step issued twice or failure not persisted", err)
			}
		})
	}
}

func TestConfigProofRejectsSessionSignerAndFinalFailures(t *testing.T) {
	for _, name := range []string{"missing-session", "revoked", "shortened", "unconfirmed", "changed-totp-credential", "signer-failed", "audit-failed", "final-denied", "signer-expired-proof", "signer-expired-session", "signer-revoked-session", "clock-backwards", "non-utc", "commit-unknown"} {
		t.Run(name, func(t *testing.T) {
			f := newConfigProofFixture(t, ConfigUpdateEndpoint)
			s := f.model
			switch name {
			case "missing-session":
				delete(s.rows, f.actor.Session)
			case "revoked", "shortened":
				r := s.rows[f.actor.Session]
				if name == "revoked" {
					r.revoked = true
				} else {
					r.expires = r.expires.Add(-time.Microsecond)
				}
				s.rows[f.actor.Session] = r
			case "unconfirmed":
				s.row.confirmed = false
			case "changed-totp-credential":
				s.row.credential = strings.Repeat("0", 64)
			case "signer-failed":
				f.signer.fail = true
			case "audit-failed":
				s.failAt = 3
			case "final-denied":
				s.denyFinal = true
			case "signer-expired-proof":
				f.signer.callback = func() { s.finalNow = s.now.Add(time.Minute) }
			case "signer-expired-session":
				f.signer.callback = func() { s.finalNow = f.actor.SessionExpiresAt }
			case "signer-revoked-session":
				f.signer.callback = func() { r := s.pending[f.actor.Session]; r.revoked = true; s.pending[f.actor.Session] = r }
			case "clock-backwards":
				f.signer.callback = func() { s.finalNow = s.now.Add(-time.Microsecond) }
			case "non-utc":
				s.offset = 1
			case "commit-unknown":
				s.commitUnknown = true
			}
			proof, err := f.issue(f.code())
			if err == nil || proof.SchemaVersion != "" || proof.Payload.Nonce != "" || s.activeTx || s.sessionEnrollments != 0 {
				t.Fatal("failed issuance released proof/session", err)
			}
			if name == "commit-unknown" {
				if err != ErrRegistrationCommitUnknown || s.commits != 1 {
					t.Fatal("unknown commit", err)
				}
			} else if name == "changed-totp-credential" {
				if s.row.step != -1 || s.row.failures != 1 {
					t.Fatal("credential rejection throttle")
				}
			} else if s.commits != 0 || s.row.step != -1 || s.audit != "" {
				t.Fatal("failure left successful issuance", err)
			}
		})
	}
}

func TestConfigProofHTTPUsesStrictBusinessRequestAndActualJWT(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			f := newConfigProofFixture(t, endpoint)
			body, _ := json.Marshal(map[string]any{"password": f.password, "code": f.code(), "endpoint": endpoint, "idempotency_key": "config_mfa_key_0123456789", "request": json.RawMessage(f.request.CanonicalJSON())})
			api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc}
			r := httptest.NewRequest("POST", "https://control.example"+strongAuthBase+"/proof", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+f.token)
			w := httptest.NewRecorder()
			api.ServeHTTP(w, r)
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("proof HTTP", w.Code, w.Body.String())
			}
			var response struct {
				HeaderName  string `json:"header_name"`
				HeaderValue string `json:"header_value"`
			}
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.HeaderName != StrongAuthProofHeader {
				t.Fatal("proof response")
			}
			raw, err := base64.StdEncoding.Strict().DecodeString(response.HeaderValue)
			var proof Proof
			if err != nil || json.Unmarshal(raw, &proof) != nil {
				t.Fatal("proof transport", err)
			}
			f.verify(t, proof)
		})
	}
}

func TestConfigProofHTTPRejectsAssertionsBeforeSQL(t *testing.T) {
	for _, name := range []string{"digest", "actor", "session", "unknown-endpoint", "missing-key", "duplicate", "bad-key", "bad-token", "plain-http", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f := newConfigProofFixture(t, ConfigRollbackEndpoint)
			fields := map[string]any{"password": f.password, "code": f.code(), "endpoint": f.request.Endpoint(), "idempotency_key": "config_mfa_key_0123456789", "request": json.RawMessage(f.request.CanonicalJSON())}
			want := 400
			switch name {
			case "digest":
				fields["request_hash"] = strings.Repeat("a", 64)
			case "actor":
				fields["actor_id"] = "7"
			case "session":
				fields["session"] = strings.Repeat("b", 64)
			case "unknown-endpoint":
				fields["endpoint"] = "deleteSystemBackup"
			case "missing-key":
				delete(fields, "idempotency_key")
			case "bad-key":
				fields["idempotency_key"] = "short"
			case "bad-token":
				want = 401
			case "plain-http":
				want = 426
			case "oversize":
				want = 413
			}
			body, _ := json.Marshal(fields)
			if name == "duplicate" {
				body = append([]byte(`{"endpoint":"updateSystemBackupConfig",`), body[1:]...)
			}
			if name == "oversize" {
				body = []byte(strings.Repeat(" ", 262144+8193))
			}
			url := "https://control.example" + strongAuthBase + "/proof"
			if name == "plain-http" {
				url = "http://control.example" + strongAuthBase + "/proof"
			}
			r := httptest.NewRequest("POST", url, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+f.token)
			if name == "bad-token" {
				r.Header.Set("Authorization", "Bearer invalid")
			}
			w := httptest.NewRecorder()
			(RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc}).ServeHTTP(w, r)
			if w.Code != want || f.model.authorizations != 0 || f.model.executions != 0 || f.model.activeTx {
				t.Fatal("invalid proof envelope reached database", w.Code, want, w.Body.String())
			}
		})
	}
}

func TestConfigProofHTTPAcceptsFullRequestBeyondOldLimit(t *testing.T) {
	f := newConfigProofFixture(t, ConfigUpdateEndpoint)
	// Valid request whitespace makes transport >24 KiB without changing the
	// exact business request hash. The inner decoder retains its 256 KiB bound.
	password, _ := json.Marshal(f.password)
	body := []byte(`{"password":` + string(password) + `,"code":"` + f.code() + `","endpoint":"` + f.request.Endpoint() + `","idempotency_key":"config_mfa_key_0123456789","request":` + strings.Repeat(" ", 30000) + string(f.request.CanonicalJSON()) + `}`)
	r := httptest.NewRequest("POST", "https://control.example"+strongAuthBase+"/proof", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	(RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc}).ServeHTTP(w, r)
	if w.Code != 200 || f.model.row.step != f.model.now.Unix()/30 {
		t.Fatal("full config request rejected by old proof limit", w.Code, w.Body.String())
	}
}

func TestConfigProofPreservesProviderAndEnrollmentFlow(t *testing.T) {
	for _, confirmation := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider", true: "confirm"}[confirmation], func(t *testing.T) {
			f := newConfigProofFixture(t, ConfigUpdateEndpoint)
			f.model.allowEnroll = true
			provider, _, _ := providerSignedFixture(t)
			request := &provider
			if confirmation {
				request = nil
				f.model.row.confirmed = false
			}
			proof, err := f.svc.VerifyAndIssue(context.Background(), f.actor, f.password, f.code(), request)
			if err != nil || f.model.commits != 1 || !f.model.row.confirmed || f.model.row.step != f.model.now.Unix()/30 || f.model.sessionEnrollments != 1 {
				t.Fatal("existing TOTP flow changed", err)
			}
			if confirmation && proof.SchemaVersion != "" || !confirmation && proof.Payload.Endpoint != ProviderRegistrationEndpoint {
				t.Fatal("existing proof endpoint changed")
			}
		})
	}
}
