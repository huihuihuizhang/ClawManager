//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type httpMySQLObserver struct {
	db           *sql.DB
	installation string
	binding      ProviderProofBinding
}

func (o httpMySQLObserver) Observe(ctx context.Context, target ProviderProofTarget, version int64) (ProviderObservation, error) {
	var row int64
	var now time.Time
	if target != o.binding.Target || version != o.binding.RowVersion {
		return ProviderObservation{}, ErrRegistrationPermission
	}
	if err := o.db.QueryRowContext(ctx, "SELECT row_version,UTC_TIMESTAMP(6) FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND public_id=?", o.installation, target.TargetPublicID).Scan(&row, &now); err != nil || row != version {
		return ProviderObservation{}, ErrRegistrationUnavailable
	}
	return ProviderObservation{Binding: o.binding, ObservedAt: now}, nil
}

// Real HTTPS, JWT validation, pinned registry resolution, SQL MFA/session state
// and registration transactions. Signing keys, provider facts, nonce material
// and capacity admission are explicit isolated fixtures: not human MFA, live
// S3 observation, real Transit signing, or production configuration activation.
func testRegistrationHTTPMySQL(t *testing.T, db *sql.DB, ctx context.Context) {
	const installation = "installation_http_synthetic"
	password := "isolated-http-password-only"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO users(id,role,is_active,password_hash) VALUES(44,'admin',TRUE,?),(45,'admin',TRUE,?)", string(hash), string(hash))
	mysqlMust(t, err)
	var now time.Time
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	identity := DatabaseIdentity{}
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&identity.ServerUUID, &identity.Database))
	r, pc, providerKey := providerSignedFixture(t)
	pc.Scope.InstallationID = installation
	pk := pc.Keys[0]
	pk.NotBefore = now.Add(-time.Hour)
	pk.NotAfter = now.Add(time.Hour)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	mysqlMust(t, err)
	sk := StrongAuthRegistryKey{Issuer: "synthetic-http-mfa", KeyID: "synthetic-http-mfa-key", KeyVersion: "1", Purpose: "strong_auth_issuer", PublicKey: pub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Policy: IssuerPolicy{Methods: []string{"totp"}, ACR: []string{}, AMR: []string{"otp"}}}
	encode := func(v any) []byte { b, e := json.Marshal(v); mysqlMust(t, e); return b }
	providerRaw := encode(ProviderIssuerRegistry{SchemaVersion: "system-backup-provider-issuers.draft.v1", Version: "http-provider-v1", Scope: pc.Scope, Keys: []ProviderIssuerRegistryKey{{Issuer: pk.Issuer, KeyID: pk.KeyID, KeyVersion: pk.KeyVersion, Purpose: pk.Purpose, PublicKey: pk.PublicKey, NotBefore: pk.NotBefore, NotAfter: pk.NotAfter, TargetTypes: pk.TargetTypes, ProofTypes: pk.ProofTypes}}})
	strongRaw := encode(StrongAuthIssuerRegistry{SchemaVersion: "system-backup-strong-auth-issuers.draft.v1", Version: "http-strong-v1", Audience: "synthetic-http-mfa-audience", Keys: []StrongAuthRegistryKey{sk}})
	rbacRaw := []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"http-rbac-v1","installation_id":"installation_http_synthetic","bindings":[{"actor_id":"44","subject":"user:44","role":"security_admin"}]}`)
	revokedRaw := bytes.ReplaceAll(bytes.ReplaceAll(rbacRaw, []byte("http-rbac-v1"), []byte("http-rbac-v2")), []byte("security_admin"), []byte("viewer"))
	registries := map[string][]byte{"provider_proof_issuers/http-provider-v1": providerRaw, "strong_auth_issuers/http-strong-v1": strongRaw, "rbac_bindings/http-rbac-v1": rbacRaw, "rbac_bindings/http-rbac-v2": revokedRaw}
	cfg := RegistrationConfig{Version: 1, ProviderRegistryVersion: "http-provider-v1", ProviderRegistrySHA256: registrationHash(string(providerRaw)), StrongAuthRegistryVersion: "http-strong-v1", StrongAuthRegistrySHA256: registrationHash(string(strongRaw)), RBACRegistryVersion: "http-rbac-v1", RBACRegistrySHA256: registrationHash(string(rbacRaw))}
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_configs VALUES(?,1,?,?,?,?,?,?,'v1',REPEAT('d',64),300,30,300,86400,2592000,60,1073741824)`, installation, cfg.ProviderRegistryVersion, cfg.ProviderRegistrySHA256, cfg.StrongAuthRegistryVersion, cfg.StrongAuthRegistrySHA256, cfg.RBACRegistryVersion, cfg.RBACRegistrySHA256)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_installation_state VALUES(?,1)", installation)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_external_actions VALUES(?,?,?)", installation, r.Target.TargetPublicID, r.ExpectedRowVersion)
	mysqlMust(t, err)
	binding := pc.Binding
	targetBinding := func(ctx context.Context, tx *sql.Tx, target ProviderProofTarget) (ProviderProofBinding, error) {
		var version int64
		if target != binding.Target {
			return ProviderProofBinding{}, ErrRegistrationPermission
		}
		if err := tx.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND public_id=? FOR UPDATE", installation, target.TargetPublicID).Scan(&version); err != nil || version != binding.RowVersion {
			return ProviderProofBinding{}, ErrRegistrationUnavailable
		}
		return binding, nil
	}
	authority := configuredAuthority{expected: cfg, database: identity, PinnedRegistrationAuthority: PinnedRegistrationAuthority{
		InstallationID: installation,
		RegistryBytes: func(kind, version, digest string) ([]byte, error) {
			b := registries[kind+"/"+version]
			if registrationHash(string(b)) != digest {
				return nil, ErrRegistrationUnavailable
			}
			return b, nil
		},
		CheckSessionAndVisibility: func(ctx context.Context, tx *sql.Tx, a RegistrationActor, target ProviderProofTarget) error {
			if err := CheckRegistrationSession(ctx, tx, installation, a); err != nil {
				return err
			}
			_, err := targetBinding(ctx, tx, target)
			return err
		},
		TargetBinding: targetBinding,
		NonceKeys: func(_ context.Context, _ *sql.Tx, _ RegistrationConfig, versions []string) (map[string][]byte, error) {
			for _, v := range versions {
				if v != "v1" {
					return nil, ErrRegistrationUnavailable
				}
			}
			return map[string][]byte{"v1": []byte(strings.Repeat("n", 32))}, nil
		},
		ReserveMetadata: func(ctx context.Context, tx *sql.Tx, _ int64, n int) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO d_capacity_reservations(bytes) VALUES(?)", n)
			return err
		},
	}}
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{8}, 32))
	mysqlMust(t, err)
	totp := SQLTOTPService{DB: db, DatabaseIdentity: &identity, InstallationID: installation, Box: box, Authorize: authority.AuthorizeMFA, Issuer: StrongAuthProofIssuer{Key: sk, Audience: "synthetic-http-mfa-audience", Signer: testProofSigner{key}, Lifetime: time.Minute}}
	jwtKey := make([]byte, 32)
	_, err = rand.Read(jwtKey)
	mysqlMust(t, err)
	defer wipeSecret(jwtKey)
	token := func(id int64, kind string, signingKey []byte) string {
		value, e := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": id, "token_type": kind, "iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Hour).Unix()}).SignedString(signingKey)
		mysqlMust(t, e)
		return value
	}
	access := token(44, "access", jwtKey)
	api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: jwtKey}, Service: ProviderRegistrationService{DB: db, InstallationID: installation, Authority: authority}}, TOTP: totp, Attestation: ProviderAttestationService{Scope: pc.Scope, Key: pk, Observer: httpMySQLObserver{db, installation, binding}, Signer: testProofSigner{providerKey}, Lifetime: 2 * time.Minute}}
	api.AuthorizeObservation = func(ctx context.Context, a RegistrationActor, target ProviderProofTarget) error {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = authority.AuthorizeMFA(ctx, tx, a); err != nil {
			return err
		}
		return authority.PinnedRegistrationAuthority.CheckSessionAndVisibility(ctx, tx, a, target)
	}
	server := httptest.NewTLSServer(api)
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	call := func(path, bearer string, body any, proof string, want int) []byte {
		t.Helper()
		request, e := http.NewRequestWithContext(ctx, "POST", server.URL+path, bytes.NewReader(encode(body)))
		mysqlMust(t, e)
		request.Header.Set("Authorization", "Bearer "+bearer)
		request.Header.Set("Content-Type", "application/json")
		if path == ProviderRegistrationPath {
			request.Header.Set("Idempotency-Key", r.IdempotencyKey)
		}
		if proof != "" {
			request.Header.Set(StrongAuthProofHeader, proof)
		}
		response, e := client.Do(request)
		mysqlMust(t, e)
		defer response.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
		mysqlMust(t, e)
		if response.StatusCode != want || len(raw) > 65536 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("HTTP stage %s status=%d want=%d (response withheld)", path, response.StatusCode, want)
		}
		return raw
	}
	enroll := map[string]any{"password": password}
	call(strongAuthBase+"/enroll", token(44, "refresh", jwtKey), enroll, "", 401)
	call(strongAuthBase+"/enroll", token(44, "access", bytes.Repeat([]byte{9}, 32)), enroll, "", 401)
	call(strongAuthBase+"/enroll", token(45, "access", jwtKey), enroll, "", 403)
	var n int
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_totp_credentials WHERE user_id=45").Scan(&n))
	if n != 0 {
		t.Fatal("unbound admin created MFA state")
	}
	var enrollment map[string]string
	mysqlMust(t, json.Unmarshal(call(strongAuthBase+"/enroll", access, enroll, "", 200), &enrollment))
	uri, err := url.Parse(enrollment["enrollment_uri"])
	mysqlMust(t, err)
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(uri.Query().Get("secret"))
	mysqlMust(t, err)
	defer wipeSecret(seed)
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	call(strongAuthBase+"/confirm", access, map[string]any{"password": password, "code": totpCode(seed, now.Unix()/30-1, 6)}, "", 200)
	mysqlMust(t, json.Unmarshal(call(ProviderObservationPath, access, map[string]any{"target": r.Target, "expected_row_version": r.ExpectedRowVersion}, "", 200), &r.Proof))
	proofBody := map[string]any{"password": password, "code": totpCode(seed, now.Unix()/30, 6), "request": r}
	var signed map[string]string
	mysqlMust(t, json.Unmarshal(call(strongAuthBase+"/proof", access, proofBody, "", 200), &signed))
	if signed["header_name"] != StrongAuthProofHeader || signed["header_value"] == "" {
		t.Fatal("missing proof header")
	}
	call(strongAuthBase+"/proof", access, proofBody, "", 401)
	var evidenceBefore int
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&evidenceBefore))
	first := call(ProviderRegistrationPath, access, r, signed["header_value"], 201)
	replay := call(ProviderRegistrationPath, access, r, "", 201)
	if !bytes.Equal(first, replay) {
		t.Fatal("HTTP committed retry changed receipt")
	}
	for _, table := range []string{"system_backup_v2_operations", "system_backup_v2_strong_auth_nonces"} {
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE origin_installation_id=?", installation).Scan(&n))
		if n != 1 {
			t.Fatal("unexpected scoped receipt count", table, n)
		}
	}
	// Evidence has a globally unique public_id and owner binding, not an
	// origin_installation_id column. Verify the returned receipt and the total
	// delta so a retry cannot silently create another unreferenced evidence row.
	var receipt ProviderRegistrationResult
	mysqlMust(t, json.Unmarshal(first, &receipt))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type=? AND owner_target_public_id=?", receipt.EvidencePublicID, r.Target.TargetType, r.Target.TargetPublicID).Scan(&n))
	if n != 1 {
		t.Fatal("HTTP receipt does not identify exactly one owned evidence row")
	}
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&n))
	if n != evidenceBefore+1 {
		t.Fatal("HTTP registration/retry did not create exactly one evidence row")
	}
	mysqlMust(t, totp.RevokeUserSessions(ctx, 44))
	call(ProviderRegistrationPath, access, r, "", 403)
	proofBody["code"] = totpCode(seed, now.Unix()/30+1, 6)
	call(strongAuthBase+"/proof", access, proofBody, "", 403)
	// Configuration revocation must not race a credential transaction. Hold the
	// real authorization locks, then use a second transaction to rotate RBAC.
	locked, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mysqlMust(t, err)
	defer locked.Rollback()
	actor := RegistrationActor{UserID: 44, Subject: "user:44"}
	mysqlMust(t, authority.AuthorizeMFA(ctx, locked, actor))
	started := make(chan struct{})
	rotated := make(chan error, 1)
	go func() {
		tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if e != nil {
			rotated <- e
			return
		}
		defer tx.Rollback()
		close(started)
		if e = lockRegistrationInstallations(ctx, tx); e == nil {
			_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_configs SELECT origin_installation_id,2,provider_proof_issuers_registry_version,provider_proof_issuers_registry_sha256,strong_auth_issuers_registry_version,strong_auth_issuers_registry_sha256,'http-rbac-v2',?,nonce_hmac_ref_version,nonce_hmac_identity_hash,strong_auth_max_age_seconds,strong_auth_clock_skew_seconds,provider_proof_max_age_seconds,evidence_retention_seconds,control_metadata_retention_seconds,operation_deadline_seconds,control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1`, registrationHash(string(revokedRaw)), installation)
		}
		if e == nil {
			_, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=2 WHERE origin_installation_id=?", installation)
		}
		if e == nil {
			e = tx.Commit()
		}
		rotated <- e
	}()
	select {
	case <-started:
	case e := <-rotated:
		mysqlMust(t, e)
		t.Fatal("rotation did not start")
	case <-ctx.Done():
		t.Fatal("rotation start timeout")
	}
	select {
	case <-rotated:
		t.Fatal("configuration changed during MFA authorization transaction")
	case <-time.After(100 * time.Millisecond):
	}
	mysqlMust(t, locked.Commit())
	select {
	case e := <-rotated:
		mysqlMust(t, e)
	case <-ctx.Done():
		t.Fatal("configuration rotation timeout")
	}
	var stepBefore, stepAfter int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT last_step FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=44", installation).Scan(&stepBefore))
	proofBody["code"] = totpCode(seed, now.Unix()/30+1, 6)
	call(strongAuthBase+"/proof", access, proofBody, "", 503)
	// Reloaded runtime sees the explicit revoked role, while old runtime refuses
	// stale pins. Replace the server only after the preceding request has ended.
	server.Close()
	authority.expected.Version = 2
	authority.expected.RBACRegistryVersion = "http-rbac-v2"
	authority.expected.RBACRegistrySHA256 = registrationHash(string(revokedRaw))
	api.TOTP.Authorize = authority.AuthorizeMFA
	api.Registration.Service = ProviderRegistrationService{DB: db, InstallationID: installation, Authority: authority}
	server = httptest.NewTLSServer(api)
	defer server.Close()
	client = server.Client()
	client.Timeout = 10 * time.Second
	call(strongAuthBase+"/proof", access, proofBody, "", 403)
	call(ProviderRegistrationPath, access, r, "", 403)
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT last_step FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=44", installation).Scan(&stepAfter))
	if stepAfter != stepBefore {
		t.Fatal("revoked MFA consumed a code")
	}
	tx, err := db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	sessionActor := RegistrationActor{UserID: 44, Subject: "user:44", Session: registrationHash(access)}
	if CheckRegistrationSession(ctx, tx, installation, sessionActor) == nil {
		tx.Rollback()
		t.Fatal("logout retained session")
	}
	tx.Rollback()
	var audit string
	rows, err := db.QueryContext(ctx, "SELECT CAST(details AS CHAR) FROM audit_logs WHERE user_id=44")
	mysqlMust(t, err)
	defer rows.Close()
	for rows.Next() {
		mysqlMust(t, rows.Scan(&audit))
		for _, secret := range []string{password, access, enrollment["enrollment_uri"], signed["header_value"], base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)} {
			if secret != "" && strings.Contains(audit, secret) {
				t.Fatal("audit leaked credential")
			}
		}
	}
	mysqlMust(t, rows.Err())
	t.Log("synthetic HTTPS JWT/MFA/observation/registration chain passed; revoked actor=" + strconv.Itoa(44) + "; human_mfa=false real_transit=false active_config_updated=false")
}
