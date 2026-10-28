package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// This driver checks the application transaction boundary and fault handling;
// only the separately tagged MySQL suite can establish database lock behavior.
type registrationTestState struct {
	now                                                   time.Time
	config                                                RegistrationConfig
	result                                                *ProviderRegistrationResult
	hash                                                  string
	committed, pending                                    []string
	queries                                               []string
	failWrite                                             int
	commitUnknown, denied, inactive, consumed, missingKey bool
	authorizations, loads, commits, rollbacks             int
	tx                                                    *sql.Tx
}
type registrationTestDriver struct{}

func (registrationTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}

type registrationTestConnector struct{ s *registrationTestState }

func (c registrationTestConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c registrationTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &registrationTestConn{c.s}, nil
}

type registrationTestConn struct{ s *registrationTestState }

func (*registrationTestConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*registrationTestConn) Close() error                        { return nil }
func (c *registrationTestConn) Begin() (driver.Tx, error) {
	c.s.pending = nil
	return &registrationTestTx{c.s}, nil
}
func (c *registrationTestConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("gap locking isolation required")
	}
	return c.Begin()
}

type registrationTestRows struct {
	data  [][]driver.Value
	width int
}

func (r *registrationTestRows) Columns() []string {
	v := make([]string, r.width)
	for i := range v {
		v[i] = "column"
	}
	return v
}
func (*registrationTestRows) Close() error { return nil }
func (r *registrationTestRows) Next(v []driver.Value) error {
	if len(r.data) == 0 {
		return io.EOF
	}
	copy(v, r.data[0])
	r.data = r.data[1:]
	return nil
}
func registrationRow(v ...driver.Value) driver.Rows {
	return &registrationTestRows{[][]driver.Value{v}, len(v)}
}
func (c *registrationTestConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	s.queries = append(s.queries, q)
	switch {
	case strings.Contains(q, "SELECT origin_installation_id FROM system_backup_v2_installation_state"):
		return registrationRow("installation_synthetic"), nil
	case strings.Contains(q, "SELECT active_config_version"):
		return registrationRow(int64(1)), nil
	case strings.Contains(q, "SELECT provider_proof_issuers_registry_version"):
		v := s.config
		return registrationRow(v.ProviderRegistryVersion, v.ProviderRegistrySHA256, v.StrongAuthRegistryVersion, v.StrongAuthRegistrySHA256, v.RBACRegistryVersion, v.RBACRegistrySHA256, v.NonceKeyVersion, strings.Repeat("d", 64), int64(300), int64(0), int64(300), int64(86400), int64(2592000), int64(60), int64(1073741824)), nil
	case strings.Contains(q, "SELECT role,is_active"):
		return registrationRow("admin", !s.inactive), nil
	case strings.Contains(q, "SELECT public_id,result_resource"):
		if s.result == nil {
			return &registrationTestRows{width: 5}, nil
		}
		r := s.result
		return registrationRow(r.OperationPublicID, r.EvidencePublicID, int64(201), s.hash, "succeeded"), nil
	case strings.Contains(q, "SELECT UTC_TIMESTAMP"):
		return registrationRow(s.now, int64(0)), nil
	case strings.Contains(q, "SELECT nonce_hmac_ref_version"):
		return &registrationTestRows{data: [][]driver.Value{{"old"}, {s.config.NonceKeyVersion}}, width: 1}, nil
	case strings.Contains(q, "SELECT id FROM system_backup_v2_strong_auth_nonces"):
		if !strings.Contains(q, "FOR UPDATE") {
			return nil, errors.New("nonce missing locking read")
		}
		if s.consumed && args[1].Value == "old" {
			return registrationRow(int64(9)), nil
		}
		return &registrationTestRows{width: 1}, nil
	case strings.Contains(q, "SELECT row_version"):
		return registrationRow(int64(3)), nil
	}
	return nil, errors.New("unexpected query")
}

type registrationTestResult int64

func (r registrationTestResult) LastInsertId() (int64, error) { return int64(r), nil }
func (registrationTestResult) RowsAffected() (int64, error)   { return 1, nil }
func (c *registrationTestConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if s.failWrite == len(s.pending)+1 {
		return nil, errors.New("PRIVATE_DATABASE_FAILURE")
	}
	kind := ""
	switch {
	case strings.Contains(q, "INSERT INTO audit_logs"):
		kind = "audit"
	case strings.Contains(q, "INSERT INTO system_backup_v2_evidence"):
		kind = "evidence"
	case strings.Contains(q, "INSERT INTO system_backup_v2_operations"):
		kind = "operation"
		s.hash = args[7].Value.(string)
		s.result = &ProviderRegistrationResult{OperationPublicID: args[0].Value.(string), EvidencePublicID: args[10].Value.(string), HTTPStatus: 201}
	case strings.Contains(q, "INSERT INTO system_backup_v2_strong_auth_nonces"):
		kind = "nonce"
	default:
		return nil, errors.New("unexpected write")
	}
	s.pending = append(s.pending, kind)
	return registrationTestResult(len(s.pending)), nil
}

type registrationTestTx struct{ s *registrationTestState }

func (t *registrationTestTx) Commit() error {
	t.s.commits++
	t.s.committed = append(t.s.committed, t.s.pending...)
	t.s.pending = nil
	if t.s.commitUnknown {
		return errors.New("PRIVATE_COMMIT_ERROR")
	}
	return nil
}
func (t *registrationTestTx) Rollback() error {
	t.s.rollbacks++
	t.s.pending = nil
	if len(t.s.committed) == 0 {
		t.s.result = nil
		t.s.hash = ""
	}
	return nil
}

type registrationTestAuthority struct {
	s  *registrationTestState
	pc ProviderProofRegistrationContext
	sc VerifyConfig
}

func (a registrationTestAuthority) Authorize(_ context.Context, tx *sql.Tx, _ RegistrationActor, _ ProviderProofTarget, _ RegistrationConfig) error {
	a.s.authorizations++
	a.s.tx = tx
	if a.s.denied {
		return ErrRegistrationPermission
	}
	return nil
}
func (a registrationTestAuthority) Load(_ context.Context, tx *sql.Tx, _ RegistrationActor, _ ProviderProofTarget, _ RegistrationConfig, _ []string, _ time.Time) (ProviderProofRegistrationContext, VerifyConfig, error) {
	a.s.loads++
	if a.s.tx != tx {
		return ProviderProofRegistrationContext{}, VerifyConfig{}, errors.New("different tx")
	}
	sc := a.sc
	if a.s.missingKey {
		sc.NonceHMACKeys = map[string][]byte{"v1": []byte(strings.Repeat("n", 32))}
	}
	return a.pc, sc, nil
}
func (a registrationTestAuthority) ReserveCapacity(_ context.Context, tx *sql.Tx, _ RegistrationConfig, _ int) error {
	if a.s.tx != tx {
		return errors.New("different tx")
	}
	return nil
}

func registrationFixture(t *testing.T) (ProviderRegistrationService, RegistrationActor, []byte, Proof, *registrationTestState) {
	t.Helper()
	r, pc, _ := providerSignedFixture(t)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	p := testProof()
	p.Payload.IdempotencyKey = r.IdempotencyKey
	p.Payload.RequestHash, _ = ProviderProofRequestSHA256(r)
	p.Signature.Algorithm = "EdDSA"
	p.Signature.KeyVersion = "v1"
	p.Signature.KeyID = "strong-key"
	header := `{"alg":"EdDSA","key_version":"v1","kid":"strong-key","purpose":"strong_auth_issuer","typ":"` + DomainSeparator + `"}`
	p.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(header))
	payload, _ := CanonicalPayload(p.Payload)
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	sc := testConfig(Ed25519JWSVerifier{})
	sc.ExpectedSubject = p.Payload.Subject
	sc.ExpectedSession = p.Payload.Session
	sc.ActiveNonceHMACKeyVersion = "v1"
	sc.NonceHMACKeys = map[string][]byte{"old": []byte(strings.Repeat("o", 32)), "v1": []byte(strings.Repeat("n", 32))}
	sc.TrustedSigners[p.Payload.Issuer] = map[string]SignatureVerifier{"v1": Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "strong-key", KeyVersion: "v1", Purpose: "strong_auth_issuer"}}
	s := &registrationTestState{now: pc.DatabaseNow, config: RegistrationConfig{ProviderRegistryVersion: pc.RegistryVersion, ProviderRegistrySHA256: pc.RegistrySHA256, NonceKeyVersion: "v1"}}
	db := sql.OpenDB(registrationTestConnector{s})
	t.Cleanup(func() { db.Close() })
	body, _ := json.Marshal(r)
	return ProviderRegistrationService{DB: db, InstallationID: pc.Scope.InstallationID, Authority: registrationTestAuthority{s, pc, sc}}, RegistrationActor{UserID: 42, Subject: p.Payload.Subject, Session: p.Payload.Session}, body, p, s
}

func TestDProviderRegistrationAtomicSuccessAndExpiredRetry(t *testing.T) {
	svc, actor, body, proof, s := registrationFixture(t)
	result, err := svc.Register(context.Background(), actor, body, proof)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.committed, ",") != "audit,evidence,operation,nonce,audit" || s.commits != 1 || result.Replayed {
		t.Fatal("partial/early success", s.committed, result)
	}
	s.now = s.now.Add(24 * time.Hour)
	replayed, err := svc.Register(context.Background(), actor, body, Proof{})
	if err != nil || !replayed.Replayed || replayed.OperationPublicID != result.OperationPublicID || replayed.EvidencePublicID != result.EvidencePublicID || s.loads != 1 || s.authorizations != 2 || len(s.committed) != 5 {
		t.Fatal("retry re-created evidence or skipped authorization", replayed, err)
	}
	s.denied = true
	if _, err = svc.Register(context.Background(), actor, body, proof); err != ErrRegistrationPermission {
		t.Fatal("revoked permission replayed", err)
	}
}

func TestDProviderRegistrationRollsBackEveryWriteFailure(t *testing.T) {
	for i := 1; i <= 5; i++ {
		t.Run(string(rune('0'+i)), func(t *testing.T) {
			svc, actor, body, proof, s := registrationFixture(t)
			s.failWrite = i
			r, err := svc.Register(context.Background(), actor, body, proof)
			if err != ErrProviderEvidenceStorage || r.HTTPStatus != 0 || len(s.committed) != 0 || len(s.pending) != 0 || s.rollbacks != 1 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("partial state/leak", r, err, s)
			}
		})
	}
}

func TestDProviderRegistrationAdmissionAndNonceFailures(t *testing.T) {
	for _, name := range []string{"denied", "inactive", "retained-nonce", "missing-historical-key", "invalid-strong-signature", "tampered-provider", "wrong-session"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, body, proof, s := registrationFixture(t)
			switch name {
			case "denied":
				s.denied = true
			case "inactive":
				s.inactive = true
			case "retained-nonce":
				s.consumed = true
			case "missing-historical-key":
				s.missingKey = true
			case "invalid-strong-signature":
				proof.Signature.Value = strings.Repeat("A", 86)
			case "tampered-provider":
				body = []byte(strings.Replace(string(body), `"expected_row_version":3`, `"expected_row_version":4`, 1))
			case "wrong-session":
				actor.Session = "different-session"
			}
			if r, err := svc.Register(context.Background(), actor, body, proof); err == nil || r.HTTPStatus != 0 || len(s.committed) != 0 || len(s.pending) != 0 {
				t.Fatal("failed admission wrote state", err)
			}
		})
	}
}

func TestDProviderRegistrationCommitUnknownAndConflict(t *testing.T) {
	svc, actor, body, proof, s := registrationFixture(t)
	s.commitUnknown = true
	if r, err := svc.Register(context.Background(), actor, body, proof); err != ErrRegistrationCommitUnknown || r.HTTPStatus != 0 {
		t.Fatal("uncertain commit reported success", err)
	}
	s.commitUnknown = false
	if r, err := svc.Register(context.Background(), actor, body, proof); err != nil || !r.Replayed || len(s.committed) != 5 {
		t.Fatal("uncertain commit duplicated effect", err)
	}
	var r ProviderProofRegistration
	json.Unmarshal(body, &r)
	r.ExpectedRowVersion++
	changed, _ := json.Marshal(r)
	if _, err := svc.Register(context.Background(), actor, changed, proof); err != ErrRegistrationConflict {
		t.Fatal("changed body accepted", err)
	}
}

func TestDProviderRegistryRequiresExactPinnedBytes(t *testing.T) {
	_, pc, _ := providerSignedFixture(t)
	k := pc.Keys[0]
	r := ProviderIssuerRegistry{SchemaVersion: "system-backup-provider-issuers.draft.v1", Version: "v1", Scope: pc.Scope, Keys: []ProviderIssuerRegistryKey{{Issuer: k.Issuer, KeyID: k.KeyID, KeyVersion: k.KeyVersion, Purpose: k.Purpose, PublicKey: k.PublicKey, NotBefore: k.NotBefore, NotAfter: k.NotAfter, TargetTypes: k.TargetTypes, ProofTypes: k.ProofTypes}}}
	raw, _ := json.Marshal(r)
	hash := registrationHash(string(raw))
	if _, err := DecodeProviderIssuerRegistry(raw, "v1", hash, pc.DatabaseNow); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), byte(' ')), []byte(strings.Replace(string(raw), `"version":"v1"`, `"version":"v1","version":"v1"`, 1)), []byte(strings.Replace(string(raw), `"version":"v1"`, `"version":"v2"`, 1))} {
		if _, err := DecodeProviderIssuerRegistry(bad, "v1", hash, pc.DatabaseNow); err == nil {
			t.Fatal("registry drift accepted")
		}
	}
	dup := []byte(strings.Replace(string(raw), `"version":"v1"`, `"version":"v1","version":"v1"`, 1))
	if _, err := DecodeProviderIssuerRegistry(dup, "v1", registrationHash(string(dup)), pc.DatabaseNow); err == nil {
		t.Fatal("duplicate registry field accepted")
	}
}
