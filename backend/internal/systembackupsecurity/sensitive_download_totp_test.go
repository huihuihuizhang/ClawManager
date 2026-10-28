package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const downloadProofTestID = "sev_11111111-2222-4333-8444-555555555555"
const downloadProofTestKey = "download_mfa_key_0123456789"

// Only the trusted Manifest/permission source and SQL transport are modeled;
// password, AES-GCM, TOTP, JWT, canonical binding and Ed25519 are real.
type downloadProofSource struct {
	f                                    *configProofFixture
	tx                                   *sql.Tx
	request                              SensitiveDownloadRequest
	until                                time.Time
	cfg                                  VerifyConfig
	prepare, validate, recheck, closed   int
	denyPrepare, denyValidate, denyFinal bool
	onFinal                              func()
}

func (s *downloadProofSource) Prepare(_ context.Context, tx *sql.Tx, actor RegistrationActor, selector SensitiveDownloadProofSelector, key string) (SensitiveDownloadProofTarget, error) {
	s.prepare++
	if s.denyPrepare {
		return s, ErrRegistrationPermission
	}
	if tx == nil || actor != s.f.actor || selector.EvidenceID() != downloadProofTestID || key != downloadProofTestKey || s.f.model.executions != 0 {
		return s, ErrRegistrationUnavailable
	}
	s.tx = tx
	return s, nil
}
func (s *downloadProofSource) Request() SensitiveDownloadRequest { return s.request }
func (s *downloadProofSource) ValidUntil() time.Time             { return s.until }
func (s *downloadProofSource) Close()                            { s.closed++ }
func (s *downloadProofSource) ValidateProof(_ context.Context, tx *sql.Tx, actor RegistrationActor, proof Proof, issuedAt time.Time) error {
	s.validate++
	if s.denyValidate || tx != s.tx || actor != s.f.actor || !issuedAt.Equal(s.f.model.now) || s.f.model.executions != 1 {
		return ErrRegistrationUnavailable
	}
	cfg := s.cfg
	cfg.Now = s.f.model.finalNow
	_, err := s.request.VerifyProof(proof, s.f.svc.Issuer.Key.Issuer, cfg)
	return err
}
func (s *downloadProofSource) Recheck(_ context.Context, tx *sql.Tx, actor RegistrationActor) error {
	s.recheck++
	if s.onFinal != nil {
		s.onFinal()
	}
	if s.denyFinal || tx != s.tx || actor != s.f.actor || s.f.model.executions != 3 {
		return ErrRegistrationPermission
	}
	return nil
}
func newDownloadProofFixture(t *testing.T) (*configProofFixture, *downloadProofSource, SensitiveDownloadProofSelector) {
	t.Helper()
	f := newConfigProofFixture(t, ConfigRollbackEndpoint)
	f.svc.Issuer.Audience = f.svc.InstallationID
	selector, err := DecodeSensitiveDownloadProofSelector([]byte(`{"evidence_id":"` + downloadProofTestID + `","range":"bytes=2-5"}`))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSensitiveDownloadRequest(SensitiveDownloadRequestFacts{Installation: f.svc.InstallationID, EvidenceID: downloadProofTestID, ManifestSHA256: strings.Repeat("a", 64), IdempotencyKey: downloadProofTestKey, Actor: f.actor, ContentSize: 8, RangeStart: 2, RangeEnd: 5, RangePresent: true})
	if err != nil {
		t.Fatal(err)
	}
	k := f.svc.Issuer.Key
	cfg := VerifyConfig{Now: f.model.now, MaxAge: 5 * time.Minute, ClockSkew: 0, ExpectedAudience: f.svc.InstallationID, ExpectedSubject: f.actor.Subject, ExpectedSession: f.actor.Session,
		TrustedSigners:        map[string]map[string]SignatureVerifier{k.Issuer: {k.KeyVersion: Ed25519JWSVerifier{PublicKey: k.PublicKey, KeyID: k.KeyID, KeyVersion: k.KeyVersion, Purpose: k.Purpose}}},
		TrustedIssuerPolicies: map[string]IssuerPolicy{k.Issuer: {Methods: []string{"totp"}, AMR: []string{"otp"}}},
		NonceHMACKeys:         map[string][]byte{"v1": bytes.Repeat([]byte{1}, 32)}, ActiveNonceHMACKeyVersion: "v1", RequiredNonceHMACKeyVersions: []string{"v1"}}
	return f, &downloadProofSource{f: f, request: request, until: f.model.now.Add(2 * time.Minute), cfg: cfg}, selector
}

func TestSensitiveDownloadTOTPIssuesOriginalRequestOnce(t *testing.T) {
	f, source, selector := newDownloadProofFixture(t)
	proof, err := f.svc.VerifySensitiveDownloadAndIssue(context.Background(), f.actor, f.password, f.code(), selector, downloadProofTestKey, source)
	if err != nil || proof.Payload.Endpoint != SensitiveDownloadEndpoint || proof.Payload.RequestHash != source.request.RequestHash() || proof.Payload.IdempotencyKey != downloadProofTestKey || source.prepare != 1 || source.validate != 1 || source.recheck != 1 || source.closed != 1 || f.model.authorizations != 0 || f.model.commits != 1 || f.model.sessionEnrollments != 0 || f.model.row.step != f.model.now.Unix()/30 {
		t.Fatal("bound download proof", err, source, f.model.commits)
	}
	if _, err = source.request.VerifyProof(proof, f.svc.Issuer.Key.Issuer, source.cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.model.audit, f.password) || strings.Contains(f.model.audit, f.token) || strings.Contains(f.model.audit, proof.Payload.Nonce) {
		t.Fatal("private proof material in audit")
	}
	// Independent fresh source, same TOTP step: replay must persist rejection.
	source.prepare, source.validate, source.recheck, source.closed = 0, 0, 0, 0
	f.model.executions = 0
	if p, e := f.svc.VerifySensitiveDownloadAndIssue(context.Background(), f.actor, f.password, f.code(), selector, downloadProofTestKey, source); e != ErrTOTPRejected || p.SchemaVersion != "" || f.model.row.failures != 1 || source.validate != 0 || f.model.sessionEnrollments != 0 {
		t.Fatal("TOTP replay issued a proof", e)
	}
}

func TestSensitiveDownloadTOTPRejectsAuthoritySessionAndCommitFailures(t *testing.T) {
	for _, name := range []string{"target-denied", "target-expired", "target-key", "target-actor", "target-evidence", "audience", "unconfirmed", "password", "bad-code", "missing-session", "revoked-session", "signer-failed", "untrusted-local-signer", "target-validation", "audit-failed", "final-denied", "final-revocation", "final-expiry", "final-target-replaced", "final-deadline-extended", "clock-backward", "commit-unknown", "commit-late"} {
		t.Run(name, func(t *testing.T) {
			f, s, selector := newDownloadProofFixture(t)
			password, code := f.password, f.code()
			switch name {
			case "target-denied":
				s.denyPrepare = true
			case "target-expired":
				s.until = f.model.now
			case "target-key":
				s.request.key = "another_download_key_012345"
			case "target-actor":
				s.request.session = strings.Repeat("b", 64)
			case "target-evidence":
				s.request.evidence = "sev_22222222-2222-4333-8444-555555555555"
			case "audience":
				f.svc.Issuer.Audience = "other-audience"
			case "unconfirmed":
				f.model.row.confirmed = false
			case "password":
				password = "incorrect-password"
			case "bad-code":
				code = "000000"
				if code == f.code() {
					code = "000001"
				}
			case "missing-session":
				delete(f.model.rows, f.actor.Session)
			case "revoked-session":
				r := f.model.rows[f.actor.Session]
				r.revoked = true
				f.model.rows[f.actor.Session] = r
			case "signer-failed":
				f.signer.fail = true
			case "untrusted-local-signer":
				s.cfg.TrustedIssuerPolicies = map[string]IssuerPolicy{}
			case "target-validation":
				s.denyValidate = true
			case "audit-failed":
				f.model.failAt = 3
			case "final-denied":
				s.denyFinal = true
			case "final-target-replaced":
				s.onFinal = func() { s.request.digest = strings.Repeat("b", 64) }
			case "final-deadline-extended":
				s.onFinal = func() { s.until = s.until.Add(time.Hour) }
			case "final-revocation":
				s.onFinal = func() { r := f.model.pending[f.actor.Session]; r.revoked = true; f.model.pending[f.actor.Session] = r }
			case "final-expiry":
				f.signer.callback = func() { f.model.finalNow = s.until }
			case "clock-backward":
				f.signer.callback = func() { f.model.finalNow = f.model.now.Add(-time.Microsecond) }
			case "commit-unknown":
				f.model.commitUnknown = true
			case "commit-late":
				s.until = f.model.now.Add(10 * time.Millisecond)
				f.model.afterCommit = func() { time.Sleep(25 * time.Millisecond) }
			}
			proof, err := f.svc.VerifySensitiveDownloadAndIssue(context.Background(), f.actor, password, code, selector, downloadProofTestKey, s)
			if err == nil || proof.SchemaVersion != "" || proof.Payload.Nonce != "" || f.model.activeTx || f.model.sessionEnrollments != 0 || s.closed != 1 {
				t.Fatal("failure released proof or extended session", err)
			}
			if name == "commit-unknown" && err != ErrRegistrationCommitUnknown {
				t.Fatal("unknown commit relabeled", err)
			}
			if name == "commit-late" {
				if f.model.commits != 1 || f.model.row.step < 0 {
					t.Fatal("late commit not exercised")
				}
			} else if name != "commit-unknown" && name != "password" && name != "bad-code" && (f.model.commits != 0 || f.model.row.step != -1 || f.model.audit != "") {
				t.Fatal("failed issuance persisted success")
			}
		})
	}
}

func TestSensitiveDownloadProofHTTPClosedSelectorsAndActualMFA(t *testing.T) {
	for _, name := range []string{"valid", "no-source", "digest", "manifest", "actor", "auth-time", "null-range", "empty-range", "multi-range", "duplicate", "case-fold", "bad-token", "plain-http"} {
		t.Run(name, func(t *testing.T) {
			f, s, selector := newDownloadProofFixture(t)
			request := map[string]any{"evidence_id": selector.EvidenceID(), "range": "bytes=2-5"}
			want := 400
			switch name {
			case "valid":
				want = 200
			case "no-source":
				want = 503
			case "digest":
				request["request_hash"] = strings.Repeat("a", 64)
			case "manifest":
				request["manifest_sha256"] = strings.Repeat("a", 64)
			case "actor":
				request["actor_id"] = "42"
			case "auth-time":
				request["auth_time"] = f.model.now.Format(time.RFC3339Nano)
			case "null-range":
				request["range"] = nil
			case "empty-range":
				request["range"] = ""
			case "multi-range":
				request["range"] = "bytes=0-1,3-4"
			case "case-fold":
				request["Evidence_ID"] = request["evidence_id"]
				delete(request, "evidence_id")
			case "bad-token":
				want = 401
			case "plain-http":
				want = 426
			}
			rawRequest, _ := json.Marshal(request)
			if name == "duplicate" {
				rawRequest = []byte(`{"evidence_id":"` + downloadProofTestID + `","evidence_id":"` + downloadProofTestID + `"}`)
			}
			body, _ := json.Marshal(map[string]any{"password": f.password, "code": f.code(), "endpoint": SensitiveDownloadEndpoint, "idempotency_key": downloadProofTestKey, "request": json.RawMessage(rawRequest)})
			r := httptest.NewRequest("POST", "https://control.example"+strongAuthBase+"/proof", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+f.token)
			if name == "bad-token" {
				r.Header.Set("Authorization", "Bearer invalid")
			}
			if name == "plain-http" {
				r.TLS = nil
			}
			api := RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc, DownloadProofTargets: s}
			if name == "no-source" {
				api.DownloadProofTargets = nil
			}
			w := httptest.NewRecorder()
			api.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal(w.Code, want, w.Body.String())
			}
			if name == "valid" {
				var response struct {
					HeaderName  string `json:"header_name"`
					HeaderValue string `json:"header_value"`
				}
				if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.HeaderName != StrongAuthProofHeader || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("proof transport")
				}
				proof, err := DecodeStrongAuthHeader(response.HeaderValue)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.request.VerifyProof(proof, f.svc.Issuer.Key.Issuer, s.cfg); err != nil {
					t.Fatal(err)
				}
			} else if s.prepare != 0 || f.model.executions != 0 || f.model.commits != 0 {
				t.Fatal("invalid HTTP selector reached SQL")
			}
		})
	}
}

func TestSensitiveDownloadMFASelectorStrictWire(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"full", `{"evidence_id":"` + downloadProofTestID + `"}`, true},
		{"bounded", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=0-3"}`, true},
		{"suffix", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=-2"}`, true},
		{"open", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=2-"}`, true},
		{"null", `null`, false}, {"array", `[]`, false}, {"missing", `{}`, false},
		{"id-null", `{"evidence_id":null}`, false},
		{"bad-id", `{"evidence_id":"sev_unknown"}`, false},
		{"range-null", `{"evidence_id":"` + downloadProofTestID + `","range":null}`, false},
		{"range-number", `{"evidence_id":"` + downloadProofTestID + `","range":2}`, false},
		{"blank-range", `{"evidence_id":"` + downloadProofTestID + `","range":""}`, false},
		{"duplicate-escaped", `{"evidence_id":"` + downloadProofTestID + `","evidence_\u0069d":"` + downloadProofTestID + `"}`, false},
		{"digest", `{"evidence_id":"` + downloadProofTestID + `","request_hash":"` + strings.Repeat("a", 64) + `"}`, false},
		{"manifest", `{"evidence_id":"` + downloadProofTestID + `","manifest":{}}`, false},
		{"assertion", `{"evidence_id":"` + downloadProofTestID + `","proof":{}}`, false},
		{"unicode", `{"evidence_id":"\ud800"}`, false},
		{"multi", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=0-1,2-3"}`, false},
		{"unsafe", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=0-9007199254740992"}`, false},
		{"overflow", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes=999999999999999999999999-"}`, false},
		{"space", `{"evidence_id":"` + downloadProofTestID + `","range":"bytes= 0-1"}`, false},
		{"case", `{"evidence_id":"` + downloadProofTestID + `","range":"Bytes=0-1"}`, false},
		{"oversize", strings.Repeat(" ", 1025), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := DecodeSensitiveDownloadProofSelector([]byte(tc.raw))
			if (err == nil) != tc.valid {
				t.Fatal("selector", err)
			}
			if tc.valid && selector.EvidenceID() != downloadProofTestID {
				t.Fatal("selector id changed")
			}
		})
	}
}

func TestSensitiveDownloadMFARejectsMissingRuntimeBeforeSQL(t *testing.T) {
	for _, name := range []string{"nil-source", "typed-nil-source", "nil-context", "cancelled", "nil-identity", "installation", "key", "selector"} {
		t.Run(name, func(t *testing.T) {
			f, source, selector := newDownloadProofFixture(t)
			var targets SensitiveDownloadProofTargets = source
			ctx := context.Background()
			key := downloadProofTestKey
			switch name {
			case "nil-source":
				targets = nil
			case "typed-nil-source":
				targets = (*downloadProofSource)(nil)
			case "nil-context":
				ctx = nil
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "nil-identity":
				f.svc.DatabaseIdentity = nil
			case "installation":
				f.svc.InstallationID = "other"
			case "key":
				key = "short"
			case "selector":
				selector = SensitiveDownloadProofSelector{}
			}
			proof, err := f.svc.VerifySensitiveDownloadAndIssue(ctx, f.actor, f.password, f.code(), selector, key, targets)
			if err == nil || proof.SchemaVersion != "" || source.prepare != 0 || source.closed != 0 || f.model.executions != 0 || f.model.activeTx {
				t.Fatal("bad runtime reached SQL", err)
			}
		})
	}
}
