package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSigningMetadataUnicodeFullVerification(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // synthetic, memory only
	for _, field := range []string{"key_id", "key_version"} {
		limit := 256
		if field == "key_version" {
			limit = 128
		}
		for _, tc := range []struct {
			name, value string
			valid       bool
		}{
			{"minimum", "界", true},
			{"maximum", strings.Repeat("界", limit), true},
			{"astral_maximum", strings.Repeat("😀", limit), true},
			{"whitespace", " ", true}, // schema only constrains length
			{"over_limit", strings.Repeat("界", limit+1), false},
			{"empty", "", false},
			{"invalid_utf8", string([]byte{0xff}), false},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				proof := testProof()
				proof.Signature.Algorithm = "EdDSA"
				if field == "key_id" {
					proof.Signature.KeyID = tc.value
				} else {
					proof.Signature.KeyVersion = tc.value
				}
				adapter := Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: proof.Signature.KeyID, KeyVersion: proof.Signature.KeyVersion, Purpose: "strong_auth_issuer"}
				header := `{"alg":"EdDSA","key_version":` + jcsString(adapter.KeyVersion) + `,"kid":` + jcsString(adapter.KeyID) + `,"purpose":"strong_auth_issuer","typ":` + jcsString(DomainSeparator) + `}`
				proof.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(header))
				payload, err := CanonicalPayload(proof.Payload)
				if err != nil {
					t.Fatal(err)
				}
				input := proof.Signature.ProtectedHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
				proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
				if !ed25519.Verify(adapter.PublicKey, []byte(input), mustDecodeSignature(t, proof.Signature.Value)) {
					t.Fatal("invalid test signature")
				}
				if tc.value != "" && utf8.ValidString(tc.value) {
					if err := adapter.Verify(payload, proof.Signature); err != nil {
						t.Fatal("positive crypto control", err)
					}
				}
				cfg := testConfig(adapter)
				cfg.TrustedSigners[proof.Payload.Issuer] = map[string]SignatureVerifier{adapter.KeyVersion: adapter}
				if _, err := Verify(proof, testRequest(), cfg); (err == nil) != tc.valid {
					t.Fatalf("valid=%v, got %v", tc.valid, err)
				}
			})
		}
	}
}

func mustDecodeSignature(t *testing.T, encoded string) []byte {
	t.Helper()
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		file := filepath.Join(dir, "contracts", "system-backup", "v12", name)
		if value, err := os.ReadFile(file); err == nil {
			return value
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("contract fixture not found: %s", name)
		}
		dir = parent
	}
}

func TestNodeJCSAndRealEd25519JWSVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name         string `json:"name"`
			Proof        Proof  `json:"proof"`
			CanonicalHex string `json:"canonical_utf8_hex"`
			PublicKey    string `json:"public_key_base64url"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readContractFixture(t, "a-strong-auth-signature-vectors.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) < 3 {
		t.Fatal("missing cross-language vectors")
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalPayload(vector.Proof.Payload)
			if err != nil || hex.EncodeToString(canonical) != vector.CanonicalHex {
				t.Fatal("JCS bytes differ from Node vector", err)
			}
			key, err := base64.RawURLEncoding.DecodeString(vector.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			adapter := Ed25519JWSVerifier{PublicKey: key, KeyID: "auth-issuer-key", KeyVersion: "2026-09-01", Purpose: "strong_auth_issuer"}
			request := testRequest()
			request.Subject = vector.Proof.Payload.Subject
			if _, err := Verify(vector.Proof, request, testConfig(adapter)); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"payload", "value", "header", "algorithm", "key", "version", "purpose"} {
				t.Run(field, func(t *testing.T) {
					proof := vector.Proof
					badAdapter := adapter
					badRequest := request
					switch field {
					case "payload":
						proof.Payload.Subject += "tampered"
						badRequest.Subject = proof.Payload.Subject
					case "value":
						proof.Signature.Value = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
					case "header":
						proof.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
					case "algorithm":
						proof.Signature.Algorithm = "ES256"
					case "key":
						proof.Signature.KeyID = "another-key"
					case "version":
						badAdapter.KeyVersion = "other-version"
					case "purpose":
						badAdapter.Purpose = "catalog_record"
					}
					if _, err := Verify(proof, badRequest, testConfig(badAdapter)); err == nil {
						t.Fatal("accepted tampered signed input")
					}
				})
			}
		})
	}
}

func TestNonceKeySnapshotMustBeComplete(t *testing.T) {
	for _, kind := range []string{"empty_snapshot", "missing_map_version", "empty_key", "duplicate_version", "extra_map_key", "empty_version"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil }))
			switch kind {
			case "empty_snapshot":
				cfg.RequiredNonceHMACKeyVersions = nil
			case "missing_map_version":
				cfg.RequiredNonceHMACKeyVersions = append(cfg.RequiredNonceHMACKeyVersions, "retained")
			case "empty_key":
				cfg.RequiredNonceHMACKeyVersions = append(cfg.RequiredNonceHMACKeyVersions, "retained")
				cfg.NonceHMACKeys["retained"] = nil
			case "duplicate_version":
				cfg.RequiredNonceHMACKeyVersions = []string{"2026-09-01", "2026-09-01"}
				cfg.NonceHMACKeys["retained"] = []byte("synthetic")
			case "extra_map_key":
				cfg.NonceHMACKeys["unregistered"] = []byte("synthetic")
			case "empty_version":
				cfg.RequiredNonceHMACKeyVersions = append(cfg.RequiredNonceHMACKeyVersions, "")
				cfg.NonceHMACKeys[""] = []byte("synthetic")
			}
			result, err := Verify(testProof(), testRequest(), cfg)
			if err == nil || len(result.NonceHMACCandidates) != 0 {
				t.Fatal("incomplete snapshot must fail without partial candidates")
			}
		})
	}
}

func TestIssuerPolicyAndUnicodeBoundaries(t *testing.T) {
	proof := testProof()
	cfg := testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil }))
	proof.Payload.Method = "oidc_mfa"
	proof.Payload.ACR = stringPtr("urn:test:mfa")
	proof.Payload.AMR = []string{"mfa"}
	cfg.TrustedIssuerPolicies[proof.Payload.Issuer] = IssuerPolicy{Methods: []string{"oidc_mfa"}, ACR: []string{"urn:test:mfa"}, AMR: []string{"mfa"}}
	if _, err := Verify(proof, testRequest(), cfg); err != nil {
		t.Fatal(err)
	}
	proof.Payload.ACR = stringPtr("untrusted")
	if _, err := Verify(proof, testRequest(), cfg); err == nil {
		t.Fatal("untrusted ACR accepted")
	}
	proof.Payload.ACR = stringPtr("urn:test:mfa")
	proof.Payload.AMR = []string{"pwd"}
	if _, err := Verify(proof, testRequest(), cfg); err == nil {
		t.Fatal("untrusted AMR accepted")
	}
	proof = testProof()
	proof.Payload.Subject = strings.Repeat("中", 256)
	if _, err := CanonicalPayload(proof.Payload); err != nil {
		t.Fatal("schema counts Unicode characters, not bytes", err)
	}
	proof.Payload.Subject += "中"
	if _, err := CanonicalPayload(proof.Payload); err == nil {
		t.Fatal("oversized Unicode subject accepted")
	}
	proof.Payload.Subject = string([]byte{0xff})
	if _, err := CanonicalPayload(proof.Payload); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

const testHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testProof() Proof {
	return Proof{
		SchemaVersion: ProofSchemaVersion,
		Payload: ProofPayload{
			Issuer: "issuer-admin-mfa-v1", Audience: "clawmanager-admin-api", Subject: "user:42",
			Session: "session:redacted-01", AuthTime: "2026-09-20T01:00:00Z", ExpiresAt: "2026-09-20T01:05:00Z",
			Method: "webauthn", Nonce: "nonce_RedactedExample_123456", Endpoint: "registerSystemBackupProviderProof",
			RequestHash: testHash, IdempotencyKey: "idem-a-proof-20260920-0001", AMR: []string{"webauthn"},
		},
		Signature: ProofSignature{
			Format: "jws", Algorithm: "ES256", KeyID: "auth-issuer-key", KeyVersion: "2026-09-01",
			DomainSeparator: DomainSeparator, ProtectedHeader: "eyJhbGciOiJFUzI1NiJ9", Value: "c2lnbmF0dXJl",
		},
	}
}

func testConfig(verifier SignatureVerifier) VerifyConfig {
	return VerifyConfig{
		Now:                          time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC),
		MaxAge:                       10 * time.Minute,
		ClockSkew:                    30 * time.Second,
		ExpectedAudience:             "clawmanager-admin-api",
		TrustedSigners:               map[string]map[string]SignatureVerifier{"issuer-admin-mfa-v1": {"2026-09-01": verifier}},
		TrustedIssuerPolicies:        map[string]IssuerPolicy{"issuer-admin-mfa-v1": {Methods: []string{"webauthn"}, AMR: []string{"webauthn"}}},
		NonceHMACKeys:                map[string][]byte{"2026-09-01": []byte("test-hmac-key")},
		ActiveNonceHMACKeyVersion:    "2026-09-01",
		RequiredNonceHMACKeyVersions: []string{"2026-09-01"},
	}
}

func testRequest() RequestBinding {
	return RequestBinding{
		Issuer: "issuer-admin-mfa-v1", Audience: "clawmanager-admin-api", Subject: "user:42",
		Session: "session:redacted-01", Endpoint: "registerSystemBackupProviderProof", RequestHash: testHash,
		IdempotencyKey: "idem-a-proof-20260920-0001",
	}
}

func TestCanonicalPayloadIsStableAndExcludesSignatureEnvelope(t *testing.T) {
	proof := testProof()
	canonical, err := CanonicalPayload(proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"acr":null,"amr":["webauthn"],"audience":"clawmanager-admin-api","auth_time":"2026-09-20T01:00:00Z","endpoint":"registerSystemBackupProviderProof","expires_at":"2026-09-20T01:05:00Z","idempotency_key":"idem-a-proof-20260920-0001","issuer":"issuer-admin-mfa-v1","method":"webauthn","nonce":"nonce_RedactedExample_123456","request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session":"session:redacted-01","subject":"user:42"}`
	if string(canonical) != want {
		t.Fatalf("canonical payload mismatch:\n got %s\nwant %s", canonical, want)
	}
	if bytes.Contains(canonical, []byte("signature")) || bytes.Contains(canonical, []byte("schema_version")) {
		t.Fatal("signature envelope must not be part of signed payload")
	}
}

func TestVerifyAcceptsHistoricalNonceKeyAndBindsRequest(t *testing.T) {
	proof := testProof()
	var observed []byte
	config := testConfig(SignatureVerifierFunc(func(payload []byte, signature ProofSignature) error {
		observed = append([]byte(nil), payload...)
		if signature.KeyID != "auth-issuer-key" || signature.Algorithm != "ES256" {
			return errors.New("wrong signer metadata")
		}
		return nil
	}))
	config.NonceHMACKeys = map[string][]byte{"2025-12-01": []byte("old-key"), "2026-09-01": []byte("new-key")}
	config.ActiveNonceHMACKeyVersion = "2025-12-01"
	config.RequiredNonceHMACKeyVersions = []string{"2025-12-01", "2026-09-01"}
	result, err := Verify(proof, testRequest(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) == 0 || result.NonceHMAC == "" || result.NonceHMACKeyVersion != "2025-12-01" || len(result.NonceHMACCandidates) != 2 {
		t.Fatalf("expected historical nonce key result, got %#v", result)
	}
}

func TestVerifyRejectsRequestTamperingBeforeSignatureAdapter(t *testing.T) {
	called := false
	proof := testProof()
	request := testRequest()
	request.RequestHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, err := Verify(proof, request, testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error {
		called = true
		return nil
	})))
	if err == nil {
		t.Fatal("expected request binding failure")
	}
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code != FailureInvalid {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("signature adapter must not run for a request binding mismatch")
	}
}

func TestVerifyRejectsExpiredFutureAndBadIssuerProofs(t *testing.T) {
	baseConfig := testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil }))
	cases := []struct {
		name string
		edit func(*Proof, *VerifyConfig)
		code FailureCode
	}{
		{name: "expired", edit: func(p *Proof, _ *VerifyConfig) { p.Payload.ExpiresAt = "2026-09-20T01:01:00Z" }, code: FailureExpired},
		{name: "future auth", edit: func(p *Proof, _ *VerifyConfig) { p.Payload.AuthTime = "2026-09-20T01:03:00Z" }, code: FailureExpired},
		{name: "unknown issuer", edit: func(p *Proof, _ *VerifyConfig) { p.Payload.Issuer = "untrusted" }, code: FailureInvalidIssuer},
		{name: "wrong domain", edit: func(p *Proof, _ *VerifyConfig) { p.Signature.DomainSeparator = "clawmanager.system-backup.other.v1" }, code: FailureInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			proof := testProof()
			config := baseConfig
			testCase.edit(&proof, &config)
			_, err := Verify(proof, testRequest(), config)
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) || verificationErr.Code != testCase.code {
				t.Fatalf("expected %s, got %v", testCase.code, err)
			}
		})
	}
}

func TestVerifyRejectsWebAuthnWithoutMethodEvidence(t *testing.T) {
	proof := testProof()
	proof.Payload.AMR = []string{"totp"}
	_, err := Verify(proof, testRequest(), testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil })))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("strong_auth_invalid")) {
		t.Fatalf("expected fail-closed method validation, got %v", err)
	}
}

func TestVerifyRejectsWireValuesOutsideSchema(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Proof)
	}{
		{name: "missing amr", edit: func(proof *Proof) { proof.Payload.AMR = nil }},
		{name: "duplicate amr", edit: func(proof *Proof) { proof.Payload.AMR = []string{"webauthn", "webauthn"} }},
		{name: "invalid endpoint", edit: func(proof *Proof) { proof.Payload.Endpoint = "register-provider-proof" }},
		{name: "short idempotency key", edit: func(proof *Proof) { proof.Payload.IdempotencyKey = "short" }},
		{name: "missing algorithm", edit: func(proof *Proof) { proof.Signature.Algorithm = "" }},
		{name: "oversized signature", edit: func(proof *Proof) { proof.Signature.Value = string(bytes.Repeat([]byte{'a'}, 4097)) }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			proof := testProof()
			testCase.edit(&proof)
			_, err := Verify(proof, testRequest(), testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil })))
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) || verificationErr.Code != FailureInvalid {
				t.Fatalf("expected fail-closed wire validation, got %v", err)
			}
		})
	}
}
