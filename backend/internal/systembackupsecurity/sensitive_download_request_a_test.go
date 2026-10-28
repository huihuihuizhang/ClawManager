package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/sensitive_download_request_vectors.json
var sensitiveDownloadVectors []byte

func sensitiveDownloadFacts() SensitiveDownloadRequestFacts {
	return SensitiveDownloadRequestFacts{Installation: "installation_test", EvidenceID: "sev_11111111-2222-4333-8444-555555555555",
		Actor:          RegistrationActor{UserID: 42, Subject: "user:42", Session: strings.Repeat("a", 64)},
		ManifestSHA256: strings.Repeat("b", 64), IdempotencyKey: "download_key_0123456789", ContentSize: 100, RangeEnd: 99}
}

func TestSensitiveDownloadRequestIndependentVectors(t *testing.T) {
	var data struct {
		Vectors []struct {
			Name  string `json:"name"`
			Size  int64  `json:"content_size"`
			Key   string `json:"idempotency_key"`
			Input struct {
				Installation string `json:"origin_installation_id"`
				Evidence     string `json:"evidence_id"`
				Subject      string `json:"subject"`
				Session      string `json:"session"`
				Manifest     string `json:"manifest_sha256"`
				Present      bool   `json:"range_present"`
				Start        int64  `json:"range_start"`
				End          int64  `json:"range_end"`
			} `json:"input"`
			Canonical string `json:"canonical_utf8"`
			Hash      string `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(sensitiveDownloadVectors, &data); err != nil || len(data.Vectors) != 5 {
		t.Fatal("invalid independent vector fixture")
	}
	for _, v := range data.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			f := SensitiveDownloadRequestFacts{Installation: v.Input.Installation, EvidenceID: v.Input.Evidence, ManifestSHA256: v.Input.Manifest, IdempotencyKey: v.Key,
				Actor: RegistrationActor{UserID: 42, Subject: v.Input.Subject, Session: v.Input.Session}, ContentSize: v.Size, RangePresent: v.Input.Present, RangeStart: v.Input.Start, RangeEnd: v.Input.End}
			r, err := NewSensitiveDownloadRequest(f)
			if err != nil || string(r.CanonicalJSON()) != v.Canonical || r.RequestHash() != v.Hash {
				t.Fatal("canonical/hash differs from independent Node vector", err)
			}
			copy := r.CanonicalJSON()
			copy[0] = '!'
			if string(r.CanonicalJSON()) != v.Canonical {
				t.Fatal("caller changed immutable request")
			}
		})
	}
}

func TestSensitiveDownloadRequestRejectsInvalidFacts(t *testing.T) {
	cases := map[string]func(*SensitiveDownloadRequestFacts){
		"installation":   func(f *SensitiveDownloadRequestFacts) { f.Installation = "installation_../other" },
		"evidence":       func(f *SensitiveDownloadRequestFacts) { f.EvidenceID = "sbk_11111111-2222-4333-8444-555555555555" },
		"subject":        func(f *SensitiveDownloadRequestFacts) { f.Actor.Subject = "user:43" },
		"unicode":        func(f *SensitiveDownloadRequestFacts) { f.Actor.Subject = string([]byte{0xff}) },
		"user":           func(f *SensitiveDownloadRequestFacts) { f.Actor.UserID = 0 },
		"session":        func(f *SensitiveDownloadRequestFacts) { f.Actor.Session = "raw-bearer" },
		"manifest":       func(f *SensitiveDownloadRequestFacts) { f.ManifestSHA256 = strings.Repeat("B", 64) },
		"key":            func(f *SensitiveDownloadRequestFacts) { f.IdempotencyKey = "bad key" },
		"negative":       func(f *SensitiveDownloadRequestFacts) { f.RangeStart = -1 },
		"reversed":       func(f *SensitiveDownloadRequestFacts) { f.RangeStart = 99; f.RangeEnd = 98 },
		"past-size":      func(f *SensitiveDownloadRequestFacts) { f.RangeEnd = 100 },
		"absent-partial": func(f *SensitiveDownloadRequestFacts) { f.RangeStart = 1 },
		"unsafe-number":  func(f *SensitiveDownloadRequestFacts) { f.ContentSize = 9007199254740992 },
		"empty-range":    func(f *SensitiveDownloadRequestFacts) { f.ContentSize = 0; f.RangeEnd = 0; f.RangePresent = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := sensitiveDownloadFacts()
			mutate(&f)
			r, err := NewSensitiveDownloadRequest(f)
			if err == nil || r.RequestHash() != "" || len(r.CanonicalJSON()) != 0 {
				t.Fatal("invalid facts returned binding")
			}
		})
	}
	if _, err := (SensitiveDownloadRequest{}).ProofBinding("issuer"); err == nil {
		t.Fatal("zero binding accepted")
	}
}

func sensitiveDownloadSignedFixture(t *testing.T) (SensitiveDownloadRequest, Proof, VerifyConfig) {
	t.Helper()
	r, err := NewSensitiveDownloadRequest(sensitiveDownloadFacts())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := r.ProofBinding("issuer-download")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	proof := Proof{SchemaVersion: ProofSchemaVersion, Payload: ProofPayload{Issuer: binding.Issuer, Audience: binding.Audience, Subject: binding.Subject, Session: binding.Session,
		Endpoint: binding.Endpoint, RequestHash: binding.RequestHash, IdempotencyKey: binding.IdempotencyKey, AuthTime: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), Method: "totp", AMR: []string{"pwd", "otp"}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	verifier := Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "key-download", KeyVersion: "v1", Purpose: "strong_auth_issuer"}
	header := `{"alg":"EdDSA","key_version":"v1","kid":"key-download","purpose":"strong_auth_issuer","typ":"` + DomainSeparator + `"}`
	proof.Signature = ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: verifier.KeyID, KeyVersion: verifier.KeyVersion, DomainSeparator: DomainSeparator, ProtectedHeader: base64.RawURLEncoding.EncodeToString([]byte(header))}
	payload, err := CanonicalPayload(proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	cfg := VerifyConfig{Now: now, MaxAge: 5 * time.Minute, ExpectedAudience: binding.Audience, ExpectedSubject: binding.Subject, ExpectedSession: binding.Session,
		TrustedSigners: map[string]map[string]SignatureVerifier{binding.Issuer: {"v1": verifier}}, TrustedIssuerPolicies: map[string]IssuerPolicy{binding.Issuer: {Methods: []string{"totp"}, AMR: []string{"pwd", "otp"}}},
		NonceHMACKeys: map[string][]byte{"v1": bytes.Repeat([]byte{0x11}, 32), "v2": bytes.Repeat([]byte{0x22}, 32)}, RequiredNonceHMACKeyVersions: []string{"v2", "v1"}, ActiveNonceHMACKeyVersion: "v2"}
	return r, proof, cfg
}

func TestSensitiveDownloadProofHistoricalCandidatesAndOriginalTime(t *testing.T) {
	r, p, cfg := sensitiveDownloadSignedFixture(t)
	v, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cs := v.NonceCandidates()
	if len(cs) != 2 || cs[0].KeyVersion != "v1" || cs[1].KeyVersion != "v2" || v.ActiveNonce() != cs[1] {
		t.Fatal("incomplete/unsorted retained candidate set")
	}
	for _, c := range cs {
		mac := hmac.New(sha256.New, cfg.NonceHMACKeys[c.KeyVersion])
		mac.Write([]byte(p.Payload.Nonce))
		if c.HMAC != hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("wrong HMAC candidate")
		}
	}
	cs[0].HMAC = "changed"
	if v.NonceCandidates()[0].HMAC == "changed" {
		t.Fatal("caller changed candidate snapshot")
	}
	if _, err := json.Marshal(v); err == nil {
		t.Fatal("ephemeral verification serialized as a receipt")
	}
	if err := v.RecheckProofAt(cfg.Now.Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{{}, cfg.Now.Add(-time.Nanosecond), v.ProofExpiresAt()} {
		if err := v.RecheckProofAt(now); err == nil {
			t.Fatal("zero/regressed/expired SQL time accepted")
		}
	}
	again, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
	if err != nil || again.ActiveNonce() != v.ActiveNonce() {
		t.Fatal("pure verification unexpectedly consumed nonce")
	}
}

func TestSensitiveDownloadProofRejectsScopeSubstitution(t *testing.T) {
	for _, field := range []string{"installation", "evidence", "session", "subject", "manifest", "range", "range-presence", "key", "issuer", "signature"} {
		t.Run(field, func(t *testing.T) {
			_, p, cfg := sensitiveDownloadSignedFixture(t)
			f := sensitiveDownloadFacts()
			issuer := p.Payload.Issuer
			switch field {
			case "installation":
				f.Installation = "installation_other"
			case "evidence":
				f.EvidenceID = "sev_aaaaaaaa-2222-4333-8444-555555555555"
			case "session":
				f.Actor.Session = strings.Repeat("c", 64)
			case "subject":
				f.Actor.UserID = 43
				f.Actor.Subject = "user:43"
			case "manifest":
				f.ManifestSHA256 = strings.Repeat("c", 64)
			case "range":
				f.RangePresent = true
				f.RangeStart = 1
			case "range-presence":
				f.RangePresent = true
			case "key":
				f.IdempotencyKey = "other_key_0123456789"
			case "issuer":
				issuer = "issuer-other"
			case "signature":
				p.Signature.Value = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			}
			r, err := NewSensitiveDownloadRequest(f)
			if err != nil {
				t.Fatal(err)
			}
			cfg.ExpectedAudience = f.Installation
			cfg.ExpectedSubject = f.Actor.Subject
			cfg.ExpectedSession = f.Actor.Session
			v, err := r.VerifyProof(p, issuer, cfg)
			if err == nil || len(v.NonceCandidates()) != 0 || v.ActiveNonce().HMAC != "" {
				t.Fatal("substitution returned nonce candidates")
			}
		})
	}
}

func TestSensitiveDownloadProofRejectsMissingMaterial(t *testing.T) {
	for _, kind := range []string{"empty", "duplicate", "unresolved", "extra", "weak-key", "missing-active", "zero-clock", "missing-principal", "nil-signature-verifier", "typed-nil-signature-verifier", "typed-nil-signature-pointer", "missing-issuer-map"} {
		t.Run(kind, func(t *testing.T) {
			r, p, cfg := sensitiveDownloadSignedFixture(t)
			switch kind {
			case "empty":
				cfg.RequiredNonceHMACKeyVersions = nil
			case "duplicate":
				cfg.RequiredNonceHMACKeyVersions = []string{"v1", "v1"}
			case "unresolved":
				cfg.RequiredNonceHMACKeyVersions = []string{"v1", "v3"}
			case "extra":
				cfg.NonceHMACKeys["v3"] = make([]byte, 32)
			case "weak-key":
				cfg.NonceHMACKeys["v1"] = []byte{1}
			case "missing-active":
				cfg.ActiveNonceHMACKeyVersion = "v3"
			case "zero-clock":
				cfg.Now = time.Time{}
			case "missing-principal":
				cfg.ExpectedSubject = ""
			case "nil-signature-verifier":
				cfg.TrustedSigners[p.Payload.Issuer]["v1"] = nil
			case "typed-nil-signature-verifier":
				cfg.TrustedSigners[p.Payload.Issuer]["v1"] = SignatureVerifierFunc(nil)
			case "typed-nil-signature-pointer":
				cfg.TrustedSigners[p.Payload.Issuer]["v1"] = (*Ed25519JWSVerifier)(nil)
			case "missing-issuer-map":
				cfg.TrustedSigners[p.Payload.Issuer] = nil
			}
			v, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
			if !errors.Is(err, ErrRegistrationUnavailable) || len(v.NonceCandidates()) != 0 {
				t.Fatal("missing authoritative material treated as valid/client proof")
			}
		})
	}
}

func TestSensitiveDownloadProofFreezesMaterialBeforeVerifierCallback(t *testing.T) {
	r, p, cfg := sensitiveDownloadSignedFixture(t)
	original := append([]byte(nil), cfg.NonceHMACKeys["v1"]...)
	real := cfg.TrustedSigners[p.Payload.Issuer]["v1"]
	cfg.TrustedSigners[p.Payload.Issuer]["v1"] = SignatureVerifierFunc(func(raw []byte, s ProofSignature) error {
		cfg.NonceHMACKeys["v1"][0] ^= 0xff
		return real.Verify(raw, s)
	})
	v, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, original)
	mac.Write([]byte(p.Payload.Nonce))
	if v.NonceCandidates()[0].HMAC != hex.EncodeToString(mac.Sum(nil)) || bytes.Equal(cfg.NonceHMACKeys["v2"], make([]byte, 32)) {
		t.Fatal("callback changed nonce snapshot or owned cleanup erased caller material")
	}
}
