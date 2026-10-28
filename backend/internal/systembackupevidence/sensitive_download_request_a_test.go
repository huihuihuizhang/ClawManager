package systembackupevidence

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

//go:embed testdata/sensitive_download_manifest_vector.json
var sensitiveDownloadManifestVector []byte

func sensitiveDownloadManifestFixture(t *testing.T) (Manifest, http.Header) {
	t.Helper()
	var v struct {
		Manifest Manifest `json:"manifest"`
		Key      string   `json:"idempotency_key"`
	}
	if json.Unmarshal(sensitiveDownloadManifestVector, &v) != nil || validateManifest(v.Manifest) != nil {
		t.Fatal("invalid independent Manifest vector")
	}
	return v.Manifest, http.Header{"Idempotency-Key": []string{v.Key}}
}

func sensitiveDownloadActor() systembackupsecurity.RegistrationActor {
	return systembackupsecurity.RegistrationActor{UserID: 42, Subject: "user:42", Session: strings.Repeat("a", 64)}
}

func TestSensitiveDownloadManifestIndependentCanonical(t *testing.T) {
	m, h := sensitiveDownloadManifestFixture(t)
	var v struct {
		ManifestJSON string `json:"manifest_canonical_utf8"`
		ManifestSHA  string `json:"manifest_sha256"`
		RequestJSON  string `json:"request_canonical_utf8"`
		RequestSHA   string `json:"request_sha256"`
	}
	if json.Unmarshal(sensitiveDownloadManifestVector, &v) != nil {
		t.Fatal("invalid vector")
	}
	r, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
	if err != nil || string(canonical(m)) != v.ManifestJSON || r.ManifestSHA256() != v.ManifestSHA || string(r.CanonicalJSON()) != v.RequestJSON || r.RequestHash() != v.RequestSHA {
		t.Fatal("full Manifest/request differs from independent Node JCS/SHA", err)
	}
	if r.ManifestSHA256() == m.Identity.ContentHash {
		t.Fatal("bound content hash instead of the complete Manifest")
	}
	before := r.RequestHash()
	m.Chunks[0].PlainHash = strings.Repeat("f", 64)
	if r.RequestHash() != before {
		t.Fatal("caller changed previously bound Manifest snapshot")
	}
}

func TestSensitiveDownloadRangeNormalizationAndPresence(t *testing.T) {
	m, h := sensitiveDownloadManifestFixture(t)
	var digest string
	for _, value := range []string{"bytes=8190-8192", "bytes=8190-", "bytes=-3", "bytes=8190-999999"} {
		t.Run(value, func(t *testing.T) {
			header := h.Clone()
			header.Set("Range", value)
			r, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, header)
			if err != nil {
				t.Fatal(err)
			}
			start, end, present := r.Range()
			if start != 8190 || end != 8192 || !present {
				t.Fatal("incorrect normalized range")
			}
			if digest == "" {
				digest = r.RequestHash()
			} else if r.RequestHash() != digest {
				t.Fatal("equivalent ranges hash differently")
			}
		})
	}
	absent, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
	if err != nil {
		t.Fatal(err)
	}
	h.Set("Range", "bytes=0-")
	full, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
	if err != nil || full.RequestHash() == absent.RequestHash() {
		t.Fatal("explicit full Range lost its HTTP 206 distinction")
	}
}

func TestSensitiveDownloadRejectsMalformedHeadersAndRanges(t *testing.T) {
	for _, kind := range []string{"missing-key", "duplicate-key", "mixed-case-key", "bad-key", "empty-range", "nil-range", "multiple-range-headers", "mixed-case-range", "multiple-ranges", "negative", "overflow", "unsafe-clamped-end", "unsafe-clamped-suffix", "out-of-bounds", "invalid-unicode", "duplicate-proof", "mixed-case-proof"} {
		t.Run(kind, func(t *testing.T) {
			m, h := sensitiveDownloadManifestFixture(t)
			switch kind {
			case "missing-key":
				h.Del("Idempotency-Key")
			case "duplicate-key":
				h.Add("Idempotency-Key", "second_key_0123456789")
			case "mixed-case-key":
				h["idempotency-key"] = []string{"second_key_0123456789"}
			case "bad-key":
				h.Set("Idempotency-Key", "bad key")
			case "empty-range":
				h.Set("Range", "")
			case "nil-range":
				h["Range"] = nil
			case "multiple-range-headers":
				h["Range"] = []string{"bytes=0-1", "bytes=2-3"}
			case "mixed-case-range":
				h.Set("Range", "bytes=0-1")
				h["range"] = []string{"bytes=2-3"}
			case "multiple-ranges":
				h.Set("Range", "bytes=0-1,2-3")
			case "negative":
				h.Set("Range", "bytes=-0")
			case "overflow":
				h.Set("Range", "bytes=9223372036854775808-")
			case "out-of-bounds":
				h.Set("Range", "bytes=8193-")
			case "invalid-unicode":
				h.Set("Range", string([]byte{0xff}))
			case "duplicate-proof":
				h[systembackupsecurity.StrongAuthProofHeader] = []string{"one", "two"}
			case "mixed-case-proof":
				h[systembackupsecurity.StrongAuthProofHeader] = []string{"one"}
				h["x-strong-auth-proof"] = []string{"two"}
			}
			if kind == "unsafe-clamped-end" {
				h.Set("Range", "bytes=0-9007199254740992")
			}
			if kind == "unsafe-clamped-suffix" {
				h.Set("Range", "bytes=-9007199254740992")
			}
			r, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
			if err == nil || r.RequestHash() != "" {
				t.Fatal("malformed transport returned a binding")
			}
		})
	}
}

func TestSensitiveDownloadBindsEveryManifestComponent(t *testing.T) {
	for _, field := range []string{"classification", "owner", "content-hash", "kek", "envelope", "object", "chunk"} {
		t.Run(field, func(t *testing.T) {
			m, h := sensitiveDownloadManifestFixture(t)
			old, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "classification":
				m.Identity.Classification = "confidential"
			case "owner":
				m.Identity.OwnerID = "sbk_aaaaaaaa-2222-4333-8444-555555555555"
			case "content-hash":
				m.Identity.ContentHash = strings.Repeat("f", 64)
			case "kek":
				m.Key.Version = "v2"
			case "envelope":
				m.EnvelopeHash = strings.Repeat("f", 64)
			case "object":
				m.ObjectHash = strings.Repeat("f", 64)
			case "chunk":
				m.Chunks[0].PlainHash = strings.Repeat("f", 64)
				m.ChunkRoot = hash(canonical(m.Chunks))
			}
			next, err := BindSensitiveDownloadRequest(sensitiveDownloadActor(), m, h)
			if err != nil || old.RequestHash() == next.RequestHash() || old.ManifestSHA256() == next.ManifestSHA256() {
				t.Fatal("changed Manifest component not signed", err)
			}
		})
	}
}

func TestSensitiveDownloadRejectsUnsupportedManifestProfiles(t *testing.T) {
	for _, kind := range []string{"public", "invalid-chunk-root", "empty-content", "invalid-actor"} {
		t.Run(kind, func(t *testing.T) {
			m, h := sensitiveDownloadManifestFixture(t)
			actor := sensitiveDownloadActor()
			switch kind {
			case "public":
				m.Identity.Classification = "public"
			case "invalid-chunk-root":
				m.ChunkRoot = strings.Repeat("f", 64)
			case "empty-content":
				m.Identity.ContentSize = 0
			case "invalid-actor":
				actor.Subject = "user:43"
			}
			r, err := BindSensitiveDownloadRequest(actor, m, h)
			if err == nil || r.RequestHash() != "" {
				t.Fatal("unsupported/invalid Manifest returned binding")
			}
		})
	}
	// Record the real current parser behavior instead of changing a production
	// envelope/profile to fit the new decision's mistaken "existing 0/0" claim.
	start, end, present, err := parseRange("", 0)
	if err != nil || start != 0 || end != -1 || present {
		t.Fatal("empty parser premise changed; review contract/profile together")
	}
}

func TestSensitiveDownloadHeaderPreflightFailsClosed(t *testing.T) {
	m, h := sensitiveDownloadManifestFixture(t)
	v, err := VerifySensitiveDownloadRequestHeader(sensitiveDownloadActor(), m, h, "issuer", systembackupsecurity.VerifyConfig{})
	var missing *systembackupsecurity.VerificationError
	if !errors.As(err, &missing) || missing.Code != systembackupsecurity.FailureRequired || len(v.NonceCandidates()) != 0 {
		t.Fatal("missing proof did not return required without nonce results")
	}
	for _, raw := range []string{"not base64", base64.StdEncoding.EncodeToString([]byte(`{"extra":"PRIVATE_RAW_NONCE"}`))} {
		t.Run(raw, func(t *testing.T) {
			h.Set(systembackupsecurity.StrongAuthProofHeader, raw)
			v, err := VerifySensitiveDownloadRequestHeader(sensitiveDownloadActor(), m, h, "issuer", systembackupsecurity.VerifyConfig{})
			if !errors.Is(err, ErrInvalid) || len(v.NonceCandidates()) != 0 || strings.Contains(err.Error(), "PRIVATE_RAW_NONCE") {
				t.Fatal("malformed proof returned results or private text")
			}
		})
	}
}

func TestSensitiveDownloadSignedHeaderRoundTripAndSubstitution(t *testing.T) {
	m, h := sensitiveDownloadManifestFixture(t)
	actor := sensitiveDownloadActor()
	r, err := BindSensitiveDownloadRequest(actor, m, h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.ProofBinding("issuer-download")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	proof := systembackupsecurity.Proof{SchemaVersion: systembackupsecurity.ProofSchemaVersion, Payload: systembackupsecurity.ProofPayload{
		Issuer: b.Issuer, Audience: b.Audience, Subject: b.Subject, Session: b.Session, Endpoint: b.Endpoint, RequestHash: b.RequestHash, IdempotencyKey: b.IdempotencyKey,
		AuthTime: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), Method: "totp", AMR: []string{"pwd", "otp"}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	verifier := systembackupsecurity.Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "key-download", KeyVersion: "v1", Purpose: "strong_auth_issuer"}
	protected := `{"alg":"EdDSA","key_version":"v1","kid":"key-download","purpose":"strong_auth_issuer","typ":"` + systembackupsecurity.DomainSeparator + `"}`
	proof.Signature = systembackupsecurity.ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: verifier.KeyID, KeyVersion: verifier.KeyVersion, DomainSeparator: systembackupsecurity.DomainSeparator, ProtectedHeader: base64.RawURLEncoding.EncodeToString([]byte(protected))}
	payload, err := systembackupsecurity.CanonicalPayload(proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	h.Set(systembackupsecurity.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
	cfg := systembackupsecurity.VerifyConfig{Now: now, MaxAge: 5 * time.Minute, ExpectedAudience: b.Audience, ExpectedSubject: b.Subject, ExpectedSession: b.Session,
		TrustedSigners: map[string]map[string]systembackupsecurity.SignatureVerifier{b.Issuer: {"v1": verifier}}, TrustedIssuerPolicies: map[string]systembackupsecurity.IssuerPolicy{b.Issuer: {Methods: []string{"totp"}, AMR: []string{"pwd", "otp"}}},
		NonceHMACKeys: map[string][]byte{"v1": bytes.Repeat([]byte{0x11}, 32), "v2": bytes.Repeat([]byte{0x22}, 32)}, RequiredNonceHMACKeyVersions: []string{"v1", "v2"}, ActiveNonceHMACKeyVersion: "v2"}
	v, err := VerifySensitiveDownloadRequestHeader(actor, m, h, b.Issuer, cfg)
	if err != nil || v.Request().RequestHash() != r.RequestHash() || len(v.NonceCandidates()) != 2 || v.ActiveNonce().KeyVersion != "v2" {
		t.Fatal("signed issuance/consumption input diverged", err)
	}
	for _, kind := range []string{"manifest", "range", "session", "key", "signature", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			manifest := m
			headers := h.Clone()
			currentActor := actor
			currentCfg := cfg
			switch kind {
			case "manifest":
				manifest.ObjectHash = strings.Repeat("f", 64)
			case "range":
				headers.Set("Range", "bytes=1-2")
			case "session":
				currentActor.Session = strings.Repeat("c", 64)
				currentCfg.ExpectedSession = currentActor.Session
			case "key":
				headers.Set("Idempotency-Key", "second_key_0123456789")
			case "signature":
				bad := proof
				bad.Signature.Value = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				body, _ := json.Marshal(bad)
				headers.Set(systembackupsecurity.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(body))
			case "unknown-field":
				body := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
				headers.Set(systembackupsecurity.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(body))
			}
			got, err := VerifySensitiveDownloadRequestHeader(currentActor, manifest, headers, b.Issuer, currentCfg)
			if err == nil || len(got.NonceCandidates()) != 0 || got.ActiveNonce().HMAC != "" {
				t.Fatal("changed request/proof returned verified candidates")
			}
		})
	}
}
