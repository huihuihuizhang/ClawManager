package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProviderNodeSignedInteroperabilityVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name         string
			Scope        ProviderProofScope
			Registration ProviderProofRegistration
			PublicKey    string `json:"public_key_base64"`
			PayloadHex   string `json:"canonical_payload_utf8_hex"`
		}
	}
	if err := json.Unmarshal(readContractFixture(t, "a-provider-proof-signature-vectors.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 3 {
		t.Fatal("missing interop vectors")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, c, _ := providerSignedFixture(t)
			c.Scope = v.Scope
			c.Binding = providerTestBinding(v.Registration)
			pub, err := base64.StdEncoding.DecodeString(v.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			c.Keys[0].PublicKey = pub
			payload, err := ProviderProofPayload(c.Scope, v.Registration.Target, v.Registration.Proof)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.PayloadHex)
			if err != nil || !bytes.Equal(want, payload) {
				t.Fatal("Node/Go canonical bytes differ", err)
			}
			if _, err = PrepareProviderProofEvidence(v.Registration, c); err != nil {
				t.Fatal("Node signature rejected", err)
			}
		})
	}
}

func providerSignedFixture(t *testing.T) (ProviderProofRegistration, ProviderProofRegistrationContext, ed25519.PrivateKey) {
	t.Helper()
	r := testProviderRegistration()
	now := time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC)
	// Public synthetic test key, never a deployed issuer.
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	c := ProviderProofRegistrationContext{Scope: ProviderProofScope{InstallationID: "installation_synthetic", Audience: "system-backup-provider-proof"},
		DatabaseNow: now, MaxAge: 5 * time.Minute, RegistryVersion: "synthetic-v1", RegistrySHA256: strings.Repeat("a", 64), RetainUntil: now.Add(24 * time.Hour),
		Keys: []ProviderProofKey{{Issuer: r.Proof.Issuer, KeyID: "synthetic-provider-key", KeyVersion: "v1", Purpose: "provider_proof_issuer", PublicKey: key.Public().(ed25519.PublicKey),
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), TargetTypes: []string{"external_action", "backup_staging", "restore_resource"}, ProofTypes: []string{"provider_presence", "provider_absence", "ownership"}}}}
	c.Binding = providerTestBinding(r)
	providerResign(t, &r, c, key)
	return r, c, key
}
func providerTestBinding(r ProviderProofRegistration) ProviderProofBinding {
	p := r.Proof
	return ProviderProofBinding{Target: r.Target, RowVersion: r.ExpectedRowVersion, Issuer: p.Issuer, ProofType: p.ProofType, ProviderIdentityHash: p.ProviderIdentityHash,
		LocationHash: p.LocationHash, ObservedState: p.ObservedState, ActionKeyHash: p.ActionKeyHash, ResourceUID: p.ResourceUID, ResourceVersion: p.ResourceVersion,
		ObservedVersion: p.ObservedVersion, ObservedChecksum: p.ObservedChecksum, ContentLength: p.ContentLength}
}
func providerResign(t *testing.T, r *ProviderProofRegistration, c ProviderProofRegistrationContext, key ed25519.PrivateKey) {
	t.Helper()
	input, err := ProviderProofSigningInput(c.Scope, r.Target, r.Proof, c.Keys[0].KeyID, c.Keys[0].KeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	r.Proof.SignedProofBase64, err = EncodeProviderProof(c.Scope, r.Target, r.Proof, c.Keys[0].KeyID, c.Keys[0].KeyVersion, ed25519.Sign(key, input))
	if err != nil {
		t.Fatal(err)
	}
}
func providerWantCode(t *testing.T, err error, code ProviderFailureCode) {
	t.Helper()
	var typed *ProviderProofError
	if !errors.As(err, &typed) || typed.Code != code || errors.Unwrap(err) != nil {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestProviderEd25519AndPreparedEvidence(t *testing.T) {
	r, c, _ := providerSignedFixture(t)
	p, err := PrepareProviderProofEvidence(r, c)
	if err != nil {
		t.Fatal(err)
	}
	if !p.prepared || p.evidenceType != "provider_presence_proof" || p.ContentSize() < 100 || p.ContentSize() > 8192 || len(p.ContentSHA256()) != 64 || len(p.RequestSHA256()) != 64 {
		t.Fatal("invalid inline projection")
	}
	if p.retainUntil.Equal(p.validUntil) {
		t.Fatal("retention must not be proof validity")
	}
}

func TestProviderRequestDigestDistinguishesIdempotencyConflicts(t *testing.T) {
	r, c, key := providerSignedFixture(t)
	p, err := PrepareProviderProofEvidence(r, c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareProviderProofEvidence(r, c)
	if err != nil || again.RequestSHA256() != p.RequestSHA256() {
		t.Fatal("unstable request fingerprint", err)
	}
	r.Proof.ExpiresAt = "2026-09-20T01:04:00Z"
	providerResign(t, &r, c, key)
	changed, err := PrepareProviderProofEvidence(r, c)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RequestSHA256() == p.RequestSHA256() {
		t.Fatal("changed proof collided under the same idempotency key")
	}
}

func TestProviderRequestAndProofByteLimits(t *testing.T) {
	r, _, _ := providerSignedFixture(t)
	raw, _ := json.Marshal(r)
	boundary := append(append([]byte(nil), raw...), []byte(strings.Repeat(" ", 16384-len(raw)))...)
	if _, err := DecodeProviderProofRegistration(boundary); err != nil {
		t.Fatal("16 KiB request rejected", err)
	}
	if _, err := DecodeProviderProofRegistration(append(boundary, ' ')); err == nil {
		t.Fatal("oversized request accepted")
	}
	r.Proof.SignedProofBase64 = base64.StdEncoding.EncodeToString(make([]byte, 8192))
	if _, err := ProviderProofRequestSHA256(r); err != nil {
		t.Fatal("8 KiB opaque proof cannot be fingerprinted", err)
	}
	r.Proof.SignedProofBase64 = base64.StdEncoding.EncodeToString(make([]byte, 8193))
	if _, err := ProviderProofRequestSHA256(r); err == nil {
		t.Fatal("oversized proof fingerprinted")
	}
	r, _, _ = providerSignedFixture(t)
	r.Proof.ContentLength = int64Ptr(9007199254740992)
	if _, err := ProviderProofRequestSHA256(r); err == nil {
		t.Fatal("unsafe integer accepted")
	}
}

func TestProviderSignedEnvelopeMutations(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*ProviderProofRegistration)
	}{
		{"location", func(r *ProviderProofRegistration) { r.Proof.LocationHash = strings.Repeat("f", 64) }},
		{"length", func(r *ProviderProofRegistration) { r.Proof.ContentLength = int64Ptr(8) }},
		{"state", func(r *ProviderProofRegistration) { r.Proof.ObservedState = "present_unsealed" }},
		{"checksum", func(r *ProviderProofRegistration) { r.Proof.ObservedChecksum = stringPtr(strings.Repeat("f", 64)) }},
		{"target", func(r *ProviderProofRegistration) {
			r.Target.TargetPublicID = "sxa_22222222-2222-4222-8222-222222222222"
		}},
		{"expiry", func(r *ProviderProofRegistration) { r.Proof.ExpiresAt = "2026-09-20T01:04:00Z" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c, _ := providerSignedFixture(t)
			tc.edit(&r)
			c.Binding = providerTestBinding(r)
			_, err := PrepareProviderProofEvidence(r, c)
			providerWantCode(t, err, ProviderChecksumMismatch)
		})
	}
}

func TestProviderTrustAndScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*ProviderProofRegistrationContext)
		code ProviderFailureCode
	}{
		{"audience", func(c *ProviderProofRegistrationContext) { c.Scope.Audience = "different" }, ProviderChecksumMismatch},
		{"installation", func(c *ProviderProofRegistrationContext) { c.Scope.InstallationID = "installation_other" }, ProviderChecksumMismatch},
		{"issuer", func(c *ProviderProofRegistrationContext) { c.Keys[0].Issuer = "other" }, ProviderValidationFailed},
		{"version", func(c *ProviderProofRegistrationContext) { c.Keys[0].KeyVersion = "v2" }, ProviderValidationFailed},
		{"purpose", func(c *ProviderProofRegistrationContext) { c.Keys[0].Purpose = "capture_certificate" }, ProviderValidationFailed},
		{"revoked", func(c *ProviderProofRegistrationContext) { c.Keys[0].Revoked = true }, ProviderValidationFailed},
		{"expiry", func(c *ProviderProofRegistrationContext) { c.DatabaseNow = c.DatabaseNow.Add(2 * time.Minute) }, ProviderValidationFailed},
		{"key-expiry", func(c *ProviderProofRegistrationContext) { c.Keys[0].NotAfter = c.DatabaseNow }, ProviderValidationFailed},
		{"target-scope", func(c *ProviderProofRegistrationContext) { c.Keys[0].TargetTypes = []string{"restore_resource"} }, ProviderValidationFailed},
		{"row-version", func(c *ProviderProofRegistrationContext) { c.Binding.RowVersion++ }, ProviderVersionConflict},
		{"stored-checksum", func(c *ProviderProofRegistrationContext) {
			c.Binding.ObservedChecksum = stringPtr(strings.Repeat("f", 64))
		}, ProviderChecksumMismatch},
		{"no-db-time", func(c *ProviderProofRegistrationContext) { c.DatabaseNow = time.Time{} }, ProviderValidationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c, _ := providerSignedFixture(t)
			tc.edit(&c)
			_, err := PrepareProviderProofEvidence(r, c)
			providerWantCode(t, err, tc.code)
		})
	}
}

func TestProviderSignatureAndClosedEncoding(t *testing.T) {
	for _, name := range []string{"signature", "header", "duplicate", "extra", "whitespace"} {
		t.Run(name, func(t *testing.T) {
			r, c, _ := providerSignedFixture(t)
			raw, _ := base64.StdEncoding.DecodeString(r.Proof.SignedProofBase64)
			var doc providerSignedDocument
			_ = json.Unmarshal(raw, &doc)
			switch name {
			case "signature":
				doc.Signature.Value = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				raw = providerDocument(doc.Payload, doc.Signature)
			case "header":
				doc.Signature.Algorithm = "none"
				raw = providerDocument(doc.Payload, doc.Signature)
			case "duplicate":
				raw = append([]byte(`{"payload":{},`), raw[1:]...)
			case "extra":
				raw = append([]byte(`{"secret":"SYNTHETIC_PRIVATE",`), raw[1:]...)
			case "whitespace":
				raw = append([]byte(" "), raw...)
			}
			r.Proof.SignedProofBase64 = base64.StdEncoding.EncodeToString(raw)
			_, err := PrepareProviderProofEvidence(r, c)
			providerWantCode(t, err, ProviderSignatureInvalid)
		})
	}
}

func TestProviderSnapshotCopiesAndHistoricalKey(t *testing.T) {
	r, c, _ := providerSignedFixture(t)
	v, err := NewProviderEd25519Verifier(c.Scope, c.DatabaseNow, c.Keys)
	if err != nil {
		t.Fatal(err)
	}
	c.Keys[0].PublicKey[0] ^= 255
	c.Keys[0].TargetTypes[0] = "invalid"
	raw, _ := base64.StdEncoding.DecodeString(r.Proof.SignedProofBase64)
	if err = v.Verify(r.Target, r.Proof, raw); err != nil {
		t.Fatal("snapshot mutated", err)
	}
	r, c, _ = providerSignedFixture(t)
	next := c.Keys[0]
	next.KeyID = "new-key"
	next.KeyVersion = "v2"
	next.PublicKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("b", 32))).Public().(ed25519.PublicKey)
	c.Keys = append(c.Keys, next)
	if _, err = PrepareProviderProofEvidence(r, c); err != nil {
		t.Fatal("old key no longer verifies", err)
	}
}

func TestProviderRequestStrictDecoder(t *testing.T) {
	r, _, _ := providerSignedFixture(t)
	raw, _ := json.Marshal(r)
	if _, err := DecodeProviderProofRegistration(raw); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{
		append([]byte(`{"idempotency_key":"duplicate",`), raw[1:]...), append(raw, []byte(" {}")...),
		[]byte(strings.Replace(string(raw), `"resource_uid":null,`, "", 1)),
		[]byte(strings.Replace(string(raw), `"resource_uid":null`, `"resource_uid":"\ud800"`, 1)),
		[]byte(strings.Replace(string(raw), `"resource_uid":null`, `"resource_uid":"\udc00"`, 1)),
		append([]byte(`{"credential":"SYNTHETIC_PRIVATE",`), raw[1:]...), []byte(strings.Repeat(" ", 16385)),
	} {
		if _, err := DecodeProviderProofRegistration(b); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	valid := []byte(strings.Replace(string(raw), `"resource_uid":null`, `"resource_uid":"\ud83d\ude00"`, 1))
	if _, err := DecodeProviderProofRegistration(valid); err != nil {
		t.Fatal("paired unicode rejected", err)
	}
}

func TestProviderOwnershipAndAbsence(t *testing.T) {
	for _, target := range []ProviderProofTarget{{"external_action", "sxa_11111111-1111-4111-8111-111111111111"}, {"backup_staging", "sbs_11111111-1111-4111-8111-111111111111"}, {"restore_resource", "srr_11111111-1111-4111-8111-111111111111"}} {
		r, c, key := providerSignedFixture(t)
		r.Target = target
		r.Proof.ObservedState = "absent"
		r.Proof.ObservedChecksum = nil
		r.Proof.ContentLength = nil
		r.Proof.ObservedVersion = nil
		if target.TargetType == "external_action" {
			r.Proof.ProofType = "provider_absence"
		} else {
			r.Proof.ProofType = "ownership"
			r.Proof.ResourceUID = stringPtr("historical-uid")
			r.Proof.ResourceVersion = stringPtr("immutable-1")
		}
		c.Binding = providerTestBinding(r)
		providerResign(t, &r, c, key)
		if _, err := PrepareProviderProofEvidence(r, c); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProviderUnknownExternalVersionRequiresTrustedOptIn(t *testing.T) {
	r, c, _ := providerSignedFixture(t)
	c.Binding.ObservedVersion = nil
	_, err := PrepareProviderProofEvidence(r, c)
	providerWantCode(t, err, ProviderChecksumMismatch)
	c.Binding.AllowAttestedObservedVersion = true
	if _, err = PrepareProviderProofEvidence(r, c); err != nil {
		t.Fatal("authenticated new version rejected", err)
	}
	c.Binding.ObservedChecksum = stringPtr(strings.Repeat("f", 64))
	_, err = PrepareProviderProofEvidence(r, c)
	providerWantCode(t, err, ProviderChecksumMismatch)
	c.Binding = providerTestBinding(r)
	c.Binding.AllowAttestedObservedVersion = true
	_, err = PrepareProviderProofEvidence(r, c)
	providerWantCode(t, err, ProviderValidationFailed)
}
