package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestSensitiveDownloadOriginalVerificationIdentity(t *testing.T) {
	for _, name := range []string{"unchanged", "nonce", "issuer", "signing_version", "observation_time", "time_policy"} {
		t.Run(name, func(t *testing.T) {
			r, p, cfg := sensitiveDownloadSignedFixture(t)
			original, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if original.IssuerSHA256() != registrationHash(p.Payload.Issuer) || !original.SignedAuthTime().Equal(cfg.Now.Add(-time.Minute)) || !original.ProofAcceptedAt().Equal(cfg.Now) {
				t.Fatal("unbound issuer/authentication time")
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
			switch name {
			case "nonce":
				p.Payload.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
			case "issuer":
				old := p.Payload.Issuer
				p.Payload.Issuer = "other-issuer"
				cfg.TrustedSigners[p.Payload.Issuer] = cfg.TrustedSigners[old]
				cfg.TrustedIssuerPolicies[p.Payload.Issuer] = cfg.TrustedIssuerPolicies[old]
			case "signing_version":
				p.Signature.KeyVersion = "v3"
				cfg.TrustedSigners[p.Payload.Issuer]["v3"] = Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: p.Signature.KeyID, KeyVersion: "v3", Purpose: "strong_auth_issuer"}
				headerBytes, err := base64.RawURLEncoding.DecodeString(p.Signature.ProtectedHeader)
				if err != nil {
					t.Fatal(err)
				}
				p.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(headerBytes), `"key_version":"v1"`, `"key_version":"v3"`)))
			case "observation_time":
				cfg.Now = cfg.Now.Add(time.Millisecond)
			case "time_policy":
				cfg.MaxAge += time.Second
			}
			payload, err := CanonicalPayload(p.Payload)
			if err != nil {
				t.Fatal(err)
			}
			p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
			other, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
			if err != nil {
				t.Fatal("second proof must independently verify", err)
			}
			if original.SameAdmissionVerification(other) != (name == "unchanged") || other.SameAdmissionVerification(original) != (name == "unchanged") {
				t.Fatal("original verification was replaced")
			}
		})
	}
	zero := SensitiveDownloadProofVerification{}
	if zero.SameAdmissionVerification(zero) || zero.IssuerSHA256() != "" || !zero.SignedAuthTime().IsZero() || !zero.ProofAcceptedAt().IsZero() {
		t.Fatal("zero verification exposed facts")
	}
}
