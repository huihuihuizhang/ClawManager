package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// Exercise the deadline through actual signed verification rather than forging
// the private verification fields or treating a time calculation as authority.
func TestASensitiveDownloadOriginalDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		auth, expiry, age, skew time.Duration
		want                    time.Duration
	}{
		{"signature_first", -time.Minute, time.Minute, 5 * time.Minute, 0, time.Minute},
		{"age_first", -time.Minute, time.Minute, 70 * time.Second, 0, 10 * time.Second},
		{"age_with_skew", -time.Minute, time.Minute, 70 * time.Second, 5 * time.Second, 15 * time.Second},
		{"future_auth_within_skew", 3 * time.Second, time.Minute, 10 * time.Second, 5 * time.Second, 18 * time.Second},
		{"submicrosecond_expiry", -time.Minute, time.Second + 789*time.Nanosecond, 5 * time.Minute, 0, time.Second + 789*time.Nanosecond},
		{"submicrosecond_age", -time.Minute, time.Minute, 61*time.Second + 321*time.Nanosecond, 0, time.Second + 321*time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, proof, cfg := sensitiveDownloadSignedFixture(t)
			proof.Payload.AuthTime = cfg.Now.Add(tc.auth).Format(time.RFC3339Nano)
			proof.Payload.ExpiresAt = cfg.Now.Add(tc.expiry).Format(time.RFC3339Nano)
			payload, err := CanonicalPayload(proof.Payload)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
			proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,
				[]byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
			cfg.MaxAge, cfg.ClockSkew = tc.age, tc.skew
			v, err := r.VerifyProof(proof, proof.Payload.Issuer, cfg)
			if err != nil {
				t.Fatal("positive signature control", err)
			}
			want := cfg.Now.Add(tc.want)
			until, err := v.AdmissionDeadlineAt()
			if err != nil || !until.Equal(want) {
				t.Fatalf("original limit: got %s, want %s, err %v", until, want, err)
			}
			if err := v.RecheckProofAt(want.Add(-time.Nanosecond)); err != nil {
				t.Fatal("valid immediately before original limit", err)
			}
			if err := v.RecheckProofAt(want.Add(time.Nanosecond)); err == nil {
				t.Fatal("original limit extended")
			}
			// External configuration changes and reads cannot refresh the result.
			cfg.MaxAge, cfg.ClockSkew = 24*time.Hour, time.Hour
			again, err := v.AdmissionDeadlineAt()
			if err != nil || !again.Equal(want) {
				t.Fatal("deadline changed after external config mutation", err)
			}
		})
	}
}
