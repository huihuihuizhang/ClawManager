package systembackupsecurity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestProviderProofSharedParityVectors(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Name         string                    `json:"name"`
			Registration ProviderProofRegistration `json:"registration"`
			RuntimeValid bool                      `json:"runtime_valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readContractFixture(t, "a-provider-proof-parity-vectors.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 40 {
		t.Fatal("missing provider boundary vectors")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			called := false
			err := VerifyProviderProof(tc.Registration, time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 30*time.Second, ProviderProofVerifierFunc(func(ProviderProofTarget, ProviderProof, []byte) error { called = true; return nil }))
			if (err == nil) != tc.RuntimeValid || called != tc.RuntimeValid {
				t.Fatalf("runtime validity mismatch: valid=%v called=%v err=%v", tc.RuntimeValid, called, err)
			}
			if err != nil {
				var typed *ProviderProofError
				if !errors.As(err, &typed) || typed.Code != ProviderValidationFailed {
					t.Fatalf("wrong failure: %v", err)
				}
			}
		})
	}
}

func TestProviderErrorsAreTypedBoundedAndDoNotWrapCauses(t *testing.T) {
	const private = "SYNTHETIC_PRIVATE_PROVIDER_ERROR"
	for _, code := range []ProviderFailureCode{ProviderValidationFailed, ProviderSignatureInvalid, ProviderChecksumMismatch, ProviderVersionConflict, ProviderFailureCode(private)} {
		for _, wrapped := range []bool{false, true} {
			var adapterError error = &ProviderProofError{Code: code}
			if wrapped {
				adapterError = fmt.Errorf("%s: %w", private, adapterError)
			}
			err := VerifyProviderProof(testProviderRegistration(), time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 0, ProviderProofVerifierFunc(func(ProviderProofTarget, ProviderProof, []byte) error { return adapterError }))
			var typed *ProviderProofError
			want := code
			if code == ProviderFailureCode(private) {
				want = ProviderSignatureInvalid
			}
			if !errors.As(err, &typed) || typed.Code != want || strings.Contains(fmt.Sprintf("%+v", err), private) || errors.Unwrap(err) != nil {
				t.Fatalf("unbounded or incorrect adapter failure: %v", err)
			}
		}
	}
}

func testProviderRegistration() ProviderProofRegistration {
	actionHash := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	checksum := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	return ProviderProofRegistration{
		SchemaVersion: "system-backup-provider-proof-registration.v1", IdempotencyKey: "idem-provider-proof-20260920-0001",
		Target: ProviderProofTarget{TargetType: "external_action", TargetPublicID: "sxa_11111111-1111-4111-8111-111111111111"},
		Proof: ProviderProof{
			ProofType: "provider_presence", Issuer: "artifact-provider-issuer-v1",
			ProviderIdentityHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			LocationHash:         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ActionKeyHash: &actionHash,
			ObservedVersion: stringPtr("object-version-redacted"), ObservedChecksum: &checksum, ContentLength: int64Ptr(4096), ObservedState: "present_sealed",
			IssuedAt: "2026-09-20T01:01:00Z", ExpiresAt: "2026-09-20T01:03:00Z", SignedProofBase64: "cHJvdmlkZXItcHJvb2YtcmVkYWN0ZWQ=",
		},
		ExpectedRowVersion: 3,
	}
}

func TestVerifyProviderProofBindsTargetAndSignedBytes(t *testing.T) {
	registration := testProviderRegistration()
	called := false
	err := VerifyProviderProof(registration, time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 30*time.Second, ProviderProofVerifierFunc(func(target ProviderProofTarget, proof ProviderProof, signedBytes []byte) error {
		called = true
		if target.TargetPublicID != registration.Target.TargetPublicID || proof.ActionKeyHash == nil || string(signedBytes) != "provider-proof-redacted" {
			return errors.New("binding mismatch")
		}
		return nil
	}))
	if err != nil || !called {
		t.Fatalf("expected provider proof acceptance, called=%v err=%v", called, err)
	}
}

func TestVerifyProviderProofRejectsAbsenceWithPresenceState(t *testing.T) {
	registration := testProviderRegistration()
	registration.Proof.ProofType = "provider_absence"
	registration.Proof.ObservedState = "present_sealed"
	err := VerifyProviderProof(registration, time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 0, ProviderProofVerifierFunc(func(ProviderProofTarget, ProviderProof, []byte) error { return nil }))
	if err == nil {
		t.Fatal("expected absence/presence mismatch to fail")
	}
}

func TestVerifyProviderProofRejectsRestoreSealedAndOversizedEvidence(t *testing.T) {
	registration := testProviderRegistration()
	registration.Target = ProviderProofTarget{TargetType: "restore_resource", TargetPublicID: "srr_11111111-1111-4111-8111-111111111111"}
	registration.Proof.ProofType = "ownership"
	registration.Proof.ActionKeyHash = nil
	registration.Proof.ObservedState = "present_sealed"
	if err := VerifyProviderProof(registration, time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 0, ProviderProofVerifierFunc(func(ProviderProofTarget, ProviderProof, []byte) error { return nil })); err == nil {
		t.Fatal("expected sealed restore resource to fail")
	}
	registration = testProviderRegistration()
	registration.Proof.SignedProofBase64 = base64.RawStdEncoding.EncodeToString(make([]byte, 8193))
	if err := VerifyProviderProof(registration, time.Date(2026, 9, 20, 1, 2, 0, 0, time.UTC), 5*time.Minute, 0, ProviderProofVerifierFunc(func(ProviderProofTarget, ProviderProof, []byte) error { return nil })); err == nil {
		t.Fatal("expected oversized provider proof to fail")
	}
}

func stringPtr(value string) *string { return &value }
func int64Ptr(value int64) *int64    { return &value }
