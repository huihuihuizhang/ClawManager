package systembackupbootstrapsecurity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sec "clawreef/internal/systembackupsecurity"
)

func TestSecurityReferenceExistingContractVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "a-secret-ref-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name  string          `json:"name"`
			Ref   json.RawMessage `json:"ref"`
			Valid bool            `json:"valid"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Cases) == 0 {
		t.Fatal("contract vectors unavailable")
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := DecodeSecurityReference(c.Ref, sha(c.Ref))
			if (err == nil) != c.Valid {
				t.Fatal("reference acceptance differs from the existing contract vector")
			}
		})
	}
}

func refFixture() map[string]string {
	return map[string]string{"ref_kind": "external_secret", "purpose": "strong_auth_nonce_hmac", "identity_hash": strings.Repeat("a", 64), "identity_version": "version:7", "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "redacted reference", "read_mode": "exact_version_only"}
}

func refBytes(t *testing.T, f map[string]string) []byte {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityReferenceRejectsAmbiguousWireAndMismatchedPin(t *testing.T) {
	good := refBytes(t, refFixture())
	for name, raw := range map[string][]byte{
		"duplicate":         append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"purpose":"strong_auth_nonce_hmac"}`)...),
		"escaped_duplicate": append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"purpos\u0065":"strong_auth_nonce_hmac"}`)...),
		"nested_secret":     append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"token":{"value":"SYNTHETIC_SECRET"}}`)...),
		"null":              bytes.Replace(good, []byte(`"version:7"`), []byte(`null`), 1),
		"array":             append(append([]byte{'['}, good...), ']'),
		"trailing":          append(append([]byte(nil), good...), []byte(` {}`)...),
		"invalid_utf8":      append(append([]byte(nil), good...), 0xff),
		"oversized":         []byte(strings.Repeat(" ", 16385)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSecurityReference(raw, sha(raw)); err != sec.ErrRegistrationUnavailable {
				t.Fatal("ambiguous wire did not return the closed error")
			}
		})
	}
	if _, err := DecodeSecurityReference(good, strings.Repeat("f", 64)); err == nil {
		t.Fatal("unreviewed complete bytes accepted")
	}
	for _, change := range []func(map[string]string){
		func(f map[string]string) { delete(f, "read_mode"); f["password"] = "SYNTHETIC_SECRET" },
		func(f map[string]string) { f["uid_hash"] = strings.Repeat("d", 64) },
		func(f map[string]string) { f["identity_hash"] = strings.Repeat("A", 64) },
		func(f map[string]string) { f["identity_version"] = "current" },
		func(f map[string]string) { f["description_redacted"] = strings.Repeat("界", 257) },
	} {
		f := refFixture()
		change(f)
		raw := refBytes(t, f)
		if _, err := DecodeSecurityReference(raw, sha(raw)); err == nil {
			t.Fatal("invalid or substituted member accepted")
		}
	}
}

func TestSecurityReferencePinCorrespondenceDoesNotGrantOtherPurposes(t *testing.T) {
	raw := refBytes(t, refFixture())
	r, err := DecodeSecurityReference(raw, sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	pin := sec.BootstrapSecretRef{Purpose: "nonce_hmac", IdentityHash: strings.Repeat("a", 64), Version: "version:7"}
	if !r.MatchesBootstrapPin(pin) {
		t.Fatal("explicit nonce correspondence missing")
	}
	for _, purpose := range []string{"kek", "evidence_kek", "evidence_store", "artifact_upload_issuer", "status_relay", "capture_signing", "evidence_read", "unknown"} {
		pin.Purpose = purpose
		if r.MatchesBootstrapPin(pin) {
			t.Fatal("reference substituted for a different resource requirement")
		}
	}
	pin.Purpose = "nonce_hmac"
	pin.Version = "version:8"
	if r.MatchesBootstrapPin(pin) {
		t.Fatal("mutable version fallback")
	}
	pin.Version = "version:7"
	pin.IdentityHash = strings.Repeat("f", 64)
	if r.MatchesBootstrapPin(pin) {
		t.Fatal("identity mismatch accepted")
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if r.Version() != "version:7" || r.Kind() != "external_secret" {
		t.Fatal("caller bytes changed immutable projection")
	}
	if _, err = json.Marshal(r); err == nil {
		t.Fatal("reference serialization unexpectedly exposed input labels")
	}
	if fmt.Sprintf("%v %#v", r, r) != "BootstrapSecurityReference BootstrapSecurityReference" {
		t.Fatal("reference formatting exposed input")
	}
	if (SecurityReference{}).MatchesBootstrapPin(sec.BootstrapSecretRef{}) {
		t.Fatal("zero reference accepted")
	}
}

func TestSecurityReferenceCapabilityAndRoleAreBoundTogether(t *testing.T) {
	f := refFixture()
	delete(f, "read_mode")
	f["ref_kind"] = "evidence_credential"
	f["purpose"] = "evidence_read"
	f["provider_role"] = "evidence"
	f["credential_capability"] = "range_read"
	raw := refBytes(t, f)
	if _, err := DecodeSecurityReference(raw, sha(raw)); err != nil {
		t.Fatal("valid exact evidence read rejected")
	}
	for name, change := range map[string]func(map[string]string){
		"delete_as_read": func(f map[string]string) { f["credential_capability"] = "exact_delete" },
		"wrong_provider": func(f map[string]string) { f["provider_role"] = "artifact" },
		"wrong_purpose":  func(f map[string]string) { f["purpose"] = "artifact_read" },
	} {
		t.Run(name, func(t *testing.T) {
			c := make(map[string]string)
			for k, v := range f {
				c[k] = v
			}
			change(c)
			raw := refBytes(t, c)
			if _, err := DecodeSecurityReference(raw, sha(raw)); err == nil {
				t.Fatal("cross-role or capability confusion accepted")
			}
		})
	}
}
