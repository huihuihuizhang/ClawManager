package systembackupsecurity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyAcceptanceCandidate(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reasons := []string{"eligible"}
	reasonHash := sha256.Sum256(acceptanceCanonicalArray(reasons))
	hash := strings.Repeat("a", 64)
	payload := map[string]any{
		"schema_version": "system-backup-acceptance.v1", "backup_public_id": "sbk_test", "attempt_no": 1,
		"manifest_checksum": hash, "marker_checksum": hash, "staging_cleanup_evidence_id": "sev_test",
		"staging_cleanup_evidence_hash": hash, "local_acceptance": true, "local_reason_codes": reasons,
		"local_reason_codes_hash": hex.EncodeToString(reasonHash[:]), "decision_at": "2026-10-01T00:00:00Z",
		"config_version": 1, "signing_key": map[string]any{"purpose": "acceptance_record", "key_id": "acceptance-a", "key_version": "v1"},
	}
	key := AcceptanceCandidateKey{InstallationID: "installation_test", Purpose: "acceptance_record", KeyID: "acceptance-a", KeyVersion: "v1", PublicKey: pub,
		NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
	binding := AcceptanceCandidateBinding{OriginInstallationID: "installation_test", BackupPublicID: "sbk_test", AttemptNo: 1, ManifestChecksum: hash, MarkerChecksum: hash}
	makeDoc := func(p map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := acceptanceCanonicalJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		header := providerCanonical(map[string]any{"alg": "EdDSA", "key_version": "v1", "kid": "acceptance-a", "purpose": "acceptance_record", "typ": AcceptanceCandidateDomain})
		encodedHeader := base64.RawURLEncoding.EncodeToString(header)
		input := []byte(encodedHeader + "." + base64.RawURLEncoding.EncodeToString(canonical))
		doc, err := json.Marshal(map[string]any{"payload": p, "signature": map[string]any{
			"algorithm": "EdDSA", "key_purpose": "acceptance_record", "key_id": "acceptance-a", "key_version": "v1",
			"domain_separator": AcceptanceCandidateDomain, "protected_header": encodedHeader,
			"value": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, input)),
		}})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	good := makeDoc(payload)
	if err := VerifyAcceptanceCandidate(good, binding, []AcceptanceCandidateKey{key}); err != nil {
		t.Fatal(err)
	}
	captureKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalogKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewArtifactSigningKeyHistory("installation_test", []ArtifactSigningPublicKey{
		key,
		{InstallationID: "installation_test", Purpose: "capture_certificate", KeyID: "capture-a", KeyVersion: "v1", PublicKey: captureKey, NotBefore: key.NotBefore, NotAfter: key.NotAfter},
		{InstallationID: "installation_test", Purpose: "catalog_record", KeyID: "catalog-a", KeyVersion: "v1", PublicKey: catalogKey, NotBefore: key.NotBefore, NotAfter: key.NotAfter},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := history.VerifyAcceptanceCandidate(good, binding); err != nil {
		t.Fatal(err)
	}
	t.Run("functional_test_negative_qualification", func(t *testing.T) {
		decision := func(accepted bool, codes []string) map[string]any {
			p := copyAcceptanceMap(payload)
			digest := sha256.Sum256(acceptanceCanonicalArray(codes))
			p["local_acceptance"], p["local_reason_codes"], p["local_reason_codes_hash"] = accepted, codes, hex.EncodeToString(digest[:])
			return p
		}
		ordinary := makeDoc(decision(false, []string{"functional_test"}))
		// Verify the original signed ordinary receipt through both independent
		// read interfaces. This authenticates a negative qualification only.
		for _, codes := range [][]string{
			{"functional_test"},
			{"attestation_invalid", "consistency_not_strong", "disqualifying_warning", "functional_test", "kek_not_recoverable", "target_not_external", "target_risk"},
		} {
			raw := makeDoc(decision(false, codes))
			if err := VerifyAcceptanceCandidate(raw, binding, []AcceptanceCandidateKey{key}); err != nil {
				t.Fatal("valid signed ordinary negative qualification rejected", err)
			}
			if err := history.VerifyAcceptanceCandidate(raw, binding); err != nil {
				t.Fatal("ordinary negative qualification history read rejected", err)
			}
		}
		for _, tc := range []struct {
			name     string
			accepted bool
			codes    []string
		}{
			{"ordinary_marked_eligible", true, []string{"functional_test"}},
			{"eligible_mixed_with_ordinary", true, []string{"eligible", "functional_test"}},
			{"negative_receipt_contains_eligible", false, []string{"eligible", "functional_test"}},
			{"wrong_case", false, []string{"Functional_test"}},
			{"unknown_reason", false, []string{"functional_test_only"}},
			{"unsorted", false, []string{"functional_test", "attestation_invalid"}},
			{"duplicate", false, []string{"functional_test", "functional_test"}},
			{"empty", false, []string{}},
			{"eight_reasons", false, []string{"attestation_invalid", "consistency_not_strong", "disqualifying_warning", "eligible", "functional_test", "kek_not_recoverable", "target_not_external", "target_risk"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := history.VerifyAcceptanceCandidate(makeDoc(decision(tc.accepted, tc.codes)), binding); err == nil {
					t.Fatal("invalid signed ordinary qualification accepted")
				}
			})
		}
		badHash := decision(false, []string{"functional_test"})
		badHash["local_reason_codes_hash"] = hash
		if err := history.VerifyAcceptanceCandidate(makeDoc(badHash), binding); err == nil {
			t.Fatal("signed ordinary receipt with wrong reason digest accepted")
		}
		for _, mutation := range []string{"reason_with_updated_hash", "signature", "domain"} {
			t.Run("tampered_"+mutation, func(t *testing.T) {
				var doc map[string]map[string]any
				if json.Unmarshal(ordinary, &doc) != nil {
					t.Fatal("ordinary receipt fixture")
				}
				switch mutation {
				case "reason_with_updated_hash":
					codes := []string{"target_risk"}
					digest := sha256.Sum256(acceptanceCanonicalArray(codes))
					doc["payload"]["local_reason_codes"] = codes
					doc["payload"]["local_reason_codes_hash"] = hex.EncodeToString(digest[:])
				case "signature":
					doc["signature"]["value"] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				case "domain":
					doc["signature"]["domain_separator"] = "clawmanager.system-backup.capture_certificate.v1"
				}
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := history.VerifyAcceptanceCandidate(raw, binding); err == nil {
					t.Fatal("tampered ordinary receipt accepted")
				}
			})
		}
	})
	otherInstallation := binding
	otherInstallation.OriginInstallationID = "installation_other"
	if err := history.VerifyAcceptanceCandidate(good, otherInstallation); err == nil {
		t.Fatal("cross-installation key history accepted")
	}
	mutateSignature := func(field, value string) []byte {
		t.Helper()
		var doc map[string]map[string]any
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		doc["signature"][field] = value
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// A historical key remains usable after its expiry if it was valid when
	// the decision was made; revocation still invalidates it.
	key.Revoked = true
	if err := VerifyAcceptanceCandidate(good, binding, []AcceptanceCandidateKey{key}); err == nil {
		t.Fatal("revoked key accepted")
	}
	activeCopy := key
	activeCopy.Revoked = false
	if err := VerifyAcceptanceCandidate(good, binding, []AcceptanceCandidateKey{key, activeCopy}); err == nil {
		t.Fatal("duplicate key identity accepted")
	}
	key.Revoked = false
	key.NotAfter = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	if err := VerifyAcceptanceCandidate(good, binding, []AcceptanceCandidateKey{key}); err == nil {
		t.Fatal("key outside decision time accepted")
	}
	key.NotAfter = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for name, raw := range map[string][]byte{
		"wrong manifest binding": makeDoc(func() map[string]any {
			p := copyAcceptanceMap(payload)
			p["manifest_checksum"] = strings.Repeat("b", 64)
			return p
		}()),
		"bad reason hash":     makeDoc(func() map[string]any { p := copyAcceptanceMap(payload); p["local_reason_codes_hash"] = hash; return p }()),
		"duplicate field":     []byte(strings.Replace(string(good), `"payload":{`, `"payload":{"attempt_no":1,`, 1)),
		"invalid surrogate":   []byte(strings.Replace(string(good), `"sbk_test"`, `"\ud800"`, 1)),
		"noncanonical number": []byte(strings.Replace(string(good), `"attempt_no":1`, `"attempt_no":1e0`, 1)),
		"wrong signature":     mutateSignature("value", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))),
		"wrong header":        mutateSignature("protected_header", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))),
		"wrong version":       mutateSignature("key_version", "v2"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyAcceptanceCandidate(raw, binding, []AcceptanceCandidateKey{key}); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	wrongPurpose := key
	wrongPurpose.Purpose = "catalog_record"
	if err := VerifyAcceptanceCandidate(good, binding, []AcceptanceCandidateKey{wrongPurpose}); err == nil {
		t.Fatal("cross-purpose key accepted")
	}
}

func copyAcceptanceMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestAcceptanceCandidateNodeVector(t *testing.T) {
	contract := filepath.Join("..", "..", "..", "contracts", "system-backup", "v12")
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(contract, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var examples struct {
		Examples struct {
			Acceptance json.RawMessage `json:"acceptance"`
		} `json:"examples"`
	}
	if err := json.Unmarshal(read("publication-redacted-examples.json"), &examples); err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicKey          string `json:"public_key_base64url"`
		Digest             string `json:"payload_sha256"`
		SigningInputDigest string `json:"signing_input_sha256"`
		Signature          string `json:"signature_base64url"`
	}
	if err := json.Unmarshal(read("a-artifact-signature-vectors.json"), &vector); err != nil {
		t.Fatal(err)
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var signed struct {
		Payload   json.RawMessage `json:"payload"`
		Signature struct {
			ProtectedHeader string `json:"protected_header"`
			Value           string `json:"value"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(examples.Examples.Acceptance, &signed); err != nil {
		t.Fatal(err)
	}
	canonical, err := acceptanceCanonicalJSON(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != vector.Digest || signed.Signature.Value != vector.Signature {
		t.Fatal("Node artifact vector drift")
	}
	input := []byte(signed.Signature.ProtectedHeader + "." + base64.RawURLEncoding.EncodeToString(canonical))
	inputDigest := sha256.Sum256(input)
	if hex.EncodeToString(inputDigest[:]) != vector.SigningInputDigest {
		t.Fatal("Node JWS input drift")
	}
	binding := AcceptanceCandidateBinding{
		OriginInstallationID: "installation_example",
		BackupPublicID:       "sbk_example01", AttemptNo: 1,
		ManifestChecksum: strings.Repeat("b", 64),
		MarkerChecksum:   "e1d1d95ebad9ace809d3200d04c72376ac8e3cff111f565c58da2dc6b8650f75",
	}
	key := AcceptanceCandidateKey{InstallationID: "installation_example", Purpose: "acceptance_record", KeyID: "acceptance-key-example", KeyVersion: "7",
		PublicKey: public, NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	if err := VerifyAcceptanceCandidate(examples.Examples.Acceptance, binding, []AcceptanceCandidateKey{key}); err != nil {
		t.Fatal(err)
	}
}
