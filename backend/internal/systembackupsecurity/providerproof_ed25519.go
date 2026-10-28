package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const ProviderProofDomain = "clawmanager.system-backup.provider-proof.v1"

// ProviderProofScope is supplied by the installation, never by the request.
type ProviderProofScope struct {
	InstallationID string `json:"installation_id"`
	Audience       string `json:"audience"`
}

// ProviderProofKey is a resolved registry entry. Revocation invalidates old as
// well as new proofs; historical keys must remain available for their lifetime.
type ProviderProofKey struct {
	Issuer, KeyID, KeyVersion, Purpose string
	PublicKey                          ed25519.PublicKey
	NotBefore, NotAfter                time.Time
	Revoked                            bool
	TargetTypes, ProofTypes            []string
}

type providerSignedDocument struct {
	Payload   json.RawMessage `json:"payload"`
	Signature ProofSignature  `json:"signature"`
}

// Restricted canonical JSON: fixed ASCII field names, strings, nullable
// strings and nonnegative safe integers. This is not a general JCS encoder.
func providerCanonical(value map[string]any) []byte {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(jcsString(key))
		out.WriteByte(':')
		switch v := value[key].(type) {
		case string:
			out.WriteString(jcsString(v))
		case *string:
			if v == nil {
				out.WriteString("null")
			} else {
				out.WriteString(jcsString(*v))
			}
		case *int64:
			if v == nil {
				out.WriteString("null")
			} else {
				out.WriteString(strconv.FormatInt(*v, 10))
			}
		case json.RawMessage:
			out.Write(v)
		}
	}
	out.WriteByte('}')
	return []byte(out.String())
}

// ProviderProofPayload gives issuers the exact unsigned payload. Signature
// bytes are excluded; all other proof fields and the target are included.
func ProviderProofPayload(scope ProviderProofScope, target ProviderProofTarget, proof ProviderProof) ([]byte, error) {
	if !providerBoundedString(scope.InstallationID) || !providerBoundedString(scope.Audience) ||
		providerIDPatterns[target.TargetType] == nil || !providerIDPatterns[target.TargetType].MatchString(target.TargetPublicID) {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	if err := validateProviderProof(target, proof); err != nil {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	if _, _, err := providerProofTimes(proof); err != nil {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	if proof.ContentLength != nil && *proof.ContentLength > 9007199254740991 {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	p := providerCanonical(map[string]any{
		"proof_type": proof.ProofType, "issuer": proof.Issuer, "provider_identity_hash": proof.ProviderIdentityHash,
		"location_hash": proof.LocationHash, "action_key_hash": proof.ActionKeyHash, "resource_uid": proof.ResourceUID,
		"resource_version": proof.ResourceVersion, "observed_version": proof.ObservedVersion, "observed_checksum": proof.ObservedChecksum,
		"content_length": proof.ContentLength, "observed_state": proof.ObservedState, "issued_at": proof.IssuedAt, "expires_at": proof.ExpiresAt,
	})
	t := providerCanonical(map[string]any{"target_type": target.TargetType, "target_public_id": target.TargetPublicID})
	return providerCanonical(map[string]any{"installation_id": scope.InstallationID, "audience": scope.Audience, "proof": json.RawMessage(p), "target": json.RawMessage(t)}), nil
}

func providerHeader(keyID, version string) []byte {
	return providerCanonical(map[string]any{"alg": "EdDSA", "key_version": version, "kid": keyID, "purpose": "provider_proof_issuer", "typ": ProviderProofDomain})
}

// ProviderProofSigningInput exposes a draft Ed25519 JWS signing profile for a
// provider-side issuer. This helper holds no private key and performs no IO.
func ProviderProofSigningInput(scope ProviderProofScope, target ProviderProofTarget, proof ProviderProof, keyID, version string) ([]byte, error) {
	if !providerBoundedString(keyID) || !providerBoundedString(version) {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	payload, err := ProviderProofPayload(scope, target, proof)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(providerHeader(keyID, version)) + "." + base64.RawURLEncoding.EncodeToString(payload)), nil
}

func providerDocument(payload []byte, s ProofSignature) []byte {
	sig := providerCanonical(map[string]any{"format": s.Format, "algorithm": s.Algorithm, "key_id": s.KeyID, "key_version": s.KeyVersion,
		"domain_separator": s.DomainSeparator, "protected_header": s.ProtectedHeader, "value": s.Value})
	return providerCanonical(map[string]any{"payload": json.RawMessage(payload), "signature": json.RawMessage(sig)})
}

// EncodeProviderProof attaches a provider-produced signature. It does not
// assert that the signature is valid; receivers must verify before recording.
func EncodeProviderProof(scope ProviderProofScope, target ProviderProofTarget, proof ProviderProof, keyID, version string, signature []byte) (string, error) {
	if len(signature) != ed25519.SignatureSize {
		return "", &ProviderProofError{Code: ProviderValidationFailed}
	}
	if _, err := ProviderProofSigningInput(scope, target, proof, keyID, version); err != nil {
		return "", err
	}
	payload, _ := ProviderProofPayload(scope, target, proof)
	doc := providerDocument(payload, ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: keyID, KeyVersion: version, DomainSeparator: ProviderProofDomain,
		ProtectedHeader: base64.RawURLEncoding.EncodeToString(providerHeader(keyID, version)), Value: base64.RawURLEncoding.EncodeToString(signature)})
	if len(doc) > 8192 {
		return "", &ProviderProofError{Code: ProviderValidationFailed}
	}
	return base64.StdEncoding.EncodeToString(doc), nil
}

type ProviderEd25519Verifier struct {
	scope ProviderProofScope
	keys  map[string]ProviderProofKey
	now   time.Time
}

// NewProviderEd25519Verifier copies the resolved snapshot so later changes to
// a caller's slices cannot silently change the trust decision in this request.
// This adapter authenticates the signature/envelope only. Registration callers
// must use PrepareProviderProofEvidence for locked target-state comparisons.
func NewProviderEd25519Verifier(scope ProviderProofScope, now time.Time, keys []ProviderProofKey) (*ProviderEd25519Verifier, error) {
	if now.IsZero() || !providerBoundedString(scope.InstallationID) || !providerBoundedString(scope.Audience) || len(keys) == 0 {
		return nil, &ProviderProofError{Code: ProviderValidationFailed}
	}
	v := &ProviderEd25519Verifier{scope: scope, now: now, keys: map[string]ProviderProofKey{}}
	for _, k := range keys {
		if !providerBoundedString(k.Issuer) || !providerBoundedString(k.KeyID) || !providerBoundedString(k.KeyVersion) || k.Purpose != "provider_proof_issuer" || len(k.PublicKey) != 32 || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) || len(k.TargetTypes) == 0 || len(k.ProofTypes) == 0 {
			return nil, &ProviderProofError{Code: ProviderValidationFailed}
		}
		id := providerKeyID(k.Issuer, k.KeyID, k.KeyVersion)
		if _, ok := v.keys[id]; ok {
			return nil, &ProviderProofError{Code: ProviderValidationFailed}
		}
		k.PublicKey = append(ed25519.PublicKey(nil), k.PublicKey...)
		k.TargetTypes = append([]string(nil), k.TargetTypes...)
		k.ProofTypes = append([]string(nil), k.ProofTypes...)
		v.keys[id] = k
	}
	return v, nil
}

func providerKeyID(issuer, key, version string) string {
	b, _ := json.Marshal([]string{issuer, key, version})
	return string(b)
}
func providerContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (v *ProviderEd25519Verifier) Verify(target ProviderProofTarget, proof ProviderProof, signedBytes []byte) error {
	invalid := &ProviderProofError{Code: ProviderSignatureInvalid}
	if v == nil || len(signedBytes) == 0 || len(signedBytes) > 8192 || !utf8.Valid(signedBytes) {
		return invalid
	}
	var doc providerSignedDocument
	if json.Unmarshal(signedBytes, &doc) != nil || !bytes.Equal(signedBytes, providerDocument(doc.Payload, doc.Signature)) {
		return invalid
	}
	s := doc.Signature
	k, ok := v.keys[providerKeyID(proof.Issuer, s.KeyID, s.KeyVersion)]
	if !ok || k.Revoked || v.now.Before(k.NotBefore) || !v.now.Before(k.NotAfter) || !providerContains(k.TargetTypes, target.TargetType) || !providerContains(k.ProofTypes, proof.ProofType) {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	issued, expiry, err := providerProofTimes(proof)
	if err != nil || issued.Before(k.NotBefore) || expiry.After(k.NotAfter) {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	if s.Format != "jws" || s.Algorithm != "EdDSA" || s.DomainSeparator != ProviderProofDomain || s.ProtectedHeader != base64.RawURLEncoding.EncodeToString(providerHeader(k.KeyID, k.KeyVersion)) {
		return invalid
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Value)
	if err != nil || len(sig) != 64 || base64.RawURLEncoding.EncodeToString(sig) != s.Value {
		return invalid
	}
	input := s.ProtectedHeader + "." + base64.RawURLEncoding.EncodeToString(doc.Payload)
	if !ed25519.Verify(k.PublicKey, []byte(input), sig) {
		return invalid
	}
	expected, err := ProviderProofPayload(v.scope, target, proof)
	if err != nil {
		return &ProviderProofError{Code: ProviderValidationFailed}
	}
	if !bytes.Equal(doc.Payload, expected) {
		return &ProviderProofError{Code: ProviderChecksumMismatch}
	}
	return nil
}
