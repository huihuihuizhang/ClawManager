package systembackupsecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"
)

// ProviderProofBinding comes from locked server state / a reviewed provider
// identity mapping. No field may be copied from the incoming proof to fill a
// missing expectation. Absence proofs can bind historical resource UID/version.
type ProviderProofBinding struct {
	Target                                                                         ProviderProofTarget
	RowVersion                                                                     int64
	Issuer, ProofType, ProviderIdentityHash, LocationHash, ObservedState           string
	ActionKeyHash, ResourceUID, ResourceVersion, ObservedVersion, ObservedChecksum *string
	ContentLength                                                                  *int64
	// Trusted opt-in for an external-action presence proof whose provider-assigned
	// version is not yet known locally. All other bindings remain exact.
	AllowAttestedObservedVersion bool
}

type ProviderProofRegistrationContext struct {
	Scope                           ProviderProofScope
	DatabaseNow                     time.Time
	MaxAge, ClockSkew               time.Duration
	RegistryVersion, RegistrySHA256 string
	Keys                            []ProviderProofKey
	Binding                         ProviderProofBinding
	// Control retention, not cryptographic validity. Proof expiry remains in
	// the signed payload; evidence must survive long enough for audit/history.
	RetainUntil time.Time
}

// PreparedProviderEvidence is opaque and immutable outside this package. It
// represents verified bytes, not a committed registration or a target verdict.
type PreparedProviderEvidence struct {
	payload                                             []byte
	checksum, requestHash, evidenceType, installationID string
	target                                              ProviderProofTarget
	rowVersion                                          int64
	validFrom, validUntil, retainUntil                  time.Time
	prepared                                            bool
}

func (p PreparedProviderEvidence) ContentSHA256() string { return p.checksum }
func (p PreparedProviderEvidence) RequestSHA256() string { return p.requestHash }
func (p PreparedProviderEvidence) ContentSize() int      { return len(p.payload) }

// DecodeProviderProofRegistration is the HTTP boundary helper. It rejects
// unknown/missing/duplicate fields, invalid UTF-8, trailing JSON and >16 KiB
// transport before any trusted lookup or cryptographic work.
func DecodeProviderProofRegistration(raw []byte) (ProviderProofRegistration, error) {
	var r ProviderProofRegistration
	fail := func() (ProviderProofRegistration, error) {
		return ProviderProofRegistration{}, &ProviderProofError{Code: ProviderValidationFailed}
	}
	if len(raw) == 0 || len(raw) > 16*1024 || !json.Valid(raw) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !providerUniqueJSON(d) {
		return fail()
	}
	if _, err := d.Token(); err != io.EOF {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || !providerFieldSet(fields, "schema_version", "idempotency_key", "target", "proof", "expected_row_version") {
		return fail()
	}
	var target, proof map[string]json.RawMessage
	if json.Unmarshal(fields["target"], &target) != nil || !providerFieldSet(target, "target_type", "target_public_id") {
		return fail()
	}
	if json.Unmarshal(fields["proof"], &proof) != nil || !providerFieldSet(proof, "proof_type", "issuer", "provider_identity_hash", "location_hash", "action_key_hash", "resource_uid", "resource_version", "observed_version", "observed_checksum", "content_length", "observed_state", "issued_at", "expires_at", "signed_proof_base64") {
		return fail()
	}
	if json.Unmarshal(raw, &r) != nil {
		return fail()
	}
	// Marshal cannot repair malformed UTF-8 or surrogate escapes before validation.
	// Compare decoded string validity via the strict string scanner below.
	if !providerJSONUnicode(raw) {
		return fail()
	}
	return r, nil
}

func providerFieldSet(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func providerUniqueJSON(d *json.Decoder) bool {
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return false
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return false
			}
			seen[s] = true
			if !providerUniqueJSON(d) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !providerUniqueJSON(d) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim(']')
	}
	return false
}

// PrepareProviderProofEvidence must be invoked with a database-time snapshot
// inside the registration transaction. D owns authorization, nonce consumption,
// idempotency, audit and commit; this function performs no external IO.
func PrepareProviderProofEvidence(r ProviderProofRegistration, c ProviderProofRegistrationContext) (PreparedProviderEvidence, error) {
	empty := PreparedProviderEvidence{}
	fail := func(code ProviderFailureCode) (PreparedProviderEvidence, error) {
		return empty, &ProviderProofError{Code: code}
	}
	if c.DatabaseNow.IsZero() || !providerBoundedString(c.RegistryVersion) || !providerHashPattern.MatchString(c.RegistrySHA256) || !c.RetainUntil.After(c.DatabaseNow) {
		return fail(ProviderValidationFailed)
	}
	if c.Binding.Target != r.Target || c.Binding.RowVersion != r.ExpectedRowVersion {
		return fail(ProviderVersionConflict)
	}
	v, err := NewProviderEd25519Verifier(c.Scope, c.DatabaseNow, c.Keys)
	if err != nil {
		return empty, err
	}
	if err = VerifyProviderProof(r, c.DatabaseNow, c.MaxAge, c.ClockSkew, v); err != nil {
		return empty, err
	}
	issued, expiry, _ := providerProofTimes(r.Proof)
	if issued.Before(c.DatabaseNow.Add(-c.MaxAge)) || c.RetainUntil.Before(expiry) {
		return fail(ProviderValidationFailed)
	}
	p := r.Proof
	b := c.Binding
	versionMatches := reflect.DeepEqual(p.ObservedVersion, b.ObservedVersion)
	if b.AllowAttestedObservedVersion {
		if b.Target.TargetType != "external_action" || b.ProofType != "provider_presence" || b.ObservedVersion != nil || p.ObservedVersion == nil {
			return fail(ProviderValidationFailed)
		}
		versionMatches = true // Newly attested version is accepted only AFTER signature verification.
	}
	if p.Issuer != b.Issuer || p.ProofType != b.ProofType || p.ProviderIdentityHash != b.ProviderIdentityHash || p.LocationHash != b.LocationHash || p.ObservedState != b.ObservedState ||
		!reflect.DeepEqual(p.ActionKeyHash, b.ActionKeyHash) || !reflect.DeepEqual(p.ResourceUID, b.ResourceUID) || !reflect.DeepEqual(p.ResourceVersion, b.ResourceVersion) ||
		!versionMatches || !reflect.DeepEqual(p.ObservedChecksum, b.ObservedChecksum) || !reflect.DeepEqual(p.ContentLength, b.ContentLength) {
		return fail(ProviderChecksumMismatch)
	}
	data, _ := base64.StdEncoding.Strict().DecodeString(p.SignedProofBase64)
	// Store the complete canonical signed object, not a success flag or only a signature.
	checksum := sha256.Sum256(data)
	requestHash, err := ProviderProofRequestSHA256(r)
	if err != nil {
		return empty, err
	}
	kind := map[string]string{"provider_presence": "provider_presence_proof", "provider_absence": "provider_absence_proof", "ownership": "ownership_proof"}[p.ProofType]
	return PreparedProviderEvidence{payload: append([]byte(nil), data...), checksum: hex.EncodeToString(checksum[:]), requestHash: requestHash,
		evidenceType: kind, installationID: c.Scope.InstallationID, target: r.Target, rowVersion: r.ExpectedRowVersion, validFrom: issued.Add(-c.ClockSkew), validUntil: expiry, retainUntil: c.RetainUntil, prepared: true}, nil
}

// ProviderProofRequestSHA256 permits D to find an already committed idempotent
// result before rechecking proof expiry. It is only a bounded request identity,
// never authorization, signature verification or permission to insert evidence.
func ProviderProofRequestSHA256(r ProviderProofRegistration) (string, error) {
	fail := func() (string, error) { return "", &ProviderProofError{Code: ProviderValidationFailed} }
	if r.SchemaVersion != "system-backup-provider-proof-registration.v1" || !validIdempotencyKey(r.IdempotencyKey) || r.ExpectedRowVersion < 1 || r.ExpectedRowVersion > 9007199254740991 {
		return fail()
	}
	if providerIDPatterns[r.Target.TargetType] == nil || !providerIDPatterns[r.Target.TargetType].MatchString(r.Target.TargetPublicID) {
		return fail()
	}
	if validateProviderProof(r.Target, r.Proof) != nil {
		return fail()
	}
	if _, _, err := providerProofTimes(r.Proof); err != nil {
		return fail()
	}
	if r.Proof.ContentLength != nil && *r.Proof.ContentLength > 9007199254740991 {
		return fail()
	}
	if len(r.Proof.SignedProofBase64) > 10924 {
		return fail()
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.Proof.SignedProofBase64)
	if err != nil || len(data) == 0 || len(data) > 8192 || base64.StdEncoding.EncodeToString(data) != r.Proof.SignedProofBase64 {
		return fail()
	}
	request := providerRegistrationCanonical(r)
	if len(request) > 16384 {
		return fail()
	}
	h := sha256.Sum256(request)
	return hex.EncodeToString(h[:]), nil
}

// Canonical fingerprint used by the transaction owner's idempotency lookup.
// It includes the key, row version and the complete signed proof.
func providerRegistrationCanonical(r ProviderProofRegistration) []byte {
	p := r.Proof
	proof := providerCanonical(map[string]any{
		"proof_type": p.ProofType, "issuer": p.Issuer, "provider_identity_hash": p.ProviderIdentityHash, "location_hash": p.LocationHash,
		"action_key_hash": p.ActionKeyHash, "resource_uid": p.ResourceUID, "resource_version": p.ResourceVersion,
		"observed_version": p.ObservedVersion, "observed_checksum": p.ObservedChecksum, "content_length": p.ContentLength,
		"observed_state": p.ObservedState, "issued_at": p.IssuedAt, "expires_at": p.ExpiresAt, "signed_proof_base64": p.SignedProofBase64,
	})
	target := providerCanonical(map[string]any{"target_type": r.Target.TargetType, "target_public_id": r.Target.TargetPublicID})
	return providerCanonical(map[string]any{"schema_version": r.SchemaVersion, "idempotency_key": r.IdempotencyKey,
		"target": json.RawMessage(target), "proof": json.RawMessage(proof), "expected_row_version": &r.ExpectedRowVersion})
}
