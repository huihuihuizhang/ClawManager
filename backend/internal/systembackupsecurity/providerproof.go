package systembackupsecurity

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	providerHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	providerIDPatterns  = map[string]*regexp.Regexp{
		"external_action":  regexp.MustCompile(`^sxa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
		"backup_staging":   regexp.MustCompile(`^sbs_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
		"restore_resource": regexp.MustCompile(`^srr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	}
)

type ProviderProofTarget struct {
	TargetType     string `json:"target_type"`
	TargetPublicID string `json:"target_public_id"`
}

type ProviderProof struct {
	ProofType            string  `json:"proof_type"`
	Issuer               string  `json:"issuer"`
	ProviderIdentityHash string  `json:"provider_identity_hash"`
	LocationHash         string  `json:"location_hash"`
	ActionKeyHash        *string `json:"action_key_hash"`
	ResourceUID          *string `json:"resource_uid"`
	ResourceVersion      *string `json:"resource_version"`
	ObservedVersion      *string `json:"observed_version"`
	ObservedChecksum     *string `json:"observed_checksum"`
	ContentLength        *int64  `json:"content_length"`
	ObservedState        string  `json:"observed_state"`
	IssuedAt             string  `json:"issued_at"`
	ExpiresAt            string  `json:"expires_at"`
	SignedProofBase64    string  `json:"signed_proof_base64"`
}

type ProviderProofRegistration struct {
	SchemaVersion      string              `json:"schema_version"`
	IdempotencyKey     string              `json:"idempotency_key"`
	Target             ProviderProofTarget `json:"target"`
	Proof              ProviderProof       `json:"proof"`
	ExpectedRowVersion int64               `json:"expected_row_version"`
}

type ProviderProofVerifier interface {
	// Verify must authenticate a trusted issuer for this installation/audience,
	// and bind the signed target and every proof field to the supplied envelope.
	// Registration must additionally compare immutable identity/version/checksum/
	// length to locked trusted state via PrepareProviderProofEvidence; signature
	// verification alone is not registration or a target-state conclusion.
	// Never select a trusted key or audience solely from caller-supplied data.
	Verify(target ProviderProofTarget, proof ProviderProof, signedBytes []byte) error
}

type ProviderFailureCode string

const (
	ProviderValidationFailed ProviderFailureCode = "validation_failed"
	ProviderSignatureInvalid ProviderFailureCode = "signature_invalid"
	ProviderChecksumMismatch ProviderFailureCode = "checksum_mismatch"
	ProviderVersionConflict  ProviderFailureCode = "version_conflict"
)

// ProviderProofError deliberately carries no cause or provider text. Adapters
// may return these codes; unknown errors map to signature_invalid. Even wrapped
// adapter errors are copied into a fresh bounded result at the public boundary.
type ProviderProofError struct{ Code ProviderFailureCode }

func (e *ProviderProofError) Error() string {
	if e != nil {
		switch e.Code {
		case ProviderValidationFailed, ProviderSignatureInvalid, ProviderChecksumMismatch, ProviderVersionConflict:
			return string(e.Code)
		}
	}
	return string(ProviderSignatureInvalid)
}

type ProviderProofVerifierFunc func(target ProviderProofTarget, proof ProviderProof, signedBytes []byte) error

func (f ProviderProofVerifierFunc) Verify(target ProviderProofTarget, proof ProviderProof, signedBytes []byte) error {
	return f(target, proof, signedBytes)
}

// VerifyProviderProof validates the redacted registration envelope and then
// delegates cryptographic verification to the trusted provider issuer adapter.
// It never accepts a caller-provided success flag or a provider URI.
func VerifyProviderProof(registration ProviderProofRegistration, now time.Time, maxAge, clockSkew time.Duration, verifier ProviderProofVerifier) error {
	err := verifyProviderProof(registration, now, maxAge, clockSkew, verifier)
	if err == nil {
		return nil
	}
	var failure *ProviderProofError
	if errors.As(err, &failure) {
		return &ProviderProofError{Code: ProviderFailureCode(failure.Error())}
	}
	return &ProviderProofError{Code: ProviderValidationFailed}
}

func verifyProviderProof(registration ProviderProofRegistration, now time.Time, maxAge, clockSkew time.Duration, verifier ProviderProofVerifier) error {
	if registration.SchemaVersion != "system-backup-provider-proof-registration.v1" || registration.ExpectedRowVersion < 1 || !validIdempotencyKey(registration.IdempotencyKey) {
		return errors.New("provider proof registration envelope is invalid")
	}
	pattern, ok := providerIDPatterns[registration.Target.TargetType]
	if !ok || !pattern.MatchString(registration.Target.TargetPublicID) {
		return errors.New("provider proof target identity is invalid")
	}
	if err := validateProviderProof(registration.Target, registration.Proof); err != nil {
		return err
	}
	if verifier == nil {
		return errors.New("provider proof verifier is required")
	}
	if maxAge <= 0 || clockSkew < 0 {
		return errors.New("provider proof time policy is invalid")
	}
	issuedAt, expiresAt, err := providerProofTimes(registration.Proof)
	if err != nil {
		return err
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if expiresAt.After(issuedAt.Add(maxAge)) || issuedAt.After(now.Add(clockSkew)) || !expiresAt.After(now) {
		return errors.New("provider proof is outside the allowed time window")
	}
	if len(registration.Proof.SignedProofBase64) > 10924 {
		return errors.New("provider proof bytes are invalid")
	}
	signedBytes, err := base64.StdEncoding.Strict().DecodeString(registration.Proof.SignedProofBase64)
	if err != nil || len(signedBytes) == 0 || len(signedBytes) > 8*1024 {
		return errors.New("provider proof bytes are invalid")
	}
	if base64.StdEncoding.EncodeToString(signedBytes) != registration.Proof.SignedProofBase64 {
		return errors.New("provider proof encoding is invalid")
	}
	if err := verifier.Verify(registration.Target, registration.Proof, signedBytes); err != nil {
		var failure *ProviderProofError
		if errors.As(err, &failure) {
			return &ProviderProofError{Code: ProviderFailureCode(failure.Error())}
		}
		return &ProviderProofError{Code: ProviderSignatureInvalid}
	}
	return nil
}

func validateProviderProof(target ProviderProofTarget, proof ProviderProof) error {
	if !providerBoundedString(proof.Issuer) || !providerHashPattern.MatchString(proof.ProviderIdentityHash) || !providerHashPattern.MatchString(proof.LocationHash) {
		return errors.New("provider proof issuer or identity is invalid")
	}
	switch target.TargetType {
	case "external_action":
		if proof.ProofType != "provider_presence" && proof.ProofType != "provider_absence" {
			return errors.New("external action provider proof type is invalid")
		}
	case "backup_staging", "restore_resource":
		if proof.ProofType != "ownership" {
			return errors.New("resource provider proof type is invalid")
		}
	default:
		return errors.New("provider proof target type is invalid")
	}
	if proof.ObservedState != "absent" && proof.ObservedState != "present_unsealed" && proof.ObservedState != "present_sealed" {
		return errors.New("provider proof observed state is invalid")
	}
	if proof.ProofType == "provider_absence" && proof.ObservedState != "absent" {
		return errors.New("provider absence proof must observe absence")
	}
	if proof.ProofType == "provider_presence" && proof.ObservedState == "absent" {
		return errors.New("provider presence proof must observe presence")
	}
	if target.TargetType == "restore_resource" && proof.ObservedState == "present_sealed" {
		return errors.New("restore resource proof cannot observe a sealed resource")
	}
	if target.TargetType == "external_action" && proof.ActionKeyHash == nil {
		return errors.New("external action proof must bind an action key")
	}
	if proof.ActionKeyHash != nil && !providerHashPattern.MatchString(*proof.ActionKeyHash) {
		return errors.New("provider proof action key hash is invalid")
	}
	if proof.ObservedChecksum != nil && !providerHashPattern.MatchString(*proof.ObservedChecksum) {
		return errors.New("provider proof checksum is invalid")
	}
	if proof.ContentLength != nil && *proof.ContentLength < 0 {
		return errors.New("provider proof content length is invalid")
	}
	if proof.ResourceUID != nil && !providerBoundedString(*proof.ResourceUID) || proof.ResourceVersion != nil && !providerBoundedString(*proof.ResourceVersion) || proof.ObservedVersion != nil && !providerBoundedString(*proof.ObservedVersion) {
		return errors.New("provider proof resource identity is invalid")
	}
	return nil
}

func providerBoundedString(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= 256
}

func providerProofTimes(proof ProviderProof) (time.Time, time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339, proof.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("provider proof issued_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, proof.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) {
		return time.Time{}, time.Time{}, errors.New("provider proof expires_at is invalid")
	}
	return issuedAt.UTC(), expiresAt.UTC(), nil
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char == '_' || char == '.' || char == ':' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
