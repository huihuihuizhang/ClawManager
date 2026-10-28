// Package systembackupsecurity contains the A-owned security primitives used
// at the system-backup boundary. The caller owns the transaction that consumes
// the returned nonce HMAC, stages verified inline evidence and records audit.
package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ProofSchemaVersion = "system-backup-strong-auth-proof.v1"
	DomainSeparator    = "clawmanager.system-backup.strong-auth.v1"
)

// ProofPayload is the signed payload from strong-auth-proof-nonce.schema.json.
// The optional fields are pointers so a missing OIDC/WebAuthn attribute cannot
// accidentally be treated as an empty, valid value.
type ProofPayload struct {
	Issuer         string   `json:"issuer"`
	Audience       string   `json:"audience"`
	Subject        string   `json:"subject"`
	Session        string   `json:"session"`
	AuthTime       string   `json:"auth_time"`
	ExpiresAt      string   `json:"expires_at"`
	Method         string   `json:"method"`
	Nonce          string   `json:"nonce"`
	Endpoint       string   `json:"endpoint"`
	RequestHash    string   `json:"request_hash"`
	IdempotencyKey string   `json:"idempotency_key"`
	ACR            *string  `json:"acr"`
	AMR            []string `json:"amr"`
}

// ProofSignature is the transport signature metadata. The actual crypto is
// delegated to an issuer-specific adapter so KMS/HSM-backed implementations do
// not need to expose key material to this package.
type ProofSignature struct {
	Format          string `json:"format"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	KeyVersion      string `json:"key_version"`
	DomainSeparator string `json:"domain_separator"`
	ProtectedHeader string `json:"protected_header"`
	Value           string `json:"value"`
}

type Proof struct {
	SchemaVersion string         `json:"schema_version"`
	Payload       ProofPayload   `json:"payload"`
	Signature     ProofSignature `json:"signature"`
}

// RequestBinding is the request context that must match the signed proof.
type RequestBinding struct {
	Issuer         string
	Audience       string
	Subject        string
	Session        string
	Endpoint       string
	RequestHash    string
	IdempotencyKey string
}

// SignatureVerifier verifies a signature over the exact canonical payload
// bytes. Implementations may use a local public key, KMS, or an HSM. The
// verifier must reject an algorithm/key-purpose mismatch.
type SignatureVerifier interface {
	Verify(payload []byte, signature ProofSignature) error
}

// SignatureVerifierFunc adapts a function to SignatureVerifier.
type SignatureVerifierFunc func(payload []byte, signature ProofSignature) error

func (f SignatureVerifierFunc) Verify(payload []byte, signature ProofSignature) error {
	return f(payload, signature)
}

// VerifyConfig contains only redacted identities and verification policy. The
// nonce HMAC keys are supplied by the transaction owner and never returned.
type VerifyConfig struct {
	Now                       time.Time
	MaxAge                    time.Duration
	ClockSkew                 time.Duration
	ExpectedAudience          string
	ExpectedSubject           string
	ExpectedSession           string
	TrustedSigners            map[string]map[string]SignatureVerifier
	TrustedIssuerPolicies     map[string]IssuerPolicy
	NonceHMACKeys             map[string][]byte
	ActiveNonceHMACKeyVersion string
	// RequiredNonceHMACKeyVersions is loaded by D from the persisted config
	// history AND all nonce ledger versions still within control retention.
	// It must not be derived from the successfully resolved key-material map.
	// D locks/revalidates that snapshot in the mutation/audit/nonce transaction.
	RequiredNonceHMACKeyVersions []string
}

// IssuerPolicy comes from the trusted issuer registry, never the proof.
// OIDC ACR and every asserted AMR must match this issuer's allowlists.
type IssuerPolicy struct {
	Methods []string `json:"methods"`
	ACR     []string `json:"acr"`
	AMR     []string `json:"amr"`
}

// Ed25519JWSVerifier is a local public-key adapter for the EdDSA JWS profile.
// Other algorithms/formats require their own reviewed adapter. The registry
// owns the exact key/version/purpose binding and historical public-key lifetime.
type Ed25519JWSVerifier struct {
	PublicKey  ed25519.PublicKey
	KeyID      string
	KeyVersion string
	Purpose    string
}

func (v Ed25519JWSVerifier) Verify(payload []byte, signature ProofSignature) error {
	invalid := errors.New("invalid strong-auth signature")
	if v.Purpose != "strong_auth_issuer" || v.KeyID == "" || v.KeyVersion == "" || len(v.PublicKey) != ed25519.PublicKeySize ||
		signature.Format != "jws" || signature.Algorithm != "EdDSA" || signature.KeyID != v.KeyID || signature.KeyVersion != v.KeyVersion || signature.DomainSeparator != DomainSeparator {
		return invalid
	}
	// The canonical protected header is a closed profile: rejects extra fields,
	// duplicate keys, alternate algorithms and unsigned key-purpose metadata.
	if !utf8.ValidString(v.KeyID) || !utf8.ValidString(v.KeyVersion) {
		return invalid
	}
	header := []byte(`{"alg":"EdDSA","key_version":` + jcsString(v.KeyVersion) + `,"kid":` + jcsString(v.KeyID) + `,"purpose":"strong_auth_issuer","typ":` + jcsString(DomainSeparator) + `}`)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(signature.ProtectedHeader)
	if err != nil || !bytes.Equal(decoded, header) {
		return invalid
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize {
		return invalid
	}
	input := signature.ProtectedHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	if !ed25519.Verify(v.PublicKey, []byte(input), value) {
		return invalid
	}
	return nil
}

type NonceHMACCandidate struct {
	KeyVersion string
	HMAC       string
}

type VerificationResult struct {
	CanonicalPayload    []byte
	NonceHMAC           string
	NonceHMACKeyVersion string
	NonceHMACCandidates []NonceHMACCandidate
}

type FailureCode string

const (
	FailureRequired      FailureCode = "strong_auth_required"
	FailureInvalid       FailureCode = "strong_auth_invalid"
	FailureInvalidIssuer FailureCode = "strong_auth_invalid_issuer"
	FailureExpired       FailureCode = "strong_auth_expired"
	FailureReplayed      FailureCode = "strong_auth_replayed"
)

type VerificationError struct {
	Code FailureCode
	err  error
}

func (e *VerificationError) Error() string {
	if e == nil || e.err == nil {
		return string(FailureInvalid)
	}
	return string(e.Code) + ": " + e.err.Error()
}

func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func verificationError(code FailureCode, message string) error {
	return &VerificationError{Code: code, err: errors.New(message)}
}

// CanonicalPayload returns the UTF-8 canonical JSON bytes covered by the
// signature. This is a deliberately restricted JCS encoder: the schema has
// fixed ASCII property names and only strings, null and arrays of strings.
// It is not a general-purpose JCS encoder for numbers or arbitrary object keys.
func CanonicalPayload(payload ProofPayload) ([]byte, error) {
	if err := validatePayloadShape(payload); err != nil {
		return nil, err
	}
	value := map[string]any{
		"acr":             payload.ACR,
		"amr":             payload.AMR,
		"audience":        payload.Audience,
		"auth_time":       payload.AuthTime,
		"endpoint":        payload.Endpoint,
		"expires_at":      payload.ExpiresAt,
		"idempotency_key": payload.IdempotencyKey,
		"issuer":          payload.Issuer,
		"method":          payload.Method,
		"nonce":           payload.Nonce,
		"request_hash":    payload.RequestHash,
		"session":         payload.Session,
		"subject":         payload.Subject,
	}
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
		case []string:
			out.WriteByte('[')
			for j, item := range v {
				if j > 0 {
					out.WriteByte(',')
				}
				out.WriteString(jcsString(item))
			}
			out.WriteByte(']')
		default:
			return nil, errors.New("unsupported canonical payload type")
		}
	}
	out.WriteByte('}')
	return []byte(out.String()), nil
}

// Inputs have already passed UTF-8 validation. JCS leaves non-control Unicode
// characters (including U+2028/U+2029 and HTML characters) unescaped.
func jcsString(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func validatePayloadShape(payload ProofPayload) error {
	for name, field := range map[string]struct {
		value string
		max   int
	}{
		"issuer": {payload.Issuer, 256}, "audience": {payload.Audience, 256}, "subject": {payload.Subject, 256},
		"session": {payload.Session, 256}, "auth_time": {payload.AuthTime, 64}, "expires_at": {payload.ExpiresAt, 64},
		"method": {payload.Method, 32}, "nonce": {payload.Nonce, 256}, "endpoint": {payload.Endpoint, 128},
		"request_hash": {payload.RequestHash, 64}, "idempotency_key": {payload.IdempotencyKey, 128},
	} {
		if field.value == "" {
			return fmt.Errorf("strong-auth payload field %s is required", name)
		}
		if !utf8.ValidString(field.value) || utf8.RuneCountInString(field.value) > field.max {
			return fmt.Errorf("strong-auth payload field %s is too long", name)
		}
	}
	if payload.Method != "webauthn" && payload.Method != "totp" && payload.Method != "oidc_mfa" {
		return errors.New("strong-auth payload method is invalid")
	}
	if payload.Method == "webauthn" && !contains(payload.AMR, "webauthn") {
		return errors.New("strong-auth WebAuthn proof must declare the WebAuthn method")
	}
	if payload.Method == "oidc_mfa" && (payload.ACR == nil || *payload.ACR == "" || len(payload.AMR) == 0) {
		return errors.New("strong-auth OIDC proof requires ACR and AMR")
	}
	if payload.ACR != nil && (!utf8.ValidString(*payload.ACR) || utf8.RuneCountInString(*payload.ACR) > 256) {
		return errors.New("strong-auth ACR is too long")
	}
	if payload.AMR == nil || len(payload.AMR) > 16 {
		return errors.New("strong-auth AMR is invalid")
	}
	seenAMR := make(map[string]struct{}, len(payload.AMR))
	for _, method := range payload.AMR {
		if method == "" || !utf8.ValidString(method) || utf8.RuneCountInString(method) > 128 {
			return errors.New("strong-auth AMR entry is invalid")
		}
		if _, exists := seenAMR[method]; exists {
			return errors.New("strong-auth AMR entries must be unique")
		}
		seenAMR[method] = struct{}{}
	}
	if len(payload.Nonce) < 16 || len(payload.Nonce) > 256 || !safeToken(payload.Nonce) {
		return errors.New("strong-auth nonce is invalid")
	}
	if !endpointToken(payload.Endpoint) {
		return errors.New("strong-auth endpoint is invalid")
	}
	if len(payload.RequestHash) != 64 || !hexLower(payload.RequestHash) {
		return errors.New("strong-auth request hash is invalid")
	}
	if !validIdempotencyKey(payload.IdempotencyKey) {
		return errors.New("strong-auth idempotency key is invalid")
	}
	return nil
}

// Verify checks the signed proof and request/time bindings. It does not mark a
// nonce consumed: callers must atomically persist the returned HMAC together
// with their audit intent and target mutation, then map a unique-key conflict
// to FailureReplayed.
func Verify(proof Proof, request RequestBinding, cfg VerifyConfig) (VerificationResult, error) {
	if proof.SchemaVersion != ProofSchemaVersion {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth schema version is invalid")
	}
	if err := validatePayloadShape(proof.Payload); err != nil {
		return VerificationResult{}, verificationError(FailureInvalid, err.Error())
	}
	// JSON Schema length bounds count Unicode scalars, not UTF-8 bytes.
	if proof.Signature.DomainSeparator != DomainSeparator || proof.Signature.Algorithm == "" || !utf8.ValidString(proof.Signature.Algorithm) || utf8.RuneCountInString(proof.Signature.Algorithm) > 32 ||
		proof.Signature.KeyID == "" || !utf8.ValidString(proof.Signature.KeyID) || utf8.RuneCountInString(proof.Signature.KeyID) > 256 ||
		proof.Signature.KeyVersion == "" || !utf8.ValidString(proof.Signature.KeyVersion) || utf8.RuneCountInString(proof.Signature.KeyVersion) > 128 {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth signature metadata is invalid")
	}
	if proof.Signature.Format != "jws" && proof.Signature.Format != "cose" {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth signature format is invalid")
	}
	if len(proof.Signature.ProtectedHeader) > 4096 || len(proof.Signature.Value) > 4096 || !base64URL(proof.Signature.ProtectedHeader) || !base64URL(proof.Signature.Value) {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth signature encoding is invalid")
	}

	payload := proof.Payload
	if payload.Issuer != request.Issuer {
		return VerificationResult{}, verificationError(FailureInvalidIssuer, "strong-auth issuer does not match request")
	}
	if cfg.ExpectedAudience != "" && payload.Audience != cfg.ExpectedAudience {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth audience does not match")
	}
	if payload.Audience != request.Audience || payload.Subject != request.Subject || payload.Session != request.Session ||
		payload.Endpoint != request.Endpoint || payload.RequestHash != request.RequestHash || payload.IdempotencyKey != request.IdempotencyKey {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth request binding does not match")
	}
	if cfg.ExpectedSubject != "" && payload.Subject != cfg.ExpectedSubject {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth subject is not allowed")
	}
	if cfg.ExpectedSession != "" && payload.Session != cfg.ExpectedSession {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth session is not allowed")
	}
	policy, trusted := cfg.TrustedIssuerPolicies[payload.Issuer]
	if !trusted {
		return VerificationResult{}, verificationError(FailureInvalidIssuer, "strong-auth issuer policy is unavailable")
	}
	if !contains(policy.Methods, payload.Method) {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth method is not allowed")
	}
	if payload.Method == "oidc_mfa" && (payload.ACR == nil || !contains(policy.ACR, *payload.ACR)) {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth ACR is not allowed")
	}
	for _, method := range payload.AMR {
		if !contains(policy.AMR, method) {
			return VerificationResult{}, verificationError(FailureInvalid, "strong-auth AMR is not allowed")
		}
	}

	if err := verifyProofTimeAt(payload, cfg.Now, cfg.MaxAge, cfg.ClockSkew); err != nil {
		return VerificationResult{}, err
	}

	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return VerificationResult{}, verificationError(FailureInvalid, err.Error())
	}
	byVersion := cfg.TrustedSigners[payload.Issuer]
	verifier := byVersion[proof.Signature.KeyVersion]
	if verifier == nil {
		return VerificationResult{}, verificationError(FailureInvalidIssuer, "strong-auth signing key version is not trusted")
	}
	if err := verifier.Verify(canonical, proof.Signature); err != nil {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth signature verification failed")
	}

	if cfg.ActiveNonceHMACKeyVersion == "" || len(cfg.NonceHMACKeys[cfg.ActiveNonceHMACKeyVersion]) == 0 {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth active nonce HMAC key is unavailable")
	}
	if len(cfg.RequiredNonceHMACKeyVersions) == 0 || len(cfg.RequiredNonceHMACKeyVersions) != len(cfg.NonceHMACKeys) {
		return VerificationResult{}, verificationError(FailureInvalid, "strong-auth retained nonce key snapshot is incomplete")
	}
	seenVersions := make(map[string]bool)
	for _, version := range cfg.RequiredNonceHMACKeyVersions {
		if version == "" || seenVersions[version] || len(cfg.NonceHMACKeys[version]) == 0 {
			return VerificationResult{}, verificationError(FailureInvalid, "strong-auth retained nonce key is unavailable")
		}
		seenVersions[version] = true
	}
	keyVersions := make([]string, 0, len(cfg.NonceHMACKeys))
	for version := range cfg.NonceHMACKeys {
		keyVersions = append(keyVersions, version)
	}
	sort.Strings(keyVersions)
	candidates := make([]NonceHMACCandidate, 0, len(keyVersions))
	for _, version := range keyVersions {
		key := cfg.NonceHMACKeys[version]
		if len(key) == 0 {
			return VerificationResult{}, verificationError(FailureInvalid, "strong-auth retained nonce key is unavailable")
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(payload.Nonce))
		candidates = append(candidates, NonceHMACCandidate{KeyVersion: version, HMAC: hex.EncodeToString(mac.Sum(nil))})
	}
	for _, candidate := range candidates {
		if candidate.KeyVersion == cfg.ActiveNonceHMACKeyVersion {
			return VerificationResult{
				CanonicalPayload:    canonical,
				NonceHMAC:           candidate.HMAC,
				NonceHMACKeyVersion: candidate.KeyVersion,
				NonceHMACCandidates: candidates,
			}, nil
		}
	}
	return VerificationResult{}, verificationError(FailureInvalid, "strong-auth active nonce HMAC key is unavailable")
}

// Temporal validation alone is NOT proof verification or authority. A caller
// that has already verified the immutable proof can use this after its final
// adapter/SQL calls with a fresh database time, without rerunning an adapter
// that could itself delay past expiry.
func verifyProofTimeAt(payload ProofPayload, now time.Time, maxAge, clockSkew time.Duration) error {
	authTime, expiresAt, err := parseTimes(payload)
	if err != nil {
		return verificationError(FailureInvalid, err.Error())
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if clockSkew < 0 {
		return verificationError(FailureInvalid, "strong-auth clock skew is invalid")
	}
	if maxAge <= 0 {
		return verificationError(FailureInvalid, "strong-auth max age is invalid")
	}
	if authTime.After(now.Add(clockSkew)) || now.Sub(authTime) > maxAge+clockSkew {
		return verificationError(FailureExpired, "strong-auth authentication time is outside the allowed window")
	}
	if !expiresAt.After(now) || !expiresAt.After(authTime) {
		return verificationError(FailureExpired, "strong-auth proof is expired")
	}
	return nil
}

func parseTimes(payload ProofPayload) (time.Time, time.Time, error) {
	authTime, err := time.Parse(time.RFC3339, payload.AuthTime)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("strong-auth auth_time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("strong-auth expires_at is invalid")
	}
	return authTime.UTC(), expiresAt.UTC(), nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func boundedText(value string, min, max int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= min && length <= max && (min == 0 || strings.TrimSpace(value) != "")
}

func safeToken(value string) bool {
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func endpointToken(value string) bool {
	for index, char := range value {
		if index == 0 && !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')) {
			return false
		}
		if index > 0 && !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return value != ""
}

func hexLower(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func base64URL(value string) bool {
	if value == "" {
		return false
	}
	if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
		return false
	}
	return true
}
