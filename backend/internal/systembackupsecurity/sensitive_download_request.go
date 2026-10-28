package systembackupsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SensitiveDownloadEndpoint = "getSystemBackupEvidence"
const SensitiveDownloadRequestDomain = "clawmanager.system-backup.evidence-download-request.v1"

var ErrSensitiveDownloadRequest = errors.New("validation_failed")
var sensitiveDownloadInstallation = regexp.MustCompile(`^installation_[A-Za-z0-9_-]{1,115}$`)
var sensitiveDownloadEvidence = regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SensitiveDownloadRequestFacts are independently loaded server facts, NOT an
// HTTP DTO or permission grant. The evidence adapter hashes the full validated
// Manifest and normalizes Range before constructing these facts.
type SensitiveDownloadRequestFacts struct {
	Installation, EvidenceID, ManifestSHA256, IdempotencyKey string
	Actor                                                    RegistrationActor
	ContentSize, RangeStart, RangeEnd                        int64
	RangePresent                                             bool
}

// SensitiveDownloadRequest is one immutable input for issuance and verification.
// The key is separately bound in ProofPayload; the server claim is not signed.
type SensitiveDownloadRequest struct {
	installation, evidence, subject, session, manifest, key, canonical, digest string
	start, end                                                                 int64
	present                                                                    bool
}

func NewSensitiveDownloadRequest(f SensitiveDownloadRequestFacts) (SensitiveDownloadRequest, error) {
	const safeInteger int64 = 9007199254740991
	bad := func() (SensitiveDownloadRequest, error) {
		return SensitiveDownloadRequest{}, ErrSensitiveDownloadRequest
	}
	if !sensitiveDownloadInstallation.MatchString(f.Installation) || !sensitiveDownloadEvidence.MatchString(f.EvidenceID) ||
		f.Actor.UserID < 1 || f.Actor.Subject != "user:"+strconv.FormatInt(f.Actor.UserID, 10) ||
		len(f.Actor.Session) != 64 || !hexLower(f.Actor.Session) || len(f.ManifestSHA256) != 64 || !hexLower(f.ManifestSHA256) ||
		!validIdempotencyKey(f.IdempotencyKey) || f.ContentSize < 0 || f.ContentSize > safeInteger || f.RangeStart < 0 || f.RangeEnd < f.RangeStart || f.RangeEnd > safeInteger {
		return bad()
	}
	if f.ContentSize == 0 {
		// The new decision defines this encoding. Current evidence Manifests
		// reject empty content, so the evidence adapter cannot produce it yet.
		if f.RangePresent || f.RangeStart != 0 || f.RangeEnd != 0 {
			return bad()
		}
	} else if f.RangeEnd >= f.ContentSize || !f.RangePresent && (f.RangeStart != 0 || f.RangeEnd != f.ContentSize-1) {
		return bad()
	}
	input := map[string]any{
		"domain": SensitiveDownloadRequestDomain, "endpoint": SensitiveDownloadEndpoint,
		"origin_installation_id": f.Installation, "evidence_id": f.EvidenceID,
		"subject": f.Actor.Subject, "session": f.Actor.Session, "manifest_sha256": f.ManifestSHA256,
		"range_present": f.RangePresent, "range_start": json.Number(strconv.FormatInt(f.RangeStart, 10)), "range_end": json.Number(strconv.FormatInt(f.RangeEnd, 10)),
	}
	var out strings.Builder
	canonicalMutationJSON(&out, input)
	canonical := out.String()
	return SensitiveDownloadRequest{installation: f.Installation, evidence: f.EvidenceID, subject: f.Actor.Subject, session: f.Actor.Session, manifest: f.ManifestSHA256,
		key: f.IdempotencyKey, canonical: canonical, digest: registrationHash(canonical), start: f.RangeStart, end: f.RangeEnd, present: f.RangePresent}, nil
}

func (r SensitiveDownloadRequest) CanonicalJSON() []byte  { return []byte(r.canonical) }
func (r SensitiveDownloadRequest) RequestHash() string    { return r.digest }
func (r SensitiveDownloadRequest) ManifestSHA256() string { return r.manifest }
func (r SensitiveDownloadRequest) IdempotencyKey() string { return r.key }
func (r SensitiveDownloadRequest) InstallationID() string { return r.installation }
func (r SensitiveDownloadRequest) EvidenceID() string     { return r.evidence }

// MatchesActor compares immutable request identity, not current authorization.
func (r SensitiveDownloadRequest) MatchesActor(a RegistrationActor) bool {
	return r.canonical != "" && a.UserID > 0 && a.Subject == "user:"+strconv.FormatInt(a.UserID, 10) && r.subject == a.Subject && r.session == a.Session
}
func (r SensitiveDownloadRequest) Range() (int64, int64, bool) { return r.start, r.end, r.present }

// ProofBinding is shared by the future issuance service and the verifier. The
// issuer must be selected from the trusted registry, never accepted as authority
// merely because it occurs in the proof. This method grants no authority.
func (r SensitiveDownloadRequest) ProofBinding(issuer string) (RequestBinding, error) {
	if r.canonical == "" || issuer == "" || !utf8.ValidString(issuer) || utf8.RuneCountInString(issuer) > 256 {
		return RequestBinding{}, ErrSensitiveDownloadRequest
	}
	return RequestBinding{Issuer: issuer, Audience: r.installation, Subject: r.subject, Session: r.session,
		Endpoint: SensitiveDownloadEndpoint, RequestHash: r.digest, IdempotencyKey: r.key}, nil
}

// SensitiveDownloadProofVerification contains only non-consuming crypto/time
// results. It is NOT a prelocked context, receipt, current authorization, nonce
// reservation or permission to read a provider. D must still implement those.
type SensitiveDownloadProofVerification struct {
	request             SensitiveDownloadRequest
	candidates          []NonceHMACCandidate
	active              NonceHMACCandidate
	verifiedAt          time.Time
	expiresAt           time.Time
	timePayload         ProofPayload
	maxAge, skew        time.Duration
	issuer, fingerprint string
	authenticatedAt     time.Time
}

func (v SensitiveDownloadProofVerification) Request() SensitiveDownloadRequest { return v.request }
func (v SensitiveDownloadProofVerification) NonceCandidates() []NonceHMACCandidate {
	return append([]NonceHMACCandidate(nil), v.candidates...)
}
func (v SensitiveDownloadProofVerification) ActiveNonce() NonceHMACCandidate { return v.active }
func (v SensitiveDownloadProofVerification) ProofExpiresAt() time.Time       { return v.expiresAt }

// SignedAuthTime is the issuer's signed auth_time, which may be ahead within
// allowed skew. Nonce authenticated_at must use ProofAcceptedAt, not this value.
func (v SensitiveDownloadProofVerification) SignedAuthTime() time.Time { return v.authenticatedAt }
func (v SensitiveDownloadProofVerification) IssuerSHA256() string {
	if v.fingerprint == "" {
		return ""
	}
	return registrationHash(v.issuer)
}

// SameAdmissionVerification compares the original sealed verification, including
// nonce candidates and original time policy. Re-verifying a different proof for
// the same request or refreshing the observation time cannot replace it.
func (v SensitiveDownloadProofVerification) SameAdmissionVerification(other SensitiveDownloadProofVerification) bool {
	if v.request.canonical == "" || v.request != other.request || v.fingerprint == "" || v.fingerprint != other.fingerprint || v.issuer != other.issuer || !v.authenticatedAt.Equal(other.authenticatedAt) ||
		v.active != other.active || !v.verifiedAt.Equal(other.verifiedAt) || !v.expiresAt.Equal(other.expiresAt) ||
		v.timePayload.AuthTime != other.timePayload.AuthTime || v.timePayload.ExpiresAt != other.timePayload.ExpiresAt ||
		v.maxAge != other.maxAge || v.skew != other.skew || len(v.candidates) == 0 || len(v.candidates) != len(other.candidates) {
		return false
	}
	for i, candidate := range v.candidates {
		if candidate != other.candidates[i] {
			return false
		}
	}
	return true
}
func (SensitiveDownloadProofVerification) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveDownloadRequest
}

// VerifyProofHeader distinguishes missing proof from malformed/duplicate wire
// input, using the same strict proof decoder as existing A endpoints.
func (r SensitiveDownloadRequest) VerifyProofHeader(headers []string, issuer string, cfg VerifyConfig) (SensitiveDownloadProofVerification, error) {
	if len(headers) == 0 {
		return SensitiveDownloadProofVerification{}, verificationError(FailureRequired, "strong-auth proof is required")
	}
	if len(headers) != 1 {
		return SensitiveDownloadProofVerification{}, ErrSensitiveDownloadRequest
	}
	proof, err := DecodeStrongAuthHeader(headers[0])
	if err != nil {
		return SensitiveDownloadProofVerification{}, ErrSensitiveDownloadRequest
	}
	return r.VerifyProof(proof, issuer, cfg)
}

// RecheckProofAt uses a fresh SQL UTC supplied by D after callbacks/writes. It
// cannot extend the original limits or replace current session/RBAC/owner,
// material-history, claim, retention and physical-capacity checks.
func (v SensitiveDownloadProofVerification) RecheckProofAt(now time.Time) error {
	if v.request.canonical == "" || now.IsZero() || now.Before(v.verifiedAt) {
		return ErrRegistrationUnavailable
	}
	return verifyProofTimeAt(v.timePayload, now, v.maxAge, v.skew)
}

// VerifyProof verifies signature, exact request/key and all retained HMAC
// candidates, but makes no SQL calls and consumes nothing. Missing material is
// not an invalid client proof. The required version set must originate in D's
// locked config-history UNION retained-ledger snapshot, not the material map.
func (r SensitiveDownloadRequest) VerifyProof(proof Proof, issuer string, cfg VerifyConfig) (SensitiveDownloadProofVerification, error) {
	if cfg.Now.IsZero() || cfg.MaxAge <= 0 || cfg.ClockSkew < 0 || cfg.ExpectedAudience == "" || cfg.ExpectedSubject == "" || cfg.ExpectedSession == "" ||
		len(cfg.TrustedSigners) == 0 || len(cfg.TrustedIssuerPolicies) == 0 || len(cfg.RequiredNonceHMACKeyVersions) == 0 || len(cfg.RequiredNonceHMACKeyVersions) > 10000 ||
		len(cfg.RequiredNonceHMACKeyVersions) != len(cfg.NonceHMACKeys) || cfg.ActiveNonceHMACKeyVersion == "" {
		return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
	}
	seen := make(map[string]bool)
	for _, version := range cfg.RequiredNonceHMACKeyVersions {
		if version == "" || seen[version] || len(cfg.NonceHMACKeys[version]) != 32 {
			return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
		}
		seen[version] = true
	}
	if !seen[cfg.ActiveNonceHMACKeyVersion] {
		return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
	}
	binding, err := r.ProofBinding(issuer)
	if err != nil {
		return SensitiveDownloadProofVerification{}, err
	}
	if _, trusted := cfg.TrustedIssuerPolicies[issuer]; trusted {
		versions := cfg.TrustedSigners[issuer]
		if len(versions) == 0 {
			return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
		}
		if verifier, declared := versions[proof.Signature.KeyVersion]; declared && nilConfigMutationBoundary(verifier) {
			return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
		}
	}
	// Freeze the key snapshot before the verifier callback and erase only owned
	// copies. A callback must not change which nonce candidates are produced.
	keys := make(map[string][]byte, len(cfg.NonceHMACKeys))
	for version, key := range cfg.NonceHMACKeys {
		keys[version] = append([]byte(nil), key...)
	}
	defer func() {
		for _, key := range keys {
			for i := range key {
				key[i] = 0
			}
		}
	}()
	cfg.NonceHMACKeys = keys
	cfg.RequiredNonceHMACKeyVersions = append([]string(nil), cfg.RequiredNonceHMACKeyVersions...)
	result, err := Verify(proof, binding, cfg)
	if err != nil {
		return SensitiveDownloadProofVerification{}, err
	}
	// Bind the exact validated signed payload and signature without retaining
	// raw proof/nonce bytes. The outer transaction can compare original proof
	// identity and obtain signed issuer/auth-time facts from this seal. The
	// ledger's authenticated_at remains the server-side ProofAcceptedAt sample.
	fingerprinter := sha256.New()
	fingerprinter.Write(result.CanonicalPayload)
	fingerprinter.Write([]byte{0})
	signatureJSON, signatureErr := json.Marshal(proof.Signature)
	if signatureErr != nil {
		wipeSecret(result.CanonicalPayload)
		return SensitiveDownloadProofVerification{}, ErrRegistrationUnavailable
	}
	fingerprinter.Write(signatureJSON)
	fingerprint := hex.EncodeToString(fingerprinter.Sum(nil))
	for i := range result.CanonicalPayload {
		result.CanonicalPayload[i] = 0
	}
	authenticated, expires, err := parseTimes(proof.Payload)
	if err != nil {
		return SensitiveDownloadProofVerification{}, ErrSensitiveDownloadRequest
	}
	return SensitiveDownloadProofVerification{request: r, candidates: result.NonceHMACCandidates,
		active: NonceHMACCandidate{KeyVersion: result.NonceHMACKeyVersion, HMAC: result.NonceHMAC}, verifiedAt: cfg.Now.UTC(), expiresAt: expires,
		issuer: proof.Payload.Issuer, authenticatedAt: authenticated, fingerprint: fingerprint,
		timePayload: ProofPayload{AuthTime: proof.Payload.AuthTime, ExpiresAt: proof.Payload.ExpiresAt}, maxAge: cfg.MaxAge, skew: cfg.ClockSkew}, nil
}
