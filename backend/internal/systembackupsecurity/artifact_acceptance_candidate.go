package systembackupsecurity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This is an A-side candidate for the draft v12 acceptance signature. It is
// deliberately separate from the production artifact path until the signing
// algorithm and protected-header semantics are frozen by the contract owners.
const AcceptanceCandidateDomain = "clawmanager.system-backup.acceptance.v1"

var (
	errAcceptanceCandidate = errors.New("invalid acceptance signature candidate")
	acceptanceBackupID     = regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`)
	acceptanceEvidenceID   = regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`)
	acceptanceHash         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type AcceptanceCandidateKey = ArtifactSigningPublicKey

type AcceptanceCandidateBinding struct {
	OriginInstallationID                             string
	BackupPublicID, ManifestChecksum, MarkerChecksum string
	AttemptNo                                        int64
}

type acceptanceCandidatePayload struct {
	SchemaVersion              string   `json:"schema_version"`
	BackupPublicID             string   `json:"backup_public_id"`
	AttemptNo                  int64    `json:"attempt_no"`
	ManifestChecksum           string   `json:"manifest_checksum"`
	MarkerChecksum             string   `json:"marker_checksum"`
	StagingCleanupEvidenceID   string   `json:"staging_cleanup_evidence_id"`
	StagingCleanupEvidenceHash string   `json:"staging_cleanup_evidence_hash"`
	LocalAcceptance            bool     `json:"local_acceptance"`
	LocalReasonCodes           []string `json:"local_reason_codes"`
	LocalReasonCodesHash       string   `json:"local_reason_codes_hash"`
	DecisionAt                 string   `json:"decision_at"`
	ConfigVersion              int64    `json:"config_version"`
}

// VerifyAcceptanceCandidate authenticates an exact manifest/marker binding
// against a caller-resolved historical public-key snapshot. Historical keys
// can be expired now, but must have been valid at decision time; a revoked key
// always fails. It does not authenticate the catalog or grant artifact reads.
func VerifyAcceptanceCandidate(raw []byte, binding AcceptanceCandidateBinding, keys []AcceptanceCandidateKey) error {
	bad := func() error { return errAcceptanceCandidate }
	if !providerBoundedString(binding.OriginInstallationID) || len(raw) == 0 || len(raw) > 16*1024 || !providerJSONUnicode(raw) ||
		!providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return bad()
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || !providerFieldSet(root, "payload", "signature") {
		return bad()
	}
	var p, s, k map[string]json.RawMessage
	if json.Unmarshal(root["payload"], &p) != nil || !providerFieldSet(p,
		"schema_version", "backup_public_id", "attempt_no", "manifest_checksum", "marker_checksum",
		"staging_cleanup_evidence_id", "staging_cleanup_evidence_hash", "local_acceptance",
		"local_reason_codes", "local_reason_codes_hash", "decision_at", "config_version", "signing_key") ||
		json.Unmarshal(p["signing_key"], &k) != nil || !providerFieldSet(k, "purpose", "key_id", "key_version") ||
		json.Unmarshal(root["signature"], &s) != nil || !providerFieldSet(s,
		"algorithm", "key_purpose", "key_id", "key_version", "domain_separator", "protected_header", "value") {
		return bad()
	}
	var payload acceptanceCandidatePayload
	if json.Unmarshal(root["payload"], &payload) != nil {
		return bad()
	}
	var keyRef struct {
		Purpose    string `json:"purpose"`
		KeyID      string `json:"key_id"`
		KeyVersion string `json:"key_version"`
	}
	if json.Unmarshal(p["signing_key"], &keyRef) != nil {
		return bad()
	}
	var sig struct {
		Algorithm, KeyPurpose, KeyID, KeyVersion, DomainSeparator, ProtectedHeader, Value string
	}
	for field, dest := range map[string]*string{
		"algorithm": &sig.Algorithm, "key_purpose": &sig.KeyPurpose, "key_id": &sig.KeyID,
		"key_version": &sig.KeyVersion, "domain_separator": &sig.DomainSeparator,
		"protected_header": &sig.ProtectedHeader, "value": &sig.Value,
	} {
		if json.Unmarshal(s[field], dest) != nil || *dest == "" {
			return bad()
		}
	}
	if payload.SchemaVersion != "system-backup-acceptance.v1" ||
		!acceptanceBackupID.MatchString(payload.BackupPublicID) || !acceptanceEvidenceID.MatchString(payload.StagingCleanupEvidenceID) ||
		payload.AttemptNo < 1 || payload.AttemptNo > 9007199254740991 || payload.ConfigVersion < 1 || payload.ConfigVersion > 9007199254740991 ||
		!acceptanceHash.MatchString(payload.ManifestChecksum) || !acceptanceHash.MatchString(payload.MarkerChecksum) ||
		!acceptanceHash.MatchString(payload.StagingCleanupEvidenceHash) || !acceptanceHash.MatchString(payload.LocalReasonCodesHash) ||
		payload.BackupPublicID != binding.BackupPublicID || payload.AttemptNo != binding.AttemptNo ||
		payload.ManifestChecksum != binding.ManifestChecksum || payload.MarkerChecksum != binding.MarkerChecksum ||
		keyRef.Purpose != "acceptance_record" || keyRef.KeyID == "" || len(keyRef.KeyID) > 256 || !utf8.ValidString(keyRef.KeyID) ||
		keyRef.KeyVersion == "" || len(keyRef.KeyVersion) > 128 || !utf8.ValidString(keyRef.KeyVersion) ||
		sig.Algorithm != "EdDSA" || sig.KeyPurpose != keyRef.Purpose || sig.KeyID != keyRef.KeyID ||
		sig.KeyVersion != keyRef.KeyVersion || sig.DomainSeparator != AcceptanceCandidateDomain {
		return bad()
	}
	decisionAt, err := time.Parse(time.RFC3339Nano, payload.DecisionAt)
	if err != nil || len(payload.LocalReasonCodes) == 0 || len(payload.LocalReasonCodes) > 7 {
		return bad()
	}
	allowed := map[string]bool{"eligible": true, "consistency_not_strong": true, "disqualifying_warning": true,
		"target_not_external": true, "target_risk": true, "attestation_invalid": true, "kek_not_recoverable": true}
	for i, code := range payload.LocalReasonCodes {
		if !allowed[code] || i > 0 && payload.LocalReasonCodes[i-1] >= code {
			return bad()
		}
	}
	if payload.LocalAcceptance != (len(payload.LocalReasonCodes) == 1 && payload.LocalReasonCodes[0] == "eligible") {
		return bad()
	}
	reasons := acceptanceCanonicalArray(payload.LocalReasonCodes)
	reasonDigest := sha256.Sum256(reasons)
	if payload.LocalReasonCodesHash != hex.EncodeToString(reasonDigest[:]) {
		return bad()
	}
	canonical, err := acceptanceCanonicalJSON(root["payload"])
	if err != nil {
		return bad()
	}
	header := providerCanonical(map[string]any{"alg": "EdDSA", "key_version": keyRef.KeyVersion, "kid": keyRef.KeyID,
		"purpose": "acceptance_record", "typ": AcceptanceCandidateDomain})
	if sig.ProtectedHeader != base64.RawURLEncoding.EncodeToString(header) {
		return bad()
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(sig.Value)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != sig.Value {
		return bad()
	}
	var match *AcceptanceCandidateKey
	for i := range keys {
		key := &keys[i]
		if key.InstallationID == binding.OriginInstallationID && key.Purpose == keyRef.Purpose && key.KeyID == keyRef.KeyID && key.KeyVersion == keyRef.KeyVersion {
			if match != nil {
				return bad()
			}
			match = key
		}
	}
	input := []byte(sig.ProtectedHeader + "." + base64.RawURLEncoding.EncodeToString(canonical))
	if match != nil && len(match.PublicKey) == ed25519.PublicKeySize && !match.Revoked &&
		!decisionAt.Before(match.NotBefore) && decisionAt.Before(match.NotAfter) &&
		ed25519.Verify(match.PublicKey, input, signature) {
		return nil
	}
	return bad()
}

// This restricted JCS encoder handles the acceptance schema's strings,
// booleans, positive safe integers, arrays and fixed nested object. Other
// JSON numbers and values fail closed instead of being rounded.
func acceptanceCanonicalJSON(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, errAcceptanceCandidate
	}
	var out strings.Builder
	if !acceptanceWriteCanonical(&out, value) {
		return nil, errAcceptanceCandidate
	}
	return []byte(out.String()), nil
}

func acceptanceCanonicalArray(values []string) []byte {
	var out strings.Builder
	out.WriteByte('[')
	for i, value := range values {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(jcsString(value))
	}
	out.WriteByte(']')
	return []byte(out.String())
}

func acceptanceWriteCanonical(out *strings.Builder, value any) bool {
	switch v := value.(type) {
	case string:
		out.WriteString(jcsString(v))
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n < 0 || n > 9007199254740991 || strconv.FormatInt(n, 10) != string(v) {
			return false
		}
		out.WriteString(string(v))
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if !acceptanceWriteCanonical(out, item) {
				return false
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(jcsString(key))
			out.WriteByte(':')
			if !acceptanceWriteCanonical(out, v[key]) {
				return false
			}
		}
		out.WriteByte('}')
	default:
		return false
	}
	return true
}
