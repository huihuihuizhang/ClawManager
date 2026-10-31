package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// PublicationSigningKey is the existing public-c-crypto.v1 payload key reference.
type PublicationSigningKey struct {
	Purpose    string `json:"purpose"`
	KeyID      string `json:"key_id"`
	KeyVersion string `json:"key_version"`
}

type publicationSignature struct {
	Algorithm  string `json:"algorithm"`
	Purpose    string `json:"key_purpose"`
	KeyID      string `json:"key_id"`
	KeyVersion string `json:"key_version"`
	Domain     string `json:"domain_separator"`
	Header     string `json:"protected_header"`
	Value      string `json:"value"`
}

type publicationEnvelope struct {
	Payload   json.RawMessage      `json:"payload"`
	Signature publicationSignature `json:"signature"`
}

// PreparedPublicationRecord owns copies of exact JCS bytes. It grants no
// business acceptance: the original publisher must validate its complete C
// payload and six-domain evidence before Stage in its original transaction.
type PreparedPublicationRecord struct {
	owner          *SQLInstallationArtifactSigners
	task           ArtifactSigningTask
	binding        TransitSigningBinding
	payload, input []byte
	header         string
}

// PublicationSigningKey returns the independently installed active reference;
// neither a request nor a payload can select a different signing key.
func (s *SQLInstallationArtifactSigners) PublicationSigningKey(ctx context.Context, purpose string) (PublicationSigningKey, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.InstallationArtifactSigners == nil || s.owners[purpose] == nil || s.check(ctx) != nil {
		return PublicationSigningKey{}, ErrRegistrationUnavailable
	}
	b := s.owners[purpose].binding
	return PublicationSigningKey{b.Purpose, b.KeyID, b.KeyVersion}, nil
}

func publicationDomain(purpose string) string {
	return map[string]string{"capture_certificate": "clawmanager.system-backup.capture_certificate.v1", "acceptance_record": "clawmanager.system-backup.acceptance.v1", "catalog_record": "clawmanager.system-backup.catalog_record.v1"}[purpose]
}

func publicationInput(payload []byte, task ArtifactSigningTask, binding TransitSigningBinding) ([]byte, string, error) {
	header, err := jsoncanonicalizer.Transform(providerCanonical(map[string]any{"alg": "EdDSA", "key_version": binding.KeyVersion, "kid": binding.KeyID, "purpose": binding.Purpose, "typ": publicationDomain(binding.Purpose)}))
	if err != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	encoded := base64.RawURLEncoding.EncodeToString(header)
	input := []byte(encoded + "." + base64.RawURLEncoding.EncodeToString(payload))
	if validateFrozenSigningInput(input, task, binding) != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	return input, encoded, nil
}

// PreparePublicationRecord uses public-c-crypto.v1 JCS/JWS, never the legacy
// recovery.Seal format. Payload schema/business validation remains the C owner
// responsibility. Identity, schema, artifact time and key binding fail closed.
func (s *SQLInstallationArtifactSigners) PreparePublicationRecord(ctx context.Context, purpose string, payload []byte) (*PreparedPublicationRecord, error) {
	if _, err := s.PublicationSigningKey(ctx, purpose); err != nil {
		return nil, err
	}
	a := s.owners[purpose]
	if len(payload) == 0 || len(payload) > maxArtifactSigningInputBytes {
		return nil, ErrRegistrationUnavailable
	}
	canonical, err := jsoncanonicalizer.Transform(bytes.Clone(payload))
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	input, header, err := publicationInput(canonical, a.task, a.binding)
	if err != nil {
		return nil, err
	}
	history, err := s.History(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = publicationKey(history, canonical, a.binding); err != nil {
		return nil, err
	}
	return &PreparedPublicationRecord{owner: s, task: a.task, binding: a.binding, payload: canonical, input: input, header: header}, nil
}

// Stage freezes the exact signing input under the CURRENT original publisher
// claim. Commit/rollback belong to the caller. No provider RPC occurs here.
func (p *PreparedPublicationRecord) Stage(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.owner == nil {
		return ErrRegistrationUnavailable
	}
	return p.owner.StageSigningInput(ctx, tx, p.binding.Purpose, p.input)
}

// SignCommitted must run after the original transaction commits. The SQL
// authority rechecks that committed input and current claim before and after
// provider use; an uncommitted/rolled-back Stage cannot authorize signing.
func (p *PreparedPublicationRecord) SignCommitted(ctx context.Context) ([]byte, string, error) {
	if p == nil || p.owner == nil {
		return nil, "", ErrRegistrationUnavailable
	}
	signer, err := p.owner.Signer(p.binding.Purpose)
	if err != nil {
		return nil, "", err
	}
	signature, err := signer.Sign(ctx, bytes.Clone(p.input))
	if err != nil {
		return nil, "", err
	}
	envelope := publicationEnvelope{Payload: p.payload, Signature: publicationSignature{"EdDSA", p.binding.Purpose, p.binding.KeyID, p.binding.KeyVersion, publicationDomain(p.binding.Purpose), p.header, base64.RawURLEncoding.EncodeToString(signature)}}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	history, err := p.owner.History(ctx)
	if err != nil {
		return nil, "", err
	}
	checksum, err := history.VerifyPublicationRecord(raw, p.task, p.binding.Purpose)
	if err != nil {
		return nil, "", err
	}
	return raw, checksum, nil
}

// publicationKey checks artifact-time validity and current revocation against
// independently authenticated history. It deliberately does not infer local
// acceptance, immutable storage or terminal task success from a signature.
func publicationKey(h *ArtifactSigningKeyHistory, payload []byte, b TransitSigningBinding) (ed25519.PublicKey, error) {
	if h == nil || h.installationID != b.InstallationID {
		return nil, ErrRegistrationUnavailable
	}
	var p struct {
		Schema   string `json:"schema_version"`
		Issued   string `json:"issued_at"`
		Decision string `json:"decision_at"`
		Recorded string `json:"recorded_at"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil, ErrRegistrationUnavailable
	}
	schema := map[string]string{"capture_certificate": "system-backup-capture-certificate.v1", "acceptance_record": "system-backup-acceptance.v1", "catalog_record": "system-backup-catalog-record.v1"}[b.Purpose]
	at := map[string]string{"capture_certificate": p.Issued, "acceptance_record": p.Decision, "catalog_record": p.Recorded}[b.Purpose]
	when, err := time.Parse(time.RFC3339Nano, at)
	if schema == "" || p.Schema != schema || err != nil {
		return nil, ErrRegistrationUnavailable
	}
	for _, key := range h.PurposeKeys(b.Purpose) {
		if key.KeyID == b.KeyID && key.KeyVersion == b.KeyVersion && !key.Revoked && !when.Before(key.NotBefore) && when.Before(key.NotAfter) {
			return key.PublicKey, nil
		}
	}
	return nil, ErrRegistrationUnavailable
}

// VerifyPublicationRecord authenticates exact canonical public record bytes
// and returns their object SHA-256. The storage reader separately pins the
// expected checksum/immutable version and validates full business payloads.
func (h *ArtifactSigningKeyHistory) VerifyPublicationRecord(raw []byte, task ArtifactSigningTask, purpose string) (string, error) {
	if h == nil || len(raw) == 0 || len(raw) > maxArtifactSigningInputBytes || !artifactSigningPurpose(purpose) {
		return "", ErrRegistrationUnavailable
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", ErrRegistrationUnavailable
	}
	var e publicationEnvelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF {
		return "", ErrRegistrationUnavailable
	}
	s := e.Signature
	if s.Algorithm != "EdDSA" || s.Purpose != purpose || s.Domain != publicationDomain(purpose) {
		return "", ErrRegistrationUnavailable
	}
	b := TransitSigningBinding{InstallationID: h.installationID, Purpose: purpose, KeyID: s.KeyID, KeyVersion: s.KeyVersion}
	input, header, err := publicationInput(e.Payload, task, b)
	if err != nil || header != s.Header {
		return "", ErrRegistrationUnavailable
	}
	key, err := publicationKey(h, e.Payload, b)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Value)
	if err != nil || base64.RawURLEncoding.EncodeToString(sig) != s.Value || !ed25519.Verify(key, input, sig) {
		return "", ErrRegistrationUnavailable
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
