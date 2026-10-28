// Package systembackupevidence owns evidence framing, verified reads and the
// evidence lifecycle. Registry/auth adapters belong to the control-plane owner;
// provider adapters must implement the exact-version and proof semantics below.
package systembackupevidence

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"
)

const (
	ChunkSize   int64 = 1 << 20
	MaxContent  int64 = 1 << 30
	MaxResponse int64 = 8 << 20
	MaxHeader         = 8192
	Framing           = "system-backup-evidence-envelope.v1"
)

var (
	ErrInvalid     = errors.New("validation_failed")
	ErrIntegrity   = errors.New("checksum_mismatch")
	ErrRedaction   = errors.New("redaction_failed")
	ErrUnavailable = errors.New("artifact_unavailable")
	ErrKey         = errors.New("encryption_key_unavailable")
	ErrDenied      = errors.New("permission_denied")
	ErrAuth        = errors.New("authentication_required")
	ErrState       = errors.New("state_conflict")
	ErrNotFound    = errors.New("not_found")
	ErrRange       = errors.New("range_not_satisfiable")
	ErrCapacity    = errors.New("capacity_exceeded")
	ErrAudit       = errors.New("internal_error")
	ErrConflict    = errors.New("version_conflict")
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var idPattern = regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var installationPattern = regexp.MustCompile(`^installation_[A-Za-z0-9_-]{1,115}$`)
var ownerPatterns = map[string]*regexp.Regexp{}

func init() {
	for kind, prefix := range map[string]string{"backup": "sbk", "backup_staging": "sbs", "external_action": "sxa", "drill": "sdr", "restore_resource": "srr", "preflight": "spf", "artifact_verify": "sav", "catalog_scan": "scs", "catalog_record": "scr", "catalog_import": "sci", "prune_run": "spr", "promotion": "spm"} {
		ownerPatterns[kind] = regexp.MustCompile(`^` + prefix + `_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	}
}

type Identity struct {
	Installation   string `json:"installation_id"`
	ID             string `json:"evidence_public_id"`
	OwnerType      string `json:"owner_target_type"`
	OwnerID        string `json:"owner_target_public_id"`
	Type           string `json:"evidence_type"`
	Media          string `json:"media_type"`
	Classification string `json:"redaction_classification"`
	ContentHash    string `json:"content_checksum"`
	ContentSize    int64  `json:"content_size_bytes"`
}

func (i Identity) valid() bool {
	return i.ContentSize > 8192 && i.validExternal()
}

// Small external bodies belong only to the system capability path. This is a
// framing constraint, not permission to prepare, persist or publish evidence.
func (i Identity) validExternal() bool {
	p := ownerPatterns[i.OwnerType]
	owner := p != nil && p.MatchString(i.OwnerID) || i.OwnerType == "system" && i.OwnerID == i.Installation
	return installationPattern.MatchString(i.Installation) && idPattern.MatchString(i.ID) && owner &&
		validEvidenceOwner(i.Type, i.OwnerType) &&
		oneOf(i.Media, "application/json", "application/jose", "application/cbor", "text/plain") &&
		oneOf(i.Classification, "public", "internal", "confidential", "sensitive") && digestPattern.MatchString(i.ContentHash) && i.ContentSize > 0 && i.ContentSize <= MaxContent &&
		(i.ContentSize > 8192 || i.OwnerType == "system" && i.Type == "capability_snapshot" && i.Media == "application/json")
}

// v12 section 6.2 fixes this matrix before persistence. Checking only the two
// enum sets would allow a proof or log to be registered under the wrong owner.
func validEvidenceOwner(kind, owner string) bool {
	task := oneOf(owner, "backup", "drill", "preflight", "artifact_verify")
	switch kind {
	case "provider_presence_proof", "provider_absence_proof":
		return owner == "external_action"
	case "ownership_proof":
		return oneOf(owner, "backup_staging", "restore_resource")
	case "provider_deletion_receipt":
		return oneOf(owner, "backup_staging", "restore_resource", "prune_run")
	case "catalog_scan_receipt":
		return owner == "catalog_scan"
	case "failure_domain_attestation":
		return oneOf(owner, "backup", "promotion", "system")
	case "job_log_chunk":
		return task
	case "promotion_release_bundle":
		return owner == "promotion"
	case "capability_snapshot":
		return owner == "system"
	case "cleanup_result":
		return oneOf(owner, "backup", "backup_staging", "drill", "restore_resource", "prune_run")
	case "verifier_report":
		return task || oneOf(owner, "catalog_import", "catalog_record", "prune_run", "promotion", "system")
	case "diagnostic":
		return owner == "system" || ownerPatterns[owner] != nil
	default:
		return false
	}
}

type KeyRef struct {
	Identity string `json:"kek_identity_hash"`
	Version  string `json:"kek_version"`
}

func (k KeyRef) valid() bool {
	return digestPattern.MatchString(k.Identity) && versionPattern.MatchString(k.Version)
}

// Keys must resolve the dedicated evidence KEK by exact immutable identity and
// version, never a default/latest key. Implementations must erase plaintext DEK
// copies and map all provider errors to ErrKey without credential text.
// Wrap borrows its DEK input read-only for the synchronous call; it must not
// retain or return an alias to that input. Preparation erases the borrowed copy.
type Keys interface {
	Wrap(context.Context, KeyRef, []byte) ([]byte, error)
	Unwrap(context.Context, KeyRef, []byte) ([]byte, error)
}

// Source reopens the SAME task-owned encrypted staging plaintext view. No
// plaintext path is accepted. The validator must consume and validate the
// complete schema/redaction policy; the second pass is checked for drift.
type Source func() (io.ReadCloser, error)
type Redactor interface {
	Validate(context.Context, Identity, io.Reader) error
}

type Chunk struct {
	EvidenceID  string `json:"evidence_public_id"`
	Index       int64  `json:"chunk_index"`
	PlainOffset int64  `json:"plaintext_offset"`
	PlainLength int64  `json:"plaintext_length"`
	PlainHash   string `json:"plaintext_sha256"`
	FrameOffset int64  `json:"object_frame_offset"`
	FrameLength int64  `json:"object_frame_length"`
	CipherHash  string `json:"ciphertext_sha256"`
	Nonce       string `json:"gcm_nonce_base64url"`
	Tag         string `json:"gcm_tag_base64url"`
}

type Manifest struct {
	Identity     Identity `json:"identity"`
	Key          KeyRef   `json:"key"`
	EnvelopeHash string   `json:"envelope_hash"`
	ObjectHash   string   `json:"object_checksum"`
	ObjectSize   int64    `json:"object_size_bytes"`
	HeaderSize   int64    `json:"header_size_bytes"`
	ChunkRoot    string   `json:"chunk_list_root"`
	Chunks       []Chunk  `json:"chunks"`
}

type Ref struct{ Identity, Version, RelativeKey, ImmutableVersion string }

func (r Ref) valid(published bool) bool {
	return digestPattern.MatchString(r.Identity) && versionPattern.MatchString(r.Version) && safeKey(r.RelativeKey) && (!published || len(r.ImmutableVersion) > 0 && len(r.ImmutableVersion) <= 256 && r.ImmutableVersion != "null")
}

type Record struct {
	Manifest                                            Manifest
	Ref                                                 Ref
	State, Failure                                      string
	RowVersion                                          int64
	CreatedAt, ExpiresAt, ProtectedUntil, OwnerDeadline time.Time
	Claim                                               string
	ClaimUntil                                          time.Time
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func boundary(err error) error {
	for _, allowed := range []error{ErrInvalid, ErrIntegrity, ErrRedaction, ErrUnavailable, ErrKey, ErrDenied, ErrAuth, ErrState, ErrNotFound, ErrRange, ErrCapacity, ErrAudit, ErrConflict, ErrDownloadAdmissionNotReady} {
		if errors.Is(err, allowed) {
			return allowed
		}
	}
	return ErrUnavailable
}
