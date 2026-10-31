package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const ArtifactSigningOwnerDomain = "system-backup-original-signing-use.v1\x00"

// ArtifactSigningOwnerRecord is the original capture/acceptance/catalog owner's
// frozen authorization. The owner signs only after authenticating its original
// operation, workload and exact signing input. This adapter cannot issue one.
// A signed installation key mapping alone never authorizes these business uses.
type ArtifactSigningOwnerRecord struct {
	Authorization    ArtifactSigningAuthorizationRequest
	Revision         uint64
	NotBefore, Until time.Time
	Revoked          bool
}

// Pins are delivered through the original owner/deployment trust channel,
// independently of the imported record. They must NOT be computed from an
// untrusted file on startup. Each purpose pins its own original owner issuer.
type ArtifactSigningOwnerPin struct {
	InstallationID, Purpose, RecordSHA256 string
	Revision                              uint64
	Issuer                                ed25519.PublicKey
}

type ArtifactSigningOwnerSource struct {
	Reader OriginalSigningRecordReader
	Pin    ArtifactSigningOwnerPin
}

// PinnedArtifactSigningAuthority is a concrete original-owner reader/caller.
// It authenticates exact bytes on initial use and every original-use recheck;
// there is no default authorization callback, grant refresh or self-signing.
type PinnedArtifactSigningAuthority struct {
	reader OriginalSigningRecordReader
	pin    ArtifactSigningOwnerPin
}

func NewPinnedArtifactSigningAuthority(source ArtifactSigningOwnerSource) (*PinnedArtifactSigningAuthority, error) {
	p := source.Pin
	if candidateAuthorityNil(source.Reader) || !providerBoundedString(p.InstallationID) || !artifactSigningPurpose(p.Purpose) ||
		!signingDigest.MatchString(p.RecordSHA256) || p.Revision == 0 || len(p.Issuer) != ed25519.PublicKeySize {
		return nil, ErrRegistrationUnavailable
	}
	p.Issuer = append(ed25519.PublicKey(nil), p.Issuer...)
	return &PinnedArtifactSigningAuthority{reader: source.Reader, pin: p}, nil
}

func (a *PinnedArtifactSigningAuthority) read(ctx context.Context, request ArtifactSigningAuthorizationRequest) (ArtifactSigningOwnerRecord, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || request.Signing.Binding.InstallationID != a.pin.InstallationID || request.Signing.Binding.Purpose != a.pin.Purpose ||
		!signingDigest.MatchString(request.Signing.InputSHA256) || !acceptanceBackupID.MatchString(request.Task.BackupPublicID) || request.Task.AttemptNo < 1 ||
		!providerBoundedString(request.Task.OperationID) || !providerBoundedString(request.Task.Workload.Namespace) || !providerBoundedString(request.Task.Workload.PodUID) || !providerBoundedString(request.Task.Workload.ServiceAccountUID) {
		return ArtifactSigningOwnerRecord{}, ErrRegistrationUnavailable
	}
	raw, sig, err := a.reader.ReadSigningRecord(ctx)
	h := sha256.Sum256(raw)
	if err != nil || len(raw) == 0 || len(raw) > 65536 || hex.EncodeToString(h[:]) != a.pin.RecordSHA256 ||
		!ed25519.Verify(a.pin.Issuer, append([]byte(ArtifactSigningOwnerDomain), raw...), sig) {
		return ArtifactSigningOwnerRecord{}, ErrRegistrationUnavailable
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return ArtifactSigningOwnerRecord{}, ErrRegistrationUnavailable
	}
	var record ArtifactSigningOwnerRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	now := time.Now()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.Authorization != request || record.Revision != a.pin.Revision || record.Revoked ||
		record.NotBefore.IsZero() || now.Before(record.NotBefore) || !now.Before(record.Until) || !record.NotBefore.Before(record.Until) || record.Until.Sub(record.NotBefore) > 24*time.Hour {
		return ArtifactSigningOwnerRecord{}, ErrRegistrationUnavailable
	}
	return record, nil
}

func (a *PinnedArtifactSigningAuthority) AuthorizeArtifactSigning(ctx context.Context, r ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error) {
	record, err := a.read(ctx, r)
	if err != nil {
		return AuthorizedArtifactSigningUse{}, ErrRegistrationUnavailable
	}
	use := OriginalSigningUse{Request: r.Signing, Workload: r.Task.Workload, NotBefore: record.NotBefore, ExpiresAt: record.Until}
	use.Recheck = func(c context.Context, got TransitSigningRequest) error {
		if got != r.Signing {
			return ErrRegistrationUnavailable
		}
		if _, e := a.read(c, r); e != nil {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	return AuthorizedArtifactSigningUse{Task: r.Task, Use: use}, nil
}

// NewPinnedInstallationArtifactSigners is the complete mounted-record entry
// point for production constructors. All three original business authorities
// are real signature-checked readers, never test implementations. The supplied
// owner records and pins must originate with their independent original owners;
// this process has none of their private keys and cannot backfill missing uses.
func NewPinnedInstallationArtifactSigners(ctx context.Context, installationReader OriginalSigningRecordReader, installationPin InstallationSigningPin, mounts []SigningJWTMount, task ArtifactSigningTask, sources []ArtifactSigningOwnerSource) (*InstallationArtifactSigners, error) {
	if len(sources) != 3 {
		return nil, ErrRegistrationUnavailable
	}
	byPurpose := make(map[string]*PinnedArtifactSigningAuthority, 3)
	for _, source := range sources {
		if source.Pin.InstallationID != installationPin.InstallationID || byPurpose[source.Pin.Purpose] != nil {
			return nil, ErrRegistrationUnavailable
		}
		authority, err := NewPinnedArtifactSigningAuthority(source)
		if err != nil {
			return nil, err
		}
		byPurpose[source.Pin.Purpose] = authority
	}
	if byPurpose["capture_certificate"] == nil || byPurpose["acceptance_record"] == nil || byPurpose["catalog_record"] == nil {
		return nil, ErrRegistrationUnavailable
	}
	return NewInstallationArtifactSigners(ctx, installationReader, installationPin, mounts, task, ArtifactSigningAuthorities{Capture: byPurpose["capture_certificate"], Acceptance: byPurpose["acceptance_record"], Catalog: byPurpose["catalog_record"]})
}
