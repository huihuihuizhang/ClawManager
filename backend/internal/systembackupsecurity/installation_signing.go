package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const InstallationSigningDomain = "system-backup-original-signing.v1\x00"

// InstallationSigningRecord is signed by the original installation owner in
// its independent signing environment. It contains public material only. A
// provider policy, successful JWT login or committed config cannot issue it.
type InstallationSigningRecord struct {
	InstallationID   string
	Revision         uint64
	NotBefore, Until time.Time
	Keys             []ArtifactSigningPublicKey
	Permissions      []InstallationSigningPermission
}

// The signed mapping pins the exact provider permission as well as the public
// key. Local JWT file paths are deployment inputs, never owner-record locators.
type InstallationSigningPermission struct {
	Binding                 TransitSigningBinding
	AuthMount, Role, Policy string
	CASHA256                string
}

// InstallationSigningPin must be deployed independently of the imported record.
// Pinning its exact revision AND bytes prevents replay of another owner-signed
// mapping, including an older record predating a revocation.
type InstallationSigningPin struct {
	InstallationID string
	Revision       uint64
	RecordSHA256   string
	Issuer         ed25519.PublicKey
}

type OriginalSigningRecordReader interface {
	ReadSigningRecord(context.Context) (record, signature []byte, err error)
}

// FileSigningRecordReader consumes externally mounted owner-signed material.
// It never creates, signs, repairs or backfills missing authority records.
type FileSigningRecordReader struct{ RecordFile, SignatureFile string }

func (r FileSigningRecordReader) ReadSigningRecord(ctx context.Context) ([]byte, []byte, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(r.RecordFile) || !filepath.IsAbs(r.SignatureFile) || r.RecordFile == r.SignatureFile {
		return nil, nil, ErrRegistrationUnavailable
	}
	read := func(path string, max int64) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, ErrRegistrationUnavailable
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > max {
			return nil, ErrRegistrationUnavailable
		}
		b, err := io.ReadAll(io.LimitReader(f, max+1))
		if err != nil || int64(len(b)) > max {
			return nil, ErrRegistrationUnavailable
		}
		return b, nil
	}
	raw, err := read(r.RecordFile, 1024*1024)
	if err != nil {
		return nil, nil, err
	}
	sig, err := read(r.SignatureFile, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || ctx.Err() != nil {
		return nil, nil, ErrRegistrationUnavailable
	}
	return raw, sig, nil
}

// ArtifactSigningTask is the original public v2 operation, never a replacement
// task or a caller-provided context value. One constructed signer set serves
// exactly this backup/attempt/operation and one authenticated workload.
type ArtifactSigningTask struct {
	BackupPublicID string
	AttemptNo      int64
	OperationID    string
	Workload       SigningWorkloadIdentity
}

type ArtifactSigningAuthorizationRequest struct {
	Task    ArtifactSigningTask
	Signing TransitSigningRequest
}

type AuthorizedArtifactSigningUse struct {
	Task ArtifactSigningTask
	Use  OriginalSigningUse
}

// The original capture, acceptance and catalog owner must read its current
// frozen operation and authenticate the exact input digest. Recheck in Use
// retains that original task/attempt/operation and its current revocation.
type ArtifactSigningAuthority interface {
	AuthorizeArtifactSigning(context.Context, ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error)
}

type ArtifactSigningAuthorities struct {
	Capture, Acceptance, Catalog ArtifactSigningAuthority
}

type InstallationArtifactSigners struct {
	history      *ArtifactSigningKeyHistory
	signers      map[string]*CredentialTransitSigner
	tokens       *JWTSigningTokenSource
	check        func(context.Context) error
	historyCheck func(context.Context) error
}

func authenticateInstallationSigning(raw, sig []byte, pin InstallationSigningPin, now time.Time) (InstallationSigningRecord, *ArtifactSigningKeyHistory, error) {
	r, h, err := decodeInstallationSigning(raw, sig, pin)
	if err != nil || now.IsZero() || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return InstallationSigningRecord{}, nil, ErrRegistrationUnavailable
	}
	return r, h, nil
}

func decodeInstallationSigning(raw, sig []byte, pin InstallationSigningPin) (InstallationSigningRecord, *ArtifactSigningKeyHistory, error) {
	fail := func() (InstallationSigningRecord, *ArtifactSigningKeyHistory, error) {
		return InstallationSigningRecord{}, nil, ErrRegistrationUnavailable
	}
	h := sha256.Sum256(raw)
	if !providerBoundedString(pin.InstallationID) || pin.Revision == 0 || !signingDigest.MatchString(pin.RecordSHA256) ||
		len(raw) == 0 || len(raw) > 1024*1024 || hex.EncodeToString(h[:]) != pin.RecordSHA256 || len(pin.Issuer) != ed25519.PublicKeySize ||
		!ed25519.Verify(pin.Issuer, append([]byte(InstallationSigningDomain), raw...), sig) {
		return fail()
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return fail()
	}
	var record InstallationSigningRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.InstallationID != pin.InstallationID || record.Revision != pin.Revision ||
		record.NotBefore.IsZero() || !record.NotBefore.Before(record.Until) || len(record.Permissions) != 3 {
		return fail()
	}
	history, err := NewArtifactSigningKeyHistory(record.InstallationID, record.Keys)
	if err != nil {
		return fail()
	}
	return record, history, nil
}

// LoadInstallationSigningHistory reads the independently pinned current trust
// material without requiring an active signing permission, a workload JWT or a
// live provider. Expired SIGNING permission must not destroy retained public
// verification keys. The source and signature/pin still must authenticate;
// replacing the source with a revocation invalidates an older pin immediately.
func LoadInstallationSigningHistory(ctx context.Context, reader OriginalSigningRecordReader, pin InstallationSigningPin) (*ArtifactSigningKeyHistory, error) {
	if ctx == nil || ctx.Err() != nil || candidateAuthorityNil(reader) {
		return nil, ErrRegistrationUnavailable
	}
	raw, sig, err := reader.ReadSigningRecord(ctx)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	_, h, err := decodeInstallationSigning(raw, sig, pin)
	return h, err
}

// NewInstallationArtifactSigners is the production composition entry: original
// signed record -> exact purpose owner -> original resolver -> projected JWT ->
// credential Transit signer. No private signing key or provider token is kept.
func NewInstallationArtifactSigners(ctx context.Context, reader OriginalSigningRecordReader, pin InstallationSigningPin, mounts []SigningJWTMount, task ArtifactSigningTask, owners ArtifactSigningAuthorities) (*InstallationArtifactSigners, error) {
	if ctx == nil || ctx.Err() != nil || candidateAuthorityNil(reader) || !acceptanceBackupID.MatchString(task.BackupPublicID) || task.AttemptNo < 1 ||
		!providerBoundedString(task.OperationID) || !providerBoundedString(task.Workload.Namespace) || !providerBoundedString(task.Workload.PodUID) || !providerBoundedString(task.Workload.ServiceAccountUID) ||
		candidateAuthorityNil(owners.Capture) || candidateAuthorityNil(owners.Acceptance) || candidateAuthorityNil(owners.Catalog) || len(mounts) != 3 {
		return nil, ErrRegistrationUnavailable
	}
	pin.Issuer = append(ed25519.PublicKey(nil), pin.Issuer...)
	raw, sig, err := reader.ReadSigningRecord(ctx)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	record, history, err := authenticateInstallationSigning(raw, sig, pin, time.Now())
	if err != nil {
		return nil, err
	}
	check := func(c context.Context) error {
		if c == nil || c.Err() != nil {
			return ErrRegistrationUnavailable
		}
		current, signature, e := reader.ReadSigningRecord(c)
		if e != nil {
			return ErrRegistrationUnavailable
		}
		if _, _, e = authenticateInstallationSigning(current, signature, pin, time.Now()); e != nil {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	permissions := make(map[string]InstallationSigningPermission, 3)
	bindings := make([]TransitSigningBinding, 0, 3)
	for _, p := range record.Permissions {
		if permissions[p.Binding.Purpose].Binding.Purpose != "" {
			return nil, ErrRegistrationUnavailable
		}
		permissions[p.Binding.Purpose] = p
		bindings = append(bindings, p.Binding)
	}
	for _, m := range mounts {
		p, ok := permissions[m.Binding.Purpose]
		if !ok || p.Binding != m.Binding || p.AuthMount != m.AuthMount || p.Role != m.Role || p.Policy != m.Policy || p.CASHA256 != m.CASHA256 {
			return nil, ErrRegistrationUnavailable
		}
	}
	tokens, err := NewJWTSigningTokenSource(mounts)
	if err != nil {
		return nil, err
	}
	historyCheck := func(c context.Context) error {
		_, e := LoadInstallationSigningHistory(c, reader, pin)
		return e
	}
	s := &InstallationArtifactSigners{history: history, signers: make(map[string]*CredentialTransitSigner, 3), tokens: tokens, check: check, historyCheck: historyCheck}
	authority := installationSigningAuthority{task: task, owners: owners, check: check, until: record.Until}
	resolver, err := NewOriginalSigningResolver(history, bindings, authority, tokens)
	if err != nil {
		s.Close()
		return nil, err
	}
	for _, m := range mounts {
		key, ok := history.keys[artifactSigningIdentity(m.Binding.Purpose, m.Binding.KeyID, m.Binding.KeyVersion)]
		if !ok {
			s.Close()
			return nil, ErrRegistrationUnavailable
		}
		signer, e := NewCredentialTransitSigner(m.Binding, key, m.CAPEM, resolver)
		if e != nil {
			s.Close()
			return nil, e
		}
		s.signers[m.Binding.Purpose] = signer
	}
	if check(ctx) != nil {
		s.Close()
		return nil, ErrRegistrationUnavailable
	}
	return s, nil
}

type installationSigningAuthority struct {
	task   ArtifactSigningTask
	owners ArtifactSigningAuthorities
	check  func(context.Context) error
	until  time.Time
}

func (a installationSigningAuthority) AuthorizeSigning(ctx context.Context, r TransitSigningRequest) (OriginalSigningUse, error) {
	if a.check(ctx) != nil {
		return OriginalSigningUse{}, ErrRegistrationUnavailable
	}
	var owner ArtifactSigningAuthority
	switch r.Binding.Purpose {
	case "capture_certificate":
		owner = a.owners.Capture
	case "acceptance_record":
		owner = a.owners.Acceptance
	case "catalog_record":
		owner = a.owners.Catalog
	default:
		return OriginalSigningUse{}, ErrRegistrationUnavailable
	}
	u, err := owner.AuthorizeArtifactSigning(ctx, ArtifactSigningAuthorizationRequest{Task: a.task, Signing: r})
	if err != nil || u.Task != a.task || u.Use.Request != r || u.Use.Workload != a.task.Workload || u.Use.Recheck == nil {
		return OriginalSigningUse{}, ErrRegistrationUnavailable
	}
	use := u.Use
	originalCheck := use.Recheck
	if a.until.Before(use.ExpiresAt) {
		use.ExpiresAt = a.until
	}
	use.Recheck = func(c context.Context, got TransitSigningRequest) error {
		if got != r || a.check(c) != nil || originalCheck(c, got) != nil {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	return use, nil
}

func (s *InstallationArtifactSigners) Signer(purpose string) (ProofSigner, error) {
	if s == nil || s.signers[purpose] == nil {
		return nil, ErrRegistrationUnavailable
	}
	return s.signers[purpose], nil
}

// History authenticates current owner material before exporting defensive
// historical public keys. Expired old keys are retained for artifact-time
// verification; revoked keys remain explicitly marked and must be rejected.
func (s *InstallationArtifactSigners) History(ctx context.Context) (*ArtifactSigningKeyHistory, error) {
	if s == nil || s.historyCheck == nil || s.historyCheck(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	var keys []ArtifactSigningPublicKey
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		keys = append(keys, s.history.PurposeKeys(purpose)...)
	}
	return NewArtifactSigningKeyHistory(s.history.installationID, keys)
}

func (s *InstallationArtifactSigners) Close() {
	if s != nil {
		for _, signer := range s.signers {
			signer.Close()
		}
		if s.tokens != nil {
			s.tokens.Close()
		}
	}
}
