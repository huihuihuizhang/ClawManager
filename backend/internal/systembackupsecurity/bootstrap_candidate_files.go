package systembackupsecurity

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// NewBootstrapCandidateFileAuthority preserves the existing deployment file
// semantics, including removal/replacement revocation after Prepare. Pins and
// paths come from original trusted deployment composition, never HTTP input.
// Construction authenticates neither that composition nor a resource mapping:
// the independent original authority is still mandatory.
//
// Unlike arbitrary BootstrapAdmissionSources callbacks, these late readers are
// concrete bounded local-file implementations. Resource Recheck belongs at the
// END OF WORK, after public writes close, under the private read/time view,
// before that view closes and the fixed SQL-only FinalGuard starts.
func NewBootstrapCandidateFileAuthority(c BootstrapDeploymentConfig, original BootstrapCandidateAuthority) (BootstrapCandidateAuthority, error) {
	if c.SchemaVersion != "system-backup-bootstrap-deployment.v1" || candidateAuthorityNil(original) ||
		!(DatabaseIdentity{ServerUUID: c.ExpectedServerUUID, Database: c.ExpectedDatabase}).valid() ||
		!regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(c.InstallationID) ||
		!providerHashPattern.MatchString(c.GrantSHA256) || !providerHashPattern.MatchString(c.ConfigSHA256) {
		return nil, ErrRegistrationUnavailable
	}
	for _, path := range []string{c.GrantFile, c.RegistryDirectory} {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return nil, ErrRegistrationUnavailable
		}
	}
	profile := bootstrapCandidateFileProfile{grantFile: c.GrantFile, grantHash: c.GrantSHA256, registryDirectory: c.RegistryDirectory,
		installation: c.InstallationID, server: c.ExpectedServerUUID, database: c.ExpectedDatabase, configHash: c.ConfigSHA256}
	files := RegistrationFiles{RegistryDirectory: profile.registryDirectory}
	snapshot, err := NewPinnedBootstrapCandidateAuthority(BootstrapAdmissionSources{
		ReadGrant: func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
			return ReadBootstrapGrantFile(profile.grantFile, profile.grantHash)
		}, RegistryBytes: files.RegistryBytes,
	}, original)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	return &bootstrapCandidateFileAuthority{profile: profile, snapshot: snapshot.(*pinnedBootstrapCandidateAuthority)}, nil
}

type bootstrapCandidateFileProfile struct {
	grantFile, grantHash, registryDirectory    string
	installation, server, database, configHash string
}
type bootstrapCandidateFileAuthority struct {
	profile  bootstrapCandidateFileProfile
	snapshot *pinnedBootstrapCandidateAuthority
}
type bootstrapCandidateFileSession struct {
	profile    bootstrapCandidateFileProfile
	snapshot   *pinnedBootstrapCandidateSession
	registries []BootstrapRegistryRef
}

func (bootstrapCandidateFileAuthority) String() string   { return "BootstrapCandidateFileAuthority" }
func (bootstrapCandidateFileAuthority) GoString() string { return "BootstrapCandidateFileAuthority" }
func (bootstrapCandidateFileAuthority) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*bootstrapCandidateFileAuthority) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}
func (bootstrapCandidateFileSession) String() string   { return "BootstrapCandidateFileSession" }
func (bootstrapCandidateFileSession) GoString() string { return "BootstrapCandidateFileSession" }
func (bootstrapCandidateFileSession) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*bootstrapCandidateFileSession) UnmarshalJSON([]byte) error { return ErrRegistrationUnavailable }

func (a *bootstrapCandidateFileAuthority) PrepareBootstrapCandidates(ctx context.Context, g OfflineBootstrapGrant, c BootstrapConfig, r pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	var zero PreparedBootstrapCandidateAuthority
	if a == nil || a.snapshot == nil || g.InstallationID != a.profile.installation || g.ServerUUID != a.profile.server || g.Database != a.profile.database || g.ConfigSHA256 != a.profile.configHash || c.SHA256() != a.profile.configHash {
		return zero, ErrRegistrationUnavailable
	}
	p, err := a.snapshot.PrepareBootstrapCandidates(ctx, g, c, r)
	if err != nil {
		return zero, pinnedCandidateError(err)
	}
	snapshot, ok := p.Session.(*pinnedBootstrapCandidateSession)
	if !ok || snapshot == nil {
		return zero, ErrRegistrationUnavailable
	}
	// Re-decode canonical data so no caller-owned config maps/slices survive.
	owned, err := DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil || owned.SHA256() != a.profile.configHash {
		return zero, ErrRegistrationUnavailable
	}
	p.Session = &bootstrapCandidateFileSession{profile: a.profile, snapshot: snapshot, registries: owned.Registries()}
	return p, nil
}

func (s *bootstrapCandidateFileSession) checkCurrent(ctx context.Context, now time.Time, full bool) error {
	if s == nil || s.snapshot == nil || !pinnedCandidateContext(ctx) {
		return ErrRegistrationUnavailable
	}
	current, start, end, err := ReadBootstrapGrantFile(s.profile.grantFile, s.profile.grantHash)
	if err != nil || current != s.snapshot.grant || !start.Equal(s.snapshot.notBefore) || !end.Equal(s.snapshot.expires) || now.Before(start) || !now.Before(end) {
		return ErrRegistrationPermission
	}
	// Direct concrete reader, never arbitrary source functions in locked work.
	files := RegistrationFiles{RegistryDirectory: s.profile.registryDirectory}
	rbac := s.snapshot.rbac
	role := PinnedRegistrationAuthority{InstallationID: current.InstallationID, RegistryBytes: files.RegistryBytes}
	if err = role.AuthorizeRole(RegistrationActor{UserID: current.UserID, Subject: "user:" + strconv.FormatInt(current.UserID, 10)}, RegistrationConfig{RBACRegistryVersion: rbac.Version, RBACRegistrySHA256: rbac.SHA256}); err != nil {
		return pinnedCandidateError(err)
	}
	if full {
		for _, ref := range s.registries {
			if !pinnedCandidateContext(ctx) {
				return ErrRegistrationUnavailable
			}
			// The concrete reader enforces closed names, size and original full SHA.
			if _, err = files.RegistryBytes(ref.Kind, ref.Version, ref.SHA256); err != nil {
				return ErrRegistrationUnavailable
			}
		}
	}
	if !pinnedCandidateContext(ctx) {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (s *bootstrapCandidateFileSession) currentAtSample(ctx context.Context, tx pd.BootstrapReadSQL, now time.Time, full bool) (time.Time, error) {
	if s == nil || s.snapshot == nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	start, err := s.snapshot.sample(ctx, tx, now)
	if err != nil {
		return time.Time{}, err
	}
	if err = s.checkCurrent(ctx, start, full); err != nil {
		return time.Time{}, err
	}
	return s.snapshot.sample(ctx, tx, start)
}

func (s *bootstrapCandidateFileSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	if s == nil || s.snapshot == nil {
		return zero, ErrRegistrationUnavailable
	}
	if _, err := s.snapshot.requestCopy(ctx, r); err != nil {
		return zero, err
	}
	start, err := s.currentAtSample(ctx, tx, now, false)
	if err != nil {
		return zero, err
	}
	a, err := s.snapshot.Authorize(ctx, tx, r, d, start)
	if err != nil {
		return zero, err
	}
	// Do not let an inner authorization callback hide a late source revocation.
	end, err := s.currentAtSample(ctx, tx, start, false)
	if err != nil {
		return zero, err
	}
	identity, err := a.IdentityExpiresAt.Time()
	if err != nil || !end.Before(identity) {
		return zero, ErrRegistrationPermission
	}
	return a, nil
}
func (s *bootstrapCandidateFileSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.snapshot == nil {
		return ErrRegistrationUnavailable
	}
	return s.snapshot.LockHosts(ctx, tx, r, f)
}
func (s *bootstrapCandidateFileSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.snapshot == nil {
		return ErrRegistrationUnavailable
	}
	if _, err := s.snapshot.requestCopy(ctx, r); err != nil {
		return err
	}
	// New-use only, after L3: unrelated missing resource bytes never preempt an
	// otherwise authorized exact historical read. No reservation/audit yet.
	if candidateAuthorityNil(tx) {
		return ErrRegistrationUnavailable
	}
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if _, err = s.currentAtSample(ctx, tx, now, true); err != nil {
		return err
	}
	return s.snapshot.LockReferences(ctx, tx, r, f)
}
func (s *bootstrapCandidateFileSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.snapshot == nil {
		return ErrRegistrationUnavailable
	}
	return s.snapshot.Reserve(ctx, tx, r, f)
}
func (s *bootstrapCandidateFileSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if s == nil || s.snapshot == nil {
		return nil, ErrRegistrationUnavailable
	}
	return s.snapshot.LockEvidence(ctx, tx, r, f)
}

// Recheck is an end-of-Work resource callback, NOT generic Policy.Recheck.
// All inner mutable/material callbacks finish first. Our current-file check
// runs last under D's private read/time view, after public writes have closed.
// D then closes that view and independently checks fixed SQL and original
// deadlines. No source/file callback may run after that guard.
func (s *bootstrapCandidateFileSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if s == nil || s.snapshot == nil {
		return ErrRegistrationUnavailable
	}
	if err := s.snapshot.Recheck(ctx, tx, r, f, now); err != nil {
		return err
	}
	_, err := s.currentAtSample(ctx, tx, now, !f.Replayed)
	return err
}
