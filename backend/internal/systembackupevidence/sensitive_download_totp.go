package systembackupevidence

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// PinnedSensitiveDownloadProofTargets reuses admission's pinned current
// session/RBAC/material/owner-preview sources. It borrows the MFA transaction;
// it never reserves capacity, locks a download key/owner, writes a nonce,
// commits, or reads a provider. Actual runtime owner sources remain mandatory.
type PinnedSensitiveDownloadProofTargets struct {
	registry SQLRegistry
	source   *PinnedDownloadAdmissionEnvironment
}

func NewPinnedSensitiveDownloadProofTargets(registry SQLRegistry, environment *PinnedDownloadAdmissionEnvironment) (*PinnedSensitiveDownloadProofTargets, error) {
	if registry.DB == nil || !installationPattern.MatchString(registry.Installation) || registry.ServerUUID == "" || registry.Database == "" || environment == nil || environment.config.Installation != registry.Installation {
		return nil, ErrDownloadAdmissionNotReady
	}
	return &PinnedSensitiveDownloadProofTargets{registry: registry, source: environment}, nil
}

type pinnedSensitiveDownloadProofTarget struct {
	prepared *pinnedPreparedDownloadAdmission
	selector sec.SensitiveDownloadProofSelector
	request  sec.SensitiveDownloadRequest
	proof    sec.SensitiveDownloadProofVerification
	until    time.Time
	verified bool
}

func (*PinnedSensitiveDownloadProofTargets) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalid
}
func (*PinnedSensitiveDownloadProofTargets) String() string {
	return "PinnedSensitiveDownloadProofTargets"
}
func (*PinnedSensitiveDownloadProofTargets) GoString() string {
	return "PinnedSensitiveDownloadProofTargets"
}
func (*pinnedSensitiveDownloadProofTarget) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalid
}
func (*pinnedSensitiveDownloadProofTarget) String() string {
	return "PinnedSensitiveDownloadProofTarget"
}
func (*pinnedSensitiveDownloadProofTarget) GoString() string {
	return "PinnedSensitiveDownloadProofTarget"
}

func proofSelectorHeaders(selector sec.SensitiveDownloadProofSelector, key string) http.Header {
	headers := http.Header{"Idempotency-Key": {key}}
	if raw, present := selector.Range(); present {
		headers.Set("Range", raw)
	}
	return headers
}

func (s *PinnedSensitiveDownloadProofTargets) Prepare(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, selector sec.SensitiveDownloadProofSelector, key string) (sec.SensitiveDownloadProofTarget, error) {
	if s == nil || s.source == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, sec.DatabaseIdentity{ServerUUID: s.registry.ServerUUID, Database: s.registry.Database}, s.registry.Installation)
	if err != nil {
		return nil, err
	}
	config, err := scope.LoadConfig(ctx, tx)
	if err != nil {
		return nil, err
	}
	prepared, err := s.source.Prepare(ctx, tx, actor, config, selector.EvidenceID(), scope.RequiredVersions())
	if err != nil {
		if !nilSystemAdapter(prepared) {
			prepared.Close()
		}
		return nil, proofTargetError(err)
	}
	p, ok := prepared.(*pinnedPreparedDownloadAdmission)
	if !ok || p == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	request, err := BindSensitiveDownloadRequest(actor, p.hint.Manifest, proofSelectorHeaders(selector, key))
	if err != nil || p.hint.State != "ready" || p.hint.Failure != "none" || !p.hint.Ref.valid(true) {
		p.Close()
		if err != nil {
			return nil, sec.ErrSensitiveDownloadRequest
		}
		return nil, sec.ErrRegistrationPermission
	}
	until := p.until
	if p.hint.Manifest.Identity.Type == "job_log_chunk" {
		if !downloadAdmissionContentTime(p.hint.ExpiresAt) {
			p.Close()
			return nil, sec.ErrRegistrationUnavailable
		}
		until = earlier(until, p.hint.ExpiresAt)
	}
	return &pinnedSensitiveDownloadProofTarget{prepared: p, selector: selector, request: request, until: until}, nil
}

func proofTargetError(err error) error {
	if err == ErrDenied || err == ErrNotFound || err == sec.ErrRegistrationPermission {
		return sec.ErrRegistrationPermission
	}
	return sec.ErrRegistrationUnavailable
}

func (p *pinnedSensitiveDownloadProofTarget) Request() sec.SensitiveDownloadRequest {
	if p == nil {
		return sec.SensitiveDownloadRequest{}
	}
	return p.request
}
func (p *pinnedSensitiveDownloadProofTarget) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}
func (p *pinnedSensitiveDownloadProofTarget) valid(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor) bool {
	return p != nil && p.prepared.valid(ctx, tx) && sameDownloadAdmissionActor(actor, p.prepared.actor)
}
func (p *pinnedSensitiveDownloadProofTarget) ValidateProof(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, proof sec.Proof, issuedAt time.Time) error {
	if !p.valid(ctx, tx, actor) || p.verified {
		return sec.ErrRegistrationUnavailable
	}
	now, err := downloadIntentNow(ctx, tx, issuedAt)
	if err != nil || !now.Before(p.until) {
		return sec.ErrRegistrationUnavailable
	}
	config := p.prepared.proofConfig
	config.Now = now
	verified, err := p.request.VerifyProof(proof, p.prepared.Issuer(), config)
	if err != nil {
		// Locally issued proof disagrees with pinned authority: configuration
		// failure, never blame a client for the server's signer configuration.
		return sec.ErrRegistrationUnavailable
	}
	p.proof, p.verified = verified, true
	return nil
}
func (p *pinnedSensitiveDownloadProofTarget) Recheck(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor) error {
	if !p.valid(ctx, tx, actor) || !p.verified {
		return sec.ErrRegistrationUnavailable
	}
	old := p.prepared
	// Preview, not Owners.Recheck: MFA issuance has acquired no L4 owner locks.
	reread, err := old.source.Prepare(ctx, tx, actor, old.config, p.selector.EvidenceID(), append([]string(nil), old.versions...))
	if !nilSystemAdapter(reread) {
		defer reread.Close()
	}
	if err != nil {
		return proofTargetError(err)
	}
	fresh, ok := reread.(*pinnedPreparedDownloadAdmission)
	if !ok || fresh == nil || !fresh.until.Equal(old.until) || !sameDownloadAdmissionImmutable(fresh.hint, old.hint) || !sameDownloadAdmissionMaterial(old.proofConfig, fresh.proofConfig) {
		return sec.ErrRegistrationUnavailable
	}
	request, err := BindSensitiveDownloadRequest(actor, fresh.hint.Manifest, proofSelectorHeaders(p.selector, p.request.IdempotencyKey()))
	if err != nil || request != p.request || old.config.Recheck(ctx, tx) != nil {
		return sec.ErrRegistrationUnavailable
	}
	now, err := downloadIntentNow(ctx, tx, old.config.ObservedAt())
	if err != nil || !now.Before(p.until) || p.proof.RecheckProofAt(now) != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (p *pinnedSensitiveDownloadProofTarget) Close() {
	if p != nil && p.prepared != nil {
		p.prepared.Close()
	}
}
