package systembackupinstallationowner

import (
	"context"
	"sync"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// CaptureSigningCandidateAuthority composes ONE concrete capture source into
// an independently supplied original authority. It never implements missing
// original mapping/host/reference/capacity/evidence owners with default success.
type CaptureSigningCandidateAuthority struct {
	original sec.BootstrapCandidateAuthority
	capture  *CaptureSigningValidator
}

func NewCaptureSigningCandidateAuthority(original sec.BootstrapCandidateAuthority, capture *CaptureSigningValidator) (*CaptureSigningCandidateAuthority, error) {
	if nilInterface(original) || capture == nil || capture.observer == nil || capture.observer.client == nil || !capture.pin.valid() {
		return nil, ErrOwner
	}
	return &CaptureSigningCandidateAuthority{original: original, capture: capture}, nil
}
func (*CaptureSigningCandidateAuthority) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*CaptureSigningCandidateAuthority) String() string               { return "CaptureSigningCandidateAuthority" }
func (*CaptureSigningCandidateAuthority) GoString() string             { return "CaptureSigningCandidateAuthority" }

// Owners adds the same exact concrete resource to the legacy requirements
// table. Candidate composition must separately use this authority; no existing
// candidate factory is silently retained and no other missing slot is supplied.
func (a *CaptureSigningCandidateAuthority) Owners(base sec.BootstrapOwnerAdapters) (sec.BootstrapOwnerAdapters, error) {
	if a == nil || nilInterface(a.original) || a.capture == nil || base.Candidates != nil {
		return sec.BootstrapOwnerAdapters{}, ErrOwner
	}
	if _, exists := base.References["capture_signing"]; exists {
		return sec.BootstrapOwnerAdapters{}, ErrOwner
	}
	out := sec.BootstrapOwnerAdapters{Registries: make(map[string]sec.BootstrapResourceValidator), References: make(map[string]sec.BootstrapResourceValidator), CrossResources: base.CrossResources, KEK: base.KEK}
	for k, v := range base.Registries {
		out.Registries[k] = v
	}
	for k, v := range base.References {
		out.References[k] = v
	}
	out.References["capture_signing"] = a.capture
	return out, nil
}

func (a *CaptureSigningCandidateAuthority) PrepareBootstrapCandidates(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	var zero sec.PreparedBootstrapCandidateAuthority
	if a == nil || nilInterface(a.original) || a.capture == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return zero, ErrOwner
	}
	prepared, e := a.capture.PrepareCandidateAttempt(ctx, grant, config, request)
	if e != nil {
		return zero, e
	}
	// Freeze comparison values across original callbacks, which cannot mutate
	// what the concrete owner subsequently authorizes.
	owned, e := sec.DecodeBootstrapConfig(config.CanonicalJSON())
	if e != nil {
		return zero, ErrOwner
	}
	frozen, e := freezeCaptureRequest(request)
	if e != nil {
		return zero, e
	}
	hash, e := pd.BootstrapConsumptionHash(frozen)
	if e != nil {
		return zero, ErrOwner
	}
	p, e := a.original.PrepareBootstrapCandidates(ctx, grant, owned, frozen)
	if e != nil {
		return zero, e
	}
	if nilInterface(p.Session) || ctx.Err() != nil {
		return zero, ErrOwner
	}
	if p.CapacityObservedAt != nil {
		value := *p.CapacityObservedAt
		p.CapacityObservedAt = &value
	}
	s := &captureCandidateSession{ctx: ctx, hash: hash, original: p.Session, capture: prepared}
	s.origin = s
	p.Session = s
	return p, nil
}

type captureCandidateSession struct {
	mu                                                  sync.Mutex
	origin                                              *captureCandidateSession
	ctx                                                 context.Context
	hash                                                pd.Hash
	original                                            sec.BootstrapCandidateAuthoritySession
	capture                                             *PreparedCaptureSigning
	guard                                               *OwnerGuard
	tx                                                  pd.BootstrapSQL
	authorized, references, reserved, evidenced, failed bool
}

func (*captureCandidateSession) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*captureCandidateSession) String() string               { return "CaptureSigningCandidateSession" }
func (*captureCandidateSession) GoString() string             { return "CaptureSigningCandidateSession" }
func (s *captureCandidateSession) check(ctx context.Context, view pd.BootstrapReadSQL, request pd.BootstrapConsumptionRequest) error {
	if s == nil || s.origin != s || s.failed || !sameContext(ctx, s.ctx) || ctx.Err() != nil || nilInterface(s.original) || s.capture == nil || !pd.SameBootstrapTransaction(s.tx, view) {
		return ErrOwner
	}
	hash, e := pd.BootstrapConsumptionHash(request)
	if e != nil || hash != s.hash {
		return ErrOwner
	}
	return nil
}
func (s *captureCandidateSession) finish(e error) error {
	if e != nil {
		s.failed = true
	}
	return e
}
func captureDeadline(old pd.Timestamp, limit *pd.Timestamp, require bool) (pd.Timestamp, error) {
	current, e := old.Time()
	if e != nil {
		return "", ErrOwner
	}
	if limit == nil {
		if require {
			return "", ErrOwner
		}
		return pd.Timestamp("1000-01-01T00:00:00.000000Z"), nil
	}
	end, e := limit.Time()
	if e != nil {
		return "", ErrOwner
	}
	if end.Before(current) {
		return *limit, nil
	}
	return old, nil
}
func (s *captureCandidateSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, domain pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	if s == nil {
		return zero, ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized || !pd.SameBootstrapTransaction(tx, tx) {
		return zero, s.finish(ErrOwner)
	}
	s.tx = tx
	if e := s.check(ctx, tx, request); e != nil {
		return zero, s.finish(e)
	}
	s.authorized = true
	frozen, e := freezeCaptureRequest(request)
	if e != nil {
		return zero, s.finish(e)
	}
	a, e := s.original.Authorize(ctx, tx, frozen, domain, now)
	if e != nil {
		return zero, s.finish(e)
	}
	if a.BindingHash != s.hash {
		return zero, s.finish(ErrOwner)
	}
	s.guard, e = s.capture.AuthorizeCandidate(ctx, tx)
	if e != nil {
		return zero, s.finish(e)
	}
	a.IdentityExpiresAt, e = captureDeadline(a.IdentityExpiresAt, s.guard.IdentityDeadline(), true)
	if e != nil {
		return zero, s.finish(e)
	}
	// An absent/expired probe closes fresh use only. D still reaches its exact
	// historical branch after current original + capture identity authorization.
	a.DependencyExpiresAt, e = captureDeadline(a.DependencyExpiresAt, s.capture.DependencyDeadline(), false)
	if e != nil {
		return zero, s.finish(e)
	}
	return a, nil
}
func (s *captureCandidateSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx, r); e != nil {
		return s.finish(e)
	}
	if !s.authorized || f.Replayed {
		return s.finish(ErrOwner)
	}
	return s.finish(s.original.LockHosts(ctx, tx, r, f))
}
func (s *captureCandidateSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx, r); e != nil {
		return s.finish(e)
	}
	if !s.authorized || s.references || f.Replayed {
		return s.finish(ErrOwner)
	}
	s.references = true
	if e := s.original.LockReferences(ctx, tx, r, f); e != nil {
		return s.finish(e)
	}
	return s.finish(s.capture.RecheckCandidateResource(ctx, tx))
}
func (s *captureCandidateSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx, r); e != nil {
		return s.finish(e)
	}
	if !s.references || s.reserved || f.Replayed {
		return s.finish(ErrOwner)
	}
	s.reserved = true
	return s.finish(s.original.Reserve(ctx, tx, r, f))
}
func (s *captureCandidateSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if s == nil {
		return nil, ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx, r); e != nil {
		return nil, s.finish(e)
	}
	if !s.reserved || s.evidenced || f.Replayed {
		return nil, s.finish(ErrOwner)
	}
	s.evidenced = true
	evidence, e := s.original.LockEvidence(ctx, tx, r, f)
	return evidence, s.finish(e)
}
func (s *captureCandidateSession) Recheck(ctx context.Context, view pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if s == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, view, r); e != nil {
		return s.finish(e)
	}
	if !s.authorized || s.guard == nil || f.Replayed && (s.references || s.reserved || s.evidenced) || !f.Replayed && (!s.references || !s.reserved || !s.evidenced) {
		return s.finish(ErrOwner)
	}
	if e := s.original.Recheck(ctx, view, r, f, now); e != nil {
		return s.finish(e)
	}
	if f.Replayed {
		return s.finish(s.guard.RecheckCandidateIdentity(ctx, view))
	}
	return s.finish(s.capture.RecheckCandidateResource(ctx, view))
}

var _ sec.BootstrapCandidateAuthority = (*CaptureSigningCandidateAuthority)(nil)
var _ sec.BootstrapCandidateAuthoritySession = (*captureCandidateSession)(nil)
