// Package systembackupbootstrapmaterials composes A's existing three concrete
// material validators. It never supplies original deployment/resource authority.
package systembackupbootstrapmaterials

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	ca "clawreef/internal/systembackupcatrust"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Materials is fixed Go composition from independently authenticated original
// bindings. New checks consistency; it cannot certify the caller's authority,
// provider scope/permissions, or the other 24 missing resource slots.
type Materials struct {
	original           sec.BootstrapCandidateAuthority
	nonce              *nonce.Validator
	artifact, evidence *ca.Validator
}

func nilBoundary(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func New(original sec.BootstrapCandidateAuthority, n nonce.Binding, artifact, evidence ca.Binding) (*Materials, error) {
	if nilBoundary(original) || artifact.Purpose != "artifact_ca" || evidence.Purpose != "evidence_ca" {
		return nil, sec.ErrRegistrationUnavailable
	}
	for _, b := range []ca.Binding{artifact, evidence} {
		if b.InstallationID != n.InstallationID || b.ServerUUID != n.ServerUUID || b.Database != n.Database || b.ConfigSHA256 != n.ConfigSHA256 {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	nv, err := nonce.New(n)
	if err != nil {
		return nil, err
	}
	av, err := ca.New(artifact)
	if err != nil {
		return nil, err
	}
	ev, err := ca.New(evidence)
	if err != nil {
		return nil, err
	}
	return &Materials{original: original, nonce: nv, artifact: av, evidence: ev}, nil
}
func (Materials) String() string               { return "BootstrapMaterials" }
func (Materials) GoString() string             { return "BootstrapMaterials" }
func (Materials) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*Materials) UnmarshalJSON([]byte) error  { return sec.ErrRegistrationUnavailable }

// Owners copies the caller's maps, rejects collisions, and adds exactly three
// REAL legacy validators. Every remaining owner and cross-resource requirement
// stays mandatory. Candidates must be constructed with this Materials authority
// separately; an existing candidate route is rejected instead of silently kept.
func (m *Materials) Owners(base sec.BootstrapOwnerAdapters) (sec.BootstrapOwnerAdapters, error) {
	if m == nil || m.nonce == nil || m.artifact == nil || m.evidence == nil || nilBoundary(m.original) || base.Candidates != nil {
		return sec.BootstrapOwnerAdapters{}, sec.ErrRegistrationUnavailable
	}
	out := sec.BootstrapOwnerAdapters{Registries: make(map[string]sec.BootstrapResourceValidator), References: make(map[string]sec.BootstrapResourceValidator), CrossResources: base.CrossResources}
	for k, v := range base.Registries {
		out.Registries[k] = v
	}
	for k, v := range base.References {
		out.References[k] = v
	}
	for k, v := range map[string]sec.BootstrapResourceValidator{"nonce_hmac": m.nonce, "artifact_ca": m.artifact, "evidence_ca": m.evidence} {
		if _, exists := out.References[k]; exists {
			return sec.BootstrapOwnerAdapters{}, sec.ErrRegistrationUnavailable
		}
		out.References[k] = v
	}
	return out, nil
}

func sameContext(a, b context.Context) bool {
	return !nilBoundary(a) && !nilBoundary(b) && reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

// PrepareBootstrapCandidates runs all TLS/material preparation BEFORE SQL on
// the same bounded context as original authority. Physical failures are kept
// closed for fresh use without blocking an authenticated exact L3 replay.
func (m *Materials) PrepareBootstrapCandidates(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, r pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	var zero sec.PreparedBootstrapCandidateAuthority
	if m == nil || m.nonce == nil || m.artifact == nil || m.evidence == nil || nilBoundary(m.original) || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, sec.ErrRegistrationUnavailable
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	if err != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	n, err := m.nonce.PrepareCandidateAttempt(ctx, g, c)
	if err != nil {
		return zero, err
	}
	a, err := m.artifact.PrepareCandidateAttempt(ctx, g, c)
	if err != nil {
		return zero, err
	}
	e, err := m.evidence.PrepareCandidateAttempt(ctx, g, c)
	if err != nil {
		return zero, err
	}
	// Detach mutable comparison data before handing it to original callbacks.
	owned, err := sec.DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	var request pd.BootstrapConsumptionRequest
	if json.Unmarshal(raw, &request) != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	p, err := m.original.PrepareBootstrapCandidates(ctx, g, owned, request)
	if err != nil {
		return zero, err
	}
	if nilBoundary(p.Session) || ctx.Err() != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	if p.CapacityObservedAt != nil {
		value := *p.CapacityObservedAt
		p.CapacityObservedAt = &value
	}
	p.Session = &materialSession{&materialState{ctx: ctx, hash: hash, original: p.Session, nonce: n, artifact: a, evidence: e}}
	return p, nil
}

type materialSession struct{ *materialState }
type materialState struct {
	mu                           sync.Mutex
	ctx                          context.Context
	hash                         pd.Hash
	original                     sec.BootstrapCandidateAuthoritySession
	nonce                        *nonce.PreparedCandidateNonce
	artifact, evidence           *ca.PreparedCandidateCA
	nonceCheck                   *nonce.CandidateNonceCheck
	artifactCheck, evidenceCheck *ca.CandidateCACheck
	tx                           pd.BootstrapSQL
	authorized, locked, failed   bool
}

func (materialSession) String() string               { return "BootstrapMaterialSession" }
func (materialSession) GoString() string             { return "BootstrapMaterialSession" }
func (materialSession) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*materialSession) UnmarshalJSON([]byte) error  { return sec.ErrRegistrationUnavailable }

func (s *materialSession) check(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest) error {
	if s == nil || s.materialState == nil || s.failed {
		return sec.ErrRegistrationUnavailable
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	if err != nil || hash != s.hash || !sameContext(ctx, s.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(s.tx, tx) {
		s.failed = true
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (s *materialSession) finish(err error) error {
	if err != nil {
		s.failed = true
	}
	return err
}

func (s *materialSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	if s == nil || s.materialState == nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized || !pd.SameBootstrapTransaction(tx, tx) {
		s.failed = true
		return zero, sec.ErrRegistrationUnavailable
	}
	s.tx = tx
	if err := s.check(ctx, tx, r); err != nil {
		return zero, err
	}
	s.authorized = true
	a, err := s.original.Authorize(ctx, tx, r, d, now)
	if err != nil {
		return zero, s.finish(err)
	}
	// D checks dependency expiry ONLY after its exact historical-operation
	// branch. Never intersect these observations into current identity expiry.
	for _, deadline := range []*pd.Timestamp{s.nonce.DependencyDeadline(), s.artifact.DependencyDeadline(), s.evidence.DependencyDeadline()} {
		if deadline == nil {
			a.DependencyExpiresAt = pd.Timestamp("1000-01-01T00:00:00.000000Z")
			break
		}
		limit, e := deadline.Time()
		if e != nil {
			return zero, s.finish(sec.ErrRegistrationUnavailable)
		}
		current, e := a.DependencyExpiresAt.Time()
		if e == nil && limit.Before(current) {
			a.DependencyExpiresAt = *deadline
		}
	}
	return a, nil
}
func (s *materialSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.materialState == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx, r); err != nil {
		return err
	}
	return s.finish(s.original.LockHosts(ctx, tx, r, f))
}
func (s *materialSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.materialState == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx, r); err != nil {
		return err
	}
	if s.locked || f.Replayed {
		return s.finish(sec.ErrRegistrationUnavailable)
	}
	s.locked = true
	if err := s.original.LockReferences(ctx, tx, r, f); err != nil {
		return s.finish(err)
	}
	var err error
	s.nonceCheck, err = s.nonce.LockReferences(ctx, tx)
	if err != nil {
		return s.finish(err)
	}
	s.artifactCheck, err = s.artifact.CheckCandidate(ctx, tx)
	if err != nil {
		return s.finish(err)
	}
	s.evidenceCheck, err = s.evidence.CheckCandidate(ctx, tx)
	return s.finish(err)
}
func (s *materialSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s == nil || s.materialState == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx, r); err != nil {
		return err
	}
	if !s.locked || s.nonceCheck == nil || s.artifactCheck == nil || s.evidenceCheck == nil {
		return s.finish(sec.ErrRegistrationUnavailable)
	}
	return s.finish(s.original.Reserve(ctx, tx, r, f))
}
func (s *materialSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if s == nil || s.materialState == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx, r); err != nil {
		return nil, err
	}
	e, err := s.original.LockEvidence(ctx, tx, r, f)
	return e, s.finish(err)
}
func (s *materialSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if s == nil || s.materialState == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx, r); err != nil {
		return err
	}
	if err := s.original.Recheck(ctx, tx, r, f, now); err != nil {
		return s.finish(err)
	}
	if f.Replayed {
		if s.locked {
			return s.finish(sec.ErrRegistrationUnavailable)
		}
		return nil
	}
	if !s.locked || s.nonceCheck == nil || s.artifactCheck == nil || s.evidenceCheck == nil {
		return s.finish(sec.ErrRegistrationUnavailable)
	}
	if err := s.nonceCheck.Recheck(ctx, tx); err != nil {
		return s.finish(err)
	}
	if err := s.artifactCheck.Recheck(ctx, tx); err != nil {
		return s.finish(err)
	}
	return s.finish(s.evidenceCheck.Recheck(ctx, tx))
}

var _ sec.BootstrapCandidateAuthority = (*Materials)(nil)
var _ sec.BootstrapCandidateAuthoritySession = (*materialSession)(nil)
