package install

import (
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	"context"
	"reflect"
	"time"
)

func (r *originalC1Run) recordMatches(record ev.Record) bool {
	return reflect.DeepEqual(record.Manifest, r.prepared.Manifest()) && record.Ref.Identity == r.parent.channel.Store.Identity && record.Ref.Version == r.parent.channel.Store.Version && record.Ref.RelativeKey == string(r.history.RelativeKey)
}
func (r *originalC1Run) grantBinding(scope pd.Scope, subject pd.Hash, grant pd.ID, generation, version pd.Counter, run pd.ID) bool {
	n := r.command.Next
	return n != nil && scope == r.parent.domain.Scope && subject == r.native.subject && grant == n.GrantID && generation == n.GrantGeneration && version == r.commandReceipt.Outcome.GrantRowVersion && run == n.RunID
}
func c1ARegistryAdditional(record ev.Record) pd.Counter {
	return c1counter(32768 + uint64(len(record.Manifest.Chunks))*4096)
}

type originalC1PendingAuthority struct{ run *originalC1Run }
type originalC1PendingSession struct {
	*originalC1SQLStage
	binding     pd.PendingBinding
	historyHash pd.Hash
	cost        pd.Counter
}

func (a *originalC1PendingAuthority) PreparePendingAuthority(ctx context.Context, b pd.PendingBinding, record ev.Record) (ev.SystemPendingAuthoritySession, *time.Time, error) {
	if a == nil || a.run == nil {
		return nil, nil, ErrInstall
	}
	r := a.run
	if !reflect.DeepEqual(b.Request, r.pending) || !r.grantBinding(b.Scope, b.Subject, b.GrantID, b.GrantGeneration, b.GrantVersion, b.RunID) || !r.recordMatches(record) || r.pending.History.ObservedAt != r.observation.ObservedAt || r.pending.History.ObservationExpiresAt != r.observation.ExpiresAt {
		return nil, nil, ErrInstall
	}
	g, err := r.before(ctx)
	if err != nil {
		return nil, nil, err
	}
	h, err := pd.PendingBindingHash(b)
	if err != nil {
		return nil, nil, err
	}
	history, err := pd.PendingHistoryHash(r.history)
	if err != nil {
		return nil, nil, err
	}
	g.requestHash = h
	g.phase = "pending"
	return &originalC1PendingSession{g, b, history, c1ARegistryAdditional(record)}, &g.sample, nil
}
func (s *originalC1PendingSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.PendingBinding) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1PendingSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.PendingBinding, d pd.DomainRecord) (pd.PendingAdmission, error) {
	if !reflect.DeepEqual(b, s.binding) || s.auth(ctx, tx, d) != nil {
		return pd.PendingAdmission{}, ErrInstall
	}
	return pd.PendingAdmission{RequestHash: s.requestHash, IdentityHash: s.run.native.subject, IdentityExpiresAt: c1stamp(s.run.until), DependencyExpiresAt: c1stamp(s.run.until), PolicyHash: b.Request.PolicyHash, PreparedHistoryHash: s.historyHash, AdditionalCost: s.cost, ReadExisting: true}, nil
}
func (s *originalC1PendingSession) LockHost(ctx context.Context, tx pd.SQL, b pd.PendingBinding, g pd.GrantRecord) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.host(ctx, g)
}
func (s *originalC1PendingSession) LockReferences(ctx context.Context, tx pd.SQL, b pd.PendingBinding, f pd.PendingFacts) error {
	if !reflect.DeepEqual(b, s.binding) || s.run.local(ctx) != nil || !reflect.DeepEqual(f.History, s.run.history) || s.run.native.lockOriginalReference(ctx, tx) != nil {
		return ErrInstall
	}
	return nil
}
func (s *originalC1PendingSession) Reserve(ctx context.Context, tx pd.SQL, b pd.PendingBinding, c uint64) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1PendingSession) Audit(ctx context.Context, tx pd.SQL, b pd.PendingBinding, p string) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.audit(ctx, tx, p)
}
func (s *originalC1PendingSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.PendingBinding, f pd.PendingFacts, now time.Time) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, !f.Replayed)
}

type originalC1ClaimAuthority struct{ run *originalC1Run }
type originalC1ClaimSession struct {
	*originalC1SQLStage
	binding  pd.ClaimRequestBinding
	readback bool
}

func (a *originalC1ClaimAuthority) PrepareClaimAuthority(ctx context.Context, b pd.ClaimRequestBinding, readback bool, record ev.Record) (ev.SystemClaimAuthoritySession, *time.Time, error) {
	if a == nil || a.run == nil {
		return nil, nil, ErrInstall
	}
	r := a.run
	if !reflect.DeepEqual(b.Request, r.claimRequest) || !r.grantBinding(b.Scope, b.Subject, b.GrantID, b.GrantGeneration, b.GrantVersion, b.RunID) || !r.recordMatches(record) {
		return nil, nil, ErrInstall
	}
	g, err := r.before(ctx)
	if err != nil {
		return nil, nil, err
	}
	h, err := pd.ClaimRequestHash(b)
	if err != nil {
		return nil, nil, err
	}
	g.requestHash = h
	g.phase = "claim"
	s := &originalC1ClaimSession{g, b, readback}
	if readback {
		return s, nil, nil
	}
	return s, &g.sample, nil
}
func (s *originalC1ClaimSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1ClaimSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, d pd.DomainRecord, readback bool) (pd.ClaimAdmission, error) {
	if !reflect.DeepEqual(b, s.binding) || readback != s.readback || s.auth(ctx, tx, d) != nil {
		return pd.ClaimAdmission{}, ErrInstall
	}
	return pd.ClaimAdmission{RequestHash: s.requestHash, IdentityHash: s.run.native.subject, IdentityExpiresAt: c1stamp(s.run.until), ExpiresNotAfter: c1stamp(s.run.until), AdditionalCost: "16384", ReadbackAllowed: true}, nil
}
func (s *originalC1ClaimSession) LockHost(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, g pd.GrantRecord) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.host(ctx, g)
}
func (s *originalC1ClaimSession) LockReferences(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, f pd.ClaimFacts) (pd.ReferenceApproval, error) {
	if !reflect.DeepEqual(b, s.binding) {
		return pd.ReferenceApproval{}, ErrInstall
	}
	return s.refs(ctx, tx, s.requestHash, b.Request.PolicyHash)
}
func (s *originalC1ClaimSession) Reserve(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, c uint64) error {
	if !reflect.DeepEqual(b, s.binding) || s.readback {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1ClaimSession) Audit(ctx context.Context, tx pd.SQL, b pd.ClaimRequestBinding, p string) error {
	if !reflect.DeepEqual(b, s.binding) || s.readback {
		return ErrInstall
	}
	return s.audit(ctx, tx, p)
}
func (s *originalC1ClaimSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ClaimRequestBinding, f pd.ClaimFacts, now time.Time) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, !s.readback)
}

// This private authority is supplied ONLY to A NewVerifiedSystemPublisher.
// A's concrete native verifier independently authenticates its actual proof
// BEFORE delegation here. A direct caller-supplied ProofHash is insufficient.
type originalC1FinishAuthority struct{ run *originalC1Run }
type originalC1FinishSession struct {
	*originalC1SQLStage
	binding pd.FinishBinding
}

func (a *originalC1FinishAuthority) PrepareFinishAuthority(ctx context.Context, b pd.FinishBinding, record ev.Record) (ev.SystemFinishAuthoritySession, *time.Time, error) {
	if a == nil || a.run == nil {
		return nil, nil, ErrInstall
	}
	r := a.run
	if r.publisher == nil || r.claim == nil || !r.grantBinding(b.Scope, b.Subject, b.GrantID, b.GrantGeneration, b.GrantVersion, b.RunID) || !r.recordMatches(record) || b.Request.ObjectHash != r.history.Evidence.ObjectHash || b.Request.ObjectBytes != r.history.Evidence.ObjectBytes || b.Request.ProofHash == "" || b.Request.State != "ready" && b.Request.State != "write_unknown" || b.Claim.PolicyHash != pd.Hash(ev.SystemSTSPolicyHash(r.publication)) || b.Claim.RefsVersionHash != pd.Hash(r.native.referenceHash) {
		return nil, nil, ErrInstall
	}
	g, err := r.before(ctx)
	if err != nil {
		return nil, nil, err
	}
	h, err := pd.FinishBindingHash(b)
	if err != nil {
		return nil, nil, err
	}
	g.requestHash = h
	g.phase = "finish"
	return &originalC1FinishSession{g, b}, &g.sample, nil
}
func (s *originalC1FinishSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.FinishBinding) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1FinishSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.FinishBinding, d pd.DomainRecord) (pd.FinishAdmission, error) {
	if !reflect.DeepEqual(b, s.binding) || s.auth(ctx, tx, d) != nil {
		return pd.FinishAdmission{}, ErrInstall
	}
	return pd.FinishAdmission{RequestHash: s.requestHash, IdentityHash: s.run.native.subject, VerifiedProofHash: b.Request.ProofHash, IdentityExpiresAt: c1stamp(s.run.until), ProofExpiresAt: c1stamp(s.run.until), AdditionalCost: "16384"}, nil
}
func (s *originalC1FinishSession) LockHost(ctx context.Context, tx pd.SQL, b pd.FinishBinding, g pd.GrantRecord) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.host(ctx, g)
}
func (s *originalC1FinishSession) LockReferences(ctx context.Context, tx pd.SQL, b pd.FinishBinding, f pd.FinishFacts) (pd.ReferenceApproval, error) {
	if !reflect.DeepEqual(b, s.binding) {
		return pd.ReferenceApproval{}, ErrInstall
	}
	return s.refs(ctx, tx, s.requestHash, b.Claim.PolicyHash)
}
func (s *originalC1FinishSession) Reserve(ctx context.Context, tx pd.SQL, b pd.FinishBinding, c uint64) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1FinishSession) Audit(ctx context.Context, tx pd.SQL, b pd.FinishBinding, p string) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.audit(ctx, tx, p)
}
func (s *originalC1FinishSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.FinishBinding, f pd.FinishFacts, now time.Time) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, true)
}

type originalC1ResultAuthority struct{ run *originalC1Run }
type originalC1ResultSession struct {
	*originalC1SQLStage
	binding    pd.ResultBinding
	projection pd.ResultProjection
}

func (a *originalC1ResultAuthority) PrepareResultAuthority(ctx context.Context, b pd.ResultBinding, record ev.Record) (ev.SystemResultAuthoritySession, *time.Time, error) {
	if a == nil || a.run == nil {
		return nil, nil, ErrInstall
	}
	r := a.run
	if !reflect.DeepEqual(b.Request, r.result) || !reflect.DeepEqual(b.Request.Results, r.native.results) || !r.grantBinding(b.Request.Scope, b.Subject, b.Request.GrantID, b.Request.GrantGeneration, b.GrantVersion, b.Request.RunID) || !r.recordMatches(record) || !r.native.observed {
		return nil, nil, ErrInstall
	}
	g, err := r.before(ctx)
	if err != nil {
		return nil, nil, err
	}
	h, err := pd.ResultBindingHash(b)
	if err != nil {
		return nil, nil, err
	}
	d, err := pd.ResultHashes(b.Request)
	if err != nil {
		return nil, nil, err
	}
	g.requestHash = h
	g.phase = "result"
	return &originalC1ResultSession{g, b, pd.ResultProjection{BindingHash: h, TargetHash: d.Target, MappingHash: pd.Hash(r.native.referenceHash), Mode: "candidate"}}, &g.sample, nil
}
func (s *originalC1ResultSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.ResultBinding) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1ResultSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.ResultBinding, d pd.DomainRecord) (pd.ResultAdmission, error) {
	if !reflect.DeepEqual(b, s.binding) || s.auth(ctx, tx, d) != nil || !reflect.DeepEqual(b.Request.Results, s.run.native.results) || d.Admission.Unconfigured == nil {
		return pd.ResultAdmission{}, ErrInstall
	}
	hashes, err := pd.ResultHashes(b.Request)
	if err != nil {
		return pd.ResultAdmission{}, ErrInstall
	}
	return pd.ResultAdmission{BindingHash: s.requestHash, IdentityHash: s.run.native.subject, VerifiedRequestHash: hashes.Request, IdentityExpiresAt: c1stamp(s.run.until), DependencyExpiresAt: c1stamp(s.run.until), ReceiptRetentionUntil: c1stamp(s.run.native.retention), AdditionalCost: "16384", ReadReceipt: true}, nil
}
func (s *originalC1ResultSession) LockHost(ctx context.Context, tx pd.SQL, b pd.ResultBinding, g pd.GrantRecord) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.host(ctx, g)
}
func (s *originalC1ResultSession) LockProjectionReferences(ctx context.Context, tx pd.SQL, b pd.ResultBinding, f pd.ResultFacts) (pd.ResultProjection, error) {
	if !reflect.DeepEqual(b, s.binding) || s.run.local(ctx) != nil || f.Domain.Admission.Unconfigured == nil || s.run.native.lockOriginalReference(ctx, tx) != nil {
		return pd.ResultProjection{}, ErrInstall
	}
	return s.projection, nil
}
func (s *originalC1ResultSession) Reserve(ctx context.Context, tx pd.SQL, b pd.ResultBinding, c uint64) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1ResultSession) Audit(ctx context.Context, tx pd.SQL, b pd.ResultBinding, p string) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.audit(ctx, tx, p)
}
func (s *originalC1ResultSession) ApplyProjections(context.Context, pd.SQL, pd.ResultBinding, pd.ResultFacts) error {
	return ErrInstall
}
func (s *originalC1ResultSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ResultBinding, f pd.ResultFacts, now time.Time) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, !f.Replayed)
}

var _ ev.SystemPendingAuthority = (*originalC1PendingAuthority)(nil)
var _ ev.SystemClaimAuthority = (*originalC1ClaimAuthority)(nil)
var _ ev.SystemFinishAuthority = (*originalC1FinishAuthority)(nil)
var _ ev.SystemResultAuthority = (*originalC1ResultAuthority)(nil)
