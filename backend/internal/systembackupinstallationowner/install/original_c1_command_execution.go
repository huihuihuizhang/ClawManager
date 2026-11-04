package install

import (
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	"context"
	"reflect"
	"time"
)

type originalC1CommandEnvironment struct{ run *originalC1Run }
type originalC1CommandSession struct {
	*originalC1SQLStage
	request pd.CommandRequest
}

func (e *originalC1CommandEnvironment) Prepare(ctx context.Context, q pd.CommandRequest) (pd.PreparedCommand, error) {
	if e == nil || e.run == nil || !reflect.DeepEqual(q, e.run.command) || q.Command != "acquire" || q.Expected != nil || q.Next == nil {
		return pd.PreparedCommand{}, ErrInstall
	}
	g, err := e.run.before(ctx)
	if err != nil {
		return pd.PreparedCommand{}, err
	}
	h, err := pd.CommandHashes(q)
	if err != nil {
		return pd.PreparedCommand{}, err
	}
	g.phase = "acquire"
	g.requestHash = h.Request
	return pd.PreparedCommand{Session: &originalC1CommandSession{g, q}, CapacityObservedAt: &g.sample}, nil
}
func (s *originalC1CommandSession) LockInstallation(ctx context.Context, tx pd.SQL, q pd.CommandRequest) error {
	if !reflect.DeepEqual(q, s.request) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1CommandSession) Authenticate(ctx context.Context, tx pd.SQL, q pd.CommandRequest, d pd.DomainRecord) (pd.CommandAdmission, error) {
	if !reflect.DeepEqual(q, s.request) || s.auth(ctx, tx, d) != nil || q.ActorIdentityHash != s.run.native.subject || !reflect.DeepEqual(q.Target, s.run.native.target) || q.Next.SubjectIdentityHash != s.run.native.subject || q.Next.IssuerIdentityHash != d.IssuerIdentityHash {
		return pd.CommandAdmission{}, ErrInstall
	}
	return pd.CommandAdmission{RequestHash: s.requestHash, IdentityHash: s.run.native.subject, Deadlines: []time.Time{s.run.until}, Management: true, HistoricalReceiptRead: true, ReceiptRetentionUntil: c1stamp(s.run.native.retention), AdditionalCost: "16384"}, nil
}
func (s *originalC1CommandSession) LockHosts(ctx context.Context, tx pd.SQL, q pd.CommandRequest) error {
	if !reflect.DeepEqual(q, s.request) || s.run.local(ctx) != nil || !reflect.DeepEqual(q.Next.Host, s.run.native.host) {
		return ErrInstall
	}
	return nil
}
func (s *originalC1CommandSession) LockReferences(ctx context.Context, tx pd.SQL, q pd.CommandRequest) error {
	if !reflect.DeepEqual(q, s.request) || s.run.local(ctx) != nil || s.run.native.referenceHash == "" || s.run.native.lockOriginalReference(ctx, tx) != nil {
		return ErrInstall
	}
	return nil
}
func (s *originalC1CommandSession) Reserve(ctx context.Context, tx pd.SQL, q pd.CommandRequest, c uint64) error {
	if !reflect.DeepEqual(q, s.request) {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1CommandSession) Audit(ctx context.Context, tx pd.SQL, q pd.CommandRequest, phase string) error {
	if !reflect.DeepEqual(q, s.request) {
		return ErrInstall
	}
	return s.audit(ctx, tx, phase)
}
func (s *originalC1CommandSession) Recheck(ctx context.Context, tx pd.ReadSQL, q pd.CommandRequest, f pd.CommandFacts, now time.Time) error {
	if !reflect.DeepEqual(q, s.request) || f.Receipt.RequestHash != s.requestHash || !reflect.DeepEqual(f.Receipt.Request, q) {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, !f.Replayed)
}

// Stable outer environment keeps ONE actual *Execution identity. Switching to
// A's preparation/publication row guards never reconstructs or replaces the
// Lifecycle/handle/Execution accepted by PublicationClaim and CommitResult.
type originalC1ExecutionSwitch struct {
	raw         *originalC1ExecutionAuthority
	preparation *ev.SystemPreparationCallEnvironment
	publication *ev.SystemPublicationCallEnvironment
}

func (e *originalC1ExecutionSwitch) PrepareExecution(ctx context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	if e == nil || e.raw == nil {
		return pd.PreparedExecution{}, ErrInstall
	}
	if b.Call.Purpose == "sts" || b.Call.Purpose == "publish" {
		if e.publication == nil {
			return pd.PreparedExecution{}, ErrInstall
		}
		return e.publication.PrepareExecution(ctx, b)
	}
	if b.Call.Purpose == "content_read" || b.Call.Purpose == "wrap" {
		if e.preparation == nil {
			return pd.PreparedExecution{}, ErrInstall
		}
		return e.preparation.PrepareExecution(ctx, b)
	}
	return e.raw.PrepareExecution(ctx, b)
}

type originalC1ExecutionAuthority struct{ run *originalC1Run }
type originalC1ExecutionSession struct {
	*originalC1SQLStage
	binding pd.ExecutionBinding
}

func (e *originalC1ExecutionAuthority) PrepareExecution(ctx context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	if e == nil || e.run == nil {
		return pd.PreparedExecution{}, ErrInstall
	}
	r := e.run
	if r.acceptExecution(b) != nil {
		return pd.PreparedExecution{}, ErrInstall
	}
	g, err := r.before(ctx)
	if err != nil {
		return pd.PreparedExecution{}, err
	}
	h, err := pd.ExecutionBindingHash(b)
	if err != nil {
		return pd.PreparedExecution{}, err
	}
	g.phase = b.Kind + "_" + b.Call.Purpose
	g.requestHash = h
	prepared := pd.PreparedExecution{Session: &originalC1ExecutionSession{g, b}}
	if b.Kind == "bind_observation" {
		prepared.CapacityObservedAt = &g.sample
	}
	return prepared, nil
}
func (r *originalC1Run) acceptExecution(b pd.ExecutionBinding) error {
	n := r.command.Next
	if n == nil || r.commandReceipt.Outcome.GrantRowVersion == "" || b.Scope != r.parent.domain.Scope || b.Subject != r.native.subject || b.GrantID != n.GrantID || b.GrantGeneration != n.GrantGeneration || b.GrantVersion != r.commandReceipt.Outcome.GrantRowVersion || b.RunID != n.RunID || b.Call.EvidenceID != n.EvidenceID {
		return ErrInstall
	}
	var identity pd.Hash
	var version pd.ProviderVersion
	var policy string
	switch b.Call.Purpose {
	case "probe":
		identity = r.native.target.IdentityHash
		version = r.native.target.RefVersion
		policy = r.native.policy
	case "content_read":
		identity = r.native.target.IdentityHash
		version = r.native.target.RefVersion
		policy = ev.SystemExecutionPreparationPolicyHash(r.preparation)
	case "wrap":
		identity = pd.Hash(r.preparation.Wrap.Transit.Key.Identity)
		version = pd.ProviderVersion(r.preparation.Wrap.Transit.Key.Version)
		policy = ev.SystemExecutionPreparationPolicyHash(r.preparation)
	case "sts":
		identity = pd.Hash(r.parent.channel.Write.Identity)
		version = pd.ProviderVersion(r.parent.channel.Write.Version)
		policy = ev.SystemSTSPolicyHash(r.publication)
	case "publish":
		identity = pd.Hash(r.parent.channel.Store.Identity)
		version = pd.ProviderVersion(r.parent.channel.Store.Version)
		policy = ev.SystemSTSPolicyHash(r.publication)
	default:
		return ErrInstall
	}
	if identity == "" || version == "" || policy == "" || b.Call.RefIdentityHash != identity || b.Call.RefVersion != version || b.Call.PolicyHash != pd.Hash(policy) {
		return ErrInstall
	}
	if b.Kind == "bind_observation" {
		if !r.native.observed || r.probe == nil || b.Observation == nil || b.ProbeSnapshotHash == nil || *b.ProbeSnapshotHash != r.probe.BindingHash() || !reflect.DeepEqual(*b.Observation, r.observation) || b.Observation.AttestationHash != pd.Hash(r.native.attestation) {
			return ErrInstall
		}
	} else if b.Kind != "call" {
		return ErrInstall
	}
	return nil
}
func (s *originalC1ExecutionSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.lock(ctx, tx)
}
func (s *originalC1ExecutionSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, d pd.DomainRecord) (pd.ExecutionAdmission, error) {
	if !reflect.DeepEqual(b, s.binding) || s.run.acceptExecution(b) != nil || s.auth(ctx, tx, d) != nil {
		return pd.ExecutionAdmission{}, ErrInstall
	}
	a := pd.ExecutionAdmission{RequestHash: s.requestHash, IdentityHash: s.run.native.subject, IdentityVersionHash: pd.Hash(s.run.native.identityVersion), IdentityExpiresAt: c1stamp(s.run.until), AdditionalCost: "16384"}
	if b.Kind == "bind_observation" {
		h := pd.Hash(s.run.native.attestation)
		start, end := c1stamp(s.run.native.started), c1stamp(s.run.native.until)
		a.AuthenticatedAttestationHash = &h
		a.ObservedNotBefore = &start
		a.ObservationExpiresNotAfter = &end
	}
	return a, nil
}
func (s *originalC1ExecutionSession) LockHost(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, g pd.GrantRecord) error {
	if !reflect.DeepEqual(b, s.binding) {
		return ErrInstall
	}
	return s.host(ctx, g)
}
func (s *originalC1ExecutionSession) LockReferences(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, f pd.ExecutionFacts) (pd.ReferenceApproval, error) {
	if !reflect.DeepEqual(b, s.binding) {
		return pd.ReferenceApproval{}, ErrInstall
	}
	return s.refs(ctx, tx, s.requestHash, b.Call.PolicyHash)
}
func (s *originalC1ExecutionSession) Reserve(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, c uint64) error {
	if !reflect.DeepEqual(b, s.binding) || b.Kind != "bind_observation" {
		return ErrInstall
	}
	return s.reserve(ctx, tx, c)
}
func (s *originalC1ExecutionSession) Audit(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, p string) error {
	if !reflect.DeepEqual(b, s.binding) || b.Kind != "bind_observation" {
		return ErrInstall
	}
	return s.audit(ctx, tx, p)
}

// All evidence-bearing calls MUST pass through A's concrete outer wrappers.
func (s *originalC1ExecutionSession) LockEvidence(context.Context, pd.SQL, pd.ExecutionBinding, pd.ExecutionFacts) (pd.CallEvidence, error) {
	return pd.CallEvidence{}, ErrInstall
}
func (s *originalC1ExecutionSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ExecutionBinding, f pd.ExecutionFacts, now time.Time) error {
	if !reflect.DeepEqual(b, s.binding) || s.run.acceptExecution(b) != nil {
		return ErrInstall
	}
	return s.final(ctx, tx, f.Domain, now, b.Kind == "bind_observation")
}

var _ pd.CommandEnvironment = (*originalC1CommandEnvironment)(nil)
var _ pd.ExecutionEnvironment = (*originalC1ExecutionSwitch)(nil)
