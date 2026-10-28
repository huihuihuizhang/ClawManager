package systembackupevidence

import (
	"context"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemPreparationCallEnvironment supplies the A-owned L8 absence check for
// D's content_read and wrap calls. No evidence row exists before preparation;
// the reserved CallEvidence is derived from the locked absence, not a caller
// assertion. The underlying environment still owns live identity, evaluator,
// deployment, reference, capacity and audit authorization.
type SystemPreparationCallEnvironment struct {
	authority pd.ExecutionEnvironment
	scope     pd.Scope
	runID     pd.ID
	evidence  pd.EvidenceID
	input     pd.Hash
	subject   pd.Hash
	issuer    pd.Hash
	policy    pd.Hash
	target    pd.Target
	content   pd.CallRequest
	wrap      pd.CallRequest
	validTo   time.Time
}

func NewSystemPreparationCallEnvironment(authority pd.ExecutionEnvironment, c SystemExecutionPreparationPolicy) (*SystemPreparationCallEnvironment, error) {
	until := c.Content.ValidUntil
	policy := SystemExecutionPreparationPolicyHash(c)
	if nilSystemAdapter(authority) || !c.Identity.validExternal() || c.Identity.OwnerType != "system" || c.Identity.Type != "capability_snapshot" ||
		string(c.Scope.Installation) != c.Identity.Installation || string(c.RunID) == "" ||
		!digestPattern.MatchString(c.InputHash) || !digestPattern.MatchString(c.SubjectIdentityHash) || !digestPattern.MatchString(c.IssuerIdentityHash) ||
		!digestPattern.MatchString(c.EvaluatorProfileHash) || !digestPattern.MatchString(policy) ||
		!digestPattern.MatchString(c.Content.ProviderIdentity) || !versionPattern.MatchString(c.Content.ProviderVersion) ||
		!c.Wrap.Transit.Key.valid() || !time.Now().Before(until) {
		return nil, ErrDenied
	}
	return &SystemPreparationCallEnvironment{
		authority: authority, scope: c.Scope, runID: c.RunID, evidence: pd.EvidenceID(c.Identity.ID),
		input: pd.Hash(c.InputHash), subject: pd.Hash(c.SubjectIdentityHash), issuer: pd.Hash(c.IssuerIdentityHash), policy: pd.Hash(policy),
		target:  pd.Target{Role: pd.Role(c.Content.Role), IdentityHash: pd.Hash(c.Content.ProviderIdentity), RefVersion: pd.ProviderVersion(c.Content.ProviderVersion), ProbeScopeHash: pd.Hash(c.Content.ScopeHash), EvaluatorProfileHash: pd.Hash(c.EvaluatorProfileHash)},
		content: pd.CallRequest{Purpose: "content_read", EvidenceID: pd.EvidenceID(c.Identity.ID), RefIdentityHash: pd.Hash(c.Content.ProviderIdentity), RefVersion: pd.ProviderVersion(c.Content.ProviderVersion), PolicyHash: pd.Hash(policy)},
		wrap:    pd.CallRequest{Purpose: "wrap", EvidenceID: pd.EvidenceID(c.Identity.ID), RefIdentityHash: pd.Hash(c.Wrap.Transit.Key.Identity), RefVersion: pd.ProviderVersion(c.Wrap.Transit.Key.Version), PolicyHash: pd.Hash(policy)},
		validTo: until,
	}, nil
}

func (e *SystemPreparationCallEnvironment) PrepareExecution(ctx context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) {
		return pd.PreparedExecution{}, ErrDenied
	}
	if b.Call.Purpose != "content_read" && b.Call.Purpose != "wrap" {
		if b.Call.Purpose != "probe" {
			return pd.PreparedExecution{}, ErrDenied
		}
		return e.authority.PrepareExecution(ctx, b)
	}
	want := e.content
	if b.Call.Purpose == "wrap" {
		want = e.wrap
	}
	want.BudgetUntil = b.Call.BudgetUntil
	if b.Kind != "call" || b.Scope != e.scope || b.RunID != e.runID || b.Subject != e.subject || b.Claim != nil || b.Observation != nil || b.ProbeSnapshotHash != nil || b.Call != want {
		return pd.PreparedExecution{}, ErrDenied
	}
	prepared, err := e.authority.PrepareExecution(ctx, b)
	if err != nil || nilSystemAdapter(prepared.Session) {
		return pd.PreparedExecution{}, ErrDenied
	}
	prepared.Session = &systemPreparationCallSession{ExecutionSession: prepared.Session, original: e, binding: b}
	return prepared, nil
}

type systemPreparationCallSession struct {
	pd.ExecutionSession
	original *SystemPreparationCallEnvironment
	binding  pd.ExecutionBinding
	locked   bool
	failed   bool
}

func (s *systemPreparationCallSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, f pd.ExecutionFacts) (pd.CallEvidence, error) {
	o := s.original
	if s.failed || s.locked || ctx == nil || ctx.Err() != nil || !reflect.DeepEqual(b, s.binding) ||
		f.Domain.Scope != o.scope || f.Domain.IssuerIdentityHash != o.issuer || f.Grant.Scope != o.scope || f.Grant.SubjectIdentityHash != o.subject ||
		f.Grant.Target.Role != o.target.Role || f.Grant.Target.IdentityHash != o.target.IdentityHash || f.Grant.Target.RefVersion != o.target.RefVersion || f.Grant.Target.ProbeScopeHash != o.target.ProbeScopeHash || f.Grant.Target.EvaluatorProfileHash != o.target.EvaluatorProfileHash ||
		f.Run.Scope != o.scope || f.Run.RunID != o.runID || f.Run.InputHash != o.input || f.Run.EvidenceID != o.evidence || f.Run.State != "acquired" ||
		f.Run.ObservedAt == nil || f.Run.ObservationExpiresAt == nil || f.Target.Scope != o.scope || f.References.PolicyHash != o.policy {
		s.failed = true
		return pd.CallEvidence{}, ErrIntegrity
	}
	observedUntil, err := f.Run.ObservationExpiresAt.Time()
	if err != nil || !observedUntil.Equal(o.validTo) {
		s.failed = true
		return pd.CallEvidence{}, ErrIntegrity
	}
	if _, ok := tx.(*pd.Transaction); !ok {
		s.failed = true
		return pd.CallEvidence{}, ErrDenied
	}
	if err := lockSystemPreparationAbsent(ctx, tx, o.evidence); err != nil {
		s.failed = true
		return pd.CallEvidence{}, err
	}
	s.locked = true
	return pd.CallEvidence{EvidenceID: o.evidence, OwnerType: "system", OwnerID: o.scope.Installation, EvidenceType: "capability_snapshot", State: "reserved", RowVersion: "0"}, nil
}

func (s *systemPreparationCallSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ExecutionBinding, f pd.ExecutionFacts, now time.Time) error {
	if s.failed || !s.locked || ctx == nil || ctx.Err() != nil || !reflect.DeepEqual(b, s.binding) {
		return ErrIntegrity
	}
	if err := s.ExecutionSession.Recheck(ctx, tx, b, f, now); err != nil {
		return err
	}
	return lockSystemPreparationAbsent(ctx, tx, s.original.evidence)
}

func lockSystemPreparationAbsent(ctx context.Context, tx pd.ReadSQL, id pd.EvidenceID) error {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", id)
	if err != nil {
		return ErrUnavailable
	}
	columns, err := rows.Columns()
	if err != nil || len(columns) != 1 || columns[0] != "id" {
		_ = rows.Close()
		return ErrIntegrity
	}
	found := rows.Next()
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	if found {
		return ErrIntegrity
	}
	return nil
}
