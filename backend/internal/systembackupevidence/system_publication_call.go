package systembackupevidence

import (
	"context"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemPublicationCallEnvironment adds A's exact registry/chunk check to D's
// sts and publish calls. The underlying environment remains responsible for
// current identity, deployment, references, capacity and audit authorization.
type SystemPublicationCallEnvironment struct {
	authority pd.ExecutionEnvironment
	original  systemPublicationOriginal
}

func NewSystemPublicationCallEnvironment(authority pd.ExecutionEnvironment, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord) (*SystemPublicationCallEnvironment, error) {
	if nilSystemAdapter(authority) {
		return nil, ErrDenied
	}
	o, err := newSystemPublicationOriginal(p, c, h)
	if err != nil {
		return nil, err
	}
	return &SystemPublicationCallEnvironment{authority: authority, original: o}, nil
}

func (e *SystemPublicationCallEnvironment) PrepareExecution(ctx context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(e.authority) {
		return pd.PreparedExecution{}, ErrDenied
	}
	if b.Call.Purpose != "sts" && b.Call.Purpose != "publish" {
		return pd.PreparedExecution{}, ErrDenied
	}
	h := e.original.history
	refIdentity, refVersion := h.Evidence.WriteIdentityHash, pd.ProviderVersion(h.Evidence.WriteRefVersion)
	if b.Call.Purpose == "publish" {
		refIdentity, refVersion = h.Evidence.StoreIdentityHash, pd.ProviderVersion(h.Evidence.StoreRefVersion)
	}
	if b.Kind != "call" || b.Scope != h.Scope || b.RunID != h.RunID || b.GrantID != h.GrantID || b.GrantGeneration != h.GrantGeneration ||
		b.Observation != nil || b.ProbeSnapshotHash != nil || b.Claim == nil || b.Call.EvidenceID != h.Evidence.EvidenceID ||
		b.Call.RefIdentityHash != refIdentity || b.Call.RefVersion != refVersion || b.Call.PolicyHash != b.Claim.PolicyHash ||
		b.Claim.EvidenceID != h.Evidence.EvidenceID || b.Claim.ManifestHash != h.Evidence.ManifestHash {
		return pd.PreparedExecution{}, ErrDenied
	}
	prepared, err := e.authority.PrepareExecution(ctx, b)
	if err != nil || nilSystemAdapter(prepared.Session) {
		return pd.PreparedExecution{}, ErrDenied
	}
	prepared.Session = &systemPublicationCallSession{ExecutionSession: prepared.Session, original: e.original, binding: b}
	return prepared, nil
}

type systemPublicationCallSession struct {
	pd.ExecutionSession
	original systemPublicationOriginal
	binding  pd.ExecutionBinding
	locked   bool
	failed   bool
	stored   systemPendingStored
}

func (s *systemPublicationCallSession) LockEvidence(ctx context.Context, tx pd.SQL, b pd.ExecutionBinding, facts pd.ExecutionFacts) (pd.CallEvidence, error) {
	h := s.original.history
	if s.failed || s.locked || ctx == nil || ctx.Err() != nil || !reflect.DeepEqual(b, s.binding) || b.Claim == nil ||
		facts.Domain.Scope != h.Scope || facts.Domain.Epoch != h.DomainEpoch || !reflect.DeepEqual(facts.Domain.Admission, h.Admission) ||
		facts.Grant.Scope != h.Scope || facts.Grant.GrantID != h.GrantID || facts.Grant.Generation != h.GrantGeneration ||
		facts.Run.Scope != h.Scope || facts.Run.RunID != h.RunID || facts.Run.EvidenceID != h.Evidence.EvidenceID || facts.Run.TargetHash != h.TargetHash || facts.Run.InputHash != h.InputHash || facts.Run.OwnerWriteExpiresAt != h.OwnerWriteExpiresAt || facts.Run.ObservedAt == nil || *facts.Run.ObservedAt != h.ObservedAt || facts.Run.ObservationExpiresAt == nil || *facts.Run.ObservationExpiresAt != h.ObservationExpiresAt || facts.Target.Scope != h.Scope || facts.Target.TargetHash != h.TargetHash {
		s.failed = true
		return pd.CallEvidence{}, ErrIntegrity
	}
	if _, ok := tx.(*pd.Transaction); !ok {
		s.failed = true
		return pd.CallEvidence{}, ErrDenied
	}
	row, found, err := loadSystemPending(ctx, tx, s.original.record)
	if err != nil || !found {
		s.failed = true
		if err != nil {
			return pd.CallEvidence{}, err
		}
		return pd.CallEvidence{}, ErrIntegrity
	}
	evidence := s.original.claimEvidence(row).Evidence
	if evidence.RowVersion != pd.ZeroCounter(b.Claim.EvidenceVersion) || evidence.ManifestHash == nil || *evidence.ManifestHash != b.Claim.ManifestHash || evidence.ClaimOwner == nil || *evidence.ClaimOwner != b.Claim.Owner || evidence.ClaimExpiresAt == nil || *evidence.ClaimExpiresAt != b.Claim.ExpiresAt {
		s.failed = true
		return pd.CallEvidence{}, ErrIntegrity
	}
	s.locked, s.stored = true, row
	return evidence, nil
}

func (s *systemPublicationCallSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.ExecutionBinding, facts pd.ExecutionFacts, now time.Time) error {
	if s.failed || !s.locked || ctx == nil || ctx.Err() != nil || !reflect.DeepEqual(b, s.binding) {
		return ErrIntegrity
	}
	if err := s.ExecutionSession.Recheck(ctx, tx, b, facts, now); err != nil {
		return err
	}
	row, found, err := loadSystemPending(ctx, tx, s.original.record)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(row, s.stored) {
		return ErrIntegrity
	}
	return nil
}
