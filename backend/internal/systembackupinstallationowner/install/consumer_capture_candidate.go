package install

import (
	"context"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type captureConsumerAuthority struct {
	source   *CaptureSigningConsumer
	original sec.BootstrapCandidateAuthority
}

func (s *CaptureSigningConsumer) CandidateAuthority(original sec.BootstrapCandidateAuthority) (sec.BootstrapCandidateAuthority, error) {
	if s == nil || consumerNil(original) {
		return nil, ErrInstall
	}
	return &captureConsumerAuthority{source: s, original: original}, nil
}
func (*captureConsumerAuthority) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*captureConsumerAuthority) String() string               { return "EnrolledCaptureCandidateAuthority" }
func (*captureConsumerAuthority) GoString() string             { return "EnrolledCaptureCandidateAuthority" }
func (a *captureConsumerAuthority) PrepareBootstrapCandidates(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	var zero sec.PreparedBootstrapCandidateAuthority
	if a == nil || a.source == nil || consumerNil(a.original) {
		return zero, ErrInstall
	}
	state, e := a.source.load(ctx)
	if e != nil {
		return zero, e
	}
	defer state.request.observer.Close()
	if grant != state.request.grant || config.SHA256() != state.request.config.SHA256() {
		return zero, ErrInstall
	}
	var joined *owner.CaptureSigningCandidateAuthority
	if state.request.observer == nil {
		joined, e = state.validator.IdentityOnlyCandidateAuthority(a.original)
	} else {
		joined, e = owner.NewCaptureSigningCandidateAuthority(a.original, state.validator)
	}
	if e != nil {
		return zero, e
	}
	prepared, e := joined.PrepareBootstrapCandidates(ctx, grant, config, request)
	if e != nil || state.current(ctx) != nil {
		return zero, ErrInstall
	}
	prepared.Session = &captureConsumerSession{state: state, original: prepared.Session}
	return prepared, nil
}

type captureConsumerSession struct {
	state    *consumerCaptureState
	original sec.BootstrapCandidateAuthoritySession
}

func (*captureConsumerSession) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*captureConsumerSession) String() string               { return "EnrolledCaptureCandidateSession" }
func (*captureConsumerSession) GoString() string             { return "EnrolledCaptureCandidateSession" }
func (s *captureConsumerSession) current(ctx context.Context) error {
	if s == nil || s.state == nil || consumerNil(s.original) {
		return ErrInstall
	}
	return s.state.current(ctx)
}
func (s *captureConsumerSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	if e := s.current(ctx); e != nil {
		return pd.BootstrapConsumptionAdmission{}, e
	}
	admission, e := s.original.Authorize(ctx, tx, r, d, now)
	return admission, s.state.finish(e)
}
func (s *captureConsumerSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if e := s.current(ctx); e != nil {
		return e
	}
	return s.state.finish(s.original.LockHosts(ctx, tx, r, f))
}
func (s *captureConsumerSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if e := s.current(ctx); e != nil {
		return e
	}
	if e := s.state.physical(ctx); e != nil {
		return e
	}
	return s.state.finish(s.original.LockReferences(ctx, tx, r, f))
}
func (s *captureConsumerSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if e := s.current(ctx); e != nil {
		return e
	}
	return s.state.finish(s.original.Reserve(ctx, tx, r, f))
}
func (s *captureConsumerSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if e := s.current(ctx); e != nil {
		return nil, e
	}
	result, e := s.original.LockEvidence(ctx, tx, r, f)
	return result, s.state.finish(e)
}
func (s *captureConsumerSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if e := s.current(ctx); e != nil {
		return e
	}
	if !f.Replayed {
		if e := s.state.physical(ctx); e != nil {
			return e
		}
	}
	return s.state.finish(s.original.Recheck(ctx, tx, r, f, now))
}

var _ sec.BootstrapCandidateAuthority = (*captureConsumerAuthority)(nil)
var _ sec.BootstrapCandidateAuthoritySession = (*captureConsumerSession)(nil)
