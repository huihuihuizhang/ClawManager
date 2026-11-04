package systembackupevidence

import (
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This wrapper adds genuine retained C provenance. It never replaces the
// original deployment/admin/revocation/host/reference/capacity/audit authority.
type nativePublicationFinishAuthority struct {
	verifier *NativeSystemPublicationVerifier
	original SystemFinishAuthority
}

func (v *NativeSystemPublicationVerifier) matchesFinish(ctx context.Context, b pd.FinishBinding, r Record, now time.Time) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.matchesFinishLocked(ctx, b, r, now)
}
func (v *NativeSystemPublicationVerifier) matchesFinishLocked(ctx context.Context, b pd.FinishBinding, r Record, now time.Time) bool {
	if v.origin != v || v.closed || v.failed || !v.used || v.sts == nil || v.sts.closed.Load() || !sameRelayContext(ctx, v.ctx) || ctx.Err() != nil {
		return false
	}
	p, q := v.proof, v.proof.Request
	if p.State != "ready" || p.ProofHash == "" || now.Before(p.ObservedAt) || !now.Before(p.ExpiresAt) || !time.Now().Before(p.ExpiresAt) || b.Request.ImmutableVersion == nil {
		return false
	}
	observed, oe := b.Request.ObservedAt.Time()
	budget, be := b.Request.BudgetUntil.Time()
	objectBytes, se := b.Request.ObjectBytes.SQLInt64()
	original := v.sts.views[0].Binding
	return oe == nil && be == nil && se == nil && b.Scope == q.Scope && b.RunID == q.RunID && b.Claim == q.Claim && b.Subject == original.Subject && b.GrantID == original.GrantID && b.GrantGeneration == original.GrantGeneration && b.GrantVersion == original.GrantVersion && b.Request.State == p.State && string(b.Request.ProofHash) == p.ProofHash && string(b.Request.ObjectHash) == p.Object.SHA256 && objectBytes == p.Object.Size && string(*b.Request.ImmutableVersion) == p.Object.Version && observed.Equal(p.ObservedAt) && budget.Equal(p.ExpiresAt) && hash(canonical(r)) == hash(canonical(v.sts.original.record))
}

func (a *nativePublicationFinishAuthority) PrepareFinishAuthority(ctx context.Context, b pd.FinishBinding, r Record) (SystemFinishAuthoritySession, *time.Time, error) {
	if a == nil || a.verifier == nil || nilSystemAdapter(a.original) {
		return nil, nil, ErrDenied
	}
	v := a.verifier
	v.mu.Lock()
	if v.bound || !v.matchesFinishLocked(ctx, b, r, time.Now().UTC()) {
		v.mu.Unlock()
		return nil, nil, ErrDenied
	}
	v.bound = true // Includes failed original-authority attempts; never retry proof.
	v.mu.Unlock()
	binding, e := pd.FinishBindingHash(b)
	if e != nil {
		return nil, nil, ErrDenied
	}
	delegate, sample, e := a.original.PrepareFinishAuthority(ctx, b, r)
	if e != nil || nilSystemAdapter(delegate) || !v.matchesFinish(ctx, b, r, time.Now().UTC()) {
		return nil, nil, ErrDenied
	}
	s := &nativePublicationFinishSession{SystemFinishAuthoritySession: delegate, verifier: v, ctx: ctx, binding: binding, record: r}
	s.origin = s
	return s, copySystemPublicationSample(sample), nil
}

type nativePublicationFinishSession struct {
	SystemFinishAuthoritySession
	origin                *nativePublicationFinishSession
	verifier              *NativeSystemPublicationVerifier
	ctx                   context.Context
	binding               pd.Hash
	record                Record
	tx                    *pd.Transaction
	failed, authenticated bool
}

func (s *nativePublicationFinishSession) valid(ctx context.Context, b pd.FinishBinding) bool {
	if s == nil || s.origin != s || s.failed || !sameRelayContext(ctx, s.ctx) || ctx.Err() != nil {
		return false
	}
	h, e := pd.FinishBindingHash(b)
	return e == nil && h == s.binding && s.verifier.matchesFinish(ctx, b, s.record, time.Now().UTC())
}
func (s *nativePublicationFinishSession) check(ctx context.Context, tx pd.SQL, b pd.FinishBinding) error {
	if !s.valid(ctx, b) || s.tx == nil || tx != s.tx {
		if s != nil {
			s.failed = true
		}
		return ErrDenied
	}
	now, e := s.tx.SampleTime(ctx)
	if e != nil || !s.verifier.matchesFinish(ctx, b, s.record, now) {
		s.failed = true
		return ErrDenied
	}
	return nil
}
func (s *nativePublicationFinishSession) LockInstallation(ctx context.Context, tx pd.SQL, b pd.FinishBinding) error {
	if !s.valid(ctx, b) || s.tx != nil {
		if s != nil {
			s.failed = true
		}
		return ErrDenied
	}
	t, ok := tx.(*pd.Transaction)
	if !ok || t == nil {
		s.failed = true
		return ErrDenied
	}
	s.tx = t
	if s.check(ctx, tx, b) != nil {
		return ErrDenied
	}
	if e := s.SystemFinishAuthoritySession.LockInstallation(ctx, tx, b); e != nil {
		s.failed = true
		return e
	}
	return s.check(ctx, tx, b)
}
func (s *nativePublicationFinishSession) Authenticate(ctx context.Context, tx pd.SQL, b pd.FinishBinding, d pd.DomainRecord) (pd.FinishAdmission, error) {
	if s.check(ctx, tx, b) != nil || s.authenticated {
		if s != nil {
			s.failed = true
		}
		return pd.FinishAdmission{}, ErrDenied
	}
	a, e := s.SystemFinishAuthoritySession.Authenticate(ctx, tx, b, d)
	expires, ee := a.ProofExpiresAt.Time()
	s.verifier.mu.Lock()
	proof := s.verifier.proof
	s.verifier.mu.Unlock()
	if e != nil || ee != nil || a.VerifiedProofHash != b.Request.ProofHash || s.check(ctx, tx, b) != nil {
		s.failed = true
		return pd.FinishAdmission{}, ErrDenied
	}
	// C contributes its genuine original proof deadline; never extend any
	// shorter current identity/authority limit returned by the original owner.
	if expires.After(proof.ExpiresAt) {
		a.ProofExpiresAt = systemPublicationTimestamp(proof.ExpiresAt)
	}
	s.authenticated = true
	return a, nil
}
func (s *nativePublicationFinishSession) LockHost(ctx context.Context, tx pd.SQL, b pd.FinishBinding, g pd.GrantRecord) error {
	if s.check(ctx, tx, b) != nil || !s.authenticated {
		return ErrDenied
	}
	if e := s.SystemFinishAuthoritySession.LockHost(ctx, tx, b, g); e != nil {
		s.failed = true
		return e
	}
	return s.check(ctx, tx, b)
}
func (s *nativePublicationFinishSession) LockReferences(ctx context.Context, tx pd.SQL, b pd.FinishBinding, f pd.FinishFacts) (pd.ReferenceApproval, error) {
	if s.check(ctx, tx, b) != nil || !s.authenticated {
		return pd.ReferenceApproval{}, ErrDenied
	}
	r, e := s.SystemFinishAuthoritySession.LockReferences(ctx, tx, b, f)
	if e != nil {
		s.failed = true
		return pd.ReferenceApproval{}, e
	}
	if s.check(ctx, tx, b) != nil {
		return pd.ReferenceApproval{}, ErrDenied
	}
	return r, nil
}
func (s *nativePublicationFinishSession) Reserve(ctx context.Context, tx pd.SQL, b pd.FinishBinding, c uint64) error {
	if s.check(ctx, tx, b) != nil || !s.authenticated {
		return ErrDenied
	}
	if e := s.SystemFinishAuthoritySession.Reserve(ctx, tx, b, c); e != nil {
		s.failed = true
		return e
	}
	return s.check(ctx, tx, b)
}
func (s *nativePublicationFinishSession) Audit(ctx context.Context, tx pd.SQL, b pd.FinishBinding, outcome string) error {
	if s.check(ctx, tx, b) != nil || !s.authenticated {
		return ErrDenied
	}
	if e := s.SystemFinishAuthoritySession.Audit(ctx, tx, b, outcome); e != nil {
		s.failed = true
		return e
	}
	return s.check(ctx, tx, b)
}
func (s *nativePublicationFinishSession) Recheck(ctx context.Context, tx pd.ReadSQL, b pd.FinishBinding, f pd.FinishFacts, now time.Time) error {
	if !s.valid(ctx, b) || !s.authenticated || !pd.SameGuardedTransaction(s.tx, tx) || !s.verifier.matchesFinish(ctx, b, s.record, now) {
		if s != nil {
			s.failed = true
		}
		return ErrDenied
	}
	if e := s.SystemFinishAuthoritySession.Recheck(ctx, tx, b, f, now); e != nil {
		s.failed = true
		return e
	}
	if !s.valid(ctx, b) || !s.verifier.matchesFinish(ctx, b, s.record, now) {
		s.failed = true
		return ErrDenied
	}
	return nil
}

var _ SystemFinishAuthority = (*nativePublicationFinishAuthority)(nil)
var _ SystemFinishAuthoritySession = (*nativePublicationFinishSession)(nil)
