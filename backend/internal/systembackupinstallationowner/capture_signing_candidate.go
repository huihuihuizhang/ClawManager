package systembackupinstallationowner

import (
	"context"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Private alias keeps the full producer write capability out of record DTOs.
type candidateWrite = pd.BootstrapSQL

func (v *CaptureSigningValidator) PrepareCandidateAttempt(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (*PreparedCaptureSigning, error) {
	h, e := pd.BootstrapConsumptionHash(request)
	if e != nil {
		return nil, ErrOwner
	}
	return v.prepare(ctx, g, c, string(h))
}

// This is only the concrete capture owner's L2 source check. It does not
// implement Original's other five methods or approve a partial resource batch.
func (p *PreparedCaptureSigning) AuthorizeCandidate(ctx context.Context, tx pd.BootstrapSQL) (*OwnerGuard, error) {
	if p == nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed || p.guard != nil || p.candidateHash == "" {
		p.failed = true
		return nil, ErrOwner
	}
	facts, until, e := p.identityRead(ctx, tx, func() (time.Time, error) { return tx.SampleTime(ctx) }, nil)
	if e != nil {
		p.failed = true
		return nil, e
	}
	p.guard = &OwnerGuard{prepared: p, candidate: tx, first: facts, until: until}
	return p.guard, nil
}
func (g *OwnerGuard) RecheckCandidateIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if g == nil || g.prepared == nil {
		return ErrOwner
	}
	p := g.prepared
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || g.failed || p.guard != g || !pd.SameBootstrapTransaction(g.candidate, view) {
		p.failed = true
		g.failed = true
		return ErrOwner
	}
	g.failed = true
	_, until, e := p.identityRead(ctx, view, func() (time.Time, error) { return view.SampleTime(ctx) }, &g.first)
	if e != nil || !until.Equal(g.until) {
		p.failed = true
		return ErrOwner
	}
	g.failed = false
	return nil
}
func (p *PreparedCaptureSigning) RecheckCandidateResource(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	if p.origin != p {
		p.mu.Unlock()
		return ErrOwner
	}
	g := p.guard
	p.mu.Unlock()
	if g == nil {
		p.mu.Lock()
		p.failed = true
		p.mu.Unlock()
		return ErrOwner
	}
	if g.RecheckCandidateIdentity(ctx, view) != nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	before, e := view.SampleTime(ctx)
	if e != nil || !p.resourceCurrent(ctx, before) {
		p.failed = true
		return ErrOwner
	}
	after, e := view.SampleTime(ctx)
	if e != nil || after.Before(before) || !after.Before(g.until) || !p.resourceCurrent(ctx, after) {
		p.failed = true
		return ErrOwner
	}
	return nil
}

// A missing/expired physical observation does not prevent L2 current identity
// authorization for exact history. It must still refuse ALL new consumption.
func (p *PreparedCaptureSigning) DependencyDeadline() *pd.Timestamp {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed || p.observation == nil {
		return nil
	}
	end := minimum(p.observation.until, p.auth.record.Until)
	out := pd.Timestamp(end.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &out
}

func (g *OwnerGuard) IdentityDeadline() *pd.Timestamp {
	if g == nil || g.prepared == nil {
		return nil
	}
	p := g.prepared
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || g.failed || p.guard != g || g.until.IsZero() {
		return nil
	}
	out := pd.Timestamp(g.until.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &out
}
