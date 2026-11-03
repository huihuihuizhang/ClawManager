package systembackupkms

import (
	"context"
	"sync"
	"time"

	w "clawreef/internal/systembackupwire"
)

// CaptureJob is composed inside the originating worker process with an already
// admitted frozen request and the original execution authorization. Its API has
// no caller-selected key/request, unwrap, raw-DEK return or HTTP serialization.
// Missing OriginalJobAuthority is a hard deployment error, not a fallback to
// the old functional Lease.DEK path.
type CaptureJob struct {
	g         *CaptureGenerator
	r         w.KeyRequest
	mu        sync.Mutex
	attempted bool
	until     time.Time
}

func NewCaptureJob(ctx context.Context, c Config, m PermitMount, original OriginalJobAuthority, frozen w.KeyRequest) (*CaptureJob, error) {
	r, e := NewJobResolver(c, m, original)
	if e != nil {
		return nil, e
	}
	return newCaptureJob(ctx, c, r, original, frozen)
}

func newCaptureJob(ctx context.Context, c Config, r *PinnedJobResolver, original OriginalJobAuthority, frozen w.KeyRequest) (*CaptureJob, error) {
	a := Access{Request: frozen, Operation: Generate, Endpoint: c.Endpoint, KeyName: c.KeyName}
	if ctx == nil || original.Recheck(ctx, a) != nil {
		return nil, ErrPermission
	}
	p, e := r.permit(ctx, a)
	if e != nil {
		return nil, ErrPermission
	}
	g, e := NewCaptureGenerator(c, r)
	if e != nil {
		return nil, e
	}
	until := p.ExpiresAt
	if c.NotAfter.Before(until) {
		until = c.NotAfter
	}
	if original.ValidUntil().Before(until) {
		until = original.ValidUntil()
	}
	return &CaptureJob{g: g, r: frozen, until: until}, nil
}

// ValidUntil is the fixed shortest admitted window, including provider permit
// and mapping bounds. Writers must use it as their cancellation deadline.
func (j *CaptureJob) ValidUntil() time.Time {
	if j == nil {
		return time.Time{}
	}
	return j.until
}

func (j *CaptureJob) WithDEK(ctx context.Context, use w.WithDEK) (w.WrappedKey, error) {
	if j == nil || j.g == nil {
		return w.WrappedKey{}, ErrPermission
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.attempted {
		return w.WrappedKey{}, ErrPermission
	}
	// Generate may have succeeded remotely even when its response was lost.
	// This original envelope identity is single-use on every outcome.
	j.attempted = true
	return j.g.Generate(ctx, j.r, use)
}
func (j *CaptureJob) Close() {
	if j != nil {
		j.g.Close()
	}
}

// RecoveryJob receives independent CURRENT recovery authority plus the exact
// retained mapping and trusted expected request. It does not depend on a live
// forward generator, forward credential, or the provider's current version.
type RecoveryJob struct {
	u        *RecoveryUnwrapper
	r        w.KeyRequest
	resolver *PinnedJobResolver
}

func NewRecoveryJob(ctx context.Context, c Config, m PermitMount, original OriginalJobAuthority, expected w.KeyRequest) (*RecoveryJob, error) {
	r, e := NewJobResolver(c, m, original)
	if e != nil {
		return nil, e
	}
	a := Access{Request: expected, Operation: Unwrap, Endpoint: c.Endpoint, KeyName: c.KeyName}
	if ctx == nil || original.Recheck(ctx, a) != nil {
		return nil, ErrPermission
	}
	if _, e = r.permit(ctx, a); e != nil {
		return nil, ErrPermission
	}
	u, e := NewRecoveryUnwrapper(c, r)
	if e != nil {
		return nil, e
	}
	return &RecoveryJob{u: u, r: expected, resolver: r}, nil
}

// Recheck repeats CURRENT independent restore authority and the exact pinned
// historical provider permit/credential. It never unwraps or renews a scope.
func (j *RecoveryJob) Recheck(ctx context.Context) error {
	if j == nil || j.u == nil || j.resolver == nil || ctx == nil || ctx.Err() != nil {
		return ErrPermission
	}
	r := j.resolver
	now := time.Now()
	if now.Before(j.u.t.c.NotBefore) || !now.Before(j.u.t.c.NotAfter) {
		return ErrPermission
	}
	a := Access{Request: j.r, Operation: Unwrap, Endpoint: j.u.t.c.Endpoint, KeyName: j.u.t.c.KeyName}
	p, err := r.permit(ctx, a)
	if err != nil || r.credentialCurrent(p) != nil || r.original.Recheck(ctx, a) != nil {
		return ErrPermission
	}
	return ctx.Err()
}
func (j *RecoveryJob) WithDEK(ctx context.Context, wrapped w.WrappedKey, use w.WithDEK) error {
	if j == nil || j.u == nil {
		return ErrPermission
	}
	return j.u.Unwrap(ctx, j.r, wrapped, use)
}
func (j *RecoveryJob) Close() {
	if j != nil {
		j.u.Close()
	}
}
