package systembackupinstallationowner

import (
	"bytes"
	"context"
	"time"
)

// A distinct dependency observation, not signing-resource admission, a capture
// certificate or a business-source hold. The private original authenticated
// record and existing observer perform actual TLS cluster-health and complete
// three-purpose retained-key/ACL/JWT metadata reads. This read-only operation
// never logs in as a signer, mints a token or signs a new business object.
type ObservedOriginalSigningDependency struct {
	origin          *ObservedOriginalSigningDependency
	ctx             context.Context
	record          *AuthenticatedRecord
	observer        *CaptureSigningObserver
	observed, until time.Time
	metadataSHA256  string
}

func (*ObservedOriginalSigningDependency) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*ObservedOriginalSigningDependency) String() string               { return "ObservedOriginalSigningDependency" }
func (*ObservedOriginalSigningDependency) GoString() string {
	return "ObservedOriginalSigningDependency"
}

func (o *CaptureSigningObserver) ObserveOriginalProviderDependency(ctx context.Context, original *AuthenticatedRecord) (*ObservedOriginalSigningDependency, error) {
	if o == nil || original == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || o.cfg.Endpoint != original.record.Binding.Endpoint || o.cfg.CASHA256 != original.record.Binding.CASHA256 {
		return nil, ErrOwner
	}
	token, err := privateToken(o.cfg.ObserverTokenFile)
	if err != nil {
		return nil, ErrOwner
	}
	defer clear(token)
	if digest(token) != o.cfg.ObserverTokenSHA256 {
		return nil, ErrOwner
	}
	health := &SigningResourceObserver{transport: o}
	if health.health(ctx, original.record.Binding) != nil {
		return nil, ErrOwner
	}
	first, err := o.metadata(ctx, original, token)
	if err != nil {
		return nil, ErrOwner
	}
	second, err := o.metadata(ctx, original, token)
	if err != nil || !bytes.Equal(first, second) || health.health(ctx, original.record.Binding) != nil {
		return nil, ErrOwner
	}
	current, err := privateToken(o.cfg.ObserverTokenFile)
	defer clear(current)
	if err != nil || !bytes.Equal(current, token) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	observed := time.Now().UTC()
	until := minimum(deadline, observed.Add(10*time.Second))
	p := &ObservedOriginalSigningDependency{ctx: ctx, observer: o, record: original, observed: observed, until: until, metadataSHA256: digest(first)}
	p.origin = p
	if p.Recheck(ctx, original.record.Binding, time.Now().UTC()) != nil {
		return nil, ErrOwner
	}
	return p, nil
}

// Only checks this exact native-produced metadata observation. The signed
// record supplies immutable independently authenticated comparison data; this
// method grants no capture/signing authority and never revives its window.
func (p *ObservedOriginalSigningDependency) Recheck(ctx context.Context, binding Binding, now time.Time) error {
	if p == nil || p.origin != p || p.record == nil || p.observer == nil || !hashPattern.MatchString(p.metadataSHA256) || !sameContext(ctx, p.ctx) || ctx.Err() != nil || binding != p.record.record.Binding || p.record.pin.RecordSHA256 != digest(p.record.raw) || now.IsZero() || now.Before(p.observed) || now.Sub(p.observed) > 10*time.Second || !now.Before(p.until) {
		return ErrOwner
	}
	return nil
}

func (p *ObservedOriginalSigningDependency) ValidUntil(ctx context.Context) (time.Time, error) {
	if p == nil || p.record == nil || p.Recheck(ctx, p.record.record.Binding, time.Now().UTC()) != nil {
		return time.Time{}, ErrOwner
	}
	return p.until, nil
}
