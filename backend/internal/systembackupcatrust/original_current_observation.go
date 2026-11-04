package systembackupcatrust

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"time"
)

// Only actual Prepare (real pinned-IP TLS, verified hostname/CA and original
// descriptor) can construct this observation. No callback/success constructor.
type OriginalCurrentObservation struct {
	started time.Time
	ctx     context.Context
	origin  *OriginalCurrentObservation
	native  *check
	proof   string
}

func (*OriginalCurrentObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (v *Validator) ObserveOriginalCurrent(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (*OriginalCurrentObservation, error) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	raw, err := v.Prepare(ctx, g, c)
	if err != nil {
		return nil, err
	}
	native, ok := raw.(*check)
	if !ok || native == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	proof, err := v.BindingSHA256()
	if err != nil {
		return nil, err
	}
	o := &OriginalCurrentObservation{ctx: ctx, native: native, proof: proof, started: started}
	o.origin = o
	return o, nil
}
func (o *OriginalCurrentObservation) Facts(ctx context.Context) (string, time.Time, time.Time, error) {
	if o == nil || o.origin != o || o.native == nil || !sameCandidateCAContext(ctx, o.ctx) || ctx.Err() != nil || !time.Now().Before(o.native.expiresAt) {
		return "", time.Time{}, time.Time{}, sec.ErrRegistrationUnavailable
	}
	return o.proof, o.started, o.native.expiresAt, nil
}
