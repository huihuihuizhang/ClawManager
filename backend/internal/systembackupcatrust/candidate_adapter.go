package systembackupcatrust

import (
	"context"
	"reflect"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// PreparedCandidateCA is an original material observation, never independent
// deployment/bootstrap authority. The original trusted authority remains
// responsible for authenticating the complete deployment/purpose mapping.
type PreparedCandidateCA struct{ state *candidateCAState }
type candidateCAState struct {
	ctx               context.Context
	binding           Binding
	observed, expires time.Time
	ready             bool
	used              atomic.Bool
}
type CandidateCACheck struct {
	state *candidateCAState
	tx    pd.BootstrapSQL
}

func (PreparedCandidateCA) String() string               { return "PreparedCandidateCA" }
func (PreparedCandidateCA) GoString() string             { return "PreparedCandidateCA" }
func (PreparedCandidateCA) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*PreparedCandidateCA) UnmarshalJSON([]byte) error  { return sec.ErrRegistrationUnavailable }
func (CandidateCACheck) String() string                  { return "CandidateCACheck" }
func (CandidateCACheck) GoString() string                { return "CandidateCACheck" }
func (CandidateCACheck) MarshalJSON() ([]byte, error)    { return nil, sec.ErrRegistrationUnavailable }
func (*CandidateCACheck) UnmarshalJSON([]byte) error     { return sec.ErrRegistrationUnavailable }

func sameCandidateCAContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.Comparable() && y.Comparable() && !(x.Kind() == reflect.Pointer && x.IsNil()) && !(y.Kind() == reflect.Pointer && y.IsNil()) && a == b
}

// PrepareCandidateAttempt retains the existing real TLS and exact source-file
// checks outside locks. Physical preparation failures remain closed until L3
// decides historical read versus new consumption; input/ctx errors fail now.
func (v *Validator) PrepareCandidateAttempt(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (*PreparedCandidateCA, error) {
	if v == nil || v.now == nil || !sameCandidateCAContext(ctx, ctx) || ctx.Err() != nil || g.InstallationID != v.binding.InstallationID || g.ServerUUID != v.binding.ServerUUID || g.Database != v.binding.Database || g.ConfigSHA256 != v.binding.ConfigSHA256 || c.SHA256() != v.binding.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	owned, err := sec.DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil || owned.SHA256() != g.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := &candidateCAState{ctx: ctx}
	legacy, err := v.Prepare(ctx, g, owned)
	if ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	if err != nil {
		return &PreparedCandidateCA{s}, nil
	}
	checked, ok := legacy.(*check)
	if !ok || checked == nil || checked.validator == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s.binding, s.observed, s.expires = checked.validator.binding, checked.observedAt, checked.expiresAt
	s.ready = true
	return &PreparedCandidateCA{s}, nil
}

// DependencyDeadline must be intersected by the original resource authority
// into admission.DependencyExpiresAt. D keeps it through the last clock sample
// AFTER every callback/write. Nil is a failed observation, not unlimited life.
// Ceil preserves strict raw-expiry semantics for UTC(6) SQL samples.
func (p *PreparedCandidateCA) DependencyDeadline() *pd.Timestamp {
	if p == nil || p.state == nil || !p.state.ready {
		return nil
	}
	t := p.state.expires.UTC()
	if rem := t.Nanosecond() % 1000; rem != 0 {
		t = t.Add(time.Duration(1000-rem) * time.Nanosecond)
	}
	stamp := pd.Timestamp(t.Format("2006-01-02T15:04:05.000000Z"))
	if _, err := stamp.Time(); err != nil {
		return nil
	}
	return &stamp
}
func candidateCATime(s *candidateCAState, now time.Time) bool {
	_, offset := now.Zone()
	return s != nil && s.ready && now.Year() >= 1000 && now.Year() <= 9999 && offset == 0 && now.Nanosecond()%1000 == 0 && !now.Before(s.binding.NotBefore) && !now.Before(s.observed) && now.Before(s.expires) && now.Before(s.binding.ExpiresAt)
}

// CheckCandidate belongs to fresh consumption only, before reservation/audit.
// Copies share one-shot use. No failed preparation can reach SQL or source I/O.
func (p *PreparedCandidateCA) CheckCandidate(ctx context.Context, tx pd.BootstrapSQL) (*CandidateCACheck, error) {
	if p == nil || p.state == nil || !p.state.used.CompareAndSwap(false, true) {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := p.state
	if !s.ready || p.DependencyDeadline() == nil || !sameCandidateCAContext(ctx, s.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, sec.ErrRegistrationUnavailable
	}
	c := &CandidateCACheck{state: s, tx: tx}
	if err := c.Recheck(ctx, tx); err != nil {
		return nil, err
	}
	return c, nil
}

// Recheck is the initial resource check and bounded pre-FinalGuard callback.
// Final callbacks use D's private read/time view after public writes close.
// It preserves
// legacy late removed/changed descriptor and CA refusal using the SAME exact
// concrete files() reader. It never repeats TLS, calls a wall clock/provider,
// starts a transaction or acquires business locks. D closes the private read
// view next and runs fixed SQL-only FinalGuard; no file/callback follows it.
func (c *CandidateCACheck) Recheck(ctx context.Context, tx pd.BootstrapReadSQL) error {
	if c == nil || c.state == nil || !sameCandidateCAContext(ctx, c.state.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(c.tx, tx) {
		return sec.ErrRegistrationUnavailable
	}
	start, err := tx.SampleTime(ctx)
	if err != nil || !candidateCATime(c.state, start) {
		return sec.ErrRegistrationUnavailable
	}
	reader := Validator{binding: c.state.binding} // No retained wall-clock callback.
	if _, _, err = reader.files(); err != nil {
		return sec.ErrRegistrationUnavailable
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != c.state.binding.ServerUUID || database != c.state.binding.Database {
		return sec.ErrRegistrationUnavailable
	}
	end, err := tx.SampleTime(ctx)
	if err != nil || ctx.Err() != nil || end.Before(start) || !candidateCATime(c.state, end) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
