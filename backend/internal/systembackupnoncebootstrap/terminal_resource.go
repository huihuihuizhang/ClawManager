package systembackupnoncebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func (*Validator) TerminalKeys() []string { return []string{"reference:nonce_hmac"} }

func (v *Validator) BindingSHA256() (string, error) {
	if v == nil {
		return "", sec.ErrRegistrationUnavailable
	}
	type keyWire Key
	keys := make([]keyWire, len(v.binding.Keys))
	for n, key := range v.binding.Keys {
		keys[n] = keyWire(key)
	}
	raw, e := json.Marshal(struct {
		Version, InstallationID, ServerUUID, Database, ConfigSHA256 string
		NotBefore, ExpiresAt                                        any
		Keys                                                        []keyWire
	}{"bootstrap-original-nonce-binding.v1", v.binding.InstallationID, v.binding.ServerUUID, v.binding.Database, v.binding.ConfigSHA256, v.binding.NotBefore, v.binding.ExpiresAt, keys})
	if e != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func (v *Validator) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	prepared, e := v.PrepareCandidateAttempt(ctx, grant, config)
	if e != nil {
		return nil, e
	}
	check := &terminalNonce{prepared: prepared, ctx: ctx, start: v.binding.NotBefore, until: v.binding.ExpiresAt}
	check.origin = check
	return check, nil
}

type terminalNonce struct {
	origin       *terminalNonce
	prepared     *PreparedCandidateNonce
	check        *CandidateNonceCheck
	failed       bool
	ctx          context.Context
	start, until time.Time
	tx           pd.BootstrapSQL
}

func (v *terminalNonce) identity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if v == nil {
		return sec.ErrRegistrationUnavailable
	}
	if v.origin != v || v.failed || ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != v.ctx || ctx.Err() != nil || !pd.SameBootstrapTransaction(v.tx, view) {
		if v.origin != nil {
			v.origin.failed = true
		}
		v.failed = true
		return sec.ErrRegistrationUnavailable
	}
	now, e := view.SampleTime(ctx)
	if e != nil || now.Before(v.start) || !now.Before(v.until) {
		v.failed = true
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (v *terminalNonce) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if v == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	if v.tx != nil && !pd.SameBootstrapTransaction(v.tx, tx) {
		v.failed = true
		return nil, sec.ErrRegistrationUnavailable
	}
	v.tx = tx
	if e := v.identity(ctx, tx); e != nil {
		return nil, e
	}
	end := pd.Timestamp(v.until.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &end, nil
}
func (v *terminalNonce) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	return v.identity(ctx, view)
}
func (v *terminalNonce) DependencyDeadline() *pd.Timestamp {
	if v == nil || v.failed || v.prepared == nil {
		return nil
	}
	return v.prepared.DependencyDeadline()
}
func (v *terminalNonce) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if v == nil {
		return sec.ErrRegistrationUnavailable
	}
	if v.failed || v.prepared == nil || v.check != nil || v.identity(ctx, tx) != nil {
		v.failed = true
		return sec.ErrRegistrationUnavailable
	}
	var e error
	v.check, e = v.prepared.LockReferences(ctx, tx)
	if e != nil {
		v.failed = true
	}
	return e
}
func (v *terminalNonce) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if v == nil {
		return sec.ErrRegistrationUnavailable
	}
	if v.origin != v || v.failed || v.check == nil || v.identity(ctx, view) != nil {
		if v.origin != nil {
			v.origin.failed = true
		}
		v.failed = true
		return sec.ErrRegistrationUnavailable
	}
	if e := v.check.Recheck(ctx, view); e != nil {
		v.failed = true
		return e
	}
	return nil
}

var _ sec.BootstrapTerminalResource = (*Validator)(nil)
