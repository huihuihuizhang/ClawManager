package systembackupbootstrapmaterials

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	registry "clawreef/internal/systembackupbootstrapsecurity"
	ca "clawreef/internal/systembackupcatrust"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	sec "clawreef/internal/systembackupsecurity"
)

// EnableOnlySecurityOwners is a concrete first-enable resource group, separate
// from bootstrap admission. No caller callback, OfflineBootstrapGrant, supplied
// readiness flag or config write authority is accepted. Native source bindings
// must match the complete authenticated original signed composition.
type EnableOnlySecurityOwners struct {
	original           *install.EnableOnlyOriginalMapping
	artifact, evidence *ca.Validator
	nonce              *nonce.Validator
	issuers            *registry.Issuers
	bindings           []install.BootstrapOriginalOwnerBinding
	mu                 sync.Mutex
	pending            map[context.Context]*enableOnlySecurityObservation
}

func NewEnableOnlySecurityOwners(capture *install.CaptureSigningConsumer, files install.BootstrapTerminalFiles, artifact, evidence *ca.Validator, nonces *nonce.Validator, issuers *registry.Issuers) (*EnableOnlySecurityOwners, error) {
	if capture == nil || artifact == nil || evidence == nil || artifact == evidence || nonces == nil || issuers == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	original, e := install.NewEnableOnlyOriginalMapping(capture, files)
	if e != nil {
		return nil, e
	}
	bindings := []install.BootstrapOriginalOwnerBinding{}
	// Concrete types and declared terminal keys prevent relabeling an artifact
	// CA as evidence CA or a different purpose source as nonce/issuer material.
	if !reflect.DeepEqual(artifact.TerminalKeys(), []string{"reference:artifact_ca"}) || !reflect.DeepEqual(evidence.TerminalKeys(), []string{"reference:evidence_ca"}) {
		return nil, sec.ErrRegistrationUnavailable
	}
	for _, source := range []sec.BootstrapTerminalResource{artifact, evidence, nonces, issuers} {
		binding, e := source.BindingSHA256()
		if e != nil {
			return nil, e
		}
		for _, key := range source.TerminalKeys() {
			bindings = append(bindings, install.BootstrapOriginalOwnerBinding{Key: key, SHA256: binding})
		}
	}
	return &EnableOnlySecurityOwners{original: original, artifact: artifact, evidence: evidence, nonce: nonces, issuers: issuers, bindings: bindings, pending: map[context.Context]*enableOnlySecurityObservation{}}, nil
}
func (v *EnableOnlySecurityOwners) References() map[string]sec.ConfigMutationResourceValidator {
	if v == nil {
		return nil
	}
	return map[string]sec.ConfigMutationResourceValidator{"artifact_ca": v, "evidence_ca": v, "nonce_hmac": v}
}
func (v *EnableOnlySecurityOwners) Registries() map[string]sec.ConfigMutationResourceValidator {
	if v == nil {
		return nil
	}
	return map[string]sec.ConfigMutationResourceValidator{"strong_auth_issuers": v, "provider_proof_issuers": v}
}
func securityEnableOnlySlot(slot string) bool {
	switch slot {
	case "reference:artifact_ca", "reference:evidence_ca", "reference:nonce_hmac", "registry:strong_auth_issuers", "registry:provider_proof_issuers":
		return true
	}
	return false
}
func sameSecurityEnableContext(a, b context.Context) bool {
	return a != nil && b != nil && reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

func (v *EnableOnlySecurityOwners) Prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if v == nil || !sameSecurityEnableContext(ctx, ctx) || ctx.Err() != nil || !securityEnableOnlySlot(in.Slot()) || sec.ValidateEnableOnlyConfigMutation(in) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	current, proposed := in.Configs()
	v.mu.Lock()
	defer v.mu.Unlock()
	if prior := v.pending[ctx]; prior != nil {
		if prior.current != current.SHA256() || prior.proposed != proposed.SHA256() || prior.actor != in.Actor() || prior.slots[in.Slot()] || prior.failed.Load() {
			return nil, prior.fail()
		}
		prior.slots[in.Slot()] = true
		return prior, nil
	}
	if len(v.pending) >= 64 {
		return nil, sec.ErrRegistrationUnavailable
	}
	// All five observations belong to this one original request, with the same
	// context and fixed interval. Grouped registry slots do not duplicate work.
	original, e := v.original.PrepareEnableOnly(ctx, in, v.bindings)
	if e != nil {
		return nil, e
	}
	artifact, e := v.artifact.ObserveEnableOnly(ctx, in)
	if e != nil {
		return nil, e
	}
	evidence, e := v.evidence.ObserveEnableOnly(ctx, in)
	if e != nil {
		return nil, e
	}
	nonces, e := v.nonce.ObserveEnableOnly(ctx, in)
	if e != nil {
		return nil, e
	}
	issuers, e := v.issuers.ObserveEnableOnly(ctx, in)
	if e != nil {
		return nil, e
	}
	until := original.ValidUntil()
	for _, end := range []time.Time{artifact.ValidUntil(), evidence.ValidUntil(), nonces.ValidUntil(), issuers.ValidUntil()} {
		if end.IsZero() {
			return nil, sec.ErrRegistrationUnavailable
		}
		if end.Before(until) {
			until = end
		}
	}
	if ctx.Err() != nil || !time.Now().Before(until) {
		return nil, sec.ErrRegistrationUnavailable
	}
	o := &enableOnlySecurityObservation{ctx: ctx, current: current.SHA256(), proposed: proposed.SHA256(), actor: in.Actor(), slots: map[string]bool{in.Slot(): true}, original: original, artifact: artifact, evidence: evidence, nonce: nonces, issuers: issuers, until: until}
	o.origin = o
	v.pending[ctx] = o
	context.AfterFunc(ctx, func() { o.failed.Store(true); v.mu.Lock(); delete(v.pending, ctx); v.mu.Unlock() })
	return o, nil
}

type enableOnlySecurityObservation struct {
	mu                       sync.Mutex
	origin                   *enableOnlySecurityObservation
	failed                   atomic.Bool
	ctx                      context.Context
	current, proposed        string
	actor                    sec.RegistrationActor
	slots                    map[string]bool
	original                 *install.PreparedEnableOnlyOriginalMapping
	artifact, evidence       *ca.EnableOnlyObservation
	nonce                    *nonce.EnableOnlyObservation
	issuers                  *registry.EnableOnlyIssuerObservation
	until, floor, inputFloor time.Time
	tx                       *sql.Tx
}

func (*enableOnlySecurityObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (o *enableOnlySecurityObservation) Risk() sec.ConfigMutationRisk {
	return sec.ConfigMutationRisk{SecurityBoundary: true}
}
func (o *enableOnlySecurityObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}
func (o *enableOnlySecurityObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (o *enableOnlySecurityObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return sec.ErrRegistrationUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.origin != o || o.failed.Load() || !sameSecurityEnableContext(ctx, o.ctx) || ctx.Err() != nil || tx == nil || o.tx != nil && o.tx != tx || now.IsZero() || !o.inputFloor.IsZero() && now.Before(o.inputFloor) || !now.Before(o.until) || !time.Now().Before(o.until) {
		return o.fail()
	}
	if o.original.Recheck(ctx, tx, now) != nil || o.artifact.Recheck(ctx, tx, now) != nil || o.evidence.Recheck(ctx, tx, now) != nil || o.nonce.Recheck(ctx, tx, now) != nil || o.issuers.Recheck(ctx, tx, now) != nil {
		return o.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !tail.Before(o.until) || ctx.Err() != nil || !time.Now().Before(o.until) {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	o.inputFloor = now
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*EnableOnlySecurityOwners)(nil)
var _ sec.ConfigMutationResourceObservation = (*enableOnlySecurityObservation)(nil)
