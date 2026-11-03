package install

import (
	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"
)

// One concrete shared owner for the six unchanged references. The explicit
// mutation path observes native providers itself, without a bootstrap check or
// mutation write authority derived from OfflineBootstrapGrant.
type SixReferenceEnableOnlyMutation struct {
	owner   *OriginalSixReference
	mu      sync.Mutex
	pending map[context.Context]*sixMutationObservation
}

func NewSixReferenceEnableOnlyMutation(p *OriginalSixReference) (*SixReferenceEnableOnlyMutation, error) {
	if p == nil || p.capture == nil {
		return nil, ErrInstall
	}
	return &SixReferenceEnableOnlyMutation{owner: p, pending: map[context.Context]*sixMutationObservation{}}, nil
}
func sixValueReferences(c sec.ConfigValues) ([]sec.BootstrapSecretRef, error) {
	refs := []sec.BootstrapSecretRef{}
	for _, ref := range c.References() {
		for _, purpose := range sixReferencePurposes {
			if ref.Purpose == purpose {
				refs = append(refs, ref)
			}
		}
	}
	if !sameSixReferences(refs, refs) {
		return nil, ErrInstall
	}
	return refs, nil
}
func (v *SixReferenceEnableOnlyMutation) Prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if v == nil || v.owner == nil || !consumerSameContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil {
		return nil, ErrInstall
	}
	slot := in.Slot()
	valid := false
	for _, purpose := range sixReferencePurposes {
		if slot == "reference:"+purpose {
			valid = true
		}
	}
	if !valid {
		return nil, ErrInstall
	}
	current, proposed := in.Configs()
	v.mu.Lock()
	defer v.mu.Unlock()
	if o := v.pending[ctx]; o != nil {
		if o.current != current.SHA256() || o.proposed != proposed.SHA256() || o.actor != in.Actor() || o.slots[slot] || o.failed.Load() {
			o.failed.Store(true)
			return nil, ErrInstall
		}
		o.slots[slot] = true
		return o, nil
	}
	if len(v.pending) >= 64 {
		return nil, ErrInstall
	}
	o, e := v.prepare(ctx, in)
	if e != nil {
		return nil, e
	}
	o.slots[slot] = true
	v.pending[ctx] = o
	context.AfterFunc(ctx, func() { o.failed.Store(true); v.mu.Lock(); delete(v.pending, ctx); v.mu.Unlock() })
	return o, nil
}
func (v *SixReferenceEnableOnlyMutation) prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (*sixMutationObservation, error) {
	p := v.owner
	current, proposed := in.Configs()
	source, e := p.capture.load(ctx)
	if e != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.config.SHA256() != current.SHA256() {
		return nil, ErrInstall
	}
	locator, _, public, e := readBootstrapOriginalPublicSource(ctx, p.capture, source)
	if e != nil {
		return nil, ErrInstall
	}
	raw, e := ReadPrivateFile(p.files.RecordFile, 262144)
	if e != nil || hash(raw) != p.files.RecordSHA256 {
		return nil, ErrInstall
	}
	signature, e := ReadPrivateFile(p.files.SignatureFile, ed25519.SignatureSize)
	var r sixReferenceRecord
	if e != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, append([]byte(sixReferenceDomain), raw...), signature) || decodeExact(raw, &r) != nil || r.Version != SixReferenceVersion || validateSixReference(r.Definition) != nil || r.NotBefore.IsZero() || !r.NotBefore.Before(r.Until) || !digestPattern.MatchString(r.NativeIdentitySHA256) {
		return nil, ErrInstall
	}
	definitionRaw, e := canonical(r.Definition)
	ref, re := SixReferenceIdentities(definitionRaw, r.DefinitionSHA256)
	actualRef, ae := sixValueReferences(current)
	if e != nil || re != nil || ae != nil || !sameSixReferences(ref, r.References) || !sameSixReferences(ref, actualRef) {
		return nil, ErrInstall
	}
	captureRaw, e := ReadPrivateFile(locator.RecordFile, 262144)
	var capture owner.Record
	if e != nil || decodeExact(captureRaw, &capture) != nil || r.CaptureRecordSHA256 != hash(captureRaw) || r.PlanSHA256 != locator.PlanSHA256 || r.Target != capture.Target || r.Actor != capture.Actor || !functionalSelectionMatches(capture, r.Selection) || r.NotBefore.Before(capture.NotBefore) || r.Until.After(capture.Until) || r.NotBefore.Before(r.Definition.NotBefore) || r.Until.After(r.Definition.Until) {
		return nil, ErrInstall
	}
	enrollmentRaw, e := ReadPrivateFile(locator.EnrollmentPinFile, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	enrollment, e := DecodeEnrollmentPin(enrollmentRaw, locator.EnrollmentPinSHA256)
	if e != nil || enrollment != r.Enrollment {
		return nil, ErrInstall
	}
	pinRaw, e := ReadPrivateFile(locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if e != nil || hash(pinRaw) != locator.TrustPinSHA256 || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(captureRaw) {
		return nil, ErrInstall
	}

	identity, e := owner.NewReferenceCurrentIdentity(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if e != nil {
		return nil, ErrInstall
	}
	prepared, e := identity.PrepareEnableOnly(ctx, in)
	if e != nil {
		return nil, ErrInstall
	}
	client, e := p.capture.OpenTerminalKubernetes(ctx)
	if e != nil {
		return nil, ErrInstall
	}
	native, e := observeSixReference(ctx, client, r.Target, r.Definition)
	if e != nil || native.identity != r.NativeIdentitySHA256 {
		return nil, ErrInstall
	}
	until := native.until
	if r.Until.Before(until) {
		until = r.Until
	}
	if prepared.ValidUntil().Before(until) {
		until = prepared.ValidUntil()
	}
	o := &sixMutationObservation{ctx: ctx, source: source, record: r, identity: prepared, native: native, until: until, current: current.SHA256(), proposed: proposed.SHA256(), actor: in.Actor(), slots: map[string]bool{}, files: []consumerPinnedFile{{p.files.RecordFile, p.files.RecordSHA256, 262144}, {p.files.SignatureFile, hash(signature), ed25519.SignatureSize}}}
	o.origin = o
	if o.local(ctx) != nil || !time.Now().Before(until) {
		return nil, ErrInstall
	}
	return o, nil
}

type sixMutationObservation struct {
	mu                sync.Mutex
	origin            *sixMutationObservation
	failed            atomic.Bool
	ctx               context.Context
	source            *consumerCaptureState
	record            sixReferenceRecord
	identity          *owner.PreparedReferenceCurrentIdentity
	native            sixReferenceNative
	until             time.Time
	current, proposed string
	actor             sec.RegistrationActor
	slots             map[string]bool
	files             []consumerPinnedFile
}

func (*sixMutationObservation) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (o *sixMutationObservation) Risk() sec.ConfigMutationRisk {
	return sec.ConfigMutationRisk{SecurityBoundary: true}
}
func (o *sixMutationObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}
func (o *sixMutationObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (o *sixMutationObservation) local(ctx context.Context) error {
	if o == nil || o.origin != o || o.failed.Load() || !consumerSameContext(ctx, o.ctx) || ctx.Err() != nil || o.source == nil || o.source.current(ctx) != nil {
		return o.fail()
	}
	for _, pin := range o.files {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			return o.fail()
		}
	}
	if recheckSixReferenceFiles(o.record.Definition) != nil {
		return o.fail()
	}
	return nil
}
func (o *sixMutationObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return ErrInstall
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.local(ctx) != nil || now.Before(o.native.started) || !now.Before(o.until) || !time.Now().Before(o.until) || o.identity.Recheck(ctx, tx, now) != nil {
		return o.fail()
	}
	// The source's final delivered SQL sample is checked against the same fixed
	// original native interval, not just the statement's supplied start time.
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !tail.Before(o.until) || ctx.Err() != nil || o.local(ctx) != nil {
		return o.fail()
	}
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*SixReferenceEnableOnlyMutation)(nil)
var _ sec.ConfigMutationResourceObservation = (*sixMutationObservation)(nil)
