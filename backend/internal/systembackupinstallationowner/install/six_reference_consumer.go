package install

import (
	"context"
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func (p *OriginalSixReference) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if p == nil || p.capture == nil {
		return nil, ErrInstall
	}
	source, e := p.capture.load(ctx)
	if e != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.grant != grant || source.request.config.SHA256() != config.SHA256() {
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
	actualRef, ae := sixConfigReferences(config)
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
	identity, e := owner.NewCaptureSigningIdentityOnlyValidator(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if e != nil {
		return nil, ErrInstall
	}
	prepared, e := identity.PrepareCandidateAttempt(ctx, grant, config, r.Selection)
	if e != nil {
		return nil, ErrInstall
	}
	check := &sixReferenceCheck{ctx: ctx, source: source, record: r, prepared: prepared, files: []consumerPinnedFile{{p.files.RecordFile, p.files.RecordSHA256, 262144}, {p.files.SignatureFile, hash(signature), ed25519.SignatureSize}}}
	check.origin = check
	// Native reads occur only here, before controlled SQL. An unavailable or
	// changed transport retains current identity solely for exact history; it
	// cannot supply a fresh dependency deadline or LockReferences success.
	client, e := p.capture.OpenTerminalKubernetes(ctx)
	if e == nil {
		native, err := observeSixReference(ctx, client, r.Target, r.Definition)
		if err == nil && native.identity == r.NativeIdentitySHA256 {
			check.native = native
		}
	}
	if check.local(ctx) != nil {
		return nil, ErrInstall
	}
	return check, nil
}

type sixReferenceCheck struct {
	mu       sync.Mutex
	origin   *sixReferenceCheck
	failed   atomic.Bool
	ctx      context.Context
	source   *consumerCaptureState
	record   sixReferenceRecord
	prepared *owner.PreparedCaptureSigning
	guard    *owner.OwnerGuard
	tx       pd.BootstrapSQL
	files    []consumerPinnedFile
	native   sixReferenceNative
	locked   bool
}

func (*sixReferenceCheck) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (c *sixReferenceCheck) fail() error {
	if c != nil {
		c.failed.Store(true)
		if c.origin != nil {
			c.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (c *sixReferenceCheck) local(ctx context.Context) error {
	if c == nil || c.origin != c || c.failed.Load() || c.source == nil || !consumerSameContext(ctx, c.ctx) || ctx.Err() != nil || c.source.current(ctx) != nil {
		return c.fail()
	}
	for _, pin := range c.files {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			return c.fail()
		}
	}
	return nil
}
func (c *sixReferenceCheck) current(ctx context.Context, view pd.BootstrapReadSQL) error {
	if !pd.SameBootstrapTransaction(c.tx, view) || c.local(ctx) != nil {
		return c.fail()
	}
	now, e := view.SampleTime(ctx)
	if e != nil || now.Before(c.record.NotBefore) || !now.Before(c.record.Until) {
		return c.fail()
	}
	return nil
}
func (c *sixReferenceCheck) identity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c.guard == nil || c.current(ctx, view) != nil || c.guard.RecheckCandidateIdentity(ctx, view) != nil {
		return c.fail()
	}
	return c.current(ctx, view)
}
func (c *sixReferenceCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if c == nil {
		return nil, ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.guard != nil || c.prepared == nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, c.fail()
	}
	c.tx = tx
	if c.current(ctx, tx) != nil {
		return nil, c.fail()
	}
	var e error
	c.guard, e = c.prepared.AuthorizeCandidate(ctx, tx)
	if e != nil {
		return nil, c.fail()
	}
	end, ok := terminalMinimum(c.record.Until, c.guard.IdentityDeadline())
	if !ok {
		return nil, c.fail()
	}
	stamp := terminalTimestamp(end)
	return &stamp, nil
}
func (c *sixReferenceCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identity(ctx, view)
}
func (c *sixReferenceCheck) DependencyDeadline() *pd.Timestamp {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.origin != c {
		_ = c.fail()
		return nil
	}
	if c.failed.Load() || c.guard == nil || c.native.until.IsZero() {
		return nil
	}
	end, ok := terminalMinimum(c.record.Until, c.guard.IdentityDeadline())
	if !ok {
		return nil
	}
	if c.native.until.Before(end) {
		end = c.native.until
	}
	stamp := terminalTimestamp(end)
	return &stamp
}
func (c *sixReferenceCheck) fresh(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c.identity(ctx, view) != nil || c.native.until.IsZero() || c.native.identity != c.record.NativeIdentitySHA256 {
		return c.fail()
	}
	// Exact local source pins only under the original SQL prefix, never TLS/API.
	d := c.record.Definition
	for _, pin := range []BootstrapSourceFilePin{d.Deployment, d.VaultCA} {
		raw, e := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if e != nil {
			return c.fail()
		}
	}
	if recheckSixReferenceFiles(d) != nil {
		return c.fail()
	}
	now, e := view.SampleTime(ctx)
	if e != nil || now.Before(c.native.started) || !now.Before(c.native.until) || ctx.Err() != nil || !time.Now().Before(c.native.until) {
		return c.fail()
	}
	return nil
}
func (c *sixReferenceCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locked || c.fresh(ctx, tx) != nil {
		return c.fail()
	}
	c.locked = true
	return nil
}
func (c *sixReferenceCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.locked {
		return c.fail()
	}
	return c.fresh(ctx, view)
}

var _ sec.BootstrapTerminalResource = (*OriginalSixReference)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*sixReferenceCheck)(nil)

// Concrete linkage only. No source is observed or counted as prepared here.
func LinkOriginalSixReferenceOwners(base sec.BootstrapOwnerAdapters, capture *CaptureSigningConsumer, files SixReferenceFiles) (sec.BootstrapOwnerAdapters, *OriginalSixReference, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *OriginalSixReference, error) {
		return sec.BootstrapOwnerAdapters{}, nil, ErrInstall
	}
	if capture == nil || base.Candidates != nil {
		return bad()
	}
	if prior, exists := base.References["capture_signing"]; exists && prior != capture {
		return bad()
	}
	for _, purpose := range sixReferencePurposes {
		if _, exists := base.References[purpose]; exists {
			return bad()
		}
	}
	resource, e := NewOriginalSixReference(capture, files)
	if e != nil {
		return bad()
	}
	out := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{}, References: map[string]sec.BootstrapResourceValidator{}, CrossResources: base.CrossResources, KEK: base.KEK}
	for key, prior := range base.Registries {
		out.Registries[key] = prior
	}
	for key, prior := range base.References {
		out.References[key] = prior
	}
	for _, purpose := range sixReferencePurposes {
		out.References[purpose] = resource
	}
	return out, resource, nil
}
