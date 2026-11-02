package install

import (
	"context"
	"path/filepath"
	"sync/atomic"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type FunctionalClassificationFiles struct{ RecordFile, RecordSHA256, SignatureFile, RegistryDirectory string }

// One concrete owner of TWO real classification registries. The capture
// consumer MUST be the same enrolled source used by the concrete terminal.
// Its current SQL head/grant is a revocation anchor ONLY. The distinct signed
// classification protocol supplies classification authority, never provider or
// key permission. The primary capture owner still needs its real physical probe.
type FunctionalClassificationOwner struct {
	capture *CaptureSigningConsumer
	files   FunctionalClassificationFiles
}

func NewFunctionalClassificationOwner(capture *CaptureSigningConsumer, files FunctionalClassificationFiles) (*FunctionalClassificationOwner, error) {
	if capture == nil || !digestPattern.MatchString(files.RecordSHA256) {
		return nil, ErrInstall
	}
	for _, path := range []string{files.RecordFile, files.SignatureFile, files.RegistryDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInstall
		}
	}
	return &FunctionalClassificationOwner{capture: capture, files: files}, nil
}
func (*FunctionalClassificationOwner) TerminalKeys() []string {
	return []string{"registry:failure_domains", "registry:disaster_identity_mapping"}
}
func (*FunctionalClassificationOwner) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (a *FunctionalClassificationOwner) BindingSHA256() (string, error) {
	if a == nil || a.capture == nil {
		return "", ErrInstall
	}
	raw, err := canonical(struct {
		Version, ConsumerFile, ConsumerPin string
		Files                              FunctionalClassificationFiles
	}{FunctionalClassificationVersion, a.capture.sourceFile, a.capture.sourcePinFile, a.files})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

// Candidate-only. Legacy config-order authorization cannot establish the
// reviewed original current-source prefix; it is deliberately refused.
func (*FunctionalClassificationOwner) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrInstall
}

func (a *FunctionalClassificationOwner) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if a == nil || a.capture == nil {
		return nil, ErrInstall
	}
	source, err := a.capture.load(ctx)
	if err != nil {
		return nil, err
	}
	defer source.request.observer.Close()
	if grant != source.request.grant || config.SHA256() != source.request.config.SHA256() {
		return nil, ErrInstall
	}
	raw, err := ReadPrivateFile(a.files.RecordFile, 262144)
	if err != nil || hash(raw) != a.files.RecordSHA256 {
		return nil, ErrInstall
	}
	signature, err := ReadPrivateFile(a.files.SignatureFile, 64)
	if err != nil {
		return nil, ErrInstall
	}
	locatorRaw, err := ReadPrivateFile(a.capture.sourceFile, 262144)
	var locator CaptureConsumerFiles
	if err != nil || decodeExact(locatorRaw, &locator) != nil {
		return nil, ErrInstall
	}
	// Authenticate this particular reread against the already loaded original
	// independent pin. A transient locator/public-key substitution followed by
	// restoring old files must not choose the classification verification key.
	locatorPinned := false
	for _, pinned := range source.files {
		if pinned.path == a.capture.sourceFile && pinned.sha == hash(locatorRaw) {
			locatorPinned = true
		}
	}
	if !locatorPinned {
		return nil, ErrInstall
	}
	public, err := ReadPrivateFile(locator.IssuerPublicFile, 32)
	if err != nil || hash(public) != locator.IssuerPublicSHA256 {
		return nil, ErrInstall
	}
	classified, err := verifyFunctionalClassification(raw, signature, public)
	if err != nil {
		return nil, ErrInstall
	}
	ownerRaw, err := ReadPrivateFile(locator.RecordFile, 262144)
	var captureRecord owner.Record
	if err != nil || decodeExact(ownerRaw, &captureRecord) != nil || classified.CaptureRecordSHA256 != hash(ownerRaw) || classified.PlanSHA256 != locator.PlanSHA256 || classified.Target != captureRecord.Target || classified.Actor != captureRecord.Actor || !classified.NotBefore.Equal(captureRecord.NotBefore) || !classified.Until.Equal(captureRecord.Until) || !functionalSelectionMatches(captureRecord, classified.Selection) {
		return nil, ErrInstall
	}
	enrolRaw, err := ReadPrivateFile(locator.EnrollmentPinFile, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	enrol, err := DecodeEnrollmentPin(enrolRaw, locator.EnrollmentPinSHA256)
	if err != nil || enrol != classified.Enrollment {
		return nil, ErrInstall
	}
	failure, mapping, err := classificationPins(config)
	if err != nil || classified.FailureDomains != failure || classified.DisasterMapping != mapping {
		return nil, ErrInstall
	}
	pinRaw, err := ReadPrivateFile(locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if err != nil || hash(pinRaw) != locator.TrustPinSHA256 || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(ownerRaw) {
		return nil, ErrInstall
	}
	identityOnly, err := owner.NewCaptureSigningIdentityOnlyValidator(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if err != nil {
		return nil, ErrInstall
	}
	prepared, err := identityOnly.PrepareCandidateAttempt(ctx, grant, config, classified.Selection)
	if err != nil {
		return nil, ErrInstall
	}
	check := &functionalClassificationCheck{ctx: ctx, source: source, classified: classified, config: source.request.config, prepared: prepared, files: []consumerPinnedFile{{a.files.RecordFile, a.files.RecordSHA256, 262144}, {a.files.SignatureFile, hash(signature), 64}}, registryDirectory: a.files.RegistryDirectory}
	check.origin = check
	if check.local(ctx) != nil {
		return nil, ErrInstall
	}
	return check, nil
}

type functionalClassificationCheck struct {
	origin            *functionalClassificationCheck
	ctx               context.Context
	source            *consumerCaptureState
	classified        FunctionalClassificationRecord
	config            sec.BootstrapConfig
	prepared          *owner.PreparedCaptureSigning
	guard             *owner.OwnerGuard
	tx                pd.BootstrapSQL
	files             []consumerPinnedFile
	registryDirectory string
	locked            bool
	failed            atomic.Bool
}

func (c *functionalClassificationCheck) fail() error {
	if c != nil {
		c.failed.Store(true)
		if c.origin != nil {
			c.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (c *functionalClassificationCheck) local(ctx context.Context) error {
	if c == nil || c.origin != c || c.failed.Load() || c.source == nil || !consumerSameContext(ctx, c.ctx) || ctx.Err() != nil || c.source.current(ctx) != nil {
		return c.fail()
	}
	for _, pin := range c.files {
		raw, err := ReadPrivateFile(pin.path, pin.limit)
		if err != nil || hash(raw) != pin.sha {
			return c.fail()
		}
	}
	files := sec.RegistrationFiles{RegistryDirectory: c.registryDirectory}
	failure, err := files.RegistryBytes(c.classified.FailureDomains.Kind, c.classified.FailureDomains.Version, c.classified.FailureDomains.SHA256)
	if err != nil {
		return c.fail()
	}
	mapping, err := files.RegistryBytes(c.classified.DisasterMapping.Kind, c.classified.DisasterMapping.Version, c.classified.DisasterMapping.SHA256)
	if err != nil {
		return c.fail()
	}
	d := FunctionalClassificationDefinition{SchemaVersion: c.classified.SchemaVersion, Profile: c.classified.Profile, TaskPurpose: c.classified.TaskPurpose, TargetClass: c.classified.TargetClass, TargetFailureDomain: c.classified.TargetFailureDomain, RecoveryEvidenceStatus: c.classified.RecoveryEvidenceStatus, FailureRegistrySHA256: c.classified.FailureDomains.SHA256, MappingRegistrySHA256: c.classified.DisasterMapping.SHA256, SourceDomains: c.classified.SourceDomains, TargetRisks: c.classified.TargetRisks}
	if validateFunctionalRegistries(d, c.classified.Target.InstallationID, c.config, failure, mapping) != nil {
		return c.fail()
	}
	return nil
}
func (c *functionalClassificationCheck) current(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil || !pd.SameBootstrapTransaction(c.tx, view) || c.local(ctx) != nil {
		return c.fail()
	}
	now, err := view.SampleTime(ctx)
	if err != nil || now.Before(c.classified.NotBefore) || !now.Before(c.classified.Until) {
		return c.fail()
	}
	return nil
}
func (c *functionalClassificationCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if c == nil || c.guard != nil || c.prepared == nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, c.fail()
	}
	c.tx = tx
	if c.current(ctx, tx) != nil {
		return nil, c.fail()
	}
	var err error
	c.guard, err = c.prepared.AuthorizeCandidate(ctx, tx)
	if err != nil {
		return nil, c.fail()
	}
	end, valid := terminalMinimum(c.classified.Until, c.guard.IdentityDeadline())
	if !valid {
		return nil, c.fail()
	}
	stamp := terminalTimestamp(end)
	return &stamp, nil
}
func (c *functionalClassificationCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil || c.guard == nil || c.current(ctx, view) != nil || c.guard.RecheckCandidateIdentity(ctx, view) != nil {
		return c.fail()
	}
	return c.current(ctx, view)
}
func (c *functionalClassificationCheck) DependencyDeadline() *pd.Timestamp {
	if c == nil || c.origin != c || c.failed.Load() || c.guard == nil {
		return nil
	}
	end, valid := terminalMinimum(c.classified.Until, c.guard.IdentityDeadline())
	if !valid {
		return nil
	}
	stamp := terminalTimestamp(end)
	return &stamp
}
func (c *functionalClassificationCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if c == nil || c.locked || c.RecheckIdentity(ctx, tx) != nil {
		return c.fail()
	}
	c.locked = true
	return nil
}
func (c *functionalClassificationCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil || !c.locked {
		return c.fail()
	}
	return c.RecheckIdentity(ctx, view)
}

// Both keys share one prepared object. No key/provider/cross-resource owner is
// filled, and an already selected classification or mismatched capture source
// cannot be silently overwritten by this explicit composition helper.
func LinkFunctionalClassificationOwners(base sec.BootstrapOwnerAdapters, capture *CaptureSigningConsumer, files FunctionalClassificationFiles) (sec.BootstrapOwnerAdapters, *FunctionalClassificationOwner, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *FunctionalClassificationOwner, error) {
		return sec.BootstrapOwnerAdapters{}, nil, ErrInstall
	}
	if base.Candidates != nil || capture == nil {
		return bad()
	}
	if old, exists := base.References["capture_signing"]; exists && old != capture {
		return bad()
	}
	for _, key := range []string{"failure_domains", "disaster_identity_mapping"} {
		if _, exists := base.Registries[key]; exists {
			return bad()
		}
	}
	classified, err := NewFunctionalClassificationOwner(capture, files)
	if err != nil {
		return bad()
	}
	out := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{}, References: map[string]sec.BootstrapResourceValidator{}, CrossResources: base.CrossResources, Candidates: base.Candidates, KEK: base.KEK}
	for key, source := range base.Registries {
		out.Registries[key] = source
	}
	for key, source := range base.References {
		out.References[key] = source
	}
	out.Registries["failure_domains"], out.Registries["disaster_identity_mapping"] = classified, classified
	return out, classified, nil
}

var _ sec.BootstrapTerminalResource = (*FunctionalClassificationOwner)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*functionalClassificationCheck)(nil)

// WithFunctionalClassification is the preferred concrete D integration seam.
// It guarantees that both new registry owners use this terminal's EXACT
// enrolled capture source/revocation anchor and preserves every other actual
// resource instance. The returned terminal still requires all thirty owners.
func (a *BootstrapTerminalOriginal) WithFunctionalClassification(files FunctionalClassificationFiles) (*BootstrapTerminalOriginal, *FunctionalClassificationOwner, error) {
	if a == nil || a.capture == nil {
		return nil, nil, ErrInstall
	}
	for _, key := range []string{"registry:failure_domains", "registry:disaster_identity_mapping"} {
		if _, exists := a.resources[key]; exists {
			return nil, nil, ErrInstall
		}
	}
	classified, err := NewFunctionalClassificationOwner(a.capture, files)
	if err != nil {
		return nil, nil, err
	}
	resources := make(map[string]sec.BootstrapTerminalResource, len(a.resources)+2)
	for key, value := range a.resources {
		resources[key] = value
	}
	resources["registry:failure_domains"], resources["registry:disaster_identity_mapping"] = classified, classified
	terminal, err := NewBootstrapTerminalOriginal(a.capture, a.files, resources)
	if err != nil {
		return nil, nil, err
	}
	return terminal, classified, nil
}
