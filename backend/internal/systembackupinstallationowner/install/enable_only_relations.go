package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	bootstrapsecurity "clawreef/internal/systembackupbootstrapsecurity"
	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

type EnableOnlyRelationFiles struct {
	Classification FunctionalClassificationFiles
	StatusRelay    StatusRelayReferenceFiles
	Terminal       BootstrapTerminalFiles
}

// Five real unchanged first-enable sources. Original signed classifications,
// transport reference and association are provenance, never write permission.
// A's independent current session/RBAC/strong-auth/nonce/KEK service owns writes.
// No BootstrapResourceCheck or BootstrapSQL is created/cast on this route.
type OriginalRelationEnableOnlyMutation struct {
	capture *CaptureSigningConsumer
	files   EnableOnlyRelationFiles
	mu      sync.Mutex
	pending map[context.Context]*enableOnlyRelationObservation
}

var enableOnlyRelationSlots = []string{"registry:failure_domains", "registry:disaster_identity_mapping", "registry:rbac_bindings", "reference:status_relay", "cross_resources"}

func NewOriginalRelationEnableOnlyMutation(capture *CaptureSigningConsumer, files EnableOnlyRelationFiles) (*OriginalRelationEnableOnlyMutation, error) {
	if capture == nil || files.Classification.RegistryDirectory != files.Terminal.RegistryDirectory {
		return nil, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{{files.Classification.RecordFile, files.Classification.RecordSHA256}, {files.StatusRelay.RecordFile, files.StatusRelay.RecordSHA256}, {files.Terminal.MappingFile, files.Terminal.MappingSHA256}} {
		if !bootstrapSourcePinValid(pin) {
			return nil, ErrInstall
		}
	}
	for _, path := range []string{files.Classification.SignatureFile, files.StatusRelay.SignatureFile, files.Terminal.SignatureFile, files.Terminal.RegistryDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInstall
		}
	}
	return &OriginalRelationEnableOnlyMutation{capture: capture, files: files, pending: map[context.Context]*enableOnlyRelationObservation{}}, nil
}
func (*OriginalRelationEnableOnlyMutation) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (r *OriginalRelationEnableOnlyMutation) Registries() map[string]sec.ConfigMutationResourceValidator {
	return map[string]sec.ConfigMutationResourceValidator{"failure_domains": r, "disaster_identity_mapping": r, "rbac_bindings": r}
}
func (r *OriginalRelationEnableOnlyMutation) References() map[string]sec.ConfigMutationResourceValidator {
	return map[string]sec.ConfigMutationResourceValidator{"status_relay": r}
}
func (r *OriginalRelationEnableOnlyMutation) CrossResources() sec.ConfigMutationResourceValidator {
	return r
}
func (r *OriginalRelationEnableOnlyMutation) Prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if r == nil || r.capture == nil || !consumerSameContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil {
		return nil, ErrInstall
	}
	valid := false
	for _, slot := range enableOnlyRelationSlots {
		valid = valid || slot == in.Slot()
	}
	if !valid {
		return nil, ErrInstall
	}
	current, proposed := in.Configs()
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.pending[ctx]; old != nil {
		if old.current != current.SHA256() || old.proposed != proposed.SHA256() || old.actor != in.Actor() || old.slots[in.Slot()] || old.failed.Load() {
			return nil, old.fail()
		}
		old.slots[in.Slot()] = true
		return old, nil
	}
	if len(r.pending) >= 32 {
		return nil, ErrInstall
	}
	check, e := r.prepare(ctx, in)
	if e != nil {
		return nil, e
	}
	check.slots[in.Slot()] = true
	r.pending[ctx] = check
	context.AfterFunc(ctx, func() { check.failed.Store(true); r.mu.Lock(); delete(r.pending, ctx); r.mu.Unlock() })
	return check, nil
}

func (r *OriginalRelationEnableOnlyMutation) prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (*enableOnlyRelationObservation, error) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	deadline := started.Add(15 * time.Second)
	parentEnd, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	if parentEnd.Before(deadline) {
		deadline = parentEnd
	}
	current, proposed := in.Configs()
	source, e := r.capture.load(ctx)
	if e != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.config.SHA256() != current.SHA256() {
		return nil, ErrInstall
	}
	locator, _, public, e := readBootstrapOriginalPublicSource(ctx, r.capture, source)
	if e != nil {
		return nil, ErrInstall
	}
	captureRaw, e := readBootstrapSourceAuthenticated(source, locator.RecordFile, 262144)
	var capture owner.Record
	if e != nil || decodeExact(captureRaw, &capture) != nil {
		return nil, ErrInstall
	}
	pinRaw, e := readBootstrapSourceAuthenticated(source, locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if e != nil || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(captureRaw) {
		return nil, ErrInstall
	}
	identitySource, e := owner.NewReferenceCurrentIdentity(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if e != nil {
		return nil, ErrInstall
	}
	identity, e := identitySource.PrepareEnableOnly(ctx, in)
	if e != nil {
		return nil, ErrInstall
	}

	classRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{r.files.Classification.RecordFile, r.files.Classification.RecordSHA256}, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	classSig, e := ReadPrivateFile(r.files.Classification.SignatureFile, ed25519.SignatureSize)
	if e != nil {
		return nil, ErrInstall
	}
	classification, e := verifyFunctionalClassification(classRaw, classSig, public)
	if e != nil || classification.CaptureRecordSHA256 != hash(captureRaw) || classification.PlanSHA256 != locator.PlanSHA256 || classification.Target != capture.Target || classification.Actor != capture.Actor || !classification.NotBefore.Equal(capture.NotBefore) || !classification.Until.Equal(capture.Until) || !functionalSelectionMatches(capture, classification.Selection) {
		return nil, ErrInstall
	}
	relayRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{r.files.StatusRelay.RecordFile, r.files.StatusRelay.RecordSHA256}, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	relaySig, e := ReadPrivateFile(r.files.StatusRelay.SignatureFile, ed25519.SignatureSize)
	var relay statusRelayReferenceRecord
	if e != nil || !ed25519.Verify(public, append([]byte(statusRelayReferenceDomain), relayRaw...), relaySig) || decodeExact(relayRaw, &relay) != nil || relay.Version != StatusRelayReferenceVersion || relay.CaptureRecordSHA256 != hash(captureRaw) || relay.PlanSHA256 != locator.PlanSHA256 || relay.Target != capture.Target || relay.Actor != capture.Actor || !functionalSelectionMatches(capture, relay.Selection) || relay.NotBefore.Before(capture.NotBefore) || relay.Until.After(capture.Until) {
		return nil, ErrInstall
	}
	definition, e := canonical(relay.Definition)
	ref, re := StatusRelayReferenceIdentity(definition, relay.DefinitionSHA256)
	if e != nil || re != nil || ref != relay.Reference {
		return nil, ErrInstall
	}
	matched := false
	for _, selected := range current.References() {
		if selected.Purpose == "status_relay" {
			matched = selected == ref
		}
	}
	if !matched {
		return nil, ErrInstall
	}
	enrolRaw, e := readBootstrapSourceAuthenticated(source, locator.EnrollmentPinFile, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	enrol, e := DecodeEnrollmentPin(enrolRaw, locator.EnrollmentPinSHA256)
	if e != nil || enrol != classification.Enrollment || enrol != relay.Enrollment {
		return nil, ErrInstall
	}
	mapRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{r.files.Terminal.MappingFile, r.files.Terminal.MappingSHA256}, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	mapSig, e := ReadPrivateFile(r.files.Terminal.SignatureFile, ed25519.SignatureSize)
	if e != nil {
		return nil, ErrInstall
	}
	mapping, e := verifyBootstrapOriginalMapping(mapRaw, mapSig, public)
	if e != nil || mapping.CaptureRecordSHA256 != hash(captureRaw) || mapping.PlanSHA256 != locator.PlanSHA256 || mapping.Target != capture.Target || mapping.Actor != capture.Actor || mapping.SelectionSHA256 != capture.SelectionSHA256 || mapping.Enrollment != enrol || !mapping.NotBefore.Equal(capture.NotBefore) || !mapping.Until.Equal(capture.Until) {
		return nil, ErrInstall
	}
	classOwner, e := NewFunctionalClassificationOwner(r.capture, r.files.Classification)
	if e != nil {
		return nil, ErrInstall
	}
	classBinding, e := classOwner.BindingSHA256()
	if e != nil {
		return nil, ErrInstall
	}
	relayOwner, e := NewOriginalStatusRelayReference(r.capture, r.files.StatusRelay)
	if e != nil {
		return nil, ErrInstall
	}
	relayBinding, e := relayOwner.BindingSHA256()
	if e != nil {
		return nil, ErrInstall
	}
	cross, e := NewOriginalCrossResourceRelations(r.capture)
	if e != nil {
		return nil, ErrInstall
	}
	crossBinding, e := cross.BindingSHA256()
	if e != nil {
		return nil, ErrInstall
	}
	rbacBinding, e := bootstrapsecurity.NewRBAC(r.files.Terminal.RegistryDirectory).BindingSHA256()
	if e != nil {
		return nil, ErrInstall
	}
	bindings := map[string]string{"registry:failure_domains": classBinding, "registry:disaster_identity_mapping": classBinding, "registry:rbac_bindings": rbacBinding, "reference:status_relay": relayBinding, "cross_resources": crossBinding, "reference:capture_signing": hash(captureRaw)}
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	if len(mapping.Owners) != len(known) {
		return nil, ErrInstall
	}
	seen := map[string]bool{}
	for _, binding := range mapping.Owners {
		if !known[binding.Key] || seen[binding.Key] || !digestPattern.MatchString(binding.SHA256) {
			return nil, ErrInstall
		}
		seen[binding.Key] = true
		if want, ok := bindings[binding.Key]; ok && want != binding.SHA256 {
			return nil, ErrInstall
		}
	}
	for _, end := range []time.Time{mapping.Until, classification.Until, relay.Until, identity.ValidUntil()} {
		if end.Before(deadline) {
			deadline = end
		}
	}
	check := &enableOnlyRelationObservation{owner: r, ctx: ctx, source: source, identity: identity, classification: classification, relay: relay, config: source.request.config, actor: in.Actor(), current: current.SHA256(), proposed: proposed.SHA256(), until: deadline, slots: map[string]bool{}, files: []consumerPinnedFile{{r.files.Classification.RecordFile, r.files.Classification.RecordSHA256, 262144}, {r.files.Classification.SignatureFile, hash(classSig), 64}, {r.files.StatusRelay.RecordFile, r.files.StatusRelay.RecordSHA256, 262144}, {r.files.StatusRelay.SignatureFile, hash(relaySig), 64}, {r.files.Terminal.MappingFile, r.files.Terminal.MappingSHA256, 262144}, {r.files.Terminal.SignatureFile, hash(mapSig), 64}}}
	check.origin = check
	if check.relations(ctx) != nil {
		return nil, ErrInstall
	}
	active, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	client, e := r.capture.OpenTerminalKubernetes(active)
	if e != nil {
		return nil, ErrInstall
	}
	native, e := observeStatusRelayReference(active, client, relay.Target, relay.Definition)
	if e != nil || native.identity != relay.NativeIdentitySHA256 {
		return nil, ErrInstall
	}
	check.native = native
	if native.until.Before(check.until) {
		check.until = native.until
	}
	if check.relations(ctx) != nil || !time.Now().Before(check.until) {
		return nil, ErrInstall
	}
	return check, nil
}

type enableOnlyRelationObservation struct {
	mu                sync.Mutex
	origin            *enableOnlyRelationObservation
	failed            atomic.Bool
	owner             *OriginalRelationEnableOnlyMutation
	ctx               context.Context
	source            *consumerCaptureState
	identity          *owner.PreparedReferenceCurrentIdentity
	classification    FunctionalClassificationRecord
	relay             statusRelayReferenceRecord
	config            sec.BootstrapConfig // immutable OLD disabled DATA, not mutation permission
	actor             sec.RegistrationActor
	current, proposed string
	native            statusRelayNative
	until, floor      time.Time
	tx                *sql.Tx
	slots             map[string]bool
	files             []consumerPinnedFile
}

func (*enableOnlyRelationObservation) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*enableOnlyRelationObservation) Risk() sec.ConfigMutationRisk {
	return sec.ConfigMutationRisk{SecurityBoundary: true}
}
func (o *enableOnlyRelationObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (o *enableOnlyRelationObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}
func (o *enableOnlyRelationObservation) local(ctx context.Context) error {
	if o == nil || o.origin != o || o.failed.Load() || o.source == nil || !consumerSameContext(ctx, o.ctx) || ctx.Err() != nil || o.source.current(ctx) != nil {
		return o.fail()
	}
	for _, pin := range o.files {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			return o.fail()
		}
	}
	for _, pin := range []BootstrapSourceFilePin{o.relay.Definition.Deployment, o.relay.Definition.CA, o.relay.Definition.ClientCertificate, o.relay.Definition.ClientPrivateKey} {
		raw, e := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if e != nil {
			return o.fail()
		}
	}
	return nil
}
func (o *enableOnlyRelationObservation) relations(ctx context.Context) error {
	if o.local(ctx) != nil {
		return o.fail()
	}
	files := sec.RegistrationFiles{RegistryDirectory: o.owner.files.Terminal.RegistryDirectory}
	registries := map[string][]byte{}
	var rbac sec.BootstrapRegistryRef
	for _, pin := range o.config.Registries() {
		raw, e := files.RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
		if e != nil {
			return o.fail()
		}
		registries[pin.Kind] = raw
		if pin.Kind == "rbac_bindings" {
			rbac = pin
		}
	}
	c := o.classification
	d := FunctionalClassificationDefinition{SchemaVersion: c.SchemaVersion, Profile: c.Profile, TaskPurpose: c.TaskPurpose, TargetClass: c.TargetClass, TargetFailureDomain: c.TargetFailureDomain, RecoveryEvidenceStatus: c.RecoveryEvidenceStatus, FailureRegistrySHA256: c.FailureDomains.SHA256, MappingRegistrySHA256: c.DisasterMapping.SHA256, SourceDomains: c.SourceDomains, TargetRisks: c.TargetRisks}
	if validateFunctionalRegistries(d, c.Target.InstallationID, o.config, registries["failure_domains"], registries["disaster_identity_mapping"]) != nil || originalCrossResourceRegistryRelations(o.config, c.Target.InstallationID, c.Target.Namespace, c.Target.NamespaceUID, registries) != nil {
		return o.fail()
	}
	authority := sec.PinnedRegistrationAuthority{InstallationID: c.Target.InstallationID, RegistryBytes: files.RegistryBytes}
	if authority.AuthorizeRole(o.actor, sec.RegistrationConfig{RBACRegistryVersion: rbac.Version, RBACRegistrySHA256: rbac.SHA256}) != nil {
		return o.fail()
	}
	return o.local(ctx)
}
func (o *enableOnlyRelationObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return ErrInstall
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if tx == nil || o.tx != nil && o.tx != tx || now.IsZero() || !o.floor.IsZero() && now.Before(o.floor) || now.Before(o.native.started) || !now.Before(o.until) || !time.Now().Before(o.until) || o.relations(ctx) != nil || o.identity.Recheck(ctx, tx, now) != nil || o.identity.ValidUntil().Before(o.until) {
		return o.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !tail.Before(o.until) || ctx.Err() != nil || o.relations(ctx) != nil {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*OriginalRelationEnableOnlyMutation)(nil)
var _ sec.ConfigMutationResourceObservation = (*enableOnlyRelationObservation)(nil)
