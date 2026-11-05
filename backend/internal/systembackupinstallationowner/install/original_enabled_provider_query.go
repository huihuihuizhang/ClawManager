package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (i *Installer) readEnabledProviderScope(ctx context.Context, db *sql.DB, enabled *OriginalEnabledPublication, current, old *c.PinnedExecutionIdentity) (time.Time, error) {
	if i == nil || db == nil || enabled == nil || enabled.operator == nil || enabled.operator.installer != i || enabled.Recheck(ctx) != nil || current == nil || old == nil {
		return time.Time{}, ErrInstall
	}
	g, before := current.DeploymentBinding(), old.DeploymentBinding()
	if g.ConfigVersion != 2 || g.ConfigSHA256 != enabled.configSHA || before.ConfigVersion != 1 || before.ConfigSHA256 != enabled.request.config.SHA256() {
		return time.Time{}, ErrInstall
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: false})
	if e != nil {
		return time.Time{}, ErrInstall
	}
	defer tx.Rollback()
	proof, e := sec.ReadOriginalEnabledOnlyLineage(ctx, tx, i.plan.Target.InstallationID, before.ConfigSHA256, 2, g.ConfigSHA256)
	if e != nil || current.CheckOriginalEnabledOnlyPredecessorInView(ctx, tx, old) != nil {
		return time.Time{}, ErrInstall
	}
	authorized, e := proof.AuthorizationConfigSHA256(ctx, tx)
	if e != nil || authorized != before.ConfigSHA256 {
		return time.Time{}, ErrInstall
	}
	until, e := proof.OriginalDiagnosticUntil(ctx, tx)
	if e != nil || tx.Rollback() != nil || enabled.Recheck(ctx) != nil {
		return time.Time{}, ErrInstall
	}
	return until, nil
}

// Explicit authenticated MinIO-v4 owner profile selection reuses the existing
// private scope; it creates no metadata-reader consent or task permission.
func (i *Installer) IssueOriginalEnabledRuntimeProviderAuthoritiesForMinIOMetadata(ctx context.Context, db *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalEnabledRuntimeProviderInputs) (OriginalRuntimeProviderIssueReceipt, error) {
	actual, close, e := i.originalMetadataOwnerContext(ctx, db, password, enrollment)
	if e != nil {
		return OriginalRuntimeProviderIssueReceipt{}, e
	}
	defer close()
	return i.IssueOriginalEnabledRuntimeProviderAuthorities(actual, db, password, enrollment, in)
}

func (i *Installer) QueryOriginalEnabledRuntimeProviderAuthoritiesForMinIOMetadata(ctx context.Context, db *sql.DB, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin) (OriginalRuntimeProviderIssueReceipt, error) {
	actual, close, e := i.originalMetadataOwnerContext(ctx, db, password, enrollment)
	if e != nil {
		return OriginalRuntimeProviderIssueReceipt{}, e
	}
	defer close()
	return i.QueryOriginalEnabledRuntimeProviderAuthorities(actual, db, password, enrollment, pin)
}

// Query never issues/signs/corrects material or writes SQL. Reauthentication,
// native permissions, original deadlines and exact committed bytes are checked
// again. Pending output plus missing/partial rows remains commit-unknown.
func (i *Installer) QueryOriginalEnabledRuntimeProviderAuthorities(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin) (OriginalRuntimeProviderIssueReceipt, error) {
	var zero OriginalRuntimeProviderIssueReceipt
	if i == nil || ctx == nil || runtimeDB == nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	var m originalEnabledProviderMaterial
	if e != nil || decodeExact(raw, &m) != nil || m.Version != "original-enabled-provider-material.v1" || m.PlanSHA256 != i.planHash || m.Enrollment != enrollment || m.Source.Version != "original-enabled-runtime-provider-inputs.v1" || pin.File != filepath.Join(m.Source.OutputDirectory, "enabled-provider.material.json") || privateDirectory(m.Source.OutputDirectory) != nil || !time.Now().Before(m.Until) || m.Until.After(m.Source.Until) {
		return zero, ErrInstall
	}
	in := m.Source
	result := m.Authorities
	if result.Version != "original-enabled-runtime-provider-authorities-result.v1" || result.State != "material_issued_sql_install_pending" || result.SQLMetadataReceipt != (BootstrapSourceFilePin{}) {
		return zero, ErrInstall
	}
	enabled, e := i.PrepareOriginalEnabledPublication(ctx, password, enrollment, in.EnableReceipt, in.Request)
	if e != nil {
		return zero, e
	}
	defer enabled.Close()
	op := enabled.operator
	before, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || before.cas != enabled.initial || !now.Before(m.Until) || m.Until.After(enabled.until) {
		return zero, ErrInstall
	}
	issuers, e := i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	public := func(purpose string) (ed25519.PublicKey, error) {
		b, e := readBootstrapSourcePin(issuers.Issuers[purpose].PublicKey, 32)
		return ed25519.PublicKey(b), e
	}
	forwardPublic, e := public("forward_execution")
	if e != nil {
		return zero, ErrInstall
	}
	coreRaw, e := readBootstrapSourcePin(in.Core, 262144)
	var core originalRuntimeCoreScope
	if e != nil || json.Unmarshal(coreRaw, &core) != nil || core.InstallationID != i.plan.Target.InstallationID || core.Namespace != i.plan.Target.Namespace || core.NamespaceUID != i.plan.Target.NamespaceUID || core.Forward.Path != in.OriginalForward.File || core.Forward.PublicKey != base64.StdEncoding.EncodeToString(forwardPublic) {
		return zero, ErrInstall
	}
	current, e := c.NewPinnedExecutionIdentity(in.Forward.File, in.Forward.SHA256, core.KeyDirectory, forwardPublic)
	if e != nil {
		return zero, ErrInstall
	}
	old, e := current.OpenOriginalEnabledOnlyPredecessor(in.OriginalForward.File, in.OriginalForward.SHA256)
	if e != nil {
		return zero, ErrInstall
	}
	end, e := i.readEnabledProviderScope(ctx, runtimeDB, enabled, current, old)
	if e != nil || m.Until.After(end) {
		return zero, ErrInstall
	}
	g := current.DeploymentBinding()
	if g.DeploymentConfigSHA256 != in.Core.SHA256 || g.ConfigVersion != 2 || g.ConfigSHA256 != enabled.configSHA || g.ControllerOwner != core.ControllerOwner || g.InstallationID != i.plan.Target.InstallationID || m.Until.After(g.ExpiresAt) {
		return zero, ErrInstall
	}
	if _, e = i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil {
		return zero, ErrInstall
	}
	dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, in.ControllerDeployment, metav1.GetOptions{})
	if e != nil || dep.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	worker, e := i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Get(ctx, core.Security.ServiceAccountName, metav1.GetOptions{})
	if e != nil || worker.DeletionTimestamp != nil || string(worker.UID) != core.Security.ServiceAccountUID || string(worker.UID) == actor.ServiceAccountUID {
		return zero, ErrInstall
	}
	owner, e := i.ReadEnabledPublicationRuntimeOwnerInputs(ctx, password, enrollment, in.PublicationOwnerInputs, enabled, runtimeDB)
	if e != nil {
		return zero, ErrInstall
	}
	publisherRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: owner.PublisherGrant.File, SHA256: owner.PublisherGrant.SHA256}, 65536)
	var signedPublisher sec.SignedPublisherCaptureGrant
	var publisher sec.PublisherCaptureGrant
	if e != nil || decodeExact(publisherRaw, &signedPublisher) != nil || !ed25519.Verify(i.public, append([]byte(sec.PublisherCaptureGrantDomain), signedPublisher.Record...), signedPublisher.Signature) || decodeExact(signedPublisher.Record, &publisher) != nil || publisher.Revoked || publisher.Deployment.ConfigVersion != 2 || publisher.Deployment.ConfigSHA256 != g.ConfigSHA256 || publisher.Deployment.CaptureGrantSHA256 != in.Forward.SHA256 || publisher.Deployment.DeploymentConfigSHA256 != in.Core.SHA256 || publisher.Workload.PodUID != actor.PodUID || publisher.Workload.ServiceAccountUID != actor.ServiceAccountUID || now.Before(publisher.NotBefore) || m.Until.After(publisher.Until) {
		return zero, ErrInstall
	}
	providerRaw, e := readBootstrapSourcePin(in.Provider, 262144)
	var cfg a.VaultPermissionObserverConfig
	if e != nil || decodeExact(providerRaw, &cfg) != nil || !reflect.DeepEqual(cfg.Binding, result.Binding) || cfg.Worker.Namespace != i.plan.Target.Namespace || cfg.Worker.ServiceAccountName != worker.Name || cfg.Worker.ServiceAccountUID != string(worker.UID) || cfg.Publisher.Namespace != actor.Namespace || cfg.Publisher.ServiceAccountName != actor.ServiceAccountName || cfg.Publisher.ServiceAccountUID != actor.ServiceAccountUID || cfg.Publisher.PodUID != actor.PodUID || cfg.Worker.Workload != nil {
		return zero, ErrInstall
	}
	workload := a.ControllerVerifierWorkload{Namespace: i.plan.Target.Namespace, PodName: actor.PodName, PodUID: actor.PodUID, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, OwnerKind: "Deployment", OwnerUID: string(dep.UID), ControllerOwner: g.ControllerOwner, ConfigVersion: 2, ConfigSHA256: g.ConfigSHA256}
	formalPublic, e := public("formal_verifier")
	if e != nil {
		return zero, ErrInstall
	}
	permitPublic, e := public("provider_permit_business")
	if e != nil {
		return zero, ErrInstall
	}
	deliveryPublic, e := public("provider_permit_delivery")
	if e != nil {
		return zero, ErrInstall
	}
	mappingPublic, e := public("installation_mapping")
	if e != nil {
		return zero, ErrInstall
	}
	permissionPublic, e := public("provider_permission")
	if e != nil {
		return zero, ErrInstall
	}
	database := reg.DatabaseIdentity{ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database}
	if result.Database != database || !bytes.Equal(result.InstallationIssuer, mappingPublic) || !bytes.Equal(result.FormalGrant.Issuer, formalPublic) || !bytes.Equal(result.PermitGrant.Issuer, permitPublic) || result.PermitSigningKeyFile != issuers.Issuers["provider_permit_delivery"].PrivateKey.File || !kms.ValidPermitDeliveryPin(result.DeliveryPin) || !bytes.Equal(result.DeliveryPin.Issuer, deliveryPublic) || result.DeliveryPin.IssuerGrantSHA256 != result.PermitGrant.SHA256 {
		return zero, ErrInstall
	}
	expectedFormal := workload
	expectedFormal.GrantSHA256 = result.FormalGrant.SHA256
	expectedPermit := workload
	expectedPermit.GrantSHA256 = result.PermitGrant.SHA256
	if result.FormalWorkload != expectedFormal || result.PermitWorkload != expectedPermit {
		return zero, ErrInstall
	}
	read := func(p BootstrapSourceFilePin, name string) ([]byte, error) {
		if p.File != filepath.Join(in.OutputDirectory, name) {
			return nil, ErrInstall
		}
		return readBootstrapSourcePin(p, 262144)
	}
	mappingRaw, e := read(result.MappingRecord, "mapping.record.json")
	if e != nil {
		return zero, ErrInstall
	}
	mappingSignature, e := read(result.MappingSignature, "mapping.signature")
	if e != nil {
		return zero, ErrInstall
	}
	mapping, e := a.InspectOriginalCurrentMapping(mappingRaw, mappingSignature, mappingPublic, now)
	if e != nil || mapping.GenerateRevoked || mapping.UnwrapRevoked || !reflect.DeepEqual(mapping.Binding, cfg.Binding) || mapping.Source != result.MappingSource || m.Until.After(mapping.Until) {
		return zero, ErrInstall
	}
	formalRaw, e := read(BootstrapSourceFilePin{File: result.FormalGrant.File, SHA256: result.FormalGrant.SHA256}, "formal-verifier.grant.json")
	var formalSigned a.SignedControllerVerifierGrant
	var formal a.ControllerVerifierGrant
	if e != nil || decodeExact(formalRaw, &formalSigned) != nil || !ed25519.Verify(formalPublic, append([]byte(a.ControllerVerifierGrantDomain), formalSigned.Record...), formalSigned.Signature) || decodeExact(formalSigned.Record, &formal) != nil || formal.Revoked || formal.InstallationID != i.plan.Target.InstallationID || formal.Database != database || formal.DatabaseAccount != g.DatabaseAccount || formal.Workload != workload || formal.CaptureGrantSHA256 != in.Forward.SHA256 || !formal.Until.Equal(m.Until) {
		return zero, ErrInstall
	}
	if result.PermitGrant.File != filepath.Join(in.OutputDirectory, "provider-permit.grant.json") {
		return zero, ErrInstall
	}
	caps, e := a.NewSQLProviderCapabilityPreparation(runtimeDB, database, i.plan.Target.InstallationID, result.Generate, result.Unwrap)
	if e != nil {
		return zero, ErrInstall
	}
	if a.InspectOriginalRuntimeGrantMaterials(ctx, result.FormalGrant, result.FormalWorkload, i.plan.Target.InstallationID, in.Forward.SHA256, database, a.ProviderPermitIssuerConfig{Capabilities: caps, Binding: result.Binding, CaptureGrantSHA256: in.Forward.SHA256, Workload: result.PermitWorkload, GrantMount: result.PermitGrant, SigningKeyFile: result.PermitSigningKeyFile}) != nil {
		return zero, ErrInstall
	}
	imports := []a.OriginalRuntimeCapabilityImport{}
	for _, pair := range []struct {
		pin  a.ProviderCapabilityPin
		file BootstrapSourceFilePin
		name string
		op   kms.Operation
	}{{result.Generate, result.GenerateFile, "generate.capability.json", kms.Generate}, {result.Unwrap, result.UnwrapFile, "unwrap.capability.json", kms.Unwrap}, {result.PublisherUnwrap, result.PublisherUnwrapFile, "publisher-unwrap.capability.json", kms.Unwrap}} {
		b, e := read(pair.file, pair.name)
		if e != nil || !bytes.Equal(pair.pin.Issuer, permissionPublic) {
			return zero, ErrInstall
		}
		r, e := a.InspectProviderCapabilityMaterial(b, pair.pin, cfg.Binding, pair.op, m.Until, now)
		if e != nil || !r.Until.Equal(m.Until) {
			return zero, ErrInstall
		}
		imports = append(imports, a.OriginalRuntimeCapabilityImport{Raw: b, Pin: pair.pin, Operation: pair.op})
	}
	// Reobserve the same actual current native role/policy facts, without
	// signing them or refreshing any existing record's original Until.
	cfg.Publisher.Workload = &expectedFormal
	observer, e := a.NewVaultPermissionObserver(cfg)
	if e != nil {
		return zero, ErrInstall
	}
	defer observer.Close()
	observed, e := observer.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	if observed.CheckOriginalRuntimeCapability(imports[0].Raw, result.Generate, cfg.Binding, kms.Generate, m.Until, time.Now()) != nil || observed.CheckOriginalRuntimeCapability(imports[1].Raw, result.Unwrap, cfg.Binding, kms.Unwrap, m.Until, time.Now()) != nil {
		return zero, ErrInstall
	}
	publisherWorkload := workload
	publisherWorkload.ControllerOwner = "public:" + actor.PodUID
	publisherWorkload.GrantSHA256 = owner.PublisherGrant.SHA256
	cfg.Publisher.Workload = &publisherWorkload
	pubObserver, e := a.NewVaultPermissionObserver(cfg)
	if e != nil {
		return zero, ErrInstall
	}
	defer pubObserver.Close()
	pubObserved, e := pubObserver.Observe(ctx)
	if e != nil || pubObserved.CheckOriginalRuntimeCapability(imports[2].Raw, result.PublisherUnwrap, cfg.Binding, kms.Unwrap, m.Until, time.Now()) != nil {
		return zero, ErrInstall
	}
	if _, e = caps.PrepareCapabilities(ctx, result.Binding); e != nil {
		return zero, ErrInstall
	}
	pubCaps, e := a.NewSQLProviderCapabilityPreparation(runtimeDB, database, i.plan.Target.InstallationID, result.Generate, result.PublisherUnwrap)
	if e != nil {
		return zero, ErrInstall
	}
	if _, e = pubCaps.PrepareCapabilities(ctx, result.Binding); e != nil {
		return zero, ErrInstall
	}
	if enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	proof, e := sec.ReadOriginalEnabledOnlyLineage(ctx, tx, i.plan.Target.InstallationID, old.DeploymentBinding().ConfigSHA256, 2, g.ConfigSHA256)
	if e != nil {
		return zero, ErrInstall
	}
	locked, e := op.lockAdmin(ctx, tx)
	if e != nil || !locked.Before(m.Until) {
		return zero, ErrInstall
	}
	head, e := op.current(ctx, tx, false)
	if e != nil || head.cas != before.cas {
		return zero, ErrInstall
	}
	writer, e := a.NewInstallationAuthorityWriter(i.db, i.plan.Target.InstallationID, database, mappingPublic)
	if e != nil {
		return zero, ErrInstall
	}
	if writer.ReadEnabledRuntimeCapabilities(ctx, tx, mappingRaw, mappingSignature, imports, proof, old.DeploymentBinding().ConfigSHA256, g.ConfigSHA256, locked) != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	tail, e := op.lockAdmin(ctx, tx)
	if e != nil || tail.Before(locked) || !tail.Before(m.Until) || !time.Now().Before(m.Until) || tx.Rollback() != nil {
		return zero, ErrInstall
	}
	if enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	check, e := readBootstrapSourcePin(pin, 262144)
	if e != nil || !bytes.Equal(check, raw) {
		return zero, ErrInstall
	}
	result.State = "enabled_native_capabilities_committed_readback_verified"
	return result, nil
}
