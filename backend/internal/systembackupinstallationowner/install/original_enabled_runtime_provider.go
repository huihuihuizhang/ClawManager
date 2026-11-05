package install

import (
	"bytes"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type OriginalEnabledRuntimeProviderInputs struct {
	Version                                                                         string
	EnableReceipt, OriginalForward                                                  BootstrapSourceFilePin
	Issuers, Core, Forward, Provider, PublicationOwnerInputs                        BootstrapSourceFilePin
	Request                                                                         RequestFiles
	ControllerDeployment, ControllerPodName, WorkerJWTIdentityFile, OutputDirectory string
	Until                                                                           time.Time
}
type originalEnabledProviderMaterial struct {
	Version, PlanSHA256 string
	Enrollment          EnrollmentPin
	Source              OriginalEnabledRuntimeProviderInputs
	Authorities         OriginalRuntimeProviderIssueReceipt
	Until               time.Time
}

// Fresh enabled owner action; every runtime grant and capability is separately
// signed from current native permission observations for config2/publication3.
// The committed original mapping remains byte-for-byte unchanged.
func (i *Installer) IssueOriginalEnabledRuntimeProviderAuthorities(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalEnabledRuntimeProviderInputs) (OriginalRuntimeProviderIssueReceipt, error) {
	var zero OriginalRuntimeProviderIssueReceipt
	if i == nil || ctx == nil || runtimeDB == nil || in.Version != "original-enabled-runtime-provider-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	entries, e := os.ReadDir(in.OutputDirectory)
	if e != nil || len(entries) != 0 {
		return zero, ErrInstall
	}
	enabled, e := i.PrepareOriginalEnabledPublication(ctx, password, enrollment, in.EnableReceipt, in.Request)
	if e != nil {
		return zero, ErrInstall
	}
	defer enabled.Close()
	s, e := i.authenticate(ctx, password)
	if e != nil || runtimeDB == nil || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	before, now, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
	if e != nil || before.cas != enabled.initial || enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	material, e := i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	keys := map[string]ed25519.PrivateKey{}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, purpose := range []string{"formal_verifier", "provider_permit_business", "provider_permit_delivery", "installation_mapping", "provider_permission"} {
		raw, e := readBootstrapSourcePin(material.Issuers[purpose].PrivateKey, 64)
		if e != nil || len(raw) != 64 {
			clear(raw)
			return zero, ErrInstall
		}
		keys[purpose] = ed25519.PrivateKey(raw)
	}
	coreRaw, e := readBootstrapSourcePin(in.Core, 262144)
	var core originalRuntimeCoreScope
	if e != nil || json.Unmarshal(coreRaw, &core) != nil {
		return zero, ErrInstall
	}
	target := i.plan.Target
	if core.InstallationID != target.InstallationID || core.Namespace != target.Namespace || core.NamespaceUID != target.NamespaceUID || core.Forward.Path != in.OriginalForward.File {
		return zero, ErrInstall
	}
	public, e := readBootstrapSourcePin(material.Issuers["forward_execution"].PublicKey, 32)
	if e != nil || core.Forward.PublicKey != base64.StdEncoding.EncodeToString(public) {
		return zero, ErrInstall
	}
	forward, e := c.NewPinnedExecutionIdentity(in.Forward.File, in.Forward.SHA256, core.KeyDirectory, public)
	if e != nil || forward.CheckDeployment(ctx, runtimeDB) != nil {
		return zero, ErrInstall
	}
	oldForward, e := forward.OpenOriginalEnabledOnlyPredecessor(in.OriginalForward.File, in.OriginalForward.SHA256)
	if e != nil {
		return zero, ErrInstall
	}
	oldBinding := oldForward.DeploymentBinding()
	if oldBinding.ConfigVersion != 1 || oldBinding.ConfigSHA256 != enabled.request.config.SHA256() {
		return zero, ErrInstall
	}
	g := forward.DeploymentBinding()
	if g.InstallationID != target.InstallationID || g.DatabaseAccount == target.DatabaseAccount || g.ServerUUID != target.ServerUUID || g.Database != target.Database || g.ConfigVersion != 2 || g.DeploymentConfigSHA256 != in.Core.SHA256 || g.ControllerOwner != core.ControllerOwner || g.ConfigSHA256 != enabled.configSHA {
		return zero, ErrInstall
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
		return zero, ErrInstall
	}
	request := enabled.request
	diagnosticUntil, e := i.readEnabledProviderScope(ctx, runtimeDB, enabled, forward, oldForward)
	if e != nil {
		return zero, ErrInstall
	}
	if oldBinding.ConfigSHA256 != request.config.SHA256() || request.grant.InstallationID != target.InstallationID || request.grant.ServerUUID != target.ServerUUID || request.grant.Database != target.Database || request.grant.UserID != s.userID || request.grant.Username != i.plan.LocalAdminUsername {
		return zero, ErrInstall
	}
	if before.cas.HeadRevision > 0 && !request.matchesDraft(before.record) {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil {
		return zero, ErrInstall
	}
	dep, e := i.kube.AppsV1().Deployments(target.Namespace).Get(ctx, in.ControllerDeployment, metav1.GetOptions{})
	if e != nil || dep.UID == "" || dep.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	worker, e := i.kube.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, core.Security.ServiceAccountName, metav1.GetOptions{})
	if e != nil || worker.UID == "" || string(worker.UID) != core.Security.ServiceAccountUID || worker.DeletionTimestamp != nil || string(worker.UID) == actor.ServiceAccountUID {
		return zero, ErrInstall
	}
	workload := a.ControllerVerifierWorkload{Namespace: target.Namespace, PodName: actor.PodName, PodUID: actor.PodUID, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, OwnerKind: "Deployment", OwnerUID: string(dep.UID), ControllerOwner: core.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256}
	raw, e := readBootstrapSourcePin(in.Provider, 262144)
	var cfg a.VaultPermissionObserverConfig
	if e != nil || decodeExact(raw, &cfg) != nil || cfg.Binding.InstallationID != target.InstallationID || cfg.Worker.Namespace != target.Namespace || cfg.Worker.ServiceAccountName != worker.Name || cfg.Worker.ServiceAccountUID != string(worker.UID) || cfg.Publisher.Namespace != target.Namespace || cfg.Publisher.ServiceAccountName != actor.ServiceAccountName || cfg.Publisher.ServiceAccountUID != actor.ServiceAccountUID || cfg.Publisher.PodUID != actor.PodUID {
		return zero, ErrInstall
	}
	issued, e := i.ReadEnabledPublicationRuntimeOwnerInputs(ctx, password, enrollment, in.PublicationOwnerInputs, enabled, runtimeDB)
	if e != nil {
		return zero, ErrInstall
	}
	publisherGrantRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: issued.PublisherGrant.File, SHA256: issued.PublisherGrant.SHA256}, 65536)
	var publisherSigned sec.SignedPublisherCaptureGrant
	var publisherGrant sec.PublisherCaptureGrant
	if e != nil || decodeExact(publisherGrantRaw, &publisherSigned) != nil || !ed25519.Verify(i.public, append([]byte(sec.PublisherCaptureGrantDomain), publisherSigned.Record...), publisherSigned.Signature) || decodeExact(publisherSigned.Record, &publisherGrant) != nil || publisherGrant.Deployment.CaptureGrantSHA256 != in.Forward.SHA256 || publisherGrant.Deployment.DeploymentConfigSHA256 != in.Core.SHA256 || publisherGrant.Deployment.ConfigVersion != g.ConfigVersion || publisherGrant.Deployment.ConfigSHA256 != g.ConfigSHA256 || publisherGrant.Workload.PodUID != actor.PodUID || publisherGrant.Workload.ServiceAccountUID != actor.ServiceAccountUID {
		return zero, ErrInstall
	}
	found := false
	for _, ref := range request.config.References() {
		if ref.Purpose == "kek" && ref.IdentityHash == cfg.Binding.ConfigRef.IdentityHash && ref.Version == cfg.Binding.ConfigRef.Version {
			found = true
		}
	}
	if !found {
		return zero, ErrInstall
	}
	if cfg.Worker.Workload != nil || cfg.Publisher.Workload != nil && !reflect.DeepEqual(*cfg.Publisher.Workload, workload) {
		return zero, ErrInstall
	}
	cfg.Publisher.Workload = &workload
	until := minTime(diagnosticUntil, minTime(enabled.until, minTime(publisherGrant.Until, minTime(in.Until, minTime(g.ExpiresAt, request.end)))))
	mappingRaw, mappingSignature, e := (a.SQLOriginalReader{DB: runtimeDB}).ReadOriginal(ctx, target.InstallationID, cfg.Binding.ConfigRef)
	mappingPublic := keys["installation_mapping"].Public().(ed25519.PublicKey)
	var m a.OriginalRecord
	if e == nil {
		m, e = a.InspectOriginalCurrentMapping(mappingRaw, mappingSignature, mappingPublic, now)
	}
	if e != nil || m.GenerateRevoked || m.UnwrapRevoked || !reflect.DeepEqual(m.Binding, cfg.Binding) {
		return zero, ErrInstall
	}
	until = minTime(until, m.Until)
	if before.cas.HeadRevision > 0 {
		until = minTime(until, minTime(before.head.Until, before.record.Until))
	}
	// SQL evidence timestamps are DATETIME(6); round DOWN before signing.
	until = until.UTC().Truncate(time.Microsecond)
	if now.Before(request.start) || now.Before(g.NotBefore) || !now.Before(until) || until.Sub(now) > 24*time.Hour || !filepath.IsAbs(in.WorkerJWTIdentityFile) || filepath.Clean(in.WorkerJWTIdentityFile) != in.WorkerJWTIdentityFile {
		return zero, ErrInstall
	}
	database := reg.DatabaseIdentity{ServerUUID: target.ServerUUID, Database: target.Database}
	formal := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: target.InstallationID, Database: database, DatabaseAccount: g.DatabaseAccount, Workload: workload, CaptureGrantSHA256: in.Forward.SHA256, NotBefore: now, Until: until}
	formalRaw, e := canonical(formal)
	if e != nil {
		return zero, ErrInstall
	}
	formalEnvelope, e := canonical(a.SignedControllerVerifierGrant{Record: formalRaw, Signature: ed25519.Sign(keys["formal_verifier"], append([]byte(a.ControllerVerifierGrantDomain), formalRaw...))})
	if e != nil {
		return zero, ErrInstall
	}
	formalObservationWorkload := workload
	formalObservationWorkload.GrantSHA256 = hash(formalEnvelope)
	cfg.Publisher.Workload = &formalObservationWorkload
	observer, e := a.NewVaultPermissionObserver(cfg)
	if e != nil {
		return zero, ErrInstall
	}
	defer observer.Close()
	observed, e := observer.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	source := func(purpose string) (reg.SourceRecord, error) {
		id, e := originalRuntimeEvidenceID()
		return reg.SourceRecord{SourceID: "enabled-runtime-" + purpose + ":" + target.InstallationID, RecordID: id, RecordVersion: "enabled-v2"}, e
	}
	generateSource, e := source("generate")
	if e != nil {
		return zero, ErrInstall
	}
	unwrapSource, e := source("unwrap")
	if e != nil {
		return zero, ErrInstall
	}
	publisherSource, e := source("publisher-unwrap")
	if e != nil {
		return zero, ErrInstall
	}
	generate, e := observed.Sign(kms.Generate, generateSource, "enabled-v2", until, keys["provider_permission"])
	if e != nil {
		return zero, ErrInstall
	}
	unwrap, e := observed.Sign(kms.Unwrap, unwrapSource, "enabled-v2", until, keys["provider_permission"])
	if e != nil {
		return zero, ErrInstall
	}
	// Publication uses a distinct business owner on the same actual Pod. Its
	// capability is separately observed/signed; formal-verifier facts never stand
	// in for a public:<PodUID> permission or vice versa.
	publisherWorkload := workload
	publisherWorkload.ControllerOwner = "public:" + actor.PodUID
	publisherWorkload.GrantSHA256 = issued.PublisherGrant.SHA256
	cfg.Publisher.Workload = &publisherWorkload
	publisherObserver, e := a.NewVaultPermissionObserver(cfg)
	if e != nil {
		return zero, ErrInstall
	}
	defer publisherObserver.Close()
	publisherObserved, e := publisherObserver.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	publisherUnwrap, e := publisherObserved.Sign(kms.Unwrap, publisherSource, "enabled-v2", until, keys["provider_permission"])
	if e != nil {
		return zero, ErrInstall
	}
	var generateRecord, unwrapRecord, publisherRecord a.ProviderCapabilityRecord
	if json.Unmarshal(generate.Record, &generateRecord) != nil || json.Unmarshal(unwrap.Record, &unwrapRecord) != nil || json.Unmarshal(publisherUnwrap.Record, &publisherRecord) != nil {
		return zero, ErrInstall
	}
	permit := a.ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: cfg.Binding, Database: database, DatabaseAccount: g.DatabaseAccount, Workload: workload, SigningPublicKey: keys["provider_permit_delivery"].Public().(ed25519.PublicKey), GeneratePermission: generateRecord.Facts.Permission, WorkerNamespace: target.Namespace, WorkerServiceAccountName: worker.Name, WorkerServiceAccountUID: string(worker.UID), WorkerJWTIdentityFile: in.WorkerJWTIdentityFile, NotBefore: now, Until: until}
	permitRaw, e := canonical(permit)
	if e != nil {
		return zero, ErrInstall
	}
	permitEnvelope, e := canonical(a.SignedProviderPermitIssuerGrant{Record: permitRaw, Signature: ed25519.Sign(keys["provider_permit_business"], append([]byte(a.ProviderPermitIssuerGrantDomain), permitRaw...))})
	if e != nil {
		return zero, ErrInstall
	}
	if unwrapRecord.Facts.Permission.ControllerVerifier == nil || *unwrapRecord.Facts.Permission.ControllerVerifier != formalObservationWorkload || publisherRecord.Facts.Permission.ControllerVerifier == nil || *publisherRecord.Facts.Permission.ControllerVerifier != publisherWorkload || generateRecord.Facts.Permission.ControllerVerifier != nil {
		return zero, ErrInstall
	}
	permissionPublic := keys["provider_permission"].Public().(ed25519.PublicKey)
	result := OriginalRuntimeProviderIssueReceipt{State: "material_issued_sql_install_pending", Version: "original-enabled-runtime-provider-authorities-result.v1", Binding: cfg.Binding, Database: database, MappingSource: m.Source, InstallationIssuer: keys["installation_mapping"].Public().(ed25519.PublicKey), Generate: a.ProviderCapabilityPin{Source: generateRecord.Source, Issuer: permissionPublic}, Unwrap: a.ProviderCapabilityPin{Source: unwrapRecord.Source, Issuer: permissionPublic}, PublisherUnwrap: a.ProviderCapabilityPin{Source: publisherRecord.Source, Issuer: permissionPublic}, FormalWorkload: workload, PermitWorkload: workload, PermitSigningKeyFile: material.Issuers["provider_permit_delivery"].PrivateKey.File}
	result.FormalGrant = a.ControllerVerifierGrantMount{File: filepath.Join(in.OutputDirectory, "formal-verifier.grant.json"), SHA256: hash(formalEnvelope), Issuer: keys["formal_verifier"].Public().(ed25519.PublicKey)}
	result.FormalWorkload.GrantSHA256 = result.FormalGrant.SHA256
	result.PermitGrant = a.ProviderPermitIssuerGrantMount{File: filepath.Join(in.OutputDirectory, "provider-permit.grant.json"), SHA256: hash(permitEnvelope), Issuer: keys["provider_permit_business"].Public().(ed25519.PublicKey)}
	result.PermitWorkload.GrantSHA256 = result.PermitGrant.SHA256
	result.DeliveryPin = kms.PermitDeliveryPin{Version: kms.PermitDeliveryVersion, Issuer: permit.SigningPublicKey, IssuerGrantSHA256: result.PermitGrant.SHA256}
	files := map[string][]byte{"mapping.record.json": mappingRaw, "mapping.signature": mappingSignature, "formal-verifier.grant.json": formalEnvelope, "provider-permit.grant.json": permitEnvelope}
	for name, value := range map[string]a.SignedProviderCapabilityRecord{"generate.capability.json": generate, "unwrap.capability.json": unwrap, "publisher-unwrap.capability.json": publisherUnwrap} {
		b, e := canonical(value)
		if e != nil {
			return zero, ErrInstall
		}
		files[name] = b
	}
	pin := func(name string) BootstrapSourceFilePin {
		return BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, name), SHA256: hash(files[name])}
	}
	result.MappingRecord = pin("mapping.record.json")
	result.MappingSignature = pin("mapping.signature")
	result.GenerateFile = pin("generate.capability.json")
	result.UnwrapFile = pin("unwrap.capability.json")
	result.PublisherUnwrapFile = pin("publisher-unwrap.capability.json")
	receipt, e := canonical(result)
	if e != nil {
		return zero, ErrInstall
	}
	files["runtime-provider-authorities.json"] = receipt
	manifest := originalEnabledProviderMaterial{Version: "original-enabled-provider-material.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Source: in, Authorities: result, Until: until}
	manifestRaw, e := canonical(manifest)
	if e != nil {
		return zero, ErrInstall
	}
	files["enabled-provider.material.json"] = manifestRaw
	floor := now
	recheck := func() error {
		if request.recheck(i) != nil {
			return ErrInstall
		}
		actual, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
		if e != nil || actual != actor {
			return ErrInstall
		}
		depNow, e := i.kube.AppsV1().Deployments(target.Namespace).Get(ctx, dep.Name, metav1.GetOptions{})
		if e != nil || depNow.UID != dep.UID || depNow.DeletionTimestamp != nil {
			return ErrInstall
		}
		workerNow, e := i.kube.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, worker.Name, metav1.GetOptions{})
		if e != nil || workerNow.UID != worker.UID || workerNow.DeletionTimestamp != nil {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{in.Core, in.Provider, in.Issuers, in.PublicationOwnerInputs, in.OriginalForward, in.Forward, in.EnableReceipt} {
			if _, e := readBootstrapSourcePin(pin, 262144); e != nil {
				return ErrInstall
			}
		}
		if _, e := i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment); e != nil {
			return ErrInstall
		}
		freshOwner, e := i.ReadEnabledPublicationRuntimeOwnerInputs(ctx, password, enrollment, in.PublicationOwnerInputs, enabled, runtimeDB)
		if e != nil || !reflect.DeepEqual(freshOwner, issued) {
			return ErrInstall
		}
		if s.authority(ctx, enrollment) != nil || forward.CheckDeployment(ctx, runtimeDB) != nil {
			return ErrInstall
		}
		if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
			return ErrInstall
		}
		tail, t, e := originalRuntimeAuthoritySnapshot(ctx, s, enrollment)
		if e != nil || tail.cas != before.cas || t.Before(floor) || !t.Before(until) || !time.Now().Before(until) || !s.live(ctx) {
			return ErrInstall
		}
		if enabled.Recheck(ctx) != nil {
			return ErrInstall
		}
		end, e := i.readEnabledProviderScope(ctx, runtimeDB, enabled, forward, oldForward)
		if e != nil || until.After(end) {
			return ErrInstall
		}
		floor = t
		return nil
	}
	if recheck() != nil {
		return zero, ErrInstall
	}
	for _, p := range []struct {
		raw []byte
		pin a.ProviderCapabilityPin
		op  kms.Operation
	}{{files["generate.capability.json"], result.Generate, kms.Generate}, {files["unwrap.capability.json"], result.Unwrap, kms.Unwrap}, {files["publisher-unwrap.capability.json"], result.PublisherUnwrap, kms.Unwrap}} {
		if _, e := a.InspectProviderCapabilityMaterial(p.raw, p.pin, result.Binding, p.op, until, time.Now()); e != nil {
			return zero, ErrInstall
		}
	}
	if writeNewFiles(in.OutputDirectory, files) != nil {
		return zero, ErrInstall
	}
	for name, want := range files {
		actual, e := ReadPrivateFile(filepath.Join(in.OutputDirectory, name), 262144)
		if e != nil || !bytes.Equal(actual, want) {
			return zero, ErrInstall
		}
	}
	caps, e := a.NewSQLProviderCapabilityPreparation(runtimeDB, database, target.InstallationID, result.Generate, result.Unwrap)
	if e != nil {
		return zero, ErrInstall
	}
	if a.InspectOriginalRuntimeGrantMaterials(ctx, result.FormalGrant, result.FormalWorkload, target.InstallationID, in.Forward.SHA256, database, a.ProviderPermitIssuerConfig{Capabilities: caps, Binding: result.Binding, CaptureGrantSHA256: in.Forward.SHA256, Workload: result.PermitWorkload, GrantMount: result.PermitGrant, SigningKeyFile: result.PermitSigningKeyFile}) != nil || recheck() != nil {
		return zero, ErrInstall
	}
	// Native/file checks finish before acquiring installer/KEK SQL locks.
	if recheck() != nil {
		return zero, ErrInstall
	}
	writer, e := a.NewInstallationAuthorityWriter(i.db, target.InstallationID, database, result.InstallationIssuer)
	if e != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	// State FOR SHARE is first. The actual proof is kept in THIS tx through
	// all append operations; no native/file I/O runs under these SQL locks.
	lineage, e := sec.ReadOriginalEnabledOnlyLineage(ctx, tx, target.InstallationID, oldBinding.ConfigSHA256, 2, g.ConfigSHA256)
	if e != nil {
		return zero, ErrInstall
	}
	locked, e := s.lockAdmin(ctx, tx)
	if e != nil || locked.Before(floor) || !locked.Before(until) {
		return zero, ErrInstall
	}
	current, e := s.current(ctx, tx, false)
	if e != nil || current.cas != before.cas {
		return zero, ErrInstall
	}
	imports := []a.OriginalRuntimeCapabilityImport{{Raw: files["generate.capability.json"], Pin: result.Generate, Operation: kms.Generate}, {Raw: files["unwrap.capability.json"], Pin: result.Unwrap, Operation: kms.Unwrap}, {Raw: files["publisher-unwrap.capability.json"], Pin: result.PublisherUnwrap, Operation: kms.Unwrap}}
	if writer.StageEnabledRuntimeCapabilities(ctx, tx, mappingRaw, mappingSignature, imports, lineage, oldBinding.ConfigSHA256, g.ConfigSHA256, result.FormalWorkload, publisherWorkload, locked) != nil {
		return zero, ErrInstall
	}
	tail, e := s.lockAdmin(ctx, tx)
	if e != nil || tail.Before(locked) || !tail.Before(until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	if tx.Commit() != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	originalRaw, originalSignature, e := (a.SQLOriginalReader{DB: i.db}).ReadOriginal(ctx, target.InstallationID, result.Binding.ConfigRef)
	if e != nil || !bytes.Equal(originalRaw, mappingRaw) || !bytes.Equal(originalSignature, mappingSignature) {
		return zero, a.ErrAuthorityCommitUnknown
	}
	if _, e = caps.PrepareCapabilities(ctx, result.Binding); e != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	publisherCaps, e := a.NewSQLProviderCapabilityPreparation(runtimeDB, database, target.InstallationID, result.Generate, result.PublisherUnwrap)
	if e != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	if _, e = publisherCaps.PrepareCapabilities(ctx, result.Binding); e != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	if recheck() != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	result.State = "enabled_native_capabilities_committed_readback_verified"
	committed, e := canonical(result)
	if e != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"enabled-provider-authorities-committed.json": committed}) != nil || recheck() != nil {
		return zero, a.ErrAuthorityCommitUnknown
	}
	return i.QueryOriginalEnabledRuntimeProviderAuthorities(ctx, runtimeDB, password, enrollment, BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "enabled-provider.material.json"), SHA256: hash(manifestRaw)})
}
