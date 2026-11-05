package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	ma "clawreef/internal/systembackupminioauthority"
)

type OriginalMinIORuntimeMetadataInputs struct {
	Issuers, Core, OriginalForward, RecoveryDescriptor       BootstrapSourceFilePin
	ControllerDeployment, ControllerPodName, OutputDirectory string
}
type OriginalMinIORuntimeMetadataReceipt struct {
	State   string
	Consent BootstrapSourceFilePin
}
type originalMinIORuntimeMetadataInputs struct {
	operator      *authenticatedOperator
	descriptor    ma.MinIORecoveryDescriptor
	descriptorRaw []byte
	forward       *c.PinnedExecutionIdentity
	public        ed25519.PublicKey
	workload      ma.RuntimeMetadataWorkload
}

// Concrete original owner authentication; caller supplies only source locators.
func (i *Installer) originalMinIORuntimeMetadata(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalMinIORuntimeMetadataInputs) (originalMinIORuntimeMetadataInputs, error) {
	var z originalMinIORuntimeMetadataInputs
	s, e := i.authenticate(ctx, password)
	if e != nil || runtimeDB == nil || privateDirectory(in.OutputDirectory) != nil || s.authority(ctx, enrollment) != nil {
		return z, ErrInstall
	}
	material, e := i.readOriginalRuntimeIssuerMaterial(in.Issuers, enrollment)
	if e != nil {
		return z, ErrInstall
	}
	raw, e := readBootstrapSourcePin(in.Core, 262144)
	var core originalRuntimeCoreScope
	if e != nil || json.Unmarshal(raw, &core) != nil || core.InstallationID != i.plan.Target.InstallationID || core.Namespace != i.plan.Target.Namespace || core.NamespaceUID != i.plan.Target.NamespaceUID || core.Forward.Path != in.OriginalForward.File {
		return z, ErrInstall
	}
	public, e := readBootstrapSourcePin(material.Issuers["forward_execution"].PublicKey, 32)
	if e != nil || core.Forward.PublicKey != base64.StdEncoding.EncodeToString(public) {
		return z, ErrInstall
	}
	forward, e := c.NewPinnedExecutionIdentity(in.OriginalForward.File, in.OriginalForward.SHA256, core.KeyDirectory, public)
	if e != nil || forward.CheckDeployment(ctx, runtimeDB) != nil {
		return z, ErrInstall
	}
	g := forward.DeploymentBinding()
	t := i.plan.Target
	if g.InstallationID != t.InstallationID || g.ServerUUID != t.ServerUUID || g.Database != t.Database || g.DatabaseAccount == t.DatabaseAccount || g.DatabaseAccount == i.plan.InstallerDatabaseAccount || g.ConfigVersion != 1 || g.DeploymentConfigSHA256 != in.Core.SHA256 || g.ControllerOwner != core.ControllerOwner {
		return z, ErrInstall
	}
	if _, e = i.checkOriginalRuntimeSQLPeer(ctx, runtimeDB, g.DatabaseAccount); e != nil {
		return z, ErrInstall
	}
	raw, e = readBootstrapSourcePin(in.RecoveryDescriptor, 65536)
	if e != nil {
		return z, ErrInstall
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	if e != nil || s.minioSQLPin(ctx, enrollment, d.Pin) != nil {
		return z, ErrInstall
	}
	workload, e := ma.CollectRuntimeMetadataWorkload(ctx, i.kube, d.Pin.Target, in.ControllerDeployment, in.ControllerPodName, g.ControllerOwner)
	if e != nil {
		return z, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPodName)
	if e != nil || actor.PodUID != workload.Pod.UID || actor.ServiceAccountUID != workload.ServiceAccount.UID {
		return z, ErrInstall
	}
	return originalMinIORuntimeMetadataInputs{s, d, raw, forward, public, workload}, nil
}

// Consent alone does not provision SQL permissions or produce runtime readiness.
func (i *Installer) IssueOriginalMinIORuntimeMetadataRead(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalMinIORuntimeMetadataInputs, issuerPrivate []byte) (OriginalMinIORuntimeMetadataReceipt, error) {
	var zero OriginalMinIORuntimeMetadataReceipt
	ownerContext, close, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return zero, e
	}
	defer close()
	ctx = ownerContext
	source, e := i.originalMinIORuntimeMetadata(ctx, runtimeDB, password, enrollment, in)
	if e != nil {
		return zero, e
	}
	file := filepath.Join(in.OutputDirectory, "minio-runtime-metadata-consent.json")
	if _, e = os.Lstat(file); !os.IsNotExist(e) {
		return zero, ErrCommitUnknown
	}
	before, _, e := originalAdoptionAuthoritySnapshot(ctx, source.operator)
	if e != nil || before.cas.HeadRevision != 1 || before.cas.State != "active" {
		return zero, ErrInstall
	}
	first, e := readOriginalMinIORecoverySQL(ctx, source.operator, source.descriptor.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	expected, _, e := first.Comparison()
	if e != nil {
		return zero, ErrInstall
	}
	forward := source.forward.DeploymentBinding()
	// No Kube/provider callbacks occur after final original SQL locks begin.
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	if _, e = source.operator.lockAdmin(ctx, tx); e != nil {
		return zero, ErrInstall
	}
	head, e := source.operator.current(ctx, tx, false)
	if e != nil || head.cas != before.cas {
		return zero, ErrInstall
	}
	current, e := ma.ReadSQLCurrentForInstaller(ctx, tx, source.descriptor.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	actual, clock, e := current.Comparison()
	g, h, _, de := current.Declarations()
	if e != nil || de != nil || !reflect.DeepEqual(expected, actual) || current.RequireCurrent(clock) != nil || !minioSQLActor(source.operator, g) || g.Actor != source.descriptor.Actor || string(g.ConfigSHA256) != forward.ConfigSHA256 || string(g.ConfigSHA256) != head.record.ConfigSHA256 || clock.Before(head.head.NotBefore) || clock.Before(head.record.NotBefore) || !clock.Before(head.head.Until) || !clock.Before(head.record.Until) || clock.Before(forward.NotBefore) || !clock.Before(forward.ExpiresAt) {
		return zero, ErrInstall
	}
	until := minTime(g.Until, minTime(h.Until, minTime(head.head.Until, minTime(head.record.Until, forward.ExpiresAt))))
	pin, e := ma.RuntimeMetadataPinSHA256(source.descriptor.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	record := ma.RuntimeMetadataConsent{Version: ma.RuntimeMetadataConsentVersion, PinSHA256: pin, RecoveryDescriptorSHA256: ma.Digest(in.RecoveryDescriptor.SHA256), OriginalConfigSHA256: g.ConfigSHA256, OriginalForwardSHA256: ma.Digest(in.OriginalForward.SHA256), ForwardIssuer: source.public, RuntimeDatabaseAccount: forward.DatabaseAccount, Workload: source.workload, Actor: g.Actor, NotBefore: clock, Until: until, SignedAt: clock}
	body, e := canonical(record)
	if e != nil {
		return zero, ErrInstall
	}
	key, e := source.operator.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	raw, e := canonical(ma.SignedRuntimeMetadataConsent{Record: body, Signature: ed25519.Sign(key, append([]byte(ma.RuntimeMetadataConsentDomain), body...))})
	if e != nil {
		return zero, ErrInstall
	}
	if _, e = ma.DecodeRuntimeMetadataConsent(raw, source.descriptor, ma.Digest(in.RecoveryDescriptor.SHA256)); e != nil {
		return zero, ErrInstall
	}
	descriptor, e := readBootstrapSourcePin(in.RecoveryDescriptor, 65536)
	if e != nil || !bytes.Equal(descriptor, source.descriptorRaw) {
		return zero, ErrInstall
	}
	if _, e = readBootstrapSourcePin(in.OriginalForward, 65536); e != nil {
		return zero, ErrInstall
	}
	if writeOriginalRuntimeIssuerFiles(in.OutputDirectory, map[string][]byte{filepath.Base(file): raw}) != nil {
		return zero, ErrCommitUnknown
	}
	tail, e := i.database(ctx, tx, source.operator.until)
	if e != nil || tail.Before(clock) || !tail.Before(until) || current.RequireCurrent(tail) != nil {
		return zero, ErrCommitUnknown
	}
	if tx.Rollback() != nil {
		return zero, ErrCommitUnknown
	}
	return i.QueryOriginalMinIORuntimeMetadataRead(ctx, runtimeDB, password, enrollment, in)
}
func (i *Installer) QueryOriginalMinIORuntimeMetadataRead(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalMinIORuntimeMetadataInputs) (OriginalMinIORuntimeMetadataReceipt, error) {
	var zero OriginalMinIORuntimeMetadataReceipt
	ownerContext, close, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return zero, e
	}
	defer close()
	ctx = ownerContext
	source, e := i.originalMinIORuntimeMetadata(ctx, runtimeDB, password, enrollment, in)
	if e != nil {
		return zero, e
	}
	file := filepath.Join(in.OutputDirectory, "minio-runtime-metadata-consent.json")
	raw, e := ReadPrivateFile(file, 65536)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	record, e := ma.DecodeRuntimeMetadataConsent(raw, source.descriptor, ma.Digest(in.RecoveryDescriptor.SHA256))
	if e != nil || record.RuntimeDatabaseAccount != source.forward.DeploymentBinding().DatabaseAccount || record.Workload != source.workload || record.OriginalForwardSHA256 != ma.Digest(in.OriginalForward.SHA256) || !bytes.Equal(record.ForwardIssuer, source.public) {
		return zero, ErrCommitUnknown
	}
	head, _, e := originalAdoptionAuthoritySnapshot(ctx, source.operator)
	if e != nil || head.cas.HeadRevision != 1 || head.cas.State != "active" {
		return zero, ErrCommitUnknown
	}
	current, e := readOriginalMinIORecoverySQL(ctx, source.operator, source.descriptor.Pin)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	g, h, _, e := current.Declarations()
	_, now, ce := current.Comparison()
	if e != nil || ce != nil || current.RequireCurrent(now) != nil || now.Before(record.NotBefore) || !now.Before(record.Until) || record.Until.After(g.Until) || record.Until.After(h.Until) || record.Until.After(head.head.Until) || record.Until.After(head.record.Until) || record.Actor != g.Actor || record.OriginalConfigSHA256 != g.ConfigSHA256 {
		return zero, ErrCommitUnknown
	}
	again, e := ReadPrivateFile(file, 65536)
	if e != nil || !bytes.Equal(again, raw) {
		return zero, ErrCommitUnknown
	}
	return OriginalMinIORuntimeMetadataReceipt{State: "original_runtime_metadata_consent_exact_readback_sql_enrollment_not_proven", Consent: BootstrapSourceFilePin{File: file, SHA256: hash(raw)}}, nil
}
