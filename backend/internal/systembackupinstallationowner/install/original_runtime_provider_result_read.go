package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"reflect"

	a "clawreef/internal/systembackupkekadapter"
	kms "clawreef/internal/systembackupkms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Read the ORIGINAL immutable pending result, not a caller-built replacement.
// Every scope/key/file is reauthenticated from the signed installation source
// and fixed D manifest. Only inert result State/SQLMetadataReceipt are filled.
func (i *Installer) readOriginalRuntimeProviderResult(ctx context.Context, enrollment EnrollmentPin, pending, metadata BootstrapSourceFilePin, receipt originalRuntimeSQLMetadataReceipt) (OriginalRuntimeProviderIssueReceipt, error) {
	var zero OriginalRuntimeProviderIssueReceipt
	directory := filepath.Dir(metadata.File)
	if filepath.Dir(pending.File) != directory || filepath.Base(pending.File) != "runtime-provider-authorities.json" || filepath.Base(metadata.File) != "runtime-installed-metadata.receipt.json" {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(pending, 262144)
	var result OriginalRuntimeProviderIssueReceipt
	if e != nil || decodeExact(raw, &result) != nil || result.Version != "original-runtime-provider-authorities-result.v1" || result.State != "material_issued_sql_install_pending" || result.SQLMetadataReceipt != (BootstrapSourceFilePin{}) {
		return zero, ErrInstall
	}
	material, e := i.readOriginalRuntimeIssuerMaterial(receipt.Issuers, enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	public := func(purpose string) (ed25519.PublicKey, error) {
		raw, e := readBootstrapSourcePin(material.Issuers[purpose].PublicKey, 32)
		return ed25519.PublicKey(raw), e
	}
	mappingPublic, e := public("installation_mapping")
	if e != nil {
		return zero, ErrInstall
	}
	formalPublic, e := public("formal_verifier")
	if e != nil {
		return zero, ErrInstall
	}
	businessPublic, e := public("provider_permit_business")
	if e != nil {
		return zero, ErrInstall
	}
	deliveryPublic, e := public("provider_permit_delivery")
	if e != nil {
		return zero, ErrInstall
	}
	var mapping a.OriginalRecord
	if json.Unmarshal(receipt.Snapshot.MappingRecord, &mapping) != nil || !reflect.DeepEqual(result.Binding, mapping.Binding) || result.Database != receipt.Snapshot.Database || result.MappingSource != mapping.Source || !bytes.Equal(result.InstallationIssuer, mappingPublic) {
		return zero, ErrInstall
	}
	check := func(pin BootstrapSourceFilePin, name string, want []byte) error {
		if pin.File != filepath.Join(directory, name) || pin.SHA256 != hash(want) {
			return ErrInstall
		}
		actual, e := readBootstrapSourcePin(pin, 262144)
		if e != nil || !bytes.Equal(actual, want) {
			return ErrInstall
		}
		return nil
	}
	if check(result.MappingRecord, "mapping.record.json", receipt.Snapshot.MappingRecord) != nil || check(result.MappingSignature, "mapping.signature", receipt.Snapshot.MappingSignature) != nil {
		return zero, ErrInstall
	}
	capsByID := map[string]a.OriginalRuntimeCapabilityImport{}
	for _, cap := range receipt.Snapshot.Capabilities {
		capsByID[cap.Pin.Source.RecordID] = cap
	}
	for _, item := range []struct {
		pin       a.ProviderCapabilityPin
		file      BootstrapSourceFilePin
		name      string
		operation kms.Operation
	}{{result.Generate, result.GenerateFile, "generate.capability.json", kms.Generate}, {result.Unwrap, result.UnwrapFile, "unwrap.capability.json", kms.Unwrap}, {result.PublisherUnwrap, result.PublisherUnwrapFile, "publisher-unwrap.capability.json", kms.Unwrap}} {
		original, exists := capsByID[item.pin.Source.RecordID]
		if !exists || original.Operation != item.operation || !reflect.DeepEqual(original.Pin, item.pin) || check(item.file, item.name, original.Raw) != nil {
			return zero, ErrInstall
		}
		delete(capsByID, item.pin.Source.RecordID)
	}
	if len(capsByID) != 0 || result.FormalGrant.File != filepath.Join(directory, "formal-verifier.grant.json") || !bytes.Equal(result.FormalGrant.Issuer, formalPublic) || result.PermitGrant.File != filepath.Join(directory, "provider-permit.grant.json") || !bytes.Equal(result.PermitGrant.Issuer, businessPublic) || result.PermitSigningKeyFile != material.Issuers["provider_permit_delivery"].PrivateKey.File || !kms.ValidPermitDeliveryPin(result.DeliveryPin) || !bytes.Equal(result.DeliveryPin.Issuer, deliveryPublic) || result.DeliveryPin.IssuerGrantSHA256 != result.PermitGrant.SHA256 {
		return zero, ErrInstall
	}
	formalRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: result.FormalGrant.File, SHA256: result.FormalGrant.SHA256}, 65536)
	var signed a.SignedControllerVerifierGrant
	var formal a.ControllerVerifierGrant
	if e != nil || decodeExact(formalRaw, &signed) != nil || !ed25519.Verify(formalPublic, append([]byte(a.ControllerVerifierGrantDomain), signed.Record...), signed.Signature) || decodeExact(signed.Record, &formal) != nil || formal.Database != result.Database || formal.InstallationID != i.plan.Target.InstallationID || formal.DatabaseAccount == i.plan.Target.DatabaseAccount || formal.DatabaseAccount == i.plan.InstallerDatabaseAccount {
		return zero, ErrInstall
	}
	caps, e := a.NewSQLProviderCapabilityPreparation(i.db, result.Database, i.plan.Target.InstallationID, result.Generate, result.Unwrap)
	if e != nil {
		return zero, ErrInstall
	}
	if a.InspectOriginalRuntimeGrantMaterials(ctx, result.FormalGrant, result.FormalWorkload, i.plan.Target.InstallationID, formal.CaptureGrantSHA256, result.Database, a.ProviderPermitIssuerConfig{Capabilities: caps, Binding: result.Binding, Workload: result.PermitWorkload, GrantMount: result.PermitGrant, SigningKeyFile: result.PermitSigningKeyFile, CaptureGrantSHA256: formal.CaptureGrantSHA256}) != nil {
		return zero, ErrInstall
	}
	var generateRecord, unwrapRecord, publisherRecord a.ProviderCapabilityRecord
	for _, cap := range receipt.Snapshot.Capabilities {
		var envelope a.SignedProviderCapabilityRecord
		if json.Unmarshal(cap.Raw, &envelope) != nil {
			return zero, ErrInstall
		}
		var record a.ProviderCapabilityRecord
		if json.Unmarshal(envelope.Record, &record) != nil {
			return zero, ErrInstall
		}
		switch cap.Pin.Source.RecordID {
		case result.Generate.Source.RecordID:
			generateRecord = record
		case result.Unwrap.Source.RecordID:
			unwrapRecord = record
		case result.PublisherUnwrap.Source.RecordID:
			publisherRecord = record
		}
	}
	if unwrapRecord.Facts.Permission.ControllerVerifier == nil || *unwrapRecord.Facts.Permission.ControllerVerifier != result.FormalWorkload || publisherRecord.Facts.Permission.ControllerVerifier == nil {
		return zero, ErrInstall
	}
	publicWorkload := result.FormalWorkload
	publicWorkload.ControllerOwner = "public:" + publicWorkload.PodUID
	publicWorkload.GrantSHA256 = publisherRecord.Facts.Permission.ControllerVerifier.GrantSHA256
	if !digestPattern.MatchString(publicWorkload.GrantSHA256) || *publisherRecord.Facts.Permission.ControllerVerifier != publicWorkload {
		return zero, ErrInstall
	}
	permitRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: result.PermitGrant.File, SHA256: result.PermitGrant.SHA256}, 65536)
	var permitEnvelope a.SignedProviderPermitIssuerGrant
	var permit a.ProviderPermitIssuerGrant
	if e != nil || decodeExact(permitRaw, &permitEnvelope) != nil || decodeExact(permitEnvelope.Record, &permit) != nil || !reflect.DeepEqual(permit.GeneratePermission, generateRecord.Facts.Permission) || permit.DatabaseAccount != formal.DatabaseAccount || permit.Database != formal.Database || permit.Workload != formal.Workload || !bytes.Equal(permit.SigningPublicKey, deliveryPublic) {
		return zero, ErrInstall
	}
	worker, e := i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Get(ctx, permit.WorkerServiceAccountName, metav1.GetOptions{})
	if e != nil || string(worker.UID) != permit.WorkerServiceAccountUID || worker.DeletionTimestamp != nil || permit.WorkerNamespace != i.plan.Target.Namespace {
		return zero, ErrInstall
	}
	// Actual original Pod chain remains the same; this neither reinstates a
	// missing holder nor treats the query as current task/provider authority.
	w := result.FormalWorkload
	pod, e := i.kube.CoreV1().Pods(i.plan.Target.Namespace).Get(ctx, w.PodName, metav1.GetOptions{})
	if e != nil || len(pod.OwnerReferences) != 1 {
		return zero, ErrInstall
	}
	rs, e := i.kube.AppsV1().ReplicaSets(i.plan.Target.Namespace).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if e != nil || len(rs.OwnerReferences) != 1 {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, rs.OwnerReferences[0].Name, w.PodName)
	if e != nil || actor.Namespace != w.Namespace || actor.PodUID != w.PodUID || actor.ServiceAccountName != w.ServiceAccountName || actor.ServiceAccountUID != w.ServiceAccountUID || string(rs.OwnerReferences[0].UID) != w.OwnerUID || w.OwnerKind != "Deployment" {
		return zero, ErrInstall
	}
	result.SQLMetadataReceipt = metadata
	result.State = "original_authority_and_capabilities_committed_readback_verified"
	return result, nil
}
