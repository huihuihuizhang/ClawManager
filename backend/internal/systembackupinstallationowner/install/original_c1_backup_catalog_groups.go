package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"time"
)

type originalC1BackupKEKInputs struct{ Observer, Record, Signature, RuntimeIssuers BootstrapSourceFilePin }
type originalC1CatalogCheckpointInputs struct{ Version, EnvelopeFile, EnvelopeSHA256, DefinitionSHA256, Bucket, Key, VersionID string }

func (p *OriginalC1Production) newBackupKEKObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var inputs originalC1BackupKEKInputs
	if err != nil || decodeExact(raw, &inputs) != nil {
		return nil, ErrInstall
	}
	issuers, err := p.operator.installer.readOriginalRuntimeIssuerMaterial(inputs.RuntimeIssuers, p.enrollment)
	if err != nil {
		return nil, err
	}
	issuer, err := readBootstrapSourcePin(issuers.Issuers["installation_mapping"].PublicKey, 32)
	if err != nil {
		return nil, ErrInstall
	}
	record, err := readBootstrapSourcePin(inputs.Record, 65536)
	if err != nil {
		return nil, ErrInstall
	}
	signature, err := readBootstrapSourcePin(inputs.Signature, 64)
	if err != nil {
		return nil, ErrInstall
	}
	original, err := a.InspectOriginalCurrentMapping(record, signature, issuer, time.Now().UTC())
	if err != nil {
		return nil, ErrInstall
	}
	raw, err = readBootstrapSourcePin(inputs.Observer, 262144)
	var cfg a.VaultPermissionObserverConfig
	if err != nil || decodeExact(raw, &cfg) != nil || !reflect.DeepEqual(cfg.Binding, original.Binding) || cfg.Binding.InstallationID != string(p.domain.Scope.Installation) || cfg.Publisher.Namespace != n.actor.Namespace || cfg.Publisher.ServiceAccountUID != n.actor.ServiceAccountUID || cfg.Publisher.PodUID != n.actor.PodUID || cfg.Worker.Namespace != n.actor.Namespace {
		return nil, ErrInstall
	}
	worker, err := p.operator.installer.kube.CoreV1().ServiceAccounts(cfg.Worker.Namespace).Get(ctx, cfg.Worker.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(worker.UID) != cfg.Worker.ServiceAccountUID || worker.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	ref := sec.BootstrapSecretRef{Purpose: "kek", IdentityHash: cfg.Binding.ConfigRef.IdentityHash, Version: cfg.Binding.ConfigRef.Version}
	found := false
	for _, actual := range p.request.config.References() {
		if actual.Purpose == ref.Purpose {
			if actual != ref {
				return nil, ErrInstall
			}
			found = true
		}
	}
	if !found {
		return nil, ErrInstall
	}
	native, err := a.NewVaultPermissionObserver(cfg)
	if err != nil {
		return nil, err
	}
	n.kind = "backup-kek-original-signed-native-permissions"
	n.backup = native
	n.backupWire = &inputs
	n.backupRecord = record
	n.backupSignature = signature
	n.groupSource = pin
	n.references = []sec.BootstrapSecretRef{ref}
	n.groupCodes = []string{"identity_scope", "version_retention"}
	if original.Until.Before(n.until) {
		n.until = original.Until
	}
	if err = n.bindGroupTarget([]pd.ID{"kek"}); err != nil {
		native.Close()
		return nil, err
	}
	n.target.Role = "kms"
	// Explicitly distinguish initial owner source absence from a present signed
	// source; a revoked/different current row is NEVER treated as first install.
	var stored, storedSig []byte
	err = p.operator.installer.db.QueryRowContext(ctx, "SELECT signed_record,signature FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=?", refScope(n), ref.IdentityHash, ref.Version).Scan(&stored, &storedSig)
	if err == nil {
		if !bytes.Equal(stored, record) || !bytes.Equal(storedSig, signature) {
			native.Close()
			return nil, ErrInstall
		}
		n.backupStored = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		native.Close()
		return nil, ErrInstall
	}
	return n, nil
}
func refScope(n *originalC1NativeObservation) string {
	return string(n.parent.domain.Scope.Installation)
}
func (n *originalC1NativeObservation) lockOriginalReference(ctx context.Context, tx pd.ReadSQL) error {
	if n.kind != "backup-kek-original-signed-native-permissions" {
		return nil
	}
	if n.backupWire == nil || len(n.references) != 1 {
		return ErrInstall
	}
	ref := n.references[0]
	var raw, signature []byte
	err := tx.QueryRowContext(ctx, "SELECT signed_record,signature FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR SHARE", refScope(n), ref.IdentityHash, ref.Version).Scan(&raw, &signature)
	if !n.backupStored {
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrInstall
		}
		return nil
	}
	if err != nil || !bytes.Equal(raw, n.backupRecord) || !bytes.Equal(signature, n.backupSignature) {
		return ErrInstall
	}
	return nil
}
func (p *OriginalC1Production) newCatalogCheckpointObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin, minioPin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newMinIOReferenceObservation(ctx, in, minioPin)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 65536)
	var location originalC1CatalogCheckpointInputs
	if err != nil || decodeExact(raw, &location) != nil || location.Version != "original-catalog-initial-inventory-location.v1" || location.DefinitionSHA256 != minioPin.SHA256 {
		return nil, ErrInstall
	}
	envelopePin := BootstrapSourceFilePin{File: location.EnvelopeFile, SHA256: location.EnvelopeSHA256}
	raw, err = readBootstrapSourcePin(envelopePin, 4096)
	var signed SignedCatalogInitialInventory
	if err != nil || decodeExact(raw, &signed) != nil {
		return nil, ErrInstall
	}
	record, err := InspectCatalogInitialInventory(signed, p.operator.installer.public)
	if err != nil || record.DefinitionSHA256 != minioPin.SHA256 || record.ConfigSHA256 != p.request.config.SHA256() || record.Installation != string(p.domain.Scope.Installation) || record.NamespaceUID != n.actor.NamespaceUID || record.Bucket != location.Bucket || record.Key != location.Key || time.Now().Before(record.CapturedAt) {
		return nil, ErrInstall
	}
	var definition MinIOPermissionDefinition
	definitionRaw, err := readBootstrapSourcePin(minioPin, 262144)
	if err != nil || decodeExact(definitionRaw, &definition) != nil {
		return nil, ErrInstall
	}
	providerRaw, err := canonical(struct {
		Provider     MinIOPermissionProvider
		Bucket, Root string
	}{definition.Grant.Provider, record.Bucket, record.Root})
	if err != nil || hash(providerRaw) != record.ProviderSHA256 {
		return nil, ErrInstall
	}
	found := false
	for _, ref := range p.request.config.References() {
		if ref.Purpose == "catalog_snapshot" {
			if ref != record.Reference {
				return nil, ErrInstall
			}
			found = true
		}
	}
	if !found {
		return nil, ErrInstall
	}
	n.kind = "catalog-original-immutable-initial-checkpoint"
	n.catalog = &location
	n.catalogEnvelope = raw
	n.groupSource = pin
	n.fiveFiles = append(n.fiveFiles, minioPin, envelopePin)
	n.references = []sec.BootstrapSecretRef{record.Reference}
	if record.Until.Before(n.until) {
		n.until = record.Until
	}
	if err = n.bindGroupTarget([]pd.ID{"catalog"}); err != nil {
		return nil, err
	}
	return n, nil
}
func (p *OriginalC1Production) ProduceOriginalC1BackupKEK(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newBackupKEKObservation(ctx, in, definition)
	if err != nil {
		return nil, err
	}
	defer n.backup.Close()
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
func (p *OriginalC1Production) ProduceOriginalC1CatalogCheckpoint(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition, minio BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newCatalogCheckpointObservation(ctx, in, definition, minio)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
