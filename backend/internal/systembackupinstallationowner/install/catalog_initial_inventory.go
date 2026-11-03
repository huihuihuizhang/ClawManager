package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

const CatalogInitialInventoryVersion = "original-catalog-initial-empty-inventory.v1"
const catalogInitialInventoryDomain = CatalogInitialInventoryVersion + "\x00"

// An original bootstrap CHECKPOINT at CapturedAt, not a current catalog head
// or an artifact_registered record. The independently enrolled issuer attests
// its provenance. No publication/task/signing-success claim belongs here.
type CatalogInitialInventory struct {
	Version, Mode, DefinitionSHA256, ConfigSHA256, Installation, NamespaceUID string
	Reference                                                                 sec.BootstrapSecretRef
	ProviderSHA256, Bucket, Root, CoveragePrefix, Key, ScanSHA256             string
	Count                                                                     uint64
	CapturedAt, NotBefore, Until                                              time.Time
}
type SignedCatalogInitialInventory struct {
	Record    []byte
	Signature []byte
}

func validCatalogInitialInventory(r CatalogInitialInventory) bool {
	return r.Version == CatalogInitialInventoryVersion && r.Mode == "inventory_manifest_initial_checkpoint" && r.Count == 0 && r.Reference.Purpose == "catalog_snapshot" && digestPattern.MatchString(r.Reference.IdentityHash) && r.Reference.Version != "" && r.Reference.Version != "latest" && r.Reference.Version != "current" && r.Reference.Version != "default" && digestPattern.MatchString(r.DefinitionSHA256) && digestPattern.MatchString(r.ConfigSHA256) && digestPattern.MatchString(r.ProviderSHA256) && digestPattern.MatchString(r.ScanSHA256) && r.Installation != "" && r.NamespaceUID != "" && r.Bucket != "" && r.Root == r.Installation+"/catalog/" && r.CoveragePrefix == r.Root && !r.NotBefore.IsZero() && !r.CapturedAt.IsZero() && !r.CapturedAt.Before(r.NotBefore) && r.CapturedAt.Before(r.Until) && r.Until.Sub(r.NotBefore) <= 24*time.Hour && r.Key == CatalogInitialInventoryKey(r.DefinitionSHA256, r.Reference, r.Root)
}
func CatalogInitialInventoryKey(definitionSHA string, ref sec.BootstrapSecretRef, root string) string {
	raw, _ := canonical([]string{CatalogInitialInventoryVersion, definitionSHA, ref.IdentityHash, ref.Version})
	return root + "initial-inventory/" + hash(raw) + ".json"
}

// Called only after concrete native scans by the operator command. This is an
// authenticated original source attestation, not a generic catalog signer and
// not proof that a remotely supplied scan digest is itself sufficient.
func (p *MinIOPermissionIssuer) SignCatalogInitialInventory(ctx context.Context, r CatalogInitialInventory, issuerPrivate []byte) (SignedCatalogInitialInventory, error) {
	var zero SignedCatalogInitialInventory
	if p == nil || p.Recheck(ctx) != nil || !validCatalogInitialInventory(r) || r.DefinitionSHA256 != p.sha || r.ConfigSHA256 != p.definition.ConfigSHA256 || r.Installation != p.definition.Grant.Installation || r.NamespaceUID != p.definition.Grant.NamespaceUID || !r.NotBefore.Equal(p.definition.Grant.NotBefore) || r.Until.After(p.definition.Grant.Until) || time.Now().Before(r.CapturedAt) || !time.Now().Before(r.Until) {
		return zero, ErrInstall
	}
	raw, e := ReadSourceMaterialFile(p.definition.ConfigFile)
	if e != nil || hash(raw) != r.ConfigSHA256 {
		return zero, ErrInstall
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	found := false
	if e != nil {
		return zero, ErrInstall
	}
	for _, ref := range config.References() {
		if ref == r.Reference {
			found = true
		}
	}
	if !found {
		return zero, ErrInstall
	}
	key, e := p.operator.privateKey(issuerPrivate)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	raw, e = canonical(r)
	if e != nil || len(raw) > 4096 || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	return SignedCatalogInitialInventory{raw, ed25519.Sign(key, append([]byte(catalogInitialInventoryDomain), raw...))}, nil
}

func InspectCatalogInitialInventory(s SignedCatalogInitialInventory, public ed25519.PublicKey) (CatalogInitialInventory, error) {
	var r CatalogInitialInventory
	if len(s.Record) == 0 || len(s.Record) > 4096 || len(s.Signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize || decodeExact(s.Record, &r) != nil || !validCatalogInitialInventory(r) || !ed25519.Verify(public, append([]byte(catalogInitialInventoryDomain), s.Record...), s.Signature) {
		return CatalogInitialInventory{}, ErrInstall
	}
	normalized, e := canonical(r)
	if e != nil || !bytes.Equal(normalized, s.Record) {
		return CatalogInitialInventory{}, ErrInstall
	}
	return r, nil
}
