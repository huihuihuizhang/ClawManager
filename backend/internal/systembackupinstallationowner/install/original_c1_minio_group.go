package install

import (
	ev "clawreef/internal/systembackupevidence"
	ma "clawreef/internal/systembackupminioauthority"
	pd "clawreef/internal/systembackupproducer"
	probe "clawreef/internal/systembackupreferenceprobe"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"time"
)

// Fixed wire DATA mirrors of original producer outputs; no authority methods.
type originalC1ArtifactTarget struct {
	Version                string `json:"schema_version"`
	InstallationID         string `json:"installation_id"`
	Endpoint               string `json:"endpoint"`
	Region                 string `json:"region"`
	Bucket                 string `json:"bucket"`
	Root                   string `json:"root"`
	RemoteStagingRoot      string `json:"remote_staging_root,omitempty"`
	ReadIdentityHash       string `json:"read_identity_hash"`
	ReadRefVersion         string `json:"read_ref_version"`
	WriteIdentityHash      string `json:"write_identity_hash"`
	WriteRefVersion        string `json:"write_ref_version"`
	CAIdentityHash         string `json:"ca_identity_hash"`
	CARefVersion           string `json:"ca_ref_version"`
	CAFile                 string `json:"ca_file"`
	CASHA256               string `json:"ca_sha256"`
	ReadCredentialFile     string `json:"read_credential_file"`
	ReadCredentialSHA256   string `json:"read_credential_sha256"`
	WriteCredentialFile    string `json:"write_credential_file"`
	WriteCredentialSHA256  string `json:"write_credential_sha256"`
	DeleteIdentityHash     string `json:"delete_identity_hash,omitempty"`
	DeleteRefVersion       string `json:"delete_ref_version,omitempty"`
	DeleteCredentialFile   string `json:"delete_credential_file,omitempty"`
	DeleteCredentialSHA256 string `json:"delete_credential_sha256,omitempty"`
	CatalogMaterialsFile   string `json:"catalog_materials_file,omitempty"`
	CatalogMaterialsSHA256 string `json:"catalog_materials_sha256,omitempty"`
}
type originalC1CatalogTarget struct {
	Version                string `json:"schema_version"`
	InstallationID         string `json:"installation_id"`
	Endpoint               string `json:"endpoint"`
	Region                 string `json:"region"`
	Bucket                 string `json:"bucket"`
	Root                   string `json:"root"`
	ReadIdentityHash       string `json:"catalog_read_identity_hash"`
	ReadRefVersion         string `json:"catalog_read_ref_version"`
	AppendIdentityHash     string `json:"catalog_append_identity_hash"`
	AppendRefVersion       string `json:"catalog_append_ref_version"`
	CAIdentityHash         string `json:"ca_identity_hash"`
	CARefVersion           string `json:"ca_ref_version"`
	CAFile                 string `json:"ca_file"`
	CASHA256               string `json:"ca_sha256"`
	ReadCredentialFile     string `json:"read_credential_file"`
	ReadCredentialSHA256   string `json:"read_credential_sha256"`
	AppendCredentialFile   string `json:"append_credential_file"`
	AppendCredentialSHA256 string `json:"append_credential_sha256"`
}

func (p *OriginalC1Production) newMinIOReferenceObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	d, err := DecodeMinIOPermissionDefinition(raw, pin.SHA256)
	if err != nil || d.Grant.Profile != ma.SeptemberPermissionProfile || d.ConfigSHA256 != p.request.config.SHA256() || d.Grant.Installation != string(p.domain.Scope.Installation) || d.Grant.Namespace != n.actor.Namespace || d.Grant.NamespaceUID != n.actor.NamespaceUID || time.Now().Before(d.Grant.NotBefore) {
		return nil, ErrInstall
	}
	targetPin := BootstrapSourceFilePin{File: d.TargetFile, SHA256: d.TargetSHA256}
	raw, err = readBootstrapSourcePin(targetPin, 65536)
	var t originalC1ArtifactTarget
	if err != nil || decodeExact(raw, &t) != nil || t.Version != "system-backup-native-publication-s3.v1" || t.InstallationID != d.Grant.Installation || t.Root != d.Grant.Installation+"/" || t.RemoteStagingRoot == "" {
		return nil, ErrInstall
	}
	catalogPin := BootstrapSourceFilePin{File: t.CatalogMaterialsFile, SHA256: t.CatalogMaterialsSHA256}
	raw, err = readBootstrapSourcePin(catalogPin, 65536)
	var c originalC1CatalogTarget
	if err != nil || decodeExact(raw, &c) != nil || c.Version != "system-backup-native-catalog-s3.v1" || c.InstallationID != t.InstallationID || c.Endpoint != t.Endpoint || c.Region != t.Region || c.Bucket == t.Bucket || c.Root != t.InstallationID+"/catalog/" || c.CAIdentityHash != t.CAIdentityHash || c.CARefVersion != t.CARefVersion || c.CAFile != t.CAFile || c.CASHA256 != t.CASHA256 {
		return nil, ErrInstall
	}
	providerRaw, err := canonical(d.Grant.Provider)
	if err != nil {
		return nil, ErrInstall
	}
	var provider probe.MinIOProvider
	if decodeExact(providerRaw, &provider) != nil || provider.Endpoint != t.Endpoint || provider.Region != t.Region || provider.CAFile != t.CAFile || provider.CASHA256 != t.CASHA256 {
		return nil, ErrInstall
	}
	profile := probe.OriginalFiveProfile{Version: "original-five-minio-reference-profile.v1", Installation: d.Grant.Installation, Namespace: d.Grant.Namespace, NamespaceUID: d.Grant.NamespaceUID, Provider: provider, Observer: probe.Principal{Purpose: "metadata_observer", AccountSHA256: d.ObserverAccountSHA256, PolicyName: d.ObserverPolicyName, PolicySHA256: d.ObserverPolicySHA256, Credential: probe.FilePin{File: d.ObserverCredentialFile, SHA256: d.ObserverCredentialSHA256}}}
	wanted := map[string]struct{ identity, version, file, sha, bucket, root, staging string }{
		"artifact_read":   {t.ReadIdentityHash, t.ReadRefVersion, t.ReadCredentialFile, t.ReadCredentialSHA256, t.Bucket, t.Root, t.RemoteStagingRoot},
		"artifact_write":  {t.WriteIdentityHash, t.WriteRefVersion, t.WriteCredentialFile, t.WriteCredentialSHA256, t.Bucket, t.Root, t.RemoteStagingRoot},
		"artifact_delete": {t.DeleteIdentityHash, t.DeleteRefVersion, t.DeleteCredentialFile, t.DeleteCredentialSHA256, t.Bucket, t.Root, t.RemoteStagingRoot},
		"catalog_read":    {c.ReadIdentityHash, c.ReadRefVersion, c.ReadCredentialFile, c.ReadCredentialSHA256, c.Bucket, c.Root, ""},
		"catalog_append":  {c.AppendIdentityHash, c.AppendRefVersion, c.AppendCredentialFile, c.AppendCredentialSHA256, c.Bucket, c.Root, ""},
	}
	refs := []sec.BootstrapSecretRef{}
	for _, principal := range d.Grant.Principals {
		w, ok := wanted[principal.Purpose]
		if !ok || principal.IdentityHash != w.identity || principal.RefVersion != w.version {
			return nil, ErrInstall
		}
		ref := sec.BootstrapSecretRef{Purpose: principal.Purpose, IdentityHash: w.identity, Version: w.version}
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
		refs = append(refs, ref)
		profile.Principals = append(profile.Principals, probe.OriginalFivePrincipal{Principal: probe.Principal{Purpose: principal.Purpose, AccountSHA256: principal.AccountSHA256, PolicyName: principal.PolicyName, PolicySHA256: principal.PolicySHA256, Credential: probe.FilePin{File: w.file, SHA256: w.sha}}, Bucket: w.bucket, Root: w.root, Staging: w.staging})
	}
	ca := sec.BootstrapSecretRef{Purpose: "artifact_ca", IdentityHash: t.CAIdentityHash, Version: t.CARefVersion}
	found := false
	for _, actual := range p.request.config.References() {
		if actual.Purpose == ca.Purpose {
			if actual != ca {
				return nil, ErrInstall
			}
			found = true
		}
	}
	if !found || probe.ValidateOriginalFiveProfile(profile) != nil {
		return nil, ErrInstall
	}
	refs = append(refs, ca)
	n.kind = "minio-five-current-permissions-and-artifact-ca"
	n.five = &profile
	n.fiveFiles = []BootstrapSourceFilePin{targetPin, catalogPin}
	n.groupSource = pin
	n.references = refs
	if d.Grant.Until.Before(n.until) {
		n.until = d.Grant.Until
	}
	if err = n.bindGroupTarget([]pd.ID{"artifact_credential", "ca", "catalog"}); err != nil {
		return nil, err
	}
	return n, nil
}
func (p *OriginalC1Production) ProduceOriginalC1MinIOReferences(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newMinIOReferenceObservation(ctx, in, definition)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
