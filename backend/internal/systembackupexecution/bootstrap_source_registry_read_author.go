package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"

	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

type OriginalBootstrapReadInputs struct {
	SourceSelection, Config, Forward, Parts, SourceWriters, IssuerPublic install.BootstrapSourceFilePin
	OutputDirectory                                                      string
}

// ProduceOriginalBootstrapReadDefinition signs only the original controller's
// bootstrap metadata delegation. The full capture material path stays free for
// the independent worker mapping, grants, and ordinary runtime materializer.
func ProduceOriginalBootstrapReadDefinition(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, password []byte, enrollment install.EnrollmentPin, key []byte, in OriginalBootstrapReadInputs) (install.BootstrapSourceFilePin, error) {
	return produceOriginalBootstrapReadDefinition(ctx, owner, runtimeDB, password, enrollment, key, in, false)
}

// ProduceOriginalBootstrapReadDefinitionForMinIOMetadata selects the original
// pre-adoption metadata SQL owner for the same bounded delegation.
func ProduceOriginalBootstrapReadDefinitionForMinIOMetadata(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, password []byte, enrollment install.EnrollmentPin, key []byte, in OriginalBootstrapReadInputs) (install.BootstrapSourceFilePin, error) {
	return produceOriginalBootstrapReadDefinition(ctx, owner, runtimeDB, password, enrollment, key, in, true)
}

func produceOriginalBootstrapReadDefinition(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, password []byte, enrollment install.EnrollmentPin, key []byte, in OriginalBootstrapReadInputs, metadataOwner bool) (install.BootstrapSourceFilePin, error) {
	var zero install.BootstrapSourceFilePin
	if ctx == nil || owner == nil || runtimeDB == nil || len(key) != ed25519.PrivateKeySize || nativeInstallEmptyDirectory(in.OutputDirectory) != nil {
		return zero, install.ErrInstall
	}
	author, err := owner.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, in.SourceSelection.File, in.SourceSelection.SHA256)
	if err != nil {
		return zero, err
	}
	defer author.Close()
	selected, target, err := author.Selection(ctx)
	if err != nil {
		return zero, err
	}
	x, err := newBootstrapSourceAuthoringReader(ctx, author)
	if err != nil {
		return zero, err
	}
	cfg, m := x.config, x.materials
	p := m.Discovery
	pub, err := pinnedDeploymentFile(in.IssuerPublic.File, in.IssuerPublic.SHA256, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(pub, p.Issuer) || !bytes.Equal(pub, ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) || m.ControlEvidence != nil || m.ControlEvidenceSource != nil {
		return zero, install.ErrInstall
	}
	if in.Forward.File != cfg.ForwardGrant.Path || in.Parts.File != selected.PartsFile || in.SourceWriters.File != selected.SourceWritersFile {
		return zero, install.ErrInstall
	}
	for _, pin := range []install.BootstrapSourceFilePin{in.Parts, in.SourceWriters} {
		raw, err := pinnedDeploymentFile(pin.File, pin.SHA256, 262144)
		clear(raw)
		if err != nil {
			return zero, err
		}
	}
	cfgBytes, err := pinnedDeploymentFile(in.Config.File, in.Config.SHA256, 262144)
	if err != nil {
		return zero, err
	}
	bootstrap, err := sec.DecodeBootstrapConfig(cfgBytes)
	if err != nil {
		return zero, err
	}
	wantParts := sec.BootstrapRegistryRef{Kind: "parts", Version: selected.PartsVersion, SHA256: in.Parts.SHA256}
	wantWriters := sec.BootstrapRegistryRef{Kind: "source_writers", Version: selected.SourceWritersVersion, SHA256: in.SourceWriters.SHA256}
	var partsMatch, writersMatch bool
	for _, registry := range bootstrap.Registries() {
		partsMatch = partsMatch || registry == wantParts
		writersMatch = writersMatch || registry == wantWriters
	}
	forwardPublic, err := base64.StdEncoding.Strict().DecodeString(cfg.ForwardGrant.PublicKey)
	if err != nil || !partsMatch || !writersMatch {
		return zero, install.ErrInstall
	}
	forward, err := c.NewPinnedExecutionIdentity(in.Forward.File, in.Forward.SHA256, cfg.KeyDirectory, forwardPublic)
	if err != nil {
		return zero, err
	}
	g := forward.DeploymentBinding()
	_, profileSHA, err := x.profile.CanonicalIdentity()
	now := time.Now()
	if err != nil || g.ConfigVersion != 1 || g.ConfigSHA256 != bootstrap.SHA256() || g.ProfileSHA256 != profileSHA || g.InstallationID != target.InstallationID ||
		g.ServerUUID != target.ServerUUID || g.Database != target.Database || g.ControllerOwner != cfg.ControllerOwner ||
		g.DeploymentConfigSHA256 != selected.Deployment.SHA256 || !forwardCaptureActions(g) ||
		g.NotBefore.Before(selected.NotBefore) || now.Before(g.NotBefore) || !now.Before(g.ExpiresAt) || g.ExpiresAt.After(selected.Until) {
		return zero, install.ErrInstall
	}
	m.CaptureGrantSHA256 = in.Forward.SHA256
	materials := install.BootstrapSourceReadMaterialsPath(cfg.CaptureModules.Path)
	p.GrantFile = materials + ".grant.json"
	definition := filepath.Join(in.OutputDirectory, "bootstrap-source-v2.definition.json")
	if checkBootstrapSourceFactOutputs(materials, p.GrantFile) != nil {
		return zero, install.ErrInstall
	}
	scope, err := sourceMetadataScope(m)
	if err != nil {
		return zero, err
	}
	redisScope, err := producerWorkerScope(m, "capture-source-redis")
	if err != nil {
		return zero, err
	}
	objectScope, err := producerWorkerScope(m, "capture-skill-objects")
	if err != nil {
		return zero, err
	}
	intent := install.SourceMaterialIntent{
		DefinitionFile: in.SourceSelection.File, DefinitionSHA256: in.SourceSelection.SHA256,
		Purpose: "functional_test", InstallationID: cfg.InstallationID, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID,
		ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount,
		ConfigSHA256: g.ConfigSHA256, DeploymentConfigSHA256: selected.Deployment.SHA256, CaptureGrantSHA256: in.Forward.SHA256, ControllerOwner: cfg.ControllerOwner,
		ControllerDeployment: p.ControllerDeployment, ControllerDeploymentUID: p.ControllerDeploymentUID,
		ControllerServiceAccount: p.ControllerServiceAccount, ControllerServiceAccountUID: p.ControllerServiceAccountUID,
		SourceServiceAccount: p.SourceAPIServiceAccount, SourceServiceAccountUID: p.SourceAPIServiceAccountUID,
		WorkerServiceAccount: cfg.Security.ServiceAccountName, WorkerServiceAccountUID: cfg.Security.ServiceAccountUID,
		RedisScopeSHA256: redisScope, RedisCredentialSHA256: m.Redis.CredentialSHA256, ObjectScopeSHA256: objectScope, ObjectCredentialSHA256: m.Objects.CredentialSHA256,
		NotBefore: g.NotBefore, Until: g.ExpiresAt,
	}
	var signer *install.SourceMaterialIssuer
	signerCtx := ctx
	if metadataOwner {
		var closeScope context.CancelFunc
		signer, signerCtx, closeScope, err = owner.PrepareSourceMaterialIssueForMinIOMetadata(ctx, password, enrollment, intent, runtimeDB)
		if err == nil {
			defer closeScope()
		}
	} else {
		signer, err = owner.PrepareSourceMaterialIssue(ctx, password, enrollment, intent, runtimeDB)
	}
	if err != nil {
		return zero, err
	}
	signed, err := signer.SignControllerMetadata(signerCtx, install.ControllerSourceMetadataGrant{
		Version: sourceMetadataGrantVersion, InstallationID: intent.InstallationID, Namespace: intent.Namespace, NamespaceUID: intent.NamespaceUID,
		ConfigSHA256: intent.ConfigSHA256, DeploymentConfigSHA256: intent.DeploymentConfigSHA256, CaptureGrantSHA256: intent.CaptureGrantSHA256,
		ControllerOwner: intent.ControllerOwner, ControllerDeployment: intent.ControllerDeployment, ControllerDeploymentUID: intent.ControllerDeploymentUID,
		ControllerServiceAccount: intent.ControllerServiceAccount, ControllerServiceAccountUID: intent.ControllerServiceAccountUID,
		ScopeSHA256: scope, NotBefore: intent.NotBefore, Until: intent.Until,
	}, key)
	if err != nil {
		return zero, err
	}
	p.GrantSHA256 = hash(signed)
	if p.validate() != nil {
		return zero, install.ErrInstall
	}
	materialsRaw, err := json.Marshal(m)
	if err != nil {
		return zero, err
	}
	if check, err := install.BootstrapSourceMetadataScopeFromMaterials(materialsRaw); err != nil || check != scope {
		return zero, install.ErrInstall
	}
	d := install.BootstrapSourceRegistryV2Definition{
		SchemaVersion: install.BootstrapSourceRegistryV2Version, Profile: install.BootstrapSourceRegistryProfile, ApplicationScope: selected.ApplicationScope,
		MetadataGrant: install.BootstrapSourceFilePin{File: p.GrantFile, SHA256: p.GrantSHA256}, MetadataIssuerPublic: in.IssuerPublic,
		Deployment: selected.Deployment, ExecutionProfile: selected.ExecutionProfile, ForwardGrant: in.Forward,
		Materials: install.BootstrapSourceFilePin{File: materials, SHA256: hash(materialsRaw)}, PartsRegistry: in.Parts, SourceWritersRegistry: in.SourceWriters,
		Controller: selected.Controller, Connections: selected.Connections, RuntimeAgent: selected.RuntimeAgent,
	}
	for n := range d.Connections {
		connection := &d.Connections[n]
		connection.IdentitySHA256, err = install.BootstrapSourceConnectionIdentitySHA256(target.InstallationID, *connection)
		if err != nil {
			return zero, err
		}
		connection.ScopeSHA256, err = install.BootstrapSourceNativeRoleScopeSHA256(target.InstallationID, d, *connection, scope)
		if err != nil {
			return zero, err
		}
	}
	if d.RuntimeAgent != nil {
		d.RuntimeAgent.ScopeSHA256, err = install.BootstrapSourceAgentScopeSHA256(target.InstallationID, d)
		if err != nil {
			return zero, err
		}
	}
	raw, err := json.Marshal(d)
	if err != nil || signer.Recheck(signerCtx) != nil || author.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	for _, f := range []struct {
		name     string
		contents []byte
	}{{p.GrantFile, signed}, {materials, materialsRaw}, {definition, raw}} {
		if err := writeBootstrapSourceFactFile(f.name, f.contents); err != nil {
			return zero, err
		}
	}
	if signer.Recheck(signerCtx) != nil || author.RecheckAuthority(ctx) != nil {
		return zero, install.ErrInstall
	}
	return install.BootstrapSourceFilePin{File: definition, SHA256: hash(raw)}, nil
}
