package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"clawreef/internal/systembackup/domain"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

// A detached file receipt is not source authority or fresh terminal evidence.
// The final original config/capture/metadata/V2 signatures bind these exact
// files afterwards; the consumer independently repeats every native read.
type BootstrapSourceRegistryFactsReceipt struct {
	Version, SelectionSHA256             string
	PartsRegistry, SourceWritersRegistry install.BootstrapSourceFilePin
}

// ProduceOriginalBootstrapSourceRegistries is the PRE-config/PRE-capture
// authenticated action. It accepts no supplied facts, observation callback,
// enabled Forward, fake V2 identity, worker credential, task or success bit.
func ProduceOriginalBootstrapSourceRegistries(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA string) (_ BootstrapSourceRegistryFactsReceipt, resultErr error) {
	var zero BootstrapSourceRegistryFactsReceipt
	raw, err := install.ReadPrivateFile(selectionFile, 262144)
	var selected install.BootstrapSourceAuthoringSelection
	if err != nil || hash(raw) != selectionSHA || strictBootstrapSourceJSON(raw, &selected) != nil {
		return zero, install.ErrInstall
	}
	// Reject existing/aliased outputs BEFORE original authentication/SQL/native
	// reads. Writes below remain create-only even after this nonauthorizing check.
	if checkBootstrapSourceFactOutputs(selected.PartsFile, selected.SourceWritersFile) != nil {
		return zero, install.ErrInstall
	}
	authority, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionFile, selectionSHA)
	if err != nil {
		return zero, install.ErrInstall
	}
	defer authority.Close()
	x, err := newBootstrapSourceAuthoringReader(ctx, authority)
	if err != nil {
		return zero, install.ErrInstall
	}
	facts, err := x.collectBootstrapSourceFacts()
	if err != nil {
		return zero, install.ErrInstall
	}
	selection, target, err := authority.Selection(ctx)
	if err != nil {
		return zero, install.ErrInstall
	}
	parts := bootstrapSourcePartsRegistry{SchemaVersion: bootstrapSourcePartsVersion, Installation: target.InstallationID, Version: selection.PartsVersion, Parts: facts.parts, Source: facts.lastSQL.inventory, SQL: facts.lastSQL.metadata, Redis: facts.redis, Skills: facts.skills, Deployment: facts.deployment, Secrets: facts.secrets}
	writers := bootstrapSourceWritersRegistry{SchemaVersion: bootstrapSourceWritersVersion, Installation: target.InstallationID, Version: selection.SourceWritersVersion, ApplicationScope: selection.ApplicationScope, Participants: facts.participants, API: facts.lastAPI.objects, Bindings: facts.lastSQL.bindings, Pods: facts.lastSQL.pods, Native: facts.native}
	partsRaw, err := ce.Canonical(parts)
	if err != nil || len(partsRaw) > 262144 {
		return zero, install.ErrInstall
	}
	writersRaw, err := ce.Canonical(writers)
	if err != nil || len(writersRaw) > 262144 {
		return zero, install.ErrInstall
	}
	// No final metadata/config/grant/scope/self digest appears inside either
	// fact document. The dependency direction is facts -> final config/grants ->
	// V2 signature; there is no SHA fixed-point and no provisional V2 grant.
	for _, file := range []struct {
		path string
		raw  []byte
	}{{selection.PartsFile, partsRaw}, {selection.SourceWritersFile, writersRaw}} {
		if authority.RecheckAuthority(ctx) != nil || writeBootstrapSourceFactFile(file.path, file.raw) != nil {
			return zero, install.ErrInstall
		}
		actual, err := install.ReadPrivateFile(file.path, 262144)
		if err != nil || hash(actual) != hash(file.raw) || authority.RecheckAuthority(ctx) != nil {
			return zero, install.ErrInstall
		}
	}
	return BootstrapSourceRegistryFactsReceipt{Version: "original-source-registry-facts-receipt.v1", SelectionSHA256: selectionSHA, PartsRegistry: install.BootstrapSourceFilePin{File: selection.PartsFile, SHA256: hash(partsRaw)}, SourceWritersRegistry: install.BootstrapSourceFilePin{File: selection.SourceWritersFile, SHA256: hash(writersRaw)}}, nil
}

func checkBootstrapSourceFactOutputs(parts, writers string) error {
	directory := filepath.Dir(parts)
	if parts == writers || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Dir(writers) != directory {
		return install.ErrInstall
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return install.ErrInstall
	}
	defer root.Close()
	for _, p := range []string{parts, writers} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return install.ErrInstall
		}
		if _, err := root.Lstat(filepath.Base(p)); !os.IsNotExist(err) {
			return install.ErrInstall
		}
	}
	return nil
}

func writeBootstrapSourceFactFile(path string, raw []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return install.ErrInstall
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return install.ErrInstall
	}
	n, writeErr := f.Write(raw)
	if writeErr == nil && n == len(raw) {
		writeErr = f.Sync()
	} else if writeErr == nil {
		writeErr = install.ErrInstall
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return install.ErrInstall
	}
	return nil
}

func newBootstrapSourceAuthoringReader(ctx context.Context, authority *install.BootstrapSourceRegistryAuthoring) (*bootstrapSourceRegistryReader, error) {
	selection, target, err := authority.Selection(ctx)
	if err != nil {
		return nil, install.ErrInstall
	}
	x := &bootstrapSourceRegistryReader{ctx: ctx, access: authority, association: bootstrapSourceReadDeclaration{Target: target, NotBefore: selection.NotBefore, Until: selection.Until, Parts: sec.BootstrapRegistryRef{Kind: "parts", Version: selection.PartsVersion}, SourceWriters: sec.BootstrapRegistryRef{Kind: "source_writers", Version: selection.SourceWritersVersion}, Source: bootstrapSourceReadSelection{ApplicationScope: selection.ApplicationScope, Controller: selection.Controller, Connections: selection.Connections, RuntimeAgent: selection.RuntimeAgent}}}
	for _, field := range []struct {
		pin install.BootstrapSourceFilePin
		out any
	}{{selection.Deployment, &x.config}, {selection.MaterialsTemplate, &x.materials}, {selection.ExecutionProfile, &x.profile}} {
		raw, err := authority.Read(ctx, field.pin)
		if err != nil || strictBootstrapSourceJSON(raw, field.out) != nil {
			clear(raw)
			return nil, install.ErrInstall
		}
		clear(raw)
	}
	cfg, m := x.config, &x.materials
	// These are the original finite native selections, with final signing fields
	// deliberately absent. Do not inject placeholder hashes to pass an existing
	// post-capture metadata/Forward validator.
	if cfg.Validate() != nil || cfg.CaptureScope != "six-part" || cfg.CaptureModules == nil || cfg.RuntimeSources == nil || cfg.InstallationID != target.InstallationID || cfg.Namespace != target.Namespace || cfg.NamespaceUID != target.NamespaceUID || cfg.ApplicationScope != selection.ApplicationScope || cfg.ProfileFile != selection.ExecutionProfile.File || m.Version != productionCaptureMaterialsVersion || m.InstallationID != cfg.InstallationID || m.ControllerOwner != cfg.ControllerOwner || m.DeploymentConfigSHA256 != selection.Deployment.SHA256 || m.CaptureGrantSHA256 != "" || m.Redis.GrantSHA256 != "" || m.Objects.GrantSHA256 != "" || m.Redis.Redis == nil || m.Objects.Objects == nil || m.Discovery == nil || m.Discovery.GrantSHA256 != "" || m.Discovery.Redis.Validate() != nil {
		return nil, install.ErrInstall
	}
	if x.profile.InstallationID != cfg.InstallationID {
		return nil, install.ErrInstall
	}
	if _, _, err := x.profile.CanonicalIdentity(); err != nil {
		return nil, install.ErrInstall
	}
	p := m.Discovery
	if p.ControllerDeployment != selection.Controller.Deployment || p.ControllerDeploymentUID != selection.Controller.DeploymentUID || p.ControllerServiceAccount != selection.Controller.ServiceAccount || p.ControllerServiceAccountUID != selection.Controller.ServiceAccountUID {
		return nil, install.ErrInstall
	}
	db := m.Operations["capture-database"].Request.Database
	if db == nil || db.SourceScope != domain.BusinessTableSourceScope || db.SchemaCensus == nil || db.SchemaCensus.Validate() != nil || db.Name != cfg.SourceDatabase || db.ServerUUID != cfg.SourceServerUUID {
		return nil, install.ErrInstall
	}
	sqlSource, redis, objects, kube := selection.Connections[4], selection.Connections[3], selection.Connections[2], selection.Connections[1]
	if sqlSource.Credential.File != cfg.SourceDSNFile || sqlSource.ServerUUID != cfg.SourceServerUUID || sqlSource.Database != cfg.SourceDatabase || !strings.HasPrefix(sqlSource.Account, cfg.SourceUser+"@") || redis.Endpoint != "rediss://"+m.Redis.Redis.Address || redis.Credential != (install.BootstrapSourceFilePin{File: m.Redis.CredentialFile, SHA256: m.Redis.CredentialSHA256}) || redis.CA != (install.BootstrapSourceFilePin{File: m.Redis.Redis.CAFile, SHA256: m.Redis.Redis.CASHA256}) || objects.Endpoint != "https://"+m.Objects.Objects.Address || objects.Credential != (install.BootstrapSourceFilePin{File: m.Objects.CredentialFile, SHA256: m.Objects.CredentialSHA256}) || objects.CA != (install.BootstrapSourceFilePin{File: m.Objects.Objects.CAFile, SHA256: m.Objects.Objects.CASHA256}) || kube.Endpoint != p.SourceAPI.Server || kube.CA != (install.BootstrapSourceFilePin{File: p.SourceAPI.CAFile, SHA256: p.SourceAPI.CASHA256}) || kube.Credential != (install.BootstrapSourceFilePin{File: p.SourceAPI.TokenFile, SHA256: p.SourceAPITokenSHA256}) || kube.Account != p.SourceAPIServiceAccountUID {
		return nil, install.ErrInstall
	}
	if a := selection.RuntimeAgent; a != nil && (a.CA != (install.BootstrapSourceFilePin{File: cfg.RuntimeSources.AgentCAFile, SHA256: cfg.RuntimeSources.AgentCASHA256}) || a.Credential.File != cfg.RuntimeSources.AgentTokenFile) {
		return nil, install.ErrInstall
	}
	x.physical, err = authority.NativeContext(ctx)
	if err != nil || authority.RecheckAuthority(ctx) != nil {
		return nil, install.ErrInstall
	}
	return x, nil
}
