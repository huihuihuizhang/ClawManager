package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"clawreef/internal/systembackup/domain"
	api "clawreef/internal/systembackupdeployment"
	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// This reader can only be constructed from the actual opaque original source
// identity. It holds no Forward, enabled config, task, Job or execution gate.
// Its private facts are not accepted as inputs by another reader/terminal.
// Package-private read mechanics, supplied ONLY by actual opaque Installer
// authoring or independently enrolled consumer constructors in this package.
// No public entry accepts an implementation, callback, passed bit or facts DTO.
type bootstrapSourceReadAccess interface {
	Check(context.Context) error
	Read(context.Context, install.BootstrapSourceFilePin) ([]byte, error)
	NativeContext(context.Context) (context.Context, error)
	Bounds(context.Context) (time.Time, time.Time, error)
	Close()
}

type bootstrapSourceReadDeclaration struct {
	Target               owner.Target
	NotBefore, Until     time.Time
	Parts, SourceWriters sec.BootstrapRegistryRef
	Source               bootstrapSourceReadSelection
}
type bootstrapSourceReadSelection struct {
	ApplicationScope                     string
	Controller                           install.BootstrapSourceController
	Connections                          []install.BootstrapSourceConnection
	RuntimeAgent                         *install.BootstrapSourceRuntimeAgentV2
	PartsRegistry, SourceWritersRegistry install.BootstrapSourceFilePin
}

type bootstrapSourceRegistryReader struct {
	ctx         context.Context
	physical    context.Context
	access      bootstrapSourceReadAccess
	association bootstrapSourceReadDeclaration
	config      DeploymentConfig
	materials   productionCaptureMaterials
	profile     api.ExecutionProfile
}

func strictBootstrapSourceJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 8<<20 || json.Unmarshal(raw, out) != nil {
		return install.ErrInstall
	}
	typed, err := json.Marshal(out)
	if err != nil {
		return install.ErrInstall
	}
	actual, err := jsoncanonicalizer.Transform(raw)
	want, we := jsoncanonicalizer.Transform(typed)
	if err != nil || we != nil || !bytes.Equal(actual, want) {
		return install.ErrInstall
	}
	return nil
}

func newBootstrapSourceRegistryReader(ctx context.Context, source *install.PreparedBootstrapSourceRegistriesV2) (_ *bootstrapSourceRegistryReader, resultErr error) {
	access, err := install.NewBootstrapSourceReaderV2Access(ctx, source)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer func() {
		if resultErr != nil {
			access.Close()
		}
	}()
	r, err := source.Association()
	if err != nil {
		return nil, install.ErrInstall
	}
	x := &bootstrapSourceRegistryReader{ctx: ctx, access: access, association: bootstrapSourceReadDeclaration{Target: r.Target, NotBefore: r.NotBefore, Until: r.Until, Parts: r.Parts, SourceWriters: r.SourceWriters, Source: bootstrapSourceReadSelection{ApplicationScope: r.Source.ApplicationScope, Controller: r.Source.Controller, Connections: r.Source.Connections, RuntimeAgent: r.Source.RuntimeAgent, PartsRegistry: r.Source.PartsRegistry, SourceWritersRegistry: r.Source.SourceWritersRegistry}}}
	for _, field := range []struct {
		pin install.BootstrapSourceFilePin
		out any
	}{{r.Source.Deployment, &x.config}, {r.Source.Materials, &x.materials}, {r.Source.ExecutionProfile, &x.profile}} {
		raw, err := access.Read(ctx, field.pin)
		if err != nil || strictBootstrapSourceJSON(raw, field.out) != nil {
			clear(raw)
			return nil, install.ErrInstall
		}
		clear(raw)
	}
	m, g, cfg := &x.materials, r.Metadata, x.config
	if cfg.Validate() != nil || cfg.CaptureScope != "six-part" || cfg.InstallationID != r.Target.InstallationID || cfg.ControllerOwner != g.ControllerOwner || cfg.Namespace != g.Namespace || cfg.NamespaceUID != g.NamespaceUID || cfg.CaptureModules == nil || cfg.CaptureModules.Path != r.Source.Materials.File || cfg.ProfileFile != r.Source.ExecutionProfile.File || m.Version != productionCaptureMaterialsVersion || m.InstallationID != cfg.InstallationID || m.ControllerOwner != cfg.ControllerOwner || m.DeploymentConfigSHA256 != r.Source.Deployment.SHA256 || m.CaptureGrantSHA256 != g.CaptureGrantSHA256 || m.Redis.Redis == nil || m.Objects.Objects == nil || m.Discovery == nil || m.Discovery.validate() != nil || m.Discovery.GrantFile != r.Source.MetadataGrant.File || m.Discovery.GrantSHA256 != r.Source.MetadataGrant.SHA256 || hash(m.Discovery.Issuer) != r.MetadataIssuerSHA256 {
		return nil, install.ErrInstall
	}
	scope, err := sourceMetadataScope(*m)
	if err != nil || scope != g.ScopeSHA256 || x.profile.InstallationID != cfg.InstallationID {
		return nil, install.ErrInstall
	}
	if _, _, err = x.profile.CanonicalIdentity(); err != nil {
		return nil, install.ErrInstall
	}
	db := m.Operations["capture-database"].Request.Database
	if db == nil || db.SourceScope != domain.BusinessTableSourceScope || db.SchemaCensus == nil || db.SchemaCensus.Validate() != nil || db.Name != cfg.SourceDatabase || db.ServerUUID != cfg.SourceServerUUID {
		return nil, install.ErrInstall
	}
	bindings := map[string]install.BootstrapSourceConnection{}
	for _, c := range r.Source.Connections {
		bindings[c.Purpose] = c
	}
	sqlSource, redis, objects, kube := bindings["source_sql"], bindings["source_redis"], bindings["source_objects"], bindings["source_api"]
	if sqlSource.Credential.File != cfg.SourceDSNFile || sqlSource.ServerUUID != cfg.SourceServerUUID || sqlSource.Database != cfg.SourceDatabase || redis.Endpoint != "rediss://"+m.Redis.Redis.Address || redis.Credential != (install.BootstrapSourceFilePin{File: m.Redis.CredentialFile, SHA256: m.Redis.CredentialSHA256}) || redis.CA != (install.BootstrapSourceFilePin{File: m.Redis.Redis.CAFile, SHA256: m.Redis.Redis.CASHA256}) || objects.Endpoint != "https://"+m.Objects.Objects.Address || objects.Credential != (install.BootstrapSourceFilePin{File: m.Objects.CredentialFile, SHA256: m.Objects.CredentialSHA256}) || objects.CA != (install.BootstrapSourceFilePin{File: m.Objects.Objects.CAFile, SHA256: m.Objects.Objects.CASHA256}) || kube.Endpoint != m.Discovery.SourceAPI.Server || kube.CA != (install.BootstrapSourceFilePin{File: m.Discovery.SourceAPI.CAFile, SHA256: m.Discovery.SourceAPI.CASHA256}) || kube.Credential != (install.BootstrapSourceFilePin{File: m.Discovery.SourceAPI.TokenFile, SHA256: m.Discovery.SourceAPITokenSHA256}) || kube.Account != m.Discovery.SourceAPIServiceAccountUID {
		return nil, install.ErrInstall
	}
	if !reflect.DeepEqual(r.Source.Controller, install.BootstrapSourceController{Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Deployment: m.Discovery.ControllerDeployment, DeploymentUID: m.Discovery.ControllerDeploymentUID, ReplicaSet: r.Source.Controller.ReplicaSet, ReplicaSetUID: r.Source.Controller.ReplicaSetUID, Pod: r.Source.Controller.Pod, PodUID: r.Source.Controller.PodUID, ServiceAccount: m.Discovery.ControllerServiceAccount, ServiceAccountUID: m.Discovery.ControllerServiceAccountUID}) {
		return nil, install.ErrInstall
	}
	x.physical, err = access.NativeContext(ctx)
	if err != nil || access.Check(ctx) != nil {
		return nil, install.ErrInstall
	}
	return x, nil
}

func (x *bootstrapSourceRegistryReader) Close() {
	if x != nil && x.access != nil {
		x.access.Close()
	}
}

func (x *bootstrapSourceRegistryReader) connection(purpose string) (install.BootstrapSourceConnection, error) {
	if x == nil || x.access.Check(x.ctx) != nil {
		return install.BootstrapSourceConnection{}, install.ErrInstall
	}
	for _, c := range x.association.Source.Connections {
		if c.Purpose == purpose {
			return c, nil
		}
	}
	return install.BootstrapSourceConnection{}, install.ErrInstall
}
