package install

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Independently pinned installation inputs. No Ready/Passed, observed identity,
// task or source-hold receipt is accepted. The exact selected deployment must
// ALSO be bound to original signed KEK + signing providers and actual native
// observations; selecting this role alone never exempts a writer.
type OriginalVaultProviderSelection struct {
	Deployment, DeploymentUID, Container, ImageID       string
	Service, ServiceUID, Claim, ClaimUID, DataMountPath string
	Mapping                                             reg.ReferencePin
	MappingIssuer, ProviderObserver, SigningObserver    BootstrapSourceFilePin
	DeploymentConfiguration, SourceMetadataGrant        BootstrapSourceFilePin
}

type originalVaultProviderDependency struct {
	origin         *originalVaultProviderDependency
	set            *PreparedOriginalWriterSet
	selection      OriginalVaultProviderSelection
	initial        originalVaultProviderScope
	provider       *kek.VaultPermissionObserver
	signing        *owner.CaptureSigningObserver
	binding        reg.Binding
	signingBinding owner.Binding
	permissions    *kek.ObservedOriginalVaultDependency
	keys           *owner.ObservedOriginalSigningDependency
	issuer         ed25519.PublicKey
	nativeUntil    time.Time
	sourceUntil    time.Time
	closed         bool
}

func (*originalVaultProviderDependency) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (s *PreparedOriginalWriterSet) prepareOriginalProviderDependencies(ctx context.Context) error {
	if len(s.selection.VaultProviderDependencies) > 1 {
		return ErrInstall
	}
	selected := map[string]string{}
	for _, d := range s.selection.Deployments {
		if d.Role == "provider-dependency" && !s.preAdoptionVaultSelected(d.Name, d.UID) {
			selected[d.Name] = d.UID
		}
	}
	if len(selected) != len(s.selection.VaultProviderDependencies) {
		return ErrInstall
	}
	for _, input := range s.selection.VaultProviderDependencies {
		if selected[input.Deployment] == "" || selected[input.Deployment] != input.DeploymentUID {
			return ErrInstall
		}
		delete(selected, input.Deployment)
		p := &originalVaultProviderDependency{set: s, selection: input}
		p.origin = p
		// Register ownership before any later constructor failure so all private
		// transports are closed by the existing complete-set failure cleanup.
		s.providerDependencies = append(s.providerDependencies, p)
		issuer, e := readBootstrapSourcePin(input.MappingIssuer, ed25519.PublicKeySize)
		if e != nil || len(issuer) != ed25519.PublicKeySize {
			return ErrInstall
		}
		p.issuer = ed25519.PublicKey(issuer)
		raw, e := readBootstrapSourcePin(input.ProviderObserver, 262144)
		var cfg kek.VaultPermissionObserverConfig
		if e != nil || decodeExact(raw, &cfg) != nil {
			return ErrInstall
		}
		p.provider, e = kek.NewVaultPermissionObserver(cfg)
		if e != nil {
			return ErrInstall
		}
		p.binding = cfg.Binding
		if p.binding.InstallationID != s.owner.operator.installer.plan.Target.InstallationID || p.binding.ConfigRef != input.Mapping {
			return ErrInstall
		}
		raw, e = readBootstrapSourcePin(input.SigningObserver, 262144)
		var signing observerDocument
		if e != nil || decodeExact(raw, &signing) != nil || signing.Endpoint != cfg.Binding.Provider.Endpoint || signing.CASHA256 != cfg.Binding.Provider.CAPEMSHA256 {
			return ErrInstall
		}
		ca, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: signing.CAFile, SHA256: signing.CASHA256}, 65536)
		if e != nil {
			return ErrInstall
		}
		p.signing, e = owner.NewCaptureSigningObserver(owner.SigningObserverConfig{Endpoint: signing.Endpoint, CASHA256: signing.CASHA256, CAPEM: ca, ObserverPolicy: signing.ObserverPolicy, ObserverTokenFile: signing.ObserverTokenFile, ObserverTokenSHA256: signing.ObserverTokenSHA256, RuntimeJWTFile: signing.RuntimeJWTFile, Trust: signing.Trust, Kubernetes: s.owner.operator.installer.kube})
		if e != nil {
			return ErrInstall
		}
		p.initial, e = p.readScope(ctx)
		if e != nil {
			return OriginalWriterSourceFailure{Dependency: "original_vault_provider_binding_native_or_private_volume_required"}
		}
	}
	return nil
}

func (p *originalVaultProviderDependency) recheckInputs() error {
	if p == nil || p.origin != p || p.closed {
		return ErrInstall
	}
	for _, input := range []BootstrapSourceFilePin{p.selection.MappingIssuer, p.selection.ProviderObserver, p.selection.SigningObserver, p.selection.DeploymentConfiguration, p.selection.SourceMetadataGrant} {
		raw, e := readBootstrapSourcePin(input, 262144)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
	}
	return nil
}

func (p *originalVaultProviderDependency) recheckAPI(ctx context.Context) error {
	if p.recheckInputs() != nil {
		return ErrInstall
	}
	current, e := p.readScope(ctx)
	if e != nil || !reflect.DeepEqual(current, p.initial) {
		return ErrInstall
	}
	return nil
}

// The requested six-domain source configuration is authenticated by its real
// original source-metadata issuer, independently of provider role selection.
// A provider PVC selected as workspace/staging/Pro data is a real source and
// must be refused by this dependency-only actor.
func (p *originalVaultProviderDependency) readBusinessConfiguration(ctx context.Context, configSHA string) error {
	i := p.set.owner.operator.installer
	raw, e := readBootstrapSourcePin(p.selection.DeploymentConfiguration, 262144)
	if e != nil {
		return ErrInstall
	}
	core, e := decodeBootstrapSourceCore(raw)
	if e != nil || core.Version != "system-backup-public-deployment.v1" || core.CaptureScope != "six-part" || core.InstallationID != i.plan.Target.InstallationID || core.Namespace != i.plan.Target.Namespace || core.NamespaceUID != i.plan.Target.NamespaceUID || core.SourceServerUUID != i.plan.Target.ServerUUID || core.SourceDatabase != i.plan.Target.Database {
		return ErrInstall
	}
	var claims struct {
		StagingClaim string `json:"staging_claim"`
		Workspace    struct {
			Claim string          `json:"claim"`
			NFS   json.RawMessage `json:"nfs"`
		} `json:"workspace"`
		RuntimeSources struct {
			Layouts []struct{ Mounts []struct{ Claim string } } `json:"current_stopped_pro_layouts"`
		} `json:"runtime_sources"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.StagingClaim == "" || claims.StagingClaim == p.selection.Claim || claims.Workspace.Claim == "" || claims.Workspace.Claim == p.selection.Claim || len(claims.Workspace.NFS) != 0 && string(claims.Workspace.NFS) != "null" {
		return ErrInstall
	}
	for _, layout := range claims.RuntimeSources.Layouts {
		for _, mount := range layout.Mounts {
			if mount.Claim == p.selection.Claim {
				return ErrInstall
			}
		}
	}
	metadataRaw, e := readBootstrapSourcePin(p.selection.SourceMetadataGrant, 65536)
	if e != nil {
		return ErrInstall
	}
	metadata, _, e := decodeBootstrapSourceMetadata(metadataRaw, i.public)
	now := time.Now().UTC()
	if e != nil || metadata.InstallationID != core.InstallationID || metadata.Namespace != core.Namespace || metadata.NamespaceUID != core.NamespaceUID || metadata.ControllerOwner != core.ControllerOwner || metadata.DeploymentConfigSHA256 != p.selection.DeploymentConfiguration.SHA256 || metadata.ConfigSHA256 != configSHA || now.Before(metadata.NotBefore) || !now.Before(metadata.Until) || ctx.Err() != nil {
		return ErrInstall
	}
	p.sourceUntil = metadata.Until
	return nil
}

func (p *originalVaultProviderDependency) observeNative(ctx context.Context) error {
	if p == nil {
		return ErrInstall
	}
	p.permissions, p.keys, p.nativeUntil = nil, nil, time.Time{}
	if p.recheckAPI(ctx) != nil || p.provider == nil || p.signing == nil || !consumerSameContext(ctx, p.set.owner.ctx) {
		return ErrInstall
	}
	s := p.set.owner
	current, _, e := originalAdoptionAuthoritySnapshot(ctx, s.operator)
	if e != nil || current.cas != s.initial || current.cas.State != "active" || current.record.Binding.Endpoint != p.binding.Provider.Endpoint || current.record.Binding.CASHA256 != p.binding.Provider.CAPEMSHA256 {
		return ErrInstall
	}
	original, e := owner.VerifyRecord(current.recordRaw, current.recordSig, s.operator.pinFor(current.record, current.cas.GrantSHA256, current.cas.HeadRevision))
	if e != nil || p.readBusinessConfiguration(ctx, current.record.ConfigSHA256) != nil {
		return ErrInstall
	}
	p.signingBinding = current.record.Binding
	var permission *kek.ObservedOriginalVaultDependency
	var keys *owner.ObservedOriginalSigningDependency
	var permissionErr, keyErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		permission, permissionErr = p.provider.ObserveOriginalProviderDependency(ctx, s.operator.installer.db, p.binding.InstallationID, p.selection.Mapping, p.issuer)
	}()
	go func() { defer wg.Done(); keys, keyErr = p.signing.ObserveOriginalProviderDependency(ctx, original) }()
	wg.Wait()
	if permissionErr != nil || keyErr != nil {
		return ErrInstall
	}
	after, _, e := originalAdoptionAuthoritySnapshot(ctx, s.operator)
	if e != nil || after.cas != current.cas || p.recheckAPI(ctx) != nil {
		return ErrInstall
	}
	p.permissions, p.keys = permission, keys
	permissionUntil, e := permission.ValidUntil(ctx)
	keysUntil, e2 := keys.ValidUntil(ctx)
	if e != nil || e2 != nil {
		return ErrInstall
	}
	p.nativeUntil = minTime(permissionUntil, keysUntil)
	p.nativeUntil = minTime(p.nativeUntil, p.sourceUntil)
	return p.recheckLocal(ctx, time.Now().UTC())
}

func (p *originalVaultProviderDependency) recheckLocal(ctx context.Context, now time.Time) error {
	if p == nil || p.origin != p || p.closed || p.set == nil || p.permissions == nil || p.keys == nil || !now.Before(p.nativeUntil) || !consumerSameContext(ctx, p.set.owner.ctx) || p.permissions.Recheck(ctx, p.binding, now) != nil || p.keys.Recheck(ctx, p.signingBinding, now) != nil {
		return ErrInstall
	}
	return nil
}

func (p *originalVaultProviderDependency) close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	if p.provider != nil {
		p.provider.Close()
	}
	if p.signing != nil {
		p.signing.Close()
	}
	clear(p.issuer)
}

// The actual complete original hold supplies this narrow dependency identity
// to original source classification. It is NOT constructed from a name/role
// DTO and conveys no business-source quiesce, coverage or admission capability.
func (h *OriginalWriterHold) RecheckOriginalProviderDependency(ctx context.Context, podUID string) error {
	if h == nil || h.origin != h || h.closed || h.set == nil || !consumerSameContext(ctx, h.ctx) || podUID == "" {
		return ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	if h.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	for _, p := range h.set.providerDependencies {
		if p.initial.PodUID == podUID {
			return p.recheckLocal(ctx, time.Now().UTC())
		}
	}
	return ErrInstall
}

// C's real constructor already owns the complete hold mutex. This private
// local-only bridge avoids taking it recursively and preserves the original
// native cap; no timestamp sampled here can extend that cap.
func (h *OriginalWriterHold) originalVaultProviderPeer(ctx context.Context, podUID, containerID, imageID string) (string, time.Time, error) {
	if h == nil || h.origin != h || h.closed || h.set == nil || h.set.actualHold != h || !consumerSameContext(ctx, h.ctx) || podUID == "" || containerID == "" || imageID == "" {
		return "", time.Time{}, ErrInstall
	}
	for _, p := range h.set.providerDependencies {
		if p.initial.PodUID != podUID {
			continue
		}
		if p.initial.ContainerID != containerID || p.initial.ImageID != imageID || p.recheckLocal(ctx, time.Now().UTC()) != nil {
			return "", time.Time{}, ErrInstall
		}
		return originalObjectSHA(struct {
			Scope   originalVaultProviderScope
			KEK     reg.Binding
			Signing owner.Binding
		}{p.initial, p.binding, p.signingBinding}), p.nativeUntil, nil
	}
	return h.preAdoptionVaultPeer(ctx, podUID, containerID, imageID)
}
