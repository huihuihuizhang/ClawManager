package install

import (
	"context"
	"reflect"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Existing installed provider coordinates and a pinned real observation
// transport. No future KEK/config ref, active capture record, signed future
// deployment JSON, task or passed receipt is accepted by this A1 input.
type PreAdoptionVaultDependencySelection struct {
	Workload          VaultProviderWorkloadSelection
	InstalledObserver BootstrapSourceFilePin
}
type preAdoptionVaultProvider struct {
	origin                   *preAdoptionVaultProvider
	set                      *PreparedOriginalWriterSet
	input                    PreAdoptionVaultDependencySelection
	config                   owner.InstalledVaultDependencyConfig
	observer                 *owner.InstalledVaultDependencyObserver
	scope                    VaultProviderScopeData
	initial                  owner.InstalledVaultDependencyData
	proof                    *owner.ObservedInstalledVaultDependency
	nativeUntil, sourceUntil time.Time
	closed                   bool
}

func (s *PreparedOriginalWriterSet) preAdoptionVaultSelected(name, uid string) bool {
	for _, p := range s.selection.PreAdoptionVaultDependencies {
		if p.Workload.Deployment == name && p.Workload.DeploymentUID == uid {
			return true
		}
	}
	return false
}
func (s *PreparedOriginalWriterSet) preparePreAdoptionVaultDependencies(ctx context.Context) error {
	if len(s.selection.PreAdoptionVaultDependencies)+len(s.selection.VaultProviderDependencies) > 1 {
		return ErrInstall
	}
	selected := map[string]string{}
	for _, d := range s.selection.Deployments {
		if d.Role == "provider-dependency" {
			selected[d.Name] = d.UID
		}
	}
	for _, active := range s.selection.VaultProviderDependencies {
		delete(selected, active.Deployment)
	}
	if len(selected) != len(s.selection.PreAdoptionVaultDependencies) {
		return ErrInstall
	}
	for _, input := range s.selection.PreAdoptionVaultDependencies {
		if selected[input.Workload.Deployment] == "" || selected[input.Workload.Deployment] != input.Workload.DeploymentUID {
			return ErrInstall
		}
		delete(selected, input.Workload.Deployment)
		p := &preAdoptionVaultProvider{set: s, input: input, sourceUntil: s.owner.until}
		p.origin = p
		s.preAdoptionProviders = append(s.preAdoptionProviders, p)
		if p.emptyOriginalHead(ctx) != nil {
			return ErrInstall
		}
		raw, e := readBootstrapSourcePin(input.InstalledObserver, 262144)
		if e != nil || decodeExact(raw, &p.config) != nil {
			return ErrInstall
		}
		i := s.owner.operator.installer
		p.observer, e = owner.NewInstalledVaultDependencyObserver(p.config, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
		if e != nil {
			return ErrInstall
		}
		p.scope, e = ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, input.Workload, p.config.Endpoint)
		if e != nil {
			return OriginalWriterSourceFailure{Dependency: "pre_adoption_vault_actual_identity_and_private_business_claim_isolation_required"}
		}
	}
	return nil
}

func (p *preAdoptionVaultProvider) emptyOriginalHead(ctx context.Context) error {
	if p == nil || p.origin != p || p.closed || p.set == nil || !consumerSameContext(ctx, p.set.owner.ctx) || p.set.owner.initial != (HeadCAS{}) || p.set.owner.check(ctx) != nil || p.set.owner.operator.authority(ctx, p.set.owner.enrollment) != nil {
		return ErrInstall
	}
	current, _, e := originalAdoptionAuthoritySnapshot(ctx, p.set.owner.operator)
	if e != nil || current.cas != (HeadCAS{}) || len(current.recordRaw) != 0 {
		return ErrInstall
	}
	return nil
}

// Recovery calls only this identity/isolation read under its NEW independent
// recovery owner. It never resurrects the old A1 context or token permission.
func (p *preAdoptionVaultProvider) recheckAPI(ctx context.Context) error {
	if p == nil || p.origin != p || p.closed || p.set == nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(p.input.InstalledObserver, 262144)
	clear(raw)
	if e != nil {
		return ErrInstall
	}
	i := p.set.owner.operator.installer
	current, e := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, p.input.Workload, p.config.Endpoint)
	if e != nil || !reflect.DeepEqual(current, p.scope) {
		return ErrInstall
	}
	return nil
}
func (p *preAdoptionVaultProvider) observeNative(ctx context.Context) error {
	if p == nil {
		return ErrInstall
	}
	p.proof = nil
	p.nativeUntil = time.Time{}
	if p.emptyOriginalHead(ctx) != nil || p.recheckAPI(ctx) != nil || p.observer == nil {
		return ErrInstall
	}
	proof, e := p.observer.Observe(ctx)
	if e != nil {
		return ErrInstall
	}
	data, until, e := proof.Data(ctx)
	if e != nil || p.initial.MetadataSHA256 != "" && !reflect.DeepEqual(data, p.initial) || p.recheckAPI(ctx) != nil || p.emptyOriginalHead(ctx) != nil {
		return ErrInstall
	}
	if p.initial.MetadataSHA256 == "" {
		p.initial = data
	}
	p.proof, p.nativeUntil = proof, minTime(until, p.sourceUntil)
	return p.recheckLocal(ctx, time.Now().UTC())
}
func (p *preAdoptionVaultProvider) recheckLocal(ctx context.Context, now time.Time) error {
	if p == nil || p.origin != p || p.closed || p.set == nil || p.proof == nil || !consumerSameContext(ctx, p.set.owner.ctx) || p.initial.MetadataSHA256 == "" || !now.Before(p.nativeUntil) || !now.Before(p.sourceUntil) || p.proof.Recheck(ctx, now) != nil {
		return ErrInstall
	}
	return nil
}
func (p *preAdoptionVaultProvider) originalState() any {
	return struct {
		Scope  VaultProviderScopeData
		Native owner.InstalledVaultDependencyData
	}{p.scope, p.initial}
}
func (p *preAdoptionVaultProvider) close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	if p.observer != nil {
		p.observer.Close()
	}
}

func (h *OriginalWriterHold) preAdoptionVaultPeer(ctx context.Context, podUID, containerID, imageID string) (string, time.Time, error) {
	if h == nil || h.origin != h || h.closed || h.set == nil || h.set.actualHold != h || !consumerSameContext(ctx, h.ctx) {
		return "", time.Time{}, ErrInstall
	}
	for _, p := range h.set.preAdoptionProviders {
		if p.scope.PodUID != podUID {
			continue
		}
		if podUID == "" || containerID == "" || p.scope.ContainerID != containerID || p.scope.ImageID != imageID || p.recheckLocal(ctx, time.Now().UTC()) != nil {
			return "", time.Time{}, ErrInstall
		}
		return originalObjectSHA(p.originalState()), p.nativeUntil, nil
	}
	return "", time.Time{}, ErrInstall
}

// Shared local-only minimum for Root's SQL-cut cap. Empty means there is no
// configured provider dependency; every configured entry otherwise must have
// its genuine same-set observation and original short cap, including A1.
func (h *OriginalWriterHold) originalVaultDependenciesUntil(ctx context.Context) (time.Time, error) {
	if h == nil || h.origin != h || h.closed || h.set == nil || h.set.actualHold != h || !consumerSameContext(ctx, h.ctx) {
		return time.Time{}, ErrInstall
	}
	until := h.set.owner.until
	for _, p := range h.set.providerDependencies {
		if p == nil || p.set != h.set || p.recheckLocal(ctx, time.Now().UTC()) != nil {
			return time.Time{}, ErrInstall
		}
		until = minTime(until, minTime(p.nativeUntil, p.sourceUntil))
	}
	for _, p := range h.set.preAdoptionProviders {
		if p == nil || p.set != h.set || p.recheckLocal(ctx, time.Now().UTC()) != nil {
			return time.Time{}, ErrInstall
		}
		until = minTime(until, minTime(p.nativeUntil, p.sourceUntil))
	}
	return until, nil
}
