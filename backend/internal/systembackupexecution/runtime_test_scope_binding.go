package systembackupexecution

import (
	"reflect"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

func configuredRuntimeTestScope(cfg DeploymentConfig) *domain.RuntimeTestScope {
	if cfg.RuntimeSources == nil {
		return nil
	}
	return cfg.RuntimeSources.RuntimeTestScope
}

// The core is already pinned by the original Forward/source-owner issuance.
// This performs no dynamic selection: IDs/status/generation/full raw digest
// must still equal the original explicitly approved scope on every reread.
func bindRuntimeTestScope(cfg DeploymentConfig, inv *b.SourceInventory) error {
	if inv == nil {
		return d.ErrNotReady
	}
	scope := configuredRuntimeTestScope(cfg)
	if scope == nil {
		if inv.RuntimeTestScope != nil {
			return d.ErrNotReady
		}
		return nil
	}
	if inv.Database != cfg.SourceDatabase || inv.ServerUUID != cfg.SourceServerUUID || scope.InstallationID != cfg.InstallationID || scope.ServerUUID != cfg.SourceServerUUID || scope.Database != cfg.SourceDatabase || scope.NamespaceUID != cfg.NamespaceUID || scope.Validate(inv.Instances) != nil || inv.RuntimeTestScope != nil && !reflect.DeepEqual(inv.RuntimeTestScope, scope) {
		return d.ErrNotReady
	}
	inv.RuntimeTestScope = scope.Clone()
	return nil
}

// A detached projection is used ONLY for runtime checks/parts. The original
// inventory, SQL relationships/export and frozen SourceSnapshot stay complete.
func runtimeTestProjection(cfg DeploymentConfig, inv b.SourceInventory) (b.SourceInventory, error) {
	if bindRuntimeTestScope(cfg, &inv) != nil {
		return b.SourceInventory{}, d.ErrNotReady
	}
	var err error
	inv.Instances, err = inv.RuntimeTestScope.RuntimeInstances(inv.Instances)
	if err != nil {
		return b.SourceInventory{}, d.ErrNotReady
	}
	return inv, nil
}

func requireScopedRunningSourceMetadata(cfg DeploymentConfig, inv b.SourceInventory) error {
	runtime, err := runtimeTestProjection(cfg, inv)
	if err != nil {
		return err
	}
	return requireRunningSourceMetadata(runtime)
}

func deferredRuntimeTestInstance(cfg DeploymentConfig, instance b.InstanceIdentity) bool {
	return configuredRuntimeTestScope(cfg).IsDeferred(instance)
}
