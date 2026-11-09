package systembackupexecution

import (
	"context"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func (s *DeploymentService) signedTenantProMount(source b.InstanceIdentity) *runningTenantProMount {
	if s.captureMaterials == nil || s.captureMaterials.Discovery == nil {
		return nil
	}
	return runningTenantProMountFor(s.captureMaterials.Discovery.PersistentMounts, source)
}

// The signed mount definition selects individual original sources. A matching
// tenant namespace alone never authorizes stopping another instance in it.
func (s *DeploymentService) attachTenantProRuntimeControls(controls *c.RuntimeControlConfig) error {
	if controls == nil || controls.RecoveryDeploymentCheck != nil {
		return d.ErrNotReady
	}
	// Installed even without current capture material. The controller calls this
	// only for the original locked journal row under its independent Recovery
	// grant, so it cannot admit a new source or reconstruct a forward selection.
	controls.RecoveryDeploymentCheck = func(ctx context.Context, _ d.Authority, spec b.RuntimeWriterSpec) error {
		if !validTenantProNamespace(s.Config.Namespace, spec.Source) || !isRunningTenantPro(spec.Source) ||
			spec.Kind != "deployment" || spec.Name == "" || spec.UID == "" || s.Runtime == nil || s.Runtime.Owner == nil {
			return d.ErrNotReady
		}
		return s.checkAutoscalers(ctx, PlatformDeployment{Namespace: spec.Source.Namespace, Name: spec.Name, UID: spec.UID})
	}
	if s.captureMaterials == nil || s.captureMaterials.Discovery == nil || s.captureMaterials.Discovery.PersistentMounts == nil {
		return nil
	}
	scope := s.captureMaterials.Discovery.PersistentMounts
	if len(scope.RunningTenantPro) == 0 {
		return nil
	}
	if controls == nil || scope.validate() != nil || controls.TenantProSourceCheck != nil || controls.DeploymentChecks == nil {
		return d.ErrNotReady
	}
	pins := make(map[int]runningTenantProMount, len(scope.RunningTenantPro))
	for _, pin := range scope.RunningTenantPro {
		if !validTenantProNamespace(s.Config.Namespace, pin.Source) || pins[pin.Source.ID].Source.ID != 0 {
			return d.ErrNotReady
		}
		ref := PlatformDeployment{Namespace: pin.Source.Namespace, Name: pin.Deployment, UID: pin.DeploymentUID}
		key := ref.Namespace + "/" + ref.Name
		if _, exists := controls.DeploymentChecks[key]; exists {
			return d.ErrNotReady
		}
		controls.DeploymentChecks[key] = runtimeDeploymentProbe{s, ref}
		pins[pin.Source.ID] = pin
	}
	controls.TenantProSourceCheck = func(ctx context.Context, source b.InstanceIdentity) error {
		pin, ok := pins[source.ID]
		if !ok || pin.Source != source || s.Runtime == nil || s.Runtime.Owner == nil {
			return d.ErrNotReady
		}
		return pin.check(ctx, s.Runtime.Owner.Client, s.Config.Namespace)
	}
	return nil
}
