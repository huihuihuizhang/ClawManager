package install

import (
	"context"
	"reflect"

	q "clawreef/internal/systembackup/quiesce"
)

// A tenant is enumerated without selectors at both held and restored
// boundaries. Recovered Pods come only from the actual deployment actors.
func (s *PreparedOriginalWriterSet) recheckTenantLifecycle(ctx context.Context, recovery *originalWriterRecoveryFence, recovered map[string][]q.PodIdentity) error {
	if s.recheckTeamAttachments(ctx, recovery) != nil {
		return ErrInstall
	}
	for _, initial := range s.selection.TenantNamespaces {
		current, pods, deployments, _, err := s.owner.readKubernetesNamespaceCensusWithRecovery(ctx, initial.Namespace, initial.NamespaceUID, recovery)
		if err != nil || !reflect.DeepEqual(current.PVCs, initial.PVCs) || len(deployments) != len(initial.Deployments) ||
			len(current.StatefulSets)+len(current.DaemonSets)+len(current.CronJobs)+len(current.Autoscalers) != 0 {
			return ErrInstall
		}
		writers := map[string]*originalDeploymentMaintenance{}
		allowed := map[string]q.PodIdentity{}
		keeperJobs := map[string]string{}
		for _, keeper := range s.longhornKeepers {
			if keeper.plan.Identity.Namespace != initial.Namespace || keeper.cleaned {
				continue
			}
			if keeper.recheckProcess(ctx) != nil || keeperJobs[keeper.record.Intent.Identity.Name] != "" {
				return ErrInstall
			}
			keeperJobs[keeper.record.Intent.Identity.Name] = keeper.record.UID
			found := false
			for _, pod := range pods {
				if string(pod.UID) != keeper.process.UID {
					continue
				}
				identity, e := originalMaintenancePodIdentity(&pod)
				if e != nil || allowed[identity.UID].UID != "" {
					return ErrInstall
				}
				allowed[identity.UID], found = identity, true
			}
			if !found {
				return ErrInstall
			}
		}
		if len(current.Jobs) != len(keeperJobs) {
			return ErrInstall
		}
		for _, job := range current.Jobs {
			if job.UID == "" || keeperJobs[job.Name] != job.UID {
				return ErrInstall
			}
		}
		for _, attachment := range s.selection.TeamAttachments {
			if attachment.Choice.Namespace != initial.Namespace {
				continue
			}
			found := false
			for _, pod := range pods {
				if string(pod.UID) != attachment.PodUID {
					continue
				}
				if pod.Name != attachment.Choice.Pod || originalObjectSHA(pod.Spec) != attachment.PodSpecSHA256 {
					return ErrInstall
				}
				identity, e := originalMaintenancePodIdentity(&pod)
				if e != nil {
					return ErrInstall
				}
				allowed[identity.UID] = identity
				found = true
			}
			if !found {
				return ErrInstall
			}
		}
		for _, writer := range s.deployments {
			if writer.namespace != initial.Namespace {
				continue
			}
			if writer.namespaceUID != initial.NamespaceUID || writers[writer.selection.Name] != nil {
				return ErrInstall
			}
			writers[writer.selection.Name] = writer
			if recovery != nil {
				for _, pod := range recovered[writer.ID()] {
					if pod.UID == "" || allowed[pod.UID].UID != "" {
						return ErrInstall
					}
					allowed[pod.UID] = pod
				}
			}
		}
		if len(writers) != len(deployments) {
			return ErrInstall
		}
		for _, dep := range deployments {
			writer := writers[dep.Name]
			if writer == nil || string(dep.UID) != writer.selection.UID || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || originalDeploymentSpecSHA(&dep) != writer.specSHA || dep.Status.ObservedGeneration < dep.Generation {
				return ErrInstall
			}
			if recovery == nil {
				if *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 {
					return ErrInstall
				}
			} else if *dep.Spec.Replicas != writer.replicas || dep.Status.ReadyReplicas != writer.replicas || len(recovered[writer.ID()]) != int(writer.replicas) {
				return ErrInstall
			}
		}
		if len(pods) != len(allowed) {
			return ErrInstall
		}
		for _, pod := range pods {
			identity, err := originalMaintenancePodIdentity(&pod)
			if err != nil || pod.DeletionTimestamp != nil || !reflect.DeepEqual(identity, allowed[string(pod.UID)]) {
				return ErrInstall
			}
		}
	}
	return nil
}
