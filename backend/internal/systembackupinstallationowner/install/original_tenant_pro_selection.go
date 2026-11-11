package install

import (
	"context"
	"sort"

	"clawreef/internal/systembackup/domain"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// Original API/SQL comparison DATA, not a native writer, stop acknowledgement,
// recovery permission or held-source proof. Controller UIDs are re-read by the
// authenticated author and the complete tenant controller census is retained.
type OriginalTenantProSelection struct {
	Source     domain.SourceInstance
	Identity   OriginalInitialTenantProCoordinates
	Deployment string
}

func originalTenantProCapture(source domain.SourceInstance, identity OriginalInitialTenantProCoordinates, pod *core.Pod, deployment *apps.Deployment) (OriginalTenantProSelection, error) {
	var zero OriginalTenantProSelection
	if source.Mode != "pro" || source.Backend != "desktop" || source.OS != "linux" || source.Status != "running" || !source.ValidRuntimeGeneration() ||
		pod == nil || deployment == nil || identity.InstanceID != source.ID || identity.Namespace != source.Namespace || identity.NamespaceUID == "" ||
		identity.PodUID != string(pod.UID) || identity.DeploymentUID != string(deployment.UID) || identity.ReplicaSetUID == "" || !digestPattern.MatchString(identity.SourceSHA256) ||
		pod.Namespace != source.Namespace || pod.Name != source.Pod || deployment.Namespace != source.Namespace || deployment.Name == "" ||
		deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.ReadyReplicas != 1 {
		return zero, ErrInstall
	}
	if _, err := originalMaintenancePodIdentity(pod); err != nil {
		return zero, err
	}
	return OriginalTenantProSelection{Source: source, Identity: identity, Deployment: deployment.Name}, nil
}

func originalTenantProCensusMatches(census originalMaintenanceKubernetesCensus, sources []OriginalTenantProSelection) error {
	if census.Namespace == "" || census.NamespaceUID == "" || len(sources) == 0 ||
		len(census.StatefulSets)+len(census.DaemonSets)+len(census.Jobs)+len(census.CronJobs)+len(census.Autoscalers) != 0 {
		return ErrInstall
	}
	pods, deployments := map[string]string{}, map[string]string{}
	instances := map[int]bool{}
	for _, source := range sources {
		if source.Source.ID <= 0 || source.Identity.InstanceID != source.Source.ID || source.Identity.Namespace != source.Source.Namespace || source.Identity.Namespace != census.Namespace || source.Identity.NamespaceUID != census.NamespaceUID || instances[source.Source.ID] ||
			pods[source.Source.Pod] != "" || deployments[source.Deployment] != "" {
			return ErrInstall
		}
		instances[source.Source.ID] = true
		pods[source.Source.Pod], deployments[source.Deployment] = source.Identity.PodUID, source.Identity.DeploymentUID
	}
	if len(census.Pods) != len(pods) || len(census.Deployments) != len(deployments) {
		return ErrInstall
	}
	for _, pod := range census.Pods {
		if pods[pod.Name] == "" || pods[pod.Name] != pod.UID {
			return ErrInstall
		}
		delete(pods, pod.Name)
	}
	for _, deployment := range census.Deployments {
		if deployments[deployment.Name] == "" || deployments[deployment.Name] != deployment.UID {
			return ErrInstall
		}
		delete(deployments, deployment.Name)
	}
	if len(pods)+len(deployments) != 0 {
		return ErrInstall
	}
	return nil
}

func (p *OriginalWriterMaintenance) collectOriginalTenantProSelections(ctx context.Context, selection *OriginalWriterSetSelection, physical *PreparedOriginalWriterSet) (map[int]bool, map[string]string, error) {
	selected, aliases := map[int]bool{}, map[string]string{}
	groups := map[string][]OriginalTenantProSelection{}
	for _, source := range p.instances {
		if selection.RuntimeTestScope.IsDeferred(source) || source.Mode != "pro" || source.Namespace == p.operator.installer.plan.Target.Namespace {
			continue
		}
		failure := func() error {
			return OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "actual_running_tenant_pro_controller_census_required"}
		}
		if originalInitialTenantNamespace(p.operator.installer.plan.Target.Namespace, source) == "" {
			return nil, nil, failure()
		}
		identity, pod, deployment, _, err := p.readInitialTenantPro(ctx, source)
		if err != nil {
			return nil, nil, failure()
		}
		record, err := originalTenantProCapture(source, identity, pod, deployment)
		if err != nil {
			return nil, nil, failure()
		}
		if _, _, err := physical.classifyPodPersistentVolumes(ctx, pod); err != nil {
			return nil, nil, err
		}
		groups[identity.Namespace] = append(groups[identity.Namespace], record)
		selection.TenantPro = append(selection.TenantPro, record)
		selected[source.ID] = true
		aliases["pod/"+source.Namespace+"/"+source.Pod] = "deployment/" + source.Namespace + "/" + deployment.Name
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		census, _, _, _, err := p.readKubernetesNamespaceCensus(ctx, name, groups[name][0].Identity.NamespaceUID)
		if err != nil || originalTenantProCensusMatches(census, groups[name]) != nil {
			return nil, nil, OriginalWriterSourceFailure{Dependency: "complete_tenant_pro_controller_census_required"}
		}
		selection.TenantNamespaces = append(selection.TenantNamespaces, census)
	}
	return selected, aliases, nil
}
