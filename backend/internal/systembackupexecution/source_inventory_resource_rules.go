package systembackupexecution

import (
	"context"

	"clawreef/internal/systembackup/worker"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The controller source reader also enumerates writers and resolves the selected
// Longhorn topology. Its credential is not a per-part GET worker credential.
// Keep the latter's strict validator unchanged; project only the finite source
// discovery reads before checking complete coverage of the captured resources.
func sourceInventoryResourceRules(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, m productionCaptureMaterials, status authzv1.SubjectRulesReviewStatus) bool {
	if m.Discovery == nil || len(m.Discovery.LonghornSources) == 0 {
		return sourceMetadataResourceRules(m.ResourceTypes, status)
	}
	if api == nil || status.Incomplete || status.EvaluationError != "" || cfg.Namespace == "" {
		return false
	}
	namespaces := map[string]bool{cfg.Namespace: true, "kube-system": true}
	claimNamespaces := map[string]bool{cfg.Namespace: true}
	for _, source := range m.Discovery.LonghornSources {
		if source.Namespace == "" || source.NamespaceUID == "" || source.ProviderNamespace == "" || source.ProviderUID == "" {
			return false
		}
		namespaces[source.Namespace], namespaces[source.ProviderNamespace] = true, true
		claimNamespaces[source.Namespace] = true
	}
	if len(namespaces) > 16 || len(cfg.Security.NodeUIDs) == 0 {
		return false
	}
	pvs := map[string]bool{}
	// Writer census already requires all source PVCs, including claims with no
	// running consumer. Bind named PV reads to that same actual complete roster.
	for ns := range claimNamespaces {
		cursor, version := "", ""
		seen := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 {
				return false
			}
			items, err := api.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{Limit: 1000, Continue: cursor})
			if err != nil || len(items.Items) > 1000 || items.ResourceVersion == "" || page > 0 && version != items.ResourceVersion {
				return false
			}
			version = items.ResourceVersion
			for _, pvc := range items.Items {
				if pvc.Namespace != ns || pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Spec.VolumeName == "" || len(pvs) >= 10000 {
					return false
				}
				pvs[pvc.Spec.VolumeName] = true
			}
			cursor = items.Continue
			if cursor == "" {
				break
			}
			if seen[cursor] {
				return false
			}
			seen[cursor] = true
		}
	}
	return sourceInventoryRuleProjection(m.ResourceTypes, status, namespaces, cfg.Security.NodeUIDs, pvs)
}

func sourceInventoryRuleProjection(types []productionResourceType, status authzv1.SubjectRulesReviewStatus, namespaces map[string]bool, nodes map[string]string, pvs map[string]bool) bool {
	captured := map[string]bool{}
	for _, t := range types {
		captured[t.Group+"/"+t.Resource] = true
	}
	// Exact read-only roster provisioned for the source graph; no wildcard,
	// stream, subresource, write, impersonation or foreign review permission.
	extra := map[string]bool{"/endpoints": true, "apps/statefulsets": true, "apps/daemonsets": true,
		"batch/jobs": true, "batch/cronjobs": true, "autoscaling/horizontalpodautoscalers": true,
		"networking.k8s.io/ingresses": true, "coordination.k8s.io/leases": true,
		"storage.k8s.io/storageclasses": true, "snapshot.storage.k8s.io/volumesnapshots": true,
		"snapshot.storage.k8s.io/volumesnapshotclasses": true, "snapshot.storage.k8s.io/volumesnapshotcontents": true}
	projected := authzv1.SubjectRulesReviewStatus{Incomplete: status.Incomplete, EvaluationError: status.EvaluationError, NonResourceRules: status.NonResourceRules}
	for _, rule := range status.ResourceRules {
		if len(rule.Verbs) == 0 || len(rule.APIGroups) == 0 || len(rule.Resources) == 0 {
			return false
		}
		for _, verb := range rule.Verbs {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					self := worker.SourceSelfReviewRule(verb, group, resource, rule.ResourceNames)
					if !self && verb != "get" && verb != "list" {
						return false
					}
					if self || captured[group+"/"+resource] {
						projected.ResourceRules = append(projected.ResourceRules, authzv1.ResourceRule{Verbs: []string{verb}, APIGroups: []string{group}, Resources: []string{resource}, ResourceNames: rule.ResourceNames})
						continue
					}
					if group == "" && (resource == "namespaces" || resource == "nodes" || resource == "persistentvolumes") {
						if verb != "get" || len(rule.ResourceNames) == 0 || len(rule.ResourceNames) > 10000 {
							return false
						}
						for _, name := range rule.ResourceNames {
							if resource == "namespaces" && !namespaces[name] || resource == "nodes" && nodes[name] == "" || resource == "persistentvolumes" && !pvs[name] {
								return false
							}
						}
						continue
					}
					if !extra[group+"/"+resource] || len(rule.ResourceNames) != 0 {
						return false
					}
				}
			}
		}
	}
	return sourceMetadataResourceRules(types, projected)
}
