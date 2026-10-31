package systembackupexecution

import (
	"context"
	"sort"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (x *originalSourceMetadataAuthority) resourceMetadata(ctx context.Context, clients *productionMetadataClients) (worker.ResourceCaptureSpec, worker.ResourceCaptureSpec, error) {
	var zero worker.ResourceCaptureSpec
	if clients == nil || clients.Metadata == nil || clients.API == nil || x.Recheck(ctx) != nil {
		return zero, zero, d.ErrNotReady
	}
	s, m := x.service, x.service.captureMaterials
	rules, err := clients.API.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authzv1.SelfSubjectRulesReview{Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: s.Config.Namespace}}, metav1.CreateOptions{})
	if err != nil || !sourceMetadataResourceRules(m.ResourceTypes, rules.Status) {
		return zero, zero, d.ErrNotReady
	}
	parts := map[string]*worker.ResourceCaptureSpec{}
	for _, part := range []string{"deployment_resources", "secret_bundle"} {
		actor := m.Discovery.ResourceActors[part]
		sa, err := x.owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Get(ctx, actor.Name, metav1.GetOptions{})
		if err != nil || string(sa.UID) != actor.UID || sa.DeletionTimestamp != nil || x.Recheck(ctx) != nil {
			return zero, zero, d.ErrNotReady
		}
		parts[part] = &worker.ResourceCaptureSpec{Part: part, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID, ServiceAccountName: actor.Name, ServiceAccountUID: actor.UID, Selections: []root.KubernetesSelection{}, MaxItems: 10000, OriginalWriters: []worker.ResourceWriterOriginal{}}
	}
	seen := map[string]bool{}
	for _, selection := range m.ResourceTypes {
		part := parts[selection.Part]
		probe := root.KubernetesSelection{Group: selection.Group, Version: selection.Version, Resource: selection.Resource, Name: "source-metadata-probe", UID: "source-metadata-probe"}
		if part == nil || !root.ValidKubernetesSelection(probe, selection.Part) {
			return zero, zero, d.ErrNotReady
		}
		if _, err := labels.Parse(selection.LabelSelector); err != nil {
			return zero, zero, d.ErrNotReady
		}
		gvr := schema.GroupVersionResource{Group: selection.Group, Version: selection.Version, Resource: selection.Resource}
		continuation := ""
		for page := 0; ; page++ {
			if page >= 100 || x.Recheck(ctx) != nil {
				return zero, zero, d.ErrNotReady
			}
			// Explicit PartialObjectMetadata avoids fetching plaintext Secret data
			// while enumerating original names and UIDs for the separate GET worker.
			objects, err := clients.Metadata.Resource(gvr).Namespace(s.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selection.LabelSelector, Limit: 1000, Continue: continuation})
			if err != nil || x.Recheck(ctx) != nil {
				return zero, zero, d.ErrNotReady
			}
			for _, object := range objects.Items {
				key := selection.Group + "/" + selection.Resource + "/" + object.Name
				if object.Namespace != s.Config.Namespace || object.UID == "" || object.Name == "" || object.DeletionTimestamp != nil || seen[key] || len(part.Selections) >= part.MaxItems {
					return zero, zero, d.ErrNotReady
				}
				seen[key] = true
				part.Selections = append(part.Selections, root.KubernetesSelection{Group: selection.Group, Version: selection.Version, Resource: selection.Resource, Name: object.Name, UID: string(object.UID)})
			}
			if objects.Continue == "" {
				break
			}
			if objects.Continue == continuation {
				return zero, zero, d.ErrNotReady
			}
			continuation = objects.Continue
		}
	}
	for _, part := range parts {
		sort.Slice(part.Selections, func(i, j int) bool {
			a, b := part.Selections[i], part.Selections[j]
			return a.Group+"/"+a.Resource+"/"+a.Name < b.Group+"/"+b.Resource+"/"+b.Name
		})
	}
	if x.Recheck(ctx) != nil {
		return zero, zero, d.ErrNotReady
	}
	return *parts["deployment_resources"], *parts["secret_bundle"], nil
}

func sourceMetadataResourceRules(types []productionResourceType, status authzv1.SubjectRulesReviewStatus) bool {
	if status.Incomplete || status.EvaluationError != "" {
		return false
	}
	allowed := map[string]bool{}
	covered := map[string]bool{}
	for _, entry := range types {
		allowed[entry.Group+"/"+entry.Resource] = true
	}
	for _, rule := range status.ResourceRules {
		if len(rule.Verbs) == 0 || len(rule.APIGroups) == 0 || len(rule.Resources) == 0 {
			return false
		}
		for _, verb := range rule.Verbs {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					if worker.SourceSelfReviewRule(verb, group, resource, rule.ResourceNames) {
						continue
					}
					if (verb != "get" && verb != "list") || !allowed[group+"/"+resource] || len(rule.ResourceNames) != 0 {
						return false
					}
					if verb == "list" {
						covered[group+"/"+resource] = true
					}
				}
			}
		}
	}
	if !worker.SourceDiscoveryNonResourceRules(status.NonResourceRules) {
		return false
	}
	return len(covered) == len(allowed)
}
