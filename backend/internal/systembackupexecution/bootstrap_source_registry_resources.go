package systembackupexecution

import (
	"context"
	"sort"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (x *bootstrapSourceRegistryReader) readResourceMetadata(ctx context.Context, clients *productionMetadataClients) (worker.ResourceCaptureSpec, worker.ResourceCaptureSpec, error) {
	var zero worker.ResourceCaptureSpec
	if clients == nil || clients.Metadata == nil || clients.API == nil || x.checkPhysical(ctx) != nil {
		return zero, zero, install.ErrInstall
	}
	m := &x.materials
	rules, err := clients.API.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authzv1.SelfSubjectRulesReview{Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: x.config.Namespace}}, metav1.CreateOptions{})
	if err != nil || !sourceMetadataResourceRules(m.ResourceTypes, rules.Status) {
		return zero, zero, install.ErrInstall
	}
	parts := map[string]*worker.ResourceCaptureSpec{}
	for _, part := range []string{"deployment_resources", "secret_bundle"} {
		actor := m.Discovery.ResourceActors[part]
		sa, err := clients.API.CoreV1().ServiceAccounts(x.config.Namespace).Get(ctx, actor.Name, metav1.GetOptions{})
		if err != nil || string(sa.UID) != actor.UID || sa.DeletionTimestamp != nil || x.checkPhysical(ctx) != nil {
			return zero, zero, install.ErrInstall
		}
		parts[part] = &worker.ResourceCaptureSpec{Part: part, Namespace: x.config.Namespace, NamespaceUID: x.config.NamespaceUID, ServiceAccountName: actor.Name, ServiceAccountUID: actor.UID, Selections: []root.KubernetesSelection{}, MaxItems: 10000, OriginalWriters: []worker.ResourceWriterOriginal{}}
	}
	seen := map[string]bool{}
	for _, selection := range m.ResourceTypes {
		part := parts[selection.Part]
		probe := root.KubernetesSelection{Group: selection.Group, Version: selection.Version, Resource: selection.Resource, Name: "source-metadata-probe", UID: "source-metadata-probe"}
		if part == nil || !root.ValidKubernetesSelection(probe, selection.Part) {
			return zero, zero, install.ErrInstall
		}
		if _, err := labels.Parse(selection.LabelSelector); err != nil {
			return zero, zero, install.ErrInstall
		}
		gvr := schema.GroupVersionResource{Group: selection.Group, Version: selection.Version, Resource: selection.Resource}
		continuation := ""
		resourceVersion := ""
		continuations := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 || x.checkPhysical(ctx) != nil {
				return zero, zero, install.ErrInstall
			}
			// Explicit PartialObjectMetadata avoids fetching plaintext Secret data
			// while enumerating original names and UIDs for the separate GET worker.
			objects, err := clients.Metadata.Resource(gvr).Namespace(x.config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selection.LabelSelector, Limit: 1000, Continue: continuation})
			if err != nil || x.checkPhysical(ctx) != nil {
				return zero, zero, install.ErrInstall
			}
			if page == 0 {
				resourceVersion = objects.ResourceVersion
			} else if resourceVersion == "" || objects.ResourceVersion != resourceVersion {
				return zero, zero, install.ErrInstall
			}
			for _, object := range objects.Items {
				key := selection.Group + "/" + selection.Resource + "/" + object.Name
				if object.Namespace != x.config.Namespace || object.UID == "" || object.Name == "" || object.DeletionTimestamp != nil || seen[key] || len(part.Selections) >= part.MaxItems {
					return zero, zero, install.ErrInstall
				}
				seen[key] = true
				part.Selections = append(part.Selections, root.KubernetesSelection{Group: selection.Group, Version: selection.Version, Resource: selection.Resource, Name: object.Name, UID: string(object.UID)})
			}
			if objects.Continue == "" {
				break
			}
			if resourceVersion == "" || continuations[objects.Continue] {
				return zero, zero, install.ErrInstall
			}
			continuations[objects.Continue] = true
			continuation = objects.Continue
		}
	}
	for _, part := range parts {
		sort.Slice(part.Selections, func(i, j int) bool {
			a, b := part.Selections[i], part.Selections[j]
			return a.Group+"/"+a.Resource+"/"+a.Name < b.Group+"/"+b.Resource+"/"+b.Name
		})
	}
	if x.checkPhysical(ctx) != nil {
		return zero, zero, install.ErrInstall
	}
	return *parts["deployment_resources"], *parts["secret_bundle"], nil
}
