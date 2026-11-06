package systembackupreferenceprobe

import (
	ma "clawreef/internal/systembackupminioauthority"
	"context"
	"strings"

	ce "clawreef/internal/systembackupcontrolevidence"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// Exact configured native owner chain; labels alone never establish identity.
// Every EndpointSlice page is consumed, with stable list RV, no repeated cursor
// and a fixed total bound. The final whole snapshot must match the first.
func minioPermissionKubernetes(ctx context.Context, k kubernetes.Interface, cfg minioPermissionConfiguration, p minioPermissionProvider) (string, error) {
	fail := func() (string, error) { return "", minioPermissionFailure("provider-resource-chain") }
	ns, err := k.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return fail()
	}
	d, err := k.AppsV1().Deployments(cfg.Namespace).Get(ctx, p.Deployment.Name, metav1.GetOptions{})
	if err != nil || string(d.UID) != p.Deployment.UID || d.DeletionTimestamp != nil || d.Spec.Selector == nil || len(d.Spec.Selector.MatchLabels) == 0 || len(d.Spec.Selector.MatchExpressions) != 0 || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 {
		return fail()
	}
	rs, err := k.AppsV1().ReplicaSets(cfg.Namespace).Get(ctx, p.ReplicaSet.Name, metav1.GetOptions{})
	if err != nil || string(rs.UID) != p.ReplicaSet.UID || rs.DeletionTimestamp != nil || !minioPermissionOwned(rs.OwnerReferences, "Deployment", p.Deployment) {
		return fail()
	}
	pod, err := k.CoreV1().Pods(cfg.Namespace).Get(ctx, p.Pod.Name, metav1.GetOptions{})
	if err != nil || string(pod.UID) != p.Pod.UID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !minioPermissionOwned(pod.OwnerReferences, "ReplicaSet", p.ReplicaSet) || pod.Spec.ServiceAccountName != p.ServiceAccount.Name || pod.Spec.NodeName != p.Node || !labels.SelectorFromSet(d.Spec.Selector.MatchLabels).Matches(labels.Set(pod.Labels)) {
		return fail()
	}
	if p.Container == "" || p.ImageID == "" || p.NodeUID == "" {
		return fail()
	}
	if ma.MatchesDeleteCompatImageID(p.ImageID) {
		for _, containers := range [][]corev1.Container{d.Spec.Template.Spec.Containers, pod.Spec.Containers} {
			matched := false
			for _, container := range containers {
				if container.Name == p.Container {
					matched = ma.MatchesDeleteCompatImageReference(container.Image)
				}
			}
			if !matched {
				return fail()
			}
		}
	}
	found := 0
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == p.Container {
			if !status.Ready || status.State.Running == nil || status.ContainerID == "" || status.ImageID != p.ImageID {
				return fail()
			}
			found++
		}
	}
	if found != 1 {
		return fail()
	}
	sa, err := k.CoreV1().ServiceAccounts(cfg.Namespace).Get(ctx, p.ServiceAccount.Name, metav1.GetOptions{})
	if err != nil || string(sa.UID) != p.ServiceAccount.UID || sa.DeletionTimestamp != nil {
		return fail()
	}
	node, err := k.CoreV1().Nodes().Get(ctx, p.Node, metav1.GetOptions{})
	if err != nil || string(node.UID) != p.NodeUID || node.DeletionTimestamp != nil {
		return fail()
	}
	svc, err := k.CoreV1().Services(cfg.Namespace).Get(ctx, p.Service.Name, metav1.GetOptions{})
	if err != nil || string(svc.UID) != p.Service.UID || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 || !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(pod.Labels)) || svc.Spec.Type == corev1.ServiceTypeExternalName {
		return fail()
	}
	stamps := []any{ns.UID, ns.ResourceVersion, d.UID, d.ResourceVersion, rs.UID, rs.ResourceVersion, pod.UID, pod.ResourceVersion, pod.Status.ContainerStatuses, sa.UID, sa.ResourceVersion, node.UID, node.ResourceVersion, svc.UID, svc.ResourceVersion, svc.Spec}
	selector := labels.Set{"kubernetes.io/service-name": p.Service.Name}.AsSelector().String()
	cursor, rv := "", ""
	seen := map[string]bool{}
	count, ready := 0, 0
	for page := 0; page < 8; page++ {
		list, err := k.DiscoveryV1().EndpointSlices(cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 16, Continue: cursor})
		if err != nil || list.ResourceVersion == "" || rv != "" && list.ResourceVersion != rv || len(list.Items) > 16 {
			return fail()
		}
		rv = list.ResourceVersion
		for _, slice := range list.Items {
			count++
			if count > 32 || slice.DeletionTimestamp != nil || slice.Namespace != cfg.Namespace || slice.UID == "" || slice.Labels["kubernetes.io/service-name"] != p.Service.Name || !minioPermissionOwned(slice.OwnerReferences, "Service", p.Service) {
				return fail()
			}
			for _, ep := range slice.Endpoints {
				if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
					if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
						return fail()
					}
					if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || string(ep.TargetRef.UID) != p.Pod.UID || ep.TargetRef.Name != p.Pod.Name || ep.TargetRef.Namespace != cfg.Namespace || len(ep.Addresses) == 0 {
						return fail()
					}
					ready++
				}
			}
			stamps = append(stamps, slice)
		}
		if list.Continue == "" {
			if ready == 0 {
				return fail()
			}
			raw, err := ce.Canonical(stamps)
			if err != nil {
				return fail()
			}
			return hash(raw), nil
		}
		if len(list.Continue) > 2048 || strings.ContainsAny(list.Continue, "\x00\r\n") || seen[list.Continue] {
			return fail()
		}
		seen[list.Continue] = true
		cursor = list.Continue
	}
	return fail()
}

func minioPermissionOwned(owners []metav1.OwnerReference, kind string, expected minioPermissionObject) bool {
	n := 0
	for _, owner := range owners {
		if owner.Controller != nil && *owner.Controller {
			if owner.Kind != kind || owner.Name != expected.Name || string(owner.UID) != expected.UID {
				return false
			}
			n++
		}
	}
	return n == 1
}
