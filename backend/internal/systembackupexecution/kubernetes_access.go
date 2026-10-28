package systembackupexecution

import (
	"context"
	"sort"
	"time"

	c "clawreef/internal/systembackupcontroller"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

type CaptureAccess struct {
	Namespace string
	Rule      rbacv1.PolicyRule
}

// RequiredCaptureAccess is the actual public platform-workspace call inventory.
// It grants no exec/log, source Secret access, source lifecycle creation/deletion,
// node proxy, role management or cluster wildcard. Dynamic worker names require
// get/create within the dedicated capture namespace, not the source namespaces.
func RequiredCaptureAccess(cfg DeploymentConfig) ([]CaptureAccess, error) {
	if cfg.Validate() != nil || len(validation.IsDNS1123Label(cfg.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(cfg.Security.ServiceAccountName)) != 0 {
		return nil, c.ErrExecutionAuthority
	}
	var out []CaptureAccess
	add := func(ns, group, resource string, verbs, names []string) {
		out = append(out, CaptureAccess{ns, rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: verbs, ResourceNames: names}})
	}
	add(cfg.Namespace, "", "pods", []string{"get", "list", "watch"}, nil)
	add(cfg.Namespace, "", "configmaps", []string{"get", "create"}, nil)
	add(cfg.Namespace, "", "secrets", []string{"get", "create"}, nil)
	add(cfg.Namespace, "batch", "jobs", []string{"get", "create", "delete"}, nil)
	add(cfg.Namespace, "", "serviceaccounts", []string{"get"}, []string{cfg.Security.ServiceAccountName})
	add(cfg.Namespace, "", "persistentvolumeclaims", []string{"get"}, sortedUnique([]string{cfg.Workspace.Claim, cfg.StagingClaim}))
	add(cfg.Namespace, "coordination.k8s.io", "leases", []string{"get", "update", "patch"}, []string{"clawmanager-public-backup-controller"})
	add(cfg.Namespace, "coordination.k8s.io", "leases", []string{"create"}, nil)
	namespaces := map[string][]string{}
	for _, ref := range cfg.Writers {
		if len(validation.IsDNS1123Label(ref.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 {
			return nil, c.ErrExecutionAuthority
		}
		namespaces[ref.Namespace] = append(namespaces[ref.Namespace], ref.Name)
	}
	for _, ns := range sortedKeys(namespaces) {
		add(ns, "apps", "deployments", []string{"get", "patch"}, sortedUnique(namespaces[ns]))
		add(ns, "apps", "replicasets", []string{"list"}, nil)
		add(ns, "autoscaling", "horizontalpodautoscalers", []string{"list"}, nil)
		if ns != cfg.Namespace {
			add(ns, "", "pods", []string{"get", "list", "watch"}, nil)
		}
	}
	nodes := make([]string, 0, len(cfg.Security.NodeUIDs))
	for node := range cfg.Security.NodeUIDs {
		if len(validation.IsDNS1123Subdomain(node)) != 0 {
			return nil, c.ErrExecutionAuthority
		}
		nodes = append(nodes, node)
	}
	var volumes []string
	for _, volume := range cfg.Security.Volumes {
		if volume.Kind == "PersistentVolumeClaim" {
			if volume.PVName == "" || volume.PVUID == "" || len(validation.IsDNS1123Subdomain(volume.PVName)) != 0 {
				return nil, c.ErrExecutionAuthority
			}
			volumes = append(volumes, volume.PVName)
		}
	}
	if len(volumes) == 0 {
		return nil, c.ErrExecutionAuthority
	}
	add("", "", "namespaces", []string{"get"}, []string{cfg.Namespace})
	add("", "", "nodes", []string{"get"}, sortedUnique(nodes))
	add("", "", "persistentvolumes", []string{"get"}, sortedUnique(volumes))
	add("", "authentication.k8s.io", "tokenreviews", []string{"create"}, nil)
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func sortedUnique(values []string) []string {
	m := map[string]bool{}
	for _, value := range values {
		m[value] = true
	}
	return sortedKeys(m)
}

// CaptureKubernetesGrants renders reviewable RBAC only. Applying it requires
// the installation administrator. No controller can create its own roles.
func CaptureKubernetesGrants(cfg DeploymentConfig, controllerSA string) ([]runtime.Object, error) {
	access, err := RequiredCaptureAccess(cfg)
	if err != nil || len(validation.IsDNS1123Subdomain(controllerSA)) != 0 || controllerSA == cfg.Security.ServiceAccountName {
		return nil, c.ErrExecutionAuthority
	}
	name := "cm-public-capture-" + hash([]byte(cfg.Namespace + "/" + controllerSA))[:12]
	subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: controllerSA, Namespace: cfg.Namespace}}
	namespaced := map[string][]rbacv1.PolicyRule{}
	var cluster []rbacv1.PolicyRule
	for _, item := range access {
		if item.Namespace == "" {
			cluster = append(cluster, item.Rule)
		} else {
			namespaced[item.Namespace] = append(namespaced[item.Namespace], item.Rule)
		}
	}
	var objects []runtime.Object
	for _, ns := range sortedKeys(namespaced) {
		meta := metav1.ObjectMeta{Name: name, Namespace: ns}
		objects = append(objects,
			&rbacv1.Role{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta, Rules: namespaced[ns]},
			&rbacv1.RoleBinding{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta, Subjects: subjects, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}})
	}
	objects = append(objects,
		&rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: cluster},
		&rbacv1.ClusterRoleBinding{TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: metav1.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}})
	return objects, nil
}

// This probe tests the current Kubernetes principal, not the configured name.
// No denial/error becomes readiness. Recovery itself does not depend on this
// forward-work probe and still uses original journals plus independent grants.
func CheckCaptureKubernetesAccess(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig) error {
	access, err := RequiredCaptureAccess(cfg)
	if err != nil || client == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, item := range access {
		names := item.Rule.ResourceNames
		if len(names) == 0 {
			names = []string{""}
		}
		for _, verb := range item.Rule.Verbs {
			for _, name := range names {
				review, e := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: item.Namespace, Verb: verb, Group: item.Rule.APIGroups[0], Resource: item.Rule.Resources[0], Name: name}}}, metav1.CreateOptions{})
				if e != nil || review == nil || !review.Status.Allowed || review.Status.Denied || review.Status.EvaluationError != "" {
					return c.ErrExecutionAuthority
				}
			}
		}
	}
	return nil
}
