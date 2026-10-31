package systembackupkekadapter

import (
	"context"
	"time"

	kms "clawreef/internal/systembackupkms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const VerifierKubernetesReadsVersion = "system-backup-verifier-kubernetes-reads.v1"

// Exact existing actor/owner lookup coordinates in independently pinned
// deployment materials. No task/Invocation/candidate hash enters this ABI.
// UID authorization still comes from the independent business grant and the
// provider permission's ControllerVerifier workload; this is not a grant.
type VerifierKubernetesReads struct {
	Version                                                                         string `json:"schema_version"`
	Namespace, NamespaceUID, PodName, PodUID, ServiceAccountName, ServiceAccountUID string
	OwnerKind, OwnerName, OwnerUID                                                  string
	ReplicaSetName, ReplicaSetUID                                                   string `json:",omitempty"`
}

type VerifierNamedRead struct{ Namespace, Group, Resource, Name string }

func (r VerifierKubernetesReads) Validate(w ControllerVerifierWorkload) error {
	for _, value := range []string{r.NamespaceUID, r.PodUID, r.ServiceAccountUID, r.OwnerUID} {
		if value == "" || len(value) > 256 {
			return kms.ErrPermission
		}
	}
	if r.Version != VerifierKubernetesReadsVersion || r.Namespace != w.Namespace || r.PodName != w.PodName || r.PodUID != w.PodUID || r.ServiceAccountName != w.ServiceAccountName || r.ServiceAccountUID != w.ServiceAccountUID || r.OwnerKind != w.OwnerKind || r.OwnerUID != w.OwnerUID || r.NamespaceUID == "" || r.OwnerName == "" || r.OwnerUID == "" || len(validation.IsDNS1123Label(r.Namespace)) != 0 {
		return kms.ErrPermission
	}
	for _, name := range []string{r.PodName, r.ServiceAccountName, r.OwnerName} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return kms.ErrPermission
		}
	}
	if r.OwnerKind == "Deployment" {
		if len(validation.IsDNS1123Subdomain(r.ReplicaSetName)) != 0 || r.ReplicaSetUID == "" {
			return kms.ErrPermission
		}
	} else if (r.OwnerKind != "StatefulSet" && r.OwnerKind != "Job") || r.ReplicaSetName != "" || r.ReplicaSetUID != "" {
		return kms.ErrPermission
	}
	return nil
}

// RequiredReads is the ONE inventory used by live checking and exact RBAC/
// SelfSubjectAccessReview generation. Every entry is a named GET only.
func (r VerifierKubernetesReads) RequiredReads(w ControllerVerifierWorkload) ([]VerifierNamedRead, error) {
	if err := r.Validate(w); err != nil {
		return nil, err
	}
	out := []VerifierNamedRead{{Group: "", Resource: "namespaces", Name: r.Namespace}, {Namespace: r.Namespace, Group: "", Resource: "pods", Name: r.PodName}, {Namespace: r.Namespace, Group: "", Resource: "serviceaccounts", Name: r.ServiceAccountName}}
	switch r.OwnerKind {
	case "Deployment":
		out = append(out, VerifierNamedRead{r.Namespace, "apps", "replicasets", r.ReplicaSetName}, VerifierNamedRead{r.Namespace, "apps", "deployments", r.OwnerName})
	case "StatefulSet":
		out = append(out, VerifierNamedRead{r.Namespace, "apps", "statefulsets", r.OwnerName})
	case "Job":
		out = append(out, VerifierNamedRead{r.Namespace, "batch", "jobs", r.OwnerName})
	}
	return out, nil
}

// Check refuses an unexpected owner coordinate BEFORE doing any owner GET.
// The controller need not gain list/all-names or source writer permissions.
func (r VerifierKubernetesReads) Check(ctx context.Context, k kubernetes.Interface, w ControllerVerifierWorkload) error {
	if nilSource(ctx) || ctx.Err() != nil || nilSource(k) || r.Validate(w) != nil {
		return kms.ErrPermission
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := k.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return kms.ErrPermission
	}
	pod, err := k.CoreV1().Pods(r.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != r.PodUID || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || pod.Spec.ServiceAccountName != r.ServiceAccountName || len(pod.OwnerReferences) != 1 {
		return kms.ErrPermission
	}
	sa, err := k.CoreV1().ServiceAccounts(r.Namespace).Get(ctx, r.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != r.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return kms.ErrPermission
	}
	owner := pod.OwnerReferences[0]
	if owner.Controller == nil || !*owner.Controller {
		return kms.ErrPermission
	}
	if r.OwnerKind == "Deployment" {
		if owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || owner.Name != r.ReplicaSetName || string(owner.UID) != r.ReplicaSetUID {
			return kms.ErrPermission
		}
		rs, e := k.AppsV1().ReplicaSets(r.Namespace).Get(ctx, r.ReplicaSetName, metav1.GetOptions{})
		if e != nil || string(rs.UID) != r.ReplicaSetUID || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
			return kms.ErrPermission
		}
		parent := rs.OwnerReferences[0]
		if parent.Controller == nil || !*parent.Controller || parent.Kind != "Deployment" || parent.APIVersion != "apps/v1" || parent.Name != r.OwnerName || string(parent.UID) != r.OwnerUID {
			return kms.ErrPermission
		}
		d, e := k.AppsV1().Deployments(r.Namespace).Get(ctx, r.OwnerName, metav1.GetOptions{})
		if e != nil || string(d.UID) != r.OwnerUID || d.DeletionTimestamp != nil {
			return kms.ErrPermission
		}
		return nil
	}
	if owner.Kind != r.OwnerKind || owner.Name != r.OwnerName || string(owner.UID) != r.OwnerUID {
		return kms.ErrPermission
	}
	if r.OwnerKind == "StatefulSet" {
		if owner.APIVersion != "apps/v1" {
			return kms.ErrPermission
		}
		o, e := k.AppsV1().StatefulSets(r.Namespace).Get(ctx, r.OwnerName, metav1.GetOptions{})
		if e != nil || string(o.UID) != r.OwnerUID || o.DeletionTimestamp != nil {
			return kms.ErrPermission
		}
		return nil
	}
	if owner.APIVersion != "batch/v1" {
		return kms.ErrPermission
	}
	o, e := k.BatchV1().Jobs(r.Namespace).Get(ctx, r.OwnerName, metav1.GetOptions{})
	if e != nil || string(o.UID) != r.OwnerUID || o.DeletionTimestamp != nil {
		return kms.ErrPermission
	}
	return nil
}
