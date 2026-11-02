package install

import (
	"context"

	owner "clawreef/internal/systembackupinstallationowner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func observeBootstrapOriginalHost(ctx context.Context, i *Installer, record owner.Record, workload string) (BootstrapOriginalHost, error) {
	var zero BootstrapOriginalHost
	b := record.Binding
	if i == nil || nilClient(i.kube) || !digestPattern.MatchString(workload) || record.Target != i.plan.Target || b.Namespace != i.plan.Target.Namespace || b.NamespaceUID != i.plan.Target.NamespaceUID {
		return zero, ErrInstall
	}
	for _, pin := range [][2]string{{"kube-system", i.plan.Target.ClusterID}, {i.plan.Target.Namespace, i.plan.Target.NamespaceUID}} {
		ns, e := i.kube.CoreV1().Namespaces().Get(ctx, pin[0], metav1.GetOptions{})
		if e != nil || string(ns.UID) != pin[1] || ns.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
	}
	pod, e := i.kube.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
	if e != nil || string(pod.UID) != b.PodUID || pod.Namespace != b.Namespace || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.ServiceAccountName != b.ServiceAccountName {
		return zero, ErrInstall
	}
	sa, e := i.kube.CoreV1().ServiceAccounts(b.Namespace).Get(ctx, b.ServiceAccountName, metav1.GetOptions{})
	if e != nil || string(sa.UID) != b.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	spec, e := canonical(pod.Spec)
	if e != nil {
		return zero, ErrInstall
	}
	return BootstrapOriginalHost{WorkloadIdentitySHA256: workload, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Pod: b.PodName, PodUID: b.PodUID, ServiceAccount: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodSpecSHA256: hash(spec)}, nil
}
