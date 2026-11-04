package install

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/netip"
	"net/url"
)

// Resolve the independently original Six provider's ACTUAL Kubernetes Service
// UID/ClusterIP and actual original Pod selector. Caller-supplied CA TargetIP
// cannot select an unrelated TLS endpoint even when certificate bytes match.
// This closed profile supports direct Service ClusterIP only, not guessed DNS
// resolution, arbitrary external IPs, ExternalName, headless or fallback IPs.
func (n *originalC1NativeObservation) verifyEvidenceCATarget(ctx context.Context) error {
	if n == nil || n.parent == nil || n.caWire == nil || n.six == nil || n.kind != "evidence-ca-actual-tls" || ctx.Err() != nil {
		return ErrInstall
	}
	provider := n.six.S3.Provider
	kube := n.parent.operator.installer.kube
	namespace := n.actor.Namespace
	ns, err := kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != n.actor.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrInstall
	}
	service, err := kube.CoreV1().Services(namespace).Get(ctx, provider.Service.Name, metav1.GetOptions{})
	if err != nil || string(service.UID) != provider.Service.UID || service.DeletionTimestamp != nil || service.Spec.Type == corev1.ServiceTypeExternalName || len(service.Spec.Selector) == 0 {
		return ErrInstall
	}
	ip, err := netip.ParseAddr(service.Spec.ClusterIP)
	if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Unmap() != n.caWire.TargetIP.Unmap() {
		return ErrInstall
	}
	endpoint, err := url.Parse(n.caWire.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil {
		return ErrInstall
	}
	host := endpoint.Hostname()
	if host != service.Name+"."+namespace+".svc" && host != service.Name+"."+namespace+".svc.cluster.local" && host != service.Spec.ClusterIP {
		return ErrInstall
	}
	pod, err := kube.CoreV1().Pods(namespace).Get(ctx, provider.Pod.Name, metav1.GetOptions{})
	if err != nil || string(pod.UID) != provider.Pod.UID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return ErrInstall
	}
	for key, value := range service.Spec.Selector {
		if pod.Labels[key] != value {
			return ErrInstall
		}
	}
	return nil
}
