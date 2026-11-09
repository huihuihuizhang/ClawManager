package systembackupexecution

import (
	"context"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Initial discovery observes the signed original Pod. Later held checks use
// that frozen mount's node: stopping the source must not rediscover placement.
func tenantSourceMountNode(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, pin runningTenantProMount, previous *productionInstanceMount) (string, error) {
	if client == nil || !pin.valid() || !validTenantProNamespace(cfg.Namespace, pin.Source) {
		return "", kube.ErrOwnership
	}
	var name string
	if previous != nil {
		if previous.InstanceID != pin.Source.ID || previous.MountID != "workspace" || previous.DataOnly || previous.Source.PersistentVolumeClaim == nil || previous.Source.PersistentVolumeClaim.ClaimName != pin.Identity.Name {
			return "", kube.ErrOwnership
		}
		name = previous.NodeName
	} else {
		pod, err := client.CoreV1().Pods(pin.Source.Namespace).Get(ctx, pin.Source.Pod, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) != pin.PodUID || kube.ContentHash(pod.Spec) != pin.PodSpecSHA256 {
			return "", kube.ErrOwnership
		}
		name = pod.Spec.NodeName
	}
	if name == "" || cfg.Security.NodeUIDs[name] == "" {
		return "", kube.ErrOwnership
	}
	node, err := client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil || node.DeletionTimestamp != nil || string(node.UID) != cfg.Security.NodeUIDs[name] || node.Labels[corev1.LabelOSStable] != "linux" {
		return "", kube.ErrOwnership
	}
	return name, nil
}
