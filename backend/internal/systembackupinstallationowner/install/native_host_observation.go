package install

import (
	"context"
	"encoding/json"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func observeNativeMappedBootstrapHost(ctx context.Context, kube kubernetes.Interface, original BootstrapOriginalHost, binding BootstrapNativeHostBinding) (evidence.BootstrapOriginalHostObservation, error) {
	var zero evidence.BootstrapOriginalHostObservation
	input := binding.Source
	if input.Namespace != original.Namespace || input.NamespaceUID != original.NamespaceUID || input.Pod != original.Pod || input.PodUID != original.PodUID || input.ServiceAccount != original.ServiceAccount || input.ServiceAccountUID != original.ServiceAccountUID {
		return zero, ErrInstall
	}
	observed, err := evidence.ObserveBootstrapOriginalHost(ctx, kube, binding.Source)
	if err != nil || observed.WorkloadIdentitySHA256 != binding.WorkloadIdentitySHA256 || observed.WorkloadIdentitySHA256 != original.WorkloadIdentitySHA256 || observed.PodSpecSHA256 != binding.Source.PodSpecSHA256 {
		return zero, ErrInstall
	}
	// Workload derivation alone must not bridge a different C1 producer issuer.
	// Read the SAME exact immutable peer source selected and verified by D.
	cm, err := kube.CoreV1().ConfigMaps(input.Namespace).Get(ctx, input.PeerConfigMap, metav1.GetOptions{})
	if err != nil || string(cm.UID) != input.PeerConfigMapUID || cm.Namespace != input.Namespace || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable {
		return zero, ErrInstall
	}
	text, hasText := cm.Data[input.PeerKey]
	binary, hasBinary := cm.BinaryData[input.PeerKey]
	if hasText == hasBinary {
		return zero, ErrInstall
	}
	peerRaw := binary
	if hasText {
		peerRaw = []byte(text)
	}
	var peer evidence.SystemPeerConfig
	if len(peerRaw) == 0 || len(peerRaw) > 262144 || hash(peerRaw) != input.PeerSHA256 || json.Unmarshal(peerRaw, &peer) != nil || peer.Scope != input.Scope || peer.IssuerIdentityHash != binding.ProducerIssuerIdentitySHA256 {
		return zero, ErrInstall
	}
	// The frozen A mapping used JCS(PodSpec); D's native source uses the exact
	// json.Marshal(PodSpec) profile. Bridge both on ONE actual Pod object. Never
	// compare these distinct profile hashes as though they were interchangeable.
	pod, err := kube.CoreV1().Pods(original.Namespace).Get(ctx, original.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != original.PodUID || pod.Namespace != original.Namespace || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.ServiceAccountName != original.ServiceAccount {
		return zero, ErrInstall
	}
	raw, err := json.Marshal(pod.Spec)
	if err != nil || hash(raw) != binding.Source.PodSpecSHA256 {
		return zero, ErrInstall
	}
	jcs, err := canonical(pod.Spec)
	if err != nil || hash(jcs) != original.PodSpecSHA256 {
		return zero, ErrInstall
	}
	imageFound := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != binding.Source.Container {
			continue
		}
		if imageFound || status.ImageID != binding.Source.ContainerImageID || status.ContainerID == "" || !status.Ready || status.State.Running == nil {
			return zero, ErrInstall
		}
		imageFound = true
	}
	if !imageFound || !time.Now().Before(observed.Until) || ctx.Err() != nil {
		return zero, ErrInstall
	}
	return observed, nil
}
