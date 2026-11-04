package install

import (
	sec "clawreef/internal/systembackupsecurity"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"testing"
)

// These are native Pod-shape rejection tests, not issuer/native-field evidence.
func TestOriginalNonceMountRejectsUncontrolledOrChangedMount(t *testing.T) {
	source := OriginalNonceMaterial{Namespace: "backup", Secret: "actual-nonce-secret", Reference: sec.BootstrapSecretRef{Purpose: "nonce_hmac", IdentityHash: "nonce-identity", Version: "1"}}
	r := OriginalNonceMountBinding{ControllerPod: "controller", ControllerPodUID: "pod-uid", Container: "owner", Volume: "nonce", NonceDirectory: originalNonceMountDirectory, ServiceAccountName: "owner", ServiceAccountUID: "owner-uid", ContainerID: "containerd://actual", ImageID: "sha256:actual"}
	base := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: r.ControllerPod, Namespace: source.Namespace, UID: types.UID(r.ControllerPodUID)}, Spec: corev1.PodSpec{ServiceAccountName: "owner", Containers: []corev1.Container{{Name: "owner", VolumeMounts: []corev1.VolumeMount{{Name: "nonce", MountPath: originalNonceMountDirectory, ReadOnly: true}}}}, Volumes: []corev1.Volume{{Name: "nonce", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: source.Secret, Items: []corev1.KeyToPath{{Key: "nonce", Path: "nonce-identity/1"}}}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "owner", ContainerID: r.ContainerID, ImageID: r.ImageID, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	cases := []struct {
		name string
		bad  bool
		edit func(*corev1.Pod)
	}{
		{"exact-current-readonly-secret", false, func(*corev1.Pod) {}},
		{"other-secret", true, func(p *corev1.Pod) { p.Spec.Volumes[0].Secret.SecretName = "foreign" }},
		{"writable-mount", true, func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].ReadOnly = false }},
		{"subpath", true, func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].SubPath = "nonce" }},
		{"child-shadow", true, func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: originalNonceMountDirectory + "/nonce-identity/1"})
		}},
		{"wrong-version", true, func(p *corev1.Pod) { p.Spec.Volumes[0].Secret.Items[0].Path = "nonce-identity/2" }},
		{"optional-secret", true, func(p *corev1.Pod) { yes := true; p.Spec.Volumes[0].Secret.Optional = &yes }},
		{"container-restarted", true, func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "containerd://new" }},
		{"container-stopped", true, func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Running = nil }},
		{"pod-replaced", true, func(p *corev1.Pod) { p.UID = "other-pod" }},
		{"service-account-changed", true, func(p *corev1.Pod) { p.Spec.ServiceAccountName = "foreign" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := base.DeepCopy()
			tc.edit(pod)
			selected := r
			// Recompute pin deliberately so the semantic guards (rather than
			// merely a mismatched Pod-spec hash) reject the counterexample.
			raw, err := canonical(pod.Spec)
			if err != nil {
				t.Fatal(err)
			}
			selected.ControllerSpecSHA256 = hash(raw)
			err = verifyOriginalNonceMountPod(pod, source, selected)
			if (err != nil) != tc.bad {
				t.Fatalf("bad=%v, error=%v", tc.bad, err)
			}
		})
	}
}
