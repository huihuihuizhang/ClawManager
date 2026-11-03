package install

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func originalPeerAdmissionFixture() (*corev1.Pod, *corev1.PodSpec, corev1.Container) {
	c := corev1.Container{Name: "original", Image: "original-fixed-image", Args: []string{"redis-server", "--appendonly", "yes"}}
	selected := &corev1.PodSpec{Containers: []corev1.Container{c}}
	mode, expiration := int32(420), int64(3607)
	m := corev1.VolumeMount{Name: "kube-api-access-original", MountPath: originalPeerServiceAccountPath, ReadOnly: true}
	actual := c.DeepCopy()
	actual.VolumeMounts = []corev1.VolumeMount{m}
	pod := &corev1.Pod{Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{*actual}, Volumes: []corev1.Volume{{Name: m.Name, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: &mode, Sources: []corev1.VolumeProjection{
		{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expiration}},
		{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
		{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}},
	}}}}}}}
	return pod, selected, c
}

func TestOriginalBackupPeerRecognizesOnlyDefaultAdmissionProjection(t *testing.T) {
	pod, selected, c := originalPeerAdmissionFixture()
	before := pod.DeepCopy()
	if !originalPeerCapturedContainerEqual(pod, selected, pod.Spec.Containers[0], c) {
		t.Fatal("original default SA injection rejected")
	}
	if !reflect.DeepEqual(pod, before) {
		t.Fatal("comparison changed original capture")
	}
	for _, mode := range []string{"unknown-env", "unknown-mount", "writable-token", "different-ca", "different-namespace-field", "audience", "other-account", "selected-token", "explicit-disabled", "extra-source", "extra-volume-kind"} {
		t.Run(mode, func(t *testing.T) {
			p, s, c := originalPeerAdmissionFixture()
			switch mode {
			case "unknown-env":
				p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "ADMITTED_OVERRIDE", Value: "different"}}
			case "unknown-mount":
				p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: "/entry"})
			case "writable-token":
				p.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
			case "different-ca":
				p.Spec.Volumes[0].Projected.Sources[1].ConfigMap.Name = "other-ca"
			case "different-namespace-field":
				p.Spec.Volumes[0].Projected.Sources[2].DownwardAPI.Items[0].FieldRef.FieldPath = "metadata.name"
			case "audience":
				p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "other"
			case "other-account":
				s.ServiceAccountName = "other"
			case "selected-token":
				c.VolumeMounts = []corev1.VolumeMount{{Name: "other", MountPath: originalPeerServiceAccountPath, ReadOnly: true}}
			case "explicit-disabled":
				v := false
				s.AutomountServiceAccountToken = &v
			case "extra-source":
				p.Spec.Volumes[0].Projected.Sources = append(p.Spec.Volumes[0].Projected.Sources, corev1.VolumeProjection{})
			case "extra-volume-kind":
				p.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/other"}
			}
			if originalPeerCapturedContainerEqual(p, s, p.Spec.Containers[0], c) {
				t.Fatal("unknown original input disappeared")
			}
		})
	}
}

func TestOriginalBackupPeerFullMembershipAllowsOriginalAdmissionOnly(t *testing.T) {
	pod, s, c := originalPeerAdmissionFixture()
	status := corev1.ContainerStatus{Name: c.Name, ImageID: originalPeerRedisImage, ContainerID: "containerd://original"}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{status}
	if !originalPeerContainerMatches(pod, s, &c, &status, false) {
		t.Fatal("actual original Pod/RS membership with default admission did not match")
	}
	changed := s.DeepCopy()
	changed.Containers[0].Args = []string{"/external/backup"}
	if originalPeerContainerMatches(pod, changed, &changed.Containers[0], &status, false) {
		t.Fatal("different actual entry borrowed original native identity")
	}
}
