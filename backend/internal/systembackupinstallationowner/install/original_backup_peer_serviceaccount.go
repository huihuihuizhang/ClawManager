package install

import (
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const originalPeerServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// The actual admission-injected SA projection is not present in an unmodified
// ReplicaSet template. Recognize only its complete code-owned native shape.
// No source bytes/config/env or unknown webhook fields are discarded. This
// helper compares DATA from the genuine original capture; it grants no native
// actor/consumer/SQL authority on its own.
func originalPeerCapturedContainerEqual(pod *corev1.Pod, selected *corev1.PodSpec, actual, requested corev1.Container) bool {
	if reflect.DeepEqual(actual, requested) {
		return true
	}
	if pod == nil || selected == nil {
		return false
	}
	// An explicit selected mount at this location must compare normally. It
	// cannot be relabelled as an implicit default to excuse changed material.
	for _, m := range requested.VolumeMounts {
		if m.MountPath == originalPeerServiceAccountPath {
			return false
		}
	}
	copy := actual.DeepCopy()
	copy.VolumeMounts = nil
	removed := false
	for _, m := range actual.VolumeMounts {
		if m.MountPath != originalPeerServiceAccountPath {
			copy.VolumeMounts = append(copy.VolumeMounts, m)
			continue
		}
		if removed || !originalPeerDefaultServiceAccountMount(pod, selected, m) {
			return false
		}
		removed = true
	}
	// The exact requested nil-vs-empty representation is retained once the
	// only injected mount was removed. The original actual input is immutable.
	if len(copy.VolumeMounts) == 0 && requested.VolumeMounts != nil {
		copy.VolumeMounts = []corev1.VolumeMount{}
	}
	return removed && reflect.DeepEqual(*copy, requested)
}

func originalPeerDefaultServiceAccountMount(pod *corev1.Pod, selected *corev1.PodSpec, m corev1.VolumeMount) bool {
	if pod == nil || selected == nil || !strings.HasPrefix(m.Name, "kube-api-access-") || len(m.Name) <= len("kube-api-access-") || !reflect.DeepEqual(m, corev1.VolumeMount{Name: m.Name, MountPath: originalPeerServiceAccountPath, ReadOnly: true}) {
		return false
	}
	if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken || selected.AutomountServiceAccountToken != nil && !*selected.AutomountServiceAccountToken {
		return false
	}
	account := func(s string) string {
		if s == "" {
			return "default"
		}
		return s
	}
	if account(pod.Spec.ServiceAccountName) != account(selected.ServiceAccountName) {
		return false
	}
	for _, v := range selected.Volumes {
		if v.Name == m.Name {
			return false
		}
	}
	var found *corev1.Volume
	for n := range pod.Spec.Volumes {
		if pod.Spec.Volumes[n].Name == m.Name {
			if found != nil {
				return false
			}
			found = &pod.Spec.Volumes[n]
		}
	}
	if found == nil || found.Projected == nil || found.Projected.DefaultMode == nil || *found.Projected.DefaultMode != 420 || len(found.Projected.Sources) != 3 {
		return false
	}
	if !reflect.DeepEqual(found.VolumeSource, corev1.VolumeSource{Projected: found.Projected}) {
		return false
	}
	token, ca, namespace := false, false, false
	for _, source := range found.Projected.Sources {
		switch {
		case source.ServiceAccountToken != nil:
			x := source.ServiceAccountToken
			if token || !reflect.DeepEqual(source, corev1.VolumeProjection{ServiceAccountToken: x}) || x.Path != "token" || x.Audience != "" || x.ExpirationSeconds == nil || *x.ExpirationSeconds < 3600 || *x.ExpirationSeconds > 3607 {
				return false
			}
			token = true
		case source.ConfigMap != nil:
			if ca || !reflect.DeepEqual(source, corev1.VolumeProjection{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}}) {
				return false
			}
			ca = true
		case source.DownwardAPI != nil:
			if namespace || !reflect.DeepEqual(source, corev1.VolumeProjection{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}}) {
				return false
			}
			namespace = true
		default:
			return false
		}
	}
	return token && ca && namespace
}
