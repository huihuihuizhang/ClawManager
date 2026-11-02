package kube

import corev1 "k8s.io/api/core/v1"

// SourceRecoveryPodSpecMatches uses the same explicit API/scheduler default
// whitelist as the original worker observer. It grants no source authority and
// permits no extra environment, mounts, sidecars or admission-time rewrites.
func SourceRecoveryPodSpecMatches(expected, actual corev1.PodSpec) bool {
	e, err := jsonMap(expected)
	if err != nil {
		return false
	}
	a, err := jsonMap(actual)
	return err == nil && podSpecMatches(e, a, true)
}
