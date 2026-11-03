package install

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Invoked only after the original retained Pod/container and exact native
// Vault startup were checked. This consumes a genuine kept-provider dependency;
// it does not manufacture a cold observation or classify by requested role.
func originalBackupKeptVaultPeer(ctx context.Context, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, container *corev1.Container, status *corev1.ContainerStatus, until time.Time) (originalBackupStartupDisposition, bool, error) {
	var zero originalBackupStartupDisposition
	if h == nil || h.set == nil || pod == nil || spec == nil || container == nil || status == nil {
		return zero, true, ErrInstall
	}
	selected := false
	for _, dependency := range h.set.providerDependencies {
		if dependency == nil {
			return zero, true, ErrInstall
		}
		selected = selected || dependency.initial.PodUID == string(pod.UID)
	}
	for _, dependency := range h.set.preAdoptionProviders {
		if dependency == nil {
			return zero, true, ErrInstall
		}
		selected = selected || dependency.scope.PodUID == string(pod.UID)
	}
	if selected {
		identity, cap, err := h.originalVaultProviderPeer(ctx, string(pod.UID), status.ContainerID, status.ImageID)
		if err != nil || !digestPattern.MatchString(identity) || cap.IsZero() {
			return zero, true, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
		if until.IsZero() || !time.Now().Before(until) {
			return zero, true, ErrInstall
		}
		const profile = "original-kept-vault-provider-startup.v1"
		source := originalObjectSHA(struct {
			Version, Dependency, PodUID, ContainerID, ImageID string
			Spec                                              corev1.PodSpec
			Container                                         corev1.Container
		}{profile, identity, string(pod.UID), status.ContainerID, status.ImageID, *spec, *container})
		return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: profile, sourceSHA256: source, until: until}, true, nil
	}
	return zero, false, nil
}
