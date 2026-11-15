package kube

import (
	corev1 "k8s.io/api/core/v1"
	"reflect"
	"strings"
)

// ValidOriginalTeamAttachmentPodSpec checks the fixed inert read-only consumer.
// It is only a shape check; callers must authenticate team, volume and live process identities.
func ValidOriginalTeamAttachmentPodSpec(p *corev1.Pod, claim, image string) bool {
	if p == nil || p.UID == "" || p.DeletionTimestamp != nil || len(p.OwnerReferences) != 0 || len(p.Finalizers) != 0 || !strings.Contains(image, "@sha256:") {
		return false
	}
	s := p.Spec
	if s.NodeName == "" || s.HostNetwork || s.HostPID || s.HostIPC || s.ShareProcessNamespace != nil && *s.ShareProcessNamespace || s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken || s.ServiceAccountName != "default" || len(s.InitContainers) != 0 || len(s.EphemeralContainers) != 0 || len(s.Containers) != 1 || len(s.Volumes) != 1 || s.RestartPolicy != corev1.RestartPolicyNever {
		return false
	}
	v := s.Volumes[0]
	expected := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim, ReadOnly: true}}}
	if !reflect.DeepEqual(v, expected) {
		return false
	}
	c := s.Containers[0]
	if c.Name != "attachment" || c.Image != image || !reflect.DeepEqual(c.Command, []string{"/bin/sh", "-ec"}) || !reflect.DeepEqual(c.Args, []string{"exec sleep 2147483647"}) || len(c.Env) != 0 || len(c.EnvFrom) != 0 || c.Lifecycle != nil || c.LivenessProbe != nil || c.ReadinessProbe != nil || c.StartupProbe != nil || len(c.VolumeDevices) != 0 || len(c.Ports) != 0 {
		return false
	}
	if !reflect.DeepEqual(c.VolumeMounts, []corev1.VolumeMount{{Name: "source", MountPath: "/source", ReadOnly: true}}) {
		return false
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged != nil && *sc.Privileged || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || !reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		return false
	}
	if s.SecurityContext != nil && (s.SecurityContext.FSGroup != nil || len(s.SecurityContext.Sysctls) != 0) {
		return false
	}
	return true
}
