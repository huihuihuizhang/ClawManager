package install

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// Finite source-profile tests only; no Kubernetes, SQL, CSI, Vault or TLS proof.
func TestOriginalVaultDependencyRejectsAdditionalWriterEntrypointsAndVolumes(t *testing.T) {
	input := VaultProviderWorkloadSelection{Container: "vault", Claim: "private-provider-data", DataMountPath: "/data"}
	base := corev1.PodSpec{
		Containers: []corev1.Container{{Name: "vault", Command: []string{"/bin/vault"}, Args: []string{"server", "-config=/config/vault.hcl"}, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}, {Name: "config", MountPath: "/config", ReadOnly: true}}}},
		Volumes:    []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: input.Claim}}}, {Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "provider-native-config"}}}}},
	}
	if !originalVaultMountSpec(base, input) {
		t.Fatal("native single provider source profile rejected")
	}
	cases := map[string]func(*corev1.PodSpec){
		"additional-container": func(s *corev1.PodSpec) {
			s.Containers = append(s.Containers, corev1.Container{Name: "unknown-sidecar"})
		},
		"init-writer":   func(s *corev1.PodSpec) { s.InitContainers = []corev1.Container{{Name: "unknown-init"}} },
		"shell-startup": func(s *corev1.PodSpec) { s.Containers[0].Command = []string{"/bin/sh", "-c"} },
		"preloaded-program": func(s *corev1.PodSpec) {
			s.Containers[0].Env = []corev1.EnvVar{{Name: "LD_PRELOAD", Value: "/data/custom.so"}}
		},
		"additional-host-source": func(s *corev1.PodSpec) {
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "business", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/business"}}})
		},
		"other-claim":           func(s *corev1.PodSpec) { s.Volumes[0].PersistentVolumeClaim.ClaimName = "business-workspaces" },
		"subpath-alias":         func(s *corev1.PodSpec) { s.Containers[0].VolumeMounts[0].SubPath = "shared-business" },
		"writable-config":       func(s *corev1.PodSpec) { s.Containers[0].VolumeMounts[1].ReadOnly = false },
		"extra-native-argument": func(s *corev1.PodSpec) { s.Containers[0].Args = append(s.Containers[0].Args, "-dev") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := base.DeepCopy()
			mutate(spec)
			if originalVaultMountSpec(*spec, input) {
				t.Fatal("additional writer/source accepted")
			}
		})
	}
}

func TestOriginalVaultDependencyCSIProfileIsFinite(t *testing.T) {
	base := &corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "actual-private-backend-volume", FSType: "ext4"}}}}
	if !originalVaultPrivateCSI(base) {
		t.Fatal("finite original provider profile rejected")
	}
	for name, mutate := range map[string]func(*corev1.PersistentVolume){
		"shared-rwx": func(p *corev1.PersistentVolume) {
			p.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
		},
		"unknown-backend": func(p *corev1.PersistentVolume) { p.Spec.CSI.Driver = "unknown.storage.example" },
		"unknown-handle":  func(p *corev1.PersistentVolume) { p.Spec.CSI.VolumeHandle = "" },
		"block-source":    func(p *corev1.PersistentVolume) { v := corev1.PersistentVolumeBlock; p.Spec.VolumeMode = &v },
		"readonly-source": func(p *corev1.PersistentVolume) { p.Spec.CSI.ReadOnly = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := base.DeepCopy()
			mutate(p)
			if originalVaultPrivateCSI(p) {
				t.Fatal("unsupported storage profile accepted")
			}
		})
	}
}
