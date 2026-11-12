package install

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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

func TestOriginalVaultPersistentInstallerEntrypointAndFiniteInitializer(t *testing.T) {
	input := VaultProviderWorkloadSelection{Container: "vault", Claim: "private-provider-data", DataMountPath: "/data"}
	uid, no, yes := int64(65532), false, true
	base := corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &yes, FSGroup: &uid},
		Containers:      []corev1.Container{{Name: "vault", Command: []string{"/bin/vault", "server", "-config=/config/server.json"}, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}, {Name: "config", MountPath: "/config", ReadOnly: true}}}},
		Volumes:         []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: input.Claim}}}, {Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "original-provider-config"}}}}},
		InitContainers: []corev1.Container{{Name: "prepare-raft-directory", Image: originalProviderVaultImage, ImagePullPolicy: corev1.PullNever,
			Command:                []string{"/bin/sh", "-ec", "umask 077; mkdir -p /data/raft; test -d /data/raft; test -w /data/raft"},
			TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}},
	}
	if !originalVaultMountSpec(base, input) {
		t.Fatal("original persistent installer profile rejected")
	}
	for name, mutate := range map[string]func(*corev1.PodSpec){
		"extra-server-argument":  func(s *corev1.PodSpec) { s.Containers[0].Command = append(s.Containers[0].Command, "-dev") },
		"extra-init":             func(s *corev1.PodSpec) { s.InitContainers = append(s.InitContainers, s.InitContainers[0]) },
		"different-init-program": func(s *corev1.PodSpec) { s.InitContainers[0].Command[2] += "; echo unexpected" },
		"different-init-image":   func(s *corev1.PodSpec) { s.InitContainers[0].Image = "unreviewed/image" },
		"injected-init-environment": func(s *corev1.PodSpec) {
			s.InitContainers[0].Env = []corev1.EnvVar{{Name: "BASH_ENV", Value: "/data/custom"}}
		},
		"another-init-mount": func(s *corev1.PodSpec) { s.InitContainers[0].VolumeMounts[0].MountPath = "/other" },
		"init-capability": func(s *corev1.PodSpec) {
			s.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		},
		"root-owner": func(s *corev1.PodSpec) { zero := int64(0); s.SecurityContext.RunAsUser = &zero },
	} {
		t.Run(name, func(t *testing.T) {
			s := base.DeepCopy()
			mutate(s)
			if originalVaultMountSpec(*s, input) {
				t.Fatal("different initializer or source accepted")
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
