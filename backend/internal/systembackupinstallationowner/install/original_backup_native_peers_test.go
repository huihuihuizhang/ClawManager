package install

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestOriginalBackupNativePeerActualEntryData(t *testing.T) {
	spec := &corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/original/minio"}}}, {Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "original-config"}}}}}}
	minio := &corev1.Container{Args: []string{"server", "/data", "--console-address", ":9001"}, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}
	vault := &corev1.Container{Command: []string{"/bin/vault"}, Args: []string{"server", "-config=/config/server.json"}, VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config", ReadOnly: true}}}
	if !originalPeerMinIOEntry(spec, minio) || !originalPeerVaultEntry(spec, vault) {
		t.Fatal("actual finite native entry DATA not recognized")
	}
	for _, mode := range []string{"minio-shell", "minio-client", "minio-remote-root", "minio-no-root", "vault-dev", "vault-replacement", "vault-writable-config", "vault-unbound-config"} {
		t.Run(mode, func(t *testing.T) {
			m, v := minio.DeepCopy(), vault.DeepCopy()
			switch mode {
			case "minio-shell":
				m.Command = []string{"/bin/sh", "-c"}
			case "minio-client":
				m.Args = []string{"mirror", "/data", "external"}
			case "minio-remote-root":
				m.Args = []string{"server", "https://other/data"}
			case "minio-no-root":
				m.Args = []string{"server", "--console-address", ":9001"}
			case "vault-dev":
				v.Args = []string{"server", "-dev"}
			case "vault-replacement":
				v.VolumeMounts = append(v.VolumeMounts, corev1.VolumeMount{Name: "data", MountPath: "/bin"})
			case "vault-writable-config":
				v.VolumeMounts[0].ReadOnly = false
			case "vault-unbound-config":
				v.Args = []string{"server", "-config=/missing/server.json"}
			}
			if mode[:5] == "minio" {
				if originalPeerMinIOEntry(spec, m) {
					t.Fatal("unknown MinIO invocation accepted")
				}
			} else {
				if originalPeerVaultEntry(spec, v) {
					t.Fatal("unknown Vault invocation accepted")
				}
			}
		})
	}
}

func TestOriginalBackupNativePeerRejectsZeroActor(t *testing.T) {
	if _, _, _, _, err := originalPeerWholeNativeActor(context.Background(), nil, &corev1.Pod{}, &corev1.ContainerStatus{}); err == nil {
		t.Fatal("caller identity became B native actor")
	}
	if _, err := classifyOriginalBackupNativePeer(context.Background(), nil, nil, nil, nil, nil, nil, time.Time{}); err == nil {
		t.Fatal("zero original context became native consumer classification")
	}
}
