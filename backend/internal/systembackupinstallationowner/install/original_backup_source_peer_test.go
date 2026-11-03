package install

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These tests verify finite DATA interpretation. They manufacture no native
// hold/metadata or positive original adoption authority.
func TestOriginalBackupSourcePeerNativeEntryData(t *testing.T) {
	for _, x := range []struct {
		binary string
		args   []string
	}{
		{"mysqld", []string{"--innodb-use-native-aio=0", "--binlog-expire-logs-seconds=259200", "--max-binlog-size=134217728"}},
		{"redis-server", []string{"redis-server", "--appendonly", "yes", "--tls-port", "6379", "--tls-cert-file", "/tls/server.pem"}},
	} {
		if !originalPeerNativeEntry(&corev1.PodSpec{}, &corev1.Container{Args: x.args}, x.binary) {
			t.Fatal("ordinary native startup was not recognized", x.binary)
		}
	}
	for _, mode := range []string{"shell", "module", "config", "missing-value", "abbreviation", "startup-mount", "loader-env", "unknown-envfrom", "lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			c := corev1.Container{Args: []string{"redis-server", "--appendonly", "yes"}}
			switch mode {
			case "shell":
				c.Command = []string{"/bin/sh", "-c"}
			case "module":
				c.Args = []string{"redis-server", "--loadmodule", "/data/custom.so"}
			case "config":
				c.Args = []string{"redis-server", "/data/redis.conf"}
			case "missing-value":
				c.Args = []string{"redis-server", "--appendonly"}
			case "abbreviation":
				c.Args = []string{"redis-server", "--loadmod", "/data/custom.so"}
			case "startup-mount":
				c.VolumeMounts = []corev1.VolumeMount{{Name: "override", MountPath: "/usr/local/bin/redis-server"}}
			case "loader-env":
				c.Env = []corev1.EnvVar{{Name: "LD_PRELOAD", Value: "/data/entry.so"}}
			case "unknown-envfrom":
				c.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "startup"}}}}
			case "lifecycle":
				c.Lifecycle = &corev1.Lifecycle{}
			}
			if originalPeerNativeEntry(&corev1.PodSpec{}, &c, "redis-server") {
				t.Fatal("overridden startup accepted without its concrete input")
			}
		})
	}
}

func TestOriginalBackupSourcePeerExactCapturedContainerData(t *testing.T) {
	c := corev1.Container{Name: "native", Image: "example/native@sha256:fixed", Args: []string{"redis-server", "--appendonly", "yes"}, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}
	s := corev1.ContainerStatus{Name: "native", ImageID: originalPeerRedisImage, ContainerID: "containerd://original"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original", UID: "original-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{c}, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{s}}}
	if !originalPeerContainerMatches(pod, &pod.Spec, &c, &s, false) {
		t.Fatal("same actual container did not match")
	}
	for _, mode := range []string{"args", "status", "volume", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			spec := pod.Spec.DeepCopy()
			candidate := c.DeepCopy()
			status := s.DeepCopy()
			switch mode {
			case "args":
				candidate.Args = []string{"/data/backup"}
				spec.Containers[0] = *candidate
			case "status":
				status.ImageID = "example/other@sha256:other"
			case "volume":
				spec.Volumes[0].EmptyDir = nil
				spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/other"}
			case "duplicate":
				spec.Containers = append(spec.Containers, *candidate)
			}
			if originalPeerContainerMatches(pod, spec, candidate, status, false) {
				t.Fatal("different actual member became native peer")
			}
		})
	}
	if !reflect.DeepEqual(c.Args, pod.Spec.Containers[0].Args) {
		t.Fatal("classification mutated original input")
	}
}

func TestOriginalBackupSourcePeerZeroOwnerRejected(t *testing.T) {
	if _, err := classifyOriginalBackupSourcePeer(context.Background(), nil, nil, nil, nil, nil, nil, false); err == nil {
		t.Fatal("zero native owner gave positive classification")
	}
	if _, err := originalPeerCapturedPod(nil, &corev1.Pod{}); err == nil {
		t.Fatal("caller Pod became captured original source")
	}
}
