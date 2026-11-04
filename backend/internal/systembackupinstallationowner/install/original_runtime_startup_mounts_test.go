package install

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestOriginalRuntimeStartupRejectsMountedStageHookAndPathInterpreters(t *testing.T) {
	for _, mount := range []string{"/docker-mods", "/opt/node/bin", "/lsiopy/bin", "/opt", "/lsiopy"} {
		t.Run(mount, func(t *testing.T) {
			image, spec := originalRuntimeTestProfile()
			// Exact public PATH decoded from the immutable Hermes base config.
			image.defaults["PATH"] = "/opt/node/bin:/usr/local/bin:/lsiopy/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
			spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "override", MountPath: mount}}
			if _, _, err := decodeOriginalRuntimeStartup(image, &spec, &spec.Containers[0]); err == nil {
				t.Fatal("mounted hook or interpreter search directory accepted")
			}
		})
	}
}
