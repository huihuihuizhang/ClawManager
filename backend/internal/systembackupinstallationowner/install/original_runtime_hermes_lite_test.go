package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func originalHermesLiteTestProfile() (*originalRuntimeStartupImage, corev1.PodSpec) {
	image, spec := originalRuntimeTestProfile()
	image.hermesLite = true
	image.manifest = originalHermesLiteNativeManifest
	image.entrypoint = []string{"/usr/bin/tini", "--", "/usr/local/bin/hermes-lite-entrypoint"}
	image.defaults = map[string]string{
		"PATH":                                   "/opt/hermes-agent/.venv/bin:/usr/local/bin:/usr/bin:/bin",
		"CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED": "true",
		"CLAWMANAGER_HERMES_BACKEND_MODE":        "serve",
	}
	spec.Containers[0].Image = "registry.invalid/hermes@sha256:" + image.manifest
	spec.Containers[0].Env = append(spec.Containers[0].Env,
		corev1.EnvVar{Name: "RUNTIME_GATEWAY_COMMAND", Value: "start-hermes-lite-runtime"},
		corev1.EnvVar{Name: "RUNTIME_AGENT_ROLE", Value: ""})
	spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
		{Name: "workspace", MountPath: "/workspaces"},
		{Name: "tls", MountPath: "/run/clawmanager-agent-tls", ReadOnly: true},
		{Name: "serviceaccount", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
	}
	return image, spec
}

func TestOriginalHermesLiteStartupExactStandaloneProfile(t *testing.T) {
	image, spec := originalHermesLiteTestProfile()
	launch, env, err := decodeOriginalRuntimeStartup(image, &spec, &spec.Containers[0])
	if err != nil || launch != "fixed-hermes-lite-shared-entrypoint" || env["RUNTIME_AGENT_DATA_DIR"] != "/var/lib/clawmanager-agent" {
		t.Fatal("pinned Lite startup comparison failed", err)
	}
}

func TestOriginalHermesLiteStartupRefusesDifferentProfileOrMountedAssets(t *testing.T) {
	for _, name := range []string{"pool", "slot", "pro", "command", "entrypoint", "manifest", "venv", "release", "python", "tokens"} {
		t.Run(name, func(t *testing.T) {
			image, spec := originalHermesLiteTestProfile()
			container := &spec.Containers[0]
			switch name {
			case "pool", "slot":
				container.Env[len(container.Env)-1].Value = name
			case "pro":
				container.Env = append(container.Env, corev1.EnvVar{Name: "CLAWMANAGER_AGENT_ENABLED", Value: " TRUE "})
			case "command":
				container.Env[len(container.Env)-2].Value = "/workspaces/launcher"
			case "entrypoint":
				image.entrypoint = []string{"/bin/sh", "-c", "/usr/local/bin/hermes-lite-entrypoint"}
			case "manifest":
				image.manifest = originalHermesSelectedManifest
			case "venv", "release", "python":
				path := map[string]string{"venv": "/opt/hermes-agent/.venv", "release": "/usr/local/share/hermes-lite", "python": "/usr/local/lib"}[name]
				container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "override", MountPath: path})
			case "tokens":
				// Secret metadata alone is still not an actual loaded-environment
				// observation. This new image profile does not relax that boundary.
				container.Env[0].Value = ""
				container.Env[0].ValueFrom = &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "current"}, Key: "control"}}
			}
			if _, _, err := decodeOriginalRuntimeStartup(image, &spec, container); err == nil {
				t.Fatal("unsupported profile admitted")
			}
		})
	}
}

func TestOriginalHermesLiteLayerRejectsUnreviewedRelease(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(gz)
	body := []byte(`{"desktop_web_accepted":true}`)
	if err := archive.WriteHeader(&tar.Header{Name: "usr/local/share/hermes-lite/release.json", Mode: 0444,
		Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "unreviewed-release.tar.gz")
	if err := os.WriteFile(file, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(compressed.Bytes())
	for _, lite := range []bool{false, true} {
		if _, _, _, err := readOriginalRuntimeLayerProfile(context.Background(), BootstrapSourceFilePin{
			File: file, SHA256: hex.EncodeToString(sum[:])}, "hermes", int64(compressed.Len()), lite); err == nil {
			t.Fatal("unreviewed release metadata accepted")
		}
	}
}
