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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func originalRuntimeTestProfile() (*originalRuntimeStartupImage, corev1.PodSpec) {
	p := &originalRuntimeStartupImage{runtime: "hermes", manifest: strings.Repeat("a", 64), config: strings.Repeat("b", 64), entrypoint: []string{"/init"}, defaults: map[string]string{"PATH": "/usr/local/bin:/usr/bin:/bin", "S6_STAGE2_HOOK": "/docker-mods", "HOME": "/config"}}
	c := corev1.Container{Name: "runtime", Image: "registry.invalid/hermes@sha256:" + p.manifest, Env: []corev1.EnvVar{{Name: "RUNTIME_AGENT_CONTROL_TOKEN", Value: strings.Repeat("c", 64)}, {Name: "RUNTIME_AGENT_REPORT_TOKEN", Value: strings.Repeat("d", 64)}, {Name: "RUNTIME_WORKSPACE_ROOT", Value: "/workspaces"}}}
	return p, corev1.PodSpec{Containers: []corev1.Container{c}}
}
func TestOriginalRuntimeStartupSharedNoModsInterpretation(t *testing.T) {
	p, s := originalRuntimeTestProfile()
	launch, env, e := decodeOriginalRuntimeStartup(p, &s, &s.Containers[0])
	if e != nil || launch != "fixed-s6-shared-no-configured-mods" || env["RUNTIME_AGENT_DATA_DIR"] != "/var/lib/clawmanager-agent" {
		t.Fatal("fixed known comparison input not interpreted")
	}
	// The actual common deployment uses matching legacy aliases as well.
	s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "CLAWMANAGER_AGENT_CONTROL_TOKEN", Value: strings.Repeat("c", 64)})
	if _, _, e = decodeOriginalRuntimeStartup(p, &s, &s.Containers[0]); e != nil {
		t.Fatal("matching explicit alias")
	}
	s.Containers[0].Command = []string{"/usr/local/bin/clawmanager-agent"}
	if launch, _, e = decodeOriginalRuntimeStartup(p, &s, &s.Containers[0]); e != nil || launch != "direct-fixed-shared-agent" {
		t.Fatal("exact direct startup comparison")
	}
}
func TestOriginalRuntimeStartupRefusesConfiguredOrAmbiguousInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*corev1.PodSpec)
	}{
		{"defined_empty_mods", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "DOCKER_MODS", Value: ""})
		}},
		{"mod_only", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "MODMANAGER_MODONLY", Value: "1"})
		}},
		{"keep_inherited_env", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "S6_KEEP_ENV", Value: "1"})
		}},
		{"unknown_hook", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "S6_STAGE2_HOOK", Value: "/workspaces/hook"})
		}},
		{"env_from", func(s *corev1.PodSpec) { s.Containers[0].EnvFrom = []corev1.EnvFromSource{{Prefix: "x"}} }},
		{"startup_secret_is_not_loaded_env", func(s *corev1.PodSpec) {
			s.Containers[0].Env[0].Value = ""
			s.Containers[0].Env[0].ValueFrom = &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "current"}, Key: "control"}}
		}},
		{"partial_mode", func(s *corev1.PodSpec) { s.Containers[0].Env = s.Containers[0].Env[1:] }},
		{"whitespace_raw_token", func(s *corev1.PodSpec) { s.Containers[0].Env[0].Value = " " + strings.Repeat("c", 64) }},
		{"loader_override", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "LD_AUDIT", Value: "/workspaces/a.so"})
		}},
		{"shell_function", func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "BASH_FUNC_sleep%%", Value: "() { bad; }"})
		}},
		{"startup_mount", func(s *corev1.PodSpec) {
			s.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "x", MountPath: "/etc/services.d"}}
		}},
		{"mutable_home_autostart", func(s *corev1.PodSpec) {
			s.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "x", MountPath: "/config"}}
		}},
		{"extra_command", func(s *corev1.PodSpec) { s.Containers[0].Command = []string{"/bin/sh", "-c", "whatever"} }},
		{"sidecar", func(s *corev1.PodSpec) { s.Containers = append(s.Containers, corev1.Container{Name: "extra"}) }},
		{"init", func(s *corev1.PodSpec) { s.InitContainers = []corev1.Container{{Name: "extra"}} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p, s := originalRuntimeTestProfile()
			tt.change(&s)
			if _, _, e := decodeOriginalRuntimeStartup(p, &s, &s.Containers[0]); e == nil {
				t.Fatal("unsupported startup input accepted")
			}
		})
	}
}
func TestOriginalRuntimeImageIdentityIsExactContentAddress(t *testing.T) {
	p, s := originalRuntimeTestProfile()
	c := &s.Containers[0]
	images := map[string]*originalRuntimeStartupImage{p.manifest: p}
	st := &corev1.ContainerStatus{Name: c.Name, ContainerID: "containerd://actual", ImageID: "sha256:" + p.config}
	if originalRuntimeImageForContainer(images, c, st) != p {
		t.Fatal("qualified config association")
	}
	st.ImageID = "sha256:" + strings.Repeat("f", 64)
	if originalRuntimeImageForContainer(images, c, st) != nil {
		t.Fatal("unrelated image accepted")
	}
	st.ImageID = "sha256:" + p.manifest
	c.Image = "registry.invalid/hermes:latest"
	if originalRuntimeImageForContainer(images, c, st) != nil {
		t.Fatal("mutable spec locator accepted")
	}
}
func TestOriginalRuntimeImageNoCallerClaimOrTypedPodCreatesDisposition(t *testing.T) {
	_, s := originalRuntimeTestProfile()
	pod := &corev1.Pod{Spec: s}
	status := &corev1.ContainerStatus{Name: s.Containers[0].Name, ContainerID: "containerd://claimed", ImageID: s.Containers[0].Image}
	if d, e := classifyOriginalBackupRuntimePeer(context.Background(), nil, nil, pod, &s, &s.Containers[0], status, time.Now().Add(time.Minute)); e == nil || d.kind != "" {
		t.Fatal("typed caller input minted original disposition")
	}
	if _, e := loadOriginalRuntimeImageInputs(context.Background(), BootstrapSourceFilePin{File: "claimed", SHA256: strings.Repeat("a", 64)}); e == nil {
		t.Fatal("unread input pin accepted")
	}
}
func TestOriginalRuntimeManagedLayerRejectsForeignEntries(t *testing.T) {
	for _, name := range []string{"../escape", "usr/local/bin/unreviewed", "usr/local/bin/clawmanager-agent"} {
		t.Run(name, func(t *testing.T) {
			var raw bytes.Buffer
			gz := gzip.NewWriter(&raw)
			tw := tar.NewWriter(gz)
			body := []byte("not-an-approved-Agent")
			if tw.WriteHeader(&tar.Header{Name: name, Mode: 0555, Uid: 0, Gid: 0, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}) != nil {
				t.Fatal("model header")
			}
			if _, e := tw.Write(body); e != nil {
				t.Fatal("model body")
			}
			if tw.Close() != nil || gz.Close() != nil {
				t.Fatal("model close")
			}
			file := filepath.Join(t.TempDir(), "layer.gz")
			if os.WriteFile(file, raw.Bytes(), 0600) != nil {
				t.Fatal("model file")
			}
			sum := sha256.Sum256(raw.Bytes())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, _, _, e := readOriginalRuntimeLayer(ctx, BootstrapSourceFilePin{File: file, SHA256: hex.EncodeToString(sum[:])}, "hermes", int64(raw.Len())); e == nil {
				t.Fatal("unreviewed content entered profile")
			}
		})
	}
}
