package install

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func originalBrokerStartupTestSpec(init bool) (*corev1.PodSpec, *corev1.Container) {
	c := corev1.Container{Name: "secret-broker", Image: originalSecretBrokerImage, Command: []string{"/usr/local/bin/clawreef-secret-broker"}, Env: []corev1.EnvVar{{Name: "CLAWMANAGER_SECRET_BROKER_TLS_CERT_FILE", Value: originalSecretBrokerTLSPath + "/tls.crt"}, {Name: "CLAWMANAGER_SECRET_BROKER_TLS_KEY_FILE", Value: originalSecretBrokerTLSPath + "/tls.key"}}, VolumeMounts: []corev1.VolumeMount{{Name: "secret-broker-tls", MountPath: originalSecretBrokerTLSPath, ReadOnly: true}}}
	volume := corev1.Volume{Name: "secret-broker-tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "clawmanager-secret-broker-tls"}}}
	if init {
		c = corev1.Container{Name: "wait-secret-broker", Image: originalSecretBrokerImage, Command: []string{"/bin/sh", "-ceu"}, Args: []string{originalSecretBrokerWaitScript("clawmanager-zhanghui08-system")}, VolumeMounts: []corev1.VolumeMount{{Name: "secret-broker-ca", MountPath: originalSecretBrokerCAPath, ReadOnly: true}}}
		volume = corev1.Volume{Name: "secret-broker-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "clawmanager-secret-broker-ca"}}}}
	}
	spec := &corev1.PodSpec{Volumes: []corev1.Volume{volume}}
	if init {
		spec.InitContainers = []corev1.Container{c}
		return spec, &spec.InitContainers[0]
	}
	spec.Containers = []corev1.Container{c}
	return spec, &spec.Containers[0]
}

func TestOriginalSecretBrokerExplicitStartup(t *testing.T) {
	const ns = "clawmanager-zhanghui08-system"
	for _, init := range []bool{false, true} {
		spec, c := originalBrokerStartupTestSpec(init)
		if !originalSecretBrokerStartupEntry(ns, spec, c, init) {
			t.Fatal("reviewed explicit launch rejected", init)
		}
	}
	cases := map[string]func(*corev1.PodSpec, *corev1.Container){
		"default_image_server": func(s *corev1.PodSpec, c *corev1.Container) { c.Command = nil },
		"different_image_same_repository": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Image = "10.130.14.23:5000/clawmanager@sha256:2483f42b0ed33f829499281ce2b821791786ef7089fb8620f4b3f374c9d67e4b"
		},
		"mutable_tag": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Image = "10.130.14.23:5000/clawmanager:ldap-test-zh-fix14"
		},
		"extra_args":     func(s *corev1.PodSpec, c *corev1.Container) { c.Args = []string{"--capture"} },
		"exec_lifecycle": func(s *corev1.PodSpec, c *corev1.Container) { c.Lifecycle = &corev1.Lifecycle{} },
		"exec_probe": func(s *corev1.PodSpec, c *corev1.Container) {
			c.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "capture"}}}}
		},
		"env_from": func(s *corev1.PodSpec, c *corev1.Container) {
			c.EnvFrom = []corev1.EnvFromSource{{Prefix: "UNRESOLVED_"}}
		},
		"loader_env": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Env = append(c.Env, corev1.EnvVar{Name: "LD_PRELOAD", Value: "/extra.so"})
		},
		"executable_overlay": func(s *corev1.PodSpec, c *corev1.Container) {
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "overlay", MountPath: "/usr/local/bin", ReadOnly: true})
		},
		"tls_writable":       func(s *corev1.PodSpec, c *corev1.Container) { c.VolumeMounts[0].ReadOnly = false },
		"tls_different_path": func(s *corev1.PodSpec, c *corev1.Container) { c.Env[0].Value = "/other/tls.crt" },
		"tls_wrong_source":   func(s *corev1.PodSpec, c *corev1.Container) { s.Volumes[0].Secret.SecretName = "arbitrary" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, c := originalBrokerStartupTestSpec(false)
			change(s, c)
			if originalSecretBrokerStartupEntry(ns, s, c, false) {
				t.Fatal("unreviewed broker startup accepted")
			}
		})
	}
}

func TestOriginalSecretBrokerFixedWaitScript(t *testing.T) {
	const ns = "clawmanager-zhanghui08-system"
	cases := map[string]func(*corev1.PodSpec, *corev1.Container){
		"wrong_namespace": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Args[0] = strings.ReplaceAll(c.Args[0], ns, "other-system")
		},
		"extra_command": func(s *corev1.PodSpec, c *corev1.Container) { c.Args[0] += "capture\n" },
		"substitution": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Args[0] = strings.Replace(c.Args[0], "openssl", "$(capture) openssl", 1)
		},
		"weaker_tls": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Args[0] = strings.ReplaceAll(c.Args[0], "-verify_return_error", "")
		},
		"alternate_shell": func(s *corev1.PodSpec, c *corev1.Container) { c.Command = []string{"/bin/sh", "-c"} },
		"openssl_env": func(s *corev1.PodSpec, c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "OPENSSL_CONF", Value: "/overlay/config"}}
		},
		"mounted_script": func(s *corev1.PodSpec, c *corev1.Container) {
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "script", MountPath: "/scripts", ReadOnly: true})
		},
		"wrong_ca_source": func(s *corev1.PodSpec, c *corev1.Container) { s.Volumes[0].ConfigMap.Name = "unknown-ca" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, c := originalBrokerStartupTestSpec(true)
			change(s, c)
			if originalSecretBrokerStartupEntry(ns, s, c, true) {
				t.Fatal("unreviewed wait startup accepted")
			}
		})
	}
}

func TestOriginalSecretBrokerBridgeNeedsActualOriginalOwner(t *testing.T) {
	for _, init := range []bool{false, true} {
		s, c := originalBrokerStartupTestSpec(init)
		if _, err := classifyOriginalSecretBrokerStartup(context.Background(), nil, nil, nil, s, c, nil, init); err == nil {
			t.Fatal("decoder data manufactured original owner")
		}
	}
	if _, err := readOriginalSecretBrokerConsumerLocked(context.Background(), nil, nil, "pod", "secret-broker", false); err == nil {
		t.Fatal("absent original capture read accepted")
	}
}
