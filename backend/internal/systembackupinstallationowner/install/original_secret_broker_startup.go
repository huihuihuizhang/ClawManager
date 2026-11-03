package install

import (
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Exact original September broker image, not ldap-test-zh-fix14 (2483...),
// the later fix18 server, a tag family, or a general image-repository exemption.
const originalSecretBrokerImage = "10.130.14.23:5000/clawmanager@sha256:1ba8cc47f468610e6875117f75fe42ce9fdb15e1cd2e6f877ac8ff2f99e2baa0"
const originalSecretBrokerProfile = "original-secret-broker-explicit-startup.v1"
const originalSecretBrokerMainSHA = "2354c18def304fadbecbaf69b81a22e935344b69d84a2544b9d2dd6876a62ede"
const originalSecretBrokerWaitSourceSHA = "0bebb1eae6aee27403dc25334fe866eb2a6697721975aa83c8a39c41736dd6b8"
const originalSecretBrokerTLSPath = "/var/run/secrets/clawmanager-secret-broker-tls"
const originalSecretBrokerCAPath = "/var/run/secrets/clawmanager-secret-broker-ca"

// Reproduce only the reviewed script's namespace interpolation. No shell
// parser, substring/openssl-presence check, arbitrary URL or caller script hash.
func originalSecretBrokerWaitScript(namespace string) string {
	return fmt.Sprintf("until openssl s_client \\\n  -connect clawmanager-secret-broker.%s.svc.cluster.local:9444 \\\n  -servername clawmanager-secret-broker.%s.svc.cluster.local \\\n  -verify_hostname clawmanager-secret-broker.%s.svc.cluster.local \\\n  -verify_return_error \\\n  -CAfile /var/run/secrets/clawmanager-secret-broker-ca/ca.crt \\\n  </dev/null >/dev/null 2>&1; do\n  sleep 2\ndone\n", namespace, namespace, namespace)
}

func originalSecretBrokerScriptTokens(raw string) string {
	if strings.ContainsAny(raw, "\x00\r$`\"'") {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\\\n", "")
	if strings.Contains(raw, "\\") {
		return ""
	}
	return strings.Join(strings.Fields(raw), " ")
}

// This decoder examines the actual selected startup DATA. It does not issue a
// hold, identify a whole source universe, sign NoS3 or read business secrets.
func originalSecretBrokerStartupEntry(namespace string, spec *corev1.PodSpec, c *corev1.Container, init bool) bool {
	if len(validation.IsDNS1123Label(namespace)) != 0 || spec == nil || c == nil || c.Image != originalSecretBrokerImage || c.Lifecycle != nil || len(c.EnvFrom) != 0 || len(c.VolumeDevices) != 0 || c.WorkingDir != "" && c.WorkingDir != "/app" {
		return false
	}
	for _, p := range []*corev1.Probe{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe} {
		if p != nil {
			if init || p.HTTPGet == nil || p.Exec != nil || p.TCPSocket != nil || p.GRPC != nil {
				return false
			}
			h := p.HTTPGet
			if h.Host != "" || len(h.HTTPHeaders) != 0 || h.Scheme != corev1.URISchemeHTTPS || h.Path != "/readyz" && h.Path != "/healthz" || h.Port.String() != "https" && h.Port.String() != "9444" {
				return false
			}
		}
	}
	for _, e := range c.Env {
		switch e.Name {
		case "PATH", "ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "SHELLOPTS", "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES":
			return false
		}
	}
	if init {
		if c.Name != "wait-secret-broker" || !reflect.DeepEqual(c.Command, []string{"/bin/sh", "-ceu"}) || len(c.Args) != 1 || len(c.Env) != 0 || originalSecretBrokerScriptTokens(c.Args[0]) != originalSecretBrokerScriptTokens(originalSecretBrokerWaitScript(namespace)) {
			return false
		}
	} else {
		if c.Name != "secret-broker" || !reflect.DeepEqual(c.Command, []string{"/usr/local/bin/clawreef-secret-broker"}) || len(c.Args) != 0 {
			return false
		}
		cert, key := false, false
		seen := map[string]bool{}
		for _, e := range c.Env {
			if seen[e.Name] {
				return false
			}
			seen[e.Name] = true
			switch e.Name {
			case "CLAWMANAGER_SECRET_BROKER_TLS_CERT_FILE":
				cert = e.ValueFrom == nil && e.Value == originalSecretBrokerTLSPath+"/tls.crt"
			case "CLAWMANAGER_SECRET_BROKER_TLS_KEY_FILE":
				key = e.ValueFrom == nil && e.Value == originalSecretBrokerTLSPath+"/tls.key"
			}
		}
		if !cert || !key {
			return false
		}
	}
	requiredPath, requiredName := originalSecretBrokerTLSPath, "secret-broker-tls"
	if init {
		requiredPath, requiredName = originalSecretBrokerCAPath, "secret-broker-ca"
	}
	required := false
	mountNames := map[string]bool{}
	for _, m := range c.VolumeMounts {
		if mountNames[m.Name] {
			return false
		}
		mountNames[m.Name] = true
		if m.MountPath == originalPeerServiceAccountPath {
			if !originalSecretBrokerServiceAccountProjection(spec, m) {
				return false
			}
			continue
		}
		if required || !reflect.DeepEqual(m, corev1.VolumeMount{Name: requiredName, MountPath: requiredPath, ReadOnly: true}) {
			return false
		}
		var volume *corev1.Volume
		for n := range spec.Volumes {
			if spec.Volumes[n].Name == m.Name {
				if volume != nil {
					return false
				}
				volume = &spec.Volumes[n]
			}
		}
		if volume == nil {
			return false
		}
		if init {
			if volume.ConfigMap == nil || volume.ConfigMap.Name != "clawmanager-secret-broker-ca" || !reflect.DeepEqual(volume.VolumeSource, corev1.VolumeSource{ConfigMap: volume.ConfigMap}) {
				return false
			}
			if len(volume.ConfigMap.Items) > 1 {
				return false
			}
			for _, item := range volume.ConfigMap.Items {
				if item.Key != "ca.crt" || item.Path != "ca.crt" {
					return false
				}
			}
		} else {
			if volume.Secret == nil || volume.Secret.SecretName != "clawmanager-secret-broker-tls" || !reflect.DeepEqual(volume.VolumeSource, corev1.VolumeSource{Secret: volume.Secret}) {
				return false
			}
			if len(volume.Secret.Items) != 0 {
				keys := map[string]bool{}
				for _, item := range volume.Secret.Items {
					if item.Key != item.Path || item.Key != "tls.crt" && item.Key != "tls.key" || keys[item.Key] {
						return false
					}
					keys[item.Key] = true
				}
				if len(keys) != 2 {
					return false
				}
			}
		}
		required = true
	}
	return required
}

// Reuse C r3's COMPLETE native projection comparator as DATA validation only.
// The detached comparison excludes the one admission-added volume. Actual Pod
// identity and requested-template equivalence are checked by the real bridge.
func originalSecretBrokerServiceAccountProjection(spec *corev1.PodSpec, m corev1.VolumeMount) bool {
	selected := spec.DeepCopy()
	selected.Volumes = nil
	for _, v := range spec.Volumes {
		if v.Name != m.Name {
			selected.Volumes = append(selected.Volumes, v)
		}
	}
	return originalPeerDefaultServiceAccountMount(&corev1.Pod{Spec: *spec}, selected, m)
}
