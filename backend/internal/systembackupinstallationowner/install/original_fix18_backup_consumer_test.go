package install

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func originalFix18ProfilePodModel() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "original", Name: "application", UID: "actual-pod-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "application", Image: "10.130.14.23:5000/clawmanager:fix18"}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "application", ImageID: "10.130.14.23:5000/clawmanager@" + originalFix18Index, ContainerID: "containerd://original-container"}}}}
}

// These are DATA shape/source-profile models only. They do not authenticate
// actual Kube objects, complete consumers, original source history or NoS3.
func TestOriginalFix18BackupReadContainerSupported(t *testing.T) {
	cases := []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"original_image_defaults", func(*corev1.Pod) {}},
		{"explicit_original_pair", func(p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{"dumb-init", "--"}
			p.Spec.Containers[0].Args = []string{"/app/start.sh"}
		}},
		{"business_yaml_mount", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "business-config", MountPath: "/app/config.yaml", ReadOnly: true}}
		}},
		{"business_storage_environment", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "OBJECT_STORAGE_ENDPOINT", Value: "business-source:9000"}, {Name: "SYSTEM_BACKUP_READ_LIVE", Value: "true"}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := originalFix18ProfilePodModel()
			c.change(p)
			got, err := classifyOriginalFix18BackupReadContainer(p, "application")
			if err != nil || got.id != "actual-pod-uid/application" || got.kind != "original_non_backup_consumer" || got.sourceVersion != originalFix18ConsumerProfileVersion || !digestPattern.MatchString(got.sourceSHA256) {
				t.Fatal("actual closed launch profile refused or lost")
			}
		})
	}
}

func TestOriginalFix18BackupReadContainerRejectsConcreteOverrides(t *testing.T) {
	cases := []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"tag_only", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "10.130.14.23:5000/clawmanager:fix18" }},
		{"another_image", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].ImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"independent_controller", func(p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{"/usr/local/bin/clawreef-system-backup-controller"}
		}},
		{"arbitrary_shell", func(p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{"sh", "-c"}
			p.Spec.Containers[0].Args = []string{"/app/start.sh; unknown-backup"}
		}},
		{"executable_overlay", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "override", MountPath: "/usr/local/bin/clawreef-server"}}
		}},
		{"entrypoint_ancestor_overlay", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "override", MountPath: "/app"}}
		}},
		{"path_override", func(p *corev1.Pod) { p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "PATH", Value: "/mounted"}} }},
		{"unresolved_environment_from", func(p *corev1.Pod) {
			p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "actual-exec-selection"}}}}
		}},
		{"missing_actual_status", func(p *corev1.Pod) { p.Status.ContainerStatuses = nil }},
		{"duplicate_container", func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, p.Spec.Containers[0]) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := originalFix18ProfilePodModel()
			c.change(p)
			if _, err := classifyOriginalFix18BackupReadContainer(p, "application"); err == nil {
				t.Fatal("unresolved actual source accepted")
			}
		})
	}
}

func TestOriginalFix18BackupReadContainerProjectionKeepsActualSource(t *testing.T) {
	p := originalFix18ProfilePodModel()
	a, err := classifyOriginalFix18BackupReadContainer(p, "application")
	if err != nil {
		t.Fatal("model source")
	}
	p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "BUSINESS_CONFIG_REVISION", Value: "changed"}}
	b, err := classifyOriginalFix18BackupReadContainer(p, "application")
	if err != nil || a.sourceSHA256 == b.sourceSHA256 {
		t.Fatal("source projection lost actual spec")
	}
	if _, err = classifyOriginalFix18BackupReadContainer(nil, "application"); err == nil {
		t.Fatal("nil source accepted")
	}
}
