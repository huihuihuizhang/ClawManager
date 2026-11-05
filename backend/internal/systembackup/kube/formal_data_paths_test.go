package kube

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestOriginalFormalDataPathProjectsSameReadOnlyItem(t *testing.T) {
	m := &FormalJobMaterials{ProjectionProtocol: OriginalFormalDataPathsV1, ConfigMap: "original-formal", Inputs: []FormalInputMount{{Volume: "formal-inputs", Kind: "Secret", Name: "original-inputs", Directory: "/run/backup/materials/inputs", Items: []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}}, DataPaths: map[string]string{"ca.pem": "/run/system-backup/runtime/original/ca.pem"}}}}
	j := &batchv1.Job{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{}}}}}}
	if err := attachFormalMaterials(j, m); err != nil {
		t.Fatal(err)
	}
	aliases := 0
	for _, v := range j.Spec.Template.Spec.Containers[0].VolumeMounts {
		if v.MountPath == m.Inputs[0].DataPaths["ca.pem"] {
			if v.Name != "formal-inputs" || !v.ReadOnly || v.SubPath != "ca.pem" {
				t.Fatal("original item projection changed")
			}
			aliases++
		}
	}
	if aliases != 1 || j.Spec.Template.Spec.Volumes[0].Secret == nil || j.Spec.Template.Spec.Volumes[0].Secret.SecretName != "original-inputs" {
		t.Fatal("original immutable secret projection missing")
	}
	m.ProjectionProtocol = ""
	if ValidateFormalJobMaterials(m) == nil {
		t.Fatal("new paths accepted without explicit protocol")
	}
}

func TestOriginalFormalDataPathRefusesUnrelatedAndOverlappingPaths(t *testing.T) {
	for _, destination := range []string{"/etc/passwd", "/run/system-backup/runtime/../owner.private", "/var/lib/system-backup/staging", "/run/system-backup/runtime/a\\b"} {
		m := &FormalJobMaterials{ProjectionProtocol: OriginalFormalDataPathsV1, ConfigMap: "original-formal", Inputs: []FormalInputMount{{Volume: "formal-inputs", Kind: "Secret", Name: "original-inputs", Directory: "/run/backup/materials/inputs", Items: []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}}, DataPaths: map[string]string{"ca.pem": destination}}}}
		if ValidateFormalJobMaterials(m) == nil {
			t.Fatalf("unrelated data path accepted: %s", destination)
		}
	}
	m := &FormalJobMaterials{ProjectionProtocol: OriginalFormalDataPathsV1, ConfigMap: "original-formal", Inputs: []FormalInputMount{{Volume: "formal-inputs", Kind: "Secret", Name: "original-inputs", Directory: "/run/backup/materials/inputs", Items: []corev1.KeyToPath{{Key: "one", Path: "one"}, {Key: "two", Path: "two"}}, DataPaths: map[string]string{"one": "/run/system-backup/runtime/one", "two": "/run/system-backup/runtime/one/two"}}}}
	if ValidateFormalJobMaterials(m) == nil {
		t.Fatal("overlapping projected files accepted")
	}
}
