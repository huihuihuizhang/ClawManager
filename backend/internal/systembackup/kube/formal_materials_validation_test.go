package kube

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestFormalMaterialPreflightRejectsSameInvalidPathsAsJobBuilder(t *testing.T) {
	for _, name := range []string{"credential.json", "bad:name", "bad\\name", "bad\x00name", "bad\nname", "bad\rname", "../name"} {
		m := &FormalJobMaterials{ConfigMap: "original-mapping", Inputs: []FormalInputMount{{Volume: "formal-source", Kind: "Secret", Name: "original-source", Directory: "/run/backup/materials/original", Items: []corev1.KeyToPath{{Key: "credential", Path: name}}}}}
		err := ValidateFormalJobMaterials(m)
		if name == "credential.json" && err != nil || name != "credential.json" && err == nil {
			t.Fatal("projection preflight parity", name, err)
		}
	}
}
