package systembackupexecution

import (
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	corev1 "k8s.io/api/core/v1"
)

// Only metadata path/coverage semantics are tested here. There is no native
// process/CRI positive, held gate, Installer capability or copied P7 authority.
func TestCurrentStoppedProTemplateRootAndSubPathBoundary(t *testing.T) {
	cases := []struct {
		name, declaredSubPath, dataPath, actualSubPath, actualClaim string
		accept                                                      bool
	}{
		{"empty-pvc-root", "", "/workspace", "", "owned", true},
		{"explicit-dot-root", ".", "/workspace", ".", "owned", true},
		{"root-covers-current-nested-alias", "", "/workspace", "nested", "owned", true},
		{"exact-private-subpath", "private", "/workspace", "private", "owned", true},
		{"private-data-suffix", "", "/workspace/private", "private/nested", "owned", true},
		{"outside-private-subpath", "private", "/workspace", "private-other", "owned", false},
		{"broader-than-declared-private", "private", "/workspace", "", "owned", false},
		{"wrong-pvc", "", "/workspace", "", "foreign", false},
		{"parent-traversal", "", "/workspace", "../outside", "owned", false},
		{"absolute-subpath", "", "/workspace", "/outside", "owned", false},
		{"noncanonical-subpath", "", "/workspace", "private/../outside", "owned", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			layout := CurrentStoppedProLayout{InstanceID: 7, Mounts: []CurrentStoppedProMountLayout{{MountID: "workspace", Claim: "owned", MountPath: "/workspace", DataPath: tc.dataPath, SubPath: tc.declaredSubPath}}}
			spec := corev1.PodSpec{Containers: []corev1.Container{{Name: "desktop", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/workspace", SubPath: tc.actualSubPath}}}}, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: tc.actualClaim}}}}}
			err := currentStoppedProTemplateCoverage(b.InstanceIdentity{ID: 7}, spec, layout)
			if (err == nil) != tc.accept {
				t.Fatalf("coverage accept=%v, want %v; error=%v", err == nil, tc.accept, err)
			}
		})
	}
}
