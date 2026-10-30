package kube

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestTeamWorkspaceJobsKeepVerifierAndInputReadOnly(t *testing.T) {
	r := JobRequest{Identity: Identity{"cm-drill-team", "team-verify", "original-owner"}, Image: "fixture/worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "verify", Command: []string{"/worker"}, Source: corev1.Volume{Name: "team-data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "isolated-team"}}}, StagingClaim: "original-staged-input", DeadlineSeconds: 120}
	job, err := TeamWorkspaceJob(r, "verify-team-workspace")
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
		if (mount.Name == "workspace" || mount.Name == "staging") && !mount.ReadOnly {
			t.Fatal("verifier has writable data mount", mount)
		}
	}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if (volume.Name == "workspace" || volume.Name == "staging") && volume.PersistentVolumeClaim != nil && !volume.PersistentVolumeClaim.ReadOnly {
			t.Fatal("verifier has writable PVC", volume.Name)
		}
	}
	if r.Source.PersistentVolumeClaim.ReadOnly {
		t.Fatal("caller mapping changed")
	}
	if _, err := TeamWorkspaceJob(r, "restore-workspace"); err == nil {
		t.Fatal("restore without explicit writable target accepted")
	}
	r.Restore = true
	job, err = TeamWorkspaceJob(r, "restore-workspace")
	if err != nil {
		t.Fatal(err)
	}
	mounts := job.Spec.Template.Spec.Containers[0].VolumeMounts
	if mounts[0].ReadOnly || !mounts[1].ReadOnly {
		t.Fatal("restore target/input permissions reversed")
	}
}
