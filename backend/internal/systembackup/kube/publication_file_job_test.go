package kube

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPublishJobMountsOnlyIndividualObservedCipherFiles(t *testing.T) {
	r := PublishJobRequest{Identity: Identity{Namespace: "backup", Name: "pub-original", Owner: "sbk_11111111-1111-4111-8111-111111111111"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "upload-only", StagingClaim: "original-capture-staging", InvocationConfigMap: "original-request", UploadCredentialSecret: "finite-put-grants", RequestSHA256: strings.Repeat("b", 64), DeadlineSeconds: 300, InputFiles: []PublishInputFile{{Path: "parts/1/original.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("c", 64) + ".enc"}, {Path: "parts/1/original.envelope.json", SubPath: ".controller-seals/seal-" + strings.Repeat("d", 64) + ".enc"}}}
	job, err := PublishJob(r)
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec
	if !pod.Volumes[0].PersistentVolumeClaim.ReadOnly {
		t.Fatal("original C volume writable")
	}
	results := false
	for _, volume := range pod.Volumes {
		if volume.Name == "publication-result" {
			results = volume.EmptyDir != nil && volume.EmptyDir.Medium == corev1.StorageMediumMemory
		}
	}
	if !results {
		t.Fatal("publish result was placed in original capture volume")
	}
	seen := 0
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "staging" {
			seen++
			if !mount.ReadOnly || mount.MountPath == "/input" || mount.SubPath == ".controller-seals" {
				t.Fatal("worker acquired whole private custody", mount)
			}
		}
	}
	if seen != len(r.InputFiles) {
		t.Fatal("incomplete original C mount set")
	}
	for _, bad := range []string{".controller-stage-owner-keys/original.key", ".controller-seals", ".controller-seals/../secret", ".controller-seals/unknown.enc", "/other/seal-" + strings.Repeat("c", 64) + ".enc"} {
		other := r
		other.InputFiles = append([]PublishInputFile(nil), r.InputFiles...)
		other.InputFiles[0].SubPath = bad
		if _, err = PublishJob(other); err == nil {
			t.Fatal("unobserved/private-key custody mount accepted", bad)
		}
	}
	other := r
	other.InputFiles = append([]PublishInputFile(nil), r.InputFiles...)
	other.InputFiles[1].SubPath = other.InputFiles[0].SubPath
	if _, err = PublishJob(other); err == nil {
		t.Fatal("same private input aliased into another part")
	}
	interleaved := []PublishInputFile{{Path: "parts/a.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("1", 64) + ".enc"}, {Path: "parts/a.enc-x.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("2", 64) + ".enc"}, {Path: "parts/a.enc/child.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("3", 64) + ".enc"}}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		other := r
		other.InputFiles = []PublishInputFile{interleaved[order[0]], interleaved[order[1]], interleaved[order[2]]}
		if _, err = PublishJob(other); err == nil {
			t.Fatal("file/directory overlap hidden by intervening lexical sibling", order)
		}
	}
}
