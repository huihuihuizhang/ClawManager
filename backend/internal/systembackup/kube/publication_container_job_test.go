package kube

import (
	"strings"
	"testing"
)

func TestPublishJobContainerMountRetainsTaskAndPartIsolation(t *testing.T) {
	owner := "sbk_11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"current", "other-task", "other-part", "directory", "key", "traversal", "unknown-part"} {
		t.Run(mode, func(t *testing.T) {
			file := PublishInputFile{Path: "parts/workspace/container.enc", SubPath: owner + "/publication-" + strings.Repeat("a", 64) + "/container-workspace.enc"}
			switch mode {
			case "other-task":
				file.SubPath = strings.Replace(file.SubPath, owner, "sbk_22222222-2222-4222-8222-222222222222", 1)
			case "other-part":
				file.Path = "parts/mysql/container.enc"
			case "directory":
				file.SubPath = strings.TrimSuffix(file.SubPath, "/container-workspace.enc")
			case "key":
				file.SubPath = ".controller-stage-owner-keys/owner.key"
			case "traversal":
				file.SubPath = strings.Replace(file.SubPath, "/container-workspace.enc", "/../container-workspace.enc", 1)
			case "unknown-part":
				file.SubPath = strings.ReplaceAll(file.SubPath, "container-workspace.enc", "container-other.enc")
			}
			request := PublishJobRequest{Identity: Identity{Namespace: "backup", Name: "pub-container", Owner: owner}, Image: "worker@sha256:" + strings.Repeat("b", 64), ServiceAccount: "upload-only", StagingClaim: "original-stage", InvocationConfigMap: "request", UploadCredentialSecret: "finite-upload", RequestSHA256: strings.Repeat("c", 64), DeadlineSeconds: 30, InputFiles: []PublishInputFile{file}}
			job, err := PublishJob(request)
			if mode != "current" {
				if err == nil || job != nil {
					t.Fatal("foreign or broad input mounted", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for _, mount := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
				if mount.Name == "staging" {
					seen++
					if !mount.ReadOnly || mount.SubPath != file.SubPath || mount.MountPath != "/input/"+file.Path {
						t.Fatal("container mount widened", mount)
					}
				}
			}
			if seen != 1 {
				t.Fatal("actual input not mounted once")
			}
		})
	}
}
