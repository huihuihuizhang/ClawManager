package kube

import (
	"strings"
	"testing"
)

func TestPublishResultUsesOnlyOriginalCapsuleAndBoundPodToken(t *testing.T) {
	r := PublishJobRequest{Identity: Identity{Namespace: "backup", Name: "original-publish", Owner: "sbk_11111111-1111-4111-8111-111111111111"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "upload-only", StagingClaim: "original-ciphertext", InvocationConfigMap: "unused-request", UploadCredentialSecret: "original-capsule", RequestSHA256: strings.Repeat("b", 64), DeadlineSeconds: 300, ResultRelayURL: "https://controller.invalid/publication-result", InputFiles: []PublishInputFile{{Path: "parts/original.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("c", 64) + ".enc"}}}
	job, err := PublishJob(r)
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec
	secrets, tokens, ciphertext := 0, 0, 0
	for _, volume := range pod.Volumes {
		if volume.ConfigMap != nil || volume.HostPath != nil || volume.CSI != nil {
			t.Fatal("result worker gained another request/source/key source")
		}
		if volume.Secret != nil {
			if volume.Secret.SecretName != r.UploadCredentialSecret {
				t.Fatal("private material escaped original capsule")
			}
			secrets++
		}
		if volume.PersistentVolumeClaim != nil {
			if volume.PersistentVolumeClaim.ClaimName != r.StagingClaim || !volume.PersistentVolumeClaim.ReadOnly {
				t.Fatal("source/staging write capability")
			}
			ciphertext++
		}
		if volume.Projected != nil {
			if len(volume.Projected.Sources) != 1 {
				t.Fatal("additional projected authority")
			}
			token := volume.Projected.Sources[0].ServiceAccountToken
			if token == nil || token.Audience != WorkerTokenAudience || token.Path != "token" || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 {
				t.Fatal("unbound/wrong-audience result token")
			}
			tokens++
		}
	}
	if secrets != 3 || tokens != 1 || ciphertext != 1 || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.ServiceAccountName != r.ServiceAccount || len(pod.Containers[0].Env) != 0 || len(pod.Containers[0].EnvFrom) != 0 {
		t.Fatal("publication authority boundary")
	}
	command := strings.Join(pod.Containers[0].Command, " ")
	if !strings.Contains(command, "--result-relay "+r.ResultRelayURL) || !strings.Contains(command, "--pod-token /run/publication-pod/token") {
		t.Fatal("actual result transport missing")
	}
	for _, endpoint := range []string{"http://controller.invalid/publication-result", "https://controller.invalid/relay", "https://user@controller.invalid/publication-result", "https://controller.invalid/publication-result?token=other", "https://controller.invalid/publication-result#other"} {
		other := r
		other.ResultRelayURL = endpoint
		if _, err := PublishJob(other); err == nil {
			t.Fatal("uncontrolled result endpoint accepted", endpoint)
		}
	}
}
