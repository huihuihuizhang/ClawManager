package kube

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublishJobHasOnlyOriginalTaskCiphertextAndUploadMaterial(t *testing.T) {
	r := PublishJobRequest{Identity: Identity{Namespace: "backup", Name: "original-publish", Owner: "sbk_11111111-1111-4111-8111-111111111111"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "upload-only", StagingClaim: "publish-staging", StagingSubPath: "publication/sbk_11111111-1111-4111-8111-111111111111/1", InvocationConfigMap: "original-publication", UploadCredentialSecret: "original-upload", DeadlineSeconds: 300, RequestSHA256: strings.Repeat("b", 64)}
	job, err := PublishJob(r)
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || len(pod.Volumes) != 4 || len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || pod.HostNetwork || pod.HostPID || pod.HostIPC || job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 || job.Spec.TTLSecondsAfterFinished != nil {
		t.Fatal("publish process isolation")
	}
	container := pod.Containers[0]
	if !strings.Contains(strings.Join(container.Command, " "), "--request-sha256 "+r.RequestSHA256) {
		t.Fatal("Job did not bind original request bytes")
	}
	if len(container.Env) != 0 || len(container.EnvFrom) != 0 || len(container.SecurityContext.Capabilities.Add) != 0 || len(container.SecurityContext.Capabilities.Drop) != 1 || container.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Fatal("publish gained source or process capability")
	}
	if len(container.VolumeMounts) != 5 || !container.VolumeMounts[0].ReadOnly || container.VolumeMounts[0].SubPath != r.StagingSubPath+"/input" || container.VolumeMounts[1].ReadOnly || container.VolumeMounts[1].SubPath != r.StagingSubPath+"/result" {
		t.Fatal("task input/result mount boundaries")
	}
	raw, _ := json.Marshal(job)
	for _, forbidden := range []string{"source-dsn", "worker-identity", "worker-pod-identity", "formal-materials", "kms", "hostPath", "projected"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("unexpected capture material", forbidden)
		}
	}
	for _, bad := range []string{"", "/publication/other", "publication/sbk_11111111-1111-4111-8111-111111111111/../other", "publication/sbk_33333333-3333-4333-8333-333333333333/1", "publication/" + r.Identity.Owner + "//1", "publication/" + r.Identity.Owner + "/1\\escape"} {
		other := r
		other.StagingSubPath = bad
		if _, err = PublishJob(other); err == nil {
			t.Fatal("invalid task subPath admitted", bad)
		}
	}
}
