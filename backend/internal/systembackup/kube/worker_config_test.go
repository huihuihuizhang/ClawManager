package kube

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	corev1 "k8s.io/api/core/v1"
)

func TestWorkerInvocationAndTaskIdentityMounts(t *testing.T) {
	i := Identity{"cm-drill-fixture", "worker-request", "owner-123"}
	inv := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Deadline: time.Now().Add(time.Minute)}, WorkspacePath: "/workspace", StagingPath: "/staging"}
	cm, err := WorkerConfigMap(i, inv)
	if err != nil {
		t.Fatal(err)
	}
	var decoded worker.Invocation
	if cm.Immutable == nil || !*cm.Immutable || json.Unmarshal([]byte(cm.Data["invocation.json"]), &decoded) != nil {
		t.Fatal("invocation changed or is mutable")
	}
	actual, actualErr := decoded.Hash()
	expected, expectedErr := inv.Hash()
	if actualErr != nil || expectedErr != nil || actual != expected {
		t.Fatal("invocation identity changed")
	}
	r := JobRequest{Identity: Identity{i.Namespace, "worker", i.Owner}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", Source: corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}, StagingClaim: "staging", DeadlineSeconds: 60, WorkerControl: &WorkerControl{URL: "https://controller/internal/backup/worker", InvocationConfigMap: cm.Name, IdentitySecret: "task-identity"}}
	job, err := Job(r)
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec
	if *pod.AutomountServiceAccountToken || len(pod.Containers[0].Env) != 0 || pod.Containers[0].Command[0] != "/backup-worker" {
		t.Fatal("unexpected worker credentials or entrypoint")
	}
	for _, name := range []string{"worker-request", "worker-identity"} {
		found := false
		for _, mount := range pod.Containers[0].VolumeMounts {
			if mount.Name == name {
				found = mount.ReadOnly
			}
		}
		if !found {
			t.Fatal("missing readonly task mount", name)
		}
	}
	for _, volume := range pod.Volumes {
		if volume.Name == "worker-request" && (volume.ConfigMap.Name != cm.Name || *volume.ConfigMap.DefaultMode != 0400) {
			t.Fatal("wrong invocation mount")
		}
		if volume.Name == "worker-identity" && (volume.Secret.SecretName != "task-identity" || *volume.Secret.DefaultMode != 0400 || len(volume.Secret.Items) != 3) {
			t.Fatal("wrong task identity mount")
		}
	}
	r.Command = []string{"/override"}
	if _, err = Job(r); err == nil {
		t.Fatal("ambiguous command accepted")
	}
	inv.WorkspacePath = "/"
	if _, err = WorkerConfigMap(i, inv); err == nil {
		t.Fatal("unscoped workspace accepted")
	}
}
