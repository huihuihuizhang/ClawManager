package publicadapter

import (
	"encoding/json"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestConcreteCaptureFactoryFreezesWorkerJobWithoutDispatch(t *testing.T) {
	for _, mode := range []string{"valid", "database", "owner", "restore", "command", "identity", "deadline", "unpinned", "wrong-part", "wrong-attempt", "capture-policy", "capture-files"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := setup(t)
			var invocation worker.Invocation
			if err := json.Unmarshal(f.x.Parts[0].InvocationJSON, &invocation); err != nil {
				t.Fatal(err)
			}
			invocation.Request.PolicyVersion = ""
			req := CapturePartRequest{Part: "users", Category: "metadata", JobUnitKey: "users", Generation: 5, Invocation: invocation, Workload: kube.JobRequest{Identity: kube.Identity{Namespace: "cm-drill-b", Name: "capture-one", Owner: f.in.Authority.TaskPublicID}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "b-worker", Source: corev1.Volume{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source-pvc"}}}, StagingClaim: "staging-pvc", DeadlineSeconds: 20, WorkerControl: &kube.WorkerControl{URL: "https://owner.invalid/worker", InvocationConfigMap: "users-invocation", IdentitySecret: "job-identity"}}}
			switch mode {
			case "capture-policy":
				req.Invocation.Request.PolicyVersion = "restore-only"
			case "capture-files":
				req.Invocation.Request.Files = []worker.FileRule{{Path: "config.json"}}
			case "database":
				req.Workload.Source = corev1.Volume{}
				req.Invocation.WorkspacePath = ""
				req.Invocation.Request.Operation = "capture-database"
				req.Invocation.Request.MaxFiles = 0
				req.Invocation.Request.MaxFileBytes = 0
				req.Invocation.Request.PolicyVersion = ""
				// The manifest builder validates structure, not a DB connection.
				// Real CA parsing/grants remain in the actual worker/A admission.
				req.Invocation.Request.Database = &worker.DatabaseSpec{Address: "fixture.invalid:3306", Name: "source", ServerUUID: "synthetic-source", TLSServerName: "fixture.invalid", RootCA: []byte("synthetic-public-ca"), MaxRows: 100, MaxMemoryBytes: 1 << 20}
			case "owner":
				req.Workload.Identity.Owner = "other"
			case "restore":
				req.Workload.Restore = true
			case "command":
				req.Workload.Command = []string{"sh"}
			case "identity":
				req.Workload.WorkerControl = nil
			case "deadline":
				req.Workload.DeadlineSeconds = 120
			case "unpinned":
				req.Workload.Image = "worker:latest"
			case "wrong-part":
				req.Part = "other"
			case "wrong-attempt":
				req.Invocation.Request.Binding.Attempt = "99"
			}
			out, err := BuildCapturePart(f.in, f.x.HoldUntil, req)
			if mode != "valid" && mode != "database" {
				if err == nil {
					t.Fatal("invalid factory input accepted")
				}
				return
			}
			var job batchv1.Job
			if err != nil || json.Unmarshal(out.Intent.SpecJSON, &job) != nil || out.InvocationSHA256 != digest(out.InvocationJSON) || out.Intent.SpecSHA256 != digest(out.Intent.SpecJSON) || f.ensures != 0 || len(job.Spec.Template.Spec.Containers) != 1 || job.Spec.Template.Spec.Containers[0].Command[0] != "/backup-worker" || *job.Spec.Template.Spec.AutomountServiceAccountToken {
				t.Fatal(out, err)
			}
			if mode == "database" {
				for _, mount := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
					if mount.Name == "workspace" {
						t.Fatal("database capture has source filesystem access")
					}
				}
			}
		})
	}
}
