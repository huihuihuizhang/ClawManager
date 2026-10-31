package kube

import (
	corev1 "k8s.io/api/core/v1"
	"strings"
	"testing"
)

func TestResourceJobMountsPinnedMaterialsWithoutAmbientSourceAccess(t *testing.T) {
	fixture := func() JobRequest {
		return JobRequest{Identity: Identity{Namespace: "backup", Name: "capture-resources", Owner: "sbk_original"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", StagingClaim: "stage", DeadlineSeconds: 60, WorkerControl: &WorkerControl{URL: "https://owner.invalid/worker", InvocationConfigMap: "original-invocation", IdentitySecret: "original-identity", BoundPodIdentity: true}, FormalMaterials: &FormalJobMaterials{ConfigMap: "resource-mapping", Inputs: []FormalInputMount{{Volume: "formal-resource-source", Kind: "Secret", Name: "resource-source-reader", Directory: "/run/backup/materials/resource-source", Items: []corev1.KeyToPath{{Key: "token", Path: "token"}}}}}}
	}
	for _, fault := range []string{"", "missing", "source", "traversal", "collision", "mode", "shell"} {
		t.Run(fault, func(t *testing.T) {
			r := fixture()
			switch fault {
			case "missing":
				r.FormalMaterials = nil
			case "source":
				r.Source.Name = "source"
			case "traversal":
				r.FormalMaterials.Inputs[0].Directory = "/run/backup/materials/../identity"
			case "collision":
				r.FormalMaterials.Inputs[0].Volume = "formal-mapping"
			case "mode":
				mode := int32(0777)
				r.FormalMaterials.Inputs[0].Items[0].Mode = &mode
			case "shell":
				r.Command = []string{"sh", "-c", "unreviewed"}
			}
			job, err := ResourceCaptureJob(r, "capture-deployment-resources")
			if fault != "" {
				if err == nil {
					t.Fatal("unsafe resource job accepted", fault)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pod := job.Spec.Template.Spec
			if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || len(pod.Containers) != 1 || len(pod.Containers[0].SecurityContext.Capabilities.Add) != 0 {
				t.Fatal("resource worker gained ambient source permissions")
			}
			command := strings.Join(pod.Containers[0].Command, " ")
			if !strings.Contains(command, "--formal-config /run/backup/formal/materials.json") {
				t.Fatal("actual CLI did not receive formal materials")
			}
			for _, m := range pod.Containers[0].VolumeMounts {
				if m.Name == "workspace" {
					t.Fatal("resource job mounted workspace")
				}
				if strings.HasPrefix(m.Name, "formal-") && !m.ReadOnly {
					t.Fatal("formal credentials writable")
				}
			}
		})
	}
}
