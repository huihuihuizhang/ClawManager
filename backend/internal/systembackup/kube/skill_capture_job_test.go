package kube

import (
	corev1 "k8s.io/api/core/v1"
	"strings"
	"testing"
)

func TestSkillObjectJobUsesOriginalCLIAndExplicitReadOnlyMaterials(t *testing.T) {
	for _, fault := range []string{"", "missing-control", "missing-materials", "source-mount", "source-subpath", "restore", "shell"} {
		t.Run(fault, func(t *testing.T) {
			r := JobRequest{Identity: Identity{Namespace: "backup", Name: "capture-skills", Owner: "sbk_original"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", StagingClaim: "stage", DeadlineSeconds: 60, WorkerControl: &WorkerControl{URL: "https://owner.invalid/worker", InvocationConfigMap: "original-invocation", IdentitySecret: "original-identity", BoundPodIdentity: true}, FormalMaterials: &FormalJobMaterials{ConfigMap: "skill-materials", Inputs: []FormalInputMount{{Volume: "formal-skill-source", Kind: "Secret", Name: "original-source-reader", Directory: "/run/backup/materials/skill-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}}
			switch fault {
			case "missing-control":
				r.WorkerControl = nil
			case "missing-materials":
				r.FormalMaterials = nil
			case "source-mount":
				r.Source.Name = "source"
			case "source-subpath":
				r.SourceSubPath = "user/instance"
			case "restore":
				r.Restore = true
			case "shell":
				r.Command = []string{"sh", "-c", "override"}
			}
			job, err := SkillObjectCaptureJob(r)
			if fault != "" {
				if err == nil {
					t.Fatal("unscoped Skill worker", fault)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pod := job.Spec.Template.Spec
			c := pod.Containers[0]
			if *pod.AutomountServiceAccountToken || len(c.Env) != 0 || len(c.SecurityContext.Capabilities.Add) != 0 || len(c.Command) == 0 || c.Command[0] != "/backup-worker" || !strings.Contains(strings.Join(c.Command, " "), "--formal-config /run/backup/formal/materials.json") {
				t.Fatal("actual worker entry/permissions changed")
			}
			for _, mount := range c.VolumeMounts {
				if mount.Name == "workspace" || mount.MountPath == "/workspace" {
					t.Fatal("Skill object job gained filesystem source")
				}
				if strings.HasPrefix(mount.Name, "formal-") && !mount.ReadOnly {
					t.Fatal("writable original materials")
				}
			}
		})
	}
}
