package kube

import (
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
)

func TestDatabaseJobsHaveOnlyRequiredDataMounts(t *testing.T) {
	for _, operation := range []string{"capture-database", "restore-database", "verify-database"} {
		t.Run(operation, func(t *testing.T) {
			r := DatabaseJobRequest{Identity: Identity{"cm-drill-fixture", "database-job", "owner-1"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", StagingClaim: "input", DeadlineSeconds: 120, Operation: operation, Control: WorkerControl{URL: "https://controller/worker", InvocationConfigMap: "invocation", IdentitySecret: "identity"}}
			if operation == "restore-database" {
				r.EvidenceClaim = "expected"
			}
			j, err := DatabaseJob(r)
			if err != nil {
				t.Fatal(err)
			}
			p := j.Spec.Template.Spec
			if *p.AutomountServiceAccountToken || len(p.Containers[0].SecurityContext.Capabilities.Add) != 0 {
				t.Fatal("database worker has source access")
			}
			foundInput, foundEvidence := false, false
			for _, m := range p.Containers[0].VolumeMounts {
				if m.Name == "workspace" {
					t.Fatal("database worker mounts workspace")
				}
				if m.Name == "staging" {
					foundInput = true
					if m.ReadOnly != (operation != "capture-database") {
						t.Fatal("wrong input mount mode")
					}
				}
				if m.Name == "evidence" {
					foundEvidence = true
					if m.ReadOnly {
						t.Fatal("evidence not writable")
					}
				}
			}
			if !foundInput || foundEvidence != (operation == "restore-database") {
				t.Fatal("missing input/evidence mount")
			}
			inv := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: operation, Deadline: time.Now().Add(time.Minute), Database: &worker.DatabaseSpec{}}, StagingPath: "/staging"}
			if operation == "restore-database" {
				inv.EvidencePath = "/evidence"
			}
			if _, err = WorkerConfigMap(r.Identity, inv); err != nil {
				t.Fatal(err)
			}
			inv.WorkspacePath = "/workspace"
			if _, err = WorkerConfigMap(r.Identity, inv); err == nil {
				t.Fatal("database invocation has workspace")
			}
			if operation != "capture-database" {
				r.Identity.Namespace = "production"
				if _, err = DatabaseJob(r); err == nil {
					t.Fatal("production restore/verifier Job allowed")
				}
			}
		})
	}
}
