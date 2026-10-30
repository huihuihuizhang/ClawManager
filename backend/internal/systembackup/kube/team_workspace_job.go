package kube

import batchv1 "k8s.io/api/batch/v1"

// TeamWorkspaceJob reuses the standard worker workload. Verification mounts
// BOTH the isolated target and authenticated staging read-only; restore keeps
// the existing writable-target/read-only-input split. Neither starts an agent.
func TeamWorkspaceJob(r JobRequest, operation string) (*batchv1.Job, error) {
	if (operation != "restore-workspace" && operation != "verify-team-workspace") || r.Restore != (operation == "restore-workspace") {
		return nil, ErrResource
	}
	job, err := Job(r)
	if err != nil {
		return nil, err
	}
	if operation == "verify-team-workspace" {
		pod := &job.Spec.Template.Spec
		for n := range pod.Containers[0].VolumeMounts {
			if pod.Containers[0].VolumeMounts[n].Name == "staging" {
				pod.Containers[0].VolumeMounts[n].ReadOnly = true
			}
		}
		for n := range pod.Volumes {
			if pod.Volumes[n].Name == "staging" && pod.Volumes[n].PersistentVolumeClaim != nil {
				pod.Volumes[n].PersistentVolumeClaim.ReadOnly = true
			}
		}
	}
	return job, nil
}
