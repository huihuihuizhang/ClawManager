package kube

import batchv1 "k8s.io/api/batch/v1"

// No source volume, inline credential, arbitrary command or restore capability.
// A/D provide original task-scoped read-only network credentials separately.
func TeamCaptureJob(r JobRequest, operation string) (*batchv1.Job, error) {
	if (operation != "capture-team-redis" && operation != "capture-team-objects") || r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || len(r.Command) != 0 {
		return nil, ErrResource
	}
	return job(r, true)
}
