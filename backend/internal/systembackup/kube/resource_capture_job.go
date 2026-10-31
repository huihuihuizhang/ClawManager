package kube

import batchv1 "k8s.io/api/batch/v1"

// Source API credentials are explicit read-only mounts, independent of the
// Pod's control identity. This Job never has a source filesystem or API token
// from automount, and never starts a workload from the captured history.
func ResourceCaptureJob(r JobRequest, operation string) (*batchv1.Job, error) {
	if (operation != "capture-deployment-resources" && operation != "capture-secret-bundle") || r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || r.FormalMaterials == nil || len(r.Command) != 0 {
		return nil, ErrResource
	}
	return job(r, true)
}
