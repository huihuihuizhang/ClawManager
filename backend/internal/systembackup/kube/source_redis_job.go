package kube

import batchv1 "k8s.io/api/batch/v1"

// The formal whole-source Redis path has no filesystem source, arbitrary
// command, restore action or Team identity. Source credentials are independent.
func SourceRedisCaptureJob(r JobRequest) (*batchv1.Job, error) {
	if r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || len(r.Command) != 0 || r.FormalMaterials == nil {
		return nil, ErrResource
	}
	return job(r, true)
}
