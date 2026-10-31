package kube

import batchv1 "k8s.io/api/batch/v1"

// Skill packages have their own source contract; no fabricated Team identity,
// source filesystem, writable source mount or arbitrary worker command.
func SkillObjectCaptureJob(r JobRequest) (*batchv1.Job, error) {
	if r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || r.FormalMaterials == nil || len(r.Command) != 0 {
		return nil, ErrResource
	}
	return job(r, true)
}
