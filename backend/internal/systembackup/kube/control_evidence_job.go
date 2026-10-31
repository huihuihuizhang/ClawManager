package kube

import batchv1 "k8s.io/api/batch/v1"

// Control evidence is pulled using the original Job identity. No source SQL
// credential, source volume, arbitrary command or plaintext report is mounted.
func ControlEvidenceCaptureJob(r JobRequest) (*batchv1.Job, error) {
	if r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || r.FormalMaterials == nil || len(r.Command) != 0 {
		return nil, ErrResource
	}
	return job(r, true)
}
