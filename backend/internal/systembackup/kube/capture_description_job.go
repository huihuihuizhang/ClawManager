package kube

import (
	cd "clawreef/internal/systembackupcapturedescription"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"strconv"
)

// Dedicated administrative C stream. No source volume, database credential,
// plaintext descriptor mount or caller command enters this Job.
func CaptureDescriptionJob(r JobRequest, seed cd.Seed) (*batchv1.Job, error) {
	if r.Source.Name != "" || r.SourceSubPath != "" || r.Restore || r.WorkerControl == nil || r.FormalMaterials == nil || len(r.Command) != 0 {
		return nil, ErrResource
	}
	memory, err := cd.DecodeMemoryBudget(seed)
	if err != nil {
		return nil, ErrResource
	}
	result, err := job(r, true)
	if err != nil {
		return nil, err
	}
	worker := &result.Spec.Template.Spec.Containers[0]
	worker.Resources.Requests[corev1.ResourceMemory] = *resource.NewQuantity(memory, resource.BinarySI)
	worker.Resources.Limits[corev1.ResourceMemory] = *resource.NewQuantity(memory, resource.BinarySI)
	worker.Env = append(worker.Env, corev1.EnvVar{Name: "GOMEMLIMIT", Value: strconv.FormatInt(memory, 10) + "B"})
	return result, nil
}
