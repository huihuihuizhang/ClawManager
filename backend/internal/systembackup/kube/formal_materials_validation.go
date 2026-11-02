package kube

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// ValidateFormalJobMaterials reuses the actual pure projection builder. It
// performs no API call and exposes neither a Job nor an authority capability.
// Call before materializing any ConfigMap/Secret to avoid signing projections
// that the unchanged worker Job builder will reject later.
func ValidateFormalJobMaterials(materials *FormalJobMaterials) error {
	job := &batchv1.Job{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{}}}}}}
	return attachFormalMaterials(job, materials)
}
