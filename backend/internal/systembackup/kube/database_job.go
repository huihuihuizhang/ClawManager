package kube

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type DatabaseJobRequest struct {
	Identity                                                                Identity
	Image, ServiceAccount, StagingClaim, EvidenceClaim, NodeName, Operation string
	DeadlineSeconds                                                         int64
	Control                                                                 WorkerControl
}

// DatabaseJob has no source volume or database Secret mount. The separate
// evidence claim is writable only for restore; input backup staging is readonly
// on restore/verify. Controller must provide observed claim UID and isolation.
func DatabaseJob(r DatabaseJobRequest) (*batchv1.Job, error) {
	if len(validation.IsDNS1123Subdomain(r.StagingClaim)) != 0 {
		return nil, ErrResource
	}
	switch r.Operation {
	case "capture-database", "verify-database":
		if r.EvidenceClaim != "" {
			return nil, ErrResource
		}
	case "restore-database":
		if len(validation.IsDNS1123Subdomain(r.EvidenceClaim)) != 0 || r.EvidenceClaim == r.StagingClaim {
			return nil, ErrResource
		}
	default:
		return nil, ErrResource
	}
	j, err := job(JobRequest{Identity: r.Identity, Image: r.Image, ServiceAccount: r.ServiceAccount, StagingClaim: r.StagingClaim, NodeName: r.NodeName, DeadlineSeconds: r.DeadlineSeconds, Restore: r.Operation != "capture-database", WorkerControl: &r.Control}, true)
	if err != nil {
		return nil, err
	}
	if r.Operation == "restore-database" {
		j.Spec.Template.Spec.Volumes = append(j.Spec.Template.Spec.Volumes, corev1.Volume{Name: "evidence", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.EvidenceClaim}}})
		j.Spec.Template.Spec.Containers[0].VolumeMounts = append(j.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "evidence", MountPath: "/evidence"})
	}
	return j, nil
}
