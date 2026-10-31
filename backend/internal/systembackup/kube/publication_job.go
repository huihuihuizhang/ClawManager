package kube

import (
	"encoding/hex"
	"path"
	"regexp"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// PublishJobRequest accepts resource references only. Its separate upload
// identity must be policy-restricted by the original provider owner before
// dispatch. This constructor is not a provider-permission or readiness proof.
type PublishJobRequest struct {
	Identity                                            Identity
	Image, ServiceAccount, StagingClaim, StagingSubPath string
	InvocationConfigMap, UploadCredentialSecret         string
	RequestSHA256                                       string
	DeadlineSeconds                                     int64
	InputFiles                                          []PublishInputFile
}

type PublishInputFile struct{ Path, SubPath string }

var publicationSealedInput = regexp.MustCompile(`^\.controller-seals/seal-[0-9a-f]{64}\.enc$`)

// PublishJob never uses the capture constructor: no source volume, capture
// identity, workload token, KMS/key material, arbitrary command or environment.
// Input is read-only and the worker can write only its distinct result subtree.
// Controller must first persist the exact original 121 send intent and 104
// resource intents, then validate immutable ConfigMap/Secret/PVC identities.
func PublishJob(r PublishJobRequest) (*batchv1.Job, error) {
	decoded, err := hex.DecodeString(r.RequestSHA256)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != r.RequestSHA256 {
		return nil, ErrResource
	}
	if !r.Identity.valid() || !strings.HasPrefix(r.Identity.Owner, "sbk_") || len(r.Identity.Owner) != 40 || !digestImage.MatchString(r.Image) || r.DeadlineSeconds < 1 || r.DeadlineSeconds > 86400 {
		return nil, ErrResource
	}
	for _, name := range []string{r.ServiceAccount, r.StagingClaim, r.InvocationConfigMap, r.UploadCredentialSecret} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, ErrResource
		}
	}
	if len(r.InputFiles) == 0 {
		if r.StagingSubPath == "" || path.IsAbs(r.StagingSubPath) || path.Clean(r.StagingSubPath) != r.StagingSubPath || strings.ContainsAny(r.StagingSubPath, "\\\x00\r\n:") || !strings.HasPrefix(r.StagingSubPath, "publication/"+r.Identity.Owner+"/") {
			return nil, ErrResource
		}
		for _, segment := range strings.Split(r.StagingSubPath, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return nil, ErrResource
			}
		}
	} else {
		if r.StagingSubPath != "" {
			return nil, ErrResource
		}
		seen := map[string]bool{}
		paths := []string{}
		for _, file := range r.InputFiles {
			if !publicationSealedInput.MatchString(file.SubPath) || file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path || strings.ContainsAny(file.Path, "\\\x00\r\n:") || (!strings.HasPrefix(file.Path, "parts/") && !strings.HasPrefix(file.Path, "control/")) || (!strings.HasSuffix(file.Path, ".enc") && !strings.HasSuffix(file.Path, ".envelope.json")) {
				return nil, ErrResource
			}
			if seen["path:"+file.Path] || seen["source:"+file.SubPath] {
				return nil, ErrResource
			}
			seen["path:"+file.Path] = true
			seen["source:"+file.SubPath] = true
			paths = append(paths, file.Path)
		}
		for _, file := range paths {
			for parent := path.Dir(file); parent != "."; parent = path.Dir(parent) {
				if seen["path:"+parent] {
					return nil, ErrResource
				}
			}
		}
	}
	no, yes := false, true
	zero := int32(0)
	uid := int64(0)
	mode := int32(0400)
	job := &batchv1.Job{ObjectMeta: r.Identity.meta(), Spec: batchv1.JobSpec{BackoffLimit: &zero, ActiveDeadlineSeconds: &r.DeadlineSeconds, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: workerLabels(r.Identity)}, Spec: corev1.PodSpec{
		RestartPolicy: corev1.RestartPolicyNever, ServiceAccountName: r.ServiceAccount, AutomountServiceAccountToken: &no, EnableServiceLinks: &no,
		SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "worker", Image: r.Image, Command: []string{"/backup-worker", "publish-upload-only", "--request", "/run/publication/request.json", "--request-sha256", r.RequestSHA256, "--ca", "/run/publication/ca.crt", "--credential", "/run/upload/credential.json", "--input", "/input", "--result", "/result"},
			SecurityContext: &corev1.SecurityContext{RunAsUser: &uid, Privileged: &no, ReadOnlyRootFilesystem: &yes, AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("512Mi")}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "staging", MountPath: "/input", SubPath: r.StagingSubPath + "/input", ReadOnly: true}, {Name: "staging", MountPath: "/result", SubPath: r.StagingSubPath + "/result"}, {Name: "publication-request", MountPath: "/run/publication", ReadOnly: true}, {Name: "publication-upload", MountPath: "/run/upload", ReadOnly: true}, {Name: "memory", MountPath: "/tmp"}},
		}},
		Volumes: []corev1.Volume{
			{Name: "staging", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.StagingClaim}}},
			{Name: "publication-request", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: r.InvocationConfigMap}, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "request.json", Path: "request.json"}, {Key: "ca.crt", Path: "ca.crt"}}}}},
			{Name: "publication-upload", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: r.UploadCredentialSecret, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "credential.json", Path: "credential.json"}}}}},
			{Name: "memory", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: quantity("32Mi")}}},
		},
	}}}}
	if len(r.InputFiles) > 0 {
		pod := &job.Spec.Template.Spec
		mounts := append([]corev1.VolumeMount(nil), pod.Containers[0].VolumeMounts[2:]...)
		for _, file := range r.InputFiles {
			mounts = append(mounts, corev1.VolumeMount{Name: "staging", MountPath: "/input/" + file.Path, SubPath: file.SubPath, ReadOnly: true})
		}
		mounts = append(mounts, corev1.VolumeMount{Name: "publication-result", MountPath: "/result"})
		pod.Containers[0].VolumeMounts = mounts
		pod.Volumes[0].PersistentVolumeClaim.ReadOnly = true
		pod.Volumes = append(pod.Volumes, corev1.Volume{Name: "publication-result", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: quantity("16Mi")}}})
	}
	return job, nil
}
