package kube

import (
	"encoding/hex"
	"net/url"
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
	ResultRelayURL                                      string
	// Legacy callers may omit placement. Formal production callers must supply
	// the node from a verified staging binding; a name is not UID/volume evidence.
	NodeName string
}

type PublishInputFile struct{ Path, SubPath string }

var publicationSealedInput = regexp.MustCompile(`^\.controller-seals/seal-[0-9a-f]{64}\.enc$`)

var publicationContainerInput = regexp.MustCompile(`^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/publication-[0-9a-f]{64}/container-(deployment_resources|mysql|object_storage|redis|secret_bundle|workspace)\.enc$`)

func validPublicationInputOwner(file PublishInputFile, owner string) bool {
	if publicationSealedInput.MatchString(file.SubPath) {
		return true
	}
	if !publicationContainerInput.MatchString(file.SubPath) || !strings.HasPrefix(file.SubPath, owner+"/publication-") {
		return false
	}
	part := strings.TrimSuffix(strings.TrimPrefix(path.Base(file.SubPath), "container-"), ".enc")
	return file.Path == "parts/"+part+"/container.enc"
}

// PublishJob never uses the capture constructor: no source volume, capture
// identity, KMS/key material, arbitrary command or environment. A result relay
// explicitly projects a bound Pod token and the separate publication identity.
// Input is read-only and the worker can write only its distinct result subtree.
// Controller must first persist the exact original 121 send intent and 104
// resource intents, then validate immutable ConfigMap/Secret/PVC identities.
func PublishJob(r PublishJobRequest) (*batchv1.Job, error) {
	if r.ResultRelayURL != "" {
		u, err := url.Parse(r.ResultRelayURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/publication-result" || len(r.InputFiles) == 0 {
			return nil, ErrResource
		}
	}
	decoded, err := hex.DecodeString(r.RequestSHA256)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != r.RequestSHA256 {
		return nil, ErrResource
	}
	if !r.Identity.valid() || !strings.HasPrefix(r.Identity.Owner, "sbk_") || len(r.Identity.Owner) != 40 || !digestImage.MatchString(r.Image) || r.DeadlineSeconds < 1 || r.DeadlineSeconds > 86400 {
		return nil, ErrResource
	}
	if r.NodeName != "" && len(validation.IsDNS1123Subdomain(r.NodeName)) != 0 {
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
			if !validPublicationInputOwner(file, r.Identity.Owner) || file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path || strings.ContainsAny(file.Path, "\\\x00\r\n:") || (!strings.HasPrefix(file.Path, "parts/") && !strings.HasPrefix(file.Path, "control/")) || (!strings.HasSuffix(file.Path, ".enc") && !strings.HasSuffix(file.Path, ".envelope.json")) {
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
	if r.NodeName != "" {
		job.Spec.Template.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{r.NodeName}}}}}}}}
	}
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
	if r.ResultRelayURL != "" {
		pod := &job.Spec.Template.Spec
		// All original bytes already reside in the immutable, UID-owned capsule.
		// A second request ConfigMap is unnecessary and cannot select other bytes.
		pod.Volumes[1].ConfigMap = nil
		pod.Volumes[1].Secret = &corev1.SecretVolumeSource{SecretName: r.UploadCredentialSecret, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "request.json", Path: "request.json"}, {Key: "artifact-ca.crt", Path: "ca.crt"}}}
		expires := int64(600)
		pod.Volumes = append(pod.Volumes,
			corev1.Volume{Name: "publication-identity", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: r.UploadCredentialSecret, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}, {Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}}}},
			corev1.Volume{Name: "publication-pod", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: &mode, Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: WorkerTokenAudience, ExpirationSeconds: &expires, Path: "token"}}}}}},
		)
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "publication-identity", MountPath: "/run/publication-identity", ReadOnly: true}, corev1.VolumeMount{Name: "publication-pod", MountPath: "/run/publication-pod", ReadOnly: true})
		pod.Containers[0].Command = append(pod.Containers[0].Command, "--result-relay", r.ResultRelayURL, "--identity-dir", "/run/publication-identity", "--pod-token", "/run/publication-pod/token")
	}
	return job, nil
}
