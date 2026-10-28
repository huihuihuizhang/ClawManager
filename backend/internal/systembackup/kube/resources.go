// Package kube builds domain resources and resolves read-only storage identity.
// Creating/deleting them belongs to the shared resource-intent journal runner.
package kube

import (
	"context"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"clawreef/internal/systembackup/scope"
)

var ErrResource = errors.New("backup resource identity or capability is incomplete")

const OwnerLabel = "backup.clawmanager.io/owner"

type Identity struct{ Namespace, Name, Owner string }

func (i Identity) valid() bool {
	return len(validation.IsDNS1123Label(i.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(i.Name)) == 0 && i.Owner != "" && len(validation.IsValidLabelValue(i.Owner)) == 0
}
func (i Identity) meta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: i.Name, Namespace: i.Namespace, Labels: map[string]string{OwnerLabel: i.Owner}}
}

// ResolvePVC follows PVC -> PV; a claim or class name is never CSI evidence.
// subPath is relative to the volume, after resolving the pod mount and instance
// path. The full mount/writer inventory remains a coordinator responsibility.
func ResolvePVC(ctx context.Context, client kubernetes.Interface, namespace, claim, node, subPath string, shared bool) (scope.Storage, error) {
	pvc, e := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, claim, metav1.GetOptions{})
	if e != nil {
		return scope.Storage{}, ErrResource
	}
	if pvc.UID == "" || pvc.Spec.VolumeName == "" || pvc.Status.Phase != corev1.ClaimBound {
		return scope.Storage{}, ErrResource
	}
	pv, e := client.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if e != nil {
		return scope.Storage{}, ErrResource
	}
	if pv.UID == "" || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Name != claim || pv.Spec.ClaimRef.Namespace != namespace {
		return scope.Storage{}, ErrResource
	}
	s := scope.Storage{SubPath: subPath, Shared: shared, NodeName: node, AdditionalMountsKnown: false}
	switch {
	case pv.Spec.HostPath != nil:
		s.Kind = "hostpath"
		s.HostPath = pv.Spec.HostPath.Path
		if node == "" {
			return scope.Storage{}, ErrResource
		}
	case pv.Spec.Local != nil:
		s.Kind = "hostpath"
		s.HostPath = pv.Spec.Local.Path
		if node == "" || pv.Spec.NodeAffinity == nil {
			return scope.Storage{}, ErrResource
		}
	case pv.Spec.NFS != nil:
		s.Kind = "nfs"
		s.NFSServer = pv.Spec.NFS.Server
		s.NFSExport = pv.Spec.NFS.Path
		s.Namespace = namespace
		s.ClaimName = claim
		s.ClaimUID = string(pvc.UID)
	case pv.Spec.CSI != nil:
		s.Kind = "pvc"
		s.Namespace = namespace
		s.ClaimName = claim
		s.ClaimUID = string(pvc.UID)
		s.CSIDriver = pv.Spec.CSI.Driver
	default:
		return scope.Storage{}, ErrResource
	}
	return s, nil
}

// VolumeRelativePath includes mount.subPath when mapping a Lite instance root.
// subPathExpr must be resolved by the pod inventory first; guessing is forbidden.
func VolumeRelativePath(mount corev1.VolumeMount, workspace string) (string, error) {
	if mount.SubPathExpr != "" || !strings.HasPrefix(workspace, "/") || path.Clean(workspace) != workspace || !strings.HasPrefix(mount.MountPath, "/") || path.Clean(mount.MountPath) != mount.MountPath {
		return "", ErrResource
	}
	if workspace != mount.MountPath && !strings.HasPrefix(workspace, strings.TrimSuffix(mount.MountPath, "/")+"/") {
		return "", ErrResource
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(workspace, mount.MountPath), "/")
	if rel == "" {
		rel = "."
	}
	if mount.SubPath != "" {
		if path.IsAbs(mount.SubPath) || path.Clean(mount.SubPath) != mount.SubPath || mount.SubPath == ".." || strings.HasPrefix(mount.SubPath, "../") {
			return "", ErrResource
		}
		rel = path.Join(mount.SubPath, rel)
	}
	if strings.ContainsAny(rel, "\\\x00:") {
		return "", ErrResource
	}
	return rel, nil
}

type JobRequest struct {
	Identity        Identity
	Image           string // immutable digest, supplied by the shared release pipeline
	ServiceAccount  string
	Command         []string // shared worker/relay command, never interpolated shell
	Source          corev1.Volume
	SourceSubPath   string
	StagingClaim    string
	NodeName        string
	DeadlineSeconds int64
	Restore         bool
	WorkerControl   *WorkerControl
}

// WorkerControl contains only refs to a credential-free immutable invocation
// and the task-issued mTLS identity. It must never reference business Secrets.
type WorkerControl struct{ URL, InvocationConfigMap, IdentitySecret string }

var digestImage = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)

// Job builds a dormant manifest only. Caller journals exact bytes/identity before
// API submission, observes mounted source UID, and waits for the capture barrier.
// Plaintext keys/credentials are not accepted in arguments or environment here;
// the command obtains its task-scoped identity from the shared relay/provider.
func Job(r JobRequest) (*batchv1.Job, error) {
	return job(r, false)
}

func job(r JobRequest, database bool) (*batchv1.Job, error) {
	if r.WorkerControl != nil {
		c := r.WorkerControl
		u, e := url.Parse(c.URL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(r.Command) > 0 || len(validation.IsDNS1123Subdomain(c.InvocationConfigMap)) != 0 || len(validation.IsDNS1123Subdomain(c.IdentitySecret)) != 0 {
			return nil, ErrResource
		}
		r.Command = []string{"/backup-worker", "--request", "/run/backup/request/invocation.json", "--control-url", c.URL, "--control-ca", "/run/backup/identity/ca.crt", "--client-cert", "/run/backup/identity/tls.crt", "--client-key", "/run/backup/identity/tls.key"}
	}
	if r.Restore && !strings.HasPrefix(r.Identity.Namespace, "cm-drill-") {
		return nil, ErrResource
	}
	if !r.Identity.valid() || !digestImage.MatchString(r.Image) || len(validation.IsDNS1123Subdomain(r.ServiceAccount)) > 0 || len(r.Command) == 0 || r.StagingClaim == "" || r.DeadlineSeconds <= 0 || (!database && r.Source.Name == "") {
		return nil, ErrResource
	}
	if r.SourceSubPath != "" && (path.IsAbs(r.SourceSubPath) || path.Clean(r.SourceSubPath) != r.SourceSubPath || r.SourceSubPath == ".." || strings.HasPrefix(r.SourceSubPath, "../") || strings.ContainsAny(r.SourceSubPath, "\\\x00:")) {
		return nil, ErrResource
	}
	source := r.Source.DeepCopy()
	source.Name = "workspace"
	if !database {
		switch {
		case source.PersistentVolumeClaim != nil:
			source.PersistentVolumeClaim.ReadOnly = !r.Restore
		case source.NFS != nil:
			source.NFS.ReadOnly = !r.Restore
		case source.HostPath != nil:
			if r.Restore || r.NodeName == "" || source.HostPath.Path == "/" || !path.IsAbs(source.HostPath.Path) || path.Clean(source.HostPath.Path) != source.HostPath.Path || strings.ContainsAny(source.HostPath.Path, "\\\x00\r\n:") {
				return nil, ErrResource
			}
		default:
			return nil, ErrResource
		}
	}
	falseValue := false
	trueValue := true
	zero := int32(0)
	uid := int64(0)
	caps := []corev1.Capability{"DAC_READ_SEARCH"}
	if r.Restore {
		caps = []corev1.Capability{"CHOWN", "FOWNER", "DAC_OVERRIDE"}
	}
	job := &batchv1.Job{ObjectMeta: r.Identity.meta(), Spec: batchv1.JobSpec{BackoffLimit: &zero, ActiveDeadlineSeconds: &r.DeadlineSeconds, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: workerLabels(r.Identity)}, Spec: corev1.PodSpec{
		RestartPolicy: corev1.RestartPolicyNever, ServiceAccountName: r.ServiceAccount, AutomountServiceAccountToken: &falseValue,
		SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "worker", Image: r.Image, Command: append([]string(nil), r.Command...),
			SecurityContext: &corev1.SecurityContext{RunAsUser: &uid, ReadOnlyRootFilesystem: &trueValue, AllowPrivilegeEscalation: &falseValue, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: caps}},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("512Mi")}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspace", SubPath: r.SourceSubPath, ReadOnly: !r.Restore}, {Name: "staging", MountPath: "/staging", ReadOnly: r.Restore}, {Name: "memory", MountPath: "/tmp"}},
		}}, Volumes: []corev1.Volume{*source, {Name: "staging", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.StagingClaim, ReadOnly: r.Restore}}}, {Name: "memory", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: quantity("32Mi")}}}},
	}}}}
	if database {
		// Database workers connect only through their task grant. Never mount a
		// source workspace or carry filesystem-read/ownership capabilities.
		job.Spec.Template.Spec.Volumes = job.Spec.Template.Spec.Volumes[1:]
		job.Spec.Template.Spec.Containers[0].VolumeMounts = job.Spec.Template.Spec.Containers[0].VolumeMounts[1:]
		job.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Add = nil
	}
	if r.NodeName != "" {
		job.Spec.Template.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{r.NodeName}}}}}}}}
	}
	if r.WorkerControl != nil {
		mode := int32(0400)
		c := r.WorkerControl
		job.Spec.Template.Spec.Volumes = append(job.Spec.Template.Spec.Volumes,
			corev1.Volume{Name: "worker-request", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: c.InvocationConfigMap}, Items: []corev1.KeyToPath{{Key: "invocation.json", Path: "invocation.json"}}, DefaultMode: &mode}}},
			corev1.Volume{Name: "worker-identity", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: c.IdentitySecret, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}, {Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}, DefaultMode: &mode}}},
		)
		job.Spec.Template.Spec.Containers[0].VolumeMounts = append(job.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "worker-request", MountPath: "/run/backup/request", ReadOnly: true}, corev1.VolumeMount{Name: "worker-identity", MountPath: "/run/backup/identity", ReadOnly: true})
	}
	return job, nil
}
func quantity(s string) *resource.Quantity { q := resource.MustParse(s); return &q }

func Snapshot(i Identity, claim, class string, probePassed bool) (*unstructured.Unstructured, error) {
	if !i.valid() || claim == "" || class == "" || !probePassed {
		return nil, ErrResource
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot", "metadata": map[string]any{"name": i.Name, "namespace": i.Namespace, "labels": map[string]any{OwnerLabel: i.Owner}}, "spec": map[string]any{"volumeSnapshotClassName": class, "source": map[string]any{"persistentVolumeClaimName": claim}}}}, nil
}
func SnapshotReady(s *unstructured.Unstructured, i Identity, uid, claim string) bool {
	if s == nil || string(s.GetUID()) != uid || uid == "" || s.GetName() != i.Name || s.GetNamespace() != i.Namespace || s.GetLabels()[OwnerLabel] != i.Owner {
		return false
	}
	source, _, _ := unstructured.NestedString(s.Object, "spec", "source", "persistentVolumeClaimName")
	ready, _, _ := unstructured.NestedBool(s.Object, "status", "readyToUse")
	content, _, _ := unstructured.NestedString(s.Object, "status", "boundVolumeSnapshotContentName")
	_, hasError, _ := unstructured.NestedMap(s.Object, "status", "error")
	return source == claim && ready && content != "" && !hasError
}

// DrillNetworkPolicy initially denies all traffic. Shared provisioning adds
// only exact artifact/KMS/relay/drill endpoint rules before starting Jobs.
func DrillNetworkPolicy(i Identity) (*networkv1.NetworkPolicy, error) {
	if !i.valid() || !strings.HasPrefix(i.Namespace, "cm-drill-") {
		return nil, ErrResource
	}
	return &networkv1.NetworkPolicy{ObjectMeta: i.meta(), Spec: networkv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress, networkv1.PolicyTypeEgress}}}, nil
}

func RestorePVC(i Identity, class, size string, snapshot string) (*corev1.PersistentVolumeClaim, error) {
	q, e := resource.ParseQuantity(size)
	if !i.valid() || !strings.HasPrefix(i.Namespace, "cm-drill-") || class == "" || e != nil || q.Sign() <= 0 {
		return nil, ErrResource
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: i.meta(), Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: &class, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: q}}}}
	if snapshot != "" {
		group := "snapshot.storage.k8s.io"
		pvc.Spec.DataSource = &corev1.TypedLocalObjectReference{APIGroup: &group, Kind: "VolumeSnapshot", Name: snapshot}
	}
	return pvc, nil
}
