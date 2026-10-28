package profile

import (
	"context"
	"path"
	"strings"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var snapshotClasses = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}

func (d *Driver) deploymentOwns(ctx context.Context, f frozenInstance, pod *corev1.Pod) bool {
	if f.Deployment == nil || pod == nil || pod.Namespace != f.Deployment.Namespace {
		return false
	}
	selector, e := metav1.LabelSelectorAsSelector(f.Deployment.Spec.Selector)
	if e != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return false
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
		return false
	}
	rs, e := d.Client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if e != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return false
	}
	parent := metav1.GetControllerOf(rs)
	return parent != nil && parent.Kind == "Deployment" && parent.APIVersion == "apps/v1" && parent.UID == f.Deployment.UID && parent.Name == f.Deployment.Name
}

func (d *Driver) nodes(ctx context.Context) (map[string]string, error) {
	nodes, e := d.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if e != nil {
		return nil, ErrProfile
	}
	out := map[string]string{}
	for _, n := range nodes.Items {
		if n.Labels[corev1.LabelOSStable] == "linux" && n.UID != "" && n.DeletionTimestamp == nil {
			if _, ok := d.Proof.Endpoints[n.Name]; ok {
				out[n.Name] = string(n.UID)
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrProfile
	}
	return out, nil
}
func (d *Driver) snapshotClass(ctx context.Context, name, driver string) (string, error) {
	s, e := d.Dynamic.Resource(snapshotClasses).Get(ctx, name, metav1.GetOptions{})
	if e != nil || s.GetUID() == "" || s.GetDeletionTimestamp() != nil {
		return "", ErrProfile
	}
	actual, _, _ := unstructured.NestedString(s.Object, "driver")
	policy, _, _ := unstructured.NestedString(s.Object, "deletionPolicy")
	if actual != driver || policy != "Delete" {
		return "", ErrProfile
	}
	return string(s.GetUID()), nil
}
func overlaps(a, b string) bool {
	a = path.Clean(a)
	b = path.Clean(b)
	return a == b || strings.HasPrefix(a, strings.TrimRight(b, "/")+"/") || strings.HasPrefix(b, strings.TrimRight(a, "/")+"/")
}

// Resolve PVC aliases before comparing backends: distinct claims can reference
// the same NFS export or CSI volume handle. Unknown backing volumes fail closed.
func (d *Driver) backing(ctx context.Context, ns string, v corev1.Volume) (corev1.Volume, error) {
	if v.PersistentVolumeClaim == nil {
		return v, nil
	}
	p, e := d.Client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
	if e != nil {
		return v, ErrProfile
	}
	if p.Spec.VolumeName == "" {
		return v, nil
	}
	pv, e := d.Client.CoreV1().PersistentVolumes().Get(ctx, p.Spec.VolumeName, metav1.GetOptions{})
	if e != nil {
		return v, ErrProfile
	}
	out := corev1.Volume{VolumeSource: corev1.VolumeSource{NFS: pv.Spec.NFS, HostPath: pv.Spec.HostPath}}
	if pv.Spec.Local != nil {
		out.HostPath = &corev1.HostPathVolumeSource{Path: pv.Spec.Local.Path}
	}
	// CSI is compared using its immutable driver/handle in backingHash.
	if pv.Spec.CSI != nil {
		out.Name = kube.ContentHash([]string{pv.Spec.CSI.Driver, pv.Spec.CSI.VolumeHandle})
	}
	return out, nil
}
