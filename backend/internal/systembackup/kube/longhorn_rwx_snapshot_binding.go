package kube

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const longhornSnapshotGroup = "snapshot.storage.k8s.io"
const longhornSnapshotDriver = "driver.longhorn.io"

// LonghornSnapshotPin comes from the original task's frozen source selection,
// its resource journal and the independently verified provider hold. The cut
// window is the verified hold interval through the snapshot observation.
type LonghornSnapshotPin struct {
	Source                    MountIdentity
	NamespaceUID              string
	ProviderNamespace         string
	ProviderNamespaceUID      string
	AccessMode                corev1.PersistentVolumeAccessMode
	SourceHandle              string
	BackendSnapshotHandle     string
	ProviderSnapshotUID       string
	Class, ClassUID, ClassSHA string
	Snapshot, Clone           ResourceRecord
	Alias                     *LonghornSnapshotAliasPin
	CutStart, CutObservedAt   time.Time
}

// LonghornSnapshotBinding records storage lineage. The caller must still
// verify its provider hold, task binding and the running worker's read-only
// mount. This value carries no mutation or publication authority.
type LonghornSnapshotBinding struct {
	SnapshotUID, ContentUID, ContentSHA256 string
	ProviderCloneUID                       string
	ProviderSnapshotUID                    string
	AliasSnapshotUID, AliasContentUID      string
	CreatedAt                              time.Time
	Clone                                  MountIdentity
}

// VerifyLonghornSnapshotBinding re-reads the exact task-owned snapshot and
// clone and the original source. It performs no storage mutations.
func VerifyLonghornSnapshotBinding(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin) (LonghornSnapshotBinding, error) {
	var out LonghornSnapshotBinding
	s, c := pin.Snapshot, pin.Clone
	if !longhornOwnedRecord(c, "PersistentVolumeClaim") || c.Intent.Identity.Owner != s.Intent.Identity.Owner ||
		len(validation.IsDNS1123Label(pin.ProviderNamespace)) != 0 || pin.ProviderNamespaceUID == "" {
		return out, ErrResource
	}
	cut, err := verifyLonghornSourceCut(ctx, client, api, pin)
	if err != nil {
		return out, err
	}
	snapshotName := s.Intent.Identity.Name
	var aliasSnapshotUID, aliasContentUID string
	if c.Intent.Identity.Namespace != s.Intent.Identity.Namespace {
		if pin.Alias == nil || pin.Alias.Snapshot.Intent.Identity.Namespace != c.Intent.Identity.Namespace {
			return out, ErrResource
		}
		if err := verifyLonghornSnapshotAlias(ctx, client, api, pin, cut); err != nil {
			return out, err
		}
		snapshotName = pin.Alias.Snapshot.Intent.Identity.Name
		aliasSnapshotUID, aliasContentUID = pin.Alias.Snapshot.UID, pin.Alias.Content.UID
	} else if pin.Alias != nil {
		return out, ErrResource
	}
	clone, clonePV, err := longhornSnapshotVolume(ctx, client, c.Intent.Identity.Namespace, c.Intent.Identity.Name)
	if err == ErrPending {
		return out, ErrPending
	}
	if err != nil || string(clone.UID) == pin.Source.UID || clonePV.Name == pin.Source.PVName || string(clonePV.UID) == pin.Source.PVUID ||
		clonePV.Spec.CSI.VolumeHandle == pin.SourceHandle || !longhornSnapshotAccessMode(clone, clonePV, corev1.ReadWriteOnce) {
		return out, ErrOwnership
	}
	ref, objectRef := clone.Spec.DataSource, clone.Spec.DataSourceRef
	if ref == nil || ref.APIGroup == nil || *ref.APIGroup != longhornSnapshotGroup || ref.Kind != "VolumeSnapshot" || ref.Name != snapshotName ||
		(objectRef != nil && (objectRef.Namespace != nil || objectRef.APIGroup == nil || *objectRef.APIGroup != longhornSnapshotGroup ||
			objectRef.Kind != ref.Kind || objectRef.Name != ref.Name)) {
		return out, ErrOwnership
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(clone)
	if err != nil || !owned(c, &unstructured.Unstructured{Object: raw}) || ctx.Err() != nil {
		return out, ErrOwnership
	}
	providerCloneUID, err := verifyLonghornProviderClone(ctx, client, api, pin, clonePV.Spec.CSI.VolumeHandle)
	if err != nil {
		return out, err
	}
	return LonghornSnapshotBinding{
		SnapshotUID: s.UID, ContentUID: cut.contentUID, CreatedAt: cut.createdAt,
		AliasSnapshotUID: aliasSnapshotUID, AliasContentUID: aliasContentUID,
		ProviderCloneUID:    providerCloneUID,
		ProviderSnapshotUID: pin.ProviderSnapshotUID,
		ContentSHA256:       cut.contentSHA256,
		Clone: MountIdentity{Volume: pin.Source.Volume, Kind: "PersistentVolumeClaim", Name: clone.Name,
			UID: string(clone.UID), PVName: clonePV.Name, PVUID: string(clonePV.UID), SHA256: ContentHash(clonePV.Spec)},
	}, nil
}

type longhornSourceCut struct {
	contentUID, contentSHA256 string
	createdAt                 time.Time
	capacity                  resource.Quantity
}

func verifyLonghornSourceCut(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin) (longhornSourceCut, error) {
	var out longhornSourceCut
	s := pin.Snapshot
	ns := s.Intent.Identity.Namespace
	if !longhornOwnedRecord(s, "VolumeSnapshot") || !longhornLocalSnapshotHandle(pin.SourceHandle, pin.BackendSnapshotHandle) ||
		pin.CutStart.IsZero() || !pin.CutStart.Before(pin.CutObservedAt) {
		return out, ErrResource
	}
	pvc, pv, err := verifyLonghornSnapshotSource(ctx, client, api, pin, ns)
	if err != nil {
		return out, err
	}
	snapshot, err := api.Resource(longhornSnapshotResource("volumesnapshots")).Namespace(ns).Get(ctx, s.Intent.Identity.Name, metav1.GetOptions{})
	if err != nil || !owned(s, snapshot) || snapshot.GetDeletionTimestamp() != nil ||
		!SnapshotReady(snapshot, s.Intent.Identity, s.UID, pvc.Name) ||
		longhornSnapshotString(snapshot, "spec", "volumeSnapshotClassName") != pin.Class {
		return out, ErrOwnership
	}
	if _, present, err := unstructured.NestedFieldNoCopy(snapshot.Object, "status", "error"); present || err != nil {
		return out, ErrOwnership
	}
	name := longhornSnapshotString(snapshot, "status", "boundVolumeSnapshotContentName")
	content, err := api.Resource(longhornSnapshotResource("volumesnapshotcontents")).Get(ctx, name, metav1.GetOptions{})
	if err != nil || content.GetUID() == "" || content.GetDeletionTimestamp() != nil ||
		longhornSnapshotString(content, "spec", "driver") != longhornSnapshotDriver ||
		longhornSnapshotString(content, "spec", "deletionPolicy") != "Delete" ||
		longhornSnapshotString(content, "spec", "volumeSnapshotClassName") != pin.Class ||
		longhornSnapshotString(content, "spec", "volumeSnapshotRef", "uid") != s.UID ||
		longhornSnapshotString(content, "spec", "volumeSnapshotRef", "name") != s.Intent.Identity.Name ||
		longhornSnapshotString(content, "spec", "volumeSnapshotRef", "namespace") != ns ||
		longhornSnapshotString(content, "spec", "source", "volumeHandle") != pin.SourceHandle {
		return out, ErrOwnership
	}
	handle := longhornSnapshotString(content, "status", "snapshotHandle")
	ready, _, _ := unstructured.NestedBool(content.Object, "status", "readyToUse")
	_, failed, statusErr := unstructured.NestedFieldNoCopy(content.Object, "status", "error")
	created, validTime := longhornSnapshotCutTime(snapshot, content, pin.CutStart, pin.CutObservedAt)
	if handle != pin.BackendSnapshotHandle || !ready || failed || statusErr != nil || !validTime {
		return out, ErrOwnership
	}
	capacity := pvc.Status.Capacity[corev1.ResourceStorage]
	pvCapacity := pv.Spec.Capacity[corev1.ResourceStorage]
	if capacity.Sign() <= 0 || capacity.Cmp(pvCapacity) != 0 {
		return out, ErrOwnership
	}
	return longhornSourceCut{
		contentUID:    string(content.GetUID()),
		contentSHA256: ContentHash([]any{content.Object["spec"], handle, created.UTC()}),
		createdAt:     created.UTC(),
		capacity:      capacity,
	}, nil
}

func verifyLonghornSnapshotSource(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, ns string) (*corev1.PersistentVolumeClaim, *corev1.PersistentVolume, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || api == nil ||
		pin.Source.Kind != "PersistentVolumeClaim" || pin.Source.Volume == "" || pin.Source.Name == "" ||
		pin.Source.UID == "" || pin.Source.PVName == "" || pin.Source.PVUID == "" || len(pin.Source.SHA256) != 64 ||
		pin.NamespaceUID == "" || (pin.AccessMode != corev1.ReadWriteMany && pin.AccessMode != corev1.ReadWriteOnce) ||
		pin.Class == "" || pin.ClassUID == "" || len(pin.ClassSHA) != 64 {
		return nil, nil, ErrResource
	}
	namespace, err := client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || string(namespace.UID) != pin.NamespaceUID || namespace.DeletionTimestamp != nil {
		return nil, nil, ErrOwnership
	}
	pvc, pv, err := longhornSnapshotVolume(ctx, client, ns, pin.Source.Name)
	if err != nil || string(pvc.UID) != pin.Source.UID || pv.Name != pin.Source.PVName ||
		string(pv.UID) != pin.Source.PVUID || ContentHash(pv.Spec) != pin.Source.SHA256 || pv.Spec.CSI.VolumeHandle != pin.SourceHandle ||
		!longhornSnapshotAccessMode(pvc, pv, pin.AccessMode) {
		return nil, nil, ErrOwnership
	}
	class, err := api.Resource(longhornSnapshotResource("volumesnapshotclasses")).Get(ctx, pin.Class, metav1.GetOptions{})
	if err != nil || string(class.GetUID()) != pin.ClassUID || class.GetDeletionTimestamp() != nil ||
		longhornSnapshotString(class, "driver") != longhornSnapshotDriver || longhornSnapshotString(class, "deletionPolicy") != "Delete" ||
		longhornSnapshotString(class, "parameters", "type") != "snap" ||
		ContentHash([]any{class.Object["driver"], class.Object["deletionPolicy"], class.Object["parameters"]}) != pin.ClassSHA {
		return nil, nil, ErrOwnership
	}
	return pvc, pv, nil
}

func longhornOwnedRecord(record ResourceRecord, kind string) bool {
	return record.Intent.Identity.valid() && record.Intent.Kind == kind && record.CreateDispatched &&
		record.UID != "" && len(record.Intent.RequestSHA256) == 64 && !record.Deleting && !record.Deleted
}

func verifyLonghornProviderClone(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, cloneHandle string) (string, error) {
	namespace, err := client.CoreV1().Namespaces().Get(ctx, pin.ProviderNamespace, metav1.GetOptions{})
	if err != nil || string(namespace.UID) != pin.ProviderNamespaceUID || namespace.DeletionTimestamp != nil {
		return "", ErrOwnership
	}
	volumes := schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}
	clone, err := api.Resource(volumes).Namespace(pin.ProviderNamespace).Get(ctx, cloneHandle, metav1.GetOptions{})
	if err != nil || clone.GetUID() == "" || clone.GetDeletionTimestamp() != nil || ctx.Err() != nil {
		return "", ErrOwnership
	}
	snapshot, _ := strings.CutPrefix(pin.BackendSnapshotHandle, "snap://"+pin.SourceHandle+"/")
	source := longhornSnapshotString(clone, "status", "cloneStatus", "sourceVolume")
	observedSnapshot := longhornSnapshotString(clone, "status", "cloneStatus", "snapshot")
	state := longhornSnapshotString(clone, "status", "cloneStatus", "state")
	if state == "" && source == "" && observedSnapshot == "" {
		return "", ErrPending
	}
	if source != pin.SourceHandle || observedSnapshot != snapshot {
		return "", ErrOwnership
	}
	switch state {
	case "completed":
		return string(clone.GetUID()), nil
	case "initiated", "copy-completed-awaiting-healthy":
		return "", ErrPending
	default:
		return "", ErrOwnership
	}
}

func longhornSnapshotAccessMode(claim *corev1.PersistentVolumeClaim, volume *corev1.PersistentVolume, mode corev1.PersistentVolumeAccessMode) bool {
	return len(claim.Spec.AccessModes) == 1 && claim.Spec.AccessModes[0] == mode &&
		len(volume.Spec.AccessModes) == 1 && volume.Spec.AccessModes[0] == mode
}

func longhornLocalSnapshotHandle(volume, handle string) bool {
	if len(validation.IsDNS1123Subdomain(volume)) != 0 {
		return false
	}
	name, ok := strings.CutPrefix(handle, "snap://"+volume+"/")
	return ok && len(validation.IsDNS1123Subdomain(name)) == 0
}

func longhornSnapshotCutTime(snapshot, content *unstructured.Unstructured, start, observed time.Time) (time.Time, bool) {
	// The snapshotter projects the CSI nanosecond timestamp into metav1.Time
	// on VolumeSnapshot. Its JSON representation can lose fractional seconds.
	nanos, ok, err := unstructured.NestedInt64(content.Object, "status", "creationTime")
	if err != nil || !ok || nanos <= 0 {
		return time.Time{}, false
	}
	created := time.Unix(0, nanos).UTC()
	displayed, err := time.Parse(time.RFC3339Nano, longhornSnapshotString(snapshot, "status", "creationTime"))
	if err != nil || !displayed.Equal(created) && !displayed.Equal(created.Truncate(time.Second)) ||
		created.Before(start) || created.After(observed) {
		return time.Time{}, false
	}
	return created, true
}

func longhornSnapshotVolume(ctx context.Context, client kubernetes.Interface, ns, name string) (*corev1.PersistentVolumeClaim, *corev1.PersistentVolume, error) {
	claim, err := client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil ||
		(claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) {
		return nil, nil, ErrOwnership
	}
	if claim.Status.Phase == corev1.ClaimPending || claim.Status.Phase == "" {
		return nil, nil, ErrPending
	}
	if claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
		return nil, nil, ErrOwnership
	}
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound ||
		(pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) ||
		pv.Spec.CSI == nil || pv.Spec.CSI.Driver != longhornSnapshotDriver || pv.Spec.CSI.VolumeHandle == "" ||
		pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != name || pv.Spec.ClaimRef.Namespace != ns {
		return nil, nil, ErrOwnership
	}
	return claim, pv, nil
}

func longhornSnapshotResource(name string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: longhornSnapshotGroup, Version: "v1", Resource: name}
}

func longhornSnapshotString(o *unstructured.Unstructured, fields ...string) string {
	value, _, _ := unstructured.NestedString(o.Object, fields...)
	return value
}
