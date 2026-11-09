package kube

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLonghornCaptureCloneReusesPendingClaim(t *testing.T) {
	ctx := context.Background()
	runner, api, journal, _ := runnerFixture(t)
	ns := "system"
	sourceID := Identity{Namespace: ns, Name: "cut", Owner: "task-1"}
	snapshot, err := Snapshot(sourceID, "workspace", "local-cut", true)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRecord, err := runner.Ensure(ctx, "VolumeSnapshot", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshotAPI := api.Resource(longhornSnapshotResource("volumesnapshots")).Namespace(ns)
	snapshot, err = snapshotAPI.Get(ctx, sourceID.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1794000000, 0).UTC()
	snapshot.Object["status"] = map[string]any{"readyToUse": true, "boundVolumeSnapshotContentName": "content", "creationTime": created.Format(time.RFC3339)}
	if _, err := snapshotAPI.UpdateStatus(ctx, snapshot, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	classSpec := map[string]any{"driver": longhornSnapshotDriver, "deletionPolicy": "Delete", "parameters": map[string]any{"type": "snap"}}
	class := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": longhornSnapshotGroup + "/v1", "kind": "VolumeSnapshotClass", "metadata": map[string]any{"name": "local-cut", "uid": "class-uid"},
	}}
	for name, value := range classSpec {
		class.Object[name] = value
	}
	backendName := "snapshot-" + snapshotRecord.UID
	handle := "snap://source-volume/" + backendName
	content := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": longhornSnapshotGroup + "/v1", "kind": "VolumeSnapshotContent", "metadata": map[string]any{"name": "content", "uid": "content-uid"},
		"spec": map[string]any{"driver": longhornSnapshotDriver, "deletionPolicy": "Delete", "volumeSnapshotClassName": "local-cut",
			"volumeSnapshotRef": map[string]any{"name": sourceID.Name, "namespace": ns, "uid": snapshotRecord.UID}, "source": map[string]any{"volumeHandle": "source-volume"}},
		"status": map[string]any{"snapshotHandle": handle, "readyToUse": true, "creationTime": created.UnixNano()},
	}}
	for kind, object := range map[string]*unstructured.Unstructured{"volumesnapshotclasses": class, "volumesnapshotcontents": content} {
		if err := api.Tracker().Create(longhornSnapshotResource(kind), object, ""); err != nil {
			t.Fatal(err)
		}
	}
	size := resource.MustParse("50Gi")
	capacity := corev1.ResourceList{corev1.ResourceStorage: size}
	modes := []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "workspace", Namespace: ns, UID: "claim-uid"},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv", AccessModes: modes}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: capacity}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "source-pv", UID: "pv-uid"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
		Spec: corev1.PersistentVolumeSpec{Capacity: capacity, AccessModes: modes, ClaimRef: &corev1.ObjectReference{Namespace: ns, Name: pvc.Name, UID: pvc.UID},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: longhornSnapshotDriver, VolumeHandle: "source-volume"}}}}
	reclaim, immediate := corev1.PersistentVolumeReclaimDelete, storagev1.VolumeBindingImmediate
	storageClass := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "capture", UID: "storage-class-uid"}, Provisioner: longhornSnapshotDriver, ReclaimPolicy: &reclaim, VolumeBindingMode: &immediate}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: "system-uid"}}, pvc, pv, storageClass,
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "worker-clone", Namespace: ns, UID: types.UID("created-uid")}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}})
	pin := LonghornSnapshotPin{Source: MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: pvc.Name, UID: string(pvc.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: ContentHash(pv.Spec)},
		NamespaceUID: "system-uid", ProviderNamespace: "longhorn", ProviderNamespaceUID: "provider-uid", AccessMode: modes[0], SourceHandle: "source-volume", BackendSnapshotHandle: handle,
		Class: class.GetName(), ClassUID: string(class.GetUID()), ClassSHA: ContentHash([]any{classSpec["driver"], classSpec["deletionPolicy"], classSpec["parameters"]}),
		Snapshot: snapshotRecord, CutStart: created.Add(-time.Second), CutObservedAt: created.Add(time.Second)}
	hold := LonghornCaptureHold{StartedAt: pin.CutStart, Recheck: func(context.Context) (time.Time, error) { return created.Add(time.Second), nil }}
	fresh := pin
	fresh.Snapshot = ResourceRecord{}
	lost := hold
	lost.Recheck = func(context.Context) (time.Time, error) { return time.Time{}, ErrOwnership }
	if _, err := ReconcileLonghornCaptureCut(ctx, client, runner, fresh, Identity{Namespace: ns, Name: "must-not-dispatch", Owner: sourceID.Owner}, lost); err != ErrOwnership || len(journal.records) != 1 {
		t.Fatalf("cut dispatched without provider hold: %v", err)
	}
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pin.ProviderNamespace, UID: types.UID(pin.ProviderNamespaceUID)}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileLonghornCaptureCut(ctx, client, runner, pin, sourceID, hold); err != ErrOwnership {
		t.Fatalf("CSI-only cut accepted: %v", err)
	}
	native := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "longhorn.io/v1beta2", "kind": "Snapshot",
		"metadata": map[string]any{"name": backendName, "namespace": pin.ProviderNamespace, "uid": "provider-snapshot-uid"},
		"spec":     map[string]any{"volume": pin.SourceHandle},
		"status":   map[string]any{"readyToUse": true, "creationTime": created.Format(time.RFC3339Nano)},
	}}
	snapshotGVR := schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "snapshots"}
	if err := api.Tracker().Create(snapshotGVR, native, pin.ProviderNamespace); err != nil {
		t.Fatal(err)
	}
	pin, err = ReconcileLonghornCaptureCut(ctx, client, runner, pin, sourceID, hold)
	if err != nil || pin.ProviderSnapshotUID != "provider-snapshot-uid" || pin.BackendSnapshotHandle != handle {
		t.Fatalf("native snapshot cut = %+v, %v", pin.Snapshot, err)
	}
	target := LonghornCaptureClone{Claim: Identity{Namespace: ns, Name: "worker-clone", Owner: sourceID.Owner}, NamespaceUID: pin.NamespaceUID, Class: storageClass.Name, ClassUID: string(storageClass.UID),
		ClassSHA256: ContentHash([]any{storageClass.Provisioner, storageClass.Parameters, storageClass.ReclaimPolicy, storageClass.VolumeBindingMode, storageClass.MountOptions, storageClass.AllowedTopologies})}
	if err := VerifyLonghornCaptureSource(ctx, client, api, pin, ns, target); err != nil || len(journal.records) != 1 {
		t.Fatalf("read-only source verification: %v", err)
	}
	stale := target
	stale.ClassUID = "previous-class-uid"
	if err := VerifyLonghornCaptureSource(ctx, client, api, pin, ns, stale); err != ErrOwnership || len(journal.records) != 1 {
		t.Fatalf("replaced clone class accepted: %v", err)
	}
	job, err := Job(JobRequest{Identity: Identity{Namespace: ns, Name: "worker-job", Owner: sourceID.Owner}, Image: "worker@sha256:" + strings.Repeat("a", 64),
		ServiceAccount: "capture", Command: []string{"/worker"}, StagingClaim: "staging", DeadlineSeconds: 120,
		Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: target.Claim.Name}}}})
	if err != nil {
		t.Fatal(err)
	}
	writable := job.DeepCopy()
	writable.Spec.Template.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
	if _, _, err := ReconcileLonghornCaptureJob(ctx, client, runner, Runner{}, pin, target, writable); err != ErrOwnership || len(journal.records) != 1 {
		t.Fatalf("writable clone mount dispatched a request: %v", err)
	}
	aliased := job.DeepCopy()
	aliased.Spec.Template.Spec.Volumes[1].PersistentVolumeClaim.ClaimName = target.Claim.Name
	if _, _, err := ReconcileLonghornCaptureJob(ctx, client, runner, Runner{}, pin, target, aliased); err != ErrOwnership || len(journal.records) != 1 {
		t.Fatalf("duplicate clone mount dispatched a request: %v", err)
	}
	for range 2 {
		pin, _, err = ReconcileLonghornCaptureJob(ctx, client, runner, Runner{}, pin, target, job)
		if err != ErrPending || pin.Clone.UID != "created-uid" {
			t.Fatalf("clone pending reconciliation = %q, %v", pin.Clone.UID, err)
		}
	}
	replacement := target
	replacement.Claim.Name = "different-clone"
	if _, _, err := ReconcileLonghornCaptureClone(ctx, client, runner, Runner{}, pin, replacement); err != ErrOwnership {
		t.Fatalf("changed clone target = %v", err)
	}
	claimAPI := api.Resource(corev1.SchemeGroupVersion.WithResource("persistentvolumeclaims")).Namespace(ns)
	claim, err := claimAPI.Get(ctx, target.Claim.Name, metav1.GetOptions{})
	if err != nil || longhornSnapshotString(claim, "spec", "dataSource", "name") != sourceID.Name ||
		longhornSnapshotString(claim, "spec", "resources", "requests", "storage") != "50Gi" || len(journal.records) != 2 {
		t.Fatalf("unexpected claim or journal: %v, %v", claim, err)
	}
	var bound corev1.PersistentVolumeClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(claim.Object, &bound); err != nil {
		t.Fatal(err)
	}
	bound.Spec.VolumeName = "clone-pv"
	bound.Status = corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: capacity}
	if _, err := client.CoreV1().PersistentVolumeClaims(ns).Update(ctx, &bound, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	clonePV := pv.DeepCopy()
	clonePV.Name, clonePV.UID = "clone-pv", "clone-pv-uid"
	clonePV.Spec.AccessModes = bound.Spec.AccessModes
	clonePV.Spec.ClaimRef = &corev1.ObjectReference{Namespace: ns, Name: bound.Name, UID: bound.UID}
	clonePV.Spec.CSI.VolumeHandle = "clone-volume"
	if _, err := client.CoreV1().PersistentVolumes().Create(ctx, clonePV, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	provider := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "longhorn.io/v1beta2", "kind": "Volume",
		"metadata": map[string]any{"name": "clone-volume", "namespace": pin.ProviderNamespace, "uid": "provider-volume-uid"},
		"status":   map[string]any{"cloneStatus": map[string]any{"state": "completed", "sourceVolume": "source-volume", "snapshot": backendName}}}}
	gvr := schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}
	if err := api.Tracker().Create(gvr, provider, pin.ProviderNamespace); err != nil {
		t.Fatal(err)
	}
	_, binding, err := ReconcileLonghornCaptureJob(ctx, client, runner, Runner{}, pin, target, job)
	if err != nil || binding.Clone.Name != bound.Name || binding.Clone.UID != string(bound.UID) || binding.Clone.PVUID != string(clonePV.UID) || binding.ProviderCloneUID != "provider-volume-uid" || binding.ProviderSnapshotUID != "provider-snapshot-uid" {
		t.Fatalf("held Job mount binding = %+v, %v", binding, err)
	}
}
