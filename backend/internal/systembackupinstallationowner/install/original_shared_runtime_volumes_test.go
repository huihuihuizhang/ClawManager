package install

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func originalSharedVolumeSet(t *testing.T, objects ...runtime.Object) (*fake.Clientset, *PreparedOriginalWriterSet) {
	t.Helper()
	client := fake.NewSimpleClientset(objects...)
	owner := &OriginalWriterMaintenance{operator: &authenticatedOperator{installer: &Installer{kube: client}}}
	return client, &PreparedOriginalWriterSet{owner: owner}
}

func originalSharedVolumeObjects() (*corev1.Node, *corev1.PersistentVolumeClaim, *corev1.PersistentVolume) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid")}}
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "clawmanager-workspaces", Namespace: "app", UID: types.UID("claim-uid")},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-workspaces"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-workspaces", UID: types.UID("pv-uid")},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Name: claim.Name, Namespace: claim.Namespace, UID: claim.UID},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{
				Driver: "driver.longhorn.io", VolumeHandle: "vol-workspaces",
			}},
		},
	}
	return node, claim, pv
}

func originalSharedVolumePod(name, uid string, mounts ...corev1.VolumeMount) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app", UID: types.UID(uid)},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "clawmanager-workspaces"},
			}}},
			Containers: []corev1.Container{{Name: "runtime", VolumeMounts: mounts}},
		},
	}
}

func TestOriginalSharedVolumeRecordsCoverTwoRWXMounters(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	_, set := originalSharedVolumeSet(t, node, claim, pv)
	var records []OriginalSharedRuntimeVolume
	for _, pod := range []corev1.Pod{
		originalSharedVolumePod("runtime-1", "pod-uid-1", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}),
		originalSharedVolumePod("runtime-2", "pod-uid-2", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}),
	} {
		roots, longhorn, err := set.classifyPodPersistentVolumes(ctx, &pod)
		if err != nil || len(roots) != 0 || len(longhorn) != 1 {
			t.Fatalf("longhorn classification: roots=%v longhorn=%v err=%v", roots, longhorn, err)
		}
		actual, err := set.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn)
		if err != nil || len(actual) != 1 {
			t.Fatalf("volume record: %#v err=%v", actual, err)
		}
		records = append(records, actual...)
	}
	if len(records) != 2 || records[0].PodUID == records[1].PodUID {
		t.Fatalf("two distinct mounter records required: %#v", records)
	}
	for _, record := range records {
		if record.ClaimUID != "claim-uid" || record.PVUID != "pv-uid" || record.Handle != "vol-workspaces" || record.Node != "node-a" || record.NodeUID != "node-a-uid" {
			t.Fatalf("record does not bind the actual claim/PV/handle/node: %#v", record)
		}
		if len(record.Mounts) != 1 || record.Mounts[0].Container != "runtime" || record.Mounts[0].MountPath != "/config" || record.Mounts[0].SubPath != "" {
			t.Fatalf("record does not bind container/mount/path: %#v", record.Mounts)
		}
	}
	set.selection.SharedRuntimeVolumes = records
	for _, pod := range []corev1.Pod{
		originalSharedVolumePod("runtime-1", "pod-uid-1", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}),
		originalSharedVolumePod("runtime-2", "pod-uid-2", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}),
	} {
		if err := set.checkOriginalSharedRuntimeVolumes(ctx, &pod); err != nil {
			t.Fatalf("fresh re-read must accept the same identity: %v", err)
		}
	}
}

func TestOriginalSharedVolumeRecordRejectsIncompleteMounts(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	_, set := originalSharedVolumeSet(t, node, claim, pv)
	for name, pod := range map[string]corev1.Pod{
		"missing":   originalSharedVolumePod("runtime-missing", "pod-missing"),
		"duplicate": originalSharedVolumePod("runtime-duplicate", "pod-duplicate", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}, corev1.VolumeMount{Name: "workspace", MountPath: "/config"}),
		"subpath":   originalSharedVolumePod("runtime-subpath", "pod-subpath", corev1.VolumeMount{Name: "workspace", MountPath: "/config", SubPath: "../escape"}),
	} {
		t.Run(name, func(t *testing.T) {
			_, longhorn, err := set.classifyPodPersistentVolumes(ctx, &pod)
			if err != nil || len(longhorn) != 1 {
				t.Fatalf("classification setup: %v", err)
			}
			if _, err := set.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn); err == nil {
				t.Fatal("incomplete or duplicate mount must not become a reviewable record")
			}
		})
	}
}

func TestOriginalSharedVolumeRecordRejectsUnknownCSI(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	pv.Spec.CSI.Driver = "another.csi.example"
	_, set := originalSharedVolumeSet(t, node, claim, pv)
	pod := originalSharedVolumePod("runtime-1", "pod-uid-1", corev1.VolumeMount{Name: "workspace", MountPath: "/config"})
	_, _, err := set.classifyPodPersistentVolumes(ctx, &pod)
	var failure OriginalWriterSourceFailure
	if !errors.As(err, &failure) || failure.Dependency != "persistent_volume_native_fence_required" {
		t.Fatalf("unknown CSI must remain an unsupported source, got %v", err)
	}
}

func TestOriginalSharedVolumeMixedHostAndLonghornKeepsBothHalves(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	_, set := originalSharedVolumeSet(t, node, claim, pv)
	pod := originalSharedVolumePod("runtime-mixed", "pod-mixed", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}, corev1.VolumeMount{Name: "data", MountPath: "/data"})
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/runtime-data"}}})
	roots, longhorn, err := set.classifyPodPersistentVolumes(ctx, &pod)
	if err != nil || !reflect.DeepEqual(roots, []string{"/var/lib/runtime-data"}) || len(longhorn) != 1 {
		t.Fatalf("mixed mount classification: roots=%v longhorn=%v err=%v", roots, longhorn, err)
	}
	records, err := set.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn)
	if err != nil || len(records) != 1 || records[0].VolumeName != "workspace" {
		t.Fatalf("mixed mount must record only the Longhorn half: %#v err=%v", records, err)
	}
}

func TestOriginalSharedVolumeDriftIsRejected(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	client, set := originalSharedVolumeSet(t, node, claim, pv)
	pod := originalSharedVolumePod("runtime-1", "pod-uid-1", corev1.VolumeMount{Name: "workspace", MountPath: "/config"})
	_, longhorn, err := set.classifyPodPersistentVolumes(ctx, &pod)
	if err != nil {
		t.Fatal(err)
	}
	records, err := set.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn)
	if err != nil {
		t.Fatal(err)
	}
	set.selection.SharedRuntimeVolumes = records

	t.Run("pv_uid_drift", func(t *testing.T) {
		drifted := pv.DeepCopy()
		drifted.UID = types.UID("replacement-pv-uid")
		if err := client.CoreV1().PersistentVolumes().Delete(ctx, pv.Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.CoreV1().PersistentVolumes().Create(ctx, drifted, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := set.checkOriginalSharedRuntimeVolumes(ctx, &pod); err == nil {
			t.Fatal("PV UID drift must be rejected")
		}
	})

	t.Run("mount_drift", func(t *testing.T) {
		changed := originalSharedVolumePod("runtime-1", "pod-uid-1", corev1.VolumeMount{Name: "workspace", MountPath: "/another"})
		if err := set.checkOriginalSharedRuntimeVolumes(ctx, &changed); err == nil {
			t.Fatal("mount path drift must be rejected")
		}
	})

	t.Run("record_without_volume", func(t *testing.T) {
		hostOnly := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runtime-1", Namespace: "app", UID: types.UID("pod-uid-1")}, Spec: corev1.PodSpec{NodeName: "node-a", Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/runtime-data"}}}}, Containers: []corev1.Container{{Name: "runtime", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}}}}
		if err := set.checkOriginalSharedRuntimeVolumes(ctx, &hostOnly); err == nil {
			t.Fatal("a recorded Longhorn volume that is gone must be rejected")
		}
	})
}

func TestOriginalSharedVolumeMixedHostPVCKeepsPhysicalPin(t *testing.T) {
	ctx := context.Background()
	node, claim, pv := originalSharedVolumeObjects()
	hostClaim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "host-data", Namespace: "app", UID: types.UID("host-claim-uid")},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-host-data"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	hostPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-host-data", UID: types.UID("host-pv-uid")},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef:               &corev1.ObjectReference{Name: hostClaim.Name, Namespace: hostClaim.Namespace, UID: hostClaim.UID},
			PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/host-data"}},
			NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a"}}},
			}}}},
		},
	}
	_, set := originalSharedVolumeSet(t, node, claim, pv, hostClaim, hostPV)
	pod := originalSharedVolumePod("runtime-mixed-pvc", "pod-mixed-pvc", corev1.VolumeMount{Name: "workspace", MountPath: "/config"}, corev1.VolumeMount{Name: "host-data", MountPath: "/data"})
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "host-data", VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "host-data"},
	}})
	roots, longhorn, err := set.classifyPodPersistentVolumes(ctx, &pod)
	if err != nil || !reflect.DeepEqual(roots, []string{"/var/lib/host-data"}) || len(longhorn) != 1 {
		t.Fatalf("mixed host PVC classification: roots=%v longhorn=%v err=%v", roots, longhorn, err)
	}
	if len(set.volumes) != 1 || set.volumes[0].ClaimName != "host-data" || set.volumes[0].PVName != "pv-host-data" || set.volumes[0].Node != "node-a" {
		t.Fatalf("host PVC physical pin must survive the mixed classification: %#v", set.volumes)
	}
	records, err := set.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn)
	if err != nil || len(records) != 1 || records[0].VolumeName != "workspace" {
		t.Fatalf("mixed host PVC must still record the Longhorn half: %#v err=%v", records, err)
	}
}

func TestOriginalSharedVolumeOldHostOnlySelectionStillReads(t *testing.T) {
	selection := OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion}
	raw, err := canonical(selection)
	if err != nil || bytes.Contains(raw, []byte(`"SharedRuntimeVolumes"`)) {
		t.Fatalf("host-only selection must not grow a volume field: %s err=%v", raw, err)
	}
	var decoded OriginalWriterSetSelection
	if err := decodeExact(raw, &decoded); err != nil || len(decoded.SharedRuntimeVolumes) != 0 {
		t.Fatalf("old host-only selection must still decode: %v", err)
	}
}

func TestOriginalSharedVolumeSelectionKeepsReviewedRecords(t *testing.T) {
	selection := OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion, SharedRuntimeVolumes: []OriginalSharedRuntimeVolume{{
		VolumeName: "workspace", ClaimName: "clawmanager-workspaces", ClaimUID: "claim-uid", PVName: "pv-workspaces", PVUID: "pv-uid", Handle: "vol-workspaces",
		Namespace: "app", Pod: "runtime-1", PodUID: "pod-uid-1", Node: "node-a", NodeUID: "node-a-uid",
		Mounts: []OriginalSharedRuntimeVolumeMount{{Container: "runtime", MountPath: "/config"}},
	}}}
	raw, err := canonical(selection)
	if err != nil {
		t.Fatal(err)
	}
	var decoded OriginalWriterSetSelection
	if err := decodeExact(raw, &decoded); err != nil || !reflect.DeepEqual(decoded.SharedRuntimeVolumes, selection.SharedRuntimeVolumes) {
		t.Fatalf("reviewed volume identity must round-trip: %v", err)
	}
}
