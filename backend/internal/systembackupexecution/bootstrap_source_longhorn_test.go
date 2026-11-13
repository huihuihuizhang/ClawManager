package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOriginalLonghornStorageAuthorRechecksSelectedVolumes(t *testing.T) {
	ctx := context.Background()
	objects := []runtime.Object{}
	for _, ns := range []string{"test-system", "test-user-1", "provider"} {
		objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: types.UID(ns + "-uid"), Labels: map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1"}}})
	}
	pair := func(ns, name string, access corev1.PersistentVolumeAccessMode) kube.MountIdentity {
		pvc := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(name + "-uid")},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: name + "-pv", AccessModes: []corev1.PersistentVolumeAccessMode{access}},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}
		pv := &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: pvc.Spec.VolumeName, UID: types.UID(name + "-pv-uid")},
			Spec: corev1.PersistentVolumeSpec{
				AccessModes:            pvc.Spec.AccessModes,
				ClaimRef:               &corev1.ObjectReference{Namespace: ns, Name: name, UID: pvc.UID},
				PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: name + "-handle"}},
			},
			Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
		}
		objects = append(objects, pvc, pv)
		return kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: name, UID: string(pvc.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
	}
	shared := pair("test-system", "workspace", corev1.ReadWriteMany)
	tenant := pair("test-user-1", "pro", corev1.ReadWriteOnce)
	teamClaim := pair("test-user-1", "team-shared", corev1.ReadWriteMany)
	reclaim, binding := corev1.PersistentVolumeReclaimDelete, storagev1.VolumeBindingImmediate
	objects = append(objects, &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "longhorn", UID: "clone-class-uid"},
		Provisioner: "driver.longhorn.io", ReclaimPolicy: &reclaim, VolumeBindingMode: &binding,
	})
	snapshot := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass",
		"metadata": map[string]any{"name": "local", "uid": "snapshot-class-uid"},
		"driver":   "driver.longhorn.io", "deletionPolicy": "Delete", "parameters": map[string]any{"type": "snap"},
	}}
	clients := &productionMetadataClients{API: fake.NewSimpleClientset(objects...), Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), snapshot)}
	cfg := DeploymentConfig{Namespace: "test-system", NamespaceUID: "test-system-uid", StagingClaim: "staging", InstallationID: "installation-test",
		Workspace: WorkspaceCapture{Claim: shared.Name}, Security: kube.WorkerSecurity{Volumes: []kube.MountIdentity{shared}}}
	pro := b.InstanceIdentity{ID: 2, UserID: 1, Mode: "pro", OS: "linux", Status: "running", Namespace: "test-user-1"}
	source := b.SourceInventory{Instances: []b.InstanceIdentity{{ID: 1, Mode: "lite", Status: "running"}, pro},
		TeamFacts: &team.SourceFacts{Teams: []team.TeamSQLFacts{{ID: 3, Namespace: cfg.Namespace, PVC: shared.Name}, {ID: 4, UserID: 1, ResourceScope: "cm", Namespace: "test-user-1", PVC: teamClaim.Name}}}}
	scope := &productionPersistentMountScope{RunningTenantPro: []runningTenantProMount{{Source: pro, Identity: tenant, NamespaceUID: "test-user-1-uid"}}}
	selection := &OriginalLonghornStorageSelection{ProviderNamespace: "provider", SnapshotClass: "local", CloneClass: "longhorn"}
	pins, err := observeOriginalLonghornSources(ctx, clients, cfg, source, scope, selection)
	if err != nil || len(pins) != 4 || pins["team_4_workspace"].Source != teamClaim || pins["team_4_workspace"].NamespaceUID != "test-user-1-uid" || pins["instance_1_workspace"].Source != shared ||
		pins["team_3_workspace"] != pins["instance_1_workspace"] ||
		pins["instance_2_workspace"].Source != tenant || pins["instance_2_workspace"].Handle != "pro-handle" {
		t.Fatalf("author lost a shared or tenant capture part: %v", err)
	}
	reader := &bootstrapSourceRegistryReader{config: cfg, materials: productionCaptureMaterials{Discovery: &productionSourceDiscovery{
		PersistentMounts: scope, LonghornSources: pins,
	}}}
	if err := reader.checkOriginalLonghornSources(ctx, clients, source); err != nil {
		t.Fatalf("unchanged source cannot reach signing: %v", err)
	}
	resource := clients.Dynamic.Resource(schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"})
	snapshot.SetUID("replacement-uid")
	if _, err := resource.Update(ctx, snapshot, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if reader.checkOriginalLonghornSources(ctx, clients, source) == nil {
		t.Fatal("same-name snapshot class replacement passed original source recheck")
	}
}
