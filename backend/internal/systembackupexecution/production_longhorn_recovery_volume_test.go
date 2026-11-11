package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestKeeperCleanupRequiresOriginalRecoveredLonghornVolume(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", UID: "tenant-uid"}}
	provider := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "storage-provider", UID: "provider-uid"}}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "original-data", UID: "claim-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-pv", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "original-pv", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}, PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "original-handle"}}}}
	source := originalLonghornSource{Namespace: ns.Name, NamespaceUID: string(ns.UID), Handle: "original-handle", ProviderNamespace: provider.Name, ProviderUID: string(provider.UID), AccessMode: corev1.ReadWriteOnce, Source: kube.MountIdentity{Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}}
	for _, fault := range []string{"", "namespace", "provider", "claim", "pv", "binding", "handle", "mode", "unbound"} {
		t.Run(fault, func(t *testing.T) {
			n, c, v, storage := ns.DeepCopy(), claim.DeepCopy(), pv.DeepCopy(), provider.DeepCopy()
			switch fault {
			case "namespace":
				n.UID = "new-tenant"
			case "provider":
				storage.UID = "replacement-provider"
			case "claim":
				c.UID = "new-claim"
			case "pv":
				v.UID = "new-pv"
			case "binding":
				v.Spec.ClaimRef.UID = "other-claim"
			case "handle":
				v.Spec.CSI.VolumeHandle = "other-handle"
			case "mode":
				c.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
			case "unbound":
				c.Status.Phase = corev1.ClaimPending
			}
			api := fake.NewSimpleClientset(n, c, v, storage)
			if err := checkRecoveredLonghornVolume(context.Background(), api, source); (err == nil) != (fault == "") {
				t.Fatalf("recovered volume check: %v", err)
			}
			for _, action := range api.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("cleanup precheck mutated source", action.GetVerb())
				}
			}
		})
	}
}
