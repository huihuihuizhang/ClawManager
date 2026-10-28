package profile

import (
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/recovery"
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"strings"
	"testing"
)

type sharedOwnerFixture struct{ fail bool }

func (sharedOwnerFixture) Probe(context.Context, recovery.Reference) error { return nil }
func (sharedOwnerFixture) Receipts(context.Context, control.Task) ([]SharedVolumeReceipt, error) {
	return nil, ErrProfile
}
func (o sharedOwnerFixture) Verify(context.Context, control.Task, SharedVolumeReceipt) error {
	if o.fail {
		return ErrProfile
	}
	return nil
}
func TestSharedWorkspaceRequiresFrozenVolumeIdentityAndContentProof(t *testing.T) {
	ctx := context.Background()
	class := "isolated"
	ref := recovery.Reference{ID: "shared", Version: "v1", SHA256: strings.Repeat("a", 64)}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "cm-drill-team", UID: "pvc-1"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv", StorageClassName: &class}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv", UID: "pv-1"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: pvc.Name, Namespace: pvc.Namespace, UID: pvc.UID}}}
	d := Driver{Config: Config{TargetNamespace: pvc.Namespace, SharedWorkspaceModule: &ref}, Client: fake.NewSimpleClientset(pvc, pv), SharedWorkspace: sharedOwnerFixture{}}
	r := SharedVolumeReceipt{TeamID: 1, ArtifactID: "backup", Namespace: pvc.Namespace, PVC: pvc.Name, PVCUID: string(pvc.UID), PV: pv.Name, PVUID: string(pv.UID), MountPath: "/shared", StorageClass: class, Contents: ref}
	task := control.Task{Request: control.Request{Artifact: "backup"}}
	if p, e := d.teamPlacements(ctx, task, []SharedVolumeReceipt{r}); e != nil || p["1"].PVC != "shared" {
		t.Fatal(p, e)
	}
	d.SharedWorkspace = sharedOwnerFixture{fail: true}
	if _, e := d.teamPlacements(ctx, task, []SharedVolumeReceipt{r}); e == nil {
		t.Fatal("missing content proof accepted")
	}
	d.SharedWorkspace = sharedOwnerFixture{}
	r.PVUID = "replaced"
	if _, e := d.teamPlacements(ctx, task, []SharedVolumeReceipt{r}); e == nil {
		t.Fatal("same-name replacement volume accepted")
	}
	d.SharedWorkspace = nil
	if _, e := d.teamPlacements(ctx, task, nil); e == nil {
		t.Fatal("missing owner treated as empty volume set")
	}
}
