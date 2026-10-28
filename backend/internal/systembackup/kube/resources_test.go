package kube

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPVCBackedHostPathIsNotCSISnapshot(t *testing.T) {
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "workspaces", Namespace: "source", UID: "claim-1"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv", UID: "pv-1"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "workspaces", Namespace: "source", UID: pvc.UID}, PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data/workspaces"}}}}
	client := fake.NewSimpleClientset(pvc, pv)
	s, e := ResolvePVC(context.Background(), client, "source", "workspaces", "node-a", "workbuddy/user-4/instance-7", true)
	if e != nil || s.Kind != "hostpath" || s.SnapshotProbePassed || s.AdditionalMountsKnown {
		t.Fatalf("bad storage evidence: %+v %v", s, e)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" {
			t.Fatal("discovery mutated cluster")
		}
	}
	pv.Spec.ClaimRef.UID = "recreated"
	client = fake.NewSimpleClientset(pvc, pv)
	if _, e = ResolvePVC(context.Background(), client, "source", "workspaces", "node-a", "x", true); e == nil {
		t.Fatal("wrong claim UID accepted")
	}
}
func TestJobsAndDrillResourcesAreInertAndScoped(t *testing.T) {
	i := Identity{"cm-drill-fixture", "capture-fixture", "owner-123"}
	r := JobRequest{Identity: i, Image: "fixture/worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "capture", Command: []string{"/worker", "capture"}, Source: corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source"}}}, SourceSubPath: "user-4/instance-7", StagingClaim: "staging", DeadlineSeconds: 120, NodeName: "node-a"}
	job, e := Job(r)
	if e != nil {
		t.Fatal(e)
	}
	pod := job.Spec.Template.Spec
	if *pod.AutomountServiceAccountToken || *job.Spec.BackoffLimit != 0 || !pod.Containers[0].VolumeMounts[0].ReadOnly || pod.Affinity == nil || pod.NodeName != "" {
		t.Fatal("job escapes scope or bypasses scheduler")
	}
	if r.Source.PersistentVolumeClaim.ReadOnly {
		t.Fatal("caller volume mutated")
	}
	r.Image = "fixture:latest"
	if _, e = Job(r); e == nil {
		t.Fatal("mutable image accepted")
	}
	policy, e := DrillNetworkPolicy(i)
	if e != nil || len(policy.Spec.Egress) != 0 || len(policy.Spec.Ingress) != 0 {
		t.Fatal("drill network not denied")
	}
	pvc, e := RestorePVC(i, "fixture-class", "1Gi", "snapshot")
	if e != nil || pvc.Spec.DataSource.Name != "snapshot" {
		t.Fatal(e)
	}
	i.Namespace = "clawmanager-system"
	if _, e = RestorePVC(i, "fixture-class", "1Gi", ""); e == nil {
		t.Fatal("production target")
	}
}
func TestSnapshotRequiresCapabilityAndIdentity(t *testing.T) {
	i := Identity{"source", "snap", "owner"}
	if _, e := Snapshot(i, "claim", "class", false); e == nil {
		t.Fatal("unprobed snapshot")
	}
	s, e := Snapshot(i, "claim", "class", true)
	if e != nil {
		t.Fatal(e)
	}
	s.SetUID(types.UID("uid"))
	unstructured.SetNestedField(s.Object, true, "status", "readyToUse")
	unstructured.SetNestedField(s.Object, "content", "status", "boundVolumeSnapshotContentName")
	if !SnapshotReady(s, i, "uid", "claim") || SnapshotReady(s, i, "other", "claim") {
		t.Fatal("snapshot identity check")
	}
}
func TestVolumePathIncludesMountSubPath(t *testing.T) {
	m := corev1.VolumeMount{MountPath: "/workspaces", SubPath: "tenant"}
	s, e := VolumeRelativePath(m, "/workspaces/hermes/user-1/instance-7")
	if e != nil || s != "tenant/hermes/user-1/instance-7" {
		t.Fatal(s, e)
	}
	for _, s := range []string{"/workspaces-other/a", "/workspaces/../secret"} {
		if _, e = VolumeRelativePath(m, s); e == nil {
			t.Fatal("escaped mount")
		}
	}
}
