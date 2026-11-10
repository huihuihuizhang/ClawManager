package install

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func classifyFixture(t *testing.T, accessMode corev1.PersistentVolumeAccessMode, driver, hostPath string) (*fake.Clientset, *corev1.Pod) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "source", Name: "writer", UID: "pod-uid"},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}
	pod.Spec.Volumes = []corev1.Volume{{Name: "data"}}
	pod.Spec.Volumes[0].PersistentVolumeClaim = &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim"}

	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "source", Name: "claim", UID: "claim-uid"},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv", AccessModes: []corev1.PersistentVolumeAccessMode{accessMode}},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}

	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv", UID: "pv-uid"}}
	pv.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{accessMode}
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "source", Name: "claim", UID: "claim-uid"}
	if hostPath != "" {
		pv.Spec.HostPath = &corev1.HostPathVolumeSource{Path: hostPath}
	} else {
		pv.Spec.CSI = &corev1.CSIPersistentVolumeSource{Driver: driver, VolumeHandle: "volume-handle", FSType: "ext4"}
	}
	return fake.NewSimpleClientset(pod, claim, pv), pod
}

func TestClassifyPodPersistentVolumesLonghorn(t *testing.T) {
	client, pod := classifyFixture(t, corev1.ReadWriteOnce, "driver.longhorn.io", "")
	roots, longhorn, err := classifyPodPersistentVolumes(context.Background(), client, pod, nil)
	if err != nil {
		t.Fatalf("longhorn volume rejected: %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("longhorn volume produced host roots: %v", roots)
	}
	if len(longhorn) != 1 || longhorn[0].Kind != originalPodVolumeLonghorn || longhorn[0].Handle != "volume-handle" {
		t.Fatalf("longhorn classification wrong: %+v", longhorn)
	}
	if longhorn[0].ClaimUID != "claim-uid" || longhorn[0].PVUID != "pv-uid" {
		t.Fatalf("longhorn identity wrong: %+v", longhorn[0])
	}
}

func TestClassifyPodPersistentVolumesHostPath(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "source", Name: "writer", UID: "pod-uid"},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}
	pod.Spec.Volumes = []corev1.Volume{{Name: "data"}}
	pod.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/var/lib/source"}
	roots, longhorn, err := classifyPodPersistentVolumes(context.Background(), fake.NewSimpleClientset(pod), pod, nil)
	if err != nil {
		t.Fatalf("host path volume rejected: %v", err)
	}
	if len(longhorn) != 0 {
		t.Fatalf("host path volume classified as longhorn: %+v", longhorn)
	}
	if len(roots) != 1 || roots[0] != "/var/lib/source" {
		t.Fatalf("host root wrong: %v", roots)
	}
}

func TestClassifyPodPersistentVolumesUnsupportedCSI(t *testing.T) {
	client, pod := classifyFixture(t, corev1.ReadWriteOnce, "driver.example.com", "")
	_, _, err := classifyPodPersistentVolumes(context.Background(), client, pod, nil)
	var failure OriginalWriterSourceFailure
	if !errors.As(err, &failure) || failure.Dependency != "persistent_volume_native_fence_required" {
		t.Fatalf("unsupported CSI not refused with the native fence dependency: %v", err)
	}
}
