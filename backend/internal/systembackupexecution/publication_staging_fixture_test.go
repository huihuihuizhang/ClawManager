package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Reuse D's exact API-shaped controller/node/PVC/PV fixture. These are test
// observations, not a storage/SQL authorization receipt. The reference enters
// the original core BEFORE its execution grants and full-file hash are signed.
func publicationStagingFixtureObjects(t *testing.T, cfg DeploymentConfig) (*corev1.Node, *corev1.PersistentVolumeClaim, *corev1.PersistentVolume) {
	t.Helper()
	_, _, _, node, claim, pv := stagingLocationFixture()
	var pin kube.MountIdentity
	for _, v := range cfg.Security.Volumes {
		if v.Kind == "PersistentVolumeClaim" && v.Name == cfg.StagingClaim {
			pin = v
		}
	}
	if pin.UID == "" || cfg.Security.NodeUIDs[cfg.Workspace.Node] == "" {
		t.Fatal("original staging volume/node pins required")
	}
	node.Name, node.UID = cfg.Workspace.Node, types.UID(cfg.Security.NodeUIDs[cfg.Workspace.Node])
	claim.Name, claim.Namespace, claim.UID, claim.Spec.VolumeName = cfg.StagingClaim, cfg.Namespace, types.UID(pin.UID), pin.PVName
	pv.Name, pv.UID = pin.PVName, types.UID(pin.PVUID)
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}
	return node, claim, pv
}

func configurePublicationStagingFixture(t *testing.T, cfg *DeploymentConfig) {
	node, claim, pv := publicationStagingFixtureObjects(t, *cfg)
	sum := kube.ContentHash(pv.Spec)
	for i := range cfg.Security.Volumes {
		if cfg.Security.Volumes[i].Kind == "PersistentVolumeClaim" && cfg.Security.Volumes[i].Name == claim.Name {
			cfg.Security.Volumes[i].SHA256 = sum
		}
	}
	cfg.StagingLocation = &StagingLocationReference{Version: stagingLocationVersion, Node: node.Name, NodeUID: string(node.UID), Container: "controller", Volume: "original-staging", ContainerPath: cfg.StagingDirectory, Claim: claim.Name, ClaimUID: string(claim.UID), PV: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: sum}
}

func installPublicationStagingFixture(t *testing.T, service *DeploymentService, client *fake.Clientset, controller string) {
	t.Helper()
	ctx := context.Background()
	cfg := service.Config
	node, claim, pv := publicationStagingFixtureObjects(t, cfg)
	for _, object := range []runtime.Object{node, claim, pv} {
		if err := client.Tracker().Add(object); err != nil {
			t.Fatal(err)
		}
	}
	pod, err := client.CoreV1().Pods(cfg.Namespace).Get(ctx, controller, metav1.GetOptions{})
	if err != nil || len(pod.Spec.Containers) != 1 {
		t.Fatal("original controller Pod required", err)
	}
	ref := cfg.StagingLocation
	// The independently signed reference already names the original container.
	if ref.Container != pod.Spec.Containers[0].Name {
		t.Fatal("fixture container changed after core signing")
	}
	pod.Spec.NodeName = node.Name
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: ref.Volume, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name}}})
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: ref.Volume, MountPath: ref.ContainerPath})
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: ref.Container, ContainerID: "containerd://original-publisher", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
	if _, err = client.CoreV1().Pods(cfg.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
