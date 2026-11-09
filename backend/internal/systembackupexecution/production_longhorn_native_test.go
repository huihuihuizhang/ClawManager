package systembackupexecution

import (
	"context"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLonghornNativeGrantIncludesEveryRunningMount(t *testing.T) {
	source := originalLonghornSource{Namespace: "test-system", NamespaceUID: "system-uid", ProviderUID: "provider-uid", Handle: "pvc-original", AccessMode: corev1.ReadWriteMany, Source: kube.MountIdentity{Name: "workspace", UID: "pvc-uid", PVUID: "pv-uid"}}
	digest := hash(mustLonghornJSON(source))
	binding := q.ObservationBinding{Kind: q.LonghornExt4Protocol, InstallationID: "installation-test", Namespace: source.Namespace, NamespaceUID: source.NamespaceUID, Node: "node-a", NodeUID: "node-uid"}
	provider := q.LonghornExt4SourceCoordinates{Binding: binding, OriginalSourceSHA256: digest, ProviderNamespaceUID: source.ProviderUID, VolumeHandle: source.Handle, PVCUID: source.Source.UID, PVUID: source.Source.PVUID}
	client := q.LonghornRWXClientCoordinates{Binding: binding, OriginalSourceSHA256: digest, ProviderNamespaceUID: source.ProviderUID, VolumeHandle: source.Handle, PVCUID: source.Source.UID, PVUID: source.Source.PVUID, PodNamespace: source.Namespace, MountPoint: "/workspace"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: source.Namespace, Name: "writer", UID: types.UID("pod-uid")}, Spec: corev1.PodSpec{NodeName: binding.Node, Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: source.Source.Name}}}}, Containers: []corev1.Container{{Name: "writer", VolumeMounts: []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspace"}}}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "writer", ContainerID: "containerd://original", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	api := fake.NewSimpleClientset(pod)
	owner := &deploymentLonghornCutOwner{owner: &PublicJobOwner{Client: api}, materials: []q.LonghornExt4Materials{{Sources: []q.LonghornExt4SourceCoordinates{provider}, Clients: []q.LonghornRWXClientCoordinates{client}}}}
	in := d.Input{Authority: d.Authority{InstallationID: binding.InstallationID, TaskPublicID: "task-original", AttemptNo: 1, MaintenanceFencingToken: 7}}
	claim := q.LonghornExt4Claim{TaskPublicID: in.Authority.TaskPublicID, Owner: "controller", MaintenanceOwner: "task-original", EntryRowVersion: 9, LeaseObservedAt: time.Now(), LeaseExpiresAt: time.Now().Add(time.Minute)}
	result, err := owner.nativeSource(context.Background(), in, plannedLonghornClone{Original: source}, claim, time.Now().Add(time.Minute), 11, digest)
	if err != nil || len(result.Clients) != 1 || result.Clients[0].ClientPodUID != "pod-uid" || result.Clients[0].ClientContainerID != "containerd://original" || result.Provider.Claim != claim {
		t.Fatalf("original mount was not bound to actual native client: %+v %v", result, err)
	}
	unknown := pod.DeepCopy()
	unknown.Name = "unregistered-writer"
	unknown.UID = "unregistered-pod"
	unknown.Spec.NodeName = "node-not-installed"
	if _, err := api.CoreV1().Pods(source.Namespace).Create(context.Background(), unknown, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.nativeSource(context.Background(), in, plannedLonghornClone{Original: source}, claim, time.Now().Add(time.Minute), 11, digest); err == nil {
		t.Fatal("unknown actual NFS client disappeared from original drain")
	}
}
