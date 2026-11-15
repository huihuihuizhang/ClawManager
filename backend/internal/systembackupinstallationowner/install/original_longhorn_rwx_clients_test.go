package install

import (
	"context"
	"reflect"
	"strings"
	"testing"

	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func originalRWXCensusFixture() (q.LonghornExt4Materials, []runtime.Object) {
	node, claim, pv := originalSharedVolumeObjects()
	pv.Spec.AccessModes = []core.PersistentVolumeAccessMode{core.ReadWriteMany}
	ns := &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: types.UID("app-uid")}}
	source := q.LonghornExt4SourceCoordinates{Binding: q.ObservationBinding{Kind: q.LonghornExt4Protocol, InstallationID: "installation_test", Namespace: "app", NamespaceUID: "app-uid", Node: node.Name, NodeUID: string(node.UID)}, PVCName: claim.Name, PVCUID: string(claim.UID), PVUID: string(pv.UID), VolumeHandle: pv.Spec.CSI.VolumeHandle, OriginalSourceSHA256: strings.Repeat("a", 64), ProviderNamespaceUID: "longhorn-uid"}
	identity, _ := q.LonghornExt4SourceIdentity(source.OriginalSourceSHA256, source.ProviderNamespaceUID, string(node.UID))
	template := q.LonghornRWXClientCoordinates{Binding: source.Binding, Identity: identity, PVCName: source.PVCName, PVCUID: source.PVCUID, PVUID: source.PVUID, VolumeHandle: source.VolumeHandle, OriginalSourceSHA256: source.OriginalSourceSHA256, ProviderNamespaceUID: source.ProviderNamespaceUID, PodNamespace: "app", MountPoint: "/workspaces", NFSSource: "10.0.0.1:/vol-workspaces", Endpoint: "10.0.0.1"}
	objects := []runtime.Object{node, claim, pv, ns}
	for _, name := range []string{"hermes", "openclaw", "readonly-attachment"} {
		pod := originalSharedVolumePod(name, "uid-"+name, core.VolumeMount{Name: "workspace", MountPath: "/workspaces", ReadOnly: name == "readonly-attachment"})
		pod.Status.Phase = core.PodRunning
		pod.Status.ContainerStatuses = []core.ContainerStatus{{Name: "runtime", ContainerID: "containerd://" + name, State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}
		objects = append(objects, &pod)
	}
	return q.LonghornExt4Materials{Sources: []q.LonghornExt4SourceCoordinates{source}, Clients: []q.LonghornRWXClientCoordinates{template}}, objects
}

func TestOriginalLonghornRWXCensusIncludesEveryRunningMount(t *testing.T) {
	m, objects := originalRWXCensusFixture()
	k := fake.NewSimpleClientset(objects...)
	before, err := originalLonghornRWXClients(context.Background(), k, m)
	if err != nil || len(before) != 3 {
		t.Fatal("running RWX mounts, including read-only attachment, were not completely observed", len(before), err)
	}
	pod, _ := k.CoreV1().Pods("app").Get(context.Background(), "hermes", metav1.GetOptions{})
	pod.UID = "replacement"
	if _, err := k.CoreV1().Pods("app").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := originalLonghornRWXClients(context.Background(), k, m)
	if err != nil || reflect.DeepEqual(before, after) {
		t.Fatal("same-name replacement did not change the retained cohort", err)
	}
	for _, action := range k.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" && action.GetVerb() != "update" {
			t.Fatal("census dispatched a mutation", action)
		}
	}
}

func TestOriginalLonghornRWXCensusRefusesUnboundOrAmbiguousClients(t *testing.T) {
	for _, scenario := range []string{"unknown-node", "unknown-mount", "pending", "missing-process", "duplicate-template", "replacement-pv", "prefilled-claim", "subpath", "ephemeral-client"} {
		t.Run(scenario, func(t *testing.T) {
			m, objects := originalRWXCensusFixture()
			pod := objects[4].(*core.Pod)
			switch scenario {
			case "unknown-node":
				pod.Spec.NodeName = "uninstalled-node"
			case "unknown-mount":
				pod.Spec.Containers[0].VolumeMounts[0].MountPath = "/uninstalled-mount"
			case "pending":
				pod.Status.ContainerStatuses[0].State = core.ContainerState{Waiting: &core.ContainerStateWaiting{}}
			case "missing-process":
				pod.Status.ContainerStatuses[0].ContainerID = ""
			case "duplicate-template":
				m.Clients = append(m.Clients, m.Clients[0])
			case "replacement-pv":
				objects[2].(*core.PersistentVolume).UID = "replacement"
			case "prefilled-claim":
				m.Clients[0].Claim.Owner = "claimed-owner"
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "partial"
			case "ephemeral-client":
				pod.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "debug", VolumeMounts: []core.VolumeMount{{Name: "workspace", MountPath: "/uninstalled-debug"}}}}}
				pod.Status.EphemeralContainerStatuses = []core.ContainerStatus{{Name: "debug", ContainerID: "containerd://debug", State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}
			}
			if _, err := originalLonghornRWXClients(context.Background(), fake.NewSimpleClientset(objects...), m); err == nil {
				t.Fatal("incomplete client drain was accepted")
			}
		})
	}
}
