package install

import (
	"context"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func originalCSIPodFixture(t *testing.T, rwo bool) (*PreparedOriginalWriterSet, *core.Pod, []originalPodVolumeClass, *fake.Clientset) {
	t.Helper()
	m, objects := originalRWXCensusFixture()
	if rwo {
		objects = objects[:5]
		objects[1].(*core.PersistentVolumeClaim).Spec.AccessModes = []core.PersistentVolumeAccessMode{core.ReadWriteOnce}
		objects[2].(*core.PersistentVolume).Spec.AccessModes = []core.PersistentVolumeAccessMode{core.ReadWriteOnce}
		m.Clients = nil
	}
	m.Sources[0].Identity, _ = q.LonghornExt4SourceIdentity(m.Sources[0].OriginalSourceSHA256, m.Sources[0].ProviderNamespaceUID, m.Sources[0].Binding.NodeUID)
	for _, obj := range objects {
		if pod, ok := obj.(*core.Pod); ok {
			pod.Status.ContainerStatuses[0].Ready = true
		}
	}
	k := fake.NewSimpleClientset(objects...)
	clients, err := originalLonghornRWXClients(context.Background(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := k.CoreV1().Pods("app").Get(context.Background(), "hermes", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := &PreparedOriginalWriterSet{owner: &OriginalWriterMaintenance{operator: &authenticatedOperator{installer: &Installer{kube: k}}}, longhornMaterials: &m, longhornRWXClients: clients, longhornSources: map[string]q.LonghornExt4SourceCoordinates{}}
	_, classes, err := s.classifyPodPersistentVolumes(context.Background(), pod)
	if err != nil {
		t.Fatal(err)
	}
	source := m.Sources[0]
	if rwo {
		source.ProviderPodName, source.ProviderPodUID, source.ProviderContainerID, source.MountPoint = pod.Name, string(pod.UID), pod.Status.ContainerStatuses[0].ContainerID, "/workspaces"
		writer := &originalDeploymentMaintenance{namespace: pod.Namespace, pods: []q.PodIdentity{{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{pod.Status.ContainerStatuses[0].ContainerID}}}}
		s.longhornKeepers = []*originalLonghornKeeper{{set: s, writer: writer, plan: kube.LonghornAttachmentKeeper{Identity: kube.Identity{Namespace: pod.Namespace}, Node: pod.Spec.NodeName, NodeUID: source.Binding.NodeUID, Source: kube.MountIdentity{Name: source.PVCName, UID: source.PVCUID, PVUID: source.PVUID}}}}
	} else {
		s.longhornRWX = []*originalLonghornRWXHold{{set: s, source: source, clients: clients}}
	}
	s.longhornSources[pod.Namespace+"/"+source.PVCName] = source
	return s, pod, classes, k
}

func TestOriginalCSIPodRequiresConcretePhysicalActorAndNeverMeansHeld(t *testing.T) {
	for _, rwo := range []bool{false, true} {
		s, pod, classes, k := originalCSIPodFixture(t, rwo)
		scope, err := s.prepareCSIPodScope(context.Background(), pod, classes)
		if err != nil || scope == nil || len(s.csiPods) != 1 {
			t.Fatal("actual CSI identity did not bind its prepared actor", rwo, err)
		}
		again, err := s.prepareCSIPodScope(context.Background(), pod, classes)
		if err != nil || again != scope || len(s.csiPods) != 1 {
			t.Fatal("same original scope was duplicated", err)
		}
		if s.recheckCSIPodsHeld(time.Now()) == nil {
			t.Fatal("metadata actor was promoted to physical held")
		}
		client, err := scope.sharedClient()
		if rwo && err == nil || !rwo && (err != nil || client.PodUID != string(pod.UID) || client.ContainerID != pod.Status.ContainerStatuses[0].ContainerID) {
			t.Fatal("wrong CSI runtime projection", err)
		}
		if !rwo {
			s.deployments = []*originalDeploymentMaintenance{{namespace: pod.Namespace, pods: []q.PodIdentity{scope.pod}}}
			if !scope.rwx.clientIsColdWriter(scope.client) {
				t.Fatal("App cold source was classified as a live client")
			}
			if _, err := scope.sharedClient(); err == nil {
				t.Fatal("cold writer borrowed runtime cgroup coverage")
			}
		}
		for _, action := range k.Actions() {
			if action.GetVerb() != "get" && action.GetVerb() != "list" {
				t.Fatal("CSI preparation mutated resources")
			}
		}
	}
}

func TestOriginalCSIPodRejectsIncompleteOrForeignCoverage(t *testing.T) {
	for _, name := range []string{"no-actor", "extra-source", "changed-uid", "sidecar", "subpath", "wrong-process", "foreign-set", "missing-client"} {
		t.Run(name, func(t *testing.T) {
			s, pod, classes, _ := originalCSIPodFixture(t, false)
			switch name {
			case "no-actor":
				s.longhornRWX = nil
			case "extra-source":
				classes = append(classes, classes[0])
			case "changed-uid":
				pod.UID = "replacement"
			case "sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, core.Container{Name: "debug"})
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "subset"
			case "wrong-process":
				pod.Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
			case "foreign-set":
				s.longhornRWX[0].set = &PreparedOriginalWriterSet{}
			case "missing-client":
				s.longhornRWX[0].clients = nil
			}
			if _, err := s.prepareCSIPodScope(context.Background(), pod, classes); err == nil {
				t.Fatal("incomplete physical CSI coverage accepted")
			}
		})
	}
}

func TestOriginalCSIPodRechecksActualClaimPVNamespaceAndNode(t *testing.T) {
	for _, name := range []string{"claim", "pv", "namespace", "node"} {
		t.Run(name, func(t *testing.T) {
			s, pod, classes, k := originalCSIPodFixture(t, false)
			if _, err := s.prepareCSIPodScope(context.Background(), pod, classes); err != nil {
				t.Fatal(err)
			}
			if s.recheckCSIResourcePins(context.Background()) != nil {
				t.Fatal("unchanged CSI resources refused")
			}
			ctx := context.Background()
			switch name {
			case "claim":
				v, _ := k.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, classes[0].ClaimName, metav1.GetOptions{})
				storage := "changed"
				v.Spec.StorageClassName = &storage
				if _, err := k.CoreV1().PersistentVolumeClaims(pod.Namespace).Update(ctx, v, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "pv":
				v, _ := k.CoreV1().PersistentVolumes().Get(ctx, classes[0].PVName, metav1.GetOptions{})
				v.Spec.CSI.VolumeHandle = "pvc-replacement"
				if _, err := k.CoreV1().PersistentVolumes().Update(ctx, v, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "namespace":
				v, _ := k.CoreV1().Namespaces().Get(ctx, pod.Namespace, metav1.GetOptions{})
				v.UID = "replacement"
				if _, err := k.CoreV1().Namespaces().Update(ctx, v, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "node":
				v, _ := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
				v.UID = "replacement"
				if _, err := k.CoreV1().Nodes().Update(ctx, v, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if s.recheckCSIResourcePins(ctx) == nil {
				t.Fatal("CSI resource drift was accepted")
			}
		})
	}
}
