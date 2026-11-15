package install

import (
	"context"
	"testing"

	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOriginalLonghornRWXTemplatesDoNotProveClientDrain(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		material, objects := originalRWXCensusFixture()
		for _, obj := range objects {
			if pod, ok := obj.(*core.Pod); ok {
				pod.Spec.Containers[0].VolumeMounts[0].ReadOnly = readOnly
			}
		}
		k := fake.NewSimpleClientset(objects...)
		clients, err := originalLonghornRWXClients(context.Background(), k, material)
		if err != nil {
			t.Fatal(err)
		}
		set := &PreparedOriginalWriterSet{owner: &OriginalWriterMaintenance{operator: &authenticatedOperator{installer: &Installer{kube: k}}}, longhornMaterials: &material, longhornRWXClients: clients}
		hold := &originalLonghornRWXHold{set: set, source: material.Sources[0], clients: clients}
		if hold.checkDrainedClients(context.Background()) == nil {
			t.Fatal("unfrozen client or unrecorded read-only attachment was accepted as drained")
		}
		for _, action := range k.Actions() {
			if action.GetVerb() != "get" && action.GetVerb() != "list" {
				t.Fatal("drain rejection mutated the source")
			}
		}
	}
}

func TestOriginalLonghornRWXRetainsStoppedAppClientsInDrainCohort(t *testing.T) {
	material, objects := originalRWXCensusFixture()
	for _, name := range []string{"app-1", "app-2"} {
		pod := objects[4].(*core.Pod).DeepCopy()
		pod.Name, pod.UID = name, types.UID("uid-"+name)
		pod.Status.ContainerStatuses[0].ContainerID = "containerd://" + name
		objects = append(objects, pod)
	}
	k := fake.NewSimpleClientset(objects...)
	before, err := originalLonghornRWXClients(context.Background(), k, material)
	if err != nil || len(before) != 5 {
		t.Fatal("App replicas were omitted from the original mount set", err)
	}
	exited := map[string]bool{}
	for _, client := range before {
		if client.PodName == "app-1" || client.PodName == "app-2" {
			exited[originalObjectSHA(client)] = true
			if err := k.CoreV1().Pods("app").Delete(context.Background(), client.PodName, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	after, err := originalLonghornRWXClients(context.Background(), k, material)
	if err != nil || len(after) != 3 || !originalLonghornRWXLiveCohortMatches(before, after, exited) {
		t.Fatal("proved stopped App clients could not retain their original drain entries", err)
	}
	if originalLonghornRWXLiveCohortMatches(before, after, nil) {
		t.Fatal("API disappearance alone silently removed a client")
	}
	replacement := append([]originalLonghornRWXClient(nil), after...)
	replacement[0].PodUID = "replacement"
	if originalLonghornRWXLiveCohortMatches(before, replacement, exited) {
		t.Fatal("same-name replacement entered the original drain")
	}
	if len(before) != 5 {
		t.Fatal("live projection mutated the complete sync cohort")
	}
}

func TestOriginalLonghornRWXPreStopRegistrationRetainsOriginalMount(t *testing.T) {
	material, objects := originalRWXCensusFixture()
	clients, err := originalLonghornRWXClients(context.Background(), fake.NewSimpleClientset(objects...), material)
	if err != nil {
		t.Fatal(err)
	}
	provider := q.LonghornExt4Request{Action: "register", Attempt: 1, Binding: material.Sources[0].Binding,
		Claim: q.LonghornExt4Claim{OriginalOperationID: "original", EntryRowVersion: 7}}
	r := originalLonghornRWXClientRegistration(provider, clients[0])
	if r.Action != "register-client" || r.ClientPodUID != clients[0].PodUID || r.ClientContainerID != clients[0].ContainerID || r.SourceIdentity != clients[0].Template.Identity || r.Claim != provider.Claim || r.Binding.NodeUID != clients[0].Template.Binding.NodeUID || r.DrainBoundarySHA256 != "" || len(r.RegistrationBoundarySHA256) != 64 {
		t.Fatal("pre-stop registration changed the original source or pretended it was drained")
	}
}

func TestOriginalLonghornRWXUnknownSyncCannotBeReissued(t *testing.T) {
	// No owner/client is attached: a repeated uncertain sync must refuse before
	// authentication, fresh census, or any new native request can be dispatched.
	h := &originalLonghornRWXHold{registered: true, syncSent: true, registration: &q.LonghornExt4Request{}}
	if h.syncClients(context.Background()) == nil {
		t.Fatal("unknown sync was replayed")
	}
}

func TestOriginalLonghornRWXFrozenAgentDoesNotCoverOtherPodContainers(t *testing.T) {
	agent := q.PodIdentity{Name: "runtime", UID: "original-pod", Containers: []string{"containerd://agent"}}
	client := originalLonghornRWXClient{PodName: agent.Name, PodUID: agent.UID, ContainerID: agent.Containers[0]}
	if !originalLonghornRWXProcessCovered(client, agent) {
		t.Fatal("original frozen process was not covered")
	}
	client.ContainerID = "containerd://debug"
	if originalLonghornRWXProcessCovered(client, agent) {
		t.Fatal("a different container cgroup in the same Pod was treated as frozen")
	}
	client.ContainerID, client.PodUID = agent.Containers[0], "replacement-pod"
	if originalLonghornRWXProcessCovered(client, agent) {
		t.Fatal("a replacement Pod inherited the original freeze")
	}
}
