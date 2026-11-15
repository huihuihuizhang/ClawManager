package install

import (
	"context"
	"testing"

	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
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
