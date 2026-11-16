package install

import (
	"reflect"
	"testing"

	q "clawreef/internal/systembackup/quiesce"
)

func TestOriginalColdNodesCannotDisappearBehindCSICoverage(t *testing.T) {
	// Actual site shape: App cold processes on node1 and a stateless broker
	// on master. Storage actor preparation must not silently drop either.
	pods := map[string][]q.PodIdentity{
		"node1":  {{Name: "app", UID: "app-original", Node: "node1"}},
		"master": {{Name: "broker", UID: "broker-original", Node: "master"}},
	}
	roots := map[string][]string{"node1": {"/actual-transit-volume"}}
	nodes, err := originalColdNativeNodes(pods, roots)
	if err != nil || !reflect.DeepEqual(nodes, []string{"master", "node1"}) {
		t.Fatal("stateless cold master omitted from native process proof", nodes, err)
	}
	// A real root on each cold node preserves both native scopes. An extra
	// root-only node remains visible to the existing stopped-source check.
	roots["master"] = []string{"/actual-master-volume"}
	roots["stopped-only"] = []string{"/actual-stopped-volume"}
	nodes, err = originalColdNativeNodes(pods, roots)
	if err != nil || !reflect.DeepEqual(nodes, []string{"master", "node1", "stopped-only"}) {
		t.Fatal("native scope membership changed", nodes, err)
	}
}

func TestOriginalBrokerPeerRequiresItsOtherNodeAnchor(t *testing.T) {
	// DATA coverage for the actual two-node broker shape; this does not create
	// or validate a native proof. The reader still uses the real API and RPC.
	master := q.PodIdentity{Name: "broker-master", UID: "master-broker", Node: "master"}
	peer := q.PodIdentity{Name: "broker-node1", UID: "node1-broker", Node: "node1"}
	set := &PreparedOriginalWriterSet{}
	scope := &originalWholeNodeScope{set: set, request: q.NodeObservationRequest{Binding: q.ObservationBinding{Node: "node1"}, Pods: []q.PodIdentity{peer}}}
	set.nodes = []*originalWholeNodeScope{scope}
	originals := []q.PodIdentity{master, peer}
	if set.originalRecoveryPeerNodeCovered(originals, "node1") {
		t.Fatal("missing native anchor accepted")
	}
	scope.prepare = &q.VerifiedNodeObservation{}
	if !set.originalRecoveryPeerNodeCovered(originals, "node1") {
		t.Fatal("original other-node peer dropped")
	}
	if set.originalRecoveryPeerNodeCovered(originals, "new-node") || set.originalRecoveryPeerNodeCovered([]q.PodIdentity{master}, "node1") {
		t.Fatal("unanchored migration or foreign writer accepted")
	}
}
