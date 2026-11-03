package install

import (
	"context"
	"reflect"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// This is a Kubernetes API model, not a genuine original installation/owner
// positive. It exercises the actual private resolver, never mints an auth grant.
func TestOriginalObserverPKIKubernetesSelection(t *testing.T) {
	cases := []struct {
		name       string
		change     func(*OriginalObserverPKIDefinition, *corev1.Node)
		deny, want bool
	}{
		{name: "exact_original_addresses", want: true},
		{name: "wrong_node_uid", change: func(d *OriginalObserverPKIDefinition, _ *corev1.Node) { d.Nodes[0].UID = "other-node-uid" }},
		{name: "wrong_service_account_uid", change: func(d *OriginalObserverPKIDefinition, _ *corev1.Node) { d.ServiceAccountUID = "other-sa-uid" }},
		{name: "arbitrary_dns_alias", change: func(d *OriginalObserverPKIDefinition, _ *corev1.Node) {
			d.Nodes[0].Endpoints["whole"] = "https://alias.example:8444/observation/v1"
		}},
		{name: "wrong_protocol_path", change: func(d *OriginalObserverPKIDefinition, _ *corev1.Node) {
			d.Nodes[0].Endpoints["whole"] = "https://127.0.0.1:8444/gateway-observation/v1"
		}},
		{name: "missing_explicit_port", change: func(d *OriginalObserverPKIDefinition, _ *corev1.Node) {
			d.Nodes[0].Endpoints["whole"] = "https://127.0.0.1/observation/v1"
		}},
		{name: "unready_node", change: func(_ *OriginalObserverPKIDefinition, n *corev1.Node) {
			n.Status.Conditions[0].Status = corev1.ConditionFalse
		}},
		{name: "unknown_native_boot", change: func(_ *OriginalObserverPKIDefinition, n *corev1.Node) { n.Status.NodeInfo.BootID = "" }},
		{name: "rbac_denied", deny: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			definition := OriginalObserverPKIDefinition{Version: OriginalObserverPKIDefinitionVersion, TrustDomain: "backup.example", ServiceAccount: "controller", ServiceAccountUID: "original-sa-uid", ValiditySeconds: 3600, Nodes: []OriginalObserverPKINodeSelection{{Name: "original-node", UID: "original-node-uid", Endpoints: map[string]string{"whole": "https://127.0.0.1:8444/observation/v1"}}}}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "original-node", UID: "original-node-uid"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: "original-boot", MachineID: "original-machine"}, Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "127.0.0.1"}}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
			if c.change != nil {
				c.change(&definition, node)
			}
			k := fake.NewSimpleClientset(node, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "backup", Name: "controller", UID: "original-sa-uid"}})
			k.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: !c.deny, Denied: c.deny}}, nil
			})
			plan := Plan{}
			plan.Target.Namespace, plan.Target.NamespaceUID, plan.Target.InstallationID = "backup", "original-ns-uid", "installation_original"
			s := &authenticatedOperator{installer: &Installer{kube: k, plan: plan}}
			state, err := s.readObserverPKIState(ctx, definition)
			if (err == nil) != c.want {
				t.Fatal("unexpected source selection result")
			}
			if !c.want {
				return
			}
			if len(state.Endpoints) != 1 || state.Endpoints[0].NodeUID != "original-node-uid" || state.Endpoints[0].BootID != "original-boot" || state.Endpoints[0].Endpoint.ServerURI != "spiffe://backup.example/system-backup/installation_original/namespace/original-ns-uid/node-whole/original-node-uid" {
				t.Fatal("original source identity lost")
			}
			fresh := node.DeepCopy()
			fresh.Status.NodeInfo.BootID = "rebooted"
			if _, err = k.CoreV1().Nodes().Update(ctx, fresh, metav1.UpdateOptions{}); err != nil {
				t.Fatal("model update")
			}
			next, err := s.readObserverPKIState(ctx, definition)
			if err != nil || reflect.DeepEqual(state, next) {
				t.Fatal("actual API re-read missed boot drift")
			}
		})
	}
}
