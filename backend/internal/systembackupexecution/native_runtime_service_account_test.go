package systembackupexecution

import (
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestNativeRuntimeServiceAccountAdmissionAndIdentity(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	server.Close()
	for _, tc := range []struct{ name, template, pod, change, step string }{
		{"omitted-default", "", "default", "", "native_instance_approved_node"},
		{"explicit-default", "default", "default", "", "native_instance_approved_node"},
		{"explicit-custom", "runtime-sa", "runtime-sa", "", "native_instance_approved_node"},
		{"omitted-custom", "", "runtime-sa", "", "native_instance_deployment"},
		{"explicit-mismatch", "runtime-sa", "default", "", "native_instance_deployment"},
		{"empty-pod-account", "", "", "", "native_instance_pod"},
		{"deployment-replaced", "", "default", "uid", "native_instance_deployment"},
		{"deployment-deleting", "", "default", "deleting", "native_instance_deployment"},
		{"census-drift", "", "default", "spec", "native_instance_deployment"},
		{"account-missing", "", "default", "missing-account", "native_instance_account"},
		{"account-deleting", "", "default", "deleting-account", "native_instance_account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, api, clients := poolHistoryReaderFixture(t)
			x.access = poolHistoryTestAccess{ca: ca}
			client := clients.API.(*fake.Clientset)
			owned, replicas := true, int32(1)
			meta := func(name, uid string) metav1.ObjectMeta {
				return metav1.ObjectMeta{Name: name, Namespace: "source", UID: types.UID(uid), ResourceVersion: "1"}
			}
			dep := &appsv1.Deployment{ObjectMeta: meta("runtime", "runtime-uid"), Spec: appsv1.DeploymentSpec{Replicas: &replicas, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: tc.template}}}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1}}
			rs := &appsv1.ReplicaSet{ObjectMeta: meta("runtime-rs", "runtime-rs-uid")}
			rs.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &owned}}
			pod := &corev1.Pod{ObjectMeta: meta("runtime-pod", "runtime-pod-uid"), Spec: corev1.PodSpec{ServiceAccountName: tc.pod, NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "runtime", Ready: true, ContainerID: "fixture", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &owned}}
			objects := []runtime.Object{dep, rs, pod}
			for i, kind := range []string{"Deployment", "ReplicaSet", "Pod"} {
				if err := client.Tracker().Add(objects[i]); err != nil {
					t.Fatal(err)
				}
				projection, err := projectWriterAPIObject(kind, objects[i])
				if err != nil {
					t.Fatal(err)
				}
				api.objects = append(api.objects, projection)
			}
			if tc.pod != "" && tc.change != "missing-account" {
				sa := &corev1.ServiceAccount{ObjectMeta: meta(tc.pod, "runtime-account-uid")}
				if tc.change == "deleting-account" {
					now := metav1.Now()
					sa.DeletionTimestamp = &now
				}
				if err := client.Tracker().Add(sa); err != nil {
					t.Fatal(err)
				}
			}
			client.PrependReactor("get", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
				if action.(ktesting.GetAction).GetName() != dep.Name {
					return false, nil, nil
				}
				got := dep.DeepCopy()
				switch tc.change {
				case "uid":
					got.UID = "replacement"
				case "deleting":
					now := metav1.Now()
					got.DeletionTimestamp = &now
				case "spec":
					got.Spec.Template.Spec.Hostname = "changed"
				}
				return true, got, nil
			})
			// Include the live root in the graph, but deliberately omit its runtime
			// approval so successful account checks stop before any agent network call.
			x.config.Writers = []PlatformDeployment{{Namespace: "source", Name: dep.Name, UID: string(dep.UID)}}
			x.association.Source.RuntimeAgent = &install.BootstrapSourceRuntimeAgentV2{Operations: []string{"backup_capabilities_read", "gateway_state_read"}, CA: install.BootstrapSourceFilePin{File: "/fixture/ca"}, Credential: install.BootstrapSourceFilePin{File: "/fixture/token"}}
			facts := &bootstrapSourceSQLFacts{
				pods:     []observedSourceRuntimePod{{ID: 4, UID: string(pod.UID), Name: pod.Name, Namespace: "source", Deployment: dep.Name, Endpoint: "https://127.0.0.1:1", State: "ready"}},
				bindings: []observedSourceRuntimeBinding{{Instance: 1, RuntimePod: 4, Generation: 1, Port: 19001, PID: 77, Gateway: "gw-1-1", Workspace: "/workspace/1", State: "running"}},
			}
			facts.inventory.Instances = []b.InstanceIdentity{{ID: 1, UserID: 1, Mode: "lite", Status: "running", Generation: 1, Workspace: "/workspace/1"}}
			_, err := x.readNativeWriters(facts, api, clients)
			var failure *WriterAPIReadFailure
			if !errors.As(err, &failure) || failure.Step != tc.step || failure.InstanceID != 1 {
				t.Fatalf("wanted %s for instance 1, got %#v (%v)", tc.step, failure, err)
			}
			if dep.Spec.Template.Spec.ServiceAccountName != tc.template {
				t.Fatal("original template was rewritten")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("native read mutated Kubernetes")
				}
			}
		})
	}
}
