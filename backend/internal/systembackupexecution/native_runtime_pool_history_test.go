package systembackupexecution

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Test-only read mechanics, never an exported installer/authority constructor.
type poolHistoryTestAccess struct{ ca []byte }

func (a poolHistoryTestAccess) Check(ctx context.Context) error { return ctx.Err() }
func (a poolHistoryTestAccess) Read(_ context.Context, p install.BootstrapSourceFilePin) ([]byte, error) {
	if p.File == "/fixture/ca" {
		return a.ca, nil
	}
	return []byte("fixture-token"), nil
}
func (a poolHistoryTestAccess) NativeContext(ctx context.Context) (context.Context, error) {
	return ctx, ctx.Err()
}
func (a poolHistoryTestAccess) Bounds(context.Context) (time.Time, time.Time, error) {
	return time.Time{}, time.Time{}, nil
}
func (a poolHistoryTestAccess) Close() {}

func poolHistoryReaderFixture(t *testing.T) (*bootstrapSourceRegistryReader, *observedWriterAPI, *productionMetadataClients) {
	t.Helper()
	owned, replicas := true, int32(1)
	meta := func(name, uid string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: "source", UID: types.UID(uid), ResourceVersion: "1"}
	}
	dep := &appsv1.Deployment{ObjectMeta: meta("controller", "controller-uid"), Spec: appsv1.DeploymentSpec{Replicas: &replicas, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "controller-sa"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: meta("controller-rs", "rs-uid")}
	rs.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &owned}}
	pod := &corev1.Pod{ObjectMeta: meta("controller-pod", "pod-uid"), Spec: corev1.PodSpec{ServiceAccountName: "controller-sa", NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &owned}}
	objects := []runtime.Object{dep, rs, pod,
		&corev1.ServiceAccount{ObjectMeta: meta("controller-sa", "sa-uid")},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{"kubernetes.io/os": "linux"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "source", UID: "namespace-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}},
	}
	api := &observedWriterAPI{}
	for i, kind := range []string{"Deployment", "ReplicaSet", "Pod"} {
		o, err := projectWriterAPIObject(kind, objects[i])
		if err != nil {
			t.Fatal(err)
		}
		api.objects = append(api.objects, o)
	}
	x := &bootstrapSourceRegistryReader{ctx: context.Background(), physical: context.Background(), access: poolHistoryTestAccess{}, config: DeploymentConfig{Namespace: "source", NamespaceUID: "namespace-uid", RuntimeSources: &RuntimeSourceConfig{}}, materials: productionCaptureMaterials{Discovery: &productionSourceDiscovery{ControllerDeployment: dep.Name, ControllerDeploymentUID: string(dep.UID)}}}
	x.config.Security.NodeUIDs = map[string]string{"node": "node-uid"}
	x.association.Target.ClusterID = "cluster-uid"
	x.association.Source.Controller = install.BootstrapSourceController{Namespace: "source", Pod: pod.Name, PodUID: string(pod.UID), ReplicaSet: rs.Name, ReplicaSetUID: string(rs.UID), Deployment: dep.Name, DeploymentUID: string(dep.UID), ServiceAccount: "controller-sa", ServiceAccountUID: "sa-uid"}
	return x, api, &productionMetadataClients{API: fake.NewSimpleClientset(objects...)}
}

func TestNativeRuntimePoolHistoryPreservesActiveAndCensusChecks(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	server.Close()
	for _, scenario := range []struct{ name, step string }{
		{"unused-unhealthy", ""}, {"unused-draining", ""}, {"unused-pending", ""},
		{"active-unhealthy", "native_instance_binding"}, {"active-draining", "native_instance_binding"},
		{"ready-orphan", "native_runtime_pool_coverage"}, {"unknown-running-binding", "native_binding_coverage"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			x, api, clients := poolHistoryReaderFixture(t)
			x.access = poolHistoryTestAccess{ca: ca}
			facts := &bootstrapSourceSQLFacts{pods: []observedSourceRuntimePod{{ID: 4, UID: "old-pod-uid", Name: "old-pod", Namespace: "source", Deployment: "runtime", Endpoint: "https://127.0.0.1:1", State: "unhealthy"}}}
			if scenario.name == "unused-pending" {
				facts.pods[0].State = "pending"
			}
			if scenario.name == "unused-draining" || scenario.name == "active-draining" {
				facts.pods[0].State = "ready"
				facts.pods[0].Draining = true
			}
			if scenario.name == "ready-orphan" {
				facts.pods[0].State = "ready"
			}
			if scenario.name == "active-unhealthy" || scenario.name == "active-draining" || scenario.name == "unknown-running-binding" {
				facts.bindings = []observedSourceRuntimeBinding{{Instance: 7, RuntimePod: 4, Generation: 1, Port: 19001, PID: 77, Gateway: "gw-7-1", Workspace: "/workspace/7", State: "running"}}
				if scenario.name != "unknown-running-binding" {
					facts.inventory.Instances = []b.InstanceIdentity{{ID: 7, UserID: 1, Mode: "lite", Status: "running", Generation: 1, Workspace: "/workspace/7"}}
					x.association.Source.RuntimeAgent = &install.BootstrapSourceRuntimeAgentV2{Operations: []string{"backup_capabilities_read", "gateway_state_read"}, CA: install.BootstrapSourceFilePin{File: "/fixture/ca"}, Credential: install.BootstrapSourceFilePin{File: "/fixture/token"}}
				}
			}
			before, _ := json.Marshal(facts.pods)
			out, err := x.readNativeWriters(facts, api, clients)
			after, _ := json.Marshal(facts.pods)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("history census was filtered or changed")
			}
			if scenario.step == "" {
				if err != nil || len(out) != 0 {
					t.Fatalf("unused history rejected: %v", err)
				}
			} else {
				var f *WriterAPIReadFailure
				if !errors.As(err, &f) || f.Step != scenario.step {
					t.Fatalf("active/coverage check lost: %v", err)
				}
			}
			for _, action := range clients.API.(*fake.Clientset).Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("history handling mutated cluster")
				}
			}
		})
	}
}

func TestNativeRuntimePoolHistoryStillParticipatesInSQLRecheck(t *testing.T) {
	a := &bootstrapSourceSQLFacts{pods: []observedSourceRuntimePod{{ID: 4, State: "unhealthy"}}}
	b := &bootstrapSourceSQLFacts{pods: append([]observedSourceRuntimePod{}, a.pods...)}
	if !sameBootstrapSourceSQL(a, b) {
		t.Fatal("equal census rejected")
	}
	b.pods[0].State = "ready"
	if sameBootstrapSourceSQL(a, b) {
		t.Fatal("historical row drift was hidden")
	}
}
