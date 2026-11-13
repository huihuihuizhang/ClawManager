package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clawreef/internal/services"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOriginalSharedMountProjectionPreservesCohortAndCoverage(t *testing.T) {
	cfg, instance, locator, layout, _, objects := originalMountInputFixture(t)
	native := mountAuthorNative(instance, locator)
	native.SharedCapabilities = &services.RuntimeSharedBackupCapabilities{Protocol: services.RuntimeSharedBackupProtocol, Namespace: native.Namespace, PodUID: native.PodUID, Deployment: native.Deployment, AgentEpoch: native.AgentEpoch, AgentPID: 7, AgentStartTicks: "123", GuardPath: "/guard", JournalDirectory: "/journal", Supported: true, DurableReservation: true}
	if cfg.RuntimeSources == nil {
		cfg.RuntimeSources = &RuntimeSourceConfig{}
	}
	cfg.RuntimeSources.SharedRuntimeProtocol = services.RuntimeSharedBackupProtocol
	cfg.RuntimeSources.SharedObserver = &FormalSharedRuntimeObserverConfig{}
	specs, err := originalMountNativeSpecs([]b.InstanceIdentity{instance}, []bootstrapSourceNativeWriter{native})
	if err != nil || len(specs) != 1 || specs[0].Kind != "shared" {
		t.Fatal("shared projection", err)
	}
	for _, fault := range []string{"valid", "cohort", "registered-pod", "legacy-version", "legacy-kind", "protocol", "observer", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			config := cfg
			runtimeConfig := *cfg.RuntimeSources
			config.RuntimeSources = &runtimeConfig
			spec := specs[0]
			switch fault {
			case "cohort":
				spec.SharedCohort = "other"
			case "registered-pod":
				spec.Runtime.RegisteredPodUID = "other"
			case "legacy-version":
				spec.Runtime.Version = "runtime-locator.v2"
			case "legacy-kind":
				spec.Kind = "gateway"
			case "protocol":
				runtimeConfig.SharedRuntimeProtocol = ""
			case "observer":
				runtimeConfig.SharedObserver = nil
			case "unknown":
				runtimeConfig.SharedRuntimeProtocol = "unknown"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			client := fake.NewSimpleClientset(objects...)
			raw, err := BuildOriginalInstanceMountScope(ctx, client, config, []b.InstanceIdentity{instance}, []b.RuntimeWriterSpec{spec}, []InstancePersistentMountLayout{layout})
			if fault == "valid" {
				var scope productionPersistentMountScope
				if err != nil || json.Unmarshal(raw, &scope) != nil || scope.validate() != nil || len(scope.Mounts) != 1 || scope.Mounts[0].PodUID != native.PodUID {
					t.Fatal("shared mount coverage failed", err)
				}
			} else if err == nil {
				t.Fatal("mixed protocol/identity accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("mount read mutated cluster")
				}
			}
		})
	}
	bad := *native.SharedCapabilities
	bad.PodUID = "other"
	native.SharedCapabilities = &bad
	if _, err := originalMountNativeSpecs([]b.InstanceIdentity{instance}, []bootstrapSourceNativeWriter{native}); err == nil {
		t.Fatal("foreign shared identity mapped")
	}
}

func nativeProtocolFixture(t *testing.T, endpoint string, ca []byte) (*bootstrapSourceRegistryReader, *bootstrapSourceSQLFacts, *observedWriterAPI, *productionMetadataClients) {
	t.Helper()
	x, api, clients := poolHistoryReaderFixture(t)
	x.access = poolHistoryTestAccess{ca: ca}
	client := clients.API.(*fake.Clientset)
	owned, replicas := true, int32(1)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: "source", UID: "runtime-uid", ResourceVersion: "1"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "runtime-rs", Namespace: "source", UID: "runtime-rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &owned}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runtime-pod", Namespace: "source", UID: "runtime-pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &owned}}}, Spec: corev1.PodSpec{ServiceAccountName: "default", NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "runtime", Ready: true, ContainerID: "fixture", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	for i, object := range []runtime.Object{dep, rs, pod} {
		if err := client.Tracker().Add(object); err != nil {
			t.Fatal(err)
		}
		projection, err := projectWriterAPIObject([]string{"Deployment", "ReplicaSet", "Pod"}[i], object)
		if err != nil {
			t.Fatal(err)
		}
		api.objects = append(api.objects, projection)
	}
	if err := client.Tracker().Add(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "source", UID: "default-uid"}}); err != nil {
		t.Fatal(err)
	}
	x.config.RuntimeSources.Deployments = []PlatformDeployment{{Namespace: "source", Name: dep.Name, UID: string(dep.UID)}}
	x.association.Source.RuntimeAgent = &install.BootstrapSourceRuntimeAgentV2{Operations: []string{"backup_capabilities_read", "gateway_state_read"}, CA: install.BootstrapSourceFilePin{File: "/fixture/ca"}, Credential: install.BootstrapSourceFilePin{File: "/fixture/token"}}
	facts := &bootstrapSourceSQLFacts{pods: []observedSourceRuntimePod{{ID: 4, UID: string(pod.UID), Name: pod.Name, Namespace: "source", Deployment: dep.Name, Endpoint: endpoint, State: "ready"}}, bindings: []observedSourceRuntimeBinding{{Instance: 1, RuntimePod: 4, Generation: 1, Port: 19001, PID: 77, Gateway: "gw-1-1", Workspace: "/workspace/1", State: "running"}}}
	facts.inventory.Instances = []b.InstanceIdentity{{ID: 1, UserID: 1, Mode: "lite", OS: "linux", Status: "running", Generation: 1, Workspace: "/workspace/1"}}
	return x, facts, api, clients
}

func TestNativeRuntimeProtocolUsesPinnedSelectionWithoutFallback(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"lite-agent.clawmanager.internal"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, tc := range []struct{ name, step string }{
		{"shared", ""}, {"legacy", ""}, {"unknown-protocol", "native_agent_protocol"}, {"missing-observer", "native_agent_protocol"},
		{"shared-404", "native_shared_agent_capabilities"}, {"shared-unauthorized", "native_shared_agent_capabilities"},
		{"wrong-namespace", "native_shared_agent_capabilities"}, {"wrong-pod", "native_shared_agent_capabilities"}, {"wrong-deployment", "native_shared_agent_capabilities"},
		{"not-supported", "native_shared_agent_capabilities"}, {"not-durable", "native_shared_agent_capabilities"}, {"restart-reconciliation", "native_shared_agent_capabilities"},
		{"invalid-epoch", "native_shared_agent_capabilities"}, {"invalid-pid", "native_shared_agent_capabilities"}, {"invalid-path", "native_shared_agent_capabilities"},
		{"unknown-field", "native_shared_agent_capabilities"}, {"legacy-404", "native_agent_capabilities"}, {"legacy-bad-recovery", "native_agent_capabilities"},
		{"gateway-pid-drift", "native_gateway_state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy := strings.HasPrefix(tc.name, "legacy")
			var routes []string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				routes = append(routes, r.URL.Path)
				if r.Method != "GET" || r.Header.Get("X-ClawManager-Control-Token") != "fixture-token" {
					t.Error("unexpected mutation/credential")
					w.WriteHeader(403)
					return
				}
				switch r.URL.Path {
				case "/v1/shared-backup/capabilities":
					if tc.name == "shared-404" {
						w.WriteHeader(404)
						return
					}
					if tc.name == "shared-unauthorized" {
						w.WriteHeader(401)
						return
					}
					caps := map[string]any{"Protocol": services.RuntimeSharedBackupProtocol, "Namespace": "source", "PodUID": "runtime-pod-uid", "Deployment": "runtime", "AgentEpoch": strings.Repeat("1", 32), "AgentStartTicks": "123", "AgentPID": 7, "GuardPath": "/guard", "JournalDirectory": "/journal", "Supported": true, "DurableReservation": true, "AgentRestartReconciliation": false}
					switch tc.name {
					case "wrong-namespace":
						caps["Namespace"] = "other"
					case "wrong-pod":
						caps["PodUID"] = "other"
					case "wrong-deployment":
						caps["Deployment"] = "other"
					case "not-supported":
						caps["Supported"] = false
					case "not-durable":
						caps["DurableReservation"] = false
					case "restart-reconciliation":
						caps["AgentRestartReconciliation"] = true
					case "invalid-epoch":
						caps["AgentEpoch"] = "invalid"
					case "invalid-pid":
						caps["AgentPID"] = 0
					case "invalid-path":
						caps["GuardPath"] = "relative"
					case "unknown-field":
						caps["extra"] = "not accepted"
					}
					json.NewEncoder(w).Encode(caps)
				case "/v1/backup/capabilities":
					if r.URL.Query().Get("gateway_port") != "19001" {
						t.Error("port differs")
					}
					if tc.name == "legacy-404" {
						w.WriteHeader(404)
						return
					}
					caps := services.RuntimeBackupCapabilities{Protocol: services.RuntimeBackupProtocol, Namespace: "source", PodUID: "runtime-pod-uid", AgentEpoch: strings.Repeat("1", 32), Slot: "slot-1", GatewayPort: 19001, Scope: services.RuntimeBackupStopScope, Supported: true, DurableReservation: true, RecoveryScope: services.RuntimeBackupOriginalRecoveryScope, AgentRestartPolicy: services.RuntimeBackupRestartQuarantinePolicy}
					if tc.name == "legacy-bad-recovery" {
						caps.RecoveryScope = ""
					}
					json.NewEncoder(w).Encode(caps)
				case "/v1/gateways/gw-1-1":
					pid := 77
					if tc.name == "gateway-pid-drift" {
						pid++
					}
					json.NewEncoder(w).Encode(services.RuntimeAgentGatewayState{UserID: 1, InstanceID: 1, Generation: 1, GatewayID: "gw-1-1", PID: pid, Port: 19001, State: "running"})
				default:
					t.Error("unexpected endpoint")
					w.WriteHeader(404)
				}
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			x, facts, api, clients := nativeProtocolFixture(t, server.URL, ca)
			if !legacy {
				x.config.RuntimeSources.SharedRuntimeProtocol = services.RuntimeSharedBackupProtocol
				x.config.RuntimeSources.SharedObserver = &FormalSharedRuntimeObserverConfig{}
			}
			if tc.name == "unknown-protocol" {
				x.config.RuntimeSources.SharedRuntimeProtocol = "unknown"
			}
			if tc.name == "missing-observer" {
				x.config.RuntimeSources.SharedObserver = nil
			}
			out, err := x.readNativeWriters(facts, api, clients)
			if tc.step != "" {
				var f *WriterAPIReadFailure
				if !errors.As(err, &f) || f.Step != tc.step {
					t.Fatalf("expected %s, got %#v (%v)", tc.step, f, err)
				}
			} else {
				if err != nil || len(out) != 1 || out[0].AgentEpoch != strings.Repeat("1", 32) {
					t.Fatalf("native read failed: %v", err)
				}
				if (out[0].SharedCapabilities == nil) != legacy {
					t.Fatal("protocol evidence lost")
				}
				specs, err := originalMountNativeSpecs(facts.inventory.Instances, out)
				if err != nil || len(specs) != 1 || !runtimeMountProtocolMatches(x.config, specs[0]) {
					t.Fatal("mount projection lost protocol", err)
				}
				if !legacy && (out[0].RecoveryScope != "" || out[0].AgentRestartPolicy != "" || specs[0].SharedCohort != "runtime-pod-uid") {
					t.Fatal("invented isolated capability")
				}
			}
			for _, route := range routes {
				if legacy && route == "/v1/shared-backup/capabilities" || !legacy && route == "/v1/backup/capabilities" {
					t.Fatal("protocol fallback")
				}
			}
			if tc.step == "native_agent_protocol" && len(routes) != 0 {
				t.Fatal("invalid protocol contacted Agent")
			}
			for _, action := range clients.API.(*fake.Clientset).Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("mutated Kubernetes")
				}
			}
		})
	}
}
