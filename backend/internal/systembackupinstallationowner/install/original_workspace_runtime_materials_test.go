package install

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOriginalWorkspaceReadbackPreservesCompleteBusinessUniverse(t *testing.T) {
	before := []domain.SourceInstance{
		{ID: 1, UserID: 7, Generation: 3, Mode: "lite", Type: "openclaw", Backend: "openclaw", Status: "running", Pod: "old", Workspace: "/workspaces/u7/i1"},
		{ID: 2, UserID: 7, Generation: 8, Mode: "pro", Type: "openclaw", Backend: "openclaw", Status: "stopped", Pod: "retained-pro", Namespace: "source", Workspace: "/workspaces/u7/i2"},
		{ID: 3, UserID: 8, Generation: 1, Mode: "lite", Type: "hermes", Backend: "hermes", Status: "error", Workspace: "/workspaces/u8/i3"},
	}
	after := append([]domain.SourceInstance(nil), before...)
	after[0].Generation, after[0].Pod, after[0].Namespace = 4, "new-actual", "source"
	if !originalWorkspaceStatesPreserved(before, after, "source") {
		t.Fatal("actual ordinary running-Lite rebuild must be observable")
	}
	for name, mutate := range map[string]func([]domain.SourceInstance){
		"lost-source":                  func(v []domain.SourceInstance) { v[1].ID = 99 },
		"new-user":                     func(v []domain.SourceInstance) { v[0].UserID++ },
		"different-workspace":          func(v []domain.SourceInstance) { v[0].Workspace = "/workspaces/another" },
		"generation-regression":        func(v []domain.SourceInstance) { v[0].Generation = 2 },
		"running-not-restored":         func(v []domain.SourceInstance) { v[0].Status = "creating" },
		"foreign-namespace":            func(v []domain.SourceInstance) { v[0].Namespace = "foreign" },
		"stopped-pro-restarted":        func(v []domain.SourceInstance) { v[1].Status = "running" },
		"stopped-pro-pod-removed":      func(v []domain.SourceInstance) { v[1].Pod = "" },
		"error-lite-silently-repaired": func(v []domain.SourceInstance) { v[2].Status = "running" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]domain.SourceInstance(nil), after...)
			mutate(changed)
			if originalWorkspaceStatesPreserved(before, changed, "source") {
				t.Fatal("unauthorized source change accepted")
			}
		})
	}
	if originalWorkspaceStatesPreserved(before, after[:2], "source") {
		t.Fatal("incomplete universe accepted")
	}
}

func TestOriginalWorkspaceStateUsesActualSecondarySDKInterface(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/gateways/gw-4-9" || r.Header.Get("X-ClawManager-Control-Token") != "original-test-control-token" {
			t.Errorf("actual SDK request changed: method=%s path=%s", r.Method, r.URL.Path)
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(services.RuntimeAgentGatewayState{UserID: 3, PID: 123, Port: 20001, GatewayID: "gw-4-9", InstanceID: 4, Generation: 9, State: "running"})
	}))
	defer server.Close()
	client := services.NewRuntimeAgentClientWithHTTPClient("original-test-control-token", server.Client())
	state, err := originalWorkspaceGatewayState(context.Background(), client, server.URL, "gw-4-9")
	if err != nil || state == nil || state.PID != 123 || state.InstanceID != 4 || state.Generation != 9 || requests != 1 {
		t.Fatalf("actual SDK read did not complete: err=%v requests=%d", err, requests)
	}
}

type workspaceBaseOnlyClient struct{}

func (workspaceBaseOnlyClient) Health(context.Context, string) error { return nil }
func (workspaceBaseOnlyClient) CreateGateway(context.Context, string, services.RuntimeAgentCreateGatewayRequest) (*services.RuntimeAgentCreateGatewayResponse, error) {
	return nil, nil
}
func (workspaceBaseOnlyClient) DeleteGateway(context.Context, string, string) error { return nil }
func (workspaceBaseOnlyClient) Drain(context.Context, string) error                 { return nil }
func (workspaceBaseOnlyClient) ResyncInstanceSkills(context.Context, string, int, string) error {
	return nil
}

func TestOriginalWorkspaceBaseOnlySDKCannotSupplyObservedState(t *testing.T) {
	state, err := originalWorkspaceGatewayState(context.Background(), workspaceBaseOnlyClient{}, "http://127.0.0.1:19090", "gw-4-9")
	if err == nil || state != nil {
		t.Fatal("a base-only client cannot supply a genuine GatewayState read")
	}
}

func TestOriginalWorkspaceGatewayTargetIsRederivedFromActualSQL(t *testing.T) {
	type fixture struct {
		sources []domain.SourceInstance
		sql     originalSharedRuntimeSQL
		agent   OriginalWorkspaceRuntimeAgent
		gateway services.RuntimeAgentGatewayState
	}
	newFixture := func() fixture {
		return fixture{
			sources: []domain.SourceInstance{{ID: 1, UserID: 2, Generation: 3, Mode: "lite", Status: "running", Workspace: "/workspaces/u2/i1"}},
			sql:     originalSharedRuntimeSQL{Pods: []originalSharedRuntimePodRow{{ID: 4, UID: "pod-uid", Pod: "pod", Namespace: "source", Deployment: "openclaw-runtime", Endpoint: "http://10.2.3.4:19090"}}, Bindings: []originalSharedRuntimeBinding{{InstanceID: 1, RuntimePodID: 4, Port: 20000, Workspace: "/workspaces/u2/i1", Generation: 3, State: "running", Gateway: "gw-1-3", PID: 123}}},
			agent:   OriginalWorkspaceRuntimeAgent{Pod: "pod", PodUID: "pod-uid", Namespace: "source", Deployment: "openclaw-runtime", Endpoint: "http://10.2.3.4:19090"},
			gateway: services.RuntimeAgentGatewayState{InstanceID: 1, UserID: 2, Generation: 3, GatewayID: "gw-1-3", PID: 123, Port: 20000, State: "running"},
		}
	}
	f := newFixture()
	if !originalWorkspaceGatewaySQLTarget(f.sources, f.sql, f.agent, f.gateway) {
		t.Fatal("actual unique running-Lite SQL target rejected")
	}
	for name, change := range map[string]func(*fixture){
		"arbitrary-agent-gateway": func(f *fixture) { f.gateway.InstanceID = 99 },
		"different-user":          func(f *fixture) { f.gateway.UserID = 99 },
		"pro":                     func(f *fixture) { f.sources[0].Mode = "pro" },
		"not-running-source":      func(f *fixture) { f.sources[0].Status = "stopped" },
		"unbound-pod":             func(f *fixture) { f.sql.Bindings[0].RuntimePodID = 99 },
		"unbound-endpoint":        func(f *fixture) { f.agent.Endpoint = "http://10.2.3.5:19090" },
		"different-workspace":     func(f *fixture) { f.sql.Bindings[0].Workspace = "/workspaces/another" },
		"different-pid":           func(f *fixture) { f.sql.Bindings[0].PID = 456 },
		"different-port":          func(f *fixture) { f.gateway.Port = 20001 },
		"different-generation":    func(f *fixture) { f.gateway.Generation = 4 },
		"stopped-gateway":         func(f *fixture) { f.gateway.State = "stopped" },
		"duplicate-binding":       func(f *fixture) { f.sql.Bindings = append(f.sql.Bindings, f.sql.Bindings[0]) },
		"duplicate-runtime-row":   func(f *fixture) { f.sql.Pods = append(f.sql.Pods, f.sql.Pods[0]) },
		"duplicate-source":        func(f *fixture) { f.sources = append(f.sources, f.sources[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			change(&f)
			if originalWorkspaceGatewaySQLTarget(f.sources, f.sql, f.agent, f.gateway) {
				t.Fatal("supplied target escaped actual unique SQL binding")
			}
		})
	}
}

func TestOriginalWorkspacePodStampIncludesSelectionAndTransportFields(t *testing.T) {
	base := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "same-uid", Labels: map[string]string{"clawmanager.io/runtime-type": "openclaw"}}, Status: corev1.PodStatus{PodIP: "10.2.3.4", PodIPs: []corev1.PodIP{{IP: "10.2.3.4"}}}}
	want := originalWorkspacePodStamps(&corev1.PodList{Items: []corev1.Pod{base}})
	for name, change := range map[string]func(*corev1.Pod){"selection-label": func(p *corev1.Pod) { p.Labels["clawmanager.io/runtime-type"] = "hermes" }, "endpoint-ip": func(p *corev1.Pod) { p.Status.PodIP = "10.2.3.5" }, "pod-ips": func(p *corev1.Pod) { p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: "fd00::1"}) }} {
		t.Run(name, func(t *testing.T) {
			changed := base.DeepCopy()
			change(changed)
			if originalWorkspacePodStamps(&corev1.PodList{Items: []corev1.Pod{*changed}}) == want {
				t.Fatal("same UID selection/transport drift omitted")
			}
		})
	}
}

func TestOriginalWorkspaceGatewayIntentCustodyDoesNotDependOnOutputDirectory(t *testing.T) {
	want := originalWorkspaceGatewayCustody("installation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pod-uid", "gw-1-3")
	if want != originalWorkspaceGatewayCustody("installation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pod-uid", "gw-1-3") {
		t.Fatal("custody must be deterministic")
	}
	for _, other := range []string{originalWorkspaceGatewayCustody("another-installation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pod-uid", "gw-1-3"), originalWorkspaceGatewayCustody("installation", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "pod-uid", "gw-1-3"), originalWorkspaceGatewayCustody("installation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "another-pod", "gw-1-3"), originalWorkspaceGatewayCustody("installation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pod-uid", "gw-2-3")} {
		if other == want {
			t.Fatal("original identity component missing from fixed custody")
		}
	}
}
