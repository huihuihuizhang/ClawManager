package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type writerScopePorts struct {
	*fixture
	normal, recovery       bool
	checks, recoveryChecks int
	intents                map[string]d.WriterState
	acks                   map[string]bool
}

func (p *writerScopePorts) Check(ctx context.Context, a d.Authority) error {
	p.checks++
	if ctx.Err() != nil || !p.normal || a != p.in.Authority {
		return &Failure{"fencing_token_lost"}
	}
	return nil
}
func (p *writerScopePorts) CheckRecovery(ctx context.Context, a d.Authority, id string, s d.WriterState) error {
	p.recoveryChecks++
	if ctx.Err() != nil || !p.recovery || a != p.in.Authority || id == "" || s.UID == "" {
		return &Failure{"fencing_token_lost"}
	}
	return nil
}
func (p *writerScopePorts) PauseIntent(ctx context.Context, a d.Authority, id string, s d.WriterState) error {
	if err := p.Check(ctx, a); err != nil {
		return err
	}
	if p.intents == nil {
		p.intents = map[string]d.WriterState{}
	}
	p.intents[id] = s
	p.events = append(p.events, "intent:"+id)
	return nil
}
func (p *writerScopePorts) Paused(ctx context.Context, a d.Authority, id string, ack d.WriterACK) error {
	if err := p.Check(ctx, a); err != nil {
		return err
	}
	original, ok := p.intents[id]
	if !ok || original.UID != ack.UID || original.Generation != ack.Generation || !ack.Stopped {
		return errors.New("ACK without exact durable intent")
	}
	if p.acks == nil {
		p.acks = map[string]bool{}
	}
	p.acks[id] = true
	p.events = append(p.events, "ack:"+id)
	return nil
}
func (p *writerScopePorts) Resumed(ctx context.Context, a d.Authority, id string) error {
	if ctx.Err() != nil || a != p.in.Authority || !p.stopped {
		return errors.New("resume without stop/scope")
	}
	p.events = append(p.events, "resumed:"+id)
	return nil
}
func (p *writerScopePorts) EnsureJob(ctx context.Context, a d.Authority, intent d.JobIntent) (d.JobBinding, error) {
	if err := p.Check(ctx, a); err != nil {
		return d.JobBinding{}, err
	}
	if len(p.acks) != 2 {
		return d.JobBinding{}, errors.New("Job started before all ACKs")
	}
	p.ensures++
	p.events = append(p.events, "ensure")
	return p.binding, nil
}
func writerTestSource() InstanceIdentity {
	return InstanceIdentity{ID: 7, UserID: 4, Generation: 7, Mode: "lite", Type: "workbuddy", Backend: "gateway", Variant: "linux", OS: "linux", Status: "running", Pod: "runtime-pod", Namespace: "source-ns", Workspace: "/workspaces/synthetic"}
}
func writerTestInventory(source InstanceIdentity) SourceInventory {
	return SourceInventory{Database: "synthetic", ServerUUID: "synthetic", Users: []int{1, 4}, Instances: []InstanceIdentity{source}}
}

func writerTestDeps(t *testing.T) (*writerScopePorts, RuntimeWriterDependencies) {
	t.Helper()
	f, _, _ := setup(t)
	ports := &writerScopePorts{fixture: f, normal: true, recovery: true}
	deps := RuntimeWriterDependencies{Ports: ports, PollInterval: time.Millisecond, Participants: []ParticipantSpec{{ID: "platform-db", Original: flow.State{UID: "registered-platform-participant", Generation: 1, Checkpoint: "reviewed-registry-proof-ref"}}}, Callbacks: WriterCallbacks{
		Guard: func(ctx context.Context, a d.Authority, id, point string, s flow.State) error {
			if ctx.Err() != nil || a != ports.in.Authority || id == "" || point == "" {
				return errors.New("wrong public scope")
			}
			return nil
		},
		ClaimRestart:    func(context.Context, d.Authority, string, flow.State) (bool, error) { return true, nil },
		CompleteRestart: func(context.Context, d.Authority, string, flow.State, RestartObservation) error { return nil },
		ConfirmStopped:  func(context.Context, d.Authority, string, flow.State, []quiesce.PodIdentity) error { return nil },
		ConfirmResumed:  func(context.Context, d.Authority, string, flow.State) error { return nil },
	}}
	return ports, deps
}

func TestConcreteGatewayFactoryRestoresOriginalStateWithPublicRecoveryScope(t *testing.T) {
	for _, mode := range []string{"valid", "gate-lost-before-pause", "recovery-denied", "no-restart-reservation", "new-owner", "public-dispatcher"} {
		t.Run(mode, func(t *testing.T) {
			ports, deps := writerTestDeps(t)
			source := writerTestSource()
			if mode == "public-dispatcher" {
				source.Type = "openclaw"
				source.Pod = "source-pod"
				source.Workspace = "/workspace"
			}
			var mu sync.Mutex
			runningOld, runningNew := true, false
			var reads, deletes, creates atomic.Int32
			completed := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.Method {
				case "GET":
					reads.Add(1)
					id := strings.TrimPrefix(r.URL.Path, "/v1/gateways/")
					gen := 7
					running := runningOld
					if id == "gw-7-19" {
						gen = 19
						running = runningNew
					}
					if !running {
						w.WriteHeader(404)
						return
					}
					json.NewEncoder(w).Encode(services.RuntimeAgentGatewayState{GatewayID: id, InstanceID: 7, Generation: gen, State: "running"})
				case "DELETE":
					if !strings.HasSuffix(r.URL.Path, "/gw-7-7") {
						t.Error("deleted reserved recovery generation")
					}
					deletes.Add(1)
					runningOld = false
					w.WriteHeader(204)
				case "POST":
					var req services.RuntimeAgentCreateGatewayRequest
					if json.NewDecoder(r.Body).Decode(&req) != nil || req.Generation != 19 || req.InstanceID != 7 || req.AgentType != source.Type || req.Environment["TOKEN"] != "synthetic-private" {
						t.Error("not the original reserved restart material")
					}
					creates.Add(1)
					runningNew = true
					json.NewEncoder(w).Encode(services.RuntimeAgentCreateGatewayResponse{GatewayID: "gw-7-19", Port: 20007, Status: "running"})
				default:
					w.WriteHeader(405)
				}
			}))
			defer srv.Close()
			deps.Agent = services.NewRuntimeAgentClient("synthetic-control").(services.BackupGatewayAgent)
			deps.Callbacks.LoadGateway = func(_ context.Context, a d.Authority, id, ref string) (services.RuntimeAgentCreateGatewayRequest, error) {
				if a != ports.in.Authority || ref != "encrypted-original-ref" {
					t.Error("restart scope")
				}
				return services.RuntimeAgentCreateGatewayRequest{InstanceID: 7, UserID: 4, Generation: 19, AgentType: source.Type, WorkspacePath: source.Workspace, UID: 200007, GID: 200007, GatewayPort: 20007, Environment: map[string]string{"TOKEN": "synthetic-private"}}, nil
			}
			deps.Callbacks.CompleteRestart = func(_ context.Context, a d.Authority, id string, s flow.State, o RestartObservation) error {
				if a != ports.in.Authority || o.GatewayID != "gw-7-19" || o.PodUID != "runtime-pod-uid" || o.Port != 20007 || s.Generation != 7 {
					t.Error("wrong public completion")
				}
				completed++
				return nil
			}
			if mode == "no-restart-reservation" {
				deps.Callbacks.ClaimRestart = func(context.Context, d.Authority, string, flow.State) (bool, error) { return false, nil }
			}
			if mode == "public-dispatcher" {
				deps.Callbacks.ClaimRestart = func(context.Context, d.Authority, string, flow.State) (bool, error) {
					if !ports.stopped {
						return false, errors.New("attempted restart before collector stop")
					}
					return true, nil
				}
			}
			spec := RuntimeWriterSpec{Source: source, Kind: "gateway", UID: "runtime-pod-uid", Endpoint: srv.URL, RestartRef: "encrypted-original-ref", ResumeGeneration: 19, UIDNumber: 200007, GIDNumber: 200007, Port: 20007}
			builder, err := NewRuntimeWriterBuilder([]RuntimeWriterSpec{spec}, deps)
			if err != nil {
				t.Fatal(err)
			}
			if reads.Load() != 0 || deletes.Load() != 0 || creates.Load() != 0 {
				t.Fatal("constructor performed I/O")
			}
			if mode == "new-owner" {
				ports.in.Authority.ClaimOwner = "takeover"
				ports.in.Authority.ClaimRowVersion++
				ports.in.Authority.MaintenanceOwner = "recovery"
				ports.in.Authority.MaintenanceFencingToken++
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "public-dispatcher" {
				db := sql.OpenDB(sourceConnector{&sourceFixture{}})
				defer db.Close()
				cfg := LinuxProfileConfig{Source: db, Database: "synthetic_source", ServerUUID: "source-uuid", Supported: map[AgentKind]bool{{"openclaw", "lite", "linux", "linux"}: true}, HoldLimit: time.Minute, BuildWriters: builder, BuildParts: func(d.Input, SourceInventory, time.Time) ([]JobPart, error) { return ports.x.Parts, nil }}
				dispatcher, err := NewLinuxDispatcher(ProfileKey{ports.in.ProfileID, ports.in.ProfileRevision}, cfg, Dependencies{Results: ports.fixture, Recovery: ports.fixture, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: fixtureInventory, RecoveryTimeout: time.Second}, ports)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := dispatcher.Prepare(ctx, ports.in)
				if err != nil {
					t.Fatal(err)
				}
				if reads.Load() == 0 || deletes.Load() != 0 || creates.Load() != 0 {
					t.Fatal("Prepare was not read-only")
				}
				discovery, err := DescribePlan(ports.in, plan)
				if err != nil {
					t.Fatal(err)
				}
				ports.x = discovery
				out, err := dispatcher.Capture(ctx, ports.in, plan)
				if err != nil || len(out) != 1 || ports.ensures != 1 || !ports.stopped || creates.Load() != 1 || completed != 1 {
					t.Fatal(out, err, ports.events)
				}
				return
			}
			writers, err := builder(ctx, ports.in, writerTestInventory(source), nil)
			if err != nil || len(writers) != 2 {
				t.Fatal(err)
			}
			if reads.Load() != 0 {
				t.Fatal("Bind rediscovered runtime")
			}
			writer := writers[1]
			original, err := writer.Observe(ctx)
			if err != nil || !original.Running || strings.Contains(original.Checkpoint, "synthetic-private") {
				t.Fatal(original, err)
			}
			if mode == "gate-lost-before-pause" {
				ports.normal = false
				if _, err := writer.Pause(ctx, original); err == nil || deletes.Load() != 0 {
					t.Fatal("pause bypassed public authority")
				}
				return
			}
			ack, err := writer.Pause(ctx, original)
			if err != nil || !ack.Stopped || ack.Generation != 7 || writer.CheckPaused(ctx, original) != nil {
				t.Fatal(ack, err)
			}
			ports.normal = false // capture permission gone; recovery MUST NOT use it
			checksBefore := ports.checks
			if mode == "recovery-denied" {
				ports.recovery = false
			}
			if mode == "no-restart-reservation" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 30*time.Millisecond)
				defer stop()
			}
			err = writer.Resume(ctx, original)
			if mode == "recovery-denied" || mode == "no-restart-reservation" {
				if err == nil || creates.Load() != 0 {
					t.Fatal("restart without public dispatch proof", err, creates.Load())
				}
				return
			}
			if err != nil || creates.Load() != 1 || completed != 1 || ports.recoveryChecks == 0 || ports.checks != checksBefore {
				t.Fatal(err, creates.Load(), completed, ports.checks, checksBefore)
			}
			frozen := []FrozenWriter{{ID: writers[0].ID(), Original: deps.Participants[0].Original}, {ID: writer.ID(), Original: original}}
			if _, err := builder(ctx, ports.in, writerTestInventory(source), frozen); err != nil {
				t.Fatal("recovery bind rediscovered current power state", err)
			}
		})
	}
}

func TestRuntimeWriterFactoryBuildsRealPodAndDeploymentWithoutAPICalls(t *testing.T) {
	for _, kind := range []string{"pod", "deployment"} {
		t.Run(kind, func(t *testing.T) {
			ports, deps := writerTestDeps(t)
			source := writerTestSource()
			source.Mode, source.Backend = "pro", "desktop"
			source.Type = "openclaw"
			client := fake.NewSimpleClientset()
			deps.Client = client
			deps.Callbacks.LoadPod = func(context.Context, d.Authority, string, string) (*corev1.Pod, error) { return &corev1.Pod{}, nil }
			name := source.Pod
			if kind == "deployment" {
				name = "source-deployment"
			}
			spec := RuntimeWriterSpec{Source: source, Kind: kind, UID: "source-object-uid", Name: name, RestartRef: "encrypted-pod-ref"}
			builder, err := NewRuntimeWriterBuilder([]RuntimeWriterSpec{spec}, deps)
			if err != nil {
				t.Fatal(err)
			}
			writers, err := builder(context.Background(), ports.in, writerTestInventory(source), nil)
			if err != nil || len(writers) != 2 || len(client.Actions()) != 0 {
				t.Fatal(err, client.Actions())
			}
			concrete := writers[1].(recoveryAwareWriter).Writer
			switch kind {
			case "pod":
				if _, ok := concrete.(*quiesce.PodWriter); !ok {
					t.Fatal("not real PodWriter")
				}
			case "deployment":
				if _, ok := concrete.(*quiesce.DeploymentWriter); !ok {
					t.Fatal("not real DeploymentWriter")
				}
			}
			// The SAME stopped-proof callback must use recovery scope during Resume.
			ports.normal = false
			ctx := context.WithValue(context.Background(), sourceRecoveryContext{}, true)
			state := flow.State{UID: "source-object-uid", Generation: 7}
			var proof func(context.Context, flow.State, []quiesce.PodIdentity) error
			if w, ok := concrete.(*quiesce.PodWriter); ok {
				proof = w.ConfirmStopped
			} else {
				proof = concrete.(*quiesce.DeploymentWriter).ConfirmStopped
			}
			if err := proof(ctx, state, nil); err != nil || ports.recoveryChecks == 0 {
				t.Fatal("proof incorrectly required capture lease", err)
			}
		})
	}
}

func TestRuntimeWriterFactoryRejectsMissingInputsAndInventoryDrift(t *testing.T) {
	ports, deps := writerTestDeps(t)
	source := writerTestSource()
	source.Status = "stopped"
	spec := RuntimeWriterSpec{Source: source, Kind: "stopped", Stopped: flow.State{UID: "registered-stopped-instance-7", Generation: 7, Checkpoint: "original-stopped-proof"}}
	builder, err := NewRuntimeWriterBuilder([]RuntimeWriterSpec{spec}, deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"owner", "missing-source", "duplicate-source", "extra-source", "bad-frozen"} {
		t.Run(mode, func(t *testing.T) {
			inv := writerTestInventory(source)
			var frozen []FrozenWriter
			switch mode {
			case "owner":
				inv.Instances[0].UserID = 1
			case "missing-source":
				inv.Instances = nil
			case "duplicate-source":
				inv.Instances = append(inv.Instances, source)
			case "extra-source":
				extra := source
				extra.ID = 8
				inv.Instances = append(inv.Instances, extra)
			case "bad-frozen":
				frozen = []FrozenWriter{{ID: "foreign"}}
			}
			if _, err := builder(context.Background(), ports.in, inv, frozen); err == nil {
				t.Fatal("accepted incomplete source mapping")
			}
		})
	}
	for _, mode := range []string{"ports", "guard", "participants", "windows", "running-stopped", "duplicate-definition"} {
		t.Run(mode, func(t *testing.T) {
			copy := deps
			one := spec
			specs := []RuntimeWriterSpec{one}
			switch mode {
			case "ports":
				copy.Ports = nil
			case "guard":
				copy.Callbacks.Guard = nil
			case "participants":
				copy.Participants = nil
			case "windows":
				specs[0].Source.OS = "windows"
			case "running-stopped":
				specs[0].Stopped.Running = true
			case "duplicate-definition":
				specs = append(specs, one)
			}
			if _, err := NewRuntimeWriterBuilder(specs, copy); err == nil {
				t.Fatal("missing input accepted")
			}
		})
	}
	writers, err := builder(context.Background(), ports.in, writerTestInventory(source), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := writers[1].Observe(context.Background())
	if err != nil || s.Running {
		t.Fatal(s, err)
	}
	if _, err := writers[1].Pause(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	ports.normal = false
	if err := writers[1].Resume(context.Background(), s); err != nil {
		t.Fatal("originally stopped instance did not stay stopped", err)
	}
}

func TestRuntimeWriterFactoryRequiresEveryPhysicalDependency(t *testing.T) {
	for _, kind := range []string{"gateway", "pod", "deployment"} {
		missing := []string{"guard", "client-or-agent", "stop-proof", "resume-proof"}
		if kind == "gateway" {
			missing = []string{"guard", "client-or-agent", "load", "claim", "complete", "reservation"}
		} else if kind == "pod" {
			missing = append(missing, "load", "claim", "complete")
		}
		for _, field := range missing {
			t.Run(kind+"/"+field, func(t *testing.T) {
				_, deps := writerTestDeps(t)
				source := writerTestSource()
				deps.Agent = services.NewRuntimeAgentClient("synthetic").(services.BackupGatewayAgent)
				deps.Client = fake.NewSimpleClientset()
				deps.Callbacks.LoadGateway = func(context.Context, d.Authority, string, string) (services.RuntimeAgentCreateGatewayRequest, error) {
					return services.RuntimeAgentCreateGatewayRequest{}, nil
				}
				deps.Callbacks.LoadPod = func(context.Context, d.Authority, string, string) (*corev1.Pod, error) { return &corev1.Pod{}, nil }
				spec := RuntimeWriterSpec{Source: source, Kind: kind, UID: "pod-uid", Name: source.Pod, Endpoint: "http://127.0.0.1", RestartRef: "encrypted", ResumeGeneration: 19, UIDNumber: 200007, GIDNumber: 200007, Port: 20007}
				if kind != "gateway" {
					spec.Source.Mode = "pro"
					spec.Source.Backend = "desktop"
					spec.Source.Type = "openclaw"
				}
				switch field {
				case "guard":
					deps.Callbacks.Guard = nil
				case "client-or-agent":
					if kind == "gateway" {
						deps.Agent = nil
					} else {
						var client *fake.Clientset
						deps.Client = client
					}
				case "load":
					if kind == "gateway" {
						deps.Callbacks.LoadGateway = nil
					} else {
						deps.Callbacks.LoadPod = nil
					}
				case "claim":
					deps.Callbacks.ClaimRestart = nil
				case "complete":
					deps.Callbacks.CompleteRestart = nil
				case "stop-proof":
					deps.Callbacks.ConfirmStopped = nil
				case "resume-proof":
					deps.Callbacks.ConfirmResumed = nil
				case "reservation":
					spec.ResumeGeneration = 7
				}
				if _, err := NewRuntimeWriterBuilder([]RuntimeWriterSpec{spec}, deps); err == nil {
					t.Fatal("physical writer constructed without mandatory dependency")
				}
			})
		}
	}
}
