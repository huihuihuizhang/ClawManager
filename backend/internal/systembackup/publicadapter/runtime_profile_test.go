package publicadapter

import (
	"context"
	"database/sql"
	"database/sql/driver"
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
	d "clawreef/internal/systembackupdispatch"
)

type mixedProfileConnector struct{ sourceConnector }

func (c mixedProfileConnector) Connect(context.Context) (driver.Conn, error) {
	return &mixedProfileConn{&sourceConn{c.f}}, nil
}

type mixedProfileConn struct{ *sourceConn }

func (c *mixedProfileConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.sourceConn.QueryContext(ctx, q, args)
	if err == nil && strings.HasPrefix(q, "SELECT id,user_id,instance_mode,type,runtime_type,") {
		r := rows.(*sourceRows)
		stopped := append([]driver.Value(nil), r.values[0]...)
		stopped[0], stopped[1], stopped[7], stopped[8], stopped[9], stopped[11] = int64(8), int64(1), "stopped", int64(2), "", "/workspace/stopped"
		r.values = append(r.values, stopped)
	}
	return rows, err
}

type runtimeProfilePorts struct {
	*writerScopePorts
	pausedChecks map[string]bool
}

func (p *runtimeProfilePorts) BeforeResume(ctx context.Context, a d.Authority) error {
	if ctx.Err() != nil || a != p.in.Authority || !p.stopped {
		return errors.New("original collectors are not durably stopped")
	}
	p.events = append(p.events, "shared-resume-barrier")
	return nil
}

func (p *runtimeProfilePorts) EnsureJob(ctx context.Context, a d.Authority, intent d.JobIntent) (d.JobBinding, error) {
	if err := p.Check(ctx, a); err != nil {
		return d.JobBinding{}, err
	}
	if len(p.acks) != 3 || len(p.pausedChecks) != 3 {
		return d.JobBinding{}, errors.New("dispatch before complete mixed-runtime barrier")
	}
	p.ensures++
	p.events = append(p.events, "ensure")
	return p.binding, nil
}

// This runs the production SQL discovery/profile/dispatcher/writer chain with
// a SELECT-only driver and real HTTP loopback. Agent, SQL state, grants, Jobs
// and seals remain isolated models, not a physical-runtime acceptance result.
func TestRuntimeProfileMixedInventoryCallsConcreteBuildersAndPreservesStoppedInstance(t *testing.T) {
	base, deps := writerTestDeps(t)
	base.in.Backup = moduleTestInput(t).in.Backup
	ports := &runtimeProfilePorts{writerScopePorts: base, pausedChecks: map[string]bool{}}
	deps.Ports = ports
	participants := deps.Participants
	deps.Participants = nil
	var mu sync.Mutex
	oldRunning, newRunning := true, false
	var reads, nativeStops, nativeResumes atomic.Int32
	completed := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			reads.Add(1)
			id := strings.TrimPrefix(r.URL.Path, "/v1/gateways/")
			running, generation := oldRunning, 7
			if id == "gw-7-19" {
				running, generation = newRunning, 19
			}
			if id != "gw-7-7" && id != "gw-7-19" {
				t.Errorf("queried stopped or foreign gateway %s", id)
			}
			if !running {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(services.RuntimeAgentGatewayState{GatewayID: id, InstanceID: 7, Generation: generation, State: "running"})
		case "DELETE":
			t.Error("native backup must not issue legacy DELETE")
			w.WriteHeader(405)
		case "POST":
			t.Error("native recovery must use original GatewayControl callback")
			w.WriteHeader(405)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	deps.Agent = services.NewRuntimeAgentClientWithHTTPClient("synthetic-control", server.Client()).(services.BackupGatewayAgent)
	// Native operation/positive receipt model. Actual D SQL receipt persistence
	// and Agent process/mount proofs are NOT simulated by GET/404 here.
	deps.Callbacks.GatewayControl = func(_ context.Context, a d.Authority, id, point string, s flow.State) (bool, error) {
		if a != ports.in.Authority || id != "gateway/runtime-pod-uid/7" || s.Generation != 7 {
			return false, errors.New("wrong native operation scope")
		}
		mu.Lock()
		defer mu.Unlock()
		switch point {
		case "before-stop":
			if oldRunning {
				nativeStops.Add(1)
				oldRunning = false
			}
			return true, nil
		case "check-stopped", "recovery-check-stopped", "recovery-stop-old":
			return !oldRunning && !newRunning, nil
		case "restart-dispatched":
			if !ports.stopped {
				return false, errors.New("restart before collector stop")
			}
			nativeResumes.Add(1)
			newRunning = true
			return true, nil
		case "check-resumed":
			return newRunning, nil
		case "release-restart":
			return completed > 0, nil
		}
		return false, errors.New("unknown native operation")
	}
	guard := deps.Callbacks.Guard
	deps.Callbacks.Guard = func(ctx context.Context, a d.Authority, id, point string, s flow.State) error {
		if point == "check-stopped" {
			ports.pausedChecks[id] = true
		}
		return guard(ctx, a, id, point, s)
	}
	deps.Callbacks.LoadGateway = func(context.Context, d.Authority, string, string) (services.RuntimeAgentCreateGatewayRequest, error) {
		return services.RuntimeAgentCreateGatewayRequest{InstanceID: 7, UserID: 4, Generation: 19, AgentType: "openclaw", WorkspacePath: "/workspace", UID: 50001, GID: 50001, GatewayPort: 20007, Environment: map[string]string{"TOKEN": "isolated-private"}}, nil
	}
	deps.Callbacks.ClaimRestart = func(context.Context, d.Authority, string, flow.State) (bool, error) {
		if !ports.stopped {
			return false, errors.New("resume before collector stopped")
		}
		return true, nil
	}
	deps.Callbacks.CompleteRestart = func(context.Context, d.Authority, string, flow.State, RestartObservation) error {
		completed++
		return nil
	}
	registrations := []CaptureModuleRegistration{moduleTestRegistration(t, ports.fixture, "instances", "B", "users")}
	modules, err := NewCaptureModules(registrations, moduleTestContext)
	if err != nil {
		t.Fatal(err)
	}
	sf := &sourceFixture{}
	db := sql.OpenDB(mixedProfileConnector{sourceConnector{sf}})
	defer db.Close()
	var sourceTx *sql.Tx
	authentications := 0
	source := LinuxProfileConfig{Source: db, Database: "synthetic_source", ServerUUID: "source-uuid", Supported: map[AgentKind]bool{{"openclaw", "lite", "linux", "linux"}: true}, HoldLimit: 30 * time.Second, VerifySource: func(ctx context.Context, tx *sql.Tx) error {
		authentications++
		// Each discovery/check uses its own read-only snapshot. Both authority
		// checks must bind THAT transaction, not the already-closed first one.
		if authentications%2 == 1 {
			sourceTx = tx
			if sf.queries != (authentications/2)*3 {
				return errors.New("wrong source authentication start")
			}
		} else if sourceTx != tx || sf.queries != (authentications/2)*3 {
			return errors.New("source authentication changed transaction or boundary")
		}
		return ctx.Err()
	}}
	resolves, binds := 0, 0
	resolve := func(_ context.Context, in d.Input, inv SourceInventory, frozen []FrozenWriter) (RuntimeWriterMapping, error) {
		resolves++
		if len(inv.Instances) != 2 || in.Authority != ports.in.Authority {
			return RuntimeWriterMapping{}, d.ErrNotReady
		}
		if frozen != nil {
			binds++
			if len(frozen) != 3 {
				t.Error("lost frozen participant/runtime states")
			}
		}
		mapping := RuntimeWriterMapping{Participants: participants, Specs: []RuntimeWriterSpec{
			{Source: inv.Instances[0], Kind: "gateway", UID: "runtime-pod-uid", Endpoint: server.URL, RestartRef: "original-encrypted-ref", ResumeGeneration: 19, UIDNumber: 50001, GIDNumber: 50001, Port: 20007},
			{Source: inv.Instances[1], Kind: "stopped", Stopped: flow.State{UID: "stopped-instance-8", Generation: 2, Checkpoint: "original-stopped-proof"}},
		}}
		mapping.Specs[0].Runtime = RuntimeLocator{Version: "runtime-locator.v2", Namespace: inv.Instances[0].Namespace, Pod: inv.Instances[0].Pod, RegisteredPodUID: "runtime-pod-uid", Deployment: "runtime", RuntimePodID: 6, GatewayPID: 123, AgentEpoch: strings.Repeat("a", 32)}
		mapping.Specs[0].Backup = RuntimeGatewayBackup{Protocol: services.RuntimeBackupProtocol, OperationID: strings.Repeat("b", 32), RestartSHA256: strings.Repeat("c", 64)}
		// Owner callbacks receive detached observations, not the runner's slices.
		inv.Users[0] = 99
		in.Backup.RequestedParts[0] = "forged"
		return mapping, nil
	}
	cfg, err := NewRuntimeLinuxProfileConfig(source, resolve, deps, modules)
	if err != nil {
		t.Fatal(err)
	}
	if sf.queries != 0 || reads.Load() != 0 || resolves != 0 {
		t.Fatal("assembly did IO")
	}
	dispatcher, err := NewLinuxDispatcher(ProfileKey{ports.in.ProfileID, ports.in.ProfileRevision}, cfg, Dependencies{Results: ports, Recovery: ports, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: fixtureInventory, RecoveryTimeout: time.Second}, ports)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := d.BindTaskRunner(dispatcher.Runner, PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Runner = bound
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plan, err := dispatcher.Prepare(ctx, ports.in)
	if err != nil {
		t.Fatal("Prepare", err)
	}
	if authentications != 2 || sf.queries != 3 || sf.writes != 0 || nativeStops.Load() != 0 || nativeResumes.Load() != 0 || ports.ensures != 0 {
		t.Fatal("prepare was not read-only")
	}
	inner, err := d.UnwrapTaskPlan(ports.in, plan, PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	x, err := DescribePlan(ports.in, inner)
	if err != nil || len(x.Writers) != 3 || strings.Contains(string(plan.CanonicalJSON), "isolated-private") {
		t.Fatal("invalid or secret-bearing frozen plan", err)
	}
	ports.x = x
	ports.binding.Name, ports.binding.Namespace, ports.binding.JobUnitKey = x.Parts[0].Intent.Name, x.Parts[0].Intent.Namespace, x.Parts[0].Intent.JobUnitKey
	results, err := dispatcher.Capture(ctx, ports.in, plan)
	if err != nil || len(results) != 1 {
		t.Fatal("Capture", err, ports.events)
	}
	if resolves != 2 || binds != 1 || sf.writes != 0 || nativeStops.Load() != 1 || nativeResumes.Load() != 1 || completed != 1 || !ports.stopped || ports.ensures != 1 {
		t.Fatal("wrong side-effect count", resolves, binds, nativeStops.Load(), nativeResumes.Load(), completed, ports.events)
	}
	if !contains(ports.events, "shared-resume-barrier") {
		t.Fatal("unified collector barrier was not called before source resume")
	}
	if ports.in.Backup.RequestedParts[0] != "workspace" {
		t.Fatal("resolver mutated original request")
	}
}

func TestRuntimeProfileMissingOwnersAndOverrideHooksFailClosed(t *testing.T) {
	for _, which := range []string{"mapping", "ports", "guard", "participants", "module", "empty-module", "source", "writer-hook", "parts-hook"} {
		t.Run(which, func(t *testing.T) {
			ports, deps := writerTestDeps(t)
			deps.Participants = nil
			profile := linuxFixture(t, ports.fixture, &sourceFixture{})
			source := profile.cfg
			source.BuildParts, source.BuildWriters = nil, nil
			modules, _ := NewCaptureModules([]CaptureModuleRegistration{moduleTestRegistration(t, ports.fixture, "instances", "B", "users")}, moduleTestContext)
			resolve := RuntimeMappingResolver(func(context.Context, d.Input, SourceInventory, []FrozenWriter) (RuntimeWriterMapping, error) {
				return RuntimeWriterMapping{}, d.ErrNotReady
			})
			switch which {
			case "mapping":
				resolve = nil
			case "ports":
				deps.Ports = nil
			case "guard":
				deps.Callbacks.Guard = nil
			case "participants":
				deps.Participants = []ParticipantSpec{{}}
			case "module":
				modules = nil
			case "empty-module":
				modules = &CaptureModules{}
			case "source":
				source.Source = nil
			case "writer-hook":
				source.BuildWriters = profile.cfg.BuildWriters
			case "parts-hook":
				source.BuildParts = profile.cfg.BuildParts
			}
			if _, err := NewRuntimeLinuxProfileConfig(source, resolve, deps, modules); err == nil {
				t.Fatal("incomplete/overridden production assembly accepted")
			}
		})
	}
}

func TestRuntimeModuleSourceAuthenticationFailsBeforeConstruction(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		f, _, _ := setup(t)
		sf := &sourceFixture{}
		source := linuxFixture(t, f, sf).cfg
		source.BuildParts, source.BuildWriters = nil, nil
		var original *sql.Tx
		checks, resolves := 0, 0
		source.VerifySource = func(_ context.Context, tx *sql.Tx) error {
			checks++
			if original == nil {
				original = tx
			} else if original != tx {
				return errors.New("changed transaction")
			}
			if checks == failAt {
				return errors.New("revoked source")
			}
			return nil
		}
		_, deps := writerTestDeps(t)
		deps.Participants = nil
		m, _ := NewCaptureModules([]CaptureModuleRegistration{moduleTestRegistration(t, f, "instances", "B", "users")}, moduleTestContext)
		cfg, e := NewRuntimeLinuxProfileConfig(source, func(context.Context, d.Input, SourceInventory, []FrozenWriter) (RuntimeWriterMapping, error) {
			resolves++
			return RuntimeWriterMapping{}, d.ErrNotReady
		}, deps, m)
		if e != nil {
			t.Fatal(e)
		}
		profile, e := NewLinuxProfile(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = profile.Discover(context.Background(), f.in); e == nil || checks != failAt || resolves != 0 || sf.writes != 0 || sf.rollbacks != 1 {
			t.Fatal("revoked source reached downstream assembly", e)
		}
	}
}

func TestRuntimeProfileBindUsesFrozenSourceAndMissingMappingCannotDispatch(t *testing.T) {
	f := moduleTestInput(t)
	ports, deps := writerTestDeps(t)
	deps.Participants = nil
	sf := &sourceFixture{}
	base := linuxFixture(t, f, sf).cfg
	base.BuildWriters, base.BuildParts = nil, nil
	m, _ := NewCaptureModules([]CaptureModuleRegistration{moduleTestRegistration(t, f, "instances", "B", "users")}, moduleTestContext)
	calls := 0
	cfg, err := NewRuntimeLinuxProfileConfig(base, func(_ context.Context, _ d.Input, _ SourceInventory, frozen []FrozenWriter) (RuntimeWriterMapping, error) {
		calls++
		if frozen == nil || frozen[0].ID != "original" {
			t.Error("original frozen states missing")
		}
		frozen[0].ID = "mutated"
		return RuntimeWriterMapping{}, d.ErrNotReady
	}, deps, m)
	if err != nil {
		t.Fatal(err)
	}
	original := []FrozenWriter{{ID: "original"}}
	if _, err := cfg.BuildWriters(context.Background(), f.in, SourceInventory{}, original); err == nil || calls != 1 || original[0].ID != "original" || sf.queries != 0 || ports.ensures != 0 {
		t.Fatal("missing mapping caused IO or mutated original", err)
	}
	// Preflight must not call either runtime mapping or module/capture context.
	pre := cloneInput(f.in)
	pre.Authority.TaskType = "preflight"
	parts, err := cfg.BuildParts(pre, SourceInventory{}, time.Now())
	if err != nil || len(parts) != 1 || parts[0].Part != "source_inventory" || calls != 1 {
		t.Fatal("preflight used execution owners", err)
	}
}

func TestRuntimeProfileRetainsPlatformWritersAndChecksCombinedFrozenCoverage(t *testing.T) {
	for _, which := range []string{"valid", "missing-platform", "nil-platform", "duplicate-platform", "missing-instance", "missing-participant"} {
		t.Run(which, func(t *testing.T) {
			f := moduleTestInput(t)
			ports, deps := writerTestDeps(t)
			participants := deps.Participants
			deps.Participants = nil
			sf := &sourceFixture{}
			source := linuxFixture(t, f, sf).cfg
			source.BuildParts, source.BuildWriters = nil, nil
			m, _ := NewCaptureModules([]CaptureModuleRegistration{moduleTestRegistration(t, f, "instances", "B", "users")}, moduleTestContext)
			instance := writerTestSource()
			instance.Status = "stopped"
			inv := writerTestInventory(instance)
			mapping := RuntimeWriterMapping{Specs: []RuntimeWriterSpec{{Source: instance, Kind: "stopped", Stopped: flow.State{UID: "stopped-original", Generation: 7, Checkpoint: "stopped-proof"}}}, Participants: participants, Platform: []flow.Writer{fixtureWriter{f}}}
			switch which {
			case "missing-platform":
				mapping.Platform = nil
			case "nil-platform":
				mapping.Platform = []flow.Writer{nil}
			case "duplicate-platform":
				mapping.Platform = append(mapping.Platform, fixtureWriter{f})
			case "missing-instance":
				mapping.Specs = nil
			case "missing-participant":
				mapping.Participants = nil
			}
			cfg, err := NewRuntimeLinuxProfileConfig(source, func(context.Context, d.Input, SourceInventory, []FrozenWriter) (RuntimeWriterMapping, error) {
				return mapping, nil
			}, deps, m)
			if err != nil {
				t.Fatal(err)
			}
			frozen := []FrozenWriter{{ID: participants[0].ID}, {ID: "stopped/7"}, {ID: "writer-1"}}
			writers, err := cfg.BuildWriters(context.Background(), f.in, inv, frozen)
			if which == "valid" {
				if err != nil || len(writers) != 3 || writers[2].ID() != "writer-1" {
					t.Fatal("lost original platform writer", err)
				}
			} else if err == nil {
				t.Fatal("incomplete/aliased writer set accepted")
			}
			if sf.queries != 0 || ports.ensures != 0 || len(f.events) != 0 {
				t.Fatal("Bind performed IO")
			}
		})
	}
}
