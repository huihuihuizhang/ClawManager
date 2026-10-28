package profile

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/recovery"
)

type ownerFixture struct {
	execution *SixDomainExecution
	binds     int
}

func (*ownerFixture) Probe(context.Context, recovery.Reference) error { return nil }
func (*ownerFixture) Discover(context.Context, control.Task) (json.RawMessage, error) {
	return json.RawMessage(`{"checkpoint":"fixed"}`), nil
}
func (o *ownerFixture) Bind(_ control.Task, raw json.RawMessage) (*SixDomainExecution, error) {
	if string(raw) != `{"checkpoint":"fixed"}` {
		return nil, ErrProfile
	}
	o.binds++
	return o.execution, nil
}
func (*ownerFixture) Contribute(context.Context, control.Task, artifact.Bundle, []flow.Part) (control.SixDomainPlan, error) {
	return control.SixDomainPlan{}, ErrProfile
}
func (*ownerFixture) Publisher(context.Context, control.Task) (recovery.Publisher, error) {
	return recovery.Publisher{}, ErrProfile
}

type ownerCollector string

func (c ownerCollector) ID() string                  { return string(c) }
func (ownerCollector) Prepare(context.Context) error { return nil }
func (c ownerCollector) Capture(context.Context) (flow.Part, error) {
	return flow.Part{ID: c.ID(), Checkpoint: "fixed", SealedRef: "sealed"}, nil
}
func (ownerCollector) Stop(context.Context) error { return nil }

type ownerWriter string

func (w ownerWriter) ID() string                                        { return string(w) }
func (ownerWriter) Observe(context.Context) (flow.State, error)         { return flow.State{}, nil }
func (ownerWriter) Pause(context.Context, flow.State) (flow.ACK, error) { return flow.ACK{}, nil }
func (ownerWriter) CheckPaused(context.Context, flow.State) error       { return nil }
func (ownerWriter) Resume(context.Context, flow.State) error            { return nil }

func TestSixDomainBindUsesFrozenOwnerPlanAndCompletePauseRegistry(t *testing.T) {
	noop := func(context.Context) error { return nil }
	owner := &ownerFixture{execution: &SixDomainExecution{Writers: []flow.Writer{ownerWriter("teams-writer")}, Collectors: []flow.Collector{ownerCollector("teams-redis")}, Prepare: noop, CheckSource: noop, ResolveMutations: noop, Cleanup: noop, Validate: func(context.Context, []flow.Part) error { return nil }}}
	d := &Driver{Config: Config{ID: "six-domain", Mode: "backup", SixDomainModule: &recovery.Reference{ID: "owner", Version: "v1", SHA256: strings.Repeat("a", 64)}}, SixDomain: owner}
	task := control.Task{ID: "sb-test", ProfileRevision: d.Metadata().Revision, Deadline: time.Now().Add(time.Minute).UnixMilli(), Request: control.Request{Kind: "backup", Profile: "six-domain", Purpose: "functional_test"}}
	p := plan{Version: "kubernetes-linux.v1", Task: task.ID, Revision: task.ProfileRevision, Deadline: task.Deadline, OwnerPlan: json.RawMessage(`{"checkpoint":"fixed"}`)}
	raw, _ := json.Marshal(p)
	x, e := d.Bind(context.Background(), task, raw)
	if e != nil || len(x.Capture) != 1 || x.Capture[0].ID() != "teams-redis" || len(x.Writers) != 2 || x.Writers[1].ID() != "teams-writer" {
		t.Fatal("owner adapters not bound", e)
	}
	_, j, e := d.writers(task, p)
	if e != nil || !reflect.DeepEqual(j.Writers, []string{"platform-database", "teams-writer"}) {
		t.Fatal("incomplete recovery writer registry", j.Writers, e)
	}
	// Binding constructs adapters only. This Driver deliberately has no SQL,
	// Kubernetes, filesystem or other live dependencies.
	if owner.binds < 2 {
		t.Fatal("owner was bypassed")
	}
	p.Work = []work{{ID: "database"}, {ID: "assets"}}
	parts := []flow.Part{{ID: "teams-redis"}, {ID: "database"}, {ID: "assets"}}
	if got := ownParts(p, parts); len(got) != 2 || got[0].ID != "database" {
		t.Fatal(got)
	}
	owner.execution.Writers = []flow.Writer{ownerWriter("platform-database")}
	if _, _, e = d.writers(task, p); e == nil {
		t.Fatal("writer collision")
	}
	owner.execution.Writers = nil
	owner.execution.Collectors = []flow.Collector{ownerCollector("database")}
	if _, e = d.bindSix(task, p); e == nil {
		t.Fatal("collector collision")
	}
	owner.execution.Collectors = []flow.Collector{ownerCollector("teams-redis")}
	owner.execution.ResolveMutations = nil
	if _, e = d.bindSix(task, p); e == nil {
		t.Fatal("missing recovery callback")
	}
	owner.execution.ResolveMutations = noop
	p.OwnerPlan = json.RawMessage(`{"checkpoint":"changed"}`)
	if _, e = d.bindSix(task, p); e == nil {
		t.Fatal("owner discovery regenerated")
	}
	d.SixDomain = nil
	if _, e = d.bindSix(task, p); e == nil {
		t.Fatal("missing owner downgraded")
	}
	d.Config.SixDomainModule = nil
	if _, e = d.bindSix(task, p); e == nil {
		t.Fatal("unbound owner plan accepted")
	}
}
