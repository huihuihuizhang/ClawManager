package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type profileFixture struct {
	metadata            Profile
	discoveries, probes int
}

func (d *profileFixture) Metadata() Profile           { return d.metadata }
func (d *profileFixture) Probe(context.Context) error { d.probes++; return nil }
func (d *profileFixture) Discover(context.Context, Task) (json.RawMessage, error) {
	d.discoveries++
	return json.RawMessage(`{}`), nil
}
func (d *profileFixture) Bind(context.Context, Task, json.RawMessage) (*Execution, error) {
	return nil, ErrNotReady
}
func TestPipelineKeepsHistoricalDriverWithoutAdmittingNewTasks(t *testing.T) {
	old := &profileFixture{metadata: Profile{ID: "cluster", Revision: strings.Repeat("a", 64), Kinds: []string{"backup"}}}
	current := &profileFixture{metadata: Profile{ID: "cluster", Revision: strings.Repeat("b", 64), Kinds: []string{"backup"}}}
	p := Pipeline{Drivers: []ProfileDriver{old, current}, ActiveRevisions: map[string]string{"cluster": current.metadata.Revision}}
	profiles, e := p.Profiles(context.Background())
	if e != nil || len(profiles) != 1 || profiles[0].Revision != current.metadata.Revision || old.probes != 0 {
		t.Fatal("historical profile admitted", e)
	}
	task, _, _ := grantFixture()
	task.Request.Profile = "cluster"
	task.Request.Kind = "backup"
	task.Request.Artifact = ""
	if d, e := p.driver(task); e != nil || d != old {
		t.Fatal("historical task cannot recover", e)
	}
	p.ActiveRevisions = nil
	if _, e = p.Profiles(context.Background()); e == nil {
		t.Fatal("ambiguous active revision accepted")
	}
}
func TestPipelinePendingRetryNeverRediscoversFrozenPlan(t *testing.T) {
	task, _, _ := grantFixture()
	task.Status = "pending"
	v := testVault()
	r, _ := v.seal(task, "execution-plan", "plan", []byte(`{"source":"frozen"}`))
	store, s := scriptStore(t, readRecordSteps(task, r)...)
	v.Store = store
	d := &profileFixture{}
	p := Pipeline{Store: store, Vault: v, Drivers: []ProfileDriver{d}}
	if e := p.Step(context.Background(), task); e != nil || d.discoveries != 0 || s.writes != 0 {
		t.Fatal("pending retry changed discovery", e)
	}
}
func TestPipelineRefusesReplayingUncertainCaptureOrRestore(t *testing.T) {
	for _, phase := range []string{"capturing", "restoring"} {
		t.Run(phase, func(t *testing.T) {
			task, _, _ := grantFixture()
			task.Status = phase
			v := testVault()
			name := "capture-started"
			if phase == "restoring" {
				name = "restore-results-started"
			}
			marker, _ := v.seal(task, name, "progress", []byte("confirmed"))
			steps := append(workerCommit(task), sqlStep{contains: "SELECT record_kind"})
			steps = append(steps, readRecordSteps(task, marker)...)
			store, s := scriptStore(t, steps...)
			v.Store = store
			p := Pipeline{Store: store, Vault: v}
			x := &Execution{}
			var e error
			if phase == "capturing" {
				e = p.backup(context.Background(), task, x)
			} else {
				e = p.runTarget(context.Background(), task, x, nil, "restore-results")
			}
			if e != ErrConflict || s.writes != 0 {
				t.Fatal("uncertain operation replayed", e)
			}
		})
	}
}
