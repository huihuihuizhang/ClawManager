package systembackupdispatch

import (
	"context"
	"testing"
)

type testPorts struct {
	Ports
	denied bool
}

func (p *testPorts) Check(context.Context, Authority) error {
	if p.denied {
		return ErrNotReady
	}
	return nil
}

type testRunner struct {
	Runner
	calls int
}

func (r *testRunner) Capture(_ context.Context, in Input, p Plan, ports Ports) ([]ModuleResult, error) {
	r.calls++
	return []ModuleResult{}, nil
}
func TestDispatcherChecksAuthorityBeforeRunner(t *testing.T) {
	r := &testRunner{}
	d := Dispatcher{r, &testPorts{denied: true}}
	if _, err := d.Capture(context.Background(), Input{}, Plan{}); err == nil || r.calls != 0 {
		t.Fatal("denied dispatch")
	}
	d.Ports = &testPorts{}
	if _, err := d.Capture(context.Background(), Input{}, Plan{}); err != nil || r.calls != 1 {
		t.Fatal("runner not invoked")
	}
	var absent *testRunner
	d.Runner = absent
	if _, err := d.Capture(context.Background(), Input{}, Plan{}); err == nil {
		t.Fatal("typed nil accepted")
	}
}
