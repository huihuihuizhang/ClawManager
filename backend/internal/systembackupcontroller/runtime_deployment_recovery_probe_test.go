package systembackupcontroller

import (
	"context"
	"errors"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

func TestJournaledTenantDeploymentRecoveryProbe(t *testing.T) {
	ctx := context.Background()
	a := d.Authority{TaskPublicID: "original-task", AttemptNo: 2}
	spec := b.RuntimeWriterSpec{Kind: "deployment", Name: "original-deployment", UID: "original-uid", RestartRef: "original-task/2/7",
		Source: b.InstanceIdentity{ID: 7, UserID: 1, Generation: 3, Namespace: "test-user-1", Mode: "pro", OS: "linux", Status: "running"}}
	calls := 0
	o := &SQLRuntimeControl{cfg: RuntimeControlConfig{Namespace: "test-system", RecoveryDeploymentCheck: func(_ context.Context, got d.Authority, gotSpec b.RuntimeWriterSpec) error {
		calls++
		if got != a || gotSpec != spec {
			t.Fatal("probe changed original authority or journal spec")
		}
		return nil
	}}}
	if err := o.checkJournaledDeployment(ctx, a, spec, true); err != nil || calls != 1 {
		t.Fatal("original recovery not probed", err, calls)
	}
	for name, mutate := range map[string]func(*b.RuntimeWriterSpec){
		"another-task":     func(s *b.RuntimeWriterSpec) { s.RestartRef = "another-task/2/7" },
		"another-attempt":  func(s *b.RuntimeWriterSpec) { s.RestartRef = "original-task/1/7" },
		"another-instance": func(s *b.RuntimeWriterSpec) { s.Source.ID++ },
		"no-uid":           func(s *b.RuntimeWriterSpec) { s.UID = "" },
		"pod":              func(s *b.RuntimeWriterSpec) { s.Kind = "pod" },
		"lite":             func(s *b.RuntimeWriterSpec) { s.Source.Mode = "lite" },
		"stopped":          func(s *b.RuntimeWriterSpec) { s.Source.Status = "stopped" },
		"system":           func(s *b.RuntimeWriterSpec) { s.Source.Namespace = "test-system" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := spec
			mutate(&changed)
			if o.checkJournaledDeployment(ctx, a, changed, true) == nil || calls != 1 {
				t.Fatal("changed journal binding reached fallback")
			}
		})
	}
	if o.checkJournaledDeployment(ctx, a, spec, false) == nil || calls != 1 {
		t.Fatal("forward admitted a recovery-only probe")
	}
	blocked := errors.New("original probe blocked")
	o.cfg.DeploymentChecks = map[string]ReadinessProbe{spec.Source.Namespace + "/" + spec.Name: ReadinessProbeFunc(func(context.Context) error { return blocked })}
	if !errors.Is(o.checkJournaledDeployment(ctx, a, spec, true), blocked) || calls != 1 {
		t.Fatal("failed installed probe was bypassed")
	}
}
