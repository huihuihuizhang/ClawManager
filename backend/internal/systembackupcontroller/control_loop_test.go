package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type recordedKillSwitchPass struct {
	order  *[]string
	report KillSwitchReport
	err    error
}

type recordedGateRecoveryPass struct {
	order  *[]string
	report GateRecoveryReport
	err    error
}

func (p recordedGateRecoveryPass) RunOnce(context.Context) (GateRecoveryReport, error) {
	*p.order = append(*p.order, "gate-recovery")
	return p.report, p.err
}

func (p recordedKillSwitchPass) RunOnce(context.Context) (KillSwitchReport, error) {
	*p.order = append(*p.order, "kill-switch")
	return p.report, p.err
}

type recordedDeadlinePass struct {
	order  *[]string
	report DeadlineSweepReport
	err    error
}

func (p recordedDeadlinePass) RunOnce(context.Context) (DeadlineSweepReport, error) {
	*p.order = append(*p.order, "deadline")
	return p.report, p.err
}

func TestControlLoopOrdersGateRecoveryKillSwitchAndDeadlineAndReportsErrors(t *testing.T) {
	var order []string
	var results []ControlLoopResult
	loop := ControlLoop{
		GateRecovery: recordedGateRecoveryPass{order: &order, report: GateRecoveryReport{FencedForRelease: 1}, err: errors.New("gate recovery failed")},
		KillSwitch:   recordedKillSwitchPass{order: &order, report: KillSwitchReport{Transitioned: 2}, err: errors.New("kill-switch write failed")},
		Deadline:     recordedDeadlinePass{order: &order, report: DeadlineSweepReport{Expired: 1}, err: errors.New("deadline write failed")},
		Interval:     DefaultReconcile,
		OnResult: func(result ControlLoopResult) {
			results = append(results, result)
		},
	}
	if err := loop.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"gate-recovery", "kill-switch", "deadline"}) {
		t.Fatalf("pass order = %#v", order)
	}
	if len(results) != 1 || results[0].Err == nil || results[0].GateRecovery.FencedForRelease != 1 || results[0].KillSwitch.Transitioned != 2 || results[0].Deadline.Expired != 1 {
		t.Fatalf("results = %#v", results)
	}
}

func TestControlLoopCancellationPreventsBothPasses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var order []string
	loop := ControlLoop{
		GateRecovery: recordedGateRecoveryPass{order: &order},
		KillSwitch:   recordedKillSwitchPass{order: &order},
		Deadline:     recordedDeadlinePass{order: &order},
		Interval:     DefaultReconcile,
	}
	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if len(order) != 0 {
		t.Fatalf("canceled loop ran passes: %#v", order)
	}
}

func TestControlLoopGrantGuardStopsBeforeAnyMutationPass(t *testing.T) {
	var order []string
	loop := ControlLoop{
		Guard: ReadinessProbeFunc(func(context.Context) error {
			order = append(order, "grant-guard")
			return errors.New("database grant widened")
		}),
		GateRecovery: recordedGateRecoveryPass{order: &order},
		KillSwitch:   recordedKillSwitchPass{order: &order},
		Deadline:     recordedDeadlinePass{order: &order},
		Interval:     DefaultReconcile,
	}
	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("control loop accepted widened grants")
	}
	if !reflect.DeepEqual(order, []string{"grant-guard"}) {
		t.Fatalf("grant guard ran after a mutation pass: %#v", order)
	}
}

func TestControlLoopUTCGuardStopsBeforeAnyMutationPass(t *testing.T) {
	var order []string
	loop := ControlLoop{
		Guard: ReadinessProbeSet{
			ReadinessProbeFunc(func(context.Context) error {
				order = append(order, "grant-guard")
				return nil
			}),
			ReadinessProbeFunc(func(context.Context) error {
				order = append(order, "utc-guard")
				return errors.New("database session is not UTC")
			}),
		},
		GateRecovery: recordedGateRecoveryPass{order: &order},
		KillSwitch:   recordedKillSwitchPass{order: &order},
		Deadline:     recordedDeadlinePass{order: &order},
		Interval:     DefaultReconcile,
	}
	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("control loop accepted a non-UTC database session")
	}
	if !reflect.DeepEqual(order, []string{"grant-guard", "utc-guard"}) {
		t.Fatalf("UTC guard ran after a mutation pass: %#v", order)
	}
}

func TestControlLoopRejectsInvalidConfiguration(t *testing.T) {
	var order []string
	for _, loop := range []ControlLoop{
		{KillSwitch: recordedKillSwitchPass{order: &order}, Deadline: recordedDeadlinePass{order: &order}, Interval: DefaultReconcile},
		{GateRecovery: recordedGateRecoveryPass{order: &order}, Deadline: recordedDeadlinePass{order: &order}, Interval: DefaultReconcile},
		{GateRecovery: recordedGateRecoveryPass{order: &order}, KillSwitch: recordedKillSwitchPass{order: &order}, Interval: DefaultReconcile},
		{GateRecovery: recordedGateRecoveryPass{order: &order}, KillSwitch: recordedKillSwitchPass{order: &order}, Deadline: recordedDeadlinePass{order: &order}, Interval: MinReconcileInterval - time.Millisecond},
	} {
		if err := loop.Run(context.Background()); err == nil {
			t.Fatalf("invalid loop accepted: %#v", loop)
		}
	}
}
