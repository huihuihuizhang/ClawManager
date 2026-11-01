package systembackupexecution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

type restoreWorkFixture struct {
	work                *c.ExecutionWork
	readyErr, recordErr error
	next, records       int
	interruptions       int
	saved               c.ExecutionWork
	out                 c.ExecutionOutcome
	interruptionCause   error
	nextHook            func(int)
}

func (s *restoreWorkFixture) ReadyDrill(context.Context) error { return s.readyErr }
func (s *restoreWorkFixture) NextDrill(context.Context) (*c.ExecutionWork, error) {
	s.next++
	if s.nextHook != nil {
		s.nextHook(s.next)
	}
	return s.work, nil
}
func (s *restoreWorkFixture) RecordDrill(_ context.Context, w c.ExecutionWork, out c.ExecutionOutcome) error {
	s.records++
	s.saved = w
	s.out = out
	return s.recordErr
}

func (s *restoreWorkFixture) RecordDrillInterruption(_ context.Context, w c.ExecutionWork, out c.ExecutionOutcome, cause error) error {
	s.interruptions++
	s.interruptionCause = cause
	s.saved = w
	s.out = out
	return s.recordErr
}

type restoreAuthorityFixture struct {
	calls  int
	err    error
	during func()
}

func (p *restoreAuthorityFixture) CheckRestore(context.Context, d.Authority, d.DrillSpec) error {
	p.calls++
	if p.during != nil {
		p.during()
	}
	return p.err
}

func publicRestoreFixture(t *testing.T, phase string) (*PublicRestore, *restoreWorkFixture, *restoreAuthorityFixture) {
	t.Helper()
	config := []byte(`{"fixture":true}`)
	in := d.Input{Authority: d.Authority{InstallationID: "installation_restore_test", TaskPublicID: "sdr_11111111-1111-4111-8111-111111111111", TaskType: "drill", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: hash(config), AttemptNo: 1, Phase: phase, ClaimOwner: "controller-1", ClaimRowVersion: 3, DeadlineAt: time.Now().UTC().Add(time.Minute)}, ConfigSnapshot: config, ProfileID: "cluster", ProfileRevision: "r1"}
	spec := d.DrillSpec{SourceType: "backup", SourcePublicID: "sbk_22222222-2222-4222-8222-222222222222", ManifestSHA256: strings.Repeat("a", 64), AcceptanceSHA256: strings.Repeat("b", 64), TargetProfile: "cluster", TargetConfigRef: "isolated-fixture", TargetConfigSHA256: strings.Repeat("c", 64), Purpose: "functional_test", CleanupPolicy: "retain-always"}
	if phase == "verify" {
		spec.RestoredPlanSHA256 = strings.Repeat("d", 64)
		spec.RestoreResultSHA256 = strings.Repeat("e", 64)
		spec.RevocationEvidenceSHA256 = strings.Repeat("f", 64)
	}
	raw := []byte(`{"fixture_target_descriptor":true}`)
	plan, err := d.BindRestoreTaskPlan(in, spec, d.Plan{SchemaVersion: b.RestorePlanVersion, CanonicalJSON: raw, SHA256: hash(raw)}, b.RestorePlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	step := c.ExecutionRestore
	if phase == "verify" {
		step = c.ExecutionVerify
	}
	store := &restoreWorkFixture{work: &c.ExecutionWork{Step: step, Input: in, Drill: &spec, Plan: plan}}
	authority := &restoreAuthorityFixture{}
	public, err := NewPublicRestore(PublicRestoreConfig{Store: store, Authority: authority, Guard: c.ReadinessProbeFunc(func(context.Context) error { return nil }), Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return public, store, authority
}

// Authority/WorkStore here are named scheduling fixtures, never source/target
// proof. B is the actual constructor and has no target IO capabilities.
func TestPublicRestoreLoopRecordsActualSourceRefusal(t *testing.T) {
	for _, phase := range []string{"restore", "verify"} {
		t.Run(phase, func(t *testing.T) {
			public, store, authority := publicRestoreFixture(t, phase)
			err := public.Loop.RunOnce(context.Background())
			if err != nil || store.next != 1 || store.records != 1 || authority.calls != 1 || !errors.Is(store.out.Err, d.ErrRestoreSourceUnavailable) || len(store.out.Drill.Evidence) != 0 || store.out.Recovery.CollectorsStopped || store.out.Recovery.WritersResumed || store.out.Results != nil {
				t.Fatal("source refusal not consumed by actual task loop", err)
			}
		})
	}
}

func TestPublicRestoreLoopAuthorityAndPersistenceFailuresNeverRetry(t *testing.T) {
	for _, mode := range []string{"denied", "store-unavailable", "record-unknown", "mutated-intent", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			public, store, authority := publicRestoreFixture(t, "restore")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("named fixture failure")
			switch mode {
			case "denied":
				authority.err = sentinel
			case "store-unavailable":
				store.readyErr = sentinel
			case "record-unknown":
				store.recordErr = sentinel
			case "mutated-intent":
				authority.during = func() {
					store.work.Drill.TargetConfigSHA256 = strings.Repeat("d", 64)
					store.work.Input.ConfigSnapshot[0] = 'x'
					store.work.Plan.CanonicalJSON[0] = 'x'
				}
			case "cancel":
				authority.during = cancel
			}
			err := public.Loop.RunOnce(ctx)
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) || store.records != 0 || store.interruptions != 1 || !errors.Is(store.out.Err, context.Canceled) {
					t.Fatal("cancellation treated as durable completion", err)
				}
				return
			}
			if mode == "store-unavailable" {
				if !errors.Is(err, sentinel) || store.next != 0 || authority.calls != 0 {
					t.Fatal("missing custody selected work", err)
				}
				return
			}
			if store.next != 1 || store.records != 1 || authority.calls != 1 {
				t.Fatal("work retried", err)
			}
			if mode == "mutated-intent" {
				if err != nil || !errors.Is(store.out.Err, d.ErrRestoreSourceUnavailable) || store.saved.Drill.TargetConfigSHA256 != strings.Repeat("c", 64) || store.saved.Input.ConfigSnapshot[0] != '{' || store.saved.Plan.CanonicalJSON[0] != '{' {
					t.Fatal("authority callback changed frozen observation", err)
				}
			} else if mode == "record-unknown" && (!errors.Is(err, sentinel) || store.interruptions != 1 || !errors.Is(store.out.Err, d.ErrRestoreSourceUnavailable)) {
				t.Fatal("record failure lost original observation", err)
			} else if mode == "denied" && (err != nil || !errors.Is(store.out.Err, sentinel)) {
				t.Fatal("authority/record failure lost", err)
			}
		})
	}
}

func TestPublicRestoreLoopRejectsDriftAndCaptureCrossRouting(t *testing.T) {
	for _, mode := range []string{"plan", "spec", "phase", "capture-step", "capture-dispatch"} {
		public, store, authority := publicRestoreFixture(t, "restore")
		switch mode {
		case "plan":
			store.work.Plan.CanonicalJSON[1] = 'x'
		case "spec":
			store.work.Drill.ManifestSHA256 = strings.Repeat("d", 64)
		case "phase":
			store.work.Input.Authority.Phase = "verify"
		case "capture-step":
			store.work.Step = c.ExecutionRecover
		case "capture-dispatch":
			public.Loop.Dispatch.Ports = struct{ d.Ports }{}
		}
		err := public.Loop.RunOnce(context.Background())
		if authority.calls != 0 {
			t.Fatal("drift reached current authority", mode, err)
		}
		if mode == "spec" {
			if err != nil || store.records != 1 || store.out.Err == nil {
				t.Fatal("dispatched rejection not recorded")
			}
		} else if err == nil || store.records != 0 {
			t.Fatal("invalid work recorded as execution")
		}
	}
}

func TestPublicRestoreRequiresAllOwnersBeforeSelectingWork(t *testing.T) {
	_, store, _ := publicRestoreFixture(t, "restore")
	var absent *restoreAuthorityFixture
	if _, err := NewPublicRestore(PublicRestoreConfig{Store: store, Authority: absent, Guard: c.ReadinessProbeFunc(func(context.Context) error { return nil }), Interval: time.Second}); err == nil || store.next != 0 {
		t.Fatal("typed nil authority selected work")
	}
}

type failedRestoreObservation struct {
	d.RestoreRunner
	err    error
	cancel context.CancelFunc
	calls  int
}

func (r *failedRestoreObservation) Restore(_ context.Context, in d.Input, _ d.DrillSpec, plan d.Plan, _ d.RestorePorts) (d.RestoreResult, error) {
	r.calls++
	in.ConfigSnapshot[0] = 'x'
	plan.CanonicalJSON[0] = 'x'
	if r.cancel != nil {
		r.cancel()
	}
	return d.RestoreResult{Evidence: []d.EvidenceRef{{PublicID: "sev_fixture_partial_observation", SHA256: strings.Repeat("e", 64)}}}, r.err
}

func TestPublicRestorePreservesPartialErrorAndInterruptedObservation(t *testing.T) {
	for _, cancelDuringRunner := range []bool{false, true} {
		public, store, _ := publicRestoreFixture(t, "restore")
		sentinel := errors.New("fixture uncertain target result")
		ctx, cancel := context.WithCancel(context.Background())
		runner := &failedRestoreObservation{err: sentinel}
		if cancelDuringRunner {
			runner.cancel = cancel
		}
		public.Loop.Restore.Runner = runner
		err := public.Loop.RunOnce(ctx)
		cancel()
		if (!cancelDuringRunner && err != nil) || runner.calls != 1 || !errors.Is(store.out.Err, sentinel) || len(store.out.Drill.Evidence) != 1 || store.saved.Input.ConfigSnapshot[0] != '{' || store.saved.Plan.CanonicalJSON[0] != '{' {
			t.Fatal("partial failure lost or treated as success", err)
		}
		if cancelDuringRunner {
			if store.records != 0 || store.interruptions != 1 || !errors.Is(err, context.Canceled) {
				t.Fatal("interrupted observation dropped", err)
			}
		} else if store.records != 1 || store.interruptions != 0 {
			t.Fatal("error observation not recorded once")
		}
	}
}

func TestPublicRestoreRechecksDeadlineAfterAuthority(t *testing.T) {
	public, store, authority := publicRestoreFixture(t, "restore")
	store.work.Input.Authority.DeadlineAt = time.Now().UTC().Add(150 * time.Millisecond)
	raw := []byte(`{"fixture_target_descriptor":true}`)
	var err error
	store.work.Plan, err = d.BindRestoreTaskPlan(store.work.Input, *store.work.Drill, d.Plan{SchemaVersion: b.RestorePlanVersion, CanonicalJSON: raw, SHA256: hash(raw)}, b.RestorePlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	authority.during = func() { time.Sleep(time.Until(store.work.Input.Authority.DeadlineAt) + 5*time.Millisecond) }
	err = public.Loop.RunOnce(context.Background())
	if err != nil || authority.calls != 1 || store.records != 1 || !errors.Is(store.out.Err, context.DeadlineExceeded) || len(store.out.Drill.Evidence) != 0 {
		t.Fatal("expired check reached source runner", err)
	}
}

func TestPublicRestoreTaskRefusalDoesNotStopScheduling(t *testing.T) {
	public, store, _ := publicRestoreFixture(t, "restore")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.nextHook = func(n int) {
		if n == 2 {
			store.work = nil
			cancel()
		}
	}
	err := public.Loop.Run(ctx)
	if !errors.Is(err, context.Canceled) || store.next != 2 || store.records != 1 || !errors.Is(store.out.Err, d.ErrRestoreSourceUnavailable) {
		t.Fatal("persisted task refusal restarted leader", err)
	}
}

type captureSelectionFixture struct {
	next int
	c.ExecutionWorkStore
}

func (s *captureSelectionFixture) Ready(context.Context) error { return nil }
func (s *captureSelectionFixture) Next(context.Context) (*c.ExecutionWork, error) {
	s.next++
	return nil, nil
}

func TestPublicRestoreCannotSelectFromCaptureStore(t *testing.T) {
	public, store, _ := publicRestoreFixture(t, "restore")
	capture := &captureSelectionFixture{}
	if _, ok := any(capture).(c.DrillExecutionWorkStore); ok {
		t.Fatal("capture store satisfies drill selection boundary")
	}
	if _, ok := any(&c.SQLExecutionWorkStore{}).(c.DrillExecutionWorkStore); ok {
		t.Fatal("production capture SQL store accepted as drill store")
	}
	public.Loop.Store = capture // A mixed manually assembled loop must fail before either queue.
	if public.Loop.RunOnce(context.Background()) == nil || capture.next != 0 || store.next != 0 {
		t.Fatal("restore claimed a backup before rejecting the store")
	}
}

func TestPublicRestoreRecordFailurePreservesPartialObservation(t *testing.T) {
	public, store, _ := publicRestoreFixture(t, "restore")
	providerFailure := errors.New("fixture partial/unknown result")
	commitUnknown := errors.New("fixture record commit unknown")
	runner := &failedRestoreObservation{err: providerFailure}
	public.Loop.Restore.Runner = runner
	store.recordErr = commitUnknown
	err := public.Loop.RunOnce(context.Background())
	if !errors.Is(err, commitUnknown) || !errors.Is(err, providerFailure) || runner.calls != 1 || store.records != 1 || store.interruptions != 1 || len(store.out.Drill.Evidence) != 1 || !errors.Is(store.out.Err, providerFailure) || !errors.Is(store.interruptionCause, commitUnknown) {
		t.Fatal("record failure discarded unknown target facts", err)
	}
}
