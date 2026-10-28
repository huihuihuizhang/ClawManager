package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

type workStoreTest struct {
	w                   *ExecutionWork
	readyErr, recordErr error
	next, record        int
	saved               ExecutionWork
	out                 ExecutionOutcome
}

func (s *workStoreTest) Ready(context.Context) error                  { return s.readyErr }
func (s *workStoreTest) Next(context.Context) (*ExecutionWork, error) { s.next++; return s.w, nil }
func (s *workStoreTest) Record(_ context.Context, w ExecutionWork, o ExecutionOutcome) error {
	s.record++
	s.saved = w
	s.out = o
	return s.recordErr
}

type executionPortsTest struct {
	dispatch.Ports
	err    error
	checks int
}

func (p *executionPortsTest) Check(context.Context, dispatch.Authority) error {
	p.checks++
	return p.err
}

type executionRunnerTest struct {
	dispatch.Runner
	calls  int
	err    error
	mutate bool
	cancel context.CancelFunc
}

func (r *executionRunnerTest) Prepare(context.Context, dispatch.Input, dispatch.Ports) (dispatch.Plan, error) {
	r.calls++
	return executionPlanTest(), r.err
}
func (r *executionRunnerTest) Capture(_ context.Context, in dispatch.Input, p dispatch.Plan, _ dispatch.Ports) ([]dispatch.ModuleResult, error) {
	r.calls++
	if r.mutate {
		in.ConfigSnapshot[0] = 'x'
		in.Jobs[0].UID = "forged"
		p.CanonicalJSON[0] = 'x'
		in.Backup.RequestedParts[0] = "forged"
	}
	if r.cancel != nil {
		r.cancel()
	}
	return []dispatch.ModuleResult{}, r.err
}
func (r *executionRunnerTest) Recover(context.Context, dispatch.Input, dispatch.Plan, dispatch.Ports) (dispatch.RecoveryResult, error) {
	r.calls++
	return dispatch.RecoveryResult{CollectorsStopped: true, WritersResumed: true}, r.err
}
func executionPlanTest() dispatch.Plan {
	b := []byte(`{"units":[]}`)
	sum := sha256.Sum256(b)
	return dispatch.Plan{SchemaVersion: "test-only-plan.v1", CanonicalJSON: b, SHA256: hex.EncodeToString(sum[:])}
}
func executionLoopTest() (TaskExecutionLoop, *workStoreTest, *executionRunnerTest, *executionPortsTest) {
	w := &ExecutionWork{Step: ExecutionCapture, Plan: executionPlanTest(), Input: dispatch.Input{Authority: dispatch.Authority{InstallationID: "installation_test", TaskType: "backup", TaskPublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: executionPlanTest().SHA256, AttemptNo: 1, Phase: "capture", ClaimOwner: "controller-1", ClaimRowVersion: 2, DeadlineAt: time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)}, ConfigSnapshot: []byte(`{"x":1}`), Jobs: []dispatch.JobBinding{{UID: "job-1"}}}}
	s := &workStoreTest{w: w}
	r := &executionRunnerTest{}
	p := &executionPortsTest{}
	return TaskExecutionLoop{Guard: ReadinessProbeFunc(func(context.Context) error { return nil }), Store: s, Dispatch: dispatch.Dispatcher{Runner: r, Ports: p}, Interval: time.Second}, s, r, p
}
func TestTaskExecutionLoopCallsRunnerAndRecordsFrozenInput(t *testing.T) {
	l, s, r, p := executionLoopTest()
	s.w.Input.Backup = &dispatch.BackupSpec{TaskPurpose: "acceptance", RequestedParts: []string{"mysql"}}
	r.mutate = true
	if err := l.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 || s.record != 1 || p.checks != 1 || s.saved.Input.Jobs[0].UID != "job-1" || s.saved.Input.ConfigSnapshot[0] != '{' || s.saved.Plan.CanonicalJSON[0] != '{' || s.w.Input.Jobs[0].UID != "job-1" || s.saved.Input.Backup.RequestedParts[0] != "mysql" || s.w.Input.Backup.RequestedParts[0] != "mysql" {
		t.Fatal("missing call or runner mutated durable identity")
	}
}
func TestTaskExecutionLoopMissingOwnersNeverClaim(t *testing.T) {
	l, s, _, _ := executionLoopTest()
	l.Dispatch.Runner = nil
	if l.RunOnce(context.Background()) == nil || s.next != 0 {
		t.Fatal("partial runner claimed work")
	}
	l, s, _, _ = executionLoopTest()
	s.readyErr = dispatch.ErrNotReady
	if l.RunOnce(context.Background()) == nil || s.next != 0 {
		t.Fatal("missing ledger claimed work")
	}
}
func TestTaskExecutionLoopPreservesRunnerFailureWithoutRetry(t *testing.T) {
	l, s, r, _ := executionLoopTest()
	r.err = errors.New("test runner failed")
	if !errors.Is(l.RunOnce(context.Background()), r.err) || s.record != 1 || s.out.Err != r.err || r.calls != 1 {
		t.Fatal("runner failure lost or retried")
	}
	l, s, r, _ = executionLoopTest()
	s.recordErr = errors.New("commit unknown")
	if !errors.Is(l.RunOnce(context.Background()), s.recordErr) || r.calls != 1 || s.record != 1 {
		t.Fatal("uncertain result retried")
	}
}
func TestTaskExecutionLoopPersistsPlanBeforeLaterCapture(t *testing.T) {
	l, s, r, _ := executionLoopTest()
	s.w.Step = ExecutionPrepare
	s.w.Plan = dispatch.Plan{}
	if err := l.RunOnce(context.Background()); err != nil || r.calls != 1 || s.record != 1 || !executionPlanValid(s.out.Plan) || s.out.Results != nil {
		t.Fatal("prepare captured without durable round trip")
	}
}
func TestTaskExecutionLoopRejectsPlanDrift(t *testing.T) {
	l, s, r, _ := executionLoopTest()
	s.w.Plan.CanonicalJSON[1] = 'x'
	if l.RunOnce(context.Background()) == nil || r.calls != 0 || s.record != 0 {
		t.Fatal("drifted plan dispatched")
	}
}
func TestTaskExecutionLoopCanceledRunnerDoesNotCommit(t *testing.T) {
	l, s, r, _ := executionLoopTest()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.cancel = cancel
	if !errors.Is(l.RunOnce(ctx), context.Canceled) || s.record != 0 {
		t.Fatal("canceled scope committed")
	}
}

func TestTaskExecutionLoopRejectsTypedNilContext(t *testing.T) {
	l, s, r, _ := executionLoopTest()
	var ctx *executionNilContext
	if l.RunOnce(ctx) == nil || l.Run(ctx) == nil || s.next != 0 || r.calls != 0 {
		t.Fatal("typed nil context dispatched work")
	}
	if RunLeaderLoops(ctx, func(context.Context) error { return nil }) == nil {
		t.Fatal("typed nil leader accepted")
	}
	var group LeaderLoopGroup
	if _, err := group.Start(ctx, func(context.Context) error { return nil }); err == nil {
		t.Fatal("typed nil leader group accepted")
	}
}
func TestLeaderLoopsKeepSafetyPassIndependentAndJoinCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	safety := make(chan struct{})
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- RunLeaderLoops(ctx, func(c context.Context) error { close(safety); <-c.Done(); return c.Err() }, func(c context.Context) error { close(started); <-c.Done(); <-release; return c.Err() })
	}()
	for _, ch := range []<-chan struct{}{safety, started} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("sibling blocked")
		}
	}
	cancel()
	select {
	case <-finished:
		t.Fatal("cancellation treated as cleanup completion")
	default:
	}
	close(release)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup not joined")
	}
}
func TestLeaderLoopsUnexpectedExitCancelsSibling(t *testing.T) {
	stopped := make(chan struct{})
	err := RunLeaderLoops(context.Background(), func(context.Context) error { return nil }, func(ctx context.Context) error { <-ctx.Done(); close(stopped); return ctx.Err() })
	if err == nil {
		t.Fatal("unexpected exit accepted")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("sibling not joined")
	}
}

func TestLeaderLoopGroupRefusesReplacementUntilCleanupJoins(t *testing.T) {
	var group LeaderLoopGroup
	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := group.Start(ctx, func(c context.Context) error { close(started); <-c.Done(); <-release; return c.Err() })
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	if _, err := group.Start(context.Background(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("replacement overlapped old cleanup")
	}
	joined := make(chan struct{})
	go func() { group.CloseAndWait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("close did not wait for cleanup")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("close failed to join")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := group.Start(context.Background(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("late callback restarted closed group")
	}
}
