package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

type ExecutionStep string

const (
	ExecutionPrepare ExecutionStep = "prepare"
	ExecutionCapture ExecutionStep = "capture"
	ExecutionRecover ExecutionStep = "recover"
)

// ExecutionWork is loaded by D from the already-claimed public task, attempt
// and durable encrypted plan. It is not a B control.Task or a request DTO.
type ExecutionWork struct {
	Step  ExecutionStep
	Input dispatch.Input
	Plan  dispatch.Plan
}
type ExecutionOutcome struct {
	Plan     dispatch.Plan
	Results  []dispatch.ModuleResult
	Recovery dispatch.RecoveryResult
	Err      error
}

// ExecutionWorkStore is D's durable scheduling boundary. Ready must reject
// missing plan/encryption/Job-intent/ledger/recovery dependencies BEFORE Next
// can select or claim. Next performs the public claim+receipt/attempt protocol;
// Record persists the exact returned observations with a fresh authority CAS.
// Record must preserve partial/unknown outcomes and never persist raw Err text.
// A failed Record must not cause this pass to rerun B's external action.
// No current SQL implementation is implied by this interface.
type ExecutionWorkStore interface {
	Ready(context.Context) error
	Next(context.Context) (*ExecutionWork, error)
	Record(context.Context, ExecutionWork, ExecutionOutcome) error
}

type TaskExecutionLoop struct {
	Guard    ReadinessProbe
	Store    ExecutionWorkStore
	Dispatch dispatch.Dispatcher
	Interval time.Duration
}

func (l TaskExecutionLoop) Validate() error {
	if absentExecutionDependency(l.Guard) || absentExecutionDependency(l.Store) || absentExecutionDependency(l.Dispatch.Runner) || absentExecutionDependency(l.Dispatch.Ports) || l.Interval < MinReconcileInterval || l.Interval > MaxReconcileInterval {
		return dispatch.ErrNotReady
	}
	return nil
}

func executionPlanValid(p dispatch.Plan) bool {
	if p.SchemaVersion == "" || len(p.SchemaVersion) > 128 || len(p.CanonicalJSON) < 2 || len(p.CanonicalJSON) > 8*1024*1024 || !json.Valid(p.CanonicalJSON) || p.CanonicalJSON[0] != '{' || !executionHash.MatchString(p.SHA256) {
		return false
	}
	sum := sha256.Sum256(p.CanonicalJSON)
	return hex.EncodeToString(sum[:]) == p.SHA256
}

// RunOnce is the D -> Dispatcher -> B call chain. It runs separately from the
// fail-safe ControlLoop; a long Capture never blocks gate recovery/deadlines.
// Prepare returns observations only. The store must durably encrypt/persist
// them before any later Next can return capture work. No automatic retry of
// uncertain side effects or conversion of a runner error into success occurs.
func (l TaskExecutionLoop) RunOnce(ctx context.Context) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if absentExecutionDependency(ctx) {
		return dispatch.ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.Guard.Check(ctx); err != nil {
		return err
	}
	if err := l.Store.Ready(ctx); err != nil {
		return err
	}
	w, err := l.Store.Next(ctx)
	if err != nil || w == nil {
		return err
	}
	if !validExecutionInput(w.Input.Authority, w.Input.Authority.InstallationID) {
		return ErrExecutionAuthority
	}
	// Freeze mutable observations before B sees them. B may not modify the
	// exact original input/plan later used by Record's public CAS.
	original := cloneExecutionWork(*w)
	call := cloneExecutionWork(original)
	var out ExecutionOutcome
	switch call.Step {
	case ExecutionPrepare:
		if call.Input.Authority.TaskType != "backup" || len(call.Plan.CanonicalJSON) != 0 {
			return dispatch.ErrNotReady
		}
		out.Plan, out.Err = l.Dispatch.Prepare(ctx, call.Input)
		if out.Err == nil && !executionPlanValid(out.Plan) {
			out.Plan = dispatch.Plan{}
			out.Err = dispatch.ErrNotReady
		}
	case ExecutionCapture:
		if call.Input.Authority.TaskType != "backup" || !executionPlanValid(call.Plan) {
			return dispatch.ErrNotReady
		}
		out.Results, out.Err = l.Dispatch.Capture(ctx, call.Input, call.Plan)
	case ExecutionRecover:
		// The caller supplies a NEW current recovery authority. Dispatcher
		// deliberately does not use the forward-work Check for compensation.
		if !executionPlanValid(call.Plan) {
			return dispatch.ErrNotReady
		}
		out.Recovery, out.Err = l.Dispatch.Recover(ctx, call.Input, call.Plan)
	default:
		return dispatch.ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Even a B error must reach D's persistent outcome handler. Record owns
	// classification, state transitions, takeover and final authorization.
	if err := l.Store.Record(ctx, original, out); err != nil {
		return err
	}
	return out.Err
}

func cloneExecutionWork(w ExecutionWork) ExecutionWork {
	w.Input.ConfigSnapshot = append(json.RawMessage(nil), w.Input.ConfigSnapshot...)
	w.Input.Jobs = append([]dispatch.JobBinding(nil), w.Input.Jobs...)
	w.Plan.CanonicalJSON = append(json.RawMessage(nil), w.Plan.CanonicalJSON...)
	if w.Input.Backup != nil {
		spec := *w.Input.Backup
		spec.RequestedParts = append([]string(nil), spec.RequestedParts...)
		w.Input.Backup = &spec
	}
	return w
}

func (l TaskExecutionLoop) Run(ctx context.Context) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if absentExecutionDependency(ctx) {
		return dispatch.ErrNotReady
	}
	ticker := time.NewTicker(l.Interval)
	defer ticker.Stop()
	for {
		if err := l.RunOnce(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunLeaderLoops cancels siblings on any unexpected exit and waits for ALL of
// them to return. Cancellation does not prove that B stopped or cleaned up.
// The bootstrap supervisor's existing stop-timeout remains the outer bound;
// it must not start a replacement worker while one has not joined.
func RunLeaderLoops(ctx context.Context, loops ...func(context.Context) error) error {
	if absentExecutionDependency(ctx) || len(loops) == 0 {
		return dispatch.ErrNotReady
	}
	for _, run := range loops {
		if run == nil {
			return dispatch.ErrNotReady
		}
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(loops))
	for _, run := range loops {
		go func() { results <- run(child) }()
	}
	first := <-results
	if ctx.Err() == nil && first == nil {
		first = errors.New("leader loop exited without cancellation")
	}
	cancel()
	for n := 1; n < len(loops); n++ {
		err := <-results
		if err != nil && !errors.Is(err, context.Canceled) {
			first = errors.Join(first, err)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first
}

// LeaderLoopGroup registers a leader generation BEFORE starting goroutines.
// It refuses replacement while old B cleanup is still running and rejects
// late client-go callbacks after the outer runtime has closed. CloseAndWait
// keeps BootstrapSupervisor from reporting worker exit before cleanup joins.
type LeaderLoopGroup struct {
	mu     sync.Mutex
	closed bool
	done   chan struct{}
	cancel context.CancelFunc
}

func (g *LeaderLoopGroup) Start(ctx context.Context, loops ...func(context.Context) error) (<-chan error, error) {
	if absentExecutionDependency(ctx) || ctx.Err() != nil || len(loops) == 0 {
		return nil, dispatch.ErrNotReady
	}
	for _, run := range loops {
		if run == nil {
			return nil, dispatch.ErrNotReady
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.done != nil {
		return nil, dispatch.ErrNotReady
	}
	child, cancel := context.WithCancel(ctx)
	g.cancel = cancel
	done := make(chan struct{})
	g.done = done
	result := make(chan error, 1)
	go func() {
		err := RunLeaderLoops(child, loops...)
		cancel()
		g.mu.Lock()
		g.done = nil
		g.cancel = nil
		close(done)
		g.mu.Unlock()
		result <- err
		close(result)
	}()
	return result, nil
}

func (g *LeaderLoopGroup) CloseAndWait() {
	g.mu.Lock()
	g.closed = true
	done, cancel := g.done, g.cancel
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
