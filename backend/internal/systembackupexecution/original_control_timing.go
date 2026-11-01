package systembackupexecution

import (
	"context"
	"sync"
	"time"

	"clawreef/internal/systembackup/worker"
)

// Optional private diagnostic context only, installed by the native fixture.
// It cannot authorize, skip, change or repeat any SQL/Kube/provider operation.
// Authorize includes its SQLBind and KeyStateSQL children: never add these
// overlapping timings as if they were disjoint execution stages.
type originalControlStageTimingData struct {
	Calls, Failures                   uint64
	ElapsedNanos, MaxNanos, LastNanos int64
}
type originalControlActionTimingData struct {
	Authorize, SQLBind, KeyStateSQL                                                                                                       originalControlStageTimingData
	ExecutionInput, OriginalPlan, OriginalPart, WorkerMounts, WorkerSecurity, WorkerProcess, ProviderQualification, GuardTail             originalControlStageTimingData
	Dependencies, OriginalWorker, TaskLocator, RecordObservation, ObservationGuard, PermitStage, PlanTail, FinalGuard, Commit, Collectors originalControlStageTimingData
}
type originalControlTimingData struct {
	KeyReserve, KeyBegin, KeyCheck, KeyEnd, Candidate originalControlActionTimingData
}
type originalControlTimingObserver struct {
	mu    sync.Mutex
	value originalControlTimingData
}
type originalControlTimingRegistry struct{ entries sync.Map }
type originalControlTimingContextKey struct{}
type originalControlStage uint8

const (
	originalControlAuthorize originalControlStage = iota
	originalControlSQLBind
	originalControlKeyStateSQL
	originalControlExecutionInput
	originalControlOriginalPlan
	originalControlOriginalPart
	originalControlWorkerMounts
	originalControlWorkerSecurity
	originalControlWorkerProcess
	originalControlProviderQualification
	originalControlGuardTail
	originalControlDependencies
	originalControlOriginalWorker
	originalControlTaskLocator
	originalControlRecordObservation
	originalControlObservationGuard
	originalControlPermitStage
	originalControlPlanTail
	originalControlFinalGuard
	originalControlCommit
	originalControlCollectors
)

type originalControlStageTimer struct {
	observer *originalControlTimingObserver
	action   string
	stage    originalControlStage
	started  time.Time
}

func startOriginalControlStage(ctx context.Context, request worker.ControlRequest, stage originalControlStage) *originalControlStageTimer {
	if ctx == nil {
		return nil
	}
	registry, ok := ctx.Value(originalControlTimingContextKey{}).(*originalControlTimingRegistry)
	if !ok || registry == nil {
		return nil
	}
	value, ok := registry.entries.Load(request.InvocationSHA256)
	if !ok {
		return nil
	}
	observer, ok := value.(*originalControlTimingObserver)
	if !ok || observer == nil {
		return nil
	}
	switch request.Action {
	case "key-reserve", "key-begin", "key-check", "key-end", "candidate":
	default:
		return nil
	}
	return &originalControlStageTimer{observer: observer, action: request.Action, stage: stage, started: time.Now()}
}
func (t *originalControlStageTimer) finish(failed bool) {
	if t == nil {
		return
	}
	nanos := time.Since(t.started).Nanoseconds()
	x := t.observer
	x.mu.Lock()
	defer x.mu.Unlock()
	var action *originalControlActionTimingData
	switch t.action {
	case "key-reserve":
		action = &x.value.KeyReserve
	case "key-begin":
		action = &x.value.KeyBegin
	case "key-check":
		action = &x.value.KeyCheck
	case "key-end":
		action = &x.value.KeyEnd
	case "candidate":
		action = &x.value.Candidate
	default:
		return
	}
	var bucket *originalControlStageTimingData
	switch t.stage {
	case originalControlAuthorize:
		bucket = &action.Authorize
	case originalControlSQLBind:
		bucket = &action.SQLBind
	case originalControlKeyStateSQL:
		bucket = &action.KeyStateSQL
	case originalControlExecutionInput:
		bucket = &action.ExecutionInput
	case originalControlOriginalPlan:
		bucket = &action.OriginalPlan
	case originalControlOriginalPart:
		bucket = &action.OriginalPart
	case originalControlWorkerMounts:
		bucket = &action.WorkerMounts
	case originalControlWorkerSecurity:
		bucket = &action.WorkerSecurity
	case originalControlWorkerProcess:
		bucket = &action.WorkerProcess
	case originalControlProviderQualification:
		bucket = &action.ProviderQualification
	case originalControlGuardTail:
		bucket = &action.GuardTail
	case originalControlDependencies:
		bucket = &action.Dependencies
	case originalControlOriginalWorker:
		bucket = &action.OriginalWorker
	case originalControlTaskLocator:
		bucket = &action.TaskLocator
	case originalControlRecordObservation:
		bucket = &action.RecordObservation
	case originalControlObservationGuard:
		bucket = &action.ObservationGuard
	case originalControlPermitStage:
		bucket = &action.PermitStage
	case originalControlPlanTail:
		bucket = &action.PlanTail
	case originalControlFinalGuard:
		bucket = &action.FinalGuard
	case originalControlCommit:
		bucket = &action.Commit
	case originalControlCollectors:
		bucket = &action.Collectors
	default:
		return
	}
	bucket.Calls++
	bucket.ElapsedNanos += nanos
	bucket.LastNanos = nanos
	if nanos > bucket.MaxNanos {
		bucket.MaxNanos = nanos
	}
	if failed {
		bucket.Failures++
	}
}
func (x *originalControlTimingObserver) data() originalControlTimingData {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.value
}
