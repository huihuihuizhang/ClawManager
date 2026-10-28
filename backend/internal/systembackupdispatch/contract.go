// Package systembackupdispatch defines D's in-process B adapter ABI. These
// values are observations, never authorization tokens or a second task store.
package systembackupdispatch

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

type Authority struct {
	InstallationID, TaskPublicID, TaskType, RequestID string
	ConfigVersion                                     uint64
	ConfigSHA256                                      string
	AttemptNo                                         uint64
	Phase                                             string
	ClaimOwner                                        string
	ClaimRowVersion                                   uint64
	MaintenanceOwner                                  string
	MaintenanceFencingToken                           uint64
	DeadlineAt                                        time.Time
}

type JobBinding struct {
	JobUnitKey, Namespace, Name, UID       string
	Generation                             uint64
	RelayIdentityRef, RelayIdentityVersion string
	RelayBoundAt, RelayExpiresAt           time.Time
}

// ConfigSnapshot contains the original canonical config bytes, not a new
// lookup. Profile identity/revision is resolved by D from admitted owner input.
type Input struct {
	Authority                  Authority
	ConfigSnapshot             json.RawMessage
	ProfileID, ProfileRevision string
	Jobs                       []JobBinding
}

// Plan is B's versioned immutable execution plan. D must encrypt/persist it
// before Bind/Capture and pass exactly the same bytes during takeover.
type Plan struct {
	SchemaVersion string
	CanonicalJSON json.RawMessage
	SHA256        string
}
type WriterState struct {
	UID        string
	Generation int64
	Running    bool
	Checkpoint string
}
type WriterACK struct {
	UID        string
	Generation int64
	Stopped    bool
}
type EvidenceRef struct{ PublicID, SHA256 string }
type JobIntent struct {
	JobUnitKey, Namespace, Name string
	Generation                  uint64
	SpecJSON                    json.RawMessage
	SpecSHA256                  string
}

// Ports are D-owned implementations, supplied at composition. Each call must
// validate the original authority. A missing port never means allow. None
// exposes DB/Tx/Commit, credentials, or a way to advance the public task state.
type Ports interface {
	Check(context.Context, Authority) error
	CheckRecovery(context.Context, Authority, string, WriterState) error
	PauseIntent(context.Context, Authority, string, WriterState) error
	Paused(context.Context, Authority, string, WriterACK) error
	Resumed(context.Context, Authority, string) error
	EnsureJob(context.Context, Authority, JobIntent) (JobBinding, error)
	ObserveJob(context.Context, Authority, JobBinding) (JobObservation, error)
	StopJob(context.Context, Authority, JobBinding) error
}
type JobObservation struct {
	Binding        JobBinding
	Complete       bool
	ResultEvidence *EvidenceRef
}

// ModuleResult follows runner-data-interfaces.schema.json PartResult. The
// checkpoint object remains B's schema-owned payload; it is not a manifest or
// capture certificate. Arrays/maps must be present, including when empty.
type Warning struct {
	Code          string  `json:"code"`
	Category      string  `json:"category"`
	Disqualifying bool    `json:"disqualifying"`
	Message       *string `json:"message,omitempty"`
}
type ModuleResult struct {
	SchemaVersion   string            `json:"schema_version"`
	Part            string            `json:"part"`
	Category        string            `json:"category"`
	Status          string            `json:"status"`
	Checkpoint      json.RawMessage   `json:"checkpoint"`
	Statistics      map[string]uint64 `json:"statistics"`
	Warnings        []Warning         `json:"warnings"`
	EvidenceIDs     []string          `json:"evidence_ids"`
	FailureCategory string            `json:"failure_category"`
}
type RecoveryResult struct {
	CollectorsStopped, WritersResumed bool
	Evidence                          []EvidenceRef
}

// Runner does not select/claim tasks, open control SQL, publish final artifacts
// or mutate public status. Prepare may discover but cannot create resources;
// Capture uses only the persisted plan and supplied public ports.
type Runner interface {
	Prepare(context.Context, Input, Ports) (Plan, error)
	Capture(context.Context, Input, Plan, Ports) ([]ModuleResult, error)
	Recover(context.Context, Input, Plan, Ports) (RecoveryResult, error)
}

var ErrNotReady = errors.New("public execution adapter unavailable")

// Dispatcher is the concrete D→B call boundary. It does not claim that a
// production scheduler/ports composition exists. That separate caller must
// acquire the public claim/attempt/gate before invoking these methods.
type Dispatcher struct {
	Runner Runner
	Ports  Ports
}

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func (d Dispatcher) Prepare(ctx context.Context, in Input) (Plan, error) {
	if missing(d.Runner) || missing(d.Ports) || missing(ctx) || ctx.Err() != nil {
		return Plan{}, ErrNotReady
	}
	if err := d.Ports.Check(ctx, in.Authority); err != nil {
		return Plan{}, err
	}
	return d.Runner.Prepare(ctx, in, d.Ports)
}
func (d Dispatcher) Capture(ctx context.Context, in Input, p Plan) ([]ModuleResult, error) {
	if missing(d.Runner) || missing(d.Ports) || missing(ctx) || ctx.Err() != nil {
		return nil, ErrNotReady
	}
	if err := d.Ports.Check(ctx, in.Authority); err != nil {
		return nil, err
	}
	return d.Runner.Capture(ctx, in, p, d.Ports)
}
func (d Dispatcher) Recover(ctx context.Context, in Input, p Plan) (RecoveryResult, error) {
	if missing(d.Runner) || missing(d.Ports) || missing(ctx) || ctx.Err() != nil {
		return RecoveryResult{}, ErrNotReady
	}
	// Cancellation is not authority to resume. Recovery ports must verify the
	// new current recovery fence for every writer before a compensation action.
	return d.Runner.Recover(ctx, in, p, d.Ports)
}
