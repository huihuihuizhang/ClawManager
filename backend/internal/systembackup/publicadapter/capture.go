package publicadapter

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/flow"
	d "clawreef/internal/systembackupdispatch"
)

type journal struct {
	in       d.Input
	ports    d.Ports
	failure  *error
	validate func(context.Context) error
}

func (j journal) record(err error) error {
	if err != nil && j.failure != nil && *j.failure == nil {
		*j.failure = err
	}
	return err
}

func (j journal) CheckFence(ctx context.Context, _ flow.Identity) error {
	if err := j.record(j.ports.Check(ctx, j.in.Authority)); err != nil {
		return err
	}
	if j.validate != nil {
		return j.record(j.validate(ctx))
	}
	return nil
}
func state(s flow.State) d.WriterState {
	return d.WriterState{UID: s.UID, Generation: s.Generation, Running: s.Running, Checkpoint: s.Checkpoint}
}
func (j journal) CheckRecoveryFence(ctx context.Context, _ flow.Identity, id string, s flow.State) error {
	return j.record(j.ports.CheckRecovery(ctx, j.in.Authority, id, state(s)))
}
func (j journal) PauseIntent(ctx context.Context, _ flow.Identity, id string, s flow.State) error {
	return j.record(j.ports.PauseIntent(ctx, j.in.Authority, id, state(s)))
}
func (j journal) Paused(ctx context.Context, _ flow.Identity, id string, a flow.ACK) error {
	return j.record(j.ports.Paused(ctx, j.in.Authority, id, d.WriterACK{UID: a.UID, Generation: a.Generation, Stopped: a.Stopped}))
}
func (j journal) Resumed(ctx context.Context, _ flow.Identity, id string) error {
	return j.record(j.ports.Resumed(ctx, j.in.Authority, id))
}

type pinnedWriter struct {
	flow.Writer
	original flow.State
	j        journal
}

func (w pinnedWriter) Observe(ctx context.Context) (flow.State, error) {
	s, e := w.Writer.Observe(ctx)
	if e != nil || s != w.original {
		return flow.State{}, flow.ErrQuiesce
	}
	return s, nil
}
func (w pinnedWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if s != w.original {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if err := w.j.record(w.j.ports.Check(ctx, w.j.in.Authority)); err != nil {
		return flow.ACK{}, err
	}
	return w.Writer.Pause(ctx, s)
}

func (w pinnedWriter) Resume(ctx context.Context, s flow.State) error {
	if s != w.original {
		return flow.ErrQuiesce
	}
	if barrier, ok := w.j.ports.(d.ResumeBarrier); ok {
		if e := barrier.BeforeResume(ctx, w.j.in.Authority); e != nil {
			return e
		}
	}
	return w.Writer.Resume(ctx, s)
}

func bindWriters(ctx context.Context, p Profile, in d.Input, x Discovery, j journal) ([]flow.Writer, error) {
	detached, err := copyDiscovery(x)
	if err != nil {
		return nil, err
	}
	actual, err := p.BindWriters(ctx, cloneInput(in), detached)
	if err != nil {
		return nil, classify(err)
	}
	expected := map[string]flow.State{}
	for _, w := range x.Writers {
		expected[w.ID] = w.Original
	}
	if len(actual) != len(expected) {
		return nil, d.ErrNotReady
	}
	out := make([]flow.Writer, 0, len(actual))
	seen := map[string]bool{}
	for _, w := range actual {
		if nilValue(w) {
			return nil, d.ErrNotReady
		}
		s, ok := expected[w.ID()]
		if !ok || seen[w.ID()] {
			return nil, d.ErrNotReady
		}
		seen[w.ID()] = true
		out = append(out, pinnedWriter{w, s, j})
	}
	return out, nil
}

// PreflightProfile is explicitly read-only. It cannot call Job ports via this
// method. Existing private restore/preflight routines are not used as fallback.
type PreflightProfile interface {
	Preflight(context.Context, d.Input, Discovery) ([]d.ModuleResult, error)
}

func (r *runner) Capture(ctx context.Context, in d.Input, plan d.Plan, ports d.Ports) ([]d.ModuleResult, error) {
	p, err := r.admit(ctx, in, ports, false)
	if err != nil {
		return nil, err
	}
	f, err := loadPlan(in, plan)
	if err != nil {
		return nil, err
	}
	if err := r.guardInventory(ctx, in, f.Discovery); err != nil {
		return nil, err
	}
	if in.Authority.TaskType == "preflight" {
		pre, ok := p.(PreflightProfile)
		if !ok {
			return nil, d.ErrNotReady
		}
		bounded, cancel := context.WithDeadline(ctx, in.Authority.DeadlineAt)
		defer cancel()
		results, err := pre.Preflight(bounded, cloneInput(in), f.Discovery)
		if err != nil {
			return nil, classify(err)
		}
		if err := validatePreflight(results, f.Discovery); err != nil {
			return nil, err
		}
		if err := bounded.Err(); err != nil {
			return nil, classify(err)
		}
		if err := ports.Check(bounded, in.Authority); err != nil {
			return nil, classify(err)
		}
		if err := bounded.Err(); err != nil {
			return nil, classify(err)
		}
		return results, nil
	}
	if len(in.Jobs) > 0 {
		return r.sealedTakeover(ctx, in, plan, f.Discovery, ports)
	}
	if in.Authority.MaintenanceOwner == "" || in.Authority.MaintenanceFencingToken == 0 || !time.Now().Before(f.Discovery.HoldUntil) || !freshInvocations(f.Discovery) || len(f.Discovery.Writers) == 0 {
		return nil, d.ErrNotReady
	}
	var journalFailure error
	j := journal{in: in, ports: ports, failure: &journalFailure, validate: func(ctx context.Context) error {
		if err := r.guardInventory(ctx, in, f.Discovery); err != nil {
			return err
		}
		x, err := copyDiscovery(f.Discovery)
		if err != nil {
			return err
		}
		return p.CheckSource(ctx, cloneInput(in), x)
	}}
	writers, err := bindWriters(ctx, p, in, f.Discovery, j)
	if err != nil {
		return nil, err
	}
	collectors := make([]flow.Collector, 0, len(f.Discovery.Parts))
	jobs := make([]*jobCollector, 0, len(f.Discovery.Parts))
	for _, part := range f.Discovery.Parts {
		c := &jobCollector{in: in, spec: part, sourceSHA: f.Discovery.SourceSHA256, ports: ports, reader: r.deps.Results}
		jobs = append(jobs, c)
		collectors = append(collectors, c)
	}
	_, err = flow.Capture(ctx, flow.Request{Identity: identity(in), HoldUntil: f.Discovery.HoldUntil, ResumeTimeout: r.deps.RecoveryTimeout, Writers: writers, Collectors: collectors, Journal: j, DependenciesReady: func(ctx context.Context) error {
		if err := j.record(ports.Check(ctx, in.Authority)); err != nil {
			return err
		}
		return j.record(r.deps.Admission(ctx, cloneInput(in)))
	}})
	if err != nil {
		for _, c := range jobs {
			err = errors.Join(err, c.failure)
		}
		return nil, classify(errors.Join(err, journalFailure))
	}
	if err := ctx.Err(); err != nil {
		return nil, classify(err)
	}
	if err := ports.Check(ctx, in.Authority); err != nil {
		return nil, classify(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, classify(err)
	}
	results := make([]d.ModuleResult, 0, len(jobs))
	for _, c := range jobs {
		if c.result == nil {
			return nil, d.ErrNotReady
		}
		results = append(results, *c.result)
	}
	return results, nil
}

// An existing Job set is NEVER interpreted as permission to start another
// source read. Only a complete authenticated sealed set can be reused, followed
// by recovery from D's original ledger. An incomplete/unknown set is left to D
// Recover/reconcile and cannot fall through to a fresh capture.
func (r *runner) sealedTakeover(ctx context.Context, in d.Input, plan d.Plan, x Discovery, ports d.Ports) ([]d.ModuleResult, error) {
	if len(in.Jobs) != len(x.Parts) || validateRecoveryJobs(in.Jobs, in, x) != nil {
		return nil, d.ErrNotReady
	}
	byUnit := map[string]d.JobBinding{}
	for _, job := range in.Jobs {
		byUnit[job.JobUnitKey] = job
	}
	for _, part := range x.Parts {
		b, ok := byUnit[part.Intent.JobUnitKey]
		if !ok {
			return nil, d.ErrNotReady
		}
		if err := ports.Check(ctx, in.Authority); err != nil {
			return nil, classify(err)
		}
		obs, err := ports.ObserveJob(ctx, in.Authority, b)
		if err != nil {
			return nil, classify(err)
		}
		if !sameBinding(obs.Binding, b) || !obs.Complete || obs.ResultEvidence == nil {
			return nil, d.ErrNotReady
		}
	}
	results := make([]d.ModuleResult, 0, len(x.Parts))
	for _, part := range x.Parts {
		b := byUnit[part.Intent.JobUnitKey]
		c := jobCollector{in: in, spec: part, sourceSHA: x.SourceSHA256, ports: ports, reader: r.deps.Results, binding: &b, ensureAttempted: true, sealedReuse: true}
		if _, err := c.Capture(ctx); err != nil {
			return nil, classify(err)
		}
		results = append(results, *c.result)
	}
	recovered, err := r.Recover(ctx, in, plan, ports)
	if err != nil {
		return nil, err
	}
	if !recovered.CollectorsStopped || !recovered.WritersResumed {
		return nil, &Failure{"quiesce_resume_failed"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ports.Check(ctx, in.Authority); err != nil {
		return nil, classify(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func validatePreflight(results []d.ModuleResult, x Discovery) error {
	if len(results) != len(x.Parts) {
		return d.ErrNotReady
	}
	expected := map[string]string{}
	for _, p := range x.Parts {
		expected[p.Part] = p.Category
	}
	for _, r := range results {
		category, ok := expected[r.Part]
		if !ok || category != r.Category || validateResult(r) != nil {
			return d.ErrNotReady
		}
		delete(expected, r.Part)
	}
	return nil
}

type recoveryJournal struct {
	journal
	pauses []flow.PauseRecord
}

func (j recoveryJournal) PendingPauses(context.Context, flow.Identity) ([]flow.PauseRecord, error) {
	return j.pauses, nil
}

func (r *runner) Recover(ctx context.Context, in d.Input, plan d.Plan, ports d.Ports) (d.RecoveryResult, error) {
	var out d.RecoveryResult
	p, err := r.admit(ctx, in, ports, true)
	if err != nil {
		return out, err
	}
	f, err := loadPlan(in, plan)
	if err != nil {
		return out, err
	}
	if err := r.guardInventory(ctx, in, f.Discovery); err != nil {
		return out, err
	}
	if in.Authority.TaskType != "backup" {
		return out, d.ErrNotReady
	}
	bounded, cancel := context.WithTimeout(ctx, r.deps.RecoveryTimeout)
	defer cancel()
	snapshot, err := r.deps.Recovery.Pending(bounded, in.Authority)
	pauses, jobs := snapshot.Pauses, snapshot.Jobs
	if err != nil || len(pauses) > 10000 || len(jobs) > 10000 || len(snapshot.Undispatched) > 10000 {
		return out, d.ErrNotReady
	}
	var journalFailure error
	j := journal{in: in, ports: ports, failure: &journalFailure}
	writers, err := bindWriters(bounded, p, in, f.Discovery, j)
	if err != nil {
		return out, err
	}
	// Validate the ENTIRE persisted scope before any Stop/Resume side effect.
	expected := map[string]flow.State{}
	for _, w := range f.Discovery.Writers {
		expected[w.ID] = w.Original
	}
	seen := map[string]bool{}
	if err := validateRecoveryScope(snapshot, in, f.Discovery); err != nil {
		return out, d.ErrNotReady
	}
	for _, pause := range pauses {
		original, ok := expected[pause.WriterID]
		if !ok || seen[pause.WriterID] || original != pause.Original {
			return out, d.ErrNotReady
		}
		seen[pause.WriterID] = true
		if err := ports.CheckRecovery(bounded, in.Authority, pause.WriterID, state(pause.Original)); err != nil {
			return out, classify(err)
		}
	}
	// Each StopJob must revoke grants, join/terminate the SAME UID, and prove
	// no further worker writes. Unknown Stop prevents every source resume.
	for _, job := range jobs {
		if err := ports.StopJob(bounded, in.Authority, job); err != nil {
			return out, &Failure{"quiesce_resume_failed"}
		}
	}
	out.CollectorsStopped = true
	if err := flow.RecoverSource(bounded, identity(in), recoveryJournal{j, pauses}, writers); err != nil {
		return out, classify(errors.Join(err, journalFailure))
	}
	if err := bounded.Err(); err != nil {
		return out, classify(err)
	}
	out.WritersResumed = true
	out.Evidence = []d.EvidenceRef{}
	return out, nil
}

// Checkpoint is B's explicit payload, not C's manifest or A's certificate.
// A evidence reader must authenticate this exact binding and immutable seal.
type Checkpoint struct {
	InstallationID   string `json:"installation_id"`
	ConfigVersion    uint64 `json:"config_version"`
	SchemaVersion    string `json:"schema_version"`
	TaskPublicID     string `json:"task_public_id"`
	AttemptNo        uint64 `json:"attempt_no"`
	Phase            string `json:"phase"`
	ConfigSHA256     string `json:"config_sha256"`
	InventorySHA256  string `json:"inventory_sha256"`
	Part             string `json:"part"`
	JobUID           string `json:"job_uid"`
	JobGeneration    uint64 `json:"job_generation"`
	InvocationSHA256 string `json:"invocation_sha256"`
	SealedRef        string `json:"sealed_ref"`
	ContentSHA256    string `json:"content_sha256"`
}

func validateCheckpoint(raw json.RawMessage, in d.Input, part JobPart, b d.JobBinding, source string) error {
	var c Checkpoint
	if decodeRequiredObject(raw, &c) != nil || c.SchemaVersion != "system-backup-b-checkpoint.v1" || c.InstallationID != in.Authority.InstallationID || c.ConfigVersion != in.Authority.ConfigVersion || c.TaskPublicID != in.Authority.TaskPublicID || c.AttemptNo != in.Authority.AttemptNo || c.Phase != in.Authority.Phase || c.ConfigSHA256 != in.Authority.ConfigSHA256 || c.InventorySHA256 != source || c.Part != part.Part || c.JobUID != b.UID || c.JobGeneration != b.Generation || c.InvocationSHA256 != part.InvocationSHA256 || c.SealedRef == "" || len(c.SealedRef) > 1024 || !hexHash.MatchString(c.ContentSHA256) {
		return &Failure{"control_evidence_invalid"}
	}
	return nil
}
