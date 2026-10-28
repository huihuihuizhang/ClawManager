// Package flow implements the conservative domain capture barrier. It has no
// task table or top-level task states: the shared controller owns those, fencing,
// durable intent records, reconciliation, writer registry and watchdog.
package flow

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotReady = errors.New("backup dependencies or capture barrier not ready")
	ErrQuiesce  = errors.New("writer quiescence could not be proven")
	ErrResume   = errors.New("source resume not confirmed; durable reconciliation required")
	ErrCapture  = errors.New("domain capture failed or staging not sealed")
	ErrJournal  = errors.New("capture journal or fencing unavailable")
)

type Identity struct {
	Task, Attempt, Phase string
	Generation           int64
}
type State struct {
	UID        string
	Generation int64
	Running    bool
	Checkpoint string
}
type ACK struct {
	UID        string
	Generation int64
	Stopped    bool
}
type Writer interface {
	ID() string
	Observe(context.Context) (State, error)
	Pause(context.Context, State) (ACK, error)
	// CheckPaused revalidates the SAME writer identity and termination proof;
	// a previously acknowledged stop is not enough at a later capture boundary.
	CheckPaused(context.Context, State) error
	// Resume must be idempotent and restore the recorded original state, even
	// when Pause timed out after the remote operation had already succeeded.
	Resume(context.Context, State) error
}
type Part struct{ ID, Checkpoint, SealedRef string }
type Collector interface {
	ID() string
	Prepare(context.Context) error
	Capture(context.Context) (Part, error)
	// Stop revokes grants/credentials and proves the worker can no longer run.
	// It must be idempotent, including when Prepare failed after remote dispatch.
	Stop(context.Context) error
}
type Journal interface {
	// CheckFence also verifies the complete registered writer set and watchdog
	// deadline. Adapters must not implement it as a mere lease-expiry check.
	CheckFence(context.Context, Identity) error
	// Recovery has its own live ownership/fence, valid after cancellation or the
	// capture deadline. It must not let an old controller resume another task.
	CheckRecoveryFence(context.Context, Identity, string, State) error
	PauseIntent(context.Context, Identity, string, State) error
	Paused(context.Context, Identity, string, ACK) error
	Resumed(context.Context, Identity, string) error
}
type Request struct {
	Identity          Identity
	HoldUntil         time.Time
	ResumeTimeout     time.Duration
	Writers           []Writer
	Collectors        []Collector
	Journal           Journal
	DependenciesReady func(context.Context) error
}

// Capture prepares ALL collectors before taking the gate and seals ALL parts
// before resuming. This is safe for single-node/HostPath/NFS; cluster checkpoint
// early release is intentionally delegated to the common coordinator. No
// acceptance/eligibility claim can be inferred from the returned Part list.
func Capture(ctx context.Context, r Request) (parts []Part, result error) {
	if r.Identity.Task == "" || r.Identity.Attempt == "" || r.Identity.Phase == "" || r.Identity.Generation <= 0 || r.Journal == nil || r.DependenciesReady == nil || len(r.Writers) == 0 || len(r.Collectors) == 0 || r.ResumeTimeout <= 0 || !time.Now().Before(r.HoldUntil) {
		return nil, ErrNotReady
	}
	seen := map[string]bool{}
	for _, w := range r.Writers {
		if w == nil || w.ID() == "" || seen[w.ID()] {
			return nil, ErrNotReady
		}
		seen[w.ID()] = true
	}
	seen = map[string]bool{}
	for _, c := range r.Collectors {
		if c == nil || c.ID() == "" || seen[c.ID()] {
			return nil, ErrNotReady
		}
		seen[c.ID()] = true
	}
	if r.DependenciesReady(ctx) != nil {
		return nil, ErrNotReady
	}
	hold, cancel := context.WithDeadline(ctx, r.HoldUntil)
	defer cancel()
	type paused struct {
		writer Writer
		state  State
	}
	var attempted []paused
	var prepared []Collector
	defer func() {
		// Cancellation of capture must not cancel source recovery. The persisted
		// intents remain available for crash/watchdog recovery by the controller.
		resume, stop := context.WithTimeout(context.WithoutCancel(ctx), r.ResumeTimeout)
		defer stop()
		// A timed-out capture may still have a live remote worker. Revoke and
		// terminate every prepared collector before ANY source writer resumes.
		stopped := true
		for i := len(prepared) - 1; i >= 0; i-- {
			if prepared[i].Stop(resume) != nil {
				stopped = false
			}
		}
		if !stopped {
			result = errors.Join(result, ErrCapture, ErrResume)
			parts = nil
			return
		}
		for i := len(attempted) - 1; i >= 0; i-- {
			p := attempted[i]
			if r.Journal.CheckRecoveryFence(resume, r.Identity, p.writer.ID(), p.state) != nil {
				result = errors.Join(result, ErrJournal, ErrResume)
				parts = nil
				continue
			}
			if p.writer.Resume(resume, p.state) != nil {
				result = errors.Join(result, ErrResume)
				parts = nil
				continue
			}
			if r.Journal.Resumed(resume, r.Identity, p.writer.ID()) != nil {
				result = errors.Join(result, ErrJournal)
				parts = nil
			}
		}
	}()
	for _, c := range r.Collectors {
		prepared = append(prepared, c) // before uncertain prepare/create
		if c.Prepare(hold) != nil {
			return nil, ErrNotReady
		}
	}
	for _, w := range r.Writers {
		if hold.Err() != nil {
			return nil, hold.Err()
		}
		if r.Journal.CheckFence(hold, r.Identity) != nil {
			return nil, ErrJournal
		}
		state, e := w.Observe(hold)
		if e != nil || state.UID == "" || state.Generation <= 0 {
			return nil, ErrQuiesce
		}
		if r.Journal.PauseIntent(hold, r.Identity, w.ID(), state) != nil {
			return nil, ErrJournal
		}
		attempted = append(attempted, paused{w, state}) // before the uncertain remote call
		ack, e := w.Pause(hold, state)
		if e != nil || !ack.Stopped || ack.UID != state.UID || ack.Generation != state.Generation {
			return nil, ErrQuiesce
		}
		if r.Journal.Paused(hold, r.Identity, w.ID(), ack) != nil {
			return nil, ErrJournal
		}
	}
	for _, c := range r.Collectors {
		if hold.Err() != nil {
			return nil, hold.Err()
		}
		if r.Journal.CheckFence(hold, r.Identity) != nil {
			return nil, ErrJournal
		}
		for _, p := range attempted {
			if p.writer.CheckPaused(hold, p.state) != nil {
				return nil, ErrQuiesce
			}
		}
		part, e := c.Capture(hold)
		if e != nil || part.ID != c.ID() || part.Checkpoint == "" || part.SealedRef == "" {
			return nil, ErrCapture
		}
		parts = append(parts, part)
	}
	if hold.Err() != nil {
		return nil, hold.Err()
	}
	if r.Journal.CheckFence(hold, r.Identity) != nil {
		return nil, ErrJournal
	}
	for _, p := range attempted {
		if p.writer.CheckPaused(hold, p.state) != nil {
			return nil, ErrQuiesce
		}
	}
	return parts, nil
}
