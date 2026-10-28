// Package control owns the shared users/instances task journal. API processes
// only admit/cancel tasks; a separately deployed controller claims and executes.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	"clawreef/internal/systembackup/recovery"
)

var (
	ErrNotReady = errors.New("not_ready")
	ErrInvalid  = errors.New("invalid_request")
	ErrConflict = errors.New("state_conflict")
	ErrNotFound = errors.New("not_found")
	ErrFence    = errors.New("coordination_invalid")
)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var catalogRecordID = regexp.MustCompile(`^sbr_[a-z2-7]{32}$`)

const Version = "users-instances-control.v1alpha1"

type Request struct {
	Kind         string `json:"kind"`
	Profile      string `json:"profile"`
	Artifact     string `json:"artifact,omitempty"`
	RecordSHA256 string `json:"record_sha256,omitempty"`
	Purpose      string `json:"purpose"`
	// Acceptance is opt-in and pinned to the controller's published policy.
	AcceptancePolicy *recovery.Reference `json:"acceptance_policy,omitempty"`
}

func (r Request) Validate() error {
	if !identifier.MatchString(r.Profile) || (r.Purpose != "functional_test" && r.Purpose != "acceptance") {
		return ErrInvalid
	}
	if r.Purpose == "acceptance" {
		if r.Kind != "backup" || r.AcceptancePolicy == nil || r.AcceptancePolicy.Validate() != nil {
			return ErrInvalid
		}
	} else if r.AcceptancePolicy != nil {
		return ErrInvalid
	}
	if r.Kind != "catalog_import" && r.RecordSHA256 != "" {
		return ErrInvalid
	}
	switch r.Kind {
	case "backup", "catalog_scan":
		if r.Artifact != "" {
			return ErrInvalid
		}
	case "drill", "preflight":
		if !identifier.MatchString(r.Artifact) {
			return ErrInvalid
		}
	case "catalog_import":
		if !catalogRecordID.MatchString(r.Artifact) || !revision.MatchString(r.RecordSHA256) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (r Request) Hash() string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", ErrNotReady
	}
	return "sb-" + hex.EncodeToString(b), nil
}

type Task struct {
	ID              string  `json:"id"`
	Request         Request `json:"request"`
	ProfileRevision string  `json:"profile_revision"`
	Actor           int     `json:"actor"`
	Status          string  `json:"status"`
	CanCancel       bool    `json:"can_cancel"`
	RowVersion      int64   `json:"row_version"`
	Generation      int64   `json:"generation"`
	Owner           string  `json:"-"`
	LeaseUntil      int64   `json:"-"`
	CreatedAt       int64   `json:"created_at"`
	Deadline        int64   `json:"deadline"`
	FailureCode     string  `json:"failure_code,omitempty"`
}

func (t Task) Terminal() bool {
	return t.Status == "succeeded" || t.Status == "failed" || t.Status == "canceled"
}

var paths = map[string][]string{
	"backup":         {"pending", "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating", "publishing", "succeeded"},
	"drill":          {"pending", "preflighting", "provisioning", "restoring", "normalizing", "verifying", "succeeded"},
	"preflight":      {"pending", "running", "succeeded"},
	"catalog_scan":   {"pending", "running", "succeeded"},
	"catalog_import": {"pending", "running", "succeeded"},
}

func Next(t Task) (string, error) {
	for i, s := range paths[t.Request.Kind] {
		if s == t.Status && i+1 < len(paths[t.Request.Kind]) {
			return paths[t.Request.Kind][i+1], nil
		}
	}
	return "", ErrConflict
}
func Allowed(t Task, next string) bool {
	if t.Terminal() {
		return false
	}
	if next == "canceling" {
		return t.CanCancel
	}
	if t.Status == "canceling" {
		return next == "canceled" || next == "failed"
	}
	if t.Status == "finalization_unknown" {
		return t.Request.Kind == "backup" && !t.CanCancel && next == "succeeded"
	}
	if next == "failed" {
		return t.CanCancel
	}
	if t.Request.Kind == "backup" && t.Status == "publishing" && !t.CanCancel && next == "finalization_unknown" {
		return true
	}
	n, e := Next(t)
	return e == nil && n == next
}

type Profile struct {
	ID               string              `json:"id"`
	Revision         string              `json:"revision"`
	Kinds            []string            `json:"kinds"`
	Ready            bool                `json:"ready"`
	Reasons          []string            `json:"reasons"`
	AcceptancePolicy *recovery.Reference `json:"acceptance_policy,omitempty"`
}

func (p Profile) Admits(r Request) bool {
	return r.Validate() == nil && (r.Purpose != "acceptance" || p.AcceptancePolicy != nil && *p.AcceptancePolicy == *r.AcceptancePolicy)
}

type Store interface {
	Create(context.Context, int, string, Request, time.Duration) (Task, error)
	List(context.Context, int) ([]Task, error)
	Get(context.Context, string) (Task, error)
	Cancel(context.Context, string, int64) (Task, error)
	Claim(context.Context, string, time.Duration) (Task, error)
	Renew(context.Context, Task, time.Duration) (Task, error)
	Advance(context.Context, Task, string, string) (Task, error)
	BeginCommit(context.Context, Task) (Task, error)
}

// Step is replayed after takeover. Implementations MUST use task/attempt-scoped
// immutable resources and durable dispatch journals for all remote mutations.
type Executor interface {
	Profiles(context.Context) ([]Profile, error)
	Step(context.Context, Task) error
	// Recover confirms source resume, worker termination and credential revocation.
	// A failure leaves a nonterminal task for takeover; it never clears the gate.
	Recover(context.Context, Task) error
}

type Controller struct {
	Store                  Store
	Executor               Executor
	Owner                  string
	Lease, RecoveryTimeout time.Duration
}

func (c Controller) RunOnce(ctx context.Context) error {
	if c.Store == nil || c.Executor == nil || !identifier.MatchString(c.Owner) || c.Lease < 3*time.Second || c.Lease > time.Minute || c.RecoveryTimeout <= 0 || c.RecoveryTimeout > 10*time.Minute {
		return ErrNotReady
	}
	t, e := c.Store.Claim(ctx, c.Owner, c.Lease)
	if e != nil {
		return e
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	claim := t
	var phaseMu sync.Mutex
	var phaseCancel context.CancelFunc
	go func() {
		defer close(done)
		timer := time.NewTicker(c.Lease / 3)
		defer timer.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-timer.C:
				if _, e := c.Store.Renew(work, claim, c.Lease); e != nil {
					cancel()
					return
				}
				current, err := c.Store.Get(work, claim.ID)
				if err != nil || current.Owner != claim.Owner || current.Generation != claim.Generation {
					cancel()
					return
				}
				if current.Status == "canceling" {
					phaseMu.Lock()
					if phaseCancel != nil {
						phaseCancel()
					}
					phaseMu.Unlock()
				}
			}
		}
	}()
	// Reload between steps: cancellation CAS and phase advancement serialize in DB.
	defer func() { cancel(); <-done }()
	for {
		current, e := c.Store.Get(work, t.ID)
		if e != nil {
			return e
		}
		if current.Owner != t.Owner || current.Generation != t.Generation {
			return ErrFence
		}
		t = current
		if t.Terminal() {
			return nil
		}
		if t.Status == "canceling" || time.Now().UnixMilli() >= t.Deadline {
			recovery, stop := context.WithTimeout(work, c.RecoveryTimeout)
			e = c.Executor.Recover(recovery, t)
			stop()
			if e != nil {
				return e
			}
			next, code := "failed", "deadline_exceeded"
			if t.Status == "canceling" {
				next, code = "canceled", "canceled_by_actor"
			} else if !t.CanCancel {
				next, code = "finalization_unknown", "finalization_unknown"
			}
			_, e = c.Store.Advance(work, t, next, code)
			return e
		}
		// Deadline bounds phase IO; recovery uses its own bounded live-owner context.
		step, stop := context.WithDeadline(work, time.UnixMilli(t.Deadline))
		phaseMu.Lock()
		phaseCancel = stop
		phaseMu.Unlock()
		e = c.Executor.Step(step, t)
		stop()
		phaseMu.Lock()
		phaseCancel = nil
		phaseMu.Unlock()
		if work.Err() != nil {
			return ErrFence
		}
		observed, observationErr := c.Store.Get(work, t.ID)
		if observationErr != nil {
			return observationErr
		}
		if observed.Owner != t.Owner || observed.Generation != t.Generation {
			return ErrFence
		}
		if e != nil {
			recovery, stop := context.WithTimeout(work, c.RecoveryTimeout)
			re := c.Executor.Recover(recovery, t)
			stop()
			if re != nil {
				return re
			}
			fresh, ge := c.Store.Get(work, t.ID)
			if ge != nil {
				return ge
			}
			if fresh.Generation != t.Generation || fresh.Owner != t.Owner {
				return ErrFence
			}
			if fresh.Status == "canceling" {
				_, e = c.Store.Advance(work, fresh, "canceled", "canceled_by_actor")
				return e
			}
			if !fresh.CanCancel {
				_, e = c.Store.Advance(work, fresh, "finalization_unknown", "finalization_unknown")
				return e
			}
			_, e = c.Store.Advance(work, fresh, "failed", "runner_failed")
			return e
		}
		next, e := Next(t)
		if e != nil {
			return e
		}
		if next == "succeeded" {
			recovery, stop := context.WithTimeout(work, c.RecoveryTimeout)
			e = c.Executor.Recover(recovery, t)
			stop()
			if e != nil {
				return e
			}
		}
		fresh, e := c.Store.Get(work, t.ID)
		if e != nil {
			return e
		}
		if fresh.Status == "canceling" {
			continue
		}
		if fresh.Generation != t.Generation || fresh.Owner != t.Owner || fresh.Status != t.Status {
			return ErrFence
		}
		if _, e = c.Store.Advance(work, fresh, next, ""); e != nil {
			if errors.Is(e, ErrConflict) {
				continue
			}
			return e
		}
	}
}
