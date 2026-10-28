package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"

	d "clawreef/internal/systembackupdispatch"
)

// DurableExecutionStore inserts custody/result persistence between the public
// scheduler and runner. Scheduler still owns claim/renewal, phase CAS, recovery
// authority and finalization. Its Record must be idempotent: uncertain SQL
// receipts are read back before any runner work can be dispatched again.
type DurableExecutionStore struct {
	Scheduler ExecutionWorkStore
	Records   SQLExecutionRecords
}

func (s DurableExecutionStore) Ready(ctx context.Context) error {
	if absentExecutionDependency(s.Scheduler) || !s.Records.ready() {
		return d.ErrNotReady
	}
	if err := s.Records.Ready(ctx); err != nil {
		return err
	}
	return s.Scheduler.Ready(ctx)
}

func (s DurableExecutionStore) Next(ctx context.Context) (*ExecutionWork, error) {
	if err := s.Ready(ctx); err != nil {
		return nil, err
	}
	w, err := s.Scheduler.Next(ctx)
	if err != nil || w == nil {
		return w, err
	}
	if w.Step == ExecutionRecover {
		// Recovery requires the scheduler's separate current read authority.
		return w, nil
	}
	plan, err := s.Records.LoadPlan(ctx, w.Input)
	if w.Step == ExecutionPrepare {
		if errors.Is(err, sql.ErrNoRows) {
			return w, nil
		}
		if err != nil {
			return nil, err
		}
		// A crash after the plan commit must never rediscover/overwrite it.
		defer clear(plan.CanonicalJSON)
		return nil, s.Scheduler.Record(ctx, *w, ExecutionOutcome{Plan: plan})
	}
	if w.Step != ExecutionCapture {
		return nil, d.ErrNotReady
	}
	if err != nil {
		return nil, err
	}
	loaded := cloneExecutionWork(*w)
	loaded.Plan = plan
	w = &loaded
	// An already-recorded capture needs scheduler reconciliation, not another
	// external Capture call. Rehydrate the exact stored observation.
	raw, err := s.Records.read(ctx, w.Input.Authority, "capture_result")
	if errors.Is(err, sql.ErrNoRows) {
		return w, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	out, err := decodeExecutionResult(raw, plan.SHA256)
	if err != nil {
		return nil, err
	}
	return nil, s.Scheduler.Record(ctx, *w, out)
}

func (s DurableExecutionStore) Record(ctx context.Context, w ExecutionWork, out ExecutionOutcome) error {
	if err := s.Ready(ctx); err != nil {
		return err
	}
	switch w.Step {
	case ExecutionPrepare:
		if out.Err == nil {
			if err := s.Records.SavePlan(ctx, w.Input, out.Plan); err != nil {
				return err
			}
		}
	case ExecutionCapture:
		if err := s.Records.RecordCapture(ctx, w, out); err != nil {
			return err
		}
	case ExecutionRecover:
	default:
		return d.ErrNotReady
	}
	return s.Scheduler.Record(ctx, w, out)
}

var _ ExecutionWorkStore = DurableExecutionStore{}
