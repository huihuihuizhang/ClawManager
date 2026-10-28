package control

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/recovery"
)

// ProtectedCollector connects the shared recovery lease to Pipeline's existing
// Prepare/Capture/Stop lifecycle. It requires a registered immutable artifact
// and an independent stop verifier; there is no unprotected fallback.
type ProtectedCollector struct {
	Guards       RecoveryGuards
	Artifact     string
	Collector    flow.Collector
	StopVerifier LeaseStopVerifier
	TTL          time.Duration
}

func (c *ProtectedCollector) ID() string {
	if c.Collector == nil {
		return ""
	}
	return c.Collector.ID()
}
func (c *ProtectedCollector) Prepare(ctx context.Context) error {
	if c.Collector == nil || c.StopVerifier == nil {
		return ErrNotReady
	}
	if _, e := c.Guards.AcquireFor(ctx, c.Artifact, recovery.Hash([]byte(c.ID())), c.TTL); e != nil {
		return e
	}
	return c.Collector.Prepare(ctx)
}
func (c *ProtectedCollector) Capture(ctx context.Context) (flow.Part, error) {
	if c.Collector == nil || c.StopVerifier == nil {
		return flow.Part{}, ErrNotReady
	}
	lease, e := c.Guards.AcquireFor(ctx, c.Artifact, recovery.Hash([]byte(c.ID())), c.TTL)
	if e != nil {
		return flow.Part{}, e
	}
	work, cancel := context.WithDeadline(ctx, time.UnixMilli(c.Guards.Task.Deadline))
	defer cancel()
	done := make(chan error, 1)
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(c.TTL / 3)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-work.Done():
				done <- work.Err()
				return
			case <-ticker.C:
				if _, e := c.Guards.AcquireFor(work, c.Artifact, recovery.Hash([]byte(c.ID())), c.TTL); e != nil {
					cancel()
					done <- e
					return
				}
			}
		}
	}()
	part, e := c.Collector.Capture(work)
	close(stop)
	renewErr := <-done
	if e != nil {
		return flow.Part{}, e
	}
	if renewErr != nil {
		return flow.Part{}, renewErr
	}
	if e = c.Guards.Check(ctx, lease); e != nil {
		return flow.Part{}, e
	}
	return part, nil
}
func (c *ProtectedCollector) Stop(ctx context.Context) error {
	if c.Collector == nil || c.StopVerifier == nil {
		return ErrNotReady
	}
	if e := c.Collector.Stop(ctx); e != nil {
		return e
	}
	lease, released, e := c.Guards.adoptLease(ctx, c.Artifact, recovery.Hash([]byte(c.ID())))
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if released {
		return nil
	}
	return c.Guards.Release(ctx, lease, c.StopVerifier)
}

// Recovery may adopt the task's existing lease after its data deadline, but
// cannot create a missing lease or restart a stopped consumer.
func (g RecoveryGuards) adoptLease(ctx context.Context, id, consumer string) (RecoveryLease, bool, error) {
	tx, _, e := g.begin(ctx)
	if e != nil {
		return RecoveryLease{}, false, e
	}
	defer tx.Rollback()
	var l RecoveryLease
	var released bool
	l.Artifact = id
	l.Task = g.Task.ID
	l.Consumer = consumer
	e = tx.QueryRowContext(ctx, "SELECT generation,until_ms,released FROM system_backup_recovery_leases WHERE artifact_id=? AND task_id=? AND consumer_id=? FOR UPDATE", id, g.Task.ID, consumer).Scan(&l.Generation, &l.Until, &released)
	if errors.Is(e, sql.ErrNoRows) {
		return l, false, ErrNotFound
	}
	if e != nil {
		return l, false, ErrNotReady
	}
	if l.Generation > g.Task.Generation {
		return l, false, ErrFence
	}
	if released || l.Generation == g.Task.Generation {
		return l, released, nil
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_recovery_leases SET generation=? WHERE artifact_id=? AND task_id=? AND consumer_id=? AND generation=? AND released=FALSE", g.Task.Generation, id, g.Task.ID, consumer, l.Generation)); e != nil {
		return l, false, e
	}
	l.Generation = g.Task.Generation
	return l, false, g.commit(ctx, tx)
}
