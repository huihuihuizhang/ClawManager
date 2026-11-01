package systembackupexecution

import (
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// PublicRestoreConfig uses D's original task store and current drill authority.
// It supplies no capture Runner, source-resume ports or target IO capabilities.
type PublicRestoreConfig struct {
	Store     c.DrillExecutionWorkStore
	Authority d.RestorePorts
	Guard     c.ReadinessProbe
	Interval  time.Duration
}

type PublicRestore struct{ Loop c.TaskExecutionLoop }

// NewPublicRestore connects the dedicated public B runner to the real task
// loop. Current execution records a source-unavailable observation through the
// supplied D store; that store alone owns durable CAS/classification. There is
// no HTTP admission, automatic claim, success or target write in construction.
func NewPublicRestore(cfg PublicRestoreConfig) (*PublicRestore, error) {
	dispatcher := &d.RestoreDispatcher{Runner: b.NewRestoreRunner(), Ports: cfg.Authority, PlanVersion: b.RestorePlanVersion}
	loop := c.TaskExecutionLoop{Guard: cfg.Guard, DrillStore: cfg.Store, Restore: dispatcher, Interval: cfg.Interval}
	if err := loop.Validate(); err != nil {
		return nil, err
	}
	return &PublicRestore{Loop: loop}, nil
}
