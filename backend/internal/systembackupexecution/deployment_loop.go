package systembackupexecution

import (
	"context"
	"log"
	"time"
)

// Each pass consults the durable original claim/journal. A failed pass never
// replays its external operation here, nor starts a second execution. Keeping
// the owner alive lets a later recovery claim close a protected failed task.
func runDeploymentPasses(ctx context.Context, pass func(context.Context) error, interval time.Duration, observe func(error)) error {
	last := ""
	delay := interval
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := pass(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		observe(err)
		code := closedExecutionCode(err)
		if code != last {
			log.Printf("[system-backup-public] execution=%s", code)
			last = code
		}
		if err == nil {
			delay = interval
		} else {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
