package worker

import (
	"context"
	"log"
	"time"
)

// Call with static stage literals only. Never log an error string, request,
// token, grant, key, locator or business payload. Authorization is unchanged.
func logControlEvidenceRejection(stage string, ctx context.Context, until time.Time, started time.Time) {
	state := "active"
	if ctx == nil {
		state = "missing"
	} else if ctx.Err() == context.DeadlineExceeded {
		state = "deadline"
	} else if ctx.Err() != nil {
		state = "canceled"
	}
	remaining := int64(0)
	if !until.IsZero() {
		remaining = time.Until(until).Microseconds()
	}
	log.Printf("[system-backup-ce] stage=%s sentinel=ce_rejected context=%s remaining_us=%d elapsed_us=%d", stage, state, remaining, time.Since(started).Microseconds())
}
