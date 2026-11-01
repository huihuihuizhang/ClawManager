package worker

import (
	"context"
	"log"
	"time"
)

// Call with static stage literals only. Never log an error string, request,
// token, grant, key, locator or business payload. Authorization is unchanged.
func logControlEvidenceRejection(stage string, ctx context.Context, until time.Time, started time.Time, callbackState ...bool) {
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
	if len(callbackState) == 2 {
		contextRemaining, contextKnown := int64(0), false
		if ctx != nil {
			if deadline, ok := ctx.Deadline(); ok {
				contextRemaining, contextKnown = time.Until(deadline).Microseconds(), true
			}
		}
		log.Printf("[system-backup-ce] stage=%s sentinel=ce_rejected context=%s key_remaining_us=%d context_remaining_us=%d context_deadline_known=%t elapsed_us=%d callback_entered=%t callback_succeeded=%t", stage, state, remaining, contextRemaining, contextKnown, time.Since(started).Microseconds(), callbackState[0], callbackState[1])
		return
	}
	log.Printf("[system-backup-ce] stage=%s sentinel=ce_rejected context=%s remaining_us=%d elapsed_us=%d", stage, state, remaining, time.Since(started).Microseconds())
}
