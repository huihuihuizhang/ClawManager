package worker

import (
	"context"
	"log"
	"time"
)

// First-failure DATA only, captured INSIDE the live callback before WithDEK's
// deferred cancellation can overwrite the context state. No authority changes.
type databaseCaptureFailure struct {
	stage, context                                           string
	keyRemaining, contextRemaining, sourceRemaining, elapsed int64
	keyKnown, contextKnown, sourceKnown                      bool
}

func (v *databaseCaptureFailure) observe(stage string, ctx context.Context, keyUntil, sourceUntil time.Time, started time.Time) {
	if v.stage != "" {
		return
	}
	v.stage, v.context = stage, "active"
	if ctx == nil {
		v.context = "missing"
	} else if ctx.Err() == context.DeadlineExceeded {
		v.context = "deadline"
	} else if ctx.Err() != nil {
		v.context = "canceled"
	}
	v.keyKnown = !keyUntil.IsZero()
	if v.keyKnown {
		v.keyRemaining = time.Until(keyUntil).Microseconds()
	}
	v.sourceKnown = !sourceUntil.IsZero()
	if v.sourceKnown {
		v.sourceRemaining = time.Until(sourceUntil).Microseconds()
	}
	if ctx != nil {
		if until, ok := ctx.Deadline(); ok {
			v.contextKnown = true
			v.contextRemaining = time.Until(until).Microseconds()
		}
	}
	v.elapsed = time.Since(started).Microseconds()
}

func (v databaseCaptureFailure) log(callbackEntered, callbackSucceeded bool) {
	log.Printf("[system-backup-database] stage=%s sentinel=database_rejected context=%s key_remaining_us=%d key_deadline_known=%t context_remaining_us=%d context_deadline_known=%t source_remaining_us=%d source_deadline_known=%t elapsed_us=%d callback_entered=%t callback_succeeded=%t", v.stage, v.context, v.keyRemaining, v.keyKnown, v.contextRemaining, v.contextKnown, v.sourceRemaining, v.sourceKnown, v.elapsed, callbackEntered, callbackSucceeded)
}
